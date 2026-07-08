//! Readiness-driven, single-thread, non-blocking per-Claw VPN datapath pump
//! (T1 redesign — design "B", panel-blessed).
//!
//! The original [`crate::claw_vpn_packet_pump`] alternates strictly between the
//! interface and relay with a **blocking** read on each arm, so it stalls on
//! the idle direction while the busy one piles up (the T2 finding). This pump
//! instead sets both fds non-blocking, `poll()`s them, and services whichever
//! is ready, so neither direction can block the other. It reuses the fixed
//! session core's per-packet policy verbatim and the stateful
//! [`crate::claw_vpn_nonblocking_frame`] codec for the relay's byte stream.
//!
//! Fail-closed rules (all lenses):
//! - `WouldBlock` / not-ready is idle — never a transfer, never fatal.
//! - Idle is bounded by an explicit budget and ends with a dedicated stop
//!   reason (no infinite spin). A partial relay frame that stops advancing has
//!   its own budget and ends fatally.
//! - EOF / reset / write error / decode / oversized frame stay fatal.
//! - A per-packet policy reject is a counted drop; it never crosses the
//!   boundary and never stops the pump by itself.
//! - Reports and errors carry no packet/address/endpoint bytes (no-value-echo).

use crate::claw_vpn_nonblocking_frame::{
    ClawVpnFrameReadProgress, ClawVpnNonblockingFrameReader, ClawVpnNonblockingFrameWriter,
};
use household_rs::claw_vpn::{CLAW_VPN_V1_INNER_MTU, ClawVpnAgentSessionCore};
use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::io::RawFd;

/// One byte beyond the accepted inner MTU so an oversized local packet is read
/// in full and rejected by the core's MTU check rather than silently truncated.
const INTERFACE_READ_LEN: usize = CLAW_VPN_V1_INNER_MTU + 1;

/// Non-blocking, packet-atomic interface (the tun device).
pub trait ClawVpnPollablePacketInterface {
    /// The pollable fd for readiness (`POLLIN`/`POLLOUT`).
    fn interface_fd(&self) -> RawFd;
    /// Read one whole packet without blocking: `Ok(Some(n))` = a packet of `n`
    /// bytes was placed in `buf`; `Ok(None)` = `WouldBlock`. Any other error is
    /// fatal.
    fn read_packet_nonblocking(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>>;
    /// Write one whole packet without blocking: `Ok(true)` = written;
    /// `Ok(false)` = `WouldBlock` (the caller retries the same packet). Any
    /// other error is fatal.
    fn write_packet_nonblocking(&mut self, packet: &[u8]) -> io::Result<bool>;
}

/// Non-blocking, byte-stream relay (the target-session socketpair). Driven
/// through the stateful frame codec, so it only needs the raw fd plus
/// `Read`/`Write`.
pub trait ClawVpnPollablePacketRelay: Read + Write {
    /// The pollable fd for readiness (`POLLIN`/`POLLOUT`).
    fn relay_fd(&self) -> RawFd;
}

/// Which arm an I/O error occurred on. Static labels only — no payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnPollablePumpDirection {
    InterfaceToRelay,
    RelayToInterface,
}

/// Per-direction forwarded/dropped counters. `WouldBlock`/idle never touches
/// these — only a policy-accepted transfer or a policy reject does.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct ClawVpnPollablePumpStats {
    interface_to_relay_forwarded: u64,
    interface_to_relay_dropped: u64,
    relay_to_interface_forwarded: u64,
    relay_to_interface_dropped: u64,
}

impl ClawVpnPollablePumpStats {
    #[must_use]
    pub fn interface_to_relay_forwarded(&self) -> u64 {
        self.interface_to_relay_forwarded
    }
    #[must_use]
    pub fn interface_to_relay_dropped(&self) -> u64 {
        self.interface_to_relay_dropped
    }
    #[must_use]
    pub fn relay_to_interface_forwarded(&self) -> u64 {
        self.relay_to_interface_forwarded
    }
    #[must_use]
    pub fn relay_to_interface_dropped(&self) -> u64 {
        self.relay_to_interface_dropped
    }
}

impl fmt::Debug for ClawVpnPollablePumpStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnPollablePumpStats")
            .field("interface_to_relay_forwarded", &self.interface_to_relay_forwarded)
            .field("interface_to_relay_dropped", &self.interface_to_relay_dropped)
            .field("relay_to_interface_forwarded", &self.relay_to_interface_forwarded)
            .field("relay_to_interface_dropped", &self.relay_to_interface_dropped)
            .finish()
    }
}

/// Why the pump stopped. Fatal variants carry only a static direction label;
/// the underlying `io::Error` is never formatted (no-value-echo).
pub enum ClawVpnPollablePumpStopReason {
    /// No traffic for the whole idle budget — clean, fail-closed teardown.
    IdleBudgetExhausted,
    /// The step budget was reached — clean, fail-closed teardown.
    StepBudgetExhausted,
    /// A relay frame stopped advancing mid-frame past its budget — fatal.
    PartialFrameStalled,
    /// A fatal I/O error on one arm (EOF/reset/write/decode/oversized). Only the
    /// static `ErrorKind` category is kept — never the raw error — so the report
    /// type cannot carry an endpoint/path/byte value.
    IoError {
        direction: ClawVpnPollablePumpDirection,
        kind: io::ErrorKind,
    },
}

impl fmt::Debug for ClawVpnPollablePumpStopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdleBudgetExhausted => f.write_str("IdleBudgetExhausted"),
            Self::StepBudgetExhausted => f.write_str("StepBudgetExhausted"),
            Self::PartialFrameStalled => f.write_str("PartialFrameStalled"),
            // The kind is a static category (e.g. UnexpectedEof); no raw error
            // is stored, so nothing can leak an endpoint/path/byte value.
            Self::IoError { direction, kind } => f
                .debug_struct("IoError")
                .field("direction", direction)
                .field("kind", kind)
                .finish(),
        }
    }
}

/// Loop bounds. Budgets are counted in non-progress poll iterations, so they
/// are deterministic in tests (which drive tiny budgets) and, in production,
/// approximate wall-clock as `budget * poll_timeout`.
#[derive(Debug, Clone, Copy)]
pub struct ClawVpnPollablePumpBudget {
    poll_timeout_ms: i32,
    max_idle_polls: usize,
    max_partial_frame_polls: usize,
    max_steps: usize,
}

impl ClawVpnPollablePumpBudget {
    /// Construct a budget, rejecting values that would break the bounded /
    /// no-stall contract: a negative `poll()` timeout (would block forever) or
    /// any zero budget (would never stop).
    #[must_use]
    pub fn new(
        poll_timeout_ms: i32,
        max_idle_polls: usize,
        max_partial_frame_polls: usize,
        max_steps: usize,
    ) -> Option<Self> {
        if poll_timeout_ms < 0
            || max_idle_polls == 0
            || max_partial_frame_polls == 0
            || max_steps == 0
        {
            return None;
        }
        Some(Self {
            poll_timeout_ms,
            max_idle_polls,
            max_partial_frame_polls,
            max_steps,
        })
    }
}

/// The end-of-run report: authoritative counters plus the stop reason.
#[derive(Debug)]
pub struct ClawVpnPollablePumpReport {
    pub stats: ClawVpnPollablePumpStats,
    pub stop_reason: ClawVpnPollablePumpStopReason,
}

/// The readiness-driven pump. Owns the session core (per-packet policy), the
/// stateful relay codec, and one packet of R→I write backpressure.
pub struct ClawVpnPollablePump {
    core: ClawVpnAgentSessionCore,
    relay_reader: ClawVpnNonblockingFrameReader,
    relay_writer: ClawVpnNonblockingFrameWriter,
    pending_interface_write: Option<Vec<u8>>,
    interface_read_buf: Vec<u8>,
}

impl fmt::Debug for ClawVpnPollablePump {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnPollablePump")
            .field("pending_interface_write", &self.pending_interface_write.is_some())
            .finish_non_exhaustive()
    }
}

impl ClawVpnPollablePump {
    #[must_use]
    pub fn new(core: ClawVpnAgentSessionCore) -> Self {
        Self {
            core,
            relay_reader: ClawVpnNonblockingFrameReader::new(),
            relay_writer: ClawVpnNonblockingFrameWriter::new(),
            pending_interface_write: None,
            interface_read_buf: vec![0; INTERFACE_READ_LEN],
        }
    }

    /// Run the datapath until a budget or a fatal error stops it. Never blocks
    /// indefinitely: every wait is a bounded `poll()`, and both idle and
    /// mid-frame stalls have explicit budgets.
    pub fn run_until_stopped(
        &mut self,
        interface: &mut impl ClawVpnPollablePacketInterface,
        relay: &mut impl ClawVpnPollablePacketRelay,
        budget: &ClawVpnPollablePumpBudget,
    ) -> ClawVpnPollablePumpReport {
        let mut stats = ClawVpnPollablePumpStats::default();
        let mut idle_polls = 0usize;
        let mut mid_frame_polls = 0usize;
        let mut steps = 0usize;

        loop {
            if steps >= budget.max_steps {
                return report(stats, ClawVpnPollablePumpStopReason::StepBudgetExhausted);
            }
            steps += 1;

            match self.service_once(interface, relay, &mut stats) {
                Ok(true) => {
                    // Progress: reset idle, and reset the partial-frame clock
                    // once the relay is no longer mid-frame.
                    idle_polls = 0;
                    if !self.relay_reader.is_mid_frame() {
                        mid_frame_polls = 0;
                    }
                    continue;
                }
                Ok(false) => {}
                Err(reason) => return report(stats, reason),
            }

            // No progress this iteration — advance the budgets. While a relay
            // frame is mid-flight, a no-progress stall is a partial-frame stall
            // (fatal), never plain idle — regardless of the budget sizes.
            if self.relay_reader.is_mid_frame() {
                mid_frame_polls += 1;
                if mid_frame_polls >= budget.max_partial_frame_polls {
                    return report(stats, ClawVpnPollablePumpStopReason::PartialFrameStalled);
                }
            } else {
                mid_frame_polls = 0;
                idle_polls += 1;
                if idle_polls >= budget.max_idle_polls {
                    return report(stats, ClawVpnPollablePumpStopReason::IdleBudgetExhausted);
                }
            }

            // Wait (bounded) for either fd to become ready before retrying.
            let interface_events = readiness_events(
                self.relay_writer.has_room(),
                self.pending_interface_write.is_some(),
            );
            let relay_events = readiness_events(
                self.pending_interface_write.is_none(),
                self.relay_writer.has_pending(),
            );
            if let Err(error) = poll_two(
                interface.interface_fd(),
                interface_events,
                relay.relay_fd(),
                relay_events,
                budget.poll_timeout_ms,
            ) {
                return report(
                    stats,
                    io_error(ClawVpnPollablePumpDirection::RelayToInterface, error),
                );
            }
        }
    }

    /// One non-blocking pass over both directions. Returns `Ok(true)` if any
    /// byte moved or any policy decision was made, `Ok(false)` if everything
    /// was idle, `Err(reason)` on a fatal condition. Exposed to the crate so a
    /// two-ended test can interleave two pumps deterministically without
    /// threads or a real `poll()`.
    pub(crate) fn service_once(
        &mut self,
        interface: &mut impl ClawVpnPollablePacketInterface,
        relay: &mut impl ClawVpnPollablePacketRelay,
        stats: &mut ClawVpnPollablePumpStats,
    ) -> Result<bool, ClawVpnPollablePumpStopReason> {
        let mut progress = false;

        // (1) Flush queued I→R frames out to the relay. `forwarded` is counted
        // here, on delivery (a whole frame crossing the fd), NOT at enqueue — a
        // frame that never flushes is never reported as forwarded.
        if self.relay_writer.has_pending() {
            match self.relay_writer.poll_flush(relay) {
                Ok(flushed) => {
                    if flushed.bytes > 0 {
                        progress = true;
                    }
                    stats.interface_to_relay_forwarded +=
                        u64::try_from(flushed.frames_delivered).unwrap_or(u64::MAX);
                }
                Err(error) => {
                    return Err(io_error(ClawVpnPollablePumpDirection::InterfaceToRelay, error));
                }
            }
        }

        // (2) Deliver a pending R→I packet to the interface.
        if let Some(packet) = self.pending_interface_write.take() {
            match interface.write_packet_nonblocking(&packet) {
                Ok(true) => {
                    stats.relay_to_interface_forwarded += 1;
                    progress = true;
                }
                Ok(false) => self.pending_interface_write = Some(packet),
                Err(error) => {
                    return Err(io_error(ClawVpnPollablePumpDirection::RelayToInterface, error));
                }
            }
        }

        // (3) I→R: read a packet from the interface if the relay has room.
        if self.relay_writer.has_room() {
            match interface.read_packet_nonblocking(&mut self.interface_read_buf) {
                Ok(Some(n)) => {
                    progress = true;
                    let (frame, _audit) = self
                        .core
                        .frame_from_interface_with_audit(&self.interface_read_buf[..n]);
                    match frame {
                        // Accepted: queue it. `forwarded` is counted on delivery
                        // in step (1), not here — enqueue is not yet a transfer.
                        Ok(frame) => {
                            if let Err(error) = self.relay_writer.enqueue(&frame) {
                                return Err(io_error(
                                    ClawVpnPollablePumpDirection::InterfaceToRelay,
                                    error,
                                ));
                            }
                        }
                        Err(_) => stats.interface_to_relay_dropped += 1,
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(io_error(ClawVpnPollablePumpDirection::InterfaceToRelay, error));
                }
            }
        }

        // (4) R→I: read a frame from the relay if no packet is pending delivery.
        if self.pending_interface_write.is_none() {
            match self.relay_reader.poll_read(relay) {
                Ok(ClawVpnFrameReadProgress::Frame(frame)) => {
                    progress = true;
                    let (packet, _audit) = self.core.packet_from_relay_with_audit(frame);
                    match packet {
                        Ok(packet) => {
                            self.pending_interface_write = Some(packet.as_bytes().to_vec());
                        }
                        Err(_) => stats.relay_to_interface_dropped += 1,
                    }
                }
                Ok(ClawVpnFrameReadProgress::Advanced) => progress = true,
                Ok(ClawVpnFrameReadProgress::Idle) => {}
                Err(error) => {
                    return Err(io_error(ClawVpnPollablePumpDirection::RelayToInterface, error));
                }
            }
        }

        Ok(progress)
    }
}

fn report(
    stats: ClawVpnPollablePumpStats,
    stop_reason: ClawVpnPollablePumpStopReason,
) -> ClawVpnPollablePumpReport {
    ClawVpnPollablePumpReport { stats, stop_reason }
}

// Takes the error by value on purpose: reducing it to a static `ErrorKind`
// consumes it here, so a caller cannot format the raw `io::Error` afterward
// (a no-value-echo enforcement, not just a style choice).
#[allow(clippy::needless_pass_by_value)]
fn io_error(
    direction: ClawVpnPollablePumpDirection,
    error: io::Error,
) -> ClawVpnPollablePumpStopReason {
    ClawVpnPollablePumpStopReason::IoError {
        direction,
        kind: error.kind(),
    }
}

fn readiness_events(readable: bool, writable: bool) -> libc::c_short {
    let mut events = 0;
    if readable {
        events |= libc::POLLIN;
    }
    if writable {
        events |= libc::POLLOUT;
    }
    events
}

/// Wait until either fd is ready or the timeout elapses. `EINTR` is retried so
/// a signal never tears the datapath down. Returns `Err` only on a genuine
/// `poll(2)` failure.
#[allow(unsafe_code)]
fn poll_two(
    interface_fd: RawFd,
    interface_events: libc::c_short,
    relay_fd: RawFd,
    relay_events: libc::c_short,
    timeout_ms: i32,
) -> io::Result<()> {
    let mut fds = [
        libc::pollfd {
            fd: interface_fd,
            events: interface_events,
            revents: 0,
        },
        libc::pollfd {
            fd: relay_fd,
            events: relay_events,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: `fds` is a valid, initialized array of two `pollfd`s for the
        // duration of the call; `poll` only reads `fd`/`events` and writes
        // `revents`.
        let nfds = libc::nfds_t::try_from(fds.len()).expect("exactly two pollfds");
        // Defense in depth: never pass a negative timeout to poll(2) (which
        // would wait forever) even though the budget constructor rejects it.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), nfds, timeout_ms.max(0)) };
        if rc >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claw_vpn_nonblocking_frame::ClawVpnNonblockingFrameReader;
    use household_rs::claw_share_data_tunnel::TunnelFrame;
    use household_rs::claw_vpn::{
        ClawVpnAcl, ClawVpnAclKey, ClawVpnAgentCore, ClawVpnAuditReason, ClawVpnDatapathSide,
        ClawVpnIpv4Pool, ClawVpnSessionAddrs, ClawVpnSessionRegistry,
    };
    use household_rs::keys::{IdentityKey, P256Keypair};
    use std::net::Ipv4Addr;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::{UnixDatagram, UnixStream};

    // Tiny budgets so tests idle out in well under a second.
    fn test_budget() -> ClawVpnPollablePumpBudget {
        ClawVpnPollablePumpBudget::new(5, 4, 4, 10_000).expect("valid budget")
    }

    #[allow(unsafe_code)]
    fn set_nonblocking(fd: RawFd) {
        // SAFETY: `fd` is an open socket owned by the test; fcntl only reads and
        // sets the file-status flags.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            assert!(flags >= 0, "F_GETFL failed");
            let rc = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            assert!(rc >= 0, "F_SETFL O_NONBLOCK failed");
        }
    }

    fn build_session_core(
        side: ClawVpnDatapathSide,
    ) -> (ClawVpnAgentSessionCore, ClawVpnSessionAddrs) {
        // Fixed key so the device and claw sides of the two-ended test resolve
        // to the same session and matching addresses.
        let member_key = P256Keypair::from_secret_scalar(&[0x33; 32]).unwrap();
        let key = ClawVpnAclKey::try_new("member-m1", member_key.public(), "claw-a").unwrap();
        let mut acl = ClawVpnAcl::new();
        assert!(acl.grant(key.clone()));
        let pool = ClawVpnIpv4Pool::try_new(Ipv4Addr::new(198, 18, 0, 0), 24).unwrap();
        let registry = ClawVpnSessionRegistry::new(acl, pool);
        let mut core = ClawVpnAgentCore::new(side, registry);
        let (session, open_event) = core.open_with_audit(&key);
        let session = session.unwrap();
        assert_eq!(open_event.reason(), ClawVpnAuditReason::SessionOpened);
        let addrs = session.addrs();
        let session_core = core.into_session_core(session.id()).unwrap();
        (session_core, addrs)
    }

    fn session_core_and_addrs() -> (ClawVpnAgentSessionCore, ClawVpnSessionAddrs) {
        build_session_core(ClawVpnDatapathSide::Device)
    }

    fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        ipv4_packet_tagged(src, dst, 0)
    }

    /// Like [`ipv4_packet`] but stamps a distinct byte in the IP identification
    /// field (offset 4) — the session policy does not inspect it, so distinct
    /// tags let a test assert exact per-packet payloads and ordering rather
    /// than only counts.
    fn ipv4_packet_tagged(src: Ipv4Addr, dst: Ipv4Addr, tag: u8) -> Vec<u8> {
        let len = 20usize;
        let mut packet = vec![0u8; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        packet[4] = tag;
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet
    }

    /// Extract the payload bytes of a sequence of `Data` frames, panicking on
    /// any other frame type — so a test can compare the exact sequence.
    fn data_payloads(frames: &[TunnelFrame]) -> Vec<Vec<u8>> {
        frames
            .iter()
            .map(|frame| match frame {
                TunnelFrame::Data(bytes) => bytes.clone(),
                other => panic!("expected a Data frame, got {other:?}"),
            })
            .collect()
    }

    fn frame_wire(frame: &TunnelFrame) -> Vec<u8> {
        let payload = frame.encode();
        let mut wire = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        wire.extend_from_slice(&payload);
        wire
    }

    /// A packet-atomic interface over a `SOCK_DGRAM` socketpair. The pump owns
    /// one end; the test's `control` end injects and captures packets.
    struct TestInterface {
        pump: UnixDatagram,
    }

    impl TestInterface {
        fn pair() -> (Self, UnixDatagram) {
            let (pump, control) = UnixDatagram::pair().unwrap();
            set_nonblocking(pump.as_raw_fd());
            set_nonblocking(control.as_raw_fd());
            (Self { pump }, control)
        }
    }

    impl ClawVpnPollablePacketInterface for TestInterface {
        fn interface_fd(&self) -> RawFd {
            self.pump.as_raw_fd()
        }
        fn read_packet_nonblocking(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
            match self.pump.recv(buf) {
                Ok(n) => Ok(Some(n)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(error) => Err(error),
            }
        }
        fn write_packet_nonblocking(&mut self, packet: &[u8]) -> io::Result<bool> {
            match self.pump.send(packet) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
                Err(error) => Err(error),
            }
        }
    }

    /// A byte-stream relay over a real `SOCK_STREAM` socketpair. The pump owns
    /// one end; the test's `control` end sends and receives framed bytes.
    struct TestRelay {
        pump: UnixStream,
    }

    impl TestRelay {
        fn pair() -> (Self, UnixStream) {
            let (pump, control) = UnixStream::pair().unwrap();
            set_nonblocking(pump.as_raw_fd());
            set_nonblocking(control.as_raw_fd());
            (Self { pump }, control)
        }

        fn from_stream(pump: UnixStream) -> Self {
            set_nonblocking(pump.as_raw_fd());
            Self { pump }
        }
    }

    impl io::Read for TestRelay {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.pump.read(buf)
        }
    }

    impl io::Write for TestRelay {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            io::Write::write(&mut self.pump, buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            io::Write::flush(&mut self.pump)
        }
    }

    impl ClawVpnPollablePacketRelay for TestRelay {
        fn relay_fd(&self) -> RawFd {
            self.pump.as_raw_fd()
        }
    }

    /// Drain all framed bytes waiting on a stream into decoded frames.
    fn drain_frames(mut stream: &UnixStream) -> Vec<TunnelFrame> {
        let mut reader = ClawVpnNonblockingFrameReader::new();
        let mut frames = Vec::new();
        while let ClawVpnFrameReadProgress::Frame(frame) =
            reader.poll_read(&mut stream).expect("relay decode")
        {
            frames.push(frame);
        }
        frames
    }

    // (1) The core T2 fix: interface→relay bursts forward while relay→interface
    // is idle — the old pump died here on the idle relay read.
    #[test]
    fn forwards_interface_to_relay_bursts_while_relay_is_idle() {
        let (core, addrs) = session_core_and_addrs();
        let mut pump = ClawVpnPollablePump::new(core);
        let (mut interface, iface_control) = TestInterface::pair();
        let (mut relay, relay_control) = TestRelay::pair();

        let packets: Vec<Vec<u8>> = (1..=3)
            .map(|tag| ipv4_packet_tagged(addrs.device(), addrs.claw(), tag))
            .collect();
        for packet in &packets {
            iface_control.send(packet).unwrap();
        }

        let report = pump.run_until_stopped(&mut interface, &mut relay, &test_budget());

        assert_eq!(report.stats.interface_to_relay_forwarded(), 3);
        assert_eq!(report.stats.interface_to_relay_dropped(), 0);
        assert_eq!(report.stats.relay_to_interface_forwarded(), 0);
        assert!(
            matches!(
                report.stop_reason,
                ClawVpnPollablePumpStopReason::IdleBudgetExhausted
            ),
            "idle relay must NOT be fatal (old-pump regression): {:?}",
            report.stop_reason
        );
        assert_eq!(
            data_payloads(&drain_frames(&relay_control)),
            packets,
            "exact frame sequence and payloads on the relay"
        );
    }

    // (2) The reverse: relay→interface bursts deliver while interface is idle.
    #[test]
    fn forwards_relay_to_interface_bursts_while_interface_is_idle() {
        let (core, addrs) = session_core_and_addrs();
        let mut pump = ClawVpnPollablePump::new(core);
        let (mut interface, iface_control) = TestInterface::pair();
        let (mut relay, mut relay_control) = TestRelay::pair();

        let packets: Vec<Vec<u8>> = (1..=2)
            .map(|tag| ipv4_packet_tagged(addrs.claw(), addrs.device(), tag))
            .collect();
        for packet in &packets {
            let frame = TunnelFrame::Data(packet.clone());
            io::Write::write_all(&mut relay_control, &frame_wire(&frame)).unwrap();
        }

        let report = pump.run_until_stopped(&mut interface, &mut relay, &test_budget());

        assert_eq!(report.stats.relay_to_interface_forwarded(), 2);
        assert_eq!(report.stats.relay_to_interface_dropped(), 0);
        assert_eq!(report.stats.interface_to_relay_forwarded(), 0);
        assert!(matches!(
            report.stop_reason,
            ClawVpnPollablePumpStopReason::IdleBudgetExhausted
        ));
        for expected in &packets {
            let mut buf = [0u8; 2048];
            let n = iface_control.recv(&mut buf).unwrap();
            assert_eq!(
                &buf[..n],
                expected.as_slice(),
                "exact packet delivered to the interface"
            );
        }
        let mut buf = [0u8; 2048];
        assert_eq!(
            iface_control.recv(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "no extra packet delivered"
        );
    }

    // (3) No traffic → clean, bounded idle teardown (not a spin, not fatal).
    #[test]
    fn idle_datapath_stops_on_idle_budget() {
        let (core, _addrs) = session_core_and_addrs();
        let mut pump = ClawVpnPollablePump::new(core);
        let (mut interface, _iface_control) = TestInterface::pair();
        let (mut relay, _relay_control) = TestRelay::pair();

        let report = pump.run_until_stopped(&mut interface, &mut relay, &test_budget());

        assert_eq!(report.stats.interface_to_relay_forwarded(), 0);
        assert_eq!(report.stats.relay_to_interface_forwarded(), 0);
        assert!(matches!(
            report.stop_reason,
            ClawVpnPollablePumpStopReason::IdleBudgetExhausted
        ));
    }

    // (4) A genuine relay EOF (peer closed) stays fatal.
    #[test]
    fn relay_eof_is_fatal() {
        let (core, _addrs) = session_core_and_addrs();
        let mut pump = ClawVpnPollablePump::new(core);
        let (mut interface, _iface_control) = TestInterface::pair();
        let (mut relay, relay_control) = TestRelay::pair();

        drop(relay_control); // peer hangs up

        let report = pump.run_until_stopped(&mut interface, &mut relay, &test_budget());

        assert!(
            matches!(
                report.stop_reason,
                ClawVpnPollablePumpStopReason::IoError {
                    direction: ClawVpnPollablePumpDirection::RelayToInterface,
                    ..
                }
            ),
            "closed relay must be a fatal IoError: {:?}",
            report.stop_reason
        );
    }

    // (5) A per-packet policy reject is a counted drop that does NOT stop the pump.
    #[test]
    fn policy_drop_does_not_stop_the_pump() {
        let (core, addrs) = session_core_and_addrs();
        let mut pump = ClawVpnPollablePump::new(core);
        let (mut interface, iface_control) = TestInterface::pair();
        let (mut relay, _relay_control) = TestRelay::pair();

        // Spoofed source (claw→device on the device's interface-read arm).
        iface_control
            .send(&ipv4_packet(addrs.claw(), addrs.device()))
            .unwrap();

        let report = pump.run_until_stopped(&mut interface, &mut relay, &test_budget());

        assert_eq!(report.stats.interface_to_relay_dropped(), 1);
        assert_eq!(report.stats.interface_to_relay_forwarded(), 0);
        assert!(
            matches!(
                report.stop_reason,
                ClawVpnPollablePumpStopReason::IdleBudgetExhausted
            ),
            "a policy drop must not stop the pump: {:?}",
            report.stop_reason
        );
    }

    // (6) A relay frame that starts but stops advancing is fatal on its own
    // budget (distinct from plain idle).
    #[test]
    fn stalled_partial_relay_frame_is_fatal() {
        let (core, _addrs) = session_core_and_addrs();
        let mut pump = ClawVpnPollablePump::new(core);
        let (mut interface, _iface_control) = TestInterface::pair();
        let (mut relay, mut relay_control) = TestRelay::pair();

        // Two of the four length-prefix bytes, then never the rest.
        io::Write::write_all(&mut relay_control, &[0x00, 0x00]).unwrap();

        let report = pump.run_until_stopped(&mut interface, &mut relay, &test_budget());

        assert!(
            matches!(
                report.stop_reason,
                ClawVpnPollablePumpStopReason::PartialFrameStalled
            ),
            "a stalled partial frame must be fatal, not treated as plain idle: {:?}",
            report.stop_reason
        );
    }

    // (7) Asymmetric bidirectional traffic (2 one way, 1 the other) forwards
    // both ways with authoritative counters > 1 and no IoError — the case the
    // old symmetric-preload test could not exercise.
    #[test]
    fn forwards_asymmetric_bidirectional_traffic() {
        let (core, addrs) = session_core_and_addrs();
        let mut pump = ClawVpnPollablePump::new(core);
        let (mut interface, iface_control) = TestInterface::pair();
        let (mut relay, mut relay_control) = TestRelay::pair();

        let i2r: Vec<Vec<u8>> = (1..=2)
            .map(|tag| ipv4_packet_tagged(addrs.device(), addrs.claw(), tag))
            .collect();
        for packet in &i2r {
            iface_control.send(packet).unwrap();
        }
        let r2i = ipv4_packet_tagged(addrs.claw(), addrs.device(), 9);
        io::Write::write_all(&mut relay_control, &frame_wire(&TunnelFrame::Data(r2i.clone())))
            .unwrap();

        let report = pump.run_until_stopped(&mut interface, &mut relay, &test_budget());

        assert_eq!(report.stats.interface_to_relay_forwarded(), 2);
        assert_eq!(report.stats.relay_to_interface_forwarded(), 1);
        assert!(
            matches!(
                report.stop_reason,
                ClawVpnPollablePumpStopReason::IdleBudgetExhausted
            ),
            "asymmetric bidirectional must forward both ways then idle out: {:?}",
            report.stop_reason
        );
        assert_eq!(
            data_payloads(&drain_frames(&relay_control)),
            i2r,
            "exact I→R frame sequence on the relay"
        );
        let mut buf = [0u8; 2048];
        let n = iface_control.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], r2i.as_slice(), "exact R→I packet on the interface");
        assert_eq!(
            iface_control.recv(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "no extra packet delivered"
        );
    }

    // (8) Two-ended, end-to-end, asymmetric: a device pump and a claw pump
    // wired back-to-back over a real relay socketpair forward both ways (2 one
    // direction, 1 the other) with counters > 1 and no IoError — the case the
    // old symmetric-preload two-ended test could not exercise.
    #[test]
    fn two_ended_asymmetric_forwards_both_ways() {
        let (device_core, addrs) = build_session_core(ClawVpnDatapathSide::Device);
        let (claw_core, _claw_addrs) = build_session_core(ClawVpnDatapathSide::Claw);
        let mut device_pump = ClawVpnPollablePump::new(device_core);
        let mut claw_pump = ClawVpnPollablePump::new(claw_core);

        let (mut device_iface, device_ctl) = TestInterface::pair();
        let (mut claw_iface, claw_ctl) = TestInterface::pair();
        let (relay_a, relay_b) = UnixStream::pair().unwrap();
        let mut device_relay = TestRelay::from_stream(relay_a);
        let mut claw_relay = TestRelay::from_stream(relay_b);

        let d2c: Vec<Vec<u8>> = (1..=2)
            .map(|tag| ipv4_packet_tagged(addrs.device(), addrs.claw(), tag))
            .collect();
        for packet in &d2c {
            device_ctl.send(packet).unwrap();
        }
        let c2d = ipv4_packet_tagged(addrs.claw(), addrs.device(), 9);
        claw_ctl.send(&c2d).unwrap();

        let mut device_stats = ClawVpnPollablePumpStats::default();
        let mut claw_stats = ClawVpnPollablePumpStats::default();
        for _ in 0..400 {
            device_pump
                .service_once(&mut device_iface, &mut device_relay, &mut device_stats)
                .expect("device pump never fatal");
            claw_pump
                .service_once(&mut claw_iface, &mut claw_relay, &mut claw_stats)
                .expect("claw pump never fatal");
        }

        assert_eq!(device_stats.interface_to_relay_forwarded(), 2);
        assert_eq!(device_stats.relay_to_interface_forwarded(), 1);
        assert_eq!(claw_stats.interface_to_relay_forwarded(), 1);
        assert_eq!(claw_stats.relay_to_interface_forwarded(), 2);

        for expected in &d2c {
            let mut buf = [0u8; 2048];
            let n = claw_ctl.recv(&mut buf).unwrap();
            assert_eq!(
                &buf[..n],
                expected.as_slice(),
                "exact device→claw packet at the claw edge"
            );
        }
        let mut buf = [0u8; 2048];
        assert_eq!(
            claw_ctl.recv(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "no extra at the claw edge"
        );
        let n = device_ctl.recv(&mut buf).unwrap();
        assert_eq!(
            &buf[..n],
            c2d.as_slice(),
            "exact claw→device packet at the device edge"
        );
        assert_eq!(
            device_ctl.recv(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "no extra at the device edge"
        );
    }

    /// A relay whose reads and writes always report `WouldBlock` — models a
    /// relay that never drains. Holds a real socketpair only so `poll()` has a
    /// valid fd; the peer is kept alive so reads are `WouldBlock`, not EOF.
    struct StallRelay {
        pump: UnixStream,
        _peer: UnixStream,
    }

    impl StallRelay {
        fn new() -> Self {
            let (pump, peer) = UnixStream::pair().unwrap();
            set_nonblocking(pump.as_raw_fd());
            set_nonblocking(peer.as_raw_fd());
            Self { pump, _peer: peer }
        }
    }

    impl io::Read for StallRelay {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    impl io::Write for StallRelay {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ClawVpnPollablePacketRelay for StallRelay {
        fn relay_fd(&self) -> RawFd {
            self.pump.as_raw_fd()
        }
    }

    // (9) A frame accepted by policy and queued but never delivered (relay never
    // drains) must NOT be counted as forwarded — forwarding is delivery, not
    // enqueue.
    #[test]
    fn queued_but_undelivered_frame_is_not_counted_forwarded() {
        let (core, addrs) = session_core_and_addrs();
        let mut pump = ClawVpnPollablePump::new(core);
        let (mut interface, iface_control) = TestInterface::pair();
        let mut relay = StallRelay::new();

        iface_control
            .send(&ipv4_packet(addrs.device(), addrs.claw()))
            .unwrap();

        let report = pump.run_until_stopped(&mut interface, &mut relay, &test_budget());

        assert_eq!(
            report.stats.interface_to_relay_forwarded(),
            0,
            "a queued-but-undelivered frame must not be reported as forwarded"
        );
        assert!(matches!(
            report.stop_reason,
            ClawVpnPollablePumpStopReason::IdleBudgetExhausted
        ));
    }

    // (10) A stalled partial frame is fatal (PartialFrameStalled) even when the
    // idle budget is SMALLER than the partial-frame budget — a mid-frame stall
    // must never be reported as a clean idle stop.
    #[test]
    fn mid_frame_stall_beats_a_smaller_idle_budget() {
        let (core, _addrs) = session_core_and_addrs();
        let mut pump = ClawVpnPollablePump::new(core);
        let (mut interface, _iface_control) = TestInterface::pair();
        let (mut relay, mut relay_control) = TestRelay::pair();

        io::Write::write_all(&mut relay_control, &[0x00, 0x00]).unwrap();

        let budget = ClawVpnPollablePumpBudget::new(5, 2, 20, 10_000).expect("valid budget");
        let report = pump.run_until_stopped(&mut interface, &mut relay, &budget);

        assert!(
            matches!(
                report.stop_reason,
                ClawVpnPollablePumpStopReason::PartialFrameStalled
            ),
            "mid-frame stall must be PartialFrameStalled even with a smaller idle budget: {:?}",
            report.stop_reason
        );
    }
}
