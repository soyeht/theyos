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
    /// A fatal I/O error on one arm (EOF/reset/write/decode/oversized).
    IoError {
        direction: ClawVpnPollablePumpDirection,
        error: io::Error,
    },
}

impl fmt::Debug for ClawVpnPollablePumpStopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdleBudgetExhausted => f.write_str("IdleBudgetExhausted"),
            Self::StepBudgetExhausted => f.write_str("StepBudgetExhausted"),
            Self::PartialFrameStalled => f.write_str("PartialFrameStalled"),
            // Deliberately drop the embedded error so no endpoint/path/byte
            // detail can leak through the report.
            Self::IoError { direction, .. } => f
                .debug_struct("IoError")
                .field("direction", direction)
                .field("error", &"<redacted>")
                .finish(),
        }
    }
}

/// Loop bounds. Budgets are counted in non-progress poll iterations, so they
/// are deterministic in tests (which drive tiny budgets) and, in production,
/// approximate wall-clock as `budget * poll_timeout`.
#[derive(Debug, Clone, Copy)]
pub struct ClawVpnPollablePumpBudget {
    /// `poll()` timeout in milliseconds for one idle wait.
    pub poll_timeout_ms: i32,
    /// Consecutive non-progress iterations before a clean idle stop.
    pub max_idle_polls: usize,
    /// Consecutive non-progress iterations while mid-frame before a fatal
    /// partial-frame stop.
    pub max_partial_frame_polls: usize,
    /// Absolute backstop on total iterations.
    pub max_steps: usize,
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

            // No progress this iteration — advance the budgets.
            if self.relay_reader.is_mid_frame() {
                mid_frame_polls += 1;
                if mid_frame_polls >= budget.max_partial_frame_polls {
                    return report(stats, ClawVpnPollablePumpStopReason::PartialFrameStalled);
                }
            } else {
                mid_frame_polls = 0;
            }
            idle_polls += 1;
            if idle_polls >= budget.max_idle_polls {
                return report(stats, ClawVpnPollablePumpStopReason::IdleBudgetExhausted);
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
                    ClawVpnPollablePumpStopReason::IoError {
                        direction: ClawVpnPollablePumpDirection::RelayToInterface,
                        error,
                    },
                );
            }
        }
    }

    /// One non-blocking pass over both directions. Returns `Ok(true)` if any
    /// byte moved or any policy decision was made, `Ok(false)` if everything
    /// was idle, `Err(reason)` on a fatal condition.
    fn service_once(
        &mut self,
        interface: &mut impl ClawVpnPollablePacketInterface,
        relay: &mut impl ClawVpnPollablePacketRelay,
        stats: &mut ClawVpnPollablePumpStats,
    ) -> Result<bool, ClawVpnPollablePumpStopReason> {
        let mut progress = false;

        // (1) Flush queued I→R frames out to the relay.
        if self.relay_writer.has_pending() {
            match self.relay_writer.poll_flush(relay) {
                Ok(n) => {
                    if n > 0 {
                        progress = true;
                    }
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
                        Ok(frame) => match self.relay_writer.enqueue(&frame) {
                            Ok(()) => stats.interface_to_relay_forwarded += 1,
                            Err(error) => {
                                return Err(io_error(
                                    ClawVpnPollablePumpDirection::InterfaceToRelay,
                                    error,
                                ));
                            }
                        },
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

fn io_error(
    direction: ClawVpnPollablePumpDirection,
    error: io::Error,
) -> ClawVpnPollablePumpStopReason {
    ClawVpnPollablePumpStopReason::IoError { direction, error }
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
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), nfds, timeout_ms) };
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
