//! Readiness-driven, single-thread, non-blocking datapath pump (T1 redesign —
//! design "B", panel-blessed).
//!
//! S0: neutral. The loop shape, the readiness discipline, the budgets and the
//! backpressure are mechanics — they move bytes and decide nothing about who may
//! do what. Every decision is delegated to a product-supplied
//! [`PacketPolicyPort`], which this crate cannot see into.
//!
//! The predecessor pump alternates strictly between the interface and relay with
//! a **blocking** read on each arm, so it stalls on the idle direction while the
//! busy one piles up (the T2 finding). This pump instead sets both fds
//! non-blocking, `poll()`s them, and services whichever is ready, so neither
//! direction can block the other. It applies the port's per-packet policy
//! verbatim and uses the stateful [`crate::frame_stream`] codec for the relay's
//! byte stream.
//!
//! What deliberately does NOT live here, and why:
//!
//! - **The session core.** It reaches a session registry, an ACL identity, the
//!   session addressing and an MTU limit on every packet. All four sit behind
//!   the port.
//! - **Session addressing.** The product resolves addresses before the pump
//!   exists — measured at the base, its assembly did exactly that one level up
//!   and then handed the pump a core it used only for the per-packet decision.
//! - **The MTU constant.** A limit is passed to [`PollablePump::new`]; the
//!   enforcement stays behind the port.
//! - **The audit record.** The base produced one per packet and dropped it on
//!   the floor. There was no sink to extract, so building one here would have
//!   invented a neutral obligation the base never had.
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

use crate::frame_stream::{FrameReadProgress, NonblockingFrameReader, NonblockingFrameWriter};
use crate::tunnel_wire::TunnelFrame;
use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::io::RawFd;

/// What the owning product decided about one packet.
///
/// Two variants, deliberately. There is no `Stop`: measured at the
/// pre-extraction base, the pump discarded the policy error variant entirely
/// (`Err(_) => dropped += 1`) and set `progress = true` *before* consulting the
/// policy, so a session that had gone away kept resetting the idle budget and
/// ran to the step budget instead. The base has no liveness-driven stop, and
/// inventing one here would be a behaviour change inside an extraction whose
/// whole bar is behaviour identity. Adding one is its own deliberate slice.
pub enum PacketOutcome<T> {
    /// Policy accepted: forward this.
    Forward(T),
    /// Policy rejected: count a drop. Carries no reason — under the pump's
    /// no-value-echo discipline a rejection is not a place to smuggle a value,
    /// and the product keeps whatever audit it wants on its own side.
    Drop,
}

/// The product's per-packet policy, as the pump's only view of it.
///
/// Both directions, because the coupling is two calls and not one: a port
/// covering only relay→interface would leave the identical authority sitting on
/// the interface→relay path.
///
/// Everything the product decides — session liveness, addressing, its own MTU
/// limit, ACL identity, whether to keep an audit record — happens inside these
/// two methods and is invisible here. This crate never learns any of it exists.
pub trait PacketPolicyPort {
    /// Interface → relay: validate an outbound packet and frame it.
    fn frame_from_interface(&self, packet: &[u8]) -> PacketOutcome<TunnelFrame>;
    /// Relay → interface: validate an inbound frame and yield its packet bytes.
    fn packet_from_relay(&self, frame: TunnelFrame) -> PacketOutcome<Vec<u8>>;
}

/// Non-blocking, packet-atomic interface (the tun device).
pub trait PollablePacketInterface {
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
pub trait PollablePacketRelay: Read + Write {
    /// The pollable fd for readiness (`POLLIN`/`POLLOUT`).
    fn relay_fd(&self) -> RawFd;
}

/// Which arm an I/O error occurred on. Static labels only — no payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollablePumpDirection {
    InterfaceToRelay,
    RelayToInterface,
}

/// Per-direction forwarded/dropped counters. `WouldBlock`/idle never touches
/// these — only a policy-accepted transfer or a policy reject does.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct PollablePumpStats {
    interface_to_relay_forwarded: u64,
    interface_to_relay_dropped: u64,
    relay_to_interface_forwarded: u64,
    relay_to_interface_dropped: u64,
}

impl PollablePumpStats {
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

impl fmt::Debug for PollablePumpStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PollablePumpStats")
            .field(
                "interface_to_relay_forwarded",
                &self.interface_to_relay_forwarded,
            )
            .field(
                "interface_to_relay_dropped",
                &self.interface_to_relay_dropped,
            )
            .field(
                "relay_to_interface_forwarded",
                &self.relay_to_interface_forwarded,
            )
            .field(
                "relay_to_interface_dropped",
                &self.relay_to_interface_dropped,
            )
            .finish()
    }
}

/// Why the pump stopped. Fatal variants carry only a static direction label;
/// the underlying `io::Error` is never formatted (no-value-echo).
pub enum PollablePumpStopReason {
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
        direction: PollablePumpDirection,
        kind: io::ErrorKind,
    },
}

impl fmt::Debug for PollablePumpStopReason {
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
pub struct PollablePumpBudget {
    poll_timeout_ms: i32,
    max_idle_polls: usize,
    max_partial_frame_polls: usize,
    max_steps: usize,
}

impl PollablePumpBudget {
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
pub struct PollablePumpReport {
    pub stats: PollablePumpStats,
    pub stop_reason: PollablePumpStopReason,
}

/// The readiness-driven pump. Owns the product's policy port, the stateful
/// relay codec, and one packet of R→I write backpressure.
pub struct PollablePump<P> {
    port: P,
    relay_reader: NonblockingFrameReader,
    relay_writer: NonblockingFrameWriter,
    pending_interface_write: Option<Vec<u8>>,
    interface_read_buf: Vec<u8>,
}

impl<P> fmt::Debug for PollablePump<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PollablePump")
            .field(
                "pending_interface_write",
                &self.pending_interface_write.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl<P: PacketPolicyPort> PollablePump<P> {
    /// Build a pump over the product's policy port.
    ///
    /// `max_accepted_packet_len` is the product's own limit, passed in rather
    /// than imported. No MTU constant travels: the enforcement stays behind the
    /// port, and what crosses is a read-buffer length. The `+ 1` derivation is
    /// the mechanic worth extracting and stays here — reading one byte beyond
    /// the limit means an oversized packet arrives whole and is rejected by the
    /// product's check, instead of being silently truncated into a valid one.
    ///
    /// Deliberately NOT a shared constant. Two products picking the same MTU are
    /// not indistinguishable on the wire — no receiver identifies a peer by its
    /// MTU — so pairwise distinctness would be a false positive here. The hazard
    /// a shared symbol would carry is coupling: changing one product's limit
    /// would silently retune the other's. A parameter removes that.
    #[must_use]
    pub fn new(port: P, max_accepted_packet_len: usize) -> Self {
        Self {
            port,
            relay_reader: NonblockingFrameReader::new(),
            relay_writer: NonblockingFrameWriter::new(),
            pending_interface_write: None,
            interface_read_buf: vec![0; max_accepted_packet_len + 1],
        }
    }

    /// Run the datapath until a budget or a fatal error stops it. Never blocks
    /// indefinitely: every wait is a bounded `poll()`, and both idle and
    /// mid-frame stalls have explicit budgets.
    pub fn run_until_stopped(
        &mut self,
        interface: &mut impl PollablePacketInterface,
        relay: &mut impl PollablePacketRelay,
        budget: &PollablePumpBudget,
    ) -> PollablePumpReport {
        let mut stats = PollablePumpStats::default();
        let mut idle_polls = 0usize;
        let mut mid_frame_polls = 0usize;
        let mut steps = 0usize;

        loop {
            if steps >= budget.max_steps {
                return report(stats, PollablePumpStopReason::StepBudgetExhausted);
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
                    return report(stats, PollablePumpStopReason::PartialFrameStalled);
                }
            } else {
                mid_frame_polls = 0;
                idle_polls += 1;
                if idle_polls >= budget.max_idle_polls {
                    return report(stats, PollablePumpStopReason::IdleBudgetExhausted);
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
                    io_error(PollablePumpDirection::RelayToInterface, error),
                );
            }
        }
    }

    /// One non-blocking pass over both directions. Returns `Ok(true)` if any
    /// byte moved or any policy decision was made, `Ok(false)` if everything
    /// was idle, `Err(reason)` on a fatal condition.
    ///
    /// Exposed so a two-ended test can interleave two pumps deterministically
    /// without threads or a real `poll()`. It was `pub(crate)` while the pump
    /// and that test shared a crate; the test is a product-side integration test
    /// and now lives outside, so the visibility had to widen with the boundary.
    /// This is the second place in this slice where a `pub(crate)` seal stopped
    /// reaching its intended caller — the first was the 0x17 body's accessors.
    /// Widening is sound here in a way it was not there: this method exposes no
    /// bytes and no authority, only one step of the same loop `run_until_stopped`
    /// already drives publicly.
    pub fn service_once(
        &mut self,
        interface: &mut impl PollablePacketInterface,
        relay: &mut impl PollablePacketRelay,
        stats: &mut PollablePumpStats,
    ) -> Result<bool, PollablePumpStopReason> {
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
                    return Err(io_error(PollablePumpDirection::InterfaceToRelay, error));
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
                    return Err(io_error(PollablePumpDirection::RelayToInterface, error));
                }
            }
        }

        // (3) I→R: read a packet from the interface if the relay has room.
        if self.relay_writer.has_room() {
            match interface.read_packet_nonblocking(&mut self.interface_read_buf) {
                Ok(Some(n)) => {
                    progress = true;
                    let frame = self
                        .port
                        .frame_from_interface(&self.interface_read_buf[..n]);
                    match frame {
                        // Accepted: queue it. `forwarded` is counted on delivery
                        // in step (1), not here — enqueue is not yet a transfer.
                        PacketOutcome::Forward(frame) => {
                            if let Err(error) = self.relay_writer.enqueue(&frame) {
                                return Err(io_error(
                                    PollablePumpDirection::InterfaceToRelay,
                                    error,
                                ));
                            }
                        }
                        PacketOutcome::Drop => stats.interface_to_relay_dropped += 1,
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(io_error(PollablePumpDirection::InterfaceToRelay, error));
                }
            }
        }

        // (4) R→I: read a frame from the relay if no packet is pending delivery.
        if self.pending_interface_write.is_none() {
            match self.relay_reader.poll_read(relay) {
                Ok(FrameReadProgress::Frame(frame)) => {
                    progress = true;
                    let packet = self.port.packet_from_relay(frame);
                    match packet {
                        PacketOutcome::Forward(packet) => {
                            self.pending_interface_write = Some(packet);
                        }
                        PacketOutcome::Drop => stats.relay_to_interface_dropped += 1,
                    }
                }
                Ok(FrameReadProgress::Advanced) => progress = true,
                Ok(FrameReadProgress::Idle) => {}
                Err(error) => {
                    return Err(io_error(PollablePumpDirection::RelayToInterface, error));
                }
            }
        }

        Ok(progress)
    }
}

fn report(stats: PollablePumpStats, stop_reason: PollablePumpStopReason) -> PollablePumpReport {
    PollablePumpReport { stats, stop_reason }
}

// Takes the error by value on purpose: reducing it to a static `ErrorKind`
// consumes it here, so a caller cannot format the raw `io::Error` afterward
// (a no-value-echo enforcement, not just a style choice).
#[allow(clippy::needless_pass_by_value)]
fn io_error(direction: PollablePumpDirection, error: io::Error) -> PollablePumpStopReason {
    PollablePumpStopReason::IoError {
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
