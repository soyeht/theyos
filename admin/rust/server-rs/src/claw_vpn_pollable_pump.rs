//! Product side of the per-Claw VPN pollable datapath.
//!
//! S0 cutover: the loop, the readiness discipline, the budgets, the codec and
//! the backpressure now live in [`tunnel_wire_rs::pollable_pump`]. What remains
//! here is the only thing that was ever product-specific — the per-packet
//! policy — expressed as a [`PacketPolicyPort`] over
//! [`ClawVpnAgentSessionCore`].
//!
//! The session core reaches four authorities on every packet: a session-registry
//! liveness lookup, the ACL identity that stamps the audit subject, the session
//! addressing, and the MTU limit. All four stay on this side of the boundary,
//! and the neutral crate cannot name any of them.
//!
//! The audit events are still produced and still dropped, exactly as before the
//! extraction. That is deliberate: the pre-extraction pump bound both events to
//! `_audit` and discarded them, so there was no sink to extract. Building one
//! here would invent an obligation the base never had, and this slice's bar is
//! behaviour identity.

use household_rs::claw_share_data_tunnel::TunnelFrame;
use household_rs::claw_vpn::{CLAW_VPN_V1_INNER_MTU, ClawVpnAgentSessionCore};
use tunnel_wire_rs::pollable_pump::{PacketOutcome, PacketPolicyPort, PollablePump};

// Claw-named paths to neutral symbols. The S0 guard's property is reachability,
// not spelling: a module that reaches only neutral symbols through a
// claw-named path passes, and that is exactly what these are. Re-exported so
// the runtime and wiring keep their existing imports.
pub use tunnel_wire_rs::pollable_pump::{
    PollablePacketInterface as ClawVpnPollablePacketInterface,
    PollablePacketRelay as ClawVpnPollablePacketRelay,
    PollablePumpBudget as ClawVpnPollablePumpBudget,
    PollablePumpDirection as ClawVpnPollablePumpDirection,
    PollablePumpReport as ClawVpnPollablePumpReport, PollablePumpStats as ClawVpnPollablePumpStats,
    PollablePumpStopReason as ClawVpnPollablePumpStopReason,
};

/// The claw session core, as the neutral pump's per-packet policy.
///
/// Both directions are implemented, because the coupling the extraction had to
/// break was two calls and not one: a port covering only relay→interface would
/// have left the identical authority on the interface→relay path.
pub struct ClawVpnSessionPolicyPort {
    core: ClawVpnAgentSessionCore,
}

impl ClawVpnSessionPolicyPort {
    #[must_use]
    pub fn new(core: ClawVpnAgentSessionCore) -> Self {
        Self { core }
    }
}

impl PacketPolicyPort for ClawVpnSessionPolicyPort {
    fn frame_from_interface(&self, packet: &[u8]) -> PacketOutcome<TunnelFrame> {
        // `_audit`: produced and dropped, byte-for-byte the pre-extraction
        // behaviour. The event never reached a sink before the move either.
        let (frame, _audit) = self.core.frame_from_interface_with_audit(packet);
        match frame {
            Ok(frame) => PacketOutcome::Forward(frame),
            Err(_) => PacketOutcome::Drop,
        }
    }

    fn packet_from_relay(&self, frame: TunnelFrame) -> PacketOutcome<Vec<u8>> {
        let (packet, _audit) = self.core.packet_from_relay_with_audit(frame);
        match packet {
            Ok(packet) => PacketOutcome::Forward(packet.as_bytes().to_vec()),
            Err(_) => PacketOutcome::Drop,
        }
    }
}

/// The claw datapath pump: the neutral loop driven by the claw policy.
pub type ClawVpnPollablePump = PollablePump<ClawVpnSessionPolicyPort>;

/// Build the claw pump from a session core.
///
/// This is where the MTU stops travelling: the limit is supplied here, by the
/// product that owns it, instead of being imported into the shared loop. The
/// neutral pump derives its read buffer as `limit + 1` so an oversized packet
/// still arrives whole and is rejected by the policy below, rather than being
/// silently truncated into a valid one.
#[must_use]
pub fn new_claw_vpn_pollable_pump(core: ClawVpnAgentSessionCore) -> ClawVpnPollablePump {
    PollablePump::new(ClawVpnSessionPolicyPort::new(core), CLAW_VPN_V1_INNER_MTU)
}

#[cfg(test)]
mod tests {
    use super::*;
    // S0 cutover: IMPORTS ONLY. The codec's neutral home replaces the deleted
    // duplicate, and `io` / `RawFd` used to arrive through `use super::*` from
    // the mechanics that now live in the neutral crate. Not one assertion below
    // is touched — the assertions are the oracle for behaviour identity across
    // this move, and rewriting them while moving them would destroy the only
    // evidence that behaviour did not change.
    use household_rs::claw_share_data_tunnel::TunnelFrame;
    use household_rs::claw_vpn::{
        ClawVpnAcl, ClawVpnAclKey, ClawVpnAgentCore, ClawVpnAuditReason, ClawVpnDatapathSide,
        ClawVpnIpv4Pool, ClawVpnSessionAddrs, ClawVpnSessionRegistry,
    };
    use household_rs::keys::{IdentityKey, P256Keypair};
    use std::io;
    use std::net::Ipv4Addr;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use tunnel_wire_rs::frame_stream::{
        FrameReadProgress as ClawVpnFrameReadProgress,
        NonblockingFrameReader as ClawVpnNonblockingFrameReader,
    };

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
        let mut pump = new_claw_vpn_pollable_pump(core);
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
        let mut pump = new_claw_vpn_pollable_pump(core);
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
        let mut pump = new_claw_vpn_pollable_pump(core);
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
        let mut pump = new_claw_vpn_pollable_pump(core);
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
        let mut pump = new_claw_vpn_pollable_pump(core);
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
        let mut pump = new_claw_vpn_pollable_pump(core);
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
        let mut pump = new_claw_vpn_pollable_pump(core);
        let (mut interface, iface_control) = TestInterface::pair();
        let (mut relay, mut relay_control) = TestRelay::pair();

        let i2r: Vec<Vec<u8>> = (1..=2)
            .map(|tag| ipv4_packet_tagged(addrs.device(), addrs.claw(), tag))
            .collect();
        for packet in &i2r {
            iface_control.send(packet).unwrap();
        }
        let r2i = ipv4_packet_tagged(addrs.claw(), addrs.device(), 9);
        io::Write::write_all(
            &mut relay_control,
            &frame_wire(&TunnelFrame::Data(r2i.clone())),
        )
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
        assert_eq!(
            &buf[..n],
            r2i.as_slice(),
            "exact R→I packet on the interface"
        );
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
        let mut device_pump = new_claw_vpn_pollable_pump(device_core);
        let mut claw_pump = new_claw_vpn_pollable_pump(claw_core);

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
        let mut pump = new_claw_vpn_pollable_pump(core);
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
        let mut pump = new_claw_vpn_pollable_pump(core);
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
