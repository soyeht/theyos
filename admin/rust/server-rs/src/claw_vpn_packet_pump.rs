//! Single-step packet pump core for the Product A per-Claw VPN dev proof.
//!
//! This module deliberately does not open TUN/utun interfaces, install routes,
//! dial relays, spawn tasks, or wire itself into bootstrap. It only connects the
//! already fixed-side/fixed-session packet policy core to abstract interface and
//! relay traits so a future runtime can reuse one fail-closed forwarding shape.

use std::fmt;
use std::io;

use household_rs::claw_share_data_tunnel::TunnelFrame;
use household_rs::claw_vpn::{
    CLAW_VPN_V1_INNER_MTU, ClawVpnAgentSessionCore, ClawVpnAuditEvent, ClawVpnDatapathSide,
    ClawVpnSessionFrameError,
};

const CLAW_VPN_PACKET_PUMP_INTERFACE_READ_LEN: usize = CLAW_VPN_V1_INNER_MTU + 1;

pub trait ClawVpnPacketInterface {
    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()>;
}

pub trait ClawVpnPacketRelay {
    fn recv_frame(&mut self) -> io::Result<TunnelFrame>;
    fn send_frame(&mut self, frame: TunnelFrame) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClawVpnPacketPumpDirection {
    InterfaceToRelay,
    RelayToInterface,
}

#[derive(Clone, PartialEq, Eq)]
pub enum ClawVpnPacketPumpOutcome {
    Forwarded {
        direction: ClawVpnPacketPumpDirection,
        audit: ClawVpnAuditEvent,
        byte_count: usize,
    },
    Dropped {
        direction: ClawVpnPacketPumpDirection,
        audit: ClawVpnAuditEvent,
        error: ClawVpnSessionFrameError,
    },
}

impl fmt::Debug for ClawVpnPacketPumpOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Forwarded {
                direction,
                audit,
                byte_count,
            } => f
                .debug_struct("ClawVpnPacketPumpOutcome::Forwarded")
                .field("direction", direction)
                .field("audit", audit)
                .field("byte_count", byte_count)
                .finish(),
            Self::Dropped {
                direction,
                audit,
                error,
            } => f
                .debug_struct("ClawVpnPacketPumpOutcome::Dropped")
                .field("direction", direction)
                .field("audit", audit)
                .field("error", error)
                .finish(),
        }
    }
}

pub enum ClawVpnPacketPumpError {
    InterfaceRead { source: io::Error },
    InterfaceWrite { source: io::Error },
    RelayRead { source: io::Error },
    RelayWrite { source: io::Error },
}

impl fmt::Debug for ClawVpnPacketPumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InterfaceRead { .. } => f
                .debug_struct("ClawVpnPacketPumpError::InterfaceRead")
                .field("source", &"<redacted>")
                .finish(),
            Self::InterfaceWrite { .. } => f
                .debug_struct("ClawVpnPacketPumpError::InterfaceWrite")
                .field("source", &"<redacted>")
                .finish(),
            Self::RelayRead { .. } => f
                .debug_struct("ClawVpnPacketPumpError::RelayRead")
                .field("source", &"<redacted>")
                .finish(),
            Self::RelayWrite { .. } => f
                .debug_struct("ClawVpnPacketPumpError::RelayWrite")
                .field("source", &"<redacted>")
                .finish(),
        }
    }
}

pub struct ClawVpnPacketPump {
    core: ClawVpnAgentSessionCore,
    interface_read_buf: Vec<u8>,
}

impl fmt::Debug for ClawVpnPacketPump {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnPacketPump")
            .field("local_side", &self.core.local_side())
            .field("interface_read_buf_len", &self.interface_read_buf.len())
            .finish()
    }
}

impl ClawVpnPacketPump {
    #[must_use]
    pub fn new(core: ClawVpnAgentSessionCore) -> Self {
        Self {
            core,
            // Read one byte beyond the accepted inner MTU so an oversized
            // local packet cannot be truncated into an apparently valid packet
            // before the fixed-session core performs its MTU check.
            interface_read_buf: vec![0; CLAW_VPN_PACKET_PUMP_INTERFACE_READ_LEN],
        }
    }

    #[must_use]
    pub fn local_side(&self) -> ClawVpnDatapathSide {
        self.core.local_side()
    }

    pub fn pump_interface_to_relay_once(
        &mut self,
        interface: &mut impl ClawVpnPacketInterface,
        relay: &mut impl ClawVpnPacketRelay,
    ) -> Result<ClawVpnPacketPumpOutcome, ClawVpnPacketPumpError> {
        let len = interface
            .read_packet(&mut self.interface_read_buf)
            .map_err(|source| ClawVpnPacketPumpError::InterfaceRead { source })?;
        if len > self.interface_read_buf.len() {
            return Err(ClawVpnPacketPumpError::InterfaceRead {
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "interface read length exceeds buffer",
                ),
            });
        }
        let packet = &self.interface_read_buf[..len];
        let (frame, audit) = self.core.frame_from_interface_with_audit(packet);
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                return Ok(ClawVpnPacketPumpOutcome::Dropped {
                    direction: ClawVpnPacketPumpDirection::InterfaceToRelay,
                    audit,
                    error,
                });
            }
        };
        relay
            .send_frame(frame)
            .map_err(|source| ClawVpnPacketPumpError::RelayWrite { source })?;
        Ok(ClawVpnPacketPumpOutcome::Forwarded {
            direction: ClawVpnPacketPumpDirection::InterfaceToRelay,
            audit,
            byte_count: len,
        })
    }

    pub fn pump_relay_to_interface_once(
        &mut self,
        relay: &mut impl ClawVpnPacketRelay,
        interface: &mut impl ClawVpnPacketInterface,
    ) -> Result<ClawVpnPacketPumpOutcome, ClawVpnPacketPumpError> {
        let frame = relay
            .recv_frame()
            .map_err(|source| ClawVpnPacketPumpError::RelayRead { source })?;
        let (packet, audit) = self.core.packet_from_relay_with_audit(frame);
        let packet = match packet {
            Ok(packet) => packet,
            Err(error) => {
                return Ok(ClawVpnPacketPumpOutcome::Dropped {
                    direction: ClawVpnPacketPumpDirection::RelayToInterface,
                    audit,
                    error,
                });
            }
        };
        let byte_count = packet.as_bytes().len();
        interface
            .write_packet(packet.as_bytes())
            .map_err(|source| ClawVpnPacketPumpError::InterfaceWrite { source })?;
        Ok(ClawVpnPacketPumpOutcome::Forwarded {
            direction: ClawVpnPacketPumpDirection::RelayToInterface,
            audit,
            byte_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::claw_vpn::{
        ClawVpnAcl, ClawVpnAclKey, ClawVpnAgentCore, ClawVpnAuditReason, ClawVpnIpv4Pool,
        ClawVpnPacketPolicyError, ClawVpnSessionAddrs, ClawVpnSessionRegistry,
        ClawVpnValidatedPacketError,
    };
    use household_rs::keys::{IdentityKey, P256Keypair};
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;

    #[derive(Default)]
    struct FakeInterface {
        reads: VecDeque<Vec<u8>>,
        writes: Vec<Vec<u8>>,
        read_error: Option<io::Error>,
        write_error: Option<io::Error>,
    }

    impl FakeInterface {
        fn with_read(packet: Vec<u8>) -> Self {
            let mut reads = VecDeque::new();
            reads.push_back(packet);
            Self {
                reads,
                writes: Vec::new(),
                read_error: None,
                write_error: None,
            }
        }
    }

    impl ClawVpnPacketInterface for FakeInterface {
        fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if let Some(error) = self.read_error.take() {
                return Err(error);
            }
            let packet = self.reads.pop_front().unwrap_or_default();
            let len = packet.len().min(buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            Ok(len)
        }

        fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
            if let Some(error) = self.write_error.take() {
                return Err(error);
            }
            self.writes.push(packet.to_vec());
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeRelay {
        recv_frames: VecDeque<TunnelFrame>,
        sent_frames: Vec<TunnelFrame>,
        recv_error: Option<io::Error>,
        send_error: Option<io::Error>,
    }

    impl FakeRelay {
        fn with_recv(frame: TunnelFrame) -> Self {
            let mut recv_frames = VecDeque::new();
            recv_frames.push_back(frame);
            Self {
                recv_frames,
                sent_frames: Vec::new(),
                recv_error: None,
                send_error: None,
            }
        }
    }

    impl ClawVpnPacketRelay for FakeRelay {
        fn recv_frame(&mut self) -> io::Result<TunnelFrame> {
            if let Some(error) = self.recv_error.take() {
                return Err(error);
            }
            self.recv_frames
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "fake relay eof"))
        }

        fn send_frame(&mut self, frame: TunnelFrame) -> io::Result<()> {
            if let Some(error) = self.send_error.take() {
                return Err(error);
            }
            self.sent_frames.push(frame);
            Ok(())
        }
    }

    fn pump_with_addrs() -> (ClawVpnPacketPump, ClawVpnSessionAddrs) {
        let key = acl_key();
        let mut acl = ClawVpnAcl::new();
        assert!(acl.grant(key.clone()));
        let pool = ClawVpnIpv4Pool::try_new(Ipv4Addr::new(198, 18, 0, 0), 24).unwrap();
        let registry = ClawVpnSessionRegistry::new(acl, pool);
        let mut core = ClawVpnAgentCore::new(ClawVpnDatapathSide::Device, registry);
        let (session, open_event) = core.open_with_audit(&key);
        let session = session.unwrap();
        assert_eq!(open_event.reason(), ClawVpnAuditReason::SessionOpened);
        let addrs = session.addrs();
        let session_core = core.into_session_core(session.id()).unwrap();
        (ClawVpnPacketPump::new(session_core), addrs)
    }

    fn acl_key() -> ClawVpnAclKey {
        ClawVpnAclKey::try_new("member-m1", P256Keypair::generate().public(), "claw-a").unwrap()
    }

    fn packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        packet_with_len(src, dst, 20)
    }

    fn packet_with_len(src: Ipv4Addr, dst: Ipv4Addr, len: usize) -> Vec<u8> {
        let total_len = u16::try_from(len).expect("test packet length fits in IPv4 total length");
        let mut packet = vec![0u8; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet
    }

    #[test]
    fn packet_pump_forwards_valid_interface_packet_to_relay() {
        let (mut pump, addrs) = pump_with_addrs();
        let local_packet = packet(addrs.device(), addrs.claw());
        let mut interface = FakeInterface::with_read(local_packet.clone());
        let mut relay = FakeRelay::default();

        let outcome = pump
            .pump_interface_to_relay_once(&mut interface, &mut relay)
            .unwrap();

        assert_eq!(
            relay.sent_frames,
            vec![TunnelFrame::Data(local_packet.clone())]
        );
        let ClawVpnPacketPumpOutcome::Forwarded {
            direction,
            audit,
            byte_count,
        } = outcome
        else {
            panic!("forwarded packet expected");
        };
        assert_eq!(direction, ClawVpnPacketPumpDirection::InterfaceToRelay);
        assert_eq!(audit.reason(), ClawVpnAuditReason::FrameAccepted);
        assert_eq!(byte_count, local_packet.len());
    }

    #[test]
    fn packet_pump_drops_spoofed_interface_packet_without_relay_write() {
        let (mut pump, addrs) = pump_with_addrs();
        let spoofed = packet(addrs.claw(), addrs.device());
        let mut interface = FakeInterface::with_read(spoofed);
        let mut relay = FakeRelay::default();

        let outcome = pump
            .pump_interface_to_relay_once(&mut interface, &mut relay)
            .unwrap();

        let ClawVpnPacketPumpOutcome::Dropped { audit, error, .. } = outcome else {
            panic!("spoofed packet must be dropped");
        };
        assert_eq!(audit.reason(), ClawVpnAuditReason::PacketPolicyRejected);
        assert_eq!(
            error,
            ClawVpnSessionFrameError::Packet(ClawVpnValidatedPacketError::Policy(
                ClawVpnPacketPolicyError::SourceMismatch,
            ))
        );
        assert!(relay.sent_frames.is_empty());
    }

    #[test]
    fn packet_pump_drops_oversized_interface_packet_without_truncating_to_mtu() {
        let (mut pump, addrs) = pump_with_addrs();
        let oversized = packet_with_len(addrs.device(), addrs.claw(), CLAW_VPN_V1_INNER_MTU + 1);
        let mut interface = FakeInterface::with_read(oversized);
        let mut relay = FakeRelay::default();

        let outcome = pump
            .pump_interface_to_relay_once(&mut interface, &mut relay)
            .unwrap();

        let ClawVpnPacketPumpOutcome::Dropped { audit, error, .. } = outcome else {
            panic!("oversized packet must be dropped");
        };
        assert_eq!(audit.reason(), ClawVpnAuditReason::PacketTooLarge);
        assert_eq!(
            error,
            ClawVpnSessionFrameError::Packet(ClawVpnValidatedPacketError::PacketTooLarge)
        );
        assert!(relay.sent_frames.is_empty());
    }

    #[test]
    fn packet_pump_writes_valid_relay_frame_to_interface() {
        let (mut pump, addrs) = pump_with_addrs();
        let relay_packet = packet(addrs.claw(), addrs.device());
        let mut relay = FakeRelay::with_recv(TunnelFrame::Data(relay_packet.clone()));
        let mut interface = FakeInterface::default();

        let outcome = pump
            .pump_relay_to_interface_once(&mut relay, &mut interface)
            .unwrap();

        let ClawVpnPacketPumpOutcome::Forwarded {
            direction,
            audit,
            byte_count,
        } = outcome
        else {
            panic!("valid relay packet must be forwarded");
        };
        assert_eq!(direction, ClawVpnPacketPumpDirection::RelayToInterface);
        assert_eq!(audit.reason(), ClawVpnAuditReason::FrameAccepted);
        assert_eq!(byte_count, relay_packet.len());
        assert_eq!(interface.writes, vec![relay_packet]);
    }

    #[test]
    fn packet_pump_drops_control_frame_without_interface_write() {
        let (mut pump, _addrs) = pump_with_addrs();
        let mut relay = FakeRelay::with_recv(TunnelFrame::Close);
        let mut interface = FakeInterface::default();

        let outcome = pump
            .pump_relay_to_interface_once(&mut relay, &mut interface)
            .unwrap();

        let ClawVpnPacketPumpOutcome::Dropped { audit, error, .. } = outcome else {
            panic!("control frame must be dropped");
        };
        assert_eq!(audit.reason(), ClawVpnAuditReason::UnexpectedTunnelFrame);
        assert_eq!(
            error,
            ClawVpnSessionFrameError::Packet(ClawVpnValidatedPacketError::UnexpectedTunnelFrame)
        );
        assert!(interface.writes.is_empty());
    }

    #[test]
    fn packet_pump_io_errors_are_redacted_and_stop_before_forwarding() {
        let (mut pump, addrs) = pump_with_addrs();
        let local_packet = packet(addrs.device(), addrs.claw());
        let mut interface = FakeInterface::with_read(local_packet);
        let mut relay = FakeRelay {
            recv_frames: VecDeque::new(),
            sent_frames: Vec::new(),
            recv_error: None,
            send_error: Some(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "/tmp/private-relay-endpoint",
            )),
        };

        let error = pump
            .pump_interface_to_relay_once(&mut interface, &mut relay)
            .unwrap_err();
        let debug = format!("{error:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("/tmp/private-relay-endpoint"));
        assert!(relay.sent_frames.is_empty());
    }

    #[test]
    fn packet_pump_rejects_interface_read_len_larger_than_buffer() {
        struct MisreportingInterface;

        impl ClawVpnPacketInterface for MisreportingInterface {
            fn read_packet(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Ok(CLAW_VPN_PACKET_PUMP_INTERFACE_READ_LEN + 1)
            }

            fn write_packet(&mut self, _packet: &[u8]) -> io::Result<()> {
                panic!("test does not exercise interface writes");
            }
        }

        let (mut pump, _addrs) = pump_with_addrs();
        let mut interface = MisreportingInterface;
        let mut relay = FakeRelay::default();

        let error = pump
            .pump_interface_to_relay_once(&mut interface, &mut relay)
            .unwrap_err();
        let debug = format!("{error:?}");

        assert!(matches!(
            error,
            ClawVpnPacketPumpError::InterfaceRead { .. }
        ));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("interface read length exceeds buffer"));
        assert!(relay.sent_frames.is_empty());
    }

    #[test]
    fn packet_pump_debug_does_not_print_relation_or_address_material() {
        let (pump, addrs) = pump_with_addrs();
        let debug = format!("{pump:?}");

        assert!(!debug.contains("member-m1"));
        assert!(!debug.contains("claw-a"));
        assert!(!debug.contains(&addrs.device().to_string()));
        assert!(!debug.contains(&addrs.claw().to_string()));
        assert!(debug.contains("interface_read_buf_len"));
    }

    #[test]
    fn packet_pump_outcome_debug_does_not_print_packet_payload() {
        let (mut pump, addrs) = pump_with_addrs();
        let mut local_packet = packet_with_len(addrs.device(), addrs.claw(), 40);
        local_packet[20..].copy_from_slice(b"SECRET-PACKET-DATA!!");
        let mut interface = FakeInterface::with_read(local_packet);
        let mut relay = FakeRelay::default();

        let outcome = pump
            .pump_interface_to_relay_once(&mut interface, &mut relay)
            .unwrap();
        let debug = format!("{outcome:?}");

        assert!(!debug.contains("SECRET-PACKET-DATA!!"));
        assert!(!debug.contains(&addrs.device().to_string()));
        assert!(!debug.contains(&addrs.claw().to_string()));
        assert!(debug.contains("FrameAccepted"));
    }
}
