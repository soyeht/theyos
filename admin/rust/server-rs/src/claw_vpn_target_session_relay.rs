//! Inert bridge between a `relay_stream` target session and the per-Claw VPN relay.
//!
//! This module does not mount the `IpTunnel` backend, open TUN/utun devices,
//! install routes, dial sockets, spawn work, read flags, or run the packet pump.
//! It only creates a local socketpair so a future owner-reviewed caller can
//! return one async byte-stream side as a `TargetSession` while the synchronous
//! packet pump owns the other side through the already-reviewed
//! `ClawVpnRelayStream` frame adapter.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::time::Duration;

use household_rs::claw_share_data_tunnel::TargetSession;
use tokio::net::UnixStream as TokioUnixStream;

use crate::claw_vpn_pollable_pump::ClawVpnPollablePacketRelay;
use crate::claw_vpn_relay_stream::ClawVpnRelayStream;

pub struct ClawVpnTargetSessionRelayPair {
    target_session: TargetSession,
    relay: ClawVpnRelayStream<StdUnixStream>,
}

impl ClawVpnTargetSessionRelayPair {
    pub fn new(io_timeout: Duration) -> io::Result<Self> {
        if io_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "target session relay timeout must be non-zero",
            ));
        }

        let (target_side, relay_side) = StdUnixStream::pair()?;
        relay_side.set_read_timeout(Some(io_timeout))?;
        relay_side.set_write_timeout(Some(io_timeout))?;
        target_side.set_nonblocking(true)?;

        let target_stream = TokioUnixStream::from_std(target_side)?;
        Ok(Self {
            target_session: TargetSession::from_stream(target_stream),
            relay: ClawVpnRelayStream::new(relay_side),
        })
    }

    #[must_use]
    pub fn into_parts(self) -> (TargetSession, ClawVpnRelayStream<StdUnixStream>) {
        (self.target_session, self.relay)
    }

    /// Pollable variant for the non-blocking datapath: the relay side is set
    /// `O_NONBLOCK` (no blocking read/write timeout) and returned as a raw
    /// byte-stream relay the pollable pump drives through its own stateful
    /// codec. The target side stays the async `TargetSession` for the tunnel
    /// pipe.
    pub fn new_pollable() -> io::Result<(TargetSession, ClawVpnPollableTargetSessionRelay)> {
        let (target_side, relay_side) = StdUnixStream::pair()?;
        relay_side.set_nonblocking(true)?;
        target_side.set_nonblocking(true)?;
        let target_stream = TokioUnixStream::from_std(target_side)?;
        Ok((
            TargetSession::from_stream(target_stream),
            ClawVpnPollableTargetSessionRelay { stream: relay_side },
        ))
    }
}

/// The relay side of a pollable target-session socketpair: a raw non-blocking
/// byte stream the pollable pump drives through its stateful frame codec.
pub struct ClawVpnPollableTargetSessionRelay {
    stream: StdUnixStream,
}

impl fmt::Debug for ClawVpnPollableTargetSessionRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnPollableTargetSessionRelay")
            .field("fd", &"<redacted>")
            .finish()
    }
}

impl Read for ClawVpnPollableTargetSessionRelay {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for ClawVpnPollableTargetSessionRelay {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl ClawVpnPollablePacketRelay for ClawVpnPollableTargetSessionRelay {
    fn relay_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}

impl fmt::Debug for ClawVpnTargetSessionRelayPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnTargetSessionRelayPair")
            .field("target_session", &"<redacted>")
            .field("relay", &self.relay)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::claw_share_data_tunnel::TunnelFrame;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::claw_vpn_packet_pump::ClawVpnPacketRelay;

    fn framed_payload(payload: &[u8]) -> Vec<u8> {
        let mut framed = Vec::new();
        framed.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("test payload length fits u32")
                .to_be_bytes(),
        );
        framed.extend_from_slice(payload);
        framed
    }

    #[tokio::test]
    async fn target_session_side_receives_length_prefixed_frames_from_relay() {
        let pair = ClawVpnTargetSessionRelayPair::new(Duration::from_secs(1)).expect("build pair");
        let (mut target_session, mut relay) = pair.into_parts();
        let packet = b"relay-to-target-session".to_vec();
        let frame = TunnelFrame::Data(packet.clone());
        let payload = frame.encode();

        relay.send_frame(frame).expect("send frame");

        let mut len_buf = [0u8; 4];
        target_session
            .reader
            .read_exact(&mut len_buf)
            .await
            .expect("read frame length");
        let len = u32::from_be_bytes(len_buf) as usize;
        assert_eq!(len, payload.len());
        let mut received = vec![0; len];
        target_session
            .reader
            .read_exact(&mut received)
            .await
            .expect("read frame payload");
        assert_eq!(
            TunnelFrame::decode(&received).expect("decode target-session payload"),
            TunnelFrame::Data(packet)
        );
    }

    #[tokio::test]
    async fn relay_receives_length_prefixed_frames_from_target_session_side() {
        let pair = ClawVpnTargetSessionRelayPair::new(Duration::from_secs(1)).expect("build pair");
        let (mut target_session, mut relay) = pair.into_parts();
        let packet = b"target-session-to-relay".to_vec();
        let payload = TunnelFrame::Data(packet.clone()).encode();
        let framed = framed_payload(&payload);

        target_session
            .writer
            .write_all(&framed)
            .await
            .expect("write frame");
        target_session.writer.flush().await.expect("flush frame");

        assert_eq!(
            relay.recv_frame().expect("recv frame"),
            TunnelFrame::Data(packet)
        );
    }

    #[tokio::test]
    async fn relay_read_timeout_is_finite_and_static() {
        let pair =
            ClawVpnTargetSessionRelayPair::new(Duration::from_millis(20)).expect("build pair");
        let (_target_session, mut relay) = pair.into_parts();

        let err = relay.recv_frame().expect_err("idle read times out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(!err.to_string().contains("target_session"));
        assert!(!err.to_string().contains("UnixStream"));
    }

    #[test]
    fn target_session_relay_pair_rejects_zero_timeout() {
        let err =
            ClawVpnTargetSessionRelayPair::new(Duration::ZERO).expect_err("zero timeout rejected");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn target_session_relay_pair_debug_redacts_session() {
        let pair = ClawVpnTargetSessionRelayPair::new(Duration::from_secs(1)).expect("build pair");
        let debug = format!("{pair:?}");

        assert!(debug.contains("ClawVpnTargetSessionRelayPair"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("reader"));
        assert!(!debug.contains("writer"));
    }
}
