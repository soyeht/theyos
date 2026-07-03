//! Synchronous relay-frame adapter for the Product A per-Claw VPN packet pump.
//!
//! This module does not dial a relay, authenticate a session, open sockets,
//! spawn tasks, read flags, or wire itself into startup. It only adapts an
//! already-established length-prefixed `TunnelFrame` stream to the packet-pump
//! relay trait so a future owner-reviewed caller can compose the concrete
//! stream without duplicating frame parsing.

use std::fmt;
use std::io::{self, Read, Write};

use household_rs::claw_share_data_tunnel::{MAX_FRAME_LEN, TunnelFrame};

use crate::claw_vpn_packet_pump::ClawVpnPacketRelay;

pub struct ClawVpnRelayStream<S> {
    stream: S,
}

impl<S> ClawVpnRelayStream<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }
}

impl<S> fmt::Debug for ClawVpnRelayStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnRelayStream")
            .field("stream", &"<redacted>")
            .finish()
    }
}

impl<S> ClawVpnPacketRelay for ClawVpnRelayStream<S>
where
    S: Read + Write,
{
    fn recv_frame(&mut self) -> io::Result<TunnelFrame> {
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .map_err(|_| relay_closed_error())?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_LEN {
            return Err(frame_too_large_error());
        }

        let mut payload = vec![0u8; len];
        self.stream
            .read_exact(&mut payload)
            .map_err(|_| relay_closed_error())?;
        TunnelFrame::decode(&payload).map_err(|_| frame_decode_error())
    }

    fn send_frame(&mut self, frame: TunnelFrame) -> io::Result<()> {
        let payload = frame.encode();
        if payload.len() > MAX_FRAME_LEN {
            return Err(frame_too_large_error());
        }
        let len = u32::try_from(payload.len()).map_err(|_| frame_too_large_error())?;
        self.stream
            .write_all(&len.to_be_bytes())
            .map_err(|_| relay_write_error())?;
        self.stream
            .write_all(&payload)
            .map_err(|_| relay_write_error())?;
        self.stream.flush().map_err(|_| relay_write_error())
    }
}

fn relay_closed_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "relay stream closed before frame completed",
    )
}

fn relay_write_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "relay stream write failed before frame completed",
    )
}

fn frame_too_large_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "relay frame exceeds maximum length",
    )
}

fn frame_decode_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "relay frame decode failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Cursor;

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

    #[test]
    fn relay_stream_sends_length_prefixed_tunnel_frames() {
        let packet = b"SECRET-PACKET-BYTES".to_vec();
        let mut relay = ClawVpnRelayStream::new(Cursor::new(Vec::new()));

        relay
            .send_frame(TunnelFrame::Data(packet.clone()))
            .expect("send frame");

        let written = relay.stream.into_inner();
        let len = u32::from_be_bytes(written[..4].try_into().expect("length prefix")) as usize;
        assert_eq!(len, written.len() - 4);
        assert_eq!(
            TunnelFrame::decode(&written[4..]).expect("decode written frame"),
            TunnelFrame::Data(packet)
        );
    }

    #[test]
    fn relay_stream_receives_length_prefixed_tunnel_frames() {
        let packet = b"relay-to-interface".to_vec();
        let payload = TunnelFrame::Data(packet.clone()).encode();
        let stream = Cursor::new(framed_payload(&payload));
        let mut relay = ClawVpnRelayStream::new(stream);

        assert_eq!(
            relay.recv_frame().expect("recv frame"),
            TunnelFrame::Data(packet)
        );
    }

    #[test]
    fn relay_stream_rejects_oversized_frames_before_reading_payload() {
        struct LengthOnlyStream<'a> {
            bytes: [u8; 4],
            offset: usize,
            payload_read_attempted: &'a Cell<bool>,
        }

        impl Read for LengthOnlyStream<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.offset < self.bytes.len() {
                    let remaining = &self.bytes[self.offset..];
                    let len = remaining.len().min(buf.len());
                    buf[..len].copy_from_slice(&remaining[..len]);
                    self.offset += len;
                    return Ok(len);
                }
                self.payload_read_attempted.set(true);
                Ok(0)
            }
        }

        impl Write for LengthOnlyStream<'_> {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Ok(0)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let payload_read_attempted = Cell::new(false);
        let oversized = u32::try_from(MAX_FRAME_LEN + 1)
            .expect("oversized test length fits u32")
            .to_be_bytes();
        let mut relay = ClawVpnRelayStream::new(LengthOnlyStream {
            bytes: oversized,
            offset: 0,
            payload_read_attempted: &payload_read_attempted,
        });

        let err = relay.recv_frame().expect_err("oversized frame rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!payload_read_attempted.get());
    }

    #[test]
    fn relay_stream_reports_decode_errors_without_payload_material() {
        let secret = b"SECRET-FRAME-PAYLOAD";
        let mut payload = vec![0xff];
        payload.extend_from_slice(secret);
        let mut relay = ClawVpnRelayStream::new(Cursor::new(framed_payload(&payload)));

        let err = relay.recv_frame().expect_err("invalid frame rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!err.to_string().contains("SECRET-FRAME-PAYLOAD"));
    }

    #[test]
    fn relay_stream_reports_write_errors_without_stream_material() {
        struct FailingWriteStream;

        impl Read for FailingWriteStream {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Ok(0)
            }
        }

        impl Write for FailingWriteStream {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::Other, "SECRET-STREAM-DETAIL"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut relay = ClawVpnRelayStream::new(FailingWriteStream);
        let err = relay
            .send_frame(TunnelFrame::Data(b"SECRET-PACKET".to_vec()))
            .expect_err("write error rejected");

        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert!(!err.to_string().contains("SECRET-STREAM-DETAIL"));
        assert!(!err.to_string().contains("SECRET-PACKET"));
    }

    #[test]
    fn relay_stream_debug_redacts_stream_without_stream_debug_bound() {
        struct SecretStream;

        impl Read for SecretStream {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Ok(0)
            }
        }

        impl Write for SecretStream {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let debug = format!("{:?}", ClawVpnRelayStream::new(SecretStream));
        assert!(debug.contains("ClawVpnRelayStream"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("SecretStream"));
    }
}
