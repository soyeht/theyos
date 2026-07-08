//! Stateful, non-blocking length-prefixed frame codec for the per-Claw VPN
//! pollable datapath (T1 redesign).
//!
//! The relay leg of the datapath is a byte stream (`[4-byte BE len][payload]`
//! per [`TunnelFrame`]). On a **non-blocking** fd a read or write can return
//! `WouldBlock` *in the middle of a frame*; a `read_exact`/`write_all` adapter
//! would discard the partially transferred bytes and corrupt the stream. This
//! codec keeps that partial state across polls:
//!
//! - [`ClawVpnNonblockingFrameReader`] accumulates the length prefix and then
//!   the payload; `WouldBlock` returns `Pending` with the partial bytes kept.
//! - [`ClawVpnNonblockingFrameWriter`] holds a pending-byte queue so a partial
//!   write (or `WouldBlock`) never loses a frame.
//!
//! Fail-closed classification lives here for the framing layer: `WouldBlock`
//! is `Pending` (never fatal on its own, never counted as a transfer), while
//! EOF, an oversized length prefix, a decode failure, and any other I/O error
//! are fatal. The idle / partial-frame *budget* is enforced by the pump loop
//! (which owns the clock); this codec only reports whether it is mid-frame via
//! [`ClawVpnNonblockingFrameReader::is_mid_frame`].

use household_rs::claw_share_data_tunnel::{MAX_FRAME_LEN, TunnelFrame};
use std::collections::VecDeque;
use std::io::{self, Read, Write};

/// Bound on bytes buffered by the writer before it applies backpressure. A
/// small multiple of the max frame keeps memory bounded when the peer stalls.
pub(crate) const CLAW_VPN_NONBLOCKING_WRITE_QUEUE_LIMIT: usize = 4 * (MAX_FRAME_LEN + 4);

fn eof_error() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "relay stream closed mid-frame")
}

fn oversized_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "relay frame length exceeds maximum")
}

fn decode_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "relay frame failed to decode")
}

fn write_zero_error() -> io::Error {
    io::Error::new(io::ErrorKind::WriteZero, "relay stream accepted no bytes")
}

fn queue_full_error() -> io::Error {
    io::Error::other("relay write queue is full")
}

#[derive(Debug)]
enum ReadState {
    /// Accumulating the 4-byte big-endian length prefix.
    Len { buf: [u8; 4], filled: usize },
    /// Accumulating `payload` bytes of the declared length.
    Payload { payload: Vec<u8>, filled: usize },
}

/// Outcome of a non-blocking frame read.
#[derive(Debug)]
pub enum ClawVpnFrameReadProgress {
    /// A complete frame was decoded.
    Frame(TunnelFrame),
    /// Bytes were consumed but no frame is complete yet — the stream is live,
    /// just mid-frame. Distinguished from `Idle` so the pump does not treat a
    /// slow-but-advancing frame as a stall.
    Advanced,
    /// `WouldBlock` with no bytes consumed this call.
    Idle,
}

/// Stateful non-blocking reader for length-prefixed [`TunnelFrame`]s.
#[derive(Debug)]
pub struct ClawVpnNonblockingFrameReader {
    state: ReadState,
}

impl Default for ClawVpnNonblockingFrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl ClawVpnNonblockingFrameReader {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: ReadState::Len {
                buf: [0; 4],
                filled: 0,
            },
        }
    }

    /// `true` while a frame is partially read (length or payload started but
    /// not complete). The pump uses this to bound how long a partial frame may
    /// sit before it treats the stall as fatal.
    #[must_use]
    pub fn is_mid_frame(&self) -> bool {
        match &self.state {
            ReadState::Len { filled, .. } => *filled != 0,
            ReadState::Payload { .. } => true,
        }
    }

    /// Pull as much as the non-blocking `reader` currently offers.
    ///
    /// - `Ok(Frame(frame))` — a complete frame was decoded; internal state is
    ///   reset to read the next one.
    /// - `Ok(Advanced)` — bytes were consumed (partial state preserved) but no
    ///   frame is complete. The stream is live.
    /// - `Ok(Idle)` — `WouldBlock` with no bytes consumed this call.
    /// - `Err(_)` — fatal: EOF mid/at frame, oversized length, decode failure,
    ///   or any other I/O error.
    pub fn poll_read(
        &mut self,
        reader: &mut impl Read,
    ) -> io::Result<ClawVpnFrameReadProgress> {
        let mut advanced = false;
        loop {
            match &mut self.state {
                ReadState::Len { buf, filled } => match reader.read(&mut buf[*filled..]) {
                    Ok(0) => return Err(eof_error()),
                    Ok(n) => {
                        advanced = true;
                        *filled += n;
                        if *filled == 4 {
                            let len = u32::from_be_bytes(*buf) as usize;
                            if len == 0 || len > MAX_FRAME_LEN {
                                return Err(oversized_error());
                            }
                            self.state = ReadState::Payload {
                                payload: vec![0; len],
                                filled: 0,
                            };
                        }
                        // Loop to keep draining while the fd is ready.
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        return Ok(idle_or_advanced(advanced));
                    }
                    Err(error) => return Err(error),
                },
                ReadState::Payload { payload, filled } => {
                    match reader.read(&mut payload[*filled..]) {
                        Ok(0) => return Err(eof_error()),
                        Ok(n) => {
                            advanced = true;
                            *filled += n;
                            if *filled == payload.len() {
                                let frame = TunnelFrame::decode(payload.as_slice())
                                    .map_err(|_| decode_error())?;
                                self.state = ReadState::Len {
                                    buf: [0; 4],
                                    filled: 0,
                                };
                                return Ok(ClawVpnFrameReadProgress::Frame(frame));
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            return Ok(idle_or_advanced(advanced));
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }
}

fn idle_or_advanced(advanced: bool) -> ClawVpnFrameReadProgress {
    if advanced {
        ClawVpnFrameReadProgress::Advanced
    } else {
        ClawVpnFrameReadProgress::Idle
    }
}

/// Stateful non-blocking writer for length-prefixed [`TunnelFrame`]s. Frames
/// are serialized into a pending byte queue so a partial write never loses a
/// frame; the queue is bounded so a stalled peer applies backpressure instead
/// of growing memory without limit.
#[derive(Debug, Default)]
pub struct ClawVpnNonblockingFrameWriter {
    pending: VecDeque<u8>,
}

impl ClawVpnNonblockingFrameWriter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: VecDeque::new(),
        }
    }

    /// `true` while bytes remain to flush.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// `true` while the queue still has room for at least one more max-size
    /// frame. The pump uses this to apply backpressure — it stops reading the
    /// interface until the relay drains rather than growing memory or hitting
    /// the fatal queue-full guard.
    #[must_use]
    pub fn has_room(&self) -> bool {
        self.pending.len() + 4 + MAX_FRAME_LEN <= CLAW_VPN_NONBLOCKING_WRITE_QUEUE_LIMIT
    }

    /// Serialize `frame` into the pending queue. Fails (fatal) if the frame is
    /// oversized or the queue is full (backpressure — the caller must stop
    /// reading the other side until [`Self::poll_flush`] drains it).
    pub fn enqueue(&mut self, frame: &TunnelFrame) -> io::Result<()> {
        let payload = frame.encode();
        if payload.is_empty() || payload.len() > MAX_FRAME_LEN {
            return Err(oversized_error());
        }
        if self.pending.len() + 4 + payload.len() > CLAW_VPN_NONBLOCKING_WRITE_QUEUE_LIMIT {
            return Err(queue_full_error());
        }
        let len = u32::try_from(payload.len()).map_err(|_| oversized_error())?;
        self.pending.extend(len.to_be_bytes());
        self.pending.extend(payload);
        Ok(())
    }

    /// Flush as much of the pending queue as the non-blocking `writer` accepts.
    /// Returns the number of bytes flushed this call (0 on `WouldBlock` with a
    /// full queue — the caller uses this to tell progress from idle).
    ///
    /// - `Ok(n)` — flushed `n` bytes; check [`Self::has_pending`] for more.
    /// - `Err(_)` — fatal write error (including a zero-length accept).
    pub fn poll_flush(&mut self, writer: &mut impl Write) -> io::Result<usize> {
        let mut flushed = 0;
        while !self.pending.is_empty() {
            let front = self.pending.as_slices().0;
            match writer.write(front) {
                Ok(0) => return Err(write_zero_error()),
                Ok(n) => {
                    self.pending.drain(..n);
                    flushed += n;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(flushed),
                Err(error) => return Err(error),
            }
        }
        Ok(flushed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serves at most `per_read` bytes per successful `read`, then one
    /// `WouldBlock`, forcing the codec to preserve partial state across
    /// separate `poll_read` calls.
    struct DripReader {
        bytes: Vec<u8>,
        pos: usize,
        per_read: usize,
        block_next: bool,
    }

    impl DripReader {
        fn new(bytes: Vec<u8>, per_read: usize) -> Self {
            Self {
                bytes,
                pos: 0,
                per_read,
                block_next: false,
            }
        }
    }

    impl Read for DripReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.block_next {
                self.block_next = false;
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            if self.pos >= self.bytes.len() {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            let want = self
                .per_read
                .min(buf.len())
                .min(self.bytes.len() - self.pos);
            buf[..want].copy_from_slice(&self.bytes[self.pos..self.pos + want]);
            self.pos += want;
            self.block_next = true;
            Ok(want)
        }
    }

    /// Accepts at most `accept` bytes per `write`, then `WouldBlock`.
    struct ThrottledWriter {
        accepted: Vec<u8>,
        accept: usize,
    }

    impl ThrottledWriter {
        fn new(accept: usize) -> Self {
            Self {
                accepted: Vec::new(),
                accept,
            }
        }
    }

    impl Write for ThrottledWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let n = buf.len().min(self.accept);
            if n == 0 {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            self.accepted.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn encode_on_wire(frame: &TunnelFrame) -> Vec<u8> {
        let payload = frame.encode();
        let mut wire = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        wire.extend_from_slice(&payload);
        wire
    }

    fn sample_frame() -> TunnelFrame {
        TunnelFrame::Data(vec![0x45, 0x00, 0x00, 0x14, 0xDE, 0xAD])
    }

    #[test]
    fn reader_reassembles_frame_from_single_byte_drips() {
        let wire = encode_on_wire(&sample_frame());
        let mut reader = ClawVpnNonblockingFrameReader::new();
        let mut source = DripReader::new(wire.clone(), 1);
        let mut saw_mid_frame = false;
        let mut got = None;
        for _ in 0..(wire.len() + 4) {
            match reader.poll_read(&mut source).expect("no fatal error") {
                ClawVpnFrameReadProgress::Frame(frame) => {
                    got = Some(frame);
                    break;
                }
                ClawVpnFrameReadProgress::Advanced | ClawVpnFrameReadProgress::Idle => {
                    if reader.is_mid_frame() {
                        saw_mid_frame = true;
                    }
                }
            }
        }
        assert!(saw_mid_frame, "state machine must report partial progress");
        assert_eq!(
            got.as_ref().map(encode_on_wire),
            Some(wire),
            "frame reassembled byte-by-byte matches the original on the wire"
        );
    }

    #[test]
    fn reader_reports_mid_frame_until_complete() {
        let wire = encode_on_wire(&sample_frame());
        let mut reader = ClawVpnNonblockingFrameReader::new();
        // Feed only 3 of the 4 length bytes.
        let mut source = DripReader::new(wire[..3].to_vec(), 3);
        assert!(!reader.is_mid_frame());
        let out = reader.poll_read(&mut source).expect("partial ok");
        assert!(
            matches!(out, ClawVpnFrameReadProgress::Advanced),
            "3/4 length bytes consumed → advanced, not a frame"
        );
        assert!(reader.is_mid_frame(), "3/4 length bytes → mid-frame");
    }

    #[test]
    fn reader_rejects_oversized_length_prefix() {
        let oversized = u32::try_from(MAX_FRAME_LEN + 1).unwrap().to_be_bytes();
        let mut reader = ClawVpnNonblockingFrameReader::new();
        let mut source = DripReader::new(oversized.to_vec(), 4);
        let err = reader
            .poll_read(&mut source)
            .expect_err("oversized is fatal");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn reader_treats_eof_mid_frame_as_fatal() {
        // Serve all but the last byte, then EOF (Ok(0)).
        struct EofAfter {
            chunk: Vec<u8>,
            served: bool,
        }
        impl Read for EofAfter {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.served {
                    return Ok(0);
                }
                self.served = true;
                let n = self.chunk.len().min(buf.len());
                buf[..n].copy_from_slice(&self.chunk[..n]);
                Ok(n)
            }
        }

        let wire = encode_on_wire(&sample_frame());
        let mut reader = ClawVpnNonblockingFrameReader::new();
        let mut source = EofAfter {
            chunk: wire[..wire.len() - 1].to_vec(),
            served: false,
        };
        let err = reader
            .poll_read(&mut source)
            .expect_err("eof mid-frame is fatal");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn writer_preserves_frame_across_partial_writes() {
        let frame = sample_frame();
        let wire = encode_on_wire(&frame);
        let mut writer = ClawVpnNonblockingFrameWriter::new();
        writer.enqueue(&frame).expect("enqueue");
        assert!(writer.has_pending());
        let mut sink = ThrottledWriter::new(3);
        for _ in 0..(wire.len() + 4) {
            writer.poll_flush(&mut sink).expect("no fatal write error");
            if !writer.has_pending() {
                break;
            }
        }
        assert!(!writer.has_pending(), "fully flushed");
        assert_eq!(sink.accepted, wire, "bytes on the wire match the frame exactly");
    }

    #[test]
    fn writer_backpressures_when_queue_full() {
        // Large-but-not-oversized frames fill the bounded queue in a handful of
        // enqueues; the rejection must be queue-full backpressure, not oversized.
        let big = TunnelFrame::Data(vec![0u8; MAX_FRAME_LEN / 4]);
        let mut writer = ClawVpnNonblockingFrameWriter::new();
        let mut last_err_kind = None;
        for _ in 0..1000 {
            match writer.enqueue(&big) {
                Ok(()) => {}
                Err(error) => {
                    last_err_kind = Some(error.kind());
                    break;
                }
            }
        }
        assert_eq!(
            last_err_kind,
            Some(io::ErrorKind::Other),
            "bounded queue must apply backpressure (queue-full), not grow unbounded"
        );
    }
}
