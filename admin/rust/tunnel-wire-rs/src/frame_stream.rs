//! Stateful, non-blocking length-prefixed frame codec for a pollable datapath.
//!
//! S0: neutral. This is byte-stream framing and partial-transfer bookkeeping —
//! it decides nothing about who may do what, so it travels with the wire types
//! it is built on. Moved verbatim from `server-rs`'s per-Claw VPN datapath; the
//! only changes are the claw-scoped names and the import, which now names the
//! wire types directly instead of reaching them through a product re-export.
//!
//! The relay leg of the datapath is a byte stream (`[4-byte BE len][payload]`
//! per [`TunnelFrame`]). On a **non-blocking** fd a read or write can return
//! `WouldBlock` *in the middle of a frame*; a `read_exact`/`write_all` adapter
//! would discard the partially transferred bytes and corrupt the stream. This
//! codec keeps that partial state across polls:
//!
//! - [`NonblockingFrameReader`] accumulates the length prefix and then
//!   the payload; `WouldBlock` returns `Pending` with the partial bytes kept.
//! - [`NonblockingFrameWriter`] holds a pending-byte queue so a partial
//!   write (or `WouldBlock`) never loses a frame.
//!
//! Fail-closed classification lives here for the framing layer: `WouldBlock`
//! is `Pending` (never fatal on its own, never counted as a transfer), while
//! EOF, an oversized length prefix, a decode failure, and any other I/O error
//! are fatal. The idle / partial-frame *budget* is enforced by the pump loop
//! (which owns the clock); this codec only reports whether it is mid-frame via
//! [`NonblockingFrameReader::is_mid_frame`].

use crate::tunnel_wire::{MAX_FRAME_LEN, TunnelFrame};
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read, Write};

/// Bound on bytes buffered by the writer before it applies backpressure. A
/// small multiple of the max frame keeps memory bounded when the peer stalls.
pub(crate) const NONBLOCKING_WRITE_QUEUE_LIMIT: usize = 4 * (MAX_FRAME_LEN + 4);

// Diagnostic strings, made neutral in the S0 cutover. They said "relay stream"
// and "relay frame" — the Product A feature's own compound noun — and survived
// the rename pass because a rename pass covers IDENTIFIERS, not prose. An error
// message is as much a part of a crate's surface as a type name. Nothing asserts
// on these (checked across the tree), and they are diagnostics rather than wire
// bytes, so the text is the only thing that changes.
fn eof_error() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "stream closed mid-frame")
}

fn oversized_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "frame length exceeds maximum")
}

fn decode_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "frame failed to decode")
}

fn write_zero_error() -> io::Error {
    io::Error::new(io::ErrorKind::WriteZero, "stream accepted no bytes")
}

fn queue_full_error() -> io::Error {
    io::Error::other("write queue is full")
}

enum ReadState {
    /// Accumulating the 4-byte big-endian length prefix.
    Len { buf: [u8; 4], filled: usize },
    /// Accumulating `payload` bytes of the declared length.
    Payload { payload: Vec<u8>, filled: usize },
}

/// Outcome of a non-blocking frame read.
#[derive(Debug)]
pub enum FrameReadProgress {
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
pub struct NonblockingFrameReader {
    state: ReadState,
}

impl fmt::Debug for NonblockingFrameReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Structural state only — never the buffered payload bytes.
        let (state, filled, len) = match &self.state {
            ReadState::Len { filled, .. } => ("Len", *filled, 4usize),
            ReadState::Payload { payload, filled } => ("Payload", *filled, payload.len()),
        };
        f.debug_struct("NonblockingFrameReader")
            .field("state", &state)
            .field("filled", &filled)
            .field("len", &len)
            .finish_non_exhaustive()
    }
}

impl Default for NonblockingFrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl NonblockingFrameReader {
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
    pub fn poll_read(&mut self, reader: &mut impl Read) -> io::Result<FrameReadProgress> {
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
                                return Ok(FrameReadProgress::Frame(frame));
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

fn idle_or_advanced(advanced: bool) -> FrameReadProgress {
    if advanced {
        FrameReadProgress::Advanced
    } else {
        FrameReadProgress::Idle
    }
}

/// Stateful non-blocking writer for length-prefixed [`TunnelFrame`]s. Frames
/// are serialized into a pending byte queue so a partial write never loses a
/// frame; the queue is bounded so a stalled peer applies backpressure instead
/// of growing memory without limit.
/// Progress from one [`NonblockingFrameWriter::poll_flush`] call: bytes
/// written and, distinctly, the number of frames whose final byte crossed to
/// the fd this call. The pump counts a frame as forwarded only on delivery
/// (`frames_delivered`), never at enqueue.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlushProgress {
    pub bytes: usize,
    pub frames_delivered: usize,
}

#[derive(Default)]
pub struct NonblockingFrameWriter {
    pending: VecDeque<u8>,
    /// Wire length (4 + payload) of each not-yet-fully-flushed frame, in order.
    frame_lengths: VecDeque<usize>,
    /// Bytes of the current front frame already flushed.
    front_flushed: usize,
}

impl fmt::Debug for NonblockingFrameWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Counts only — never the buffered payload bytes.
        f.debug_struct("NonblockingFrameWriter")
            .field("pending_bytes", &self.pending.len())
            .field("pending_frames", &self.frame_lengths.len())
            .finish_non_exhaustive()
    }
}

impl NonblockingFrameWriter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        self.pending.len() + 4 + MAX_FRAME_LEN <= NONBLOCKING_WRITE_QUEUE_LIMIT
    }

    /// Serialize `frame` into the pending queue. Fails (fatal) if the frame is
    /// oversized or the queue is full (backpressure — the caller must stop
    /// reading the other side until [`Self::poll_flush`] drains it).
    pub fn enqueue(&mut self, frame: &TunnelFrame) -> io::Result<()> {
        let payload = frame.encode();
        if payload.is_empty() || payload.len() > MAX_FRAME_LEN {
            return Err(oversized_error());
        }
        if self.pending.len() + 4 + payload.len() > NONBLOCKING_WRITE_QUEUE_LIMIT {
            return Err(queue_full_error());
        }
        let len = u32::try_from(payload.len()).map_err(|_| oversized_error())?;
        let wire_len = 4 + payload.len();
        self.pending.extend(len.to_be_bytes());
        self.pending.extend(payload);
        self.frame_lengths.push_back(wire_len);
        Ok(())
    }

    /// Flush as much of the pending queue as the non-blocking `writer` accepts.
    /// Returns the number of bytes flushed this call (0 on `WouldBlock` with a
    /// full queue — the caller uses this to tell progress from idle).
    ///
    /// - `Ok(n)` — flushed `n` bytes; check [`Self::has_pending`] for more.
    /// - `Err(_)` — fatal write error (including a zero-length accept).
    pub fn poll_flush(&mut self, writer: &mut impl Write) -> io::Result<FlushProgress> {
        let mut progress = FlushProgress::default();
        while !self.pending.is_empty() {
            let front = self.pending.as_slices().0;
            match writer.write(front) {
                Ok(0) => return Err(write_zero_error()),
                Ok(n) => {
                    self.pending.drain(..n);
                    progress.bytes += n;
                    self.advance_frame_boundaries(n, &mut progress.frames_delivered);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(progress),
                Err(error) => return Err(error),
            }
        }
        Ok(progress)
    }

    /// Advance `front_flushed` / pop completed frames as `flushed` bytes leave
    /// the front of the queue, counting each frame whose final byte crossed.
    fn advance_frame_boundaries(&mut self, flushed: usize, frames_delivered: &mut usize) {
        let mut remaining = flushed;
        while remaining > 0 {
            let front_len = *self
                .frame_lengths
                .front()
                .expect("frame_lengths tracks every pending byte");
            let needed = front_len - self.front_flushed;
            if remaining >= needed {
                *frames_delivered += 1;
                self.frame_lengths.pop_front();
                self.front_flushed = 0;
                remaining -= needed;
            } else {
                self.front_flushed += remaining;
                remaining = 0;
            }
        }
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
        let mut reader = NonblockingFrameReader::new();
        let mut source = DripReader::new(wire.clone(), 1);
        let mut saw_mid_frame = false;
        let mut got = None;
        for _ in 0..(wire.len() + 4) {
            match reader.poll_read(&mut source).expect("no fatal error") {
                FrameReadProgress::Frame(frame) => {
                    got = Some(frame);
                    break;
                }
                FrameReadProgress::Advanced | FrameReadProgress::Idle => {
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
        let mut reader = NonblockingFrameReader::new();
        // Feed only 3 of the 4 length bytes.
        let mut source = DripReader::new(wire[..3].to_vec(), 3);
        assert!(!reader.is_mid_frame());
        let out = reader.poll_read(&mut source).expect("partial ok");
        assert!(
            matches!(out, FrameReadProgress::Advanced),
            "3/4 length bytes consumed → advanced, not a frame"
        );
        assert!(reader.is_mid_frame(), "3/4 length bytes → mid-frame");
    }

    #[test]
    fn reader_rejects_oversized_length_prefix() {
        let oversized = u32::try_from(MAX_FRAME_LEN + 1).unwrap().to_be_bytes();
        let mut reader = NonblockingFrameReader::new();
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
        let mut reader = NonblockingFrameReader::new();
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
        let mut writer = NonblockingFrameWriter::new();
        writer.enqueue(&frame).expect("enqueue");
        assert!(writer.has_pending());
        let mut sink = ThrottledWriter::new(3);
        let mut delivered = 0;
        for _ in 0..(wire.len() + 4) {
            delivered += writer
                .poll_flush(&mut sink)
                .expect("no fatal write error")
                .frames_delivered;
            if !writer.has_pending() {
                break;
            }
        }
        assert!(!writer.has_pending(), "fully flushed");
        assert_eq!(
            sink.accepted, wire,
            "bytes on the wire match the frame exactly"
        );
        assert_eq!(
            delivered, 1,
            "exactly one frame delivered, counted on completion"
        );
    }

    #[test]
    fn writer_reports_no_delivery_until_frame_completes() {
        // A sink that accepts up to `budget` bytes total, then WouldBlock — the
        // frame's last byte never crosses, so no delivery is counted. This is
        // the fail-closed check against forwarding overclaim: bytes may leave
        // but a frame is "forwarded" only when it fully crosses.
        struct StallAfter {
            budget: usize,
        }
        impl Write for StallAfter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if self.budget == 0 {
                    return Err(io::Error::from(io::ErrorKind::WouldBlock));
                }
                let n = buf.len().min(self.budget);
                self.budget -= n;
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let frame = sample_frame();
        let wire = encode_on_wire(&frame);
        let mut writer = NonblockingFrameWriter::new();
        writer.enqueue(&frame).expect("enqueue");
        let mut sink = StallAfter {
            budget: wire.len() - 1,
        };
        let progress = writer.poll_flush(&mut sink).expect("partial write ok");
        assert_eq!(progress.bytes, wire.len() - 1, "partial bytes went out");
        assert_eq!(
            progress.frames_delivered, 0,
            "an incomplete frame is NOT counted as delivered"
        );
        assert!(writer.has_pending(), "the final byte is still queued");
    }

    #[test]
    fn writer_backpressures_when_queue_full() {
        // Large-but-not-oversized frames fill the bounded queue in a handful of
        // enqueues; the rejection must be queue-full backpressure, not oversized.
        let big = TunnelFrame::Data(vec![0u8; MAX_FRAME_LEN / 4]);
        let mut writer = NonblockingFrameWriter::new();
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
