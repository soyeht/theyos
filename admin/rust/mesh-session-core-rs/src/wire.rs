//! Wire framing (Fila 1 item 1).
//!
//! Two layers, per B-SESSAO v6 §1/§3:
//! - Outer: every Noise flight/record is `[4 bytes BE length][bytes]`. The
//!   declared length is checked against a ceiling *before* any buffer sized
//!   by it is allocated, so a malicious peer cannot force a multi-GiB
//!   allocation with a forged length prefix (RED-44).
//! - Inner (post-handshake plaintext only): `[type_byte: u8][body: CBOR
//!   canonical map]`. The type byte lives outside the CBOR; the body map
//!   must not itself contain a `"type"` key (RED-34..39).
//!
//! **Hardened 2026-08-04, independent audit of `911409eb`:**
//! - The generic `max_len`-parameterized framing functions are now
//!   `pub(crate)` — nothing outside this crate can call them with an
//!   arbitrary (possibly wrong, possibly attacker-influenced-by-accident)
//!   ceiling. The four purpose-named entry points, each with its ceiling
//!   baked in as a constant, are `pub(crate)` too (2026-08-04, @kiana:
//!   nothing production-facing exists yet, matching `auth_state_machine`'s
//!   own `pub(crate)` posture pending real D-1/D-9).
//! - `encode_typed_frame` now requires the body to already be canonical CBOR
//!   (checked via `cbor::verify_canonical`, not assumed) and within the
//!   frozen `MAX_CBOR_BODY_LEN` (65_518) ceiling *before* framing it — the
//!   original silently framed whatever bytes it was given.
//! - `decode_typed_frame` checks the body length against the same ceiling
//!   *before* parsing it as CBOR, and is now `pub(crate)`: the public
//!   decode surface for real frames is `auth_frames::decode_auth_frame`,
//!   which returns a closed `AuthFrame` enum over exactly the 5 known type
//!   bytes rather than a raw `(u8, &[u8])` a caller could mishandle.
//!
//! **`DeadlineBoundedIo` (2026-08-04, @kiana, D9 carrier-B erratum1 E3,
//! definitive):** `pub(crate)` — sealed against external no-op
//! implementations that would defeat the whole point. Every read/write in
//! this crate goes through an explicit byte-by-byte loop (never
//! `read_exact`/`write_all`, which hide however many underlying syscalls
//! they need behind one call) so the deadline is recomputed against the
//! same monotonic [`crate::ingress::CeremonyDeadline`] before *every*
//! individual syscall, not once per logical frame. `arm_io_deadline`
//! returns `io::Result<()>`; a real `setsockopt` failure propagates as an
//! error (fails closed), never silently ignored.

use std::io::{Read, Write};
use std::time::Duration;

use crate::cbor;
use crate::error::WireError;
use crate::ingress::CeremonyDeadline;

/// Arms exactly the *next* blocking read/write call with a remaining-time
/// budget. `pub(crate)`: only this crate's own `TcpStream`/in-memory
/// implementations exist — an external crate cannot implement a no-op
/// version and silently defeat the deadline.
///
/// **`clear_io_deadline` (2026-08-04, @kiana, lifecycle CFX):** a real
/// `TcpStream`'s `SO_RCVTIMEO`/`SO_SNDTIMEO` are socket-level options that
/// persist across `arm_io_deadline` calls — they do not expire or reset
/// themselves once the ceremony that armed them ends. Without an explicit
/// clear, a freshly `Active` session would silently inherit whatever
/// (possibly tiny, possibly already near-zero) timeout the *last* ceremony
/// syscall happened to arm, and every later DATA/CLOSE/rekey read or write
/// on that same socket would be bounded by a budget that was never meant
/// to apply to them. `auth_state_machine` calls this exactly once, right
/// before exposing an `ActiveMeshSession`, and refuses to return the
/// session at all if clearing fails (see its construction site) — see
/// [`Self::arm_io_deadline`]'s sibling method.
pub(crate) trait DeadlineBoundedIo {
    fn arm_io_deadline(&mut self, remaining: Duration) -> std::io::Result<()>;
    /// Removes any per-call deadline previously armed, restoring
    /// unbounded (blocking-forever, at this layer) I/O. Called exactly
    /// once, at the ceremony→Active transition boundary.
    fn clear_io_deadline(&mut self) -> std::io::Result<()>;
}

impl DeadlineBoundedIo for std::net::TcpStream {
    fn arm_io_deadline(&mut self, remaining: Duration) -> std::io::Result<()> {
        // `remaining` is always > 0 here (callers check `is_zero()` first)
        // — `set_read_timeout`/`set_write_timeout` themselves error on a
        // zero `Duration`, so this ordering also avoids that failure mode
        // on the boundary case rather than working around it.
        self.set_read_timeout(Some(remaining))?;
        self.set_write_timeout(Some(remaining))?;
        Ok(())
    }
    fn clear_io_deadline(&mut self) -> std::io::Result<()> {
        self.set_read_timeout(None)?;
        self.set_write_timeout(None)?;
        Ok(())
    }
}

impl<T> DeadlineBoundedIo for std::io::Cursor<T> {
    fn arm_io_deadline(&mut self, _remaining: Duration) -> std::io::Result<()> {
        Ok(()) // in-memory, never blocks — nothing to bound
    }
    fn clear_io_deadline(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl DeadlineBoundedIo for Vec<u8> {
    fn arm_io_deadline(&mut self, _remaining: Duration) -> std::io::Result<()> {
        Ok(())
    }
    fn clear_io_deadline(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Ceiling for a single length-prefixed frame during the Noise handshake.
/// Snow XX handshake messages are always well under this; it exists purely
/// as a pre-allocation DoS guard against a forged length prefix.
pub const MAX_NOISE_HANDSHAKE_MESSAGE_LEN: u32 = 65_535;

/// Ceiling for a post-handshake Noise transport record (ciphertext,
/// including the Poly1305 tag).
pub const MAX_NOISE_RECORD_LEN: u32 = 65_535;
pub const POLY1305_TAG_LEN: u32 = 16;
/// Maximum plaintext recovered from one transport record.
pub const MAX_PLAINTEXT_LEN: u32 = MAX_NOISE_RECORD_LEN - POLY1305_TAG_LEN;
const TYPE_BYTE_LEN: u32 = 1;
/// Maximum canonical-CBOR body inside one post-handshake plaintext frame.
pub const MAX_CBOR_BODY_LEN: u32 = MAX_PLAINTEXT_LEN - TYPE_BYTE_LEN;

/// Fill `buf` completely, one syscall at a time, re-arming the deadline
/// fresh before each one (2026-08-04, @kiana: "não uma chamada read_exact
/// ... que esconde múltiplos syscalls"). Zero remaining budget fails
/// closed *before* attempting the syscall, not after it hangs.
fn read_exact_with_deadline<R: Read + DeadlineBoundedIo>(
    r: &mut R,
    buf: &mut [u8],
    deadline: &CeremonyDeadline,
) -> Result<(), WireError> {
    let mut filled = 0;
    while filled < buf.len() {
        let remaining = deadline.remaining();
        if remaining.is_zero() {
            return Err(WireError::DeadlineExceeded);
        }
        r.arm_io_deadline(remaining)
            .map_err(|_| WireError::DeadlineArmingFailed)?;
        let n = r.read(&mut buf[filled..])?;
        if n == 0 {
            return Err(WireError::Io(std::io::Error::from(
                std::io::ErrorKind::UnexpectedEof,
            )));
        }
        filled += n;
        // 2026-08-04, @kiana, WIP audit (a): the armed read timeout
        // bounds how long the syscall itself may block, but does not
        // PROVE it returned before the deadline — a syscall that raced
        // right up against the armed timeout (or a misbehaving/test
        // implementation that ignores it) could still hand back a full
        // read after the real budget was already exhausted. Recheck
        // immediately after EVERY syscall, including the one that just
        // completed the buffer — not only before starting the next one.
        if deadline.is_expired() {
            return Err(WireError::DeadlineExceeded);
        }
    }
    Ok(())
}

/// Write all of `buf`, one syscall at a time — see
/// [`read_exact_with_deadline`].
fn write_all_with_deadline<W: Write + DeadlineBoundedIo>(
    w: &mut W,
    mut buf: &[u8],
    deadline: &CeremonyDeadline,
) -> Result<(), WireError> {
    while !buf.is_empty() {
        let remaining = deadline.remaining();
        if remaining.is_zero() {
            return Err(WireError::DeadlineExceeded);
        }
        w.arm_io_deadline(remaining)
            .map_err(|_| WireError::DeadlineArmingFailed)?;
        let n = w.write(buf)?;
        if n == 0 {
            return Err(WireError::Io(std::io::Error::from(
                std::io::ErrorKind::WriteZero,
            )));
        }
        buf = &buf[n..];
        // 2026-08-04, @kiana, WIP audit (a) — see the identical note in
        // `read_exact_with_deadline`: recheck immediately after EVERY
        // syscall, including the final one that empties `buf`.
        if deadline.is_expired() {
            return Err(WireError::DeadlineExceeded);
        }
    }
    Ok(())
}

/// Read one `[4-byte BE length][bytes]` frame from `r`. Internal building
/// block only — see the module-level hardening note for why the public
/// surface is the four fixed-ceiling wrappers below instead of this
/// directly.
///
/// The length prefix is validated against `max_len` before any
/// length-sized buffer is allocated. Fragmented/short reads are handled
/// transparently by the explicit loop in [`read_exact_with_deadline`]; a
/// `Read` that coalesces multiple frames into one underlying buffer works
/// too, because only the bytes belonging to this one frame are ever
/// consumed.
pub(crate) fn read_length_prefixed_frame<R: Read + DeadlineBoundedIo>(
    r: &mut R,
    max_len: u32,
    deadline: &CeremonyDeadline,
) -> Result<Vec<u8>, WireError> {
    let mut len_buf = [0u8; 4];
    read_exact_with_deadline(r, &mut len_buf, deadline)?;
    let declared = u32::from_be_bytes(len_buf);
    if declared > max_len {
        return Err(WireError::OversizeFrame {
            declared,
            max: max_len,
        });
    }
    let mut body = vec![0u8; declared as usize];
    read_exact_with_deadline(r, &mut body, deadline)?;
    Ok(body)
}

/// Write one `[4-byte BE length][bytes]` frame to `w`. Internal building
/// block only — see [`read_length_prefixed_frame`].
pub(crate) fn write_length_prefixed_frame<W: Write + DeadlineBoundedIo>(
    w: &mut W,
    body: &[u8],
    max_len: u32,
    deadline: &CeremonyDeadline,
) -> Result<(), WireError> {
    let declared = u32::try_from(body.len()).map_err(|_| WireError::OversizeFrame {
        declared: u32::MAX,
        max: max_len,
    })?;
    if declared > max_len {
        return Err(WireError::OversizeFrame {
            declared,
            max: max_len,
        });
    }
    write_all_with_deadline(w, &declared.to_be_bytes(), deadline)?;
    write_all_with_deadline(w, body, deadline)?;
    Ok(())
}

/// Read one Noise handshake flight. Ceiling fixed at
/// `MAX_NOISE_HANDSHAKE_MESSAGE_LEN` — not a parameter. `deadline`
/// (2026-08-04, @kiana, erratum1 E3) bounds every individual syscall this
/// makes — see [`DeadlineBoundedIo`].
pub(crate) fn read_handshake_flight<R: Read + DeadlineBoundedIo>(
    r: &mut R,
    deadline: &CeremonyDeadline,
) -> Result<Vec<u8>, WireError> {
    read_length_prefixed_frame(r, MAX_NOISE_HANDSHAKE_MESSAGE_LEN, deadline)
}

/// Write one Noise handshake flight. Ceiling fixed at
/// `MAX_NOISE_HANDSHAKE_MESSAGE_LEN` — not a parameter.
pub(crate) fn write_handshake_flight<W: Write + DeadlineBoundedIo>(
    w: &mut W,
    body: &[u8],
    deadline: &CeremonyDeadline,
) -> Result<(), WireError> {
    write_length_prefixed_frame(w, body, MAX_NOISE_HANDSHAKE_MESSAGE_LEN, deadline)
}

/// Read one post-handshake Noise transport record (ciphertext). Ceiling
/// fixed at `MAX_NOISE_RECORD_LEN` — not a parameter.
pub(crate) fn read_transport_record<R: Read + DeadlineBoundedIo>(
    r: &mut R,
    deadline: &CeremonyDeadline,
) -> Result<Vec<u8>, WireError> {
    read_length_prefixed_frame(r, MAX_NOISE_RECORD_LEN, deadline)
}

/// Write one post-handshake Noise transport record (ciphertext). Ceiling
/// fixed at `MAX_NOISE_RECORD_LEN` — not a parameter.
pub(crate) fn write_transport_record<W: Write + DeadlineBoundedIo>(
    w: &mut W,
    body: &[u8],
    deadline: &CeremonyDeadline,
) -> Result<(), WireError> {
    write_length_prefixed_frame(w, body, MAX_NOISE_RECORD_LEN, deadline)
}

/// Build a post-handshake plaintext frame: `[type_byte][canonical CBOR
/// body]`. `body_cbor` must already be canonical CBOR (checked) of a map
/// that does not contain a `"type"` key (checked) and must fit within
/// `MAX_CBOR_BODY_LEN` (checked, before any frame is built).
pub(crate) fn encode_typed_frame(type_byte: u8, body_cbor: &[u8]) -> Result<Vec<u8>, WireError> {
    if body_cbor.len() as u32 > MAX_CBOR_BODY_LEN {
        return Err(WireError::OversizeFrame {
            declared: body_cbor.len() as u32,
            max: MAX_CBOR_BODY_LEN,
        });
    }
    cbor::verify_canonical(body_cbor)?;
    if cbor::map_has_top_level_key(body_cbor, "type")? {
        return Err(WireError::TypeKeyInBody);
    }
    let mut out = Vec::with_capacity(1 + body_cbor.len());
    out.push(type_byte);
    out.extend_from_slice(body_cbor);
    Ok(out)
}

/// Split a post-handshake plaintext frame into `(type_byte, body_cbor)`,
/// rejecting a body that exceeds `MAX_CBOR_BODY_LEN` (checked *before*
/// parsing), is not canonical CBOR, or smuggles a `"type"` key back inside
/// the map. Internal building block — the public decode surface is
/// `auth_frames::decode_auth_frame`, which closes over the known 0x01..0x05
/// type bytes and a fixed schema per type.
pub(crate) fn decode_typed_frame(plaintext: &[u8]) -> Result<(u8, &[u8]), WireError> {
    let (type_byte, body) = plaintext
        .split_first()
        .ok_or(WireError::Cbor(crate::error::CborError::Decode))?;
    if body.len() as u32 > MAX_CBOR_BODY_LEN {
        return Err(WireError::OversizeFrame {
            declared: body.len() as u32,
            max: MAX_CBOR_BODY_LEN,
        });
    }
    cbor::verify_canonical(body)?;
    if cbor::map_has_top_level_key(body, "type")? {
        return Err(WireError::TypeKeyInBody);
    }
    Ok((*type_byte, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::CeremonyDeadline;
    use std::io::Cursor;
    use std::time::Instant;

    fn far_future() -> CeremonyDeadline {
        CeremonyDeadline::for_test(Instant::now(), Duration::from_secs(3600))
    }

    /// A `Read` that yields the 4-byte length prefix on the first call and
    /// then errors on any further call — proves the frame reader never
    /// attempts to read (and therefore never allocates for) the body once
    /// the declared length fails the ceiling check.
    struct PrefixOnlyThenFail {
        prefix: [u8; 4],
        served_prefix: bool,
    }
    impl Read for PrefixOnlyThenFail {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.served_prefix {
                self.served_prefix = true;
                buf[..4].copy_from_slice(&self.prefix);
                Ok(4)
            } else {
                Err(std::io::Error::other(
                    "read attempted past oversize prefix — would have allocated for the body",
                ))
            }
        }
    }
    impl DeadlineBoundedIo for PrefixOnlyThenFail {
        fn arm_io_deadline(&mut self, _remaining: Duration) -> std::io::Result<()> {
            Ok(())
        }
        fn clear_io_deadline(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn red44_oversize_prefix_65536_rejected_without_body_read() {
        let mut r = PrefixOnlyThenFail {
            prefix: 65_536u32.to_be_bytes(),
            served_prefix: false,
        };
        let err = read_handshake_flight(&mut r, &far_future()).unwrap_err();
        assert!(matches!(
            err,
            WireError::OversizeFrame {
                declared: 65_536,
                max: MAX_NOISE_HANDSHAKE_MESSAGE_LEN
            }
        ));
    }

    #[test]
    fn red44_oversize_prefix_max_u32_rejected_without_body_read() {
        let mut r = PrefixOnlyThenFail {
            prefix: 0xFFFF_FFFFu32.to_be_bytes(),
            served_prefix: false,
        };
        let err = read_handshake_flight(&mut r, &far_future()).unwrap_err();
        assert!(matches!(
            err,
            WireError::OversizeFrame {
                declared: 0xFFFF_FFFF,
                max: MAX_NOISE_HANDSHAKE_MESSAGE_LEN
            }
        ));
    }

    #[test]
    fn valid_frame_at_the_ceiling_is_accepted() {
        let body = vec![0x42u8; MAX_NOISE_HANDSHAKE_MESSAGE_LEN as usize];
        let mut buf = Vec::new();
        write_handshake_flight(&mut buf, &body, &far_future()).unwrap();
        let mut cursor = Cursor::new(buf);
        let read_back = read_handshake_flight(&mut cursor, &far_future()).unwrap();
        assert_eq!(read_back, body);
    }

    #[test]
    fn one_byte_over_the_handshake_ceiling_is_rejected() {
        let body = vec![0x42u8; MAX_NOISE_HANDSHAKE_MESSAGE_LEN as usize + 1];
        let mut buf = Vec::new();
        let err = write_handshake_flight(&mut buf, &body, &far_future()).unwrap_err();
        assert!(matches!(err, WireError::OversizeFrame { .. }));
    }

    /// Delivers the underlying bytes a handful at a time, simulating a
    /// fragmented (short-read) transport.
    struct Dribble<'a> {
        remaining: &'a [u8],
        chunk: usize,
    }
    impl<'a> Read for Dribble<'a> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.chunk.min(self.remaining.len()).min(buf.len());
            buf[..n].copy_from_slice(&self.remaining[..n]);
            self.remaining = &self.remaining[n..];
            Ok(n)
        }
    }
    impl<'a> DeadlineBoundedIo for Dribble<'a> {
        fn arm_io_deadline(&mut self, _remaining: Duration) -> std::io::Result<()> {
            Ok(())
        }
        fn clear_io_deadline(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn fragmentation_one_byte_at_a_time_still_assembles_the_frame() {
        let body = b"hello mesh session".to_vec();
        let mut framed = Vec::new();
        write_handshake_flight(&mut framed, &body, &far_future()).unwrap();
        let mut r = Dribble {
            remaining: &framed,
            chunk: 1,
        };
        let read_back = read_handshake_flight(&mut r, &far_future()).unwrap();
        assert_eq!(read_back, body);
    }

    #[test]
    fn coalescing_two_frames_in_one_buffer_are_read_independently() {
        let body_a = b"flight one".to_vec();
        let body_b = b"flight two, a different length".to_vec();
        let mut framed = Vec::new();
        write_handshake_flight(&mut framed, &body_a, &far_future()).unwrap();
        write_handshake_flight(&mut framed, &body_b, &far_future()).unwrap();
        let mut cursor = Cursor::new(framed);
        let first = read_handshake_flight(&mut cursor, &far_future()).unwrap();
        let second = read_handshake_flight(&mut cursor, &far_future()).unwrap();
        assert_eq!(first, body_a);
        assert_eq!(second, body_b);
    }

    /// A stream double proving the anti-slow-loris contract end to end
    /// (2026-08-04, @kiana): `arm_io_deadline` is called before EVERY
    /// syscall (not once per frame), and once the deadline is expired,
    /// zero further bytes are ever read — `read` itself must never even
    /// be reached once `remaining()` is zero.
    struct ExpiresAfterNReads {
        remaining_reads: std::cell::Cell<usize>,
        armed_count: std::cell::Cell<usize>,
    }
    impl Read for ExpiresAfterNReads {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.remaining_reads.get() == 0 {
                panic!("read() called after the deadline should already have rejected this call");
            }
            self.remaining_reads.set(self.remaining_reads.get() - 1);
            buf[0] = 0xAA;
            Ok(1)
        }
    }
    impl DeadlineBoundedIo for ExpiresAfterNReads {
        fn arm_io_deadline(&mut self, _remaining: Duration) -> std::io::Result<()> {
            self.armed_count.set(self.armed_count.get() + 1);
            Ok(())
        }
        fn clear_io_deadline(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn red_already_expired_deadline_rejects_before_the_first_syscall() {
        // An already-expired deadline must reject the very first byte,
        // never reach `read()` at all — proving the check happens BEFORE
        // I/O, not as a post-hoc timeout on a call already in flight.
        // NOTE: this alone does NOT prove the check is re-done before
        // EVERY syscall (a deadline checked once at entry would pass this
        // too) — see
        // `red_deadline_expiring_between_two_syscalls_stops_the_second_one`
        // below for that (2026-08-04, @kiana CFX: this test alone was
        // flagged as a vacuously weak gate for that stronger claim).
        let mut r = ExpiresAfterNReads {
            remaining_reads: std::cell::Cell::new(0),
            armed_count: std::cell::Cell::new(0),
        };
        let expired = CeremonyDeadline::already_expired_for_test();
        let err = read_handshake_flight(&mut r, &expired).unwrap_err();
        assert!(matches!(err, WireError::DeadlineExceeded));
        assert_eq!(
            r.armed_count.get(),
            0,
            "arm_io_deadline must not even be called once remaining() is zero"
        );
    }

    /// Succeeds its first `read()` call, but only after real wall-clock
    /// time has genuinely advanced past `EXPIRING_BUDGET` — chosen with a
    /// wide safety margin so this is not a scheduling race — then panics
    /// if ever called a second time. This is the test kiana's CFX asked
    /// for: alive at syscall #1, provably expired before #2, proving the
    /// budget is recomputed against the same `Instant` fresh before EVERY
    /// syscall, not cached once per logical frame/call.
    const EXPIRING_BUDGET: Duration = Duration::from_millis(20);

    struct ExpiresBetweenSyscalls {
        calls: std::cell::Cell<usize>,
        armed_count: std::cell::Cell<usize>,
    }
    impl Read for ExpiresBetweenSyscalls {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let call = self.calls.get();
            self.calls.set(call + 1);
            if call > 0 {
                panic!(
                    "read() called a second time — the deadline should have expired and rejected it before reaching here"
                );
            }
            // Guarantee (not race) that EXPIRING_BUDGET has elapsed by
            // the time the loop rechecks `deadline.remaining()`.
            std::thread::sleep(EXPIRING_BUDGET * 5);
            buf[0] = 0xAA;
            Ok(1)
        }
    }
    impl DeadlineBoundedIo for ExpiresBetweenSyscalls {
        fn arm_io_deadline(&mut self, _remaining: Duration) -> std::io::Result<()> {
            self.armed_count.set(self.armed_count.get() + 1);
            Ok(())
        }
        fn clear_io_deadline(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn red_deadline_expiring_between_two_syscalls_stops_the_second_one() {
        let deadline = CeremonyDeadline::for_test(Instant::now(), EXPIRING_BUDGET);
        let mut r = ExpiresBetweenSyscalls {
            calls: std::cell::Cell::new(0),
            armed_count: std::cell::Cell::new(0),
        };
        // 2 bytes requested: the first syscall only ever fills 1, forcing
        // the loop to recheck the deadline before a second syscall it
        // must now refuse.
        let mut buf = [0u8; 2];
        let err = read_exact_with_deadline(&mut r, &mut buf, &deadline).unwrap_err();
        assert!(matches!(err, WireError::DeadlineExceeded));
        assert_eq!(
            r.calls.get(),
            1,
            "read() must not be attempted a second time"
        );
        assert_eq!(
            r.armed_count.get(),
            1,
            "arm_io_deadline must not be called for a syscall that never happens"
        );
    }

    /// Returns the FULL requested buffer in a SINGLE call, but only after
    /// sleeping past the deadline's budget — simulating a syscall that
    /// itself raced right up to (or past) its armed timeout and still
    /// produced a complete result. `SO_RCVTIMEO` bounds how long a real
    /// syscall may block, but does not *prove* it returned before the
    /// deadline; this double proves the loop rechecks `deadline` after
    /// THIS syscall too, not only before a next one that (since the
    /// buffer is already full) never happens (2026-08-04, @kiana, WIP
    /// audit item (a)).
    struct SleepsPastBudgetThenReturnsFull;
    impl Read for SleepsPastBudgetThenReturnsFull {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(EXPIRING_BUDGET * 5);
            buf.fill(0xAA);
            Ok(buf.len())
        }
    }
    impl DeadlineBoundedIo for SleepsPastBudgetThenReturnsFull {
        fn arm_io_deadline(&mut self, _remaining: Duration) -> std::io::Result<()> {
            Ok(())
        }
        fn clear_io_deadline(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn red_single_read_syscall_racing_past_the_budget_and_returning_full_still_fails() {
        let deadline = CeremonyDeadline::for_test(Instant::now(), EXPIRING_BUDGET);
        let mut r = SleepsPastBudgetThenReturnsFull;
        let mut buf = [0u8; 2];
        let err = read_exact_with_deadline(&mut r, &mut buf, &deadline).unwrap_err();
        assert!(matches!(err, WireError::DeadlineExceeded));
    }

    /// Write-side symmetric case of
    /// `red_single_read_syscall_racing_past_the_budget_and_returning_full_still_fails`.
    struct SleepsPastBudgetThenWritesFull;
    impl Write for SleepsPastBudgetThenWritesFull {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(EXPIRING_BUDGET * 5);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl DeadlineBoundedIo for SleepsPastBudgetThenWritesFull {
        fn arm_io_deadline(&mut self, _remaining: Duration) -> std::io::Result<()> {
            Ok(())
        }
        fn clear_io_deadline(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn red_single_write_syscall_racing_past_the_budget_and_writing_full_still_fails() {
        let deadline = CeremonyDeadline::for_test(Instant::now(), EXPIRING_BUDGET);
        let mut w = SleepsPastBudgetThenWritesFull;
        let err = write_all_with_deadline(&mut w, b"ab", &deadline).unwrap_err();
        assert!(matches!(err, WireError::DeadlineExceeded));
    }

    /// `arm_io_deadline` failing (e.g. a real `setsockopt` rejecting the
    /// timeout) must fail the read/write closed, never silently proceed
    /// as if unbounded.
    struct ArmingAlwaysFails;
    impl Read for ArmingAlwaysFails {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            panic!("read() must never be reached once arm_io_deadline failed");
        }
    }
    impl DeadlineBoundedIo for ArmingAlwaysFails {
        fn arm_io_deadline(&mut self, _remaining: Duration) -> std::io::Result<()> {
            Err(std::io::Error::other("simulated setsockopt failure"))
        }
        fn clear_io_deadline(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn red_deadline_arming_failure_fails_closed_before_io() {
        let mut r = ArmingAlwaysFails;
        let err = read_handshake_flight(&mut r, &far_future()).unwrap_err();
        assert!(matches!(err, WireError::DeadlineArmingFailed));
    }

    /// Arms successfully on the first syscall (which only partially
    /// writes), then fails arming on the *second* — proving the write
    /// loop re-arms fresh before every syscall rather than only guarding
    /// the very first one (2026-08-04, @kiana CFX: "não basta setsockopt
    /// failure no primeiro call").
    struct WriteArmingFailsOnSecondCall {
        arm_calls: std::cell::Cell<usize>,
        write_calls: std::cell::Cell<usize>,
    }
    impl Write for WriteArmingFailsOnSecondCall {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write_calls.set(self.write_calls.get() + 1);
            // Always a short (1-byte) write, forcing a second syscall for
            // any multi-byte buffer.
            Ok(1.min(buf.len()))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl DeadlineBoundedIo for WriteArmingFailsOnSecondCall {
        fn arm_io_deadline(&mut self, _remaining: Duration) -> std::io::Result<()> {
            let call = self.arm_calls.get();
            self.arm_calls.set(call + 1);
            if call == 0 {
                Ok(())
            } else {
                Err(std::io::Error::other(
                    "simulated setsockopt failure on a later syscall",
                ))
            }
        }
        fn clear_io_deadline(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn red_write_deadline_arming_failure_on_a_later_syscall_fails_closed() {
        let mut w = WriteArmingFailsOnSecondCall {
            arm_calls: std::cell::Cell::new(0),
            write_calls: std::cell::Cell::new(0),
        };
        let err = write_all_with_deadline(&mut w, b"ab", &far_future()).unwrap_err();
        assert!(matches!(err, WireError::DeadlineArmingFailed));
        assert_eq!(
            w.arm_calls.get(),
            2,
            "arming must be attempted fresh before the second syscall too, not just the first"
        );
        assert_eq!(
            w.write_calls.get(),
            1,
            "write() must not be attempted once the second arm has already failed"
        );
    }

    #[derive(serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        a: u32,
    }

    #[test]
    fn typed_frame_round_trip() {
        let body_cbor = cbor::to_canonical_vec(&Body { a: 7 }).unwrap();
        let frame = encode_typed_frame(0x01, &body_cbor).unwrap();
        assert_eq!(frame[0], 0x01);
        let (type_byte, body) = decode_typed_frame(&frame).unwrap();
        assert_eq!(type_byte, 0x01);
        assert_eq!(body, body_cbor.as_slice());
    }

    #[test]
    fn red_type_key_inside_cbor_body_is_rejected_on_encode() {
        #[derive(serde::Serialize)]
        #[serde(deny_unknown_fields)]
        struct BadBody {
            r#type: u32,
        }
        let body_cbor = cbor::to_canonical_vec(&BadBody { r#type: 1 }).unwrap();
        assert!(matches!(
            encode_typed_frame(0x01, &body_cbor),
            Err(WireError::TypeKeyInBody)
        ));
    }

    #[test]
    fn type_key_smuggled_into_a_decoded_body_is_rejected() {
        // Bypass encode_typed_frame's own guard to prove decode_typed_frame
        // independently rejects a body carrying "type", not just relying on
        // the encoder never producing one.
        #[derive(serde::Serialize)]
        #[serde(deny_unknown_fields)]
        struct BadBody {
            r#type: u32,
        }
        let body_cbor = cbor::to_canonical_vec(&BadBody { r#type: 1 }).unwrap();
        let mut frame = vec![0x01u8];
        frame.extend_from_slice(&body_cbor);
        assert!(matches!(
            decode_typed_frame(&frame),
            Err(WireError::TypeKeyInBody)
        ));
    }

    #[test]
    fn red_noncanonical_body_is_rejected_on_decode() {
        use ciborium::Value;
        let raw = Value::Map(vec![
            (Value::Text("b".into()), Value::Integer(2.into())),
            (Value::Text("a".into()), Value::Integer(1.into())),
        ]);
        let mut body_cbor = Vec::new();
        ciborium::ser::into_writer(&raw, &mut body_cbor).unwrap();
        let mut frame = vec![0x01u8];
        frame.extend_from_slice(&body_cbor);
        assert!(decode_typed_frame(&frame).is_err());
    }

    #[test]
    fn red_encode_rejects_a_noncanonical_body_it_did_not_build_itself() {
        use ciborium::Value;
        let raw = Value::Map(vec![
            (Value::Text("b".into()), Value::Integer(2.into())),
            (Value::Text("a".into()), Value::Integer(1.into())),
        ]);
        let mut noncanonical = Vec::new();
        ciborium::ser::into_writer(&raw, &mut noncanonical).unwrap();
        assert!(encode_typed_frame(0x01, &noncanonical).is_err());
    }

    #[test]
    fn max_cbor_body_arithmetic_matches_spec() {
        assert_eq!(MAX_NOISE_RECORD_LEN, 65_535);
        assert_eq!(MAX_PLAINTEXT_LEN, 65_519);
        assert_eq!(MAX_CBOR_BODY_LEN, 65_518);
    }

    #[derive(serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct Padded {
        a: String,
    }

    /// Constant per-map/per-key CBOR overhead for `Padded`, measured using
    /// a placeholder string long enough (>255 bytes) to be in the same
    /// CBOR text-length-header size class (3-byte header: 0x79 + 2 length
    /// bytes) as the multi-KB strings these tests actually build — an
    /// empty-string placeholder would measure the *1-byte*-header class
    /// instead and be off by 2.
    fn padded_overhead() -> usize {
        const PROBE_LEN: usize = 300;
        cbor::to_canonical_vec(&Padded {
            a: "x".repeat(PROBE_LEN),
        })
        .unwrap()
        .len()
            - PROBE_LEN
    }

    #[test]
    fn red_body_at_exactly_the_65518_ceiling_is_accepted_by_encode() {
        // A body this large won't be valid canonical CBOR of a small
        // struct, so build a minimal canonical map padded via a long text
        // value to land exactly on the ceiling, then confirm encode
        // accepts it (the ceiling check must not be off-by-one).
        let pad_len = MAX_CBOR_BODY_LEN as usize - padded_overhead();
        let body_cbor = cbor::to_canonical_vec(&Padded {
            a: "x".repeat(pad_len),
        })
        .unwrap();
        assert_eq!(body_cbor.len() as u32, MAX_CBOR_BODY_LEN);
        encode_typed_frame(0x01, &body_cbor).unwrap();
    }

    #[test]
    fn red_body_one_byte_over_65518_is_rejected_by_encode_before_parsing() {
        let pad_len = MAX_CBOR_BODY_LEN as usize - padded_overhead() + 1;
        let body_cbor = cbor::to_canonical_vec(&Padded {
            a: "x".repeat(pad_len),
        })
        .unwrap();
        assert_eq!(body_cbor.len() as u32, MAX_CBOR_BODY_LEN + 1);
        assert!(matches!(
            encode_typed_frame(0x01, &body_cbor),
            Err(WireError::OversizeFrame { .. })
        ));
    }

    #[test]
    fn red_decode_rejects_oversize_body_before_parsing_as_cbor() {
        // A body this large is not even valid CBOR (it's garbage bytes) —
        // proving decode_typed_frame's length check fires first, before
        // any parse attempt, exactly like the handshake-flight RED-44
        // family above.
        let oversize_garbage = vec![0u8; MAX_CBOR_BODY_LEN as usize + 1];
        let mut frame = vec![0x01u8];
        frame.extend_from_slice(&oversize_garbage);
        assert!(matches!(
            decode_typed_frame(&frame),
            Err(WireError::OversizeFrame { .. })
        ));
    }
}
