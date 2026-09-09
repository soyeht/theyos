#![cfg(test)]

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
}

#[test]
fn red_single_read_syscall_racing_past_the_budget_and_returning_full_still_fails() {
    let deadline = CeremonyDeadline::for_test(Instant::now(), EXPIRING_BUDGET);
    let mut r = SleepsPastBudgetThenReturnsFull;
    let mut buf = [0u8; 2];
    let err = read_exact_with_deadline(&mut r, &mut buf, &deadline).unwrap_err();
    assert!(matches!(err, WireError::DeadlineExceeded));
}

/// A write that only fully drains `buf` on its final syscall, and only
/// AFTER that syscall returns does the deadline actually expire (the
/// sleep happens strictly *before* the write, so the "budget expiring
/// during the syscall" scenario is deterministic, not a race) —
/// proves `write_all_with_deadline` treats a write that genuinely
/// completed as a terminal success, never retroactively failed
/// (2026-08-04, @kiana, definitive — corrects the earlier, wrong
/// expectation that this must fail; see the function's own doc for
/// why: the peer already has the bytes once this returns `Ok`, so
/// failing afterward would create exactly the split-brain this crate
/// avoids everywhere else).
struct SleepsThenWritesFullOnFinalSyscall;
impl Write for SleepsThenWritesFullOnFinalSyscall {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::thread::sleep(EXPIRING_BUDGET * 5);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl DeadlineBoundedIo for SleepsThenWritesFullOnFinalSyscall {
    fn arm_io_deadline(&mut self, _remaining: Duration) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn red_write_that_completes_on_its_final_syscall_is_terminal_success_not_retroactive_failure() {
    let deadline = CeremonyDeadline::for_test(Instant::now(), EXPIRING_BUDGET);
    let mut w = SleepsThenWritesFullOnFinalSyscall;
    // The sleep inside `write()` (5x the budget) guarantees the
    // deadline is already expired by the time this call returns —
    // yet the write itself fully succeeded, so the overall result
    // must still be `Ok`.
    write_all_with_deadline(&mut w, b"ab", &deadline).unwrap();
    assert!(
        deadline.is_expired(),
        "the deadline must genuinely have expired during the sleep, or this test proves nothing"
    );
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
