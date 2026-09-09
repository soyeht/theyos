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
/// **No `clear`/`capture`/restore step (2026-08-04, @kiana, lifecycle CFX,
/// definitive — supersedes the earlier `capture_io_deadline`/
/// `clear_io_deadline` pair):** `PrevalidatedIngress` gives this crate
/// *exclusive* ownership of the stream (v6 §10: raw `T` never comes back
/// out to an external caller). Between the Ack write succeeding and any
/// future operation, no I/O happens at all — there is nothing to leave in
/// a bad state. Every future Active-side I/O operation (once a real,
/// guarded DATA path exists — see `ActiveMeshSession`'s module doc) is
/// required to call `arm_io_deadline` again, with its own budget, before
/// its own first syscall — exactly the same "recompute fresh before every
/// syscall" discipline `read_exact_with_deadline`/`write_all_with_deadline`
/// already apply during the ceremony itself. That next arm always
/// overwrites whatever timeout the stream currently holds, so nothing
/// about the ceremony's *last* armed value is ever observable by a
/// well-behaved caller; if there never is a next operation, the stream
/// (and its socket options along with it) is simply dropped. A prior
/// design tried to restore the stream to its pre-ceremony timeout instead
/// — that added a fallible syscall on the terminal, already-committed
/// path (right after `activate_if_authorized`, when a real D1 registry
/// may already consider the session Active) for no benefit this ownership
/// model doesn't already provide for free.
/// Anything that can bound a per-syscall I/O loop the same way
/// [`CeremonyDeadline`] does: monotonic, rechecked fresh before (and,
/// where the caller needs it, after) every syscall, never cached.
/// `pub(crate)` — generic-ized (2026-08-04, @kiana, post-Active wire
/// addendum work) so the bounded read/write loops below can be reused for
/// a per-operation deadline that outlives a single ceremony, without
/// giving [`CeremonyDeadline`] itself a second, non-ingress-admission
/// constructor — see that type's own doc for why that boundary is
/// deliberate. [`CeremonyDeadline`] implements this unchanged; nothing
/// about its existing behavior changes.
pub(crate) trait BoundedDeadline {
    fn remaining(&self) -> Duration;
    fn is_expired(&self) -> bool;
}

impl BoundedDeadline for CeremonyDeadline {
    fn remaining(&self) -> Duration {
        CeremonyDeadline::remaining(self)
    }
    fn is_expired(&self) -> bool {
        CeremonyDeadline::is_expired(self)
    }
}

pub(crate) trait DeadlineBoundedIo {
    fn arm_io_deadline(&mut self, remaining: Duration) -> std::io::Result<()>;
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
}

impl<T> DeadlineBoundedIo for std::io::Cursor<T> {
    fn arm_io_deadline(&mut self, _remaining: Duration) -> std::io::Result<()> {
        Ok(()) // in-memory, never blocks — nothing to bound
    }
}

impl DeadlineBoundedIo for Vec<u8> {
    fn arm_io_deadline(&mut self, _remaining: Duration) -> std::io::Result<()> {
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
fn read_exact_with_deadline<R: Read + DeadlineBoundedIo, D: BoundedDeadline>(
    r: &mut R,
    buf: &mut [u8],
    deadline: &D,
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
/// [`read_exact_with_deadline`] for the pre-syscall check this shares.
///
/// **No post-syscall recheck here (2026-08-04, @kiana, WIP audit,
/// definitive — corrects an earlier version of this function that DID
/// recheck `deadline` after every syscall, symmetrically with
/// `read_exact_with_deadline`):** a write, once a syscall has put its
/// bytes on the wire, is irreversible — the peer has them regardless of
/// how long that syscall took. For a terminal write like `ActivateAck`,
/// the erratum's own rule is "write succeeded → proceed to
/// `activate_if_authorized` immediately"; retroactively turning a
/// completed transmission into a local `DeadlineExceeded` error would
/// create exactly the split-brain this crate works hard everywhere else
/// to avoid — peer believes Active, this side reports failure and never
/// even calls `activate_if_authorized`. The deadline still bounds
/// whether a NEXT syscall may be *attempted*: the `while` condition's own
/// top-of-loop check (`remaining.is_zero()`) already fails a still-partial
/// write before its next chunk, satisfying "a partial write that crosses
/// the deadline fails on the next iteration" without needing a separate
/// post-syscall check that could fire on the syscall that just finished.
fn write_all_with_deadline<W: Write + DeadlineBoundedIo, D: BoundedDeadline>(
    w: &mut W,
    mut buf: &[u8],
    deadline: &D,
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
pub(crate) fn read_length_prefixed_frame<R: Read + DeadlineBoundedIo, D: BoundedDeadline>(
    r: &mut R,
    max_len: u32,
    deadline: &D,
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
pub(crate) fn write_length_prefixed_frame<W: Write + DeadlineBoundedIo, D: BoundedDeadline>(
    w: &mut W,
    body: &[u8],
    max_len: u32,
    deadline: &D,
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
pub(crate) fn read_handshake_flight<R: Read + DeadlineBoundedIo, D: BoundedDeadline>(
    r: &mut R,
    deadline: &D,
) -> Result<Vec<u8>, WireError> {
    read_length_prefixed_frame(r, MAX_NOISE_HANDSHAKE_MESSAGE_LEN, deadline)
}

/// Write one Noise handshake flight. Ceiling fixed at
/// `MAX_NOISE_HANDSHAKE_MESSAGE_LEN` — not a parameter.
pub(crate) fn write_handshake_flight<W: Write + DeadlineBoundedIo, D: BoundedDeadline>(
    w: &mut W,
    body: &[u8],
    deadline: &D,
) -> Result<(), WireError> {
    write_length_prefixed_frame(w, body, MAX_NOISE_HANDSHAKE_MESSAGE_LEN, deadline)
}

/// Read one post-handshake Noise transport record (ciphertext). Ceiling
/// fixed at `MAX_NOISE_RECORD_LEN` — not a parameter.
pub(crate) fn read_transport_record<R: Read + DeadlineBoundedIo, D: BoundedDeadline>(
    r: &mut R,
    deadline: &D,
) -> Result<Vec<u8>, WireError> {
    read_length_prefixed_frame(r, MAX_NOISE_RECORD_LEN, deadline)
}

/// Write one post-handshake Noise transport record (ciphertext). Ceiling
/// fixed at `MAX_NOISE_RECORD_LEN` — not a parameter.
pub(crate) fn write_transport_record<W: Write + DeadlineBoundedIo, D: BoundedDeadline>(
    w: &mut W,
    body: &[u8],
    deadline: &D,
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
mod tests;
