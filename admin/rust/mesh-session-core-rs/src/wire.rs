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
//!   ceiling. The *public* surface is four purpose-named entry points, each
//!   with its ceiling baked in as a constant, so there is no parameter to
//!   get wrong.
//! - `encode_typed_frame` now requires the body to already be canonical CBOR
//!   (checked via `cbor::verify_canonical`, not assumed) and within the
//!   frozen `MAX_CBOR_BODY_LEN` (65_518) ceiling *before* framing it — the
//!   original silently framed whatever bytes it was given.
//! - `decode_typed_frame` checks the body length against the same ceiling
//!   *before* parsing it as CBOR, and is now `pub(crate)`: the public
//!   decode surface for real frames is `auth_frames::decode_auth_frame`,
//!   which returns a closed `AuthFrame` enum over exactly the 5 known type
//!   bytes rather than a raw `(u8, &[u8])` a caller could mishandle.

use std::io::{Read, Write};

use crate::cbor;
use crate::error::WireError;

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

/// Read one `[4-byte BE length][bytes]` frame from `r`. Internal building
/// block only — see the module-level hardening note for why the public
/// surface is the four fixed-ceiling wrappers below instead of this
/// directly.
///
/// The length prefix is validated against `max_len` before any
/// length-sized buffer is allocated. `read_exact` is used for both the
/// prefix and the body, so a reader that only delivers a few bytes per
/// `read()` call (fragmentation) is handled transparently; a `Read` that
/// coalesces multiple frames into one underlying buffer works too, because
/// only the bytes belonging to this one frame are ever consumed.
pub(crate) fn read_length_prefixed_frame<R: Read>(
    r: &mut R,
    max_len: u32,
) -> Result<Vec<u8>, WireError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let declared = u32::from_be_bytes(len_buf);
    if declared > max_len {
        return Err(WireError::OversizeFrame {
            declared,
            max: max_len,
        });
    }
    let mut body = vec![0u8; declared as usize];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Write one `[4-byte BE length][bytes]` frame to `w`. Internal building
/// block only — see [`read_length_prefixed_frame`].
pub(crate) fn write_length_prefixed_frame<W: Write>(
    w: &mut W,
    body: &[u8],
    max_len: u32,
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
    w.write_all(&declared.to_be_bytes())?;
    w.write_all(body)?;
    Ok(())
}

/// Read one Noise handshake flight. Ceiling fixed at
/// `MAX_NOISE_HANDSHAKE_MESSAGE_LEN` — not a parameter.
pub fn read_handshake_flight<R: Read>(r: &mut R) -> Result<Vec<u8>, WireError> {
    read_length_prefixed_frame(r, MAX_NOISE_HANDSHAKE_MESSAGE_LEN)
}

/// Write one Noise handshake flight. Ceiling fixed at
/// `MAX_NOISE_HANDSHAKE_MESSAGE_LEN` — not a parameter.
pub fn write_handshake_flight<W: Write>(w: &mut W, body: &[u8]) -> Result<(), WireError> {
    write_length_prefixed_frame(w, body, MAX_NOISE_HANDSHAKE_MESSAGE_LEN)
}

/// Read one post-handshake Noise transport record (ciphertext). Ceiling
/// fixed at `MAX_NOISE_RECORD_LEN` — not a parameter.
pub fn read_transport_record<R: Read>(r: &mut R) -> Result<Vec<u8>, WireError> {
    read_length_prefixed_frame(r, MAX_NOISE_RECORD_LEN)
}

/// Write one post-handshake Noise transport record (ciphertext). Ceiling
/// fixed at `MAX_NOISE_RECORD_LEN` — not a parameter.
pub fn write_transport_record<W: Write>(w: &mut W, body: &[u8]) -> Result<(), WireError> {
    write_length_prefixed_frame(w, body, MAX_NOISE_RECORD_LEN)
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
    use std::io::Cursor;

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

    #[test]
    fn red44_oversize_prefix_65536_rejected_without_body_read() {
        let mut r = PrefixOnlyThenFail {
            prefix: 65_536u32.to_be_bytes(),
            served_prefix: false,
        };
        let err = read_handshake_flight(&mut r).unwrap_err();
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
        let err = read_handshake_flight(&mut r).unwrap_err();
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
        write_handshake_flight(&mut buf, &body).unwrap();
        let mut cursor = Cursor::new(buf);
        let read_back = read_handshake_flight(&mut cursor).unwrap();
        assert_eq!(read_back, body);
    }

    #[test]
    fn one_byte_over_the_handshake_ceiling_is_rejected() {
        let body = vec![0x42u8; MAX_NOISE_HANDSHAKE_MESSAGE_LEN as usize + 1];
        let mut buf = Vec::new();
        let err = write_handshake_flight(&mut buf, &body).unwrap_err();
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

    #[test]
    fn fragmentation_one_byte_at_a_time_still_assembles_the_frame() {
        let body = b"hello mesh session".to_vec();
        let mut framed = Vec::new();
        write_handshake_flight(&mut framed, &body).unwrap();
        let mut r = Dribble {
            remaining: &framed,
            chunk: 1,
        };
        let read_back = read_handshake_flight(&mut r).unwrap();
        assert_eq!(read_back, body);
    }

    #[test]
    fn coalescing_two_frames_in_one_buffer_are_read_independently() {
        let body_a = b"flight one".to_vec();
        let body_b = b"flight two, a different length".to_vec();
        let mut framed = Vec::new();
        write_handshake_flight(&mut framed, &body_a).unwrap();
        write_handshake_flight(&mut framed, &body_b).unwrap();
        let mut cursor = Cursor::new(framed);
        let first = read_handshake_flight(&mut cursor).unwrap();
        let second = read_handshake_flight(&mut cursor).unwrap();
        assert_eq!(first, body_a);
        assert_eq!(second, body_b);
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
