//! Post-Active wire records: `DATA`, `REVOKE_NOTICE`, `CLOSE`, `REKEY`.
//!
//! Frozen by `kiana-bsessao-post-active-wire-addendum.b14fcf9520222ad3ab3ac3443ae4b0e7ba219411f41e3389751c92a402b64d8a.md`
//! (+ provenance-only erratum1
//! `kiana-bsessao-post-active-wire-addendum-erratum1.4be4cd3d0963cbc145b4aeb1f5450e5753e84f1b65e94e84af9ecd29832bf203.md`),
//! both self-hash verified against their embedded SHA-256 before this
//! module was written, 2026-08-04. Type byte values (`DATA=0x10`,
//! `REVOKE_NOTICE=0x20`, `CLOSE=0x30`, `REKEY=0x40`) trace to
//! `daisy-bsessao-v3-final.489ef122998127b83fbd1eab341dbeab5e199502584637894fb1b765088c7c74.md`
//! lines 366-377 per the erratum's own provenance correction; the
//! addendum ratifies those four values and fixes the bodies, which no
//! prior version (v3-final through v6) ever specified.
//!
//! **Deliberately NOT built on [`wire::encode_typed_frame`]/
//! [`wire::decode_typed_frame`] for `DATA`/`REVOKE_NOTICE`/`CLOSE`**
//! (2026-08-04, @kiana, catch before implementation): those two
//! functions unconditionally run `cbor::verify_canonical` on the body.
//! `DATA`'s body is addendum-frozen as opaque bytes, never CBOR (§3.1:
//! "O body é bytes opacos, não CBOR"); `CLOSE`/`REVOKE_NOTICE` bodies
//! are frozen empty (§3.2/§3.3) — and an empty byte slice is not a
//! well-formed CBOR item at all (`ciborium` cannot parse zero bytes as
//! any item), so running canonical-CBOR validation on a correctly empty
//! control body would *reject* it, not accept it. Only `REKEY`'s body
//! (§3.4) is genuinely canonical CBOR, so only `REKEY` reuses
//! `wire::encode_typed_frame`/`decode_typed_frame` — `DATA`/
//! `REVOKE_NOTICE`/`CLOSE` get their own opaque/empty-body framing
//! below, sharing only the outer length-prefix/Noise-record layer
//! ([`wire::write_transport_record`]/[`wire::read_transport_record`],
//! driven by `auth_state_machine`) and the [`wire::MAX_CBOR_BODY_LEN`]
//! ceiling (65,518 bytes — the name is CBOR-specific but the ceiling
//! itself just bounds "body after the type byte", which applies
//! regardless of encoding).
//!
//! Records here never carry a P-256 signature, are never accepted before
//! the terminal `ActivateAck`, and never enter `AuthFrame`/`AuthFrameBody`
//! — see `auth_state_machine`'s `PostActiveRecord`-vs-`AuthFrame`
//! compile-fail proofs.

use serde::{Deserialize, Serialize};

use crate::error::PostActiveError;
use crate::wire;

pub const DATA_TYPE_BYTE: u8 = 0x10;
pub const REVOKE_NOTICE_TYPE_BYTE: u8 = 0x20;
pub const CLOSE_TYPE_BYTE: u8 = 0x30;
pub const REKEY_TYPE_BYTE: u8 = 0x40;

/// addendum §3.4: `plaintext := 0x40 || canonical_cbor({ "next_generation": uint })`
/// — closed map, exactly one text key, no `"type"` field smuggled in.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RekeyMarkerWire {
    next_generation: u64,
}

/// A decoded post-Active record, addendum §3/§4's closed namespace already
/// enforced by construction — there is no variant for `0x01..0x07` or any
/// other byte, because [`decode_post_active_record`] never returns `Ok` for
/// one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PostActiveRecord {
    Data(Vec<u8>),
    RevokeNotice,
    Close,
    Rekey { next_generation: u64 },
}

fn check_opaque_body_len(len: usize) -> Result<(), PostActiveError> {
    if len as u32 > wire::MAX_CBOR_BODY_LEN {
        return Err(PostActiveError::OversizeBody {
            declared: len as u32,
            max: wire::MAX_CBOR_BODY_LEN,
        });
    }
    Ok(())
}

/// addendum §3.1. `0 <= len(payload) <= 65_518`; body is opaque, never
/// validated as CBOR.
pub(crate) fn encode_data_record(payload: &[u8]) -> Result<Vec<u8>, PostActiveError> {
    check_opaque_body_len(payload.len())?;
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(DATA_TYPE_BYTE);
    out.extend_from_slice(payload);
    Ok(out)
}

/// addendum §3.2: `plaintext := 0x20`, body always empty. Infallible.
pub(crate) fn encode_revoke_notice_record() -> Vec<u8> {
    vec![REVOKE_NOTICE_TYPE_BYTE]
}

/// addendum §3.3: `plaintext := 0x30`, body always empty. Infallible.
pub(crate) fn encode_close_record() -> Vec<u8> {
    vec![CLOSE_TYPE_BYTE]
}

/// addendum §3.4. Genuinely canonical CBOR — reuses
/// [`wire::encode_typed_frame`] deliberately (unlike the other three).
pub(crate) fn encode_rekey_record(next_generation: u64) -> Result<Vec<u8>, PostActiveError> {
    let body = crate::cbor::to_canonical_vec(&RekeyMarkerWire { next_generation })?;
    Ok(wire::encode_typed_frame(REKEY_TYPE_BYTE, &body)?)
}

/// Dispatches on the type byte BEFORE deciding whether (and how) to
/// validate the body — the load-bearing property this module exists for
/// (2026-08-04, @kiana catch): `DATA` never runs CBOR validation on its
/// opaque body; `REVOKE_NOTICE`/`CLOSE` never run it on their (always
/// empty) body either, they only check length; only `REKEY` is decoded
/// through the canonical-CBOR path. Enforces addendum §4's closed
/// namespace: `0x01..0x05` (auth frames), `0x06` (intent), `0x07`
/// (reserved capability), and any other byte are all rejected with a
/// distinct error, never silently accepted.
pub(crate) fn decode_post_active_record(
    plaintext: &[u8],
) -> Result<PostActiveRecord, PostActiveError> {
    let (&type_byte, body) = plaintext
        .split_first()
        .ok_or(PostActiveError::EmptyRecord)?;
    match type_byte {
        DATA_TYPE_BYTE => {
            check_opaque_body_len(body.len())?;
            Ok(PostActiveRecord::Data(body.to_vec()))
        }
        REVOKE_NOTICE_TYPE_BYTE => {
            if !body.is_empty() {
                return Err(PostActiveError::NonEmptyControlBody);
            }
            Ok(PostActiveRecord::RevokeNotice)
        }
        CLOSE_TYPE_BYTE => {
            if !body.is_empty() {
                return Err(PostActiveError::NonEmptyControlBody);
            }
            Ok(PostActiveRecord::Close)
        }
        REKEY_TYPE_BYTE => {
            let (_, cbor_body) = wire::decode_typed_frame(plaintext)?;
            let marker: RekeyMarkerWire = crate::cbor::from_canonical_bytes(cbor_body)?;
            Ok(PostActiveRecord::Rekey {
                next_generation: marker.next_generation,
            })
        }
        0x01..=0x05 => Err(PostActiveError::UnexpectedAuthFrame(type_byte)),
        0x06 => Err(PostActiveError::UnexpectedIntentRecord),
        0x07 => Err(PostActiveError::ReservedTypeByte),
        other => Err(PostActiveError::UnknownTypeByte(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // addendum §8 item 14 (2026-08-04, @kiana): non-vacuous proof that
    // post-Active types never enter `AuthFrameBody`/`AuthFrame`/any K_mesh
    // signing API. `static_assertions::assert_not_impl_any!` expands to a
    // real trait-resolution check evaluated at normal compile time — if a
    // later change ever made either type satisfy `AuthFrameBody`, this
    // crate would stop compiling, not merely fail a runtime test. Neither
    // `PostActiveRecord` nor `RekeyMarkerWire` is made `pub` to enable
    // this — `static_assertions` runs inside this crate's own test
    // compilation, which already sees every `pub(crate)` item, so no
    // production visibility was widened to write this proof.
    //
    // Doubly true by construction, not just by this assertion:
    // `AuthFrameBody: sealed::Sealed + Serialize` is a SEALED trait (see
    // `auth_frames.rs`) — no type outside that module could implement it
    // even by accident, regardless of `Serialize`. `PostActiveRecord`
    // additionally doesn't even derive `Serialize` at all (it is never
    // encoded directly — `encode_data_record`/`encode_close_record`/etc.
    // build wire bytes by hand), so it fails both independent halves of
    // the bound.
    static_assertions::assert_not_impl_any!(
        PostActiveRecord: crate::auth_frames::AuthFrameBody
    );
    static_assertions::assert_not_impl_any!(
        RekeyMarkerWire: crate::auth_frames::AuthFrameBody
    );
    // `AuthFrame` itself is a closed enum over exactly the 5 sealed
    // variants (see `auth_frames::AuthFrame`) with no `From`/`Into`
    // conversion defined from anything in this module — asserting
    // non-convertibility the same way, for both directions kiana asked
    // about ("não entra em AuthFrameBody/AuthFrame").
    static_assertions::assert_not_impl_any!(PostActiveRecord: Into<crate::auth_frames::AuthFrame>);
    static_assertions::assert_not_impl_any!(RekeyMarkerWire: Into<crate::auth_frames::AuthFrame>);

    #[test]
    fn data_round_trips_exact_bytes() {
        let payload = b"hello mesh".to_vec();
        let encoded = encode_data_record(&payload).unwrap();
        assert_eq!(encoded[0], DATA_TYPE_BYTE);
        match decode_post_active_record(&encoded).unwrap() {
            PostActiveRecord::Data(got) => assert_eq!(got, payload),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn data_empty_payload_is_valid() {
        let encoded = encode_data_record(&[]).unwrap();
        assert_eq!(
            decode_post_active_record(&encoded).unwrap(),
            PostActiveRecord::Data(vec![])
        );
    }

    #[test]
    fn data_at_the_65518_ceiling_is_accepted() {
        let payload = vec![0xABu8; wire::MAX_CBOR_BODY_LEN as usize];
        let encoded = encode_data_record(&payload).unwrap();
        assert_eq!(
            decode_post_active_record(&encoded).unwrap(),
            PostActiveRecord::Data(payload)
        );
    }

    #[test]
    fn data_one_byte_over_the_ceiling_is_rejected_by_encode() {
        let payload = vec![0xABu8; wire::MAX_CBOR_BODY_LEN as usize + 1];
        assert!(matches!(
            encode_data_record(&payload),
            Err(PostActiveError::OversizeBody { .. })
        ));
    }

    /// item 7/8 RED (2026-08-04, @kiana, catch before implementation):
    /// an arbitrary, GUARANTEED-not-valid-CBOR payload must decode as
    /// `DATA` successfully, byte for byte. `0xff` repeated is not a
    /// well-formed CBOR item at the top level for canonical parsing in
    /// this crate's schema set (raw indefinite-length marker, rejected
    /// everywhere else in this crate — see cbor.rs's own
    /// `red_indefinite_length_array_rejected`), so this is a genuine,
    /// not-accidentally-CBOR-shaped payload.
    #[test]
    fn red_data_accepts_a_payload_that_is_definitely_not_valid_cbor() {
        let payload = vec![0xFFu8; 64];
        assert!(crate::cbor::verify_canonical(&payload).is_err());
        let encoded = encode_data_record(&payload).unwrap();
        assert_eq!(
            decode_post_active_record(&encoded).unwrap(),
            PostActiveRecord::Data(payload)
        );
    }

    /// item 7/8 RED (2026-08-04, @kiana, catch before implementation):
    /// proves CLOSE/REVOKE_NOTICE's empty body never passes through
    /// `cbor::verify_canonical` — by contrast. An empty byte slice is not
    /// a parseable CBOR item at all (`ciborium` needs at least one byte
    /// for any item), so if this module's CLOSE/REVOKE_NOTICE decode path
    /// wrongly ran canonical-CBOR validation on the (correctly) empty
    /// body, this exact positive case would fail with a CBOR decode
    /// error instead of succeeding.
    #[test]
    fn red_close_and_revoke_notice_empty_body_never_reaches_cbor_verify_canonical() {
        assert!(
            crate::cbor::verify_canonical(&[]).is_err(),
            "test fixture invariant: an empty byte slice must not be valid CBOR, \
             or this RED cannot distinguish the two code paths"
        );
        assert_eq!(
            decode_post_active_record(&encode_close_record()).unwrap(),
            PostActiveRecord::Close
        );
        assert_eq!(
            decode_post_active_record(&encode_revoke_notice_record()).unwrap(),
            PostActiveRecord::RevokeNotice
        );
    }

    #[test]
    fn red_close_with_nonempty_body_rejected() {
        let mut malformed = encode_close_record();
        malformed.push(0x00);
        assert!(matches!(
            decode_post_active_record(&malformed),
            Err(PostActiveError::NonEmptyControlBody)
        ));
    }

    #[test]
    fn red_revoke_notice_with_nonempty_body_rejected() {
        let mut malformed = encode_revoke_notice_record();
        malformed.push(0x00);
        assert!(matches!(
            decode_post_active_record(&malformed),
            Err(PostActiveError::NonEmptyControlBody)
        ));
    }

    #[test]
    fn rekey_golden_canonical_round_trips() {
        let encoded = encode_rekey_record(7).unwrap();
        assert_eq!(
            decode_post_active_record(&encoded).unwrap(),
            PostActiveRecord::Rekey { next_generation: 7 }
        );
    }

    #[test]
    fn red_rekey_unknown_field_rejected() {
        // Hand-build a map with next_generation PLUS an extra field —
        // deny_unknown_fields must reject it.
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct WithExtra {
            next_generation: u64,
            extra: u64,
        }
        let body = crate::cbor::to_canonical_vec(&WithExtra {
            next_generation: 1,
            extra: 2,
        })
        .unwrap();
        let plaintext = wire::encode_typed_frame(REKEY_TYPE_BYTE, &body).unwrap();
        assert!(decode_post_active_record(&plaintext).is_err());
    }

    #[test]
    fn red_rekey_noncanonical_rejected() {
        // Build canonical bytes, then splice in a non-canonical (2-byte
        // encoded) length-1 unsigned int, which ciborium accepts on
        // decode but is not the shortest form.
        let good = wire::encode_typed_frame(
            REKEY_TYPE_BYTE,
            &crate::cbor::to_canonical_vec(&RekeyMarkerWire { next_generation: 1 }).unwrap(),
        )
        .unwrap();
        // good = [0x40, 0xa1, 0x6f, ..."next_generation"..., 0x01]
        // Replace the trailing canonical `0x01` (shortest-form uint 1)
        // with the 2-byte form `0x18 0x01` (major 0, additional info 24).
        assert_eq!(*good.last().unwrap(), 0x01);
        let mut bad = good[..good.len() - 1].to_vec();
        bad.push(0x18);
        bad.push(0x01);
        assert!(decode_post_active_record(&bad).is_err());
    }

    #[test]
    fn red_rekey_trailing_bytes_rejected() {
        let mut malformed = encode_rekey_record(1).unwrap();
        malformed.push(0x00);
        assert!(decode_post_active_record(&malformed).is_err());
    }

    #[test]
    fn red_type_swap_0x01_through_0x05_rejected() {
        for type_byte in 0x01u8..=0x05 {
            let plaintext = vec![type_byte];
            match decode_post_active_record(&plaintext) {
                Err(PostActiveError::UnexpectedAuthFrame(got)) => assert_eq!(got, type_byte),
                other => panic!(
                    "type byte {type_byte:#04x}: expected UnexpectedAuthFrame, got {other:?}"
                ),
            }
        }
    }

    #[test]
    fn red_0x06_intent_record_rejected() {
        assert!(matches!(
            decode_post_active_record(&[0x06]),
            Err(PostActiveError::UnexpectedIntentRecord)
        ));
    }

    #[test]
    fn red_0x07_reserved_never_decodes() {
        assert!(matches!(
            decode_post_active_record(&[0x07]),
            Err(PostActiveError::ReservedTypeByte)
        ));
    }

    #[test]
    fn red_unknown_type_byte_rejected() {
        for &b in &[0x00u8, 0x08, 0x11, 0x41, 0xff] {
            assert!(matches!(
                decode_post_active_record(&[b]),
                Err(PostActiveError::UnknownTypeByte(got)) if got == b
            ));
        }
    }

    #[test]
    fn red_empty_plaintext_rejected() {
        assert!(matches!(
            decode_post_active_record(&[]),
            Err(PostActiveError::EmptyRecord)
        ));
    }
}
