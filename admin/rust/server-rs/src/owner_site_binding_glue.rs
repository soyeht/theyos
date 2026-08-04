//! S2 binding glue — derive `binding_id` / `binding_digest` from the roster
//! `machine_cert` and the A2 session keys, deterministically, so BOTH sides
//! compute the same values and the peer's C1 claim resolves exactly.
//!
//! ## Field origins (the observation-mapping discipline, applied to bindings)
//!
//! | field | origin | why this is the authority |
//! |---|---|---|
//! | `machine_cert` | roster authority (`MachineRosterMemberV1`) | the roster is the only authority that vouches machine↔cert |
//! | `member_device` | `MemberDeviceBinding` inside the machine cert | verified by `MemberDeviceBinding::verify`, never trusted raw |
//! | `channel_auth` / `action_pop` public keys | the device ENROLLMENT (owner-signed, distributed before the handshake) | keys are enrolled BEFORE the handshake; the handshake PROVES POSSESSION by signing the transcript — it does not birth them |
//!
//! ## One session key MAY serve both roles (ratified 2026-08-01)
//!
//! The separation between channel-auth and action-PoP lives in the
//! transcript PREIMAGE (`DeviceAuthHash` vs `OwnerActionHash` differ from
//! byte 0 of the canonical encoding), not in the keys. One P-256 key —
//! the device key already enrolled in the roster — serves both verifier
//! roles; cross-domain verification fails on the preimage, not the key.
//! **The enrollment flow for distinct session keys is therefore DEAD.**
//!
//! Reopening trigger, named: if a requirement ever appears to revoke
//! action-authority WITHOUT dropping the channel, distinct keys return as
//! an ADDITIVE v2 — bindings are per-session, so reopening is additive,
//! never migratory. Keeping the door open today would mean building an
//! enrollment flow for an unmeasured need: surface without an owner.
//! | scope / resource | the server-owned A2 request context | the server decides what it serves |
//! | `enrolled_at` generation | the roster adapter's observation (floor-less digest) | like-to-like with the AKE's comparison target |
//!
//! ## What the glue does NOT derive
//!
//! - It does NOT derive anything from an address: no `ConnectInfo`, no CIDR,
//!   no interface name. An address is not an identity input here, ever.
//! - It does NOT invent a `channel_auth`/`action_pop` key: absent session
//!   keys ⇒ NO binding (the keys are session-born; fabricating them would be
//!   inventing authority).
//! - It does NOT derive `binding_id` from the roster alone: a binding is
//!   roster-member × session-keys; roster alone is a machine, not a binding.
//!
//! ## Digest discipline (the lesson of the projection digest)
//!
//! Both digests are domain-separated SHA-256 over the canonical CBOR of the
//! declared tuple — nothing else enters the preimage. `binding_id` and
//! `binding_digest` use DIFFERENT domains so one can never be mistaken for
//! the other (the third-digest lesson: three similar digests on one path is
//! an invitation to pick the wrong one twice).

use sha2::{Digest, Sha256};

use crate::owner_site_a2_wire::{ClientHelloCore, ServerHello};
use crate::owner_site_authority::{
    DeviceAuthHash, OwnerActionHash, OwnerSiteAuthorityError, OwnerSiteBindingDigest,
    OwnerSiteBindingId, OwnerSiteChannelAuthKeyId,
};

/// The channel-binding pre-transcript. Produced ONLY by [`pop_binding_pre`]
/// from the Noise transcript `t1` and the device static — there is NO
/// constructor from raw bytes. This is the last rung of the chain: with a
/// naked `[u8; 32]` parameter, `compute` would still accept a forged pre
/// and emit a "correctly computed" hash of it — the same hole one layer
/// down, with a better-looking name. Typed to where the bytes are actually
/// born (the AKE transcript), the injection point no longer exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChannelBindingPre([u8; 32]);

impl ChannelBindingPre {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The A2 protocol domain. Shared by BOTH sides of the handshake — the
/// harness and the production M3 verification call the SAME functions
/// below; a second implementation of any of these preimages would diverge
/// in silence ("handshake never works", three layers from the cause).
pub(crate) const A2_DOMAIN: &str = "soyeht/owner-site/a2/v1";

pub(crate) fn hash_canonical<T: serde::Serialize>(
    value: &T,
) -> Result<[u8; 32], OwnerSiteAuthorityError> {
    let bytes = household_rs::cbor::to_canonical_vec(value)
        .map_err(|_| OwnerSiteAuthorityError::CborEncode)?;
    Ok(Sha256::digest(&bytes).into())
}

// NOTE: the `serde_bytes` attributes below are load-bearing — without them
// the byte fields encode as CBOR arrays instead of CBOR byte strings and
// the digest differs from the harness's. Both sides MUST produce identical
// preimages or the handshake never verifies.
#[derive(serde::Serialize)]
struct PopBindingTranscript<'a>(
    &'a str,
    &'a str,
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
);

/// `pop_binding_pre(t1, device_static)` — the shared pre-binding the device
/// signs over. Same function on both sides, and the ONLY producer of
/// [`ChannelBindingPre`].
#[allow(dead_code)]
pub(crate) fn pop_binding_pre(
    t1: [u8; 32],
    device_static: [u8; 32],
) -> Result<ChannelBindingPre, OwnerSiteAuthorityError> {
    let digest = hash_canonical(&PopBindingTranscript(
        A2_DOMAIN,
        "pop-binding",
        &t1,
        &device_static,
    ))?;
    Ok(ChannelBindingPre(digest))
}

#[derive(serde::Serialize)]
struct DeviceAuthTranscript<'a>(
    &'a str,
    &'a str,
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    &'a str,
    &'a str,
);

/// The ONE producer of `DeviceAuthHash` in production: it takes the
/// transcript INPUTS and computes inside — there is no parameter of bytes
/// by which wire bytes could be passed (the `from_glue` move, third time),
/// and the pre arrives as [`ChannelBindingPre`], which itself has no
/// from-bytes path (fourth time).
#[allow(dead_code)]
pub(crate) fn device_auth_hash(
    channel_binding_pre: &ChannelBindingPre,
    binding_id: &OwnerSiteBindingId,
    binding_digest: &OwnerSiteBindingDigest,
    participant_npub: &str,
    channel_auth_key_id: &OwnerSiteChannelAuthKeyId,
) -> Result<DeviceAuthHash, OwnerSiteAuthorityError> {
    let digest = hash_canonical(&DeviceAuthTranscript(
        A2_DOMAIN,
        "D-auth",
        channel_binding_pre.as_bytes(),
        binding_id.as_bytes(),
        binding_digest.as_bytes(),
        participant_npub,
        channel_auth_key_id.as_str(),
    ))?;
    Ok(DeviceAuthHash::from_digest_impl(digest))
}

#[derive(serde::Serialize)]
struct OwnerActionTranscript<'a>(
    &'a str,
    &'a str,
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    u64,
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    &'a str,
    &'a str,
    &'a str,
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    &'a str,
    &'a str,
    &'a str,
    #[serde(with = "serde_bytes")] &'a [u8],
    u64,
    #[serde(with = "serde_bytes")] &'a [u8],
    u64,
);

/// The ONE producer of `OwnerActionHash` in production: transcript fields
/// in, hash out — same function the peer uses, never a reimplementation.
/// The intent enters already canonically encoded by the caller's own
/// `encode_canonical` (the wire form), never re-encoded differently here.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn owner_action_hash(
    channel_binding_pre: &ChannelBindingPre,
    m2: &ServerHello,
    c1: &ClientHelloCore,
    binding_id: &OwnerSiteBindingId,
    binding_digest: &OwnerSiteBindingDigest,
    participant_npub: &str,
    intent_wire: &[u8],
) -> Result<OwnerActionHash, OwnerSiteAuthorityError> {
    let digest = hash_canonical(&OwnerActionTranscript(
        A2_DOMAIN,
        "owner-action",
        channel_binding_pre.as_bytes(),
        &m2.channel_id,
        m2.channel_epoch,
        &m2.challenge_id,
        &m2.challenge_secret,
        &c1.household_id,
        &c1.network_id,
        &m2.engine_key_id,
        binding_id.as_bytes(),
        binding_digest.as_bytes(),
        participant_npub,
        &c1.route,
        &c1.resource,
        intent_wire,
        m2.authz_epoch,
        &m2.roster_digest,
        m2.fresh_until,
    ))?;
    Ok(OwnerActionHash::from_digest_impl(digest))
}

// Consumed by the binding-establishment flow when the glue lands (named
// increment); the allows come off then — same pattern as the roster arm.
#[allow(dead_code)]
const BINDING_ID_DOMAIN: &[u8] = b"theyos/owner-site/binding-id/v1";
#[allow(dead_code)]
const BINDING_DIGEST_DOMAIN: &[u8] = b"theyos/owner-site/binding-digest/v1";

/// The exact preimage tuple both sides canonicalize. Fields enter in
/// declaration order; no address-derived value may ever be added here.
#[allow(dead_code)]
#[derive(serde::Serialize)]
struct BindingPreimage<'a> {
    machine_cert: &'a [u8],
    channel_auth_public: &'a [u8],
    action_pop_public: &'a [u8],
    household_id: &'a str,
    network_id: &'a str,
    resource: &'a str,
    enrolled_epoch: u64,
    enrolled_digest: &'a [u8],
}

#[allow(dead_code)]
fn domain_hash(domain: &[u8], preimage_cbor: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(preimage_cbor);
    hasher.finalize().into()
}

/// Derive the pair (`binding_id`, `binding_digest`) both sides must agree on.
///
/// # Errors
/// [`OwnerSiteAuthorityError::CborEncode`] if the preimage cannot be encoded
/// canonically (never expected for these field types, but fail-closed).
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn derive_binding_id_and_digest(
    machine_cert: &[u8],
    channel_auth_public: &[u8],
    action_pop_public: &[u8],
    household_id: &str,
    network_id: &str,
    resource: &str,
    enrolled_epoch: u64,
    enrolled_digest: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), OwnerSiteAuthorityError> {
    let preimage = BindingPreimage {
        machine_cert,
        channel_auth_public,
        action_pop_public,
        household_id,
        network_id,
        resource,
        enrolled_epoch,
        enrolled_digest,
    };
    let cbor = household_rs::cbor::to_canonical_vec(&preimage)
        .map_err(|_| OwnerSiteAuthorityError::CborEncode)?;
    Ok((
        domain_hash(BINDING_ID_DOMAIN, &cbor),
        domain_hash(BINDING_DIGEST_DOMAIN, &cbor),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &[u8] = b"machine-cert-bytes";
    const CH: &[u8; 33] = &[0x02; 33];
    const POP: &[u8; 33] = &[0x03; 33];
    const DIGEST: &[u8; 32] = &[7u8; 32];

    fn derive() -> ([u8; 32], [u8; 32]) {
        derive_binding_id_and_digest(CERT, CH, POP, "hh-a", "net-a", "claw-a", 7, DIGEST)
            .expect("derivation succeeds")
    }

    /// Like-to-like: identical inputs on both sides must yield identical
    /// id/digest — this is what makes the peer's claim resolvable at all.
    #[test]
    fn derivation_is_deterministic_for_identical_inputs() {
        assert_eq!(derive(), derive());
    }

    /// id and digest never coincide (different domains): one cannot be
    /// mistaken for the other on a path that carries both.
    #[test]
    fn id_and_digest_are_domain_separated() {
        let (id, digest) = derive();
        assert_ne!(id, digest);
    }

    /// Every declared input is load-bearing: changing ANY one changes the
    /// digest. A field that did not move the digest would be decoration —
    /// and decoration in an authority preimage is a hole.
    #[test]
    fn every_preimage_field_is_load_bearing() {
        let (base_id, base_digest) = derive();
        let other_ch = &[0x12; 33];
        let other_pop = &[0x13; 33];
        let other_digest = &[8u8; 32];
        for (id, digest) in [
            derive_binding_id_and_digest(
                b"other-cert",
                CH,
                POP,
                "hh-a",
                "net-a",
                "claw-a",
                7,
                DIGEST,
            )
            .unwrap(),
            derive_binding_id_and_digest(CERT, other_ch, POP, "hh-a", "net-a", "claw-a", 7, DIGEST)
                .unwrap(),
            derive_binding_id_and_digest(CERT, CH, other_pop, "hh-a", "net-a", "claw-a", 7, DIGEST)
                .unwrap(),
            derive_binding_id_and_digest(CERT, CH, POP, "hh-b", "net-a", "claw-a", 7, DIGEST)
                .unwrap(),
            derive_binding_id_and_digest(CERT, CH, POP, "hh-a", "net-a", "claw-b", 7, DIGEST)
                .unwrap(),
            derive_binding_id_and_digest(CERT, CH, POP, "hh-a", "net-a", "claw-a", 8, DIGEST)
                .unwrap(),
            derive_binding_id_and_digest(CERT, CH, POP, "hh-a", "net-a", "claw-a", 7, other_digest)
                .unwrap(),
        ] {
            assert_ne!(id, base_id, "an input change must move the binding id");
            assert_ne!(
                digest, base_digest,
                "an input change must move the binding digest"
            );
        }
    }
}
