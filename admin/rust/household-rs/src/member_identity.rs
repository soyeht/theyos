//! Stable guest member identity for shared-access groups (Fase E1).
//!
//! Today a guest is an EPHEMERAL per-share P-256 device key (`guest_device_pub`)
//! with no link to a long-lived identity — a new device is a new stranger. For
//! durable group membership ("the same Alice across her phones and re-shares"),
//! a guest holds ONE long-lived **member key** and derives a stable `member_id`
//! from it. Each device still uses a fresh per-share device key + mesh npub for
//! all crypto; a [`MemberDeviceBinding`] — signed by the member key — vouches
//! that a `(device_pub, participant_npub)` belongs to that member.
//!
//! Privacy: `member_id` is derived from a bare P-256 key with NO link to email/
//! phone (the same posture as the per-share device key, only persisted). It is a
//! correlation handle WITHIN one household and MUST stay engine-internal — only
//! per-device npubs ever appear in published rosters/deny-lists.
//!
//! Authority note: this binding is MEMBER-self-signed (sybil-resistant: a member
//! can only bind devices under its own derived id). It does NOT, by itself, make
//! the member trusted by a household — that is the owner's job, via the
//! owner-signed group-membership events in `household_mesh_log`.

use serde::{Deserialize, Serialize};

use crate::cbor;
use crate::error::{HouseholdError, KeystoreError};
use crate::ids::{base32_lower_nopad_encode, hash_public_key};
use crate::keys::{IdentityKey, P256PublicKey, P256Signature, verify_signature};

/// `g_` + 52-char base32, stable per member public key. Distinct prefix from the
/// household `p_`/`m_` ids so a member id can never be confused with a
/// person/machine id.
pub const MEMBER_ID_PREFIX: &str = "g_";

const MEMBER_DEVICE_BINDING_VERSION: u8 = 1;
const MEMBER_DEVICE_BINDING_KIND: &str = "claw-share/member-device/v1";

/// Derive a stable member id from a 33-byte SEC1 compressed P-256 member key.
#[must_use]
pub fn derive_member_id(member_pub: &P256PublicKey) -> String {
    let h = hash_public_key(member_pub.as_bytes());
    format!("{MEMBER_ID_PREFIX}{}", base32_lower_nopad_encode(&h))
}

/// Member-signed statement: "`device_pub` D and mesh npub N belong to member M".
/// The engine verifies this on group-join enrollment, then records the device
/// under the member in the mesh log (`MeshMemberDeviceEnrolled`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberDeviceBinding {
    pub v: u8,
    pub kind: String,
    pub member_id: String,
    pub member_pub: P256PublicKey,
    pub device_pub: P256PublicKey,
    pub participant_npub: String,
    pub issued_at: u64,
    pub member_signature: P256Signature,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct MemberDeviceBindingUnsigned<'a> {
    v: u8,
    kind: &'a str,
    member_id: &'a str,
    member_pub: &'a P256PublicKey,
    device_pub: &'a P256PublicKey,
    participant_npub: &'a str,
    issued_at: u64,
}

impl MemberDeviceBinding {
    /// Sign a binding with the long-lived MEMBER key. `member_id` is derived
    /// from the member key, so a member can only ever bind devices under its own
    /// (sybil-resistant) id.
    pub fn sign(
        member_key: &dyn IdentityKey,
        device_pub: P256PublicKey,
        participant_npub: String,
        issued_at: u64,
    ) -> Result<Self, MemberIdentityError> {
        let member_pub = member_key.public();
        let member_id = derive_member_id(&member_pub);
        let unsigned = MemberDeviceBindingUnsigned {
            v: MEMBER_DEVICE_BINDING_VERSION,
            kind: MEMBER_DEVICE_BINDING_KIND,
            member_id: &member_id,
            member_pub: &member_pub,
            device_pub: &device_pub,
            participant_npub: &participant_npub,
            issued_at,
        };
        let bytes = cbor::to_canonical_vec(&unsigned).map_err(MemberIdentityError::Cbor)?;
        let member_signature = member_key.sign(&bytes).map_err(MemberIdentityError::Sign)?;
        Ok(Self {
            v: MEMBER_DEVICE_BINDING_VERSION,
            kind: MEMBER_DEVICE_BINDING_KIND.to_string(),
            member_id,
            member_pub,
            device_pub,
            participant_npub,
            issued_at,
            member_signature,
        })
    }

    /// Verify the member self-signature AND that `member_id` derives from
    /// `member_pub` (so a forged id can never impersonate another member).
    pub fn verify(&self) -> Result<(), MemberIdentityError> {
        if self.v != MEMBER_DEVICE_BINDING_VERSION {
            return Err(MemberIdentityError::VersionUnsupported(self.v));
        }
        if self.kind != MEMBER_DEVICE_BINDING_KIND {
            return Err(MemberIdentityError::KindMismatch(self.kind.clone()));
        }
        if self.member_id != derive_member_id(&self.member_pub) {
            return Err(MemberIdentityError::MemberIdMismatch);
        }
        let unsigned = MemberDeviceBindingUnsigned {
            v: self.v,
            kind: &self.kind,
            member_id: &self.member_id,
            member_pub: &self.member_pub,
            device_pub: &self.device_pub,
            participant_npub: &self.participant_npub,
            issued_at: self.issued_at,
        };
        let bytes = cbor::to_canonical_vec(&unsigned).map_err(MemberIdentityError::Cbor)?;
        verify_signature(&self.member_pub, &bytes, &self.member_signature)
            .map_err(|_| MemberIdentityError::SignatureRejected)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MemberIdentityError {
    #[error("member device binding version unsupported: {0}")]
    VersionUnsupported(u8),
    #[error("member device binding kind mismatch: {0}")]
    KindMismatch(String),
    #[error("member_id does not derive from member_pub")]
    MemberIdMismatch,
    #[error("member device binding cbor error: {0}")]
    Cbor(#[source] HouseholdError),
    #[error("member device binding sign error: {0}")]
    Sign(#[source] KeystoreError),
    #[error("member device binding signature rejected")]
    SignatureRejected,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::P256Keypair;

    #[test]
    fn member_id_is_stable_g_prefixed_base32() {
        let member = P256Keypair::generate();
        let id1 = derive_member_id(&member.public());
        let id2 = derive_member_id(&member.public());
        assert_eq!(id1, id2);
        assert!(id1.starts_with("g_"));
        assert_eq!(id1.len(), MEMBER_ID_PREFIX.len() + 52);
    }

    #[test]
    fn binding_round_trips_and_verifies() {
        let member = P256Keypair::generate();
        let device = P256Keypair::generate();
        let binding = MemberDeviceBinding::sign(
            &member,
            device.public(),
            "npub_hex_xonly".to_string(),
            1_800_000_000,
        )
        .unwrap();

        assert_eq!(binding.member_id, derive_member_id(&member.public()));
        binding.verify().unwrap();

        // Canonical CBOR round-trips intact and the decoded binding still verifies.
        let bytes = cbor::to_canonical_vec(&binding).unwrap();
        let decoded: MemberDeviceBinding = cbor::from_canonical_slice(&bytes).unwrap();
        assert_eq!(decoded, binding);
        decoded.verify().unwrap();
    }

    #[test]
    fn forged_member_id_is_rejected_before_signature() {
        let member = P256Keypair::generate();
        let device = P256Keypair::generate();
        let mut binding =
            MemberDeviceBinding::sign(&member, device.public(), "npub".to_string(), 1).unwrap();
        binding.member_id = format!("{MEMBER_ID_PREFIX}{}", "a".repeat(52));
        assert!(matches!(
            binding.verify(),
            Err(MemberIdentityError::MemberIdMismatch)
        ));
    }

    #[test]
    fn tampered_device_pub_breaks_signature() {
        let member = P256Keypair::generate();
        let device = P256Keypair::generate();
        let other = P256Keypair::generate();
        let mut binding =
            MemberDeviceBinding::sign(&member, device.public(), "npub".to_string(), 1).unwrap();
        binding.device_pub = other.public();
        assert!(matches!(
            binding.verify(),
            Err(MemberIdentityError::SignatureRejected)
        ));
    }
}
