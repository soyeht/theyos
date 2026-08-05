//! Claw-share — time-bound guest access to a single claw inside a household.
//!
//! Unlike `pair_machine` (Mac → household member) or `pair_device`
//! (device → owner), claw-share lets the household owner grant a third
//! party (friend, family member, contractor) ephemeral access to one
//! specific claw **without** making them a household member.
//!
//! The shapes in this module are the wire contract for the friend-join
//! flow. They are transport-agnostic on purpose — the slice ships first
//! over an in-process loopback channel; the same envelopes can ride a
//! relay-backed transport later without changes.
//!
//! Flow:
//!
//!   1. Owner mints `ClawShareInvite`. Signed by the owner identity over
//!      canonical CBOR of every field except `owner_signature`. Shared
//!      out-of-band (link, `AirDrop`, QR).
//!   2. Guest's device parses the invite, generates a fresh P-256 device
//!      keypair (one per share — no Apple-ID/email coupling), and sends
//!      `ClawShareClaim` over the configured transport. The claim carries
//!      a signature by the guest's device key proving possession.
//!   3. Engine verifies invite (owner signature, expiry, slot still open),
//!      verifies the claim (guest device signature, nonce freshness),
//!      atomically consumes the slot, mints a `GuestCredential` bound to
//!      `(guest_device_pub, claw_id, expires_at)` and signed by the owner.
//!   4. Engine returns `ClawShareAck` with the credential and a
//!      `TunnelHandle` the guest can dial.
//!
//! Trust model: the owner vouches for the guest's device. The guest is
//! never a household member, never holds a `PersonCert`, never accumulates
//! household-management caveats. The credential's authority is bounded
//! by `(claw_id, expires_at, revoked)`.

use std::collections::HashMap;
use std::sync::Mutex;

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::cbor;
use crate::error::HouseholdError;
use crate::ids::HouseholdId;
use crate::keys::{IdentityKey, P256PublicKey, P256Signature, verify_signature};
use crate::machine_cert::PersonId;
use crate::member_identity::MemberDeviceBinding;

// ─── Constants ───────────────────────────────────────────────────────────────

pub const CLAW_SHARE_INVITE_VERSION: u8 = 1;
pub const CLAW_SHARE_CLAIM_VERSION: u8 = 1;
pub const GUEST_CREDENTIAL_VERSION: u8 = 1;
/// Version of the optional Path-A [`GroupClaimRequest`] envelope carried by a
/// [`ClawShareClaim`].
pub const CLAW_SHARE_GROUP_REQUEST_VERSION: u8 = 1;
/// Version of the credential-less [`ClawShareGroupAck`] response.
pub const CLAW_SHARE_GROUP_ACK_VERSION: u8 = 1;

pub const SLOT_ID_LEN: usize = 16;
pub const NONCE_LEN: usize = 32;

/// Default invite TTL (the link the owner shares with the guest).
pub const DEFAULT_INVITE_TTL_SECS: u64 = 15 * 60;

/// Hard cap on invite TTL — refuse to mint anything longer.
pub const MAX_INVITE_TTL_SECS: u64 = 24 * 60 * 60;

/// Default credential TTL (how long the guest can use the claw after claim).
pub const DEFAULT_CREDENTIAL_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Hard cap on credential TTL.
pub const MAX_CREDENTIAL_TTL_SECS: u64 = 90 * 24 * 60 * 60;

/// Replay window on `ClawShareClaim.timestamp`.
pub const CLAIM_TIMESTAMP_TOLERANCE_SECS: u64 = 60;

// ─── Newtype IDs ─────────────────────────────────────────────────────────────

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SlotId(#[serde(with = "serde_bytes_16")] pub [u8; SLOT_ID_LEN]);

impl SlotId {
    #[must_use]
    pub fn random() -> Self {
        let mut buf = [0u8; SLOT_ID_LEN];
        rand::thread_rng().fill_bytes(&mut buf);
        Self(buf)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ClawShareError> {
        if bytes.len() != SLOT_ID_LEN {
            return Err(ClawShareError::SlotIdMalformed);
        }
        let mut out = [0u8; SLOT_ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SLOT_ID_LEN] {
        &self.0
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClaimNonce(#[serde(with = "serde_bytes_32")] pub [u8; NONCE_LEN]);

impl ClaimNonce {
    #[must_use]
    pub fn random() -> Self {
        let mut buf = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut buf);
        Self(buf)
    }
}

// ─── Transport handle ────────────────────────────────────────────────────────

// NOTE: the L3 overlay transport variants are intentionally NOT part of
// this relay/membership subset; only the loopback and direct-dial handles
// below ship here.

/// How the guest's device should dial the data plane after the claim
/// succeeds. Kept transport-agnostic so the slice can run over a loopback
/// channel or a direct same-LAN dial without changing the wire envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TunnelHandle {
    /// In-process channel keyed by an opaque string. Used by tests and
    /// the Mac-Studio single-host harness.
    Loopback { channel: String },
    /// Direct dial of the engine's data tunnel at a reachable `host:port`
    /// (LAN / same-network / reachable-address deployment). The engine
    /// advertises its operator-configured public data-tunnel address
    /// (`THEYOS_CLAW_DATA_TUNNEL_PUBLIC_ADDR`) so a friend with no overlay
    /// and no prior pairing can reach the PTY straight from the claim ack.
    /// `Direct`/`Loopback` are dev / same-LAN convenience and MUST NOT be
    /// the product path for a remote friend (no NAT traversal). The L3
    /// overlay transport variants are intentionally not part of this
    /// relay/membership subset.
    Direct { host: String, port: u16 },
}

// ─── ClawShareInvite ─────────────────────────────────────────────────────────

/// Envelope the owner shares with the guest (out-of-band link / QR).
///
/// `claim_relays` + `owner_engine_npub` are the relay store-and-forward
/// addresses: the canonical claim path is the friend publishing an
/// encrypted `ClaimRequest` to one of these relays addressed to
/// `owner_engine_npub`. Empty `claim_relays` means HTTP fast-path only
/// (the slice ships HTTP wired; the relay loop ships behind the same
/// envelope so the wire shape is stable across the transition).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClawShareInvite {
    /// Schema version. `v == 1` for the slice.
    pub v: u8,
    /// Domain-separation tag. `"claw-share/invite"` for the slice.
    pub kind: String,
    pub hh_id: HouseholdId,
    pub owner_p_id: PersonId,
    pub owner_p_pub: P256PublicKey,
    pub claw_id: String,
    pub slot_id: SlotId,
    pub transport_hint: TunnelHandle,
    /// Unix seconds. Engine + guest both reject if `expires_at <= now`.
    pub expires_at: u64,
    /// Engine's mesh-side npub the friend should target on the relay
    /// path. Empty string means relay not configured for this invite
    /// (HTTP-only fast-path).
    #[serde(default)]
    pub owner_engine_npub: String,
    /// Relay WSS URLs the friend may publish to. The friend tries each
    /// in order with backoff and stops on the first ack. Empty means
    /// relay path not configured.
    #[serde(default)]
    pub claim_relays: Vec<String>,
    pub owner_signature: P256Signature,
}

/// Mirrors `ClawShareInvite` minus `owner_signature`. Used to compute the
/// bytes the owner signs / the verifier checks.
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ClawShareInviteUnsigned<'a> {
    v: u8,
    kind: &'a str,
    hh_id: &'a HouseholdId,
    owner_p_id: &'a PersonId,
    owner_p_pub: &'a P256PublicKey,
    claw_id: &'a str,
    slot_id: &'a SlotId,
    transport_hint: &'a TunnelHandle,
    expires_at: u64,
    owner_engine_npub: &'a str,
    claim_relays: &'a [String],
}

const INVITE_KIND: &str = "claw-share/invite";

impl ClawShareInvite {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        hh_id: HouseholdId,
        owner_p_id: PersonId,
        owner_p_pub: P256PublicKey,
        claw_id: String,
        slot_id: SlotId,
        transport_hint: TunnelHandle,
        expires_at: u64,
        owner_engine_npub: String,
        claim_relays: Vec<String>,
        owner_key: &dyn IdentityKey,
    ) -> Result<Self, ClawShareError> {
        if owner_key.public() != owner_p_pub {
            return Err(ClawShareError::OwnerKeyMismatch);
        }
        let unsigned = ClawShareInviteUnsigned {
            v: CLAW_SHARE_INVITE_VERSION,
            kind: INVITE_KIND,
            hh_id: &hh_id,
            owner_p_id: &owner_p_id,
            owner_p_pub: &owner_p_pub,
            claw_id: &claw_id,
            slot_id: &slot_id,
            transport_hint: &transport_hint,
            expires_at,
            owner_engine_npub: &owner_engine_npub,
            claim_relays: &claim_relays,
        };
        let bytes = cbor::to_canonical_vec(&unsigned).map_err(ClawShareError::Cbor)?;
        let signature = owner_key.sign(&bytes).map_err(ClawShareError::Sign)?;
        Ok(Self {
            v: CLAW_SHARE_INVITE_VERSION,
            kind: INVITE_KIND.to_string(),
            hh_id,
            owner_p_id,
            owner_p_pub,
            claw_id,
            slot_id,
            transport_hint,
            expires_at,
            owner_engine_npub,
            claim_relays,
            owner_signature: signature,
        })
    }

    /// Verify the owner signature and the not-expired invariant.
    pub fn verify(&self, now_unix: u64) -> Result<(), ClawShareError> {
        if self.v != CLAW_SHARE_INVITE_VERSION {
            return Err(ClawShareError::VersionUnsupported(self.v));
        }
        if self.kind != INVITE_KIND {
            return Err(ClawShareError::KindMismatch(self.kind.clone()));
        }
        if self.expires_at <= now_unix {
            return Err(ClawShareError::InviteExpired);
        }
        let unsigned = ClawShareInviteUnsigned {
            v: self.v,
            kind: &self.kind,
            hh_id: &self.hh_id,
            owner_p_id: &self.owner_p_id,
            owner_p_pub: &self.owner_p_pub,
            claw_id: &self.claw_id,
            slot_id: &self.slot_id,
            transport_hint: &self.transport_hint,
            expires_at: self.expires_at,
            owner_engine_npub: &self.owner_engine_npub,
            claim_relays: &self.claim_relays,
        };
        let bytes = cbor::to_canonical_vec(&unsigned).map_err(ClawShareError::Cbor)?;
        verify_signature(&self.owner_p_pub, &bytes, &self.owner_signature)
            .map_err(|_| ClawShareError::InviteSignatureRejected)
    }
}

// ─── ClawShareClaim ──────────────────────────────────────────────────────────

/// Guest's device → engine. Proves possession of the guest device key and
/// freshness of the request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClawShareClaim {
    pub v: u8,
    pub kind: String,
    pub slot_id: SlotId,
    pub guest_device_pub: P256PublicKey,
    pub nonce: ClaimNonce,
    pub timestamp: u64,
    /// The friend's per-device overlay npub (x-only hex) the engine adds to
    /// the claw's participant roster. SIGNED (so a MITM can't swap in their
    /// own npub to gain routing access), and OPTIONAL: omitted by clients
    /// that don't yet enroll — when omitted, the canonical CBOR (and thus the
    /// signature) is byte-identical to an older claim, so old claims keep
    /// verifying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub participant_npub: Option<String>,
    /// Optional Path-A Group offer request envelope. Present means this claim is
    /// routed to the Group offer path; absent preserves the existing Device
    /// claim shape. This field is deliberately outside
    /// [`ClawShareClaimUnsigned`]: the nested request is self-authenticating via
    /// its member binding and device proof-of-possession, while Device claim
    /// signing bytes remain byte-stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_request: Option<GroupClaimRequest>,
    /// `r || s` over the canonical CBOR of every field above.
    pub guest_signature: P256Signature,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ClawShareClaimUnsigned<'a> {
    v: u8,
    kind: &'a str,
    slot_id: &'a SlotId,
    guest_device_pub: &'a P256PublicKey,
    nonce: &'a ClaimNonce,
    timestamp: u64,
    // Skipped when None → identical signing bytes to a pre-mesh claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    participant_npub: Option<&'a str>,
}

const CLAIM_KIND: &str = "claw-share/claim";

impl ClawShareClaim {
    /// Sign a claim with no mesh identity (pre-mesh / non-joining client). The
    /// signed bytes are identical to before `participant_npub` existed.
    pub fn sign(
        slot_id: SlotId,
        guest_device_pub: P256PublicKey,
        nonce: ClaimNonce,
        timestamp: u64,
        guest_key: &dyn IdentityKey,
    ) -> Result<Self, ClawShareError> {
        Self::sign_with_participant(slot_id, guest_device_pub, nonce, timestamp, None, guest_key)
    }

    /// Sign a claim, optionally binding the friend's mesh `participant_npub`
    /// (hex) into the signed payload so the engine can add it to the claw's
    /// roster on a verified claim.
    pub fn sign_with_participant(
        slot_id: SlotId,
        guest_device_pub: P256PublicKey,
        nonce: ClaimNonce,
        timestamp: u64,
        participant_npub: Option<String>,
        guest_key: &dyn IdentityKey,
    ) -> Result<Self, ClawShareError> {
        if guest_key.public() != guest_device_pub {
            return Err(ClawShareError::GuestKeyMismatch);
        }
        let unsigned = ClawShareClaimUnsigned {
            v: CLAW_SHARE_CLAIM_VERSION,
            kind: CLAIM_KIND,
            slot_id: &slot_id,
            guest_device_pub: &guest_device_pub,
            nonce: &nonce,
            timestamp,
            participant_npub: participant_npub.as_deref(),
        };
        let bytes = cbor::to_canonical_vec(&unsigned).map_err(ClawShareError::Cbor)?;
        let signature = guest_key.sign(&bytes).map_err(ClawShareError::Sign)?;
        Ok(Self {
            v: CLAW_SHARE_CLAIM_VERSION,
            kind: CLAIM_KIND.to_string(),
            slot_id,
            guest_device_pub,
            nonce,
            timestamp,
            participant_npub,
            group_request: None,
            guest_signature: signature,
        })
    }

    /// Sign a Group claim. The slot is a zero sentinel: Group claims do not
    /// consume invite slots, and the handler routes by `group_request`.
    pub fn sign_group(
        guest_device_pub: P256PublicKey,
        nonce: ClaimNonce,
        timestamp: u64,
        group_request: GroupClaimRequest,
        guest_key: &dyn IdentityKey,
    ) -> Result<Self, ClawShareError> {
        if guest_key.public() != guest_device_pub {
            return Err(ClawShareError::GuestKeyMismatch);
        }
        if group_request.binding.device_pub != guest_device_pub {
            return Err(ClawShareError::GroupDeviceKeyMismatch);
        }
        let slot_id = SlotId([0u8; SLOT_ID_LEN]);
        let unsigned = ClawShareClaimUnsigned {
            v: CLAW_SHARE_CLAIM_VERSION,
            kind: CLAIM_KIND,
            slot_id: &slot_id,
            guest_device_pub: &guest_device_pub,
            nonce: &nonce,
            timestamp,
            participant_npub: None,
        };
        let bytes = cbor::to_canonical_vec(&unsigned).map_err(ClawShareError::Cbor)?;
        let signature = guest_key.sign(&bytes).map_err(ClawShareError::Sign)?;
        Ok(Self {
            v: CLAW_SHARE_CLAIM_VERSION,
            kind: CLAIM_KIND.to_string(),
            slot_id,
            guest_device_pub,
            nonce,
            timestamp,
            participant_npub: None,
            group_request: Some(group_request),
            guest_signature: signature,
        })
    }

    /// Verify the guest signature, version, kind, and timestamp freshness.
    /// The slot binding (`slot_id` ↔ invite) is checked separately by the
    /// engine when it consumes the slot.
    pub fn verify(&self, now_unix: u64) -> Result<(), ClawShareError> {
        if self.v != CLAW_SHARE_CLAIM_VERSION {
            return Err(ClawShareError::VersionUnsupported(self.v));
        }
        if self.kind != CLAIM_KIND {
            return Err(ClawShareError::KindMismatch(self.kind.clone()));
        }
        let skew = now_unix.abs_diff(self.timestamp);
        if skew > CLAIM_TIMESTAMP_TOLERANCE_SECS {
            return Err(ClawShareError::ClaimReplayWindow { skew });
        }
        let unsigned = ClawShareClaimUnsigned {
            v: self.v,
            kind: &self.kind,
            slot_id: &self.slot_id,
            guest_device_pub: &self.guest_device_pub,
            nonce: &self.nonce,
            timestamp: self.timestamp,
            participant_npub: self.participant_npub.as_deref(),
        };
        let bytes = cbor::to_canonical_vec(&unsigned).map_err(ClawShareError::Cbor)?;
        verify_signature(&self.guest_device_pub, &bytes, &self.guest_signature)
            .map_err(|_| ClawShareError::ClaimSignatureRejected)
    }
}

// ─── GroupClaimRequest (Path-A Group offer transport) ─────────────────────────

/// Group offer request carried inside a [`ClawShareClaim`].
///
/// This mirrors the HTTP Group offer request shape so both transports can share
/// one verifier: the member-signed [`MemberDeviceBinding`] proves the member
/// authorized this device, and `device_pop` proves fresh possession of the bound
/// device key over the request fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupClaimRequest {
    pub v: u8,
    #[serde(with = "serde_bytes")]
    pub challenge: Vec<u8>,
    pub binding: MemberDeviceBinding,
    pub group_id: String,
    pub claw_id: String,
    pub device_pop: P256Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct GroupClaimRequestPopFields<'a> {
    v: u8,
    #[serde(with = "serde_bytes")]
    challenge: &'a [u8],
    group_id: &'a str,
    claw_id: &'a str,
    ttl_secs: Option<u64>,
}

impl GroupClaimRequest {
    pub fn sign(
        binding: MemberDeviceBinding,
        group_id: String,
        claw_id: String,
        challenge: Vec<u8>,
        ttl_secs: Option<u64>,
        device_key: &dyn IdentityKey,
    ) -> Result<Self, ClawShareError> {
        if device_key.public() != binding.device_pub {
            return Err(ClawShareError::GroupDeviceKeyMismatch);
        }
        let pop_fields = GroupClaimRequestPopFields {
            v: CLAW_SHARE_GROUP_REQUEST_VERSION,
            challenge: &challenge,
            group_id: &group_id,
            claw_id: &claw_id,
            ttl_secs,
        };
        let bytes = cbor::to_canonical_vec(&pop_fields).map_err(ClawShareError::Cbor)?;
        let device_pop = device_key.sign(&bytes).map_err(ClawShareError::Sign)?;
        Ok(Self {
            v: CLAW_SHARE_GROUP_REQUEST_VERSION,
            challenge,
            binding,
            group_id,
            claw_id,
            device_pop,
            ttl_secs,
        })
    }

    pub fn verify_device_pop(&self) -> Result<(), ClawShareError> {
        if self.v != CLAW_SHARE_GROUP_REQUEST_VERSION {
            return Err(ClawShareError::VersionUnsupported(self.v));
        }
        let pop_fields = GroupClaimRequestPopFields {
            v: self.v,
            challenge: &self.challenge,
            group_id: &self.group_id,
            claw_id: &self.claw_id,
            ttl_secs: self.ttl_secs,
        };
        let bytes = cbor::to_canonical_vec(&pop_fields).map_err(ClawShareError::Cbor)?;
        verify_signature(&self.binding.device_pub, &bytes, &self.device_pop)
            .map_err(|_| ClawShareError::GroupDevicePopRejected)
    }
}

// ─── GuestCredential ─────────────────────────────────────────────────────────

/// Authorization grant issued by the owner after a successful claim. Bound
/// to `(claw_id, guest_device_pub, expires_at)`. **Not** a household-member
/// cert — never carries household-management authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestCredential {
    pub v: u8,
    pub kind: String,
    pub hh_id: HouseholdId,
    pub owner_p_id: PersonId,
    pub owner_p_pub: P256PublicKey,
    pub claw_id: String,
    pub guest_device_pub: P256PublicKey,
    pub slot_id: SlotId,
    pub issued_at: u64,
    pub expires_at: u64,
    pub owner_signature: P256Signature,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct GuestCredentialUnsigned<'a> {
    v: u8,
    kind: &'a str,
    hh_id: &'a HouseholdId,
    owner_p_id: &'a PersonId,
    owner_p_pub: &'a P256PublicKey,
    claw_id: &'a str,
    guest_device_pub: &'a P256PublicKey,
    slot_id: &'a SlotId,
    issued_at: u64,
    expires_at: u64,
}

const CREDENTIAL_KIND: &str = "claw-share/guest-credential";

impl GuestCredential {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        hh_id: HouseholdId,
        owner_p_id: PersonId,
        owner_p_pub: P256PublicKey,
        claw_id: String,
        guest_device_pub: P256PublicKey,
        slot_id: SlotId,
        issued_at: u64,
        expires_at: u64,
        owner_key: &dyn IdentityKey,
    ) -> Result<Self, ClawShareError> {
        if owner_key.public() != owner_p_pub {
            return Err(ClawShareError::OwnerKeyMismatch);
        }
        if expires_at <= issued_at {
            return Err(ClawShareError::CredentialExpiryInvalid);
        }
        let lifetime = expires_at - issued_at;
        if lifetime > MAX_CREDENTIAL_TTL_SECS {
            return Err(ClawShareError::CredentialLifetimeExceedsCap { lifetime });
        }
        let unsigned = GuestCredentialUnsigned {
            v: GUEST_CREDENTIAL_VERSION,
            kind: CREDENTIAL_KIND,
            hh_id: &hh_id,
            owner_p_id: &owner_p_id,
            owner_p_pub: &owner_p_pub,
            claw_id: &claw_id,
            guest_device_pub: &guest_device_pub,
            slot_id: &slot_id,
            issued_at,
            expires_at,
        };
        let bytes = cbor::to_canonical_vec(&unsigned).map_err(ClawShareError::Cbor)?;
        let signature = owner_key.sign(&bytes).map_err(ClawShareError::Sign)?;
        Ok(Self {
            v: GUEST_CREDENTIAL_VERSION,
            kind: CREDENTIAL_KIND.to_string(),
            hh_id,
            owner_p_id,
            owner_p_pub,
            claw_id,
            guest_device_pub,
            slot_id,
            issued_at,
            expires_at,
            owner_signature: signature,
        })
    }

    /// Verify the owner signature and the not-expired invariant. The
    /// claw binding (`claw_id` exists, owner authorized to share it) is
    /// the caller's concern.
    pub fn verify(&self, now_unix: u64) -> Result<(), ClawShareError> {
        if self.v != GUEST_CREDENTIAL_VERSION {
            return Err(ClawShareError::VersionUnsupported(self.v));
        }
        if self.kind != CREDENTIAL_KIND {
            return Err(ClawShareError::KindMismatch(self.kind.clone()));
        }
        if self.expires_at <= now_unix {
            return Err(ClawShareError::CredentialExpired);
        }
        let unsigned = GuestCredentialUnsigned {
            v: self.v,
            kind: &self.kind,
            hh_id: &self.hh_id,
            owner_p_id: &self.owner_p_id,
            owner_p_pub: &self.owner_p_pub,
            claw_id: &self.claw_id,
            guest_device_pub: &self.guest_device_pub,
            slot_id: &self.slot_id,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        };
        let bytes = cbor::to_canonical_vec(&unsigned).map_err(ClawShareError::Cbor)?;
        verify_signature(&self.owner_p_pub, &bytes, &self.owner_signature)
            .map_err(|_| ClawShareError::CredentialSignatureRejected)
    }
}

// ─── ClawShareAck ────────────────────────────────────────────────────────────

/// Engine → guest after a successful claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClawShareAck {
    pub v: u8,
    pub credential: GuestCredential,
    pub tunnel: TunnelHandle,
    /// Opaque canonical-CBOR of a Product A `RelayStreamOfferContract`, for
    /// future relay-path-only delivery (C7c). Always `None` for now: nothing
    /// emits it yet. The bytes stay opaque so household-rs does not depend on
    /// the server-rs offer type. `#[serde(default)]` lets an older ack without
    /// the field decode as `None`, and `skip_serializing_if` omits it on the
    /// wire when `None`, so an older guest sees a byte-identical ack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_stream_offer: Option<serde_bytes::ByteBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClawShareGroupAck {
    pub v: u8,
    pub relay_stream_offer: serde_bytes::ByteBuf,
}

// ─── In-memory slot store ────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotRecord {
    pub slot_id: SlotId,
    pub claw_id: String,
    pub expires_at: u64,
    pub state: SlotState,
    pub app_presentation:
        Option<crate::claw_share_relay_stream_contract::ShareableAppPresentation>,
    /// When the invite was minted. `None` only where the mint event was never
    /// observed — a projection that saw a consume or a revoke before its mint.
    /// Never synthesized: an owner surface must be able to tell "minted then"
    /// from "we do not know", and a fabricated timestamp would be
    /// indistinguishable from a real one.
    pub created_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotState {
    Open,
    Consumed {
        guest_device_pub: P256PublicKey,
        consumed_at: u64,
    },
    Revoked {
        revoked_at: u64,
        /// Preserved across `Consumed -> Revoked`: the owner surface must still
        /// say whether — and when — the share was accepted, after revoking it.
        /// `None` means it was revoked while still Open.
        accepted_at: Option<u64>,
    },
}

/// In-memory slot store. Thread-safe. The slice uses this directly; a
/// persistent backend can replace it later behind a trait without
/// changing call sites.
pub struct ClawShareSlotStore {
    inner: Mutex<HashMap<SlotId, SlotRecord>>,
}

impl ClawShareSlotStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Rehydrate slot state from a mesh-log projection. Used at engine
    /// startup so a process restart cannot reopen invites that were
    /// consumed or revoked in a previous lifetime.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (cannot happen on a
    /// fresh store).
    #[must_use]
    pub fn seeded_from(projection: &crate::household_mesh_log::ProjectedState) -> Self {
        use crate::household_mesh_log::SlotProjectedStatus;
        let store = Self::new();
        let mut guard = store.inner.lock().expect("fresh mutex");
        for (slot_id, projected) in &projection.slots {
            let state = match &projected.status {
                SlotProjectedStatus::Open => SlotState::Open,
                SlotProjectedStatus::Consumed {
                    guest_device_pub,
                    consumed_at,
                    // The runtime slot store gates the PTY by guest_device_pub +
                    // claw_id; the mesh npub is a roster/projection concern only.
                    participant_npub: _,
                } => SlotState::Consumed {
                    guest_device_pub: guest_device_pub.clone(),
                    consumed_at: *consumed_at,
                },
                SlotProjectedStatus::Revoked {
                    revoked_at,
                    accepted_at,
                    ..
                } => SlotState::Revoked {
                    revoked_at: *revoked_at,
                    accepted_at: *accepted_at,
                },
            };
            guard.insert(
                slot_id.clone(),
                SlotRecord {
                    slot_id: slot_id.clone(),
                    claw_id: projected.claw_id.clone(),
                    expires_at: projected.expires_at,
                    state,
                    app_presentation: projected.app_presentation.clone(),
                    // Carried straight from the projection — the replay is the
                    // only place the runtime store learns it.
                    created_at: projected.created_at,
                },
            );
        }
        drop(guard);
        store
    }

    /// Insert a fresh open slot. Refuses to overwrite an existing entry.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned by a previous panic — at
    /// that point the store is unsafe to continue using.
    pub fn insert(&self, record: SlotRecord) -> Result<(), ClawShareError> {
        let mut guard = self.inner.lock().expect("slot store mutex poisoned");
        if guard.contains_key(&record.slot_id) {
            return Err(ClawShareError::SlotAlreadyExists);
        }
        guard.insert(record.slot_id.clone(), record);
        Ok(())
    }

    /// Atomic compare-and-swap: transition from `Open` to `Consumed`.
    /// Fails if the slot is missing, already consumed, revoked, or expired.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn consume_atomic(
        &self,
        slot_id: &SlotId,
        claw_id: &str,
        guest_device_pub: P256PublicKey,
        now_unix: u64,
    ) -> Result<SlotRecord, ClawShareError> {
        let mut guard = self.inner.lock().expect("slot store mutex poisoned");
        let record = guard.get_mut(slot_id).ok_or(ClawShareError::SlotNotFound)?;
        if record.claw_id != claw_id {
            return Err(ClawShareError::SlotClawMismatch);
        }
        match &record.state {
            SlotState::Open => {}
            SlotState::Consumed { .. } => return Err(ClawShareError::SlotAlreadyConsumed),
            SlotState::Revoked { .. } => return Err(ClawShareError::SlotRevoked),
        }
        if record.expires_at <= now_unix {
            return Err(ClawShareError::InviteExpired);
        }
        record.state = SlotState::Consumed {
            guest_device_pub,
            consumed_at: now_unix,
        };
        Ok(record.clone())
    }

    /// Force-revoke a slot regardless of current state, and return the
    /// CANONICAL revocation timestamp — the one from the FIRST revoke.
    ///
    /// Fully idempotent, not merely convergent on the status:
    /// - `Open` -> `Revoked { revoked_at: now, accepted_at: None }`
    /// - `Consumed` -> `Revoked { revoked_at: now, accepted_at: Some(consumed_at) }`,
    ///   so revoking never erases the fact that the share was accepted.
    /// - `Revoked` -> unchanged, and `now_unix` is ignored.
    ///
    /// Returning the canonical timestamp is what makes the caller's persistence
    /// retry-safe: signing the log event with THIS value yields the same
    /// `entry_id` every time, so a retry after a failed append still persists
    /// while a retry after a successful one dedupes.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn revoke(&self, slot_id: &SlotId, now_unix: u64) -> Result<u64, ClawShareError> {
        let mut guard = self.inner.lock().expect("slot store mutex poisoned");
        let record = guard.get_mut(slot_id).ok_or(ClawShareError::SlotNotFound)?;
        let (revoked_at, accepted_at) = match &record.state {
            SlotState::Open => (now_unix, None),
            SlotState::Consumed { consumed_at, .. } => (now_unix, Some(*consumed_at)),
            // Already revoked: keep the original decision intact.
            SlotState::Revoked {
                revoked_at,
                accepted_at,
            } => (*revoked_at, *accepted_at),
        };
        record.state = SlotState::Revoked {
            revoked_at,
            accepted_at,
        };
        Ok(revoked_at)
    }

    /// Snapshot the slot record by id, if present.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn get(&self, slot_id: &SlotId) -> Option<SlotRecord> {
        let guard = self.inner.lock().expect("slot store mutex poisoned");
        guard.get(slot_id).cloned()
    }
}

impl Default for ClawShareSlotStore {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ClawShareError {
    #[error("unsupported schema version: {0}")]
    VersionUnsupported(u8),

    #[error("envelope kind mismatch: {0}")]
    KindMismatch(String),

    #[error("owner-supplied key did not match the bound public key")]
    OwnerKeyMismatch,

    #[error("guest-supplied key did not match the bound public key")]
    GuestKeyMismatch,

    #[error("group request device key did not match the bound public key")]
    GroupDeviceKeyMismatch,

    #[error("group request device proof-of-possession verification failed")]
    GroupDevicePopRejected,

    #[error("invite is past expiry")]
    InviteExpired,

    #[error("invite signature verification failed")]
    InviteSignatureRejected,

    #[error("claim timestamp outside replay window (skew {skew}s)")]
    ClaimReplayWindow { skew: u64 },

    #[error("claim signature verification failed")]
    ClaimSignatureRejected,

    #[error("credential past expiry")]
    CredentialExpired,

    #[error("credential signature verification failed")]
    CredentialSignatureRejected,

    #[error("credential expires_at must be > issued_at")]
    CredentialExpiryInvalid,

    #[error("credential lifetime {lifetime}s exceeds 90-day cap")]
    CredentialLifetimeExceedsCap { lifetime: u64 },

    #[error("slot id malformed: expected {SLOT_ID_LEN} bytes")]
    SlotIdMalformed,

    #[error("slot already exists in store")]
    SlotAlreadyExists,

    #[error("slot not found")]
    SlotNotFound,

    #[error("slot claw_id mismatch")]
    SlotClawMismatch,

    #[error("slot already consumed")]
    SlotAlreadyConsumed,

    #[error("slot revoked")]
    SlotRevoked,

    #[error("CBOR encoding error: {0}")]
    Cbor(#[source] HouseholdError),

    #[error("signing failed: {0}")]
    Sign(#[source] crate::error::KeystoreError),

    #[error("URI is malformed or schema is unsupported")]
    UriMalformed,

    #[error("transport channel closed before the operation completed")]
    TransportClosed,

    #[error("unexpected frame received from transport")]
    UnexpectedFrame,

    #[error("returned credential was signed by a different owner key than the invite")]
    CredentialIssuerMismatch,

    #[error("returned credential's claw_id did not match the invite")]
    CredentialClawMismatch,

    #[error("returned credential's guest_device_pub did not match our key")]
    CredentialGuestMismatch,

    #[error("returned credential's slot_id did not match the invite")]
    CredentialSlotMismatch,
}

// ─── Owner mint helper ───────────────────────────────────────────────────────

/// Atomically mint a `ClawShareInvite` AND persist its slot record so the
/// engine will accept the matching claim later. Caller MUST be the owner
/// of `owner_key`.
///
/// `ttl_secs` is capped to [`MAX_INVITE_TTL_SECS`]. Both the invite envelope
/// and the slot record carry the same `expires_at = now_unix + ttl`.
#[allow(clippy::too_many_arguments)]
pub fn owner_mint_invite(
    owner_key: &dyn IdentityKey,
    owner_p_id: &PersonId,
    hh_id: &HouseholdId,
    claw_id: &str,
    transport_hint: TunnelHandle,
    ttl_secs: u64,
    now_unix: u64,
    owner_engine_npub: String,
    claim_relays: Vec<String>,
    slot_store: &ClawShareSlotStore,
) -> Result<ClawShareInvite, ClawShareError> {
    owner_mint_invite_with_presentation(
        owner_key,
        owner_p_id,
        hh_id,
        claw_id,
        transport_hint,
        ttl_secs,
        now_unix,
        owner_engine_npub,
        claim_relays,
        slot_store,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn owner_mint_invite_with_presentation(
    owner_key: &dyn IdentityKey,
    owner_p_id: &PersonId,
    hh_id: &HouseholdId,
    claw_id: &str,
    transport_hint: TunnelHandle,
    ttl_secs: u64,
    now_unix: u64,
    owner_engine_npub: String,
    claim_relays: Vec<String>,
    slot_store: &ClawShareSlotStore,
    app_presentation: Option<
        crate::claw_share_relay_stream_contract::ShareableAppPresentation,
    >,
) -> Result<ClawShareInvite, ClawShareError> {
    let ttl_capped = ttl_secs.min(MAX_INVITE_TTL_SECS);
    let expires_at = now_unix.saturating_add(ttl_capped);
    let slot_id = SlotId::random();

    let invite = ClawShareInvite::sign(
        hh_id.clone(),
        owner_p_id.clone(),
        owner_key.public(),
        claw_id.to_string(),
        slot_id.clone(),
        transport_hint,
        expires_at,
        owner_engine_npub,
        claim_relays,
        owner_key,
    )?;

    // The slot mirror has to land AFTER the signature succeeds, otherwise
    // a partial mint would leave a slot the engine accepts for a never-
    // shared invite. If the insert fails, the invite is discarded.
    slot_store.insert(SlotRecord {
        slot_id: invite.slot_id.clone(),
        claw_id: invite.claw_id.clone(),
        expires_at: invite.expires_at,
        state: SlotState::Open,
        app_presentation,
        // The real mint: `now` here is the same value the durable
        // `ClawShareSlotMinted` carries, so the live store and a later replay
        // agree on the creation time.
        created_at: Some(now_unix),
    })?;

    Ok(invite)
}

// ─── URI encoding ────────────────────────────────────────────────────────────

/// Soyeht claw-share URI scheme version. The full prefix is
/// `soyeht://claw-share/v1?e=`; the suffix is base64url(no-pad) over the
/// canonical CBOR of the [`ClawShareInvite`].
pub const CLAW_SHARE_URI_PREFIX: &str = "soyeht://claw-share/v1?e=";

impl ClawShareInvite {
    /// Render the invite as a shareable URI (link / QR text). The CBOR is
    /// the same canonical bytes the signature covers — round-tripping does
    /// not invalidate the signature.
    pub fn to_uri(&self) -> Result<String, ClawShareError> {
        use base64::Engine;
        let cbor = cbor::to_canonical_vec(self).map_err(ClawShareError::Cbor)?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cbor);
        Ok(format!("{CLAW_SHARE_URI_PREFIX}{encoded}"))
    }

    /// Parse a URI produced by [`Self::to_uri`]. Strict prefix match — any
    /// other scheme or version returns `UriMalformed`. Does NOT verify the
    /// signature; callers MUST call [`Self::verify`] before trusting any
    /// field.
    pub fn from_uri(uri: &str) -> Result<Self, ClawShareError> {
        use base64::Engine;
        let encoded = uri
            .strip_prefix(CLAW_SHARE_URI_PREFIX)
            .ok_or(ClawShareError::UriMalformed)?;
        let cbor = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ClawShareError::UriMalformed)?;
        cbor::from_canonical_slice(&cbor).map_err(ClawShareError::Cbor)
    }
}

// ─── serde helpers for fixed-length byte arrays ──────────────────────────────

mod serde_bytes_16 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let bytes: serde_bytes::ByteBuf = Deserialize::deserialize(d)?;
        if bytes.len() != 16 {
            return Err(Error::custom(format!(
                "expected 16-byte slot id, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod serde_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let bytes: serde_bytes::ByteBuf = Deserialize::deserialize(d)?;
        if bytes.len() != 32 {
            return Err(Error::custom(format!(
                "expected 32-byte nonce, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::derive_household_id;
    use crate::keys::P256Keypair;
    use crate::person_cert::derive_person_id;

    fn fresh_owner() -> (P256Keypair, HouseholdId, PersonId) {
        let kp = P256Keypair::generate();
        let pub_bytes = kp.public();
        let hh_id = derive_household_id(&pub_bytes);
        let p_id = derive_person_id(&pub_bytes);
        (kp, hh_id, p_id)
    }

    /// Cross-language fixture: a deterministic invite encoded to
    /// canonical CBOR. The hex literal below MUST be identical to the
    /// vector the Swift `ClawShareCodecTests.swift` fixture asserts.
    /// If you change the wire shape, regenerate both sides together.
    ///
    /// Deterministic inputs:
    /// - owner key: P-256 with secret scalar = [0x11; 32]
    /// - slot_id:   [0x22; 16]
    /// - expires_at: 1_800_000_000
    /// - claw_id:    "claw_fixture_v1"
    /// - transport:  Loopback { channel: "ch-fixture" }
    /// - owner_engine_npub: "npub_engine_fixture"
    /// - claim_relays:  ["wss://relay-a", "wss://relay-b"]
    #[test]
    fn cross_language_fixture_invite_hex() {
        let scalar = [0x11u8; 32];
        let owner_key = P256Keypair::from_secret_scalar(&scalar).expect("key");
        let pub_bytes = owner_key.public();
        let hh_id = derive_household_id(&pub_bytes);
        let owner_p_id = derive_person_id(&pub_bytes);
        let slot_id = SlotId([0x22u8; SLOT_ID_LEN]);
        let invite = ClawShareInvite::sign(
            hh_id,
            owner_p_id,
            owner_key.public(),
            "claw_fixture_v1".to_string(),
            slot_id,
            TunnelHandle::Loopback {
                channel: "ch-fixture".to_string(),
            },
            1_800_000_000,
            "npub_engine_fixture".to_string(),
            vec!["wss://relay-a".to_string(), "wss://relay-b".to_string()],
            &owner_key,
        )
        .expect("sign");
        let bytes = cbor::to_canonical_vec(&invite).expect("encode");
        let hex_actual = hex::encode(&bytes);
        // To regenerate after a wire-shape change:
        //   eprintln!("{hex_actual}");
        // The Swift counterpart pins this same hex via
        // `ClawShareCodecTests.cross_language_fixture_invite_hex`.
        let expected = ClawShareInvite::from_uri(&invite.to_uri().unwrap()).expect("decode self");
        assert_eq!(invite, expected, "self round-trip");
        // The hex is pinned by length: a wire-shape change visibly
        // mutates the byte length, and the matching Swift test will
        // also fail. We don't pin the full hex here because key
        // generation from a fixed scalar is the only non-portable
        // step — the signature varies if either side regenerates with
        // different `rfc6979` deps. The portable invariant is "Swift
        // can decode the Rust output AND the unsigned bytes match".
        let unsigned_bytes = cbor::to_canonical_vec(&ClawShareInviteUnsigned {
            v: invite.v,
            kind: &invite.kind,
            hh_id: &invite.hh_id,
            owner_p_id: &invite.owner_p_id,
            owner_p_pub: &invite.owner_p_pub,
            claw_id: &invite.claw_id,
            slot_id: &invite.slot_id,
            transport_hint: &invite.transport_hint,
            expires_at: invite.expires_at,
            owner_engine_npub: &invite.owner_engine_npub,
            claim_relays: &invite.claim_relays,
        })
        .expect("encode unsigned");
        let unsigned_hex = hex::encode(&unsigned_bytes);

        // Pinned cross-language fixture: the SAME hex literal lives
        // in `Packages/SoyehtCore/Tests/SoyehtCoreTests/
        // ClawShareCrossLanguageFixtureTests.swift`. If a wire-shape
        // change makes them diverge, both tests fail loudly. To
        // regenerate after an intentional wire-shape change, run this
        // test with `--nocapture` and copy the printed hex to both
        // files in lockstep.
        const EXPECTED_UNSIGNED_HEX: &str = "ab617601646b696e6471636c61772d73686172652f696e766974656568685f6964783768685f6a707173797570796f747268676175343579376e6575336c3370346c65723678687537646e32783232337232716636616769727167636c61775f69646f636c61775f666978747572655f763167736c6f745f696450222222222222222222222222222222226a657870697265735f61741a6b49d2006a6f776e65725f705f69647836705f6a707173797570796f747268676175343579376e6575336c3370346c65723678687537646e3278323233723271663661676972716b6f776e65725f705f7075625821020217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed6c636c61696d5f72656c617973826d7773733a2f2f72656c61792d616d7773733a2f2f72656c61792d626e7472616e73706f72745f68696e74a2646b696e64686c6f6f706261636b676368616e6e656c6a63682d66697874757265716f776e65725f656e67696e655f6e707562736e7075625f656e67696e655f66697874757265";
        assert_eq!(
            unsigned_hex, EXPECTED_UNSIGNED_HEX,
            "wire shape drift — Swift fixture is now stale"
        );

        // Determinism check inside the same compilation: re-encoding
        // the decoded invite must produce identical bytes.
        let re = cbor::to_canonical_vec(&invite).expect("re-encode");
        assert_eq!(re, bytes, "canonical encoding is not deterministic");
        let _ = hex_actual;
    }

    // The two L3-overlay cross-language tunnel-handle fixtures are
    // intentionally omitted from this relay/membership subset: that
    // overlay transport variant is not part of this landing.

    /// Cross-language fixture: deterministic `ClawShareClaim` unsigned
    /// canonical CBOR. Same lockstep contract as the invite fixture —
    /// the Swift counterpart in
    /// `ClawShareCrossLanguageFixtureTests.testUnsignedClaimCBORMatchesRustFixture`
    /// pins this same hex.
    #[test]
    fn cross_language_fixture_claim_hex() {
        let slot_id = SlotId([0x22u8; SLOT_ID_LEN]);
        let guest_scalar = [0x33u8; 32];
        let guest_key = P256Keypair::from_secret_scalar(&guest_scalar).expect("guest key");
        let guest_device_pub = guest_key.public();
        let nonce = ClaimNonce([0x44u8; NONCE_LEN]);
        let timestamp: u64 = 1_800_000_500;
        let unsigned = ClawShareClaimUnsigned {
            v: CLAW_SHARE_CLAIM_VERSION,
            kind: CLAIM_KIND,
            slot_id: &slot_id,
            guest_device_pub: &guest_device_pub,
            nonce: &nonce,
            timestamp,
            // None → skipped → byte-identical to a pre-mesh claim (a6 = 6-entry
            // map). This pins the backward-compat guarantee.
            participant_npub: None,
        };
        let bytes = cbor::to_canonical_vec(&unsigned).expect("encode");
        let unsigned_hex = hex::encode(&bytes);
        const EXPECTED_UNSIGNED_HEX: &str = "a6617601646b696e6470636c61772d73686172652f636c61696d656e6f6e63655820444444444444444444444444444444444444444444444444444444444444444467736c6f745f696450222222222222222222222222222222226974696d657374616d701a6b49d3f47067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d";
        assert_eq!(
            unsigned_hex, EXPECTED_UNSIGNED_HEX,
            "claim wire shape drift — Swift fixture is now stale"
        );
        let re = cbor::to_canonical_vec(&unsigned).expect("re-encode");
        assert_eq!(re, bytes);
    }

    #[test]
    fn claim_participant_npub_is_signed_and_tamper_proof() {
        let slot_id = SlotId([0x22u8; SLOT_ID_LEN]);
        let guest_key = P256Keypair::from_secret_scalar(&[0x33u8; 32]).expect("guest key");
        let guest_device_pub = guest_key.public();
        let nonce = ClaimNonce([0x44u8; NONCE_LEN]);
        let ts: u64 = 1_800_000_500;
        let npub = "82f283e20094eb4da5922cfba6c0284b790525f4d4ddb2d17fd98f1bd0956c02";

        let claim = ClawShareClaim::sign_with_participant(
            slot_id.clone(),
            guest_device_pub.clone(),
            nonce.clone(),
            ts,
            Some(npub.to_string()),
            &guest_key as &dyn IdentityKey,
        )
        .expect("sign");
        claim.verify(ts).expect("verify");
        assert_eq!(claim.participant_npub.as_deref(), Some(npub));

        // The npub is inside the signed payload: swapping it (a MITM trying to
        // gain mesh routing under their own npub) breaks verification.
        let mut tampered = claim.clone();
        tampered.participant_npub = Some("00".repeat(32));
        assert!(matches!(
            tampered.verify(ts),
            Err(ClawShareError::ClaimSignatureRejected)
        ));

        // Dropping it from a claim that signed WITH it also fails — bound, not
        // advisory.
        let mut dropped = claim.clone();
        dropped.participant_npub = None;
        assert!(matches!(
            dropped.verify(ts),
            Err(ClawShareError::ClaimSignatureRejected)
        ));

        // Cross-language fixture: Some-variant unsigned CBOR (a7 = 7-entry map;
        // participant_npub sorts last). Swift must pin the same hex.
        let unsigned = ClawShareClaimUnsigned {
            v: CLAW_SHARE_CLAIM_VERSION,
            kind: CLAIM_KIND,
            slot_id: &slot_id,
            guest_device_pub: &guest_device_pub,
            nonce: &nonce,
            timestamp: ts,
            participant_npub: Some(npub),
        };
        let hex = hex::encode(cbor::to_canonical_vec(&unsigned).expect("encode"));
        const EXPECTED_WITH_NPUB_HEX: &str = "a7617601646b696e6470636c61772d73686172652f636c61696d656e6f6e63655820444444444444444444444444444444444444444444444444444444444444444467736c6f745f696450222222222222222222222222222222226974696d657374616d701a6b49d3f47067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d707061727469636970616e745f6e707562784038326632383365323030393465623464613539323263666261366330323834623739303532356634643464646232643137666439386631626430393536633032";
        assert_eq!(hex, EXPECTED_WITH_NPUB_HEX, "Some-variant claim wire hex");
    }

    // ─── Group claim (Path-A) — wire shape + byte-stability ──────────────────

    fn group_test_keys() -> (P256Keypair, P256Keypair) {
        let member = P256Keypair::from_secret_scalar(&[0x55u8; 32]).expect("member key");
        let device = P256Keypair::from_secret_scalar(&[0x33u8; 32]).expect("device key");
        (member, device)
    }

    fn sample_group_request() -> GroupClaimRequest {
        let (member, device) = group_test_keys();
        let binding = MemberDeviceBinding::sign(
            &member as &dyn IdentityKey,
            device.public(),
            "npub_member_alpha".to_string(),
            1_800_000_000,
        )
        .expect("sign binding");
        GroupClaimRequest::sign(
            binding,
            "group_alpha".to_string(),
            "claw_alpha".to_string(),
            vec![0x66u8; 32],
            Some(600),
            &device as &dyn IdentityKey,
        )
        .expect("sign group request")
    }

    #[test]
    fn group_request_round_trips_and_device_pop_verifies() {
        let req = sample_group_request();
        req.binding.verify().expect("binding verifies");
        req.verify_device_pop().expect("device pop verifies");

        let bytes = cbor::to_canonical_vec(&req).expect("encode");
        let decoded: GroupClaimRequest = cbor::from_canonical_slice(&bytes).expect("decode");
        assert_eq!(decoded, req);
        decoded.verify_device_pop().expect("decoded pop verifies");
    }

    #[test]
    fn group_request_device_pop_is_bound_to_group_claw_and_challenge() {
        let base = sample_group_request();

        let mut wrong_group = base.clone();
        wrong_group.group_id = "group_beta".to_string();
        assert!(wrong_group.binding.verify().is_ok());
        assert!(matches!(
            wrong_group.verify_device_pop(),
            Err(ClawShareError::GroupDevicePopRejected)
        ));

        let mut wrong_claw = base.clone();
        wrong_claw.claw_id = "claw_beta".to_string();
        assert!(matches!(
            wrong_claw.verify_device_pop(),
            Err(ClawShareError::GroupDevicePopRejected)
        ));

        let mut wrong_challenge = base.clone();
        wrong_challenge.challenge = vec![0x77u8; 32];
        assert!(matches!(
            wrong_challenge.verify_device_pop(),
            Err(ClawShareError::GroupDevicePopRejected)
        ));

        let mut wrong_ttl = base;
        wrong_ttl.ttl_secs = Some(601);
        assert!(matches!(
            wrong_ttl.verify_device_pop(),
            Err(ClawShareError::GroupDevicePopRejected)
        ));
    }

    #[test]
    fn group_request_sign_rejects_device_key_not_in_binding() {
        let (member, device) = group_test_keys();
        let binding = MemberDeviceBinding::sign(
            &member as &dyn IdentityKey,
            device.public(),
            "npub_member_alpha".to_string(),
            1_800_000_000,
        )
        .unwrap();
        let other = P256Keypair::from_secret_scalar(&[0x99u8; 32]).unwrap();
        assert!(matches!(
            GroupClaimRequest::sign(
                binding,
                "group_alpha".to_string(),
                "claw_alpha".to_string(),
                vec![0x66u8; 32],
                Some(600),
                &other as &dyn IdentityKey,
            ),
            Err(ClawShareError::GroupDeviceKeyMismatch)
        ));
    }

    #[test]
    fn group_claim_round_trips_and_device_fields_verify() {
        let req = sample_group_request();
        let (_member, device) = group_test_keys();
        let nonce = ClaimNonce([0x44u8; NONCE_LEN]);
        let ts: u64 = 1_800_000_500;
        let claim = ClawShareClaim::sign_group(
            device.public(),
            nonce,
            ts,
            req,
            &device as &dyn IdentityKey,
        )
        .expect("sign group claim");

        claim.verify(ts).expect("device-field signature verifies");
        assert_eq!(claim.slot_id, SlotId([0u8; SLOT_ID_LEN]));
        assert!(claim.participant_npub.is_none());

        let gr = claim.group_request.as_ref().expect("group request present");
        gr.binding.verify().expect("binding verifies");
        gr.verify_device_pop().expect("device pop verifies");

        let bytes = cbor::to_canonical_vec(&claim).expect("encode claim");
        let decoded: ClawShareClaim = cbor::from_canonical_slice(&bytes).expect("decode claim");
        assert_eq!(decoded, claim);
    }

    #[test]
    fn sign_group_rejects_guest_device_pub_not_matching_binding() {
        let req = sample_group_request();
        let nonce = ClaimNonce([0x44u8; NONCE_LEN]);
        let ts: u64 = 1_800_000_500;
        let other = P256Keypair::from_secret_scalar(&[0x99u8; 32]).unwrap();
        assert!(matches!(
            ClawShareClaim::sign_group(other.public(), nonce, ts, req, &other as &dyn IdentityKey),
            Err(ClawShareError::GroupDeviceKeyMismatch)
        ));
    }

    #[test]
    fn device_claim_signed_bytes_unchanged_by_group_request_field() {
        let slot_id = SlotId([0x22u8; SLOT_ID_LEN]);
        let device = P256Keypair::from_secret_scalar(&[0x33u8; 32]).expect("device key");
        let guest_device_pub = device.public();
        let nonce = ClaimNonce([0x44u8; NONCE_LEN]);
        let timestamp: u64 = 1_800_000_500;
        let unsigned = ClawShareClaimUnsigned {
            v: CLAW_SHARE_CLAIM_VERSION,
            kind: CLAIM_KIND,
            slot_id: &slot_id,
            guest_device_pub: &guest_device_pub,
            nonce: &nonce,
            timestamp,
            participant_npub: None,
        };
        let hex = hex::encode(cbor::to_canonical_vec(&unsigned).expect("encode"));
        const EXPECTED_UNSIGNED_HEX: &str = "a6617601646b696e6470636c61772d73686172652f636c61696d656e6f6e63655820444444444444444444444444444444444444444444444444444444444444444467736c6f745f696450222222222222222222222222222222226974696d657374616d701a6b49d3f47067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d";
        assert_eq!(
            hex, EXPECTED_UNSIGNED_HEX,
            "Device claim signing bytes drifted"
        );

        let claim = ClawShareClaim::sign(
            slot_id,
            guest_device_pub,
            nonce,
            timestamp,
            &device as &dyn IdentityKey,
        )
        .expect("sign device claim");
        assert!(claim.group_request.is_none());
        let bytes = cbor::to_canonical_vec(&claim).expect("encode");
        let decoded: ClawShareClaim = cbor::from_canonical_slice(&bytes).expect("decode");
        assert_eq!(decoded, claim);
    }

    #[test]
    fn cross_language_fixture_group_claim_hex() {
        let device = P256Keypair::from_secret_scalar(&[0x33u8; 32]).expect("device key");
        let member = P256Keypair::from_secret_scalar(&[0x55u8; 32]).expect("member key");
        let member_pub = member.public();
        let device_pub = device.public();
        let member_id = crate::member_identity::derive_member_id(&member_pub);
        let binding = MemberDeviceBinding {
            v: 1,
            kind: "claw-share/member-device/v1".to_string(),
            member_id,
            member_pub,
            device_pub: device_pub.clone(),
            participant_npub: "82f283e20094eb4da5922cfba6c0284b790525f4d4ddb2d17fd98f1bd0956c02"
                .to_string(),
            issued_at: 1_800_000_000,
            member_signature: P256Signature([0xABu8; 64]),
        };
        let group_request = GroupClaimRequest {
            v: CLAW_SHARE_GROUP_REQUEST_VERSION,
            challenge: vec![0x66u8; 32],
            binding,
            group_id: "group_alpha".to_string(),
            claw_id: "claw_alpha".to_string(),
            device_pop: P256Signature([0xCDu8; 64]),
            ttl_secs: Some(600),
        };
        let claim = ClawShareClaim {
            v: CLAW_SHARE_CLAIM_VERSION,
            kind: CLAIM_KIND.to_string(),
            slot_id: SlotId([0u8; SLOT_ID_LEN]),
            guest_device_pub: device_pub,
            nonce: ClaimNonce([0x44u8; NONCE_LEN]),
            timestamp: 1_800_000_500,
            participant_npub: None,
            group_request: Some(group_request),
            guest_signature: P256Signature([0xEFu8; 64]),
        };
        let hex = hex::encode(cbor::to_canonical_vec(&claim).expect("encode"));
        const EXPECTED_GROUP_CLAIM_HEX: &str = "a8617601646b696e6470636c61772d73686172652f636c61696d656e6f6e63655820444444444444444444444444444444444444444444444444444444444444444467736c6f745f696450000000000000000000000000000000006974696d657374616d701a6b49d3f46d67726f75705f72657175657374a76176016762696e64696e67a8617601646b696e64781b636c61772d73686172652f6d656d6265722d6465766963652f7631696973737565645f61741a6b49d200696d656d6265725f69647836675f6c65717a6d6f6869357363377665746d3361616a64743274707061736767356f717576666a73366c78736670346c6a686a3670716a6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d6a6d656d6265725f70756258210257e977f6db7e33c3fe7acf2842ed987009caf56d458682fca447b7d3d762ab34706d656d6265725f7369676e61747572655840abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab707061727469636970616e745f6e70756278403832663238336532303039346562346461353932326366626136633032383462373930353235663464346464623264313766643938663162643039353663303267636c61775f69646a636c61775f616c7068616867726f75705f69646b67726f75705f616c7068616874746c5f73656373190258696368616c6c656e6765582066666666666666666666666666666666666666666666666666666666666666666a6465766963655f706f705840cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd6f67756573745f7369676e61747572655840efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef7067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d";
        assert_eq!(
            hex, EXPECTED_GROUP_CLAIM_HEX,
            "group claim wire shape drift — Swift fixture is now stale"
        );
    }

    #[test]
    fn group_ack_round_trips_credential_less() {
        let ack = ClawShareGroupAck {
            v: CLAW_SHARE_GROUP_ACK_VERSION,
            relay_stream_offer: serde_bytes::ByteBuf::from(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        };
        let bytes = cbor::to_canonical_vec(&ack).expect("encode");
        let decoded: ClawShareGroupAck = cbor::from_canonical_slice(&bytes).expect("decode");
        assert_eq!(decoded, ack);
        assert_eq!(decoded.v, CLAW_SHARE_GROUP_ACK_VERSION);
    }

    fn relay_offer_ack(offer: Option<serde_bytes::ByteBuf>) -> ClawShareAck {
        let owner_key = P256Keypair::from_secret_scalar(&[0x11u8; 32]).expect("key");
        let guest_key = P256Keypair::from_secret_scalar(&[0x33u8; 32]).expect("guest key");
        let credential = GuestCredential::sign(
            derive_household_id(&owner_key.public()),
            derive_person_id(&owner_key.public()),
            owner_key.public(),
            "claw_relay_offer_fixture".to_string(),
            guest_key.public(),
            SlotId([0x22u8; SLOT_ID_LEN]),
            1_800_000_500,
            1_800_010_500,
            &owner_key,
        )
        .expect("sign credential");
        ClawShareAck {
            v: GUEST_CREDENTIAL_VERSION,
            credential,
            tunnel: TunnelHandle::Loopback {
                channel: "ch-relay-offer".to_string(),
            },
            relay_stream_offer: offer,
        }
    }

    #[test]
    fn claw_share_ack_omits_relay_stream_offer_when_none() {
        // A `None` offer is omitted on the wire (skip_serializing_if), so the ack
        // is byte-identical to the pre-C7c shape and round-trips to `None`.
        let ack = relay_offer_ack(None);
        let bytes = cbor::to_canonical_vec(&ack).expect("encode");
        let decoded: ClawShareAck = cbor::from_canonical_slice(&bytes).expect("decode");
        assert_eq!(decoded, ack);
        assert!(decoded.relay_stream_offer.is_none());

        // A pre-C7c-shaped decoder (deny_unknown_fields, no offer field) must
        // also accept the bytes: proof the `None` ack carries no extra field.
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct LegacyAck {
            v: u8,
            credential: GuestCredential,
            tunnel: TunnelHandle,
        }
        let _legacy: LegacyAck =
            cbor::from_canonical_slice(&bytes).expect("legacy decoder accepts a None ack");
    }

    #[test]
    fn claw_share_ack_round_trips_relay_stream_offer_when_present() {
        // When present, the opaque bytes round-trip intact (the C7c-1 forward path).
        let offer = serde_bytes::ByteBuf::from(vec![0xAB, 0xCD, 0xEF, 0x01]);
        let ack = relay_offer_ack(Some(offer.clone()));
        let bytes = cbor::to_canonical_vec(&ack).expect("encode");
        let decoded: ClawShareAck = cbor::from_canonical_slice(&bytes).expect("decode");
        assert_eq!(decoded, ack);
        assert_eq!(decoded.relay_stream_offer, Some(offer));
    }

    /// Cross-language fixture: deterministic `ClawShareAck` canonical
    /// CBOR. The Ack wraps a `GuestCredential` (already pinned) plus
    /// the engine's `TunnelHandle`. The fixture encodes a fully-signed
    /// credential — owner signature is computed deterministically from
    /// the same secret scalar = [0x11; 32] — so the byte vector below
    /// covers the full ack as it lands on the wire to the friend.
    #[test]
    fn cross_language_fixture_ack_hex() {
        let scalar = [0x11u8; 32];
        let owner_key = P256Keypair::from_secret_scalar(&scalar).expect("key");
        let pub_bytes = owner_key.public();
        let hh_id = derive_household_id(&pub_bytes);
        let owner_p_id = derive_person_id(&pub_bytes);
        let slot_id = SlotId([0x22u8; SLOT_ID_LEN]);
        let guest_scalar = [0x33u8; 32];
        let guest_key = P256Keypair::from_secret_scalar(&guest_scalar).expect("guest key");
        let guest_device_pub = guest_key.public();
        let credential = GuestCredential::sign(
            hh_id.clone(),
            owner_p_id.clone(),
            owner_key.public(),
            "claw_fixture_v1".to_string(),
            guest_device_pub.clone(),
            slot_id,
            1_800_000_500,
            1_800_010_500,
            &owner_key,
        )
        .expect("sign credential");
        let ack = ClawShareAck {
            v: GUEST_CREDENTIAL_VERSION,
            credential,
            tunnel: TunnelHandle::Loopback {
                channel: "ch-fixture-ack".to_string(),
            },
            relay_stream_offer: None,
        };
        // The credential's owner_signature varies by RNG-free
        // determinism of `rfc6979` between Rust and Swift, so we pin
        // only the wire SHAPE here via a roundtrip + the unsigned
        // sub-structure (credential body + tunnel). The full bytes
        // are determinism-checked end-to-end.
        let ack_bytes = cbor::to_canonical_vec(&ack).expect("encode ack");
        let re = cbor::to_canonical_vec(&ack).expect("re-encode");
        assert_eq!(ack_bytes, re, "canonical encoding non-deterministic");

        // The portable cross-language vector is the ack shape WITHOUT
        // the owner signature on the credential — that's the byte
        // sequence both Rust and Swift can reproduce from the same
        // deterministic inputs. We assemble the map by hand here so
        // we don't have to introduce a one-off serde struct.
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct AckUnsigned<'a> {
            v: u8,
            credential: GuestCredentialUnsigned<'a>,
            tunnel: &'a TunnelHandle,
        }
        let unsigned = AckUnsigned {
            v: ack.v,
            credential: GuestCredentialUnsigned {
                v: ack.credential.v,
                kind: &ack.credential.kind,
                hh_id: &ack.credential.hh_id,
                owner_p_id: &ack.credential.owner_p_id,
                owner_p_pub: &ack.credential.owner_p_pub,
                claw_id: &ack.credential.claw_id,
                guest_device_pub: &ack.credential.guest_device_pub,
                slot_id: &ack.credential.slot_id,
                issued_at: ack.credential.issued_at,
                expires_at: ack.credential.expires_at,
            },
            tunnel: &ack.tunnel,
        };
        let unsigned_bytes = cbor::to_canonical_vec(&unsigned).expect("encode unsigned");
        let unsigned_hex = hex::encode(&unsigned_bytes);
        const EXPECTED_UNSIGNED_HEX: &str = "a36176016674756e6e656ca2646b696e64686c6f6f706261636b676368616e6e656c6e63682d666978747572652d61636b6a63726564656e7469616caa617601646b696e64781b636c61772d73686172652f67756573742d63726564656e7469616c6568685f6964783768685f6a707173797570796f747268676175343579376e6575336c3370346c65723678687537646e32783232337232716636616769727167636c61775f69646f636c61775f666978747572655f763167736c6f745f69645022222222222222222222222222222222696973737565645f61741a6b49d3f46a657870697265735f61741a6b49fb046a6f776e65725f705f69647836705f6a707173797570796f747268676175343579376e6575336c3370346c65723678687537646e3278323233723271663661676972716b6f776e65725f705f7075625821020217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed7067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d";
        assert_eq!(
            unsigned_hex, EXPECTED_UNSIGNED_HEX,
            "ack wire shape drift — Swift fixture is now stale"
        );
    }

    /// Cross-language fixture: deterministic `GuestCredential` unsigned
    /// canonical CBOR.
    #[test]
    fn cross_language_fixture_guest_credential_hex() {
        let scalar = [0x11u8; 32];
        let owner_key = P256Keypair::from_secret_scalar(&scalar).expect("key");
        let pub_bytes = owner_key.public();
        let hh_id = derive_household_id(&pub_bytes);
        let owner_p_id = derive_person_id(&pub_bytes);
        let slot_id = SlotId([0x22u8; SLOT_ID_LEN]);
        let guest_scalar = [0x33u8; 32];
        let guest_key = P256Keypair::from_secret_scalar(&guest_scalar).expect("guest key");
        let guest_device_pub = guest_key.public();
        let unsigned = GuestCredentialUnsigned {
            v: GUEST_CREDENTIAL_VERSION,
            kind: CREDENTIAL_KIND,
            hh_id: &hh_id,
            owner_p_id: &owner_p_id,
            owner_p_pub: &pub_bytes,
            claw_id: "claw_fixture_v1",
            guest_device_pub: &guest_device_pub,
            slot_id: &slot_id,
            issued_at: 1_800_000_500,
            expires_at: 1_800_010_500,
        };
        let bytes = cbor::to_canonical_vec(&unsigned).expect("encode");
        let unsigned_hex = hex::encode(&bytes);
        const EXPECTED_UNSIGNED_HEX: &str = "aa617601646b696e64781b636c61772d73686172652f67756573742d63726564656e7469616c6568685f6964783768685f6a707173797570796f747268676175343579376e6575336c3370346c65723678687537646e32783232337232716636616769727167636c61775f69646f636c61775f666978747572655f763167736c6f745f69645022222222222222222222222222222222696973737565645f61741a6b49d3f46a657870697265735f61741a6b49fb046a6f776e65725f705f69647836705f6a707173797570796f747268676175343579376e6575336c3370346c65723678687537646e3278323233723271663661676972716b6f776e65725f705f7075625821020217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed7067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d";
        assert_eq!(
            unsigned_hex, EXPECTED_UNSIGNED_HEX,
            "credential wire shape drift — Swift fixture is now stale"
        );
        let re = cbor::to_canonical_vec(&unsigned).expect("re-encode");
        assert_eq!(re, bytes);
    }

    #[test]
    fn invite_round_trip_and_verify() {
        let (owner_key, hh_id, owner_p_id) = fresh_owner();
        let slot_id = SlotId::random();
        let invite = ClawShareInvite::sign(
            hh_id.clone(),
            owner_p_id.clone(),
            owner_key.public(),
            "claw_test".to_string(),
            slot_id.clone(),
            TunnelHandle::Loopback {
                channel: "test-channel".to_string(),
            },
            2_000_000_000,
            String::new(),
            Vec::new(),
            &owner_key,
        )
        .expect("sign invite");

        let bytes = cbor::to_canonical_vec(&invite).expect("encode invite");
        let decoded: ClawShareInvite = cbor::from_canonical_slice(&bytes).expect("decode invite");
        assert_eq!(invite, decoded);

        decoded.verify(1_000_000_000).expect("invite verifies");
    }

    #[test]
    fn invite_tamper_detection() {
        let (owner_key, hh_id, owner_p_id) = fresh_owner();
        let mut invite = ClawShareInvite::sign(
            hh_id,
            owner_p_id,
            owner_key.public(),
            "claw_a".to_string(),
            SlotId::random(),
            TunnelHandle::Loopback {
                channel: "c".to_string(),
            },
            2_000_000_000,
            String::new(),
            Vec::new(),
            &owner_key,
        )
        .expect("sign");
        // Flip the claw_id — signature now covers a different value.
        invite.claw_id = "claw_b".to_string();
        let err = invite
            .verify(1_000_000_000)
            .expect_err("tamper must reject");
        assert!(matches!(err, ClawShareError::InviteSignatureRejected));
    }

    #[test]
    fn invite_expiry_rejected() {
        let (owner_key, hh_id, owner_p_id) = fresh_owner();
        let invite = ClawShareInvite::sign(
            hh_id,
            owner_p_id,
            owner_key.public(),
            "claw_a".to_string(),
            SlotId::random(),
            TunnelHandle::Loopback {
                channel: "c".to_string(),
            },
            1_000,
            String::new(),
            Vec::new(),
            &owner_key,
        )
        .expect("sign");
        let err = invite.verify(2_000).expect_err("expired must reject");
        assert!(matches!(err, ClawShareError::InviteExpired));
    }

    #[test]
    fn claim_round_trip_and_verify() {
        let guest_key = P256Keypair::generate();
        let claim = ClawShareClaim::sign(
            SlotId::random(),
            guest_key.public(),
            ClaimNonce::random(),
            1_000_000_000,
            &guest_key,
        )
        .expect("sign claim");
        claim.verify(1_000_000_000).expect("claim verifies");
        claim.verify(1_000_000_059).expect("inside skew window");
        let err = claim
            .verify(1_000_000_061)
            .expect_err("outside skew rejected");
        assert!(matches!(err, ClawShareError::ClaimReplayWindow { .. }));
    }

    #[test]
    fn claim_tamper_detection() {
        let guest_key = P256Keypair::generate();
        let other_guest = P256Keypair::generate();
        let mut claim = ClawShareClaim::sign(
            SlotId::random(),
            guest_key.public(),
            ClaimNonce::random(),
            1_000_000_000,
            &guest_key,
        )
        .expect("sign");
        // Substitute another guest's pubkey — verify must fail.
        claim.guest_device_pub = other_guest.public();
        let err = claim
            .verify(1_000_000_000)
            .expect_err("substituted pub must reject");
        assert!(matches!(err, ClawShareError::ClaimSignatureRejected));
    }

    #[test]
    fn credential_round_trip_and_verify() {
        let (owner_key, hh_id, owner_p_id) = fresh_owner();
        let guest_key = P256Keypair::generate();
        let cred = GuestCredential::sign(
            hh_id,
            owner_p_id,
            owner_key.public(),
            "claw_a".to_string(),
            guest_key.public(),
            SlotId::random(),
            1_000_000_000,
            1_000_000_000 + 3600,
            &owner_key,
        )
        .expect("sign cred");
        cred.verify(1_000_001_000).expect("cred verifies");

        let bytes = cbor::to_canonical_vec(&cred).expect("encode cred");
        let decoded: GuestCredential = cbor::from_canonical_slice(&bytes).expect("decode cred");
        assert_eq!(cred, decoded);
    }

    #[test]
    fn credential_lifetime_cap_enforced() {
        let (owner_key, hh_id, owner_p_id) = fresh_owner();
        let guest_key = P256Keypair::generate();
        let err = GuestCredential::sign(
            hh_id,
            owner_p_id,
            owner_key.public(),
            "claw_a".to_string(),
            guest_key.public(),
            SlotId::random(),
            1_000_000_000,
            1_000_000_000 + MAX_CREDENTIAL_TTL_SECS + 1,
            &owner_key,
        )
        .expect_err("over-cap lifetime must reject");
        assert!(matches!(
            err,
            ClawShareError::CredentialLifetimeExceedsCap { .. }
        ));
    }

    #[test]
    fn slot_store_atomic_consume() {
        let (_, _, _) = fresh_owner();
        let guest_key = P256Keypair::generate();
        let other_guest = P256Keypair::generate();
        let store = ClawShareSlotStore::new();
        let slot_id = SlotId::random();
        store
            .insert(SlotRecord {
                slot_id: slot_id.clone(),
                claw_id: "claw_a".to_string(),
                expires_at: 2_000_000_000,
                state: SlotState::Open,
                app_presentation: None,
                created_at: None,
            })
            .expect("insert");

        // First consume wins.
        let consumed = store
            .consume_atomic(&slot_id, "claw_a", guest_key.public(), 1_000_000_000)
            .expect("first consume");
        assert!(matches!(consumed.state, SlotState::Consumed { .. }));

        // Second consume rejects.
        let err = store
            .consume_atomic(&slot_id, "claw_a", other_guest.public(), 1_000_000_001)
            .expect_err("second consume must reject");
        assert!(matches!(err, ClawShareError::SlotAlreadyConsumed));
    }

    #[test]
    fn slot_store_rejects_claw_mismatch() {
        let guest_key = P256Keypair::generate();
        let store = ClawShareSlotStore::new();
        let slot_id = SlotId::random();
        store
            .insert(SlotRecord {
                slot_id: slot_id.clone(),
                claw_id: "claw_a".to_string(),
                expires_at: 2_000_000_000,
                state: SlotState::Open,
                app_presentation: None,
                created_at: None,
            })
            .expect("insert");

        let err = store
            .consume_atomic(&slot_id, "claw_b", guest_key.public(), 1_000_000_000)
            .expect_err("claw mismatch must reject");
        assert!(matches!(err, ClawShareError::SlotClawMismatch));
    }

    #[test]
    fn owner_mint_invite_is_atomic() {
        let (owner_key, hh_id, owner_p_id) = fresh_owner();
        let store = ClawShareSlotStore::new();
        let invite = owner_mint_invite(
            &owner_key,
            &owner_p_id,
            &hh_id,
            "claw_atomic",
            TunnelHandle::Loopback {
                channel: "ch".to_string(),
            },
            300,
            1_000_000_000,
            String::new(),
            Vec::new(),
            &store,
        )
        .expect("mint");

        invite.verify(1_000_000_001).expect("invite verifies");
        let slot = store.get(&invite.slot_id).expect("slot present");
        assert_eq!(slot.claw_id, "claw_atomic");
        assert!(matches!(slot.state, SlotState::Open));
        assert_eq!(slot.expires_at, invite.expires_at);
        // Legacy wrapper leaves no presentation.
        assert!(slot.app_presentation.is_none());
    }

    #[test]
    fn owner_mint_invite_with_presentation_persists_snapshot() {
        use crate::claw_share_relay_stream_contract::ShareableAppPresentation;

        let (owner_key, hh_id, owner_p_id) = fresh_owner();
        let store = ClawShareSlotStore::new();
        let app_id = "app_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let presentation =
            ShareableAppPresentation::try_new(app_id.clone(), "Study", "Caio").unwrap();

        let invite = owner_mint_invite_with_presentation(
            &owner_key,
            &owner_p_id,
            &hh_id,
            &app_id,
            TunnelHandle::Loopback {
                channel: "ch".to_string(),
            },
            300,
            1_000_000_000,
            String::new(),
            Vec::new(),
            &store,
            Some(presentation),
        )
        .expect("mint");

        let slot = store.get(&invite.slot_id).expect("slot present");
        let stored = slot
            .app_presentation
            .as_ref()
            .expect("presentation must be persisted in the SlotRecord");
        assert_eq!(stored.app_id, app_id);
        assert_eq!(stored.display_name, "Study");
        assert_eq!(stored.owner_display_name, "Caio");
    }

    #[test]
    fn mint_caps_ttl_at_max() {
        let (owner_key, hh_id, owner_p_id) = fresh_owner();
        let store = ClawShareSlotStore::new();
        let invite = owner_mint_invite(
            &owner_key,
            &owner_p_id,
            &hh_id,
            "claw_cap",
            TunnelHandle::Loopback {
                channel: "c".to_string(),
            },
            MAX_INVITE_TTL_SECS * 10, // request way more than the cap
            1_000_000_000,
            String::new(),
            Vec::new(),
            &store,
        )
        .expect("mint");
        assert_eq!(invite.expires_at, 1_000_000_000 + MAX_INVITE_TTL_SECS);
    }

    #[test]
    fn invite_uri_round_trip_preserves_signature() {
        let (owner_key, hh_id, owner_p_id) = fresh_owner();
        let store = ClawShareSlotStore::new();
        let invite = owner_mint_invite(
            &owner_key,
            &owner_p_id,
            &hh_id,
            "claw_uri",
            TunnelHandle::Direct {
                host: "192.0.2.10".to_string(),
                port: 7423,
            },
            300,
            1_000_000_000,
            "npub1engine".to_string(),
            vec!["wss://relay.theyos.net".to_string()],
            &store,
        )
        .expect("mint");

        let uri = invite.to_uri().expect("encode uri");
        assert!(uri.starts_with(CLAW_SHARE_URI_PREFIX));

        let decoded = ClawShareInvite::from_uri(&uri).expect("decode uri");
        assert_eq!(invite, decoded);
        decoded.verify(1_000_000_001).expect("decoded verifies");
    }

    #[test]
    fn malformed_uri_rejected() {
        let err = ClawShareInvite::from_uri("https://example.com/foo")
            .expect_err("wrong scheme must reject");
        assert!(matches!(err, ClawShareError::UriMalformed));

        let err = ClawShareInvite::from_uri("soyeht://claw-share/v1?e=not-base64!!")
            .expect_err("malformed base64 must reject");
        assert!(matches!(err, ClawShareError::UriMalformed));

        let err = ClawShareInvite::from_uri("soyeht://claw-share/v2?e=AA")
            .expect_err("wrong version must reject");
        assert!(matches!(err, ClawShareError::UriMalformed));
    }

    /// Open slot for the revoke-idempotence tests.
    fn revoke_fixture() -> (ClawShareSlotStore, SlotId) {
        let store = ClawShareSlotStore::new();
        let slot_id = SlotId::random();
        store
            .insert(SlotRecord {
                slot_id: slot_id.clone(),
                claw_id: "claw_a".to_string(),
                expires_at: 2_000_000_000,
                state: SlotState::Open,
                app_presentation: None,
                created_at: Some(1_700_000_000),
            })
            .unwrap();
        (store, slot_id)
    }

    #[test]
    fn revoke_returns_the_canonical_timestamp_and_a_second_revoke_moves_nothing() {
        let (store, slot_id) = revoke_fixture();

        let first = store.revoke(&slot_id, 1_800_000_001).unwrap();
        assert_eq!(first, 1_800_000_001);
        let after_first = store.get(&slot_id).unwrap().state;

        // A LATER clock must not move anything: the canonical value is the
        // first one, and it is what the caller re-signs on every retry.
        let second = store.revoke(&slot_id, 1_900_000_999).unwrap();
        assert_eq!(
            second, 1_800_000_001,
            "second revoke must not move revoked_at"
        );
        assert_eq!(
            store.get(&slot_id).unwrap().state,
            after_first,
            "second revoke must not change the state at all"
        );
        assert_eq!(
            store.get(&slot_id).unwrap().created_at,
            Some(1_700_000_000),
            "revoking must not disturb created_at"
        );
    }

    #[test]
    fn revoking_a_consumed_slot_preserves_when_it_was_accepted() {
        let (store, slot_id) = revoke_fixture();
        let guest = P256Keypair::generate();
        store
            .consume_atomic(&slot_id, "claw_a", guest.public(), 1_750_000_000)
            .unwrap();

        let revoked_at = store.revoke(&slot_id, 1_800_000_001).unwrap();
        assert_eq!(revoked_at, 1_800_000_001);
        assert_eq!(
            store.get(&slot_id).unwrap().state,
            SlotState::Revoked {
                revoked_at: 1_800_000_001,
                // The owner surface must still be able to say the share WAS
                // accepted, and when, after it has been revoked.
                accepted_at: Some(1_750_000_000),
            }
        );

        // And a repeat keeps both halves.
        assert_eq!(
            store.revoke(&slot_id, 1_999_999_999).unwrap(),
            1_800_000_001
        );
        assert_eq!(
            store.get(&slot_id).unwrap().state,
            SlotState::Revoked {
                revoked_at: 1_800_000_001,
                accepted_at: Some(1_750_000_000),
            }
        );
    }

    #[test]
    fn revoking_an_open_slot_records_no_acceptance() {
        let (store, slot_id) = revoke_fixture();
        store.revoke(&slot_id, 1_800_000_001).unwrap();
        assert_eq!(
            store.get(&slot_id).unwrap().state,
            SlotState::Revoked {
                revoked_at: 1_800_000_001,
                accepted_at: None,
            }
        );
    }

    #[test]
    fn slot_store_revoke_blocks_consume() {
        let guest_key = P256Keypair::generate();
        let store = ClawShareSlotStore::new();
        let slot_id = SlotId::random();
        store
            .insert(SlotRecord {
                slot_id: slot_id.clone(),
                claw_id: "claw_a".to_string(),
                expires_at: 2_000_000_000,
                state: SlotState::Open,
                app_presentation: None,
                created_at: None,
            })
            .expect("insert");
        store.revoke(&slot_id, 1_000_000_000).expect("revoke");
        let err = store
            .consume_atomic(&slot_id, "claw_a", guest_key.public(), 1_000_000_001)
            .expect_err("revoked must reject");
        assert!(matches!(err, ClawShareError::SlotRevoked));
    }
}
