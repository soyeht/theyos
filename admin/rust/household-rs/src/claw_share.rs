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

pub mod data_tunnel;
pub mod flow;
pub mod relay;
pub mod relay_stream_contract;
pub mod relay_stream_endpoint;
pub mod relay_stream_noise;
pub mod rendezvous_hello;
pub mod rendezvous_token;

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
        Option<crate::claw_share::relay_stream_contract::ShareableAppPresentation>,
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
        crate::claw_share::relay_stream_contract::ShareableAppPresentation,
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
mod tests;
