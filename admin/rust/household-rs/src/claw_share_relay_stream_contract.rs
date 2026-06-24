//! Internal Product A `relay_stream` offer contract.
//!
//! This is the signed/canonical binding that the future Noise handshake will
//! consume. It is not a public wire schema yet and is not wired into bootstrap,
//! claim ack, iOS, or any public listener.
//!
//! Owner-key CRL/revocation is intentionally not implemented in this contract
//! object; there is no small trusted CRL boundary wired here yet. Consumers must
//! apply that household boundary before public use.

use std::fmt;

use crate::claw_share::{GuestCredential, SlotId};
use crate::household_mesh_log::ProjectedState;
use crate::household_record::HouseholdRecord;
use crate::issuer_trust::{MachineIssuerError, is_machine_issuer_active};
use crate::keys::{IdentityKey, P256PublicKey, P256Signature, verify_signature};
use crate::machine_cert::MachineCert;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::claw_share_rendezvous_token::RendezvousToken;

pub const RELAY_STREAM_OFFER_VERSION: u8 = 2;
pub const RELAY_STREAM_OFFER_KIND: &str = "claw-share/relay-stream-offer";
pub const RELAY_STREAM_NOISE_PROLOGUE_VERSION: u8 = 2;
pub const RELAY_STREAM_NOISE_PROLOGUE_KIND: &str = "claw-share/relay-stream-noise-prologue";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayStreamResource {
    Pty,
    #[serde(rename = "clawsite")]
    ClawSite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayStreamExpectedPath {
    CommunityRelay,
    RelayStream,
}

/// Future Noise static public key binding for the claw side.
///
/// The relay stream contract signs this value now so the Noise cut can bind
/// the handshake transcript to the same announced claw identity later.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayStreamClawStaticPublicKey([u8; Self::LEN]);

impl RelayStreamClawStaticPublicKey {
    pub const LEN: usize = 32;

    pub fn try_new(bytes: impl AsRef<[u8]>) -> Result<Self, RelayStreamContractError> {
        let bytes = bytes.as_ref();
        if bytes.len() != Self::LEN {
            return Err(RelayStreamContractError::StaticKeyMalformed {
                actual: bytes.len(),
            });
        }
        let mut out = [0u8; Self::LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Debug for RelayStreamClawStaticPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RelayStreamClawStaticPublicKey(len={}, redacted)",
            Self::LEN
        )
    }
}

impl Serialize for RelayStreamClawStaticPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::Bytes::new(self.as_bytes()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RelayStreamClawStaticPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        Self::try_new(bytes.as_slice()).map_err(de::Error::custom)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayStreamOfferPayload {
    pub v: u8,
    pub kind: String,
    pub rendezvous_token: RendezvousToken,
    pub claw_id: String,
    pub slot_id: SlotId,
    pub guest_device_pub: P256PublicKey,
    pub resource: RelayStreamResource,
    pub expected_path: RelayStreamExpectedPath,
    pub relay_endpoint: String,
    pub claw_static_pub: RelayStreamClawStaticPublicKey,
    pub not_after: u64,
    /// Fase E2 (ADDITIVE, default-Device). `None` ⇒ [`RelayStreamAudience::Device`]
    /// and is OMITTED from the wire (`skip_serializing_if`), so a v2 offer's
    /// canonical CBOR — and thus its owner signature and any cross-language
    /// fixture — is byte-identical to before this field existed. `Some(_)` binds
    /// the audience mode into the signed bytes AND the Noise prologue (which
    /// embeds `offer_payload_cbor`), so a Group/Public offer can never be
    /// downgraded to Device (or across modes) without breaking the signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authz: Option<RelayStreamAudience>,
}

/// Fase E2: how a `relay_stream` offer is authorized at the dial gate. The offer's
/// `guest_device_pub` is ALWAYS the dialing device (the Noise transcript pin);
/// the audience decides HOW that device is authorized.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayStreamAudience {
    /// 1:1 single guest: `guest_device_pub` is pinned to a consumed slot (today's path).
    Device,
    /// Group member: authorized iff the dialing device is an active device of
    /// `member_id`, `member_id` is active in `group_id`, and `group_id` has an
    /// active grant to the claw — checked against the LIVE projection.
    Group { group_id: String, member_id: String },
    /// Public site: anyone, gated only by an explicit owner publication (Fase E3).
    Public,
}

pub struct RelayStreamOfferMintInput<'a> {
    pub rendezvous_token: RendezvousToken,
    pub credential: &'a GuestCredential,
    pub resource: RelayStreamResource,
    pub expected_path: RelayStreamExpectedPath,
    pub relay_endpoint: String,
    pub claw_static_pub: RelayStreamClawStaticPublicKey,
    pub not_after: u64,
    pub now_unix: u64,
}

impl fmt::Debug for RelayStreamOfferMintInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamOfferMintInput")
            .field("rendezvous_token", &self.rendezvous_token)
            .field("credential.claw_id", &self.credential.claw_id)
            .field("credential.slot_id", &self.credential.slot_id)
            .field(
                "credential.guest_device_pub",
                &self.credential.guest_device_pub,
            )
            .field("credential.expires_at", &self.credential.expires_at)
            .field("resource", &self.resource)
            .field("expected_path", &self.expected_path)
            .field("relay_endpoint", &self.relay_endpoint)
            .field("claw_static_pub", &self.claw_static_pub)
            .field("not_after", &self.not_after)
            .field("now_unix", &self.now_unix)
            .finish()
    }
}

pub fn mint_relay_stream_offer(
    input: RelayStreamOfferMintInput<'_>,
    owner_key: &dyn IdentityKey,
) -> Result<RelayStreamOfferContract, RelayStreamContractError> {
    input
        .credential
        .verify(input.now_unix)
        .map_err(RelayStreamContractError::Credential)?;
    if owner_key.public() != input.credential.owner_p_pub {
        return Err(RelayStreamContractError::MintOwnerMismatch);
    }
    if input.not_after <= input.now_unix {
        return Err(RelayStreamContractError::Expired);
    }
    if input.not_after > input.credential.expires_at {
        return Err(RelayStreamContractError::MintNotAfterExceedsCredentialExpiry);
    }

    let payload = RelayStreamOfferPayload::new(
        input.rendezvous_token,
        input.credential.claw_id.clone(),
        input.credential.slot_id.clone(),
        input.credential.guest_device_pub.clone(),
        input.resource,
        input.expected_path,
        input.relay_endpoint,
        input.claw_static_pub,
        input.not_after,
    );
    RelayStreamOfferContract::sign(payload, owner_key)
}

/// Fase E2: mint a GROUP offer for one member device. Unlike
/// [`mint_relay_stream_offer`] (a single guest credential bound to a slot), a
/// group offer is authorized by LIVE group membership and carries no real
/// slot/credential. `guest_device_pub` is the dialing member device's key (still
/// the Noise transcript pin); `authz` = `Group`; expected path is `RelayStream`.
///
/// `slot_id` is NOT read on the Group dial path — but it MUST be UNIQUE because
/// the offer store keys offers by `(slot_id, resource)`; a shared sentinel would
/// make two members' offers for the same claw+resource collide. The caller
/// supplies a fresh random `slot_id` (the same place it generates the token).
#[allow(clippy::too_many_arguments)]
pub fn mint_relay_stream_group_offer(
    rendezvous_token: RendezvousToken,
    slot_id: SlotId,
    group_id: String,
    member_id: String,
    member_device_pub: P256PublicKey,
    claw_id: String,
    resource: RelayStreamResource,
    relay_endpoint: String,
    claw_static_pub: RelayStreamClawStaticPublicKey,
    not_after: u64,
    now_unix: u64,
    owner_key: &dyn IdentityKey,
) -> Result<RelayStreamOfferContract, RelayStreamContractError> {
    if not_after <= now_unix {
        return Err(RelayStreamContractError::Expired);
    }
    let payload = RelayStreamOfferPayload::new(
        rendezvous_token,
        claw_id,
        slot_id,
        member_device_pub,
        resource,
        RelayStreamExpectedPath::RelayStream,
        relay_endpoint,
        claw_static_pub,
        not_after,
    )
    .with_authz(RelayStreamAudience::Group {
        group_id,
        member_id,
    });
    RelayStreamOfferContract::sign(payload, owner_key)
}

/// Fase E3: mint a PUBLIC offer for one dialer device. A public `ClawSite` is open
/// to anyone, gated ONLY by the live `published_claws` flag (checked at the dial
/// gate), so this carries no slot/credential/group. `guest_device_pub` is the
/// dialing device's own ephemeral key (still the Noise transcript pin, not an
/// access barrier); `authz` = `Public`. `slot_id` must be UNIQUE for the same
/// store-keying reason as the group mint. The engine mints one of these per
/// public dialer of a published claw.
#[allow(clippy::too_many_arguments)]
pub fn mint_relay_stream_public_offer(
    rendezvous_token: RendezvousToken,
    slot_id: SlotId,
    dialer_device_pub: P256PublicKey,
    claw_id: String,
    resource: RelayStreamResource,
    relay_endpoint: String,
    claw_static_pub: RelayStreamClawStaticPublicKey,
    not_after: u64,
    now_unix: u64,
    owner_key: &dyn IdentityKey,
) -> Result<RelayStreamOfferContract, RelayStreamContractError> {
    if not_after <= now_unix {
        return Err(RelayStreamContractError::Expired);
    }
    let payload = RelayStreamOfferPayload::new(
        rendezvous_token,
        claw_id,
        slot_id,
        dialer_device_pub,
        resource,
        RelayStreamExpectedPath::RelayStream,
        relay_endpoint,
        claw_static_pub,
        not_after,
    )
    .with_authz(RelayStreamAudience::Public);
    RelayStreamOfferContract::sign(payload, owner_key)
}

/// Fase E2: pure group-membership authorization for a `Group` offer, checked
/// against the SAME live projection the issuer-trust gated the signer on (the
/// caller passes `ctx.projection`). Fail-closed — every condition must hold:
/// the group grants the claw, the member is active in the group, and the dialing
/// `guest_device_pub` is an active enrolled device of that member. Returns a
/// static reason on rejection (callers collapse it to one opaque error).
pub fn check_relay_stream_group_membership(
    projection: &ProjectedState,
    group_id: &str,
    member_id: &str,
    claw_id: &str,
    guest_device_pub: &P256PublicKey,
) -> Result<(), &'static str> {
    use crate::household_mesh_log::MeshMembership;
    let group = projection
        .groups
        .get(group_id)
        .ok_or("relay-stream-group-unknown")?;
    if group.granted_claws.get(claw_id) != Some(&MeshMembership::Active) {
        return Err("relay-stream-group-claw-not-granted");
    }
    if group.members.get(member_id) != Some(&MeshMembership::Active) {
        return Err("relay-stream-group-member-inactive");
    }
    let devices = projection
        .member_devices
        .get(member_id)
        .ok_or("relay-stream-member-no-devices")?;
    match devices.get(&guest_device_pub.as_bytes()[..]) {
        Some(device) if device.status == MeshMembership::Active => Ok(()),
        _ => Err("relay-stream-member-device-inactive"),
    }
}

/// Fase E3: pure public-site authorization for a `Public` offer, checked against
/// the SAME live projection that gated the signer. Fail-closed: the claw must be
/// currently PUBLISHED (an explicit owner flag). There is no per-guest barrier —
/// that is the point of public — but signer-trust + `not_after` + the relay's D3
/// abuse limits still apply on the surrounding path.
pub fn check_relay_stream_public(
    projection: &ProjectedState,
    claw_id: &str,
) -> Result<(), &'static str> {
    if projection.is_claw_published(claw_id) {
        Ok(())
    } else {
        Err("relay-stream-claw-not-published")
    }
}

impl RelayStreamOfferPayload {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        rendezvous_token: RendezvousToken,
        claw_id: String,
        slot_id: SlotId,
        guest_device_pub: P256PublicKey,
        resource: RelayStreamResource,
        expected_path: RelayStreamExpectedPath,
        relay_endpoint: String,
        claw_static_pub: RelayStreamClawStaticPublicKey,
        not_after: u64,
    ) -> Self {
        Self {
            v: RELAY_STREAM_OFFER_VERSION,
            kind: RELAY_STREAM_OFFER_KIND.to_string(),
            rendezvous_token,
            claw_id,
            slot_id,
            guest_device_pub,
            resource,
            expected_path,
            relay_endpoint,
            claw_static_pub,
            not_after,
            authz: None,
        }
    }

    /// The resolved audience: an absent `authz` ⇒ [`RelayStreamAudience::Device`].
    #[must_use]
    pub fn audience(&self) -> RelayStreamAudience {
        self.authz.clone().unwrap_or(RelayStreamAudience::Device)
    }

    /// Builder: stamp a non-Device audience (Group/Public) on a freshly-`new`'d
    /// payload before signing.
    #[must_use]
    pub fn with_authz(mut self, authz: RelayStreamAudience) -> Self {
        self.authz = Some(authz);
        self
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, RelayStreamContractError> {
        crate::cbor::to_canonical_vec(self).map_err(RelayStreamContractError::Cbor)
    }

    fn validate(&self, now_unix: u64) -> Result<(), RelayStreamContractError> {
        if self.v != RELAY_STREAM_OFFER_VERSION {
            return Err(RelayStreamContractError::VersionUnsupported(self.v));
        }
        if self.kind != RELAY_STREAM_OFFER_KIND {
            return Err(RelayStreamContractError::KindMismatch(self.kind.clone()));
        }
        if self.not_after <= now_unix {
            return Err(RelayStreamContractError::Expired);
        }
        Ok(())
    }
}

impl fmt::Debug for RelayStreamOfferPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamOfferPayload")
            .field("v", &self.v)
            .field("kind", &self.kind)
            .field("rendezvous_token", &self.rendezvous_token)
            .field("claw_id", &self.claw_id)
            .field("slot_id", &self.slot_id)
            .field("guest_device_pub", &self.guest_device_pub)
            .field("resource", &self.resource)
            .field("expected_path", &self.expected_path)
            .field("relay_endpoint", &self.relay_endpoint)
            .field("claw_static_pub", &self.claw_static_pub)
            .field("not_after", &self.not_after)
            .field("authz", &self.authz)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayStreamOfferContract {
    pub payload: RelayStreamOfferPayload,
    pub signer_pub: P256PublicKey,
    pub signature: P256Signature,
}

impl RelayStreamOfferContract {
    pub fn sign(
        payload: RelayStreamOfferPayload,
        signer: &dyn IdentityKey,
    ) -> Result<Self, RelayStreamContractError> {
        let signing_bytes = payload.to_canonical_bytes()?;
        let signature = signer
            .sign(&signing_bytes)
            .map_err(|error| RelayStreamContractError::Sign(error.to_string()))?;
        Ok(Self {
            payload,
            signer_pub: signer.public(),
            signature,
        })
    }

    /// Verifies owner signature, payload shape, and expiry only.
    ///
    /// This owner-only check is for the Claw responder before it has seen an
    /// `AuthEnvelope`. Guest consumers must use [`Self::verify_for_audience`].
    /// CRL/owner-key revocation is not checked here; callers that consume offers
    /// from a store or claim ack must apply the trusted household CRL boundary
    /// when that boundary is available.
    pub fn verify_owner_signature(
        &self,
        expected_signer_pub: &P256PublicKey,
        now_unix: u64,
    ) -> Result<(), RelayStreamContractError> {
        self.payload.validate(now_unix)?;
        if self.signer_pub != *expected_signer_pub {
            return Err(RelayStreamContractError::SignerMismatch);
        }
        let signing_bytes = self.payload.to_canonical_bytes()?;
        verify_signature(expected_signer_pub, &signing_bytes, &self.signature)
            .map_err(|_| RelayStreamContractError::SignatureRejected)
    }

    /// Compatibility wrapper for the owner-only signature check.
    ///
    /// Prefer [`Self::verify_owner_signature`] for Claw-side checks and
    /// [`Self::verify_for_audience`] for guest-side checks.
    pub fn verify(
        &self,
        expected_signer_pub: &P256PublicKey,
        now_unix: u64,
    ) -> Result<(), RelayStreamContractError> {
        self.verify_owner_signature(expected_signer_pub, now_unix)
    }

    pub fn verify_for_audience(
        &self,
        expected_signer_pub: &P256PublicKey,
        expected_guest_device_pub: &P256PublicKey,
        now_unix: u64,
    ) -> Result<(), RelayStreamContractError> {
        self.verify_owner_signature(expected_signer_pub, now_unix)?;
        if self.payload.guest_device_pub != *expected_guest_device_pub {
            return Err(RelayStreamContractError::AudienceMismatch);
        }
        Ok(())
    }

    /// Builds a Noise prologue after owner-only verification.
    ///
    /// This is for the Claw responder before data-tunnel auth reveals the guest
    /// credential. Guest consumers must call
    /// [`Self::to_noise_prologue_for_audience`].
    pub fn to_noise_prologue_owner_verified(
        &self,
        expected_signer_pub: &P256PublicKey,
        now_unix: u64,
    ) -> Result<RelayStreamNoisePrologue, RelayStreamContractError> {
        self.verify_owner_signature(expected_signer_pub, now_unix)?;
        self.build_noise_prologue(expected_signer_pub)
    }

    /// Compatibility wrapper for Claw-side owner-only prologue derivation.
    ///
    /// Prefer [`Self::to_noise_prologue_owner_verified`] on the responder side
    /// and [`Self::to_noise_prologue_for_audience`] on the guest side.
    pub fn to_noise_prologue(
        &self,
        expected_signer_pub: &P256PublicKey,
        now_unix: u64,
    ) -> Result<RelayStreamNoisePrologue, RelayStreamContractError> {
        self.to_noise_prologue_owner_verified(expected_signer_pub, now_unix)
    }

    pub fn to_noise_prologue_for_audience(
        &self,
        expected_signer_pub: &P256PublicKey,
        expected_guest_device_pub: &P256PublicKey,
        now_unix: u64,
    ) -> Result<RelayStreamNoisePrologue, RelayStreamContractError> {
        self.verify_for_audience(expected_signer_pub, expected_guest_device_pub, now_unix)?;
        self.build_noise_prologue(expected_signer_pub)
    }

    /// Claw/engine-side verification anchored in household machine-issuer trust.
    ///
    /// Unlike [`Self::verify_owner_signature`], the expected signer is not a
    /// single pinned key. The offer's own `signer_pub` is accepted iff it is an
    /// active, household-authorized machine issuer (per
    /// [`crate::issuer_trust::is_machine_issuer_active`]); the signature
    /// is then verified against that now-authorized key. This is the production
    /// path now that offers are signed by the engine machine key
    /// (`identity.m_priv`), not the Shamir-split household root. Issuer-trust
    /// failures collapse to the opaque
    /// [`RelayStreamContractError::IssuerUnauthorized`] so signer/cert/removal
    /// detail never reaches a guest-facing boundary.
    ///
    /// `projection` is REQUIRED (not `Option`): a live directory-device
    /// projection must always be supplied so the revocation kill switch can
    /// never be silently inert behind a missing projection. The `Option` lives
    /// only one layer down, in [`crate::issuer_trust`].
    pub fn verify_with_trust(
        &self,
        record: &HouseholdRecord,
        cert: &MachineCert,
        projection: &ProjectedState,
        now_unix: u64,
    ) -> Result<(), RelayStreamContractError> {
        self.payload.validate(now_unix)?;
        is_machine_issuer_active(record, cert, Some(projection), &self.signer_pub)
            .map_err(RelayStreamContractError::IssuerUnauthorized)?;
        let signing_bytes = self.payload.to_canonical_bytes()?;
        verify_signature(&self.signer_pub, &signing_bytes, &self.signature)
            .map_err(|_| RelayStreamContractError::SignatureRejected)
    }

    /// Builds a Noise prologue after machine-issuer trust verification.
    ///
    /// The prologue is built from the offer's own `signer_pub`, so for any offer
    /// the guest accepts via [`Self::to_noise_prologue_for_audience`] with that
    /// same `signer_pub`, the prologue bytes are byte-identical — only the
    /// Claw-side gate changes, never the handshake transcript.
    pub fn to_noise_prologue_with_trust(
        &self,
        record: &HouseholdRecord,
        cert: &MachineCert,
        projection: &ProjectedState,
        now_unix: u64,
    ) -> Result<RelayStreamNoisePrologue, RelayStreamContractError> {
        self.verify_with_trust(record, cert, projection, now_unix)?;
        self.build_noise_prologue(&self.signer_pub)
    }

    fn build_noise_prologue(
        &self,
        expected_signer_pub: &P256PublicKey,
    ) -> Result<RelayStreamNoisePrologue, RelayStreamContractError> {
        let offer_payload_cbor = self.payload.to_canonical_bytes()?;
        let envelope = RelayStreamNoisePrologueEnvelope {
            v: RELAY_STREAM_NOISE_PROLOGUE_VERSION,
            kind: RELAY_STREAM_NOISE_PROLOGUE_KIND.to_string(),
            offer_payload_cbor,
            expected_owner_pub: expected_signer_pub.clone(),
            signer_pub: self.signer_pub.clone(),
            rendezvous_token: self.payload.rendezvous_token.clone(),
            claw_static_pub: self.payload.claw_static_pub.clone(),
            slot_id: self.payload.slot_id.clone(),
            guest_device_pub: self.payload.guest_device_pub.clone(),
            claw_id: self.payload.claw_id.clone(),
            resource: self.payload.resource,
            expected_path: self.payload.expected_path,
            relay_endpoint: self.payload.relay_endpoint.clone(),
            not_after: self.payload.not_after,
        };
        let bytes =
            crate::cbor::to_canonical_vec(&envelope).map_err(RelayStreamContractError::Cbor)?;
        Ok(RelayStreamNoisePrologue(bytes))
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, RelayStreamContractError> {
        crate::cbor::to_canonical_vec(self).map_err(RelayStreamContractError::Cbor)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RelayStreamContractError> {
        crate::cbor::from_canonical_slice(bytes).map_err(RelayStreamContractError::Cbor)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RelayStreamNoisePrologue(Vec<u8>);

impl RelayStreamNoisePrologue {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RelayStreamContractError> {
        let decoded: RelayStreamNoisePrologueEnvelope =
            crate::cbor::from_canonical_slice(bytes).map_err(RelayStreamContractError::Cbor)?;
        if decoded.v != RELAY_STREAM_NOISE_PROLOGUE_VERSION {
            return Err(RelayStreamContractError::VersionUnsupported(decoded.v));
        }
        if decoded.kind != RELAY_STREAM_NOISE_PROLOGUE_KIND {
            return Err(RelayStreamContractError::KindMismatch(decoded.kind));
        }
        Ok(Self(bytes.to_vec()))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for RelayStreamNoisePrologue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelayStreamNoisePrologue(len={}, redacted)", self.len())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayStreamNoisePrologueEnvelope {
    v: u8,
    kind: String,
    #[serde(with = "serde_bytes")]
    offer_payload_cbor: Vec<u8>,
    expected_owner_pub: P256PublicKey,
    signer_pub: P256PublicKey,
    rendezvous_token: RendezvousToken,
    claw_static_pub: RelayStreamClawStaticPublicKey,
    slot_id: SlotId,
    guest_device_pub: P256PublicKey,
    claw_id: String,
    resource: RelayStreamResource,
    expected_path: RelayStreamExpectedPath,
    relay_endpoint: String,
    not_after: u64,
}

impl fmt::Debug for RelayStreamOfferContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamOfferContract")
            .field("payload", &self.payload)
            .field("signer_pub", &self.signer_pub)
            .field("signature", &"P256Signature(len=64, redacted)")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamContractError {
    #[error("unsupported relay stream offer version: {0}")]
    VersionUnsupported(u8),

    #[error("relay stream offer kind mismatch: {0}")]
    KindMismatch(String),

    #[error("relay stream offer is expired")]
    Expired,

    #[error("relay stream offer signer did not match expected owner")]
    SignerMismatch,

    #[error("relay stream offer signer is not an authorized machine issuer")]
    IssuerUnauthorized(#[source] MachineIssuerError),

    #[error("relay stream offer mint owner did not match credential owner")]
    MintOwnerMismatch,

    #[error("relay stream offer audience did not match expected guest")]
    AudienceMismatch,

    #[error("relay stream offer not_after exceeds credential expiry")]
    MintNotAfterExceedsCredentialExpiry,

    #[error("relay stream offer credential is invalid: {0}")]
    Credential(#[source] crate::claw_share::ClawShareError),

    #[error("relay stream offer signature rejected")]
    SignatureRejected,

    #[error("relay stream claw static public key malformed: {actual} bytes")]
    StaticKeyMalformed { actual: usize },

    #[error("relay stream offer CBOR error: {0}")]
    Cbor(#[source] crate::HouseholdError),

    #[error("relay stream offer signing failed: {0}")]
    Sign(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claw_share::SlotId;
    use crate::ids::derive_household_id;
    use crate::keys::{IdentityKey, P256Keypair};
    use crate::person_cert::derive_person_id;

    const NOW: u64 = 1_800_000_000;
    const NOT_AFTER: u64 = NOW + 60;

    fn signer() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap()
    }

    // ── Fase E2: additive authz migration + Group audience ───────────────────

    fn member_device() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x66; 32]).unwrap()
    }

    fn group_projection(
        member_active: bool,
        claw_granted: bool,
        device_active: bool,
        device: &P256PublicKey,
    ) -> crate::household_mesh_log::ProjectedState {
        use crate::household_mesh_log::{
            MeshMembership, ProjectedGroup, ProjectedMemberDevice, ProjectedState,
        };
        let status = |on: bool| {
            if on {
                MeshMembership::Active
            } else {
                MeshMembership::Removed
            }
        };
        let mut p = ProjectedState::default();
        p.groups.insert(
            "g".to_string(),
            ProjectedGroup {
                group_id: "g".to_string(),
                name: "G".to_string(),
                members: [("g_a".to_string(), status(member_active))]
                    .into_iter()
                    .collect(),
                granted_claws: [("claw_alpha".to_string(), status(claw_granted))]
                    .into_iter()
                    .collect(),
                revision: 1,
            },
        );
        p.member_devices.insert(
            "g_a".to_string(),
            [(
                device.as_bytes()[..].to_vec(),
                ProjectedMemberDevice {
                    participant_npub: "npub".to_string(),
                    status: status(device_active),
                },
            )]
            .into_iter()
            .collect(),
        );
        p
    }

    #[test]
    fn authz_none_is_omitted_so_v2_canonical_bytes_are_unchanged() {
        let payload = payload();
        assert!(payload.authz.is_none());
        assert_eq!(payload.audience(), RelayStreamAudience::Device);
        let bytes = payload.to_canonical_bytes().unwrap();
        // The `authz` map key must NOT appear on the wire when None — this is the
        // byte-identity-to-v2 invariant that keeps old signatures/fixtures valid.
        assert!(
            !bytes.windows(5).any(|w| w == b"authz"),
            "authz key must be omitted when None"
        );
        // And the v2 offer still signs + verifies unchanged.
        let offer = RelayStreamOfferContract::sign(payload, &signer()).unwrap();
        offer.verify_owner_signature(&owner_pub(), NOW).unwrap();
    }

    #[test]
    fn group_offer_carries_authz_round_trips_and_verifies_signer() {
        let offer = mint_relay_stream_group_offer(
            token(0x42),
            SlotId([0x99; 16]),
            "g".to_string(),
            "g_a".to_string(),
            member_device().public(),
            "claw_alpha".to_string(),
            RelayStreamResource::ClawSite,
            "relay-stream://127.0.0.1:49152".to_string(),
            static_pub(0x33),
            NOT_AFTER,
            NOW,
            &signer(),
        )
        .unwrap();

        assert_eq!(
            offer.payload.audience(),
            RelayStreamAudience::Group {
                group_id: "g".to_string(),
                member_id: "g_a".to_string(),
            }
        );
        // authz is in the signed bytes (so it cannot be downgraded silently).
        let bytes = offer.payload.to_canonical_bytes().unwrap();
        assert!(bytes.windows(5).any(|w| w == b"authz"));
        offer.verify_owner_signature(&owner_pub(), NOW).unwrap();
        let encoded = offer.to_canonical_bytes().unwrap();
        let decoded = RelayStreamOfferContract::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(decoded, offer);
    }

    #[test]
    fn group_membership_authorizes_only_active_member_active_grant_active_device() {
        let dev = member_device().public();
        // Happy path.
        check_relay_stream_group_membership(
            &group_projection(true, true, true, &dev),
            "g",
            "g_a",
            "claw_alpha",
            &dev,
        )
        .unwrap();
        // Each missing condition fails closed.
        for (proj, why) in [
            (group_projection(false, true, true, &dev), "member inactive"),
            (
                group_projection(true, false, true, &dev),
                "claw not granted",
            ),
            (group_projection(true, true, false, &dev), "device retired"),
        ] {
            assert!(
                check_relay_stream_group_membership(&proj, "g", "g_a", "claw_alpha", &dev).is_err(),
                "{why} must fail closed"
            );
        }
        // Unknown group / wrong claw / wrong device all fail.
        let ok = group_projection(true, true, true, &dev);
        assert!(
            check_relay_stream_group_membership(&ok, "other", "g_a", "claw_alpha", &dev).is_err()
        );
        assert!(check_relay_stream_group_membership(&ok, "g", "g_a", "other_claw", &dev).is_err());
        let stranger = P256Keypair::from_secret_scalar(&[0x77; 32])
            .unwrap()
            .public();
        assert!(
            check_relay_stream_group_membership(&ok, "g", "g_a", "claw_alpha", &stranger).is_err()
        );
    }

    #[test]
    fn public_offer_carries_authz_and_check_requires_published_claw() {
        use crate::household_mesh_log::{MeshMembership, ProjectedState};

        let offer = mint_relay_stream_public_offer(
            token(0x42),
            SlotId([0x98; 16]),
            guest_pub(),
            "claw_alpha".to_string(),
            RelayStreamResource::ClawSite,
            "relay-stream://127.0.0.1:49152".to_string(),
            static_pub(0x33),
            NOT_AFTER,
            NOW,
            &signer(),
        )
        .unwrap();
        assert_eq!(offer.payload.audience(), RelayStreamAudience::Public);
        offer.verify_owner_signature(&owner_pub(), NOW).unwrap();

        let mut published = ProjectedState::default();
        published
            .published_claws
            .insert("claw_alpha".to_string(), MeshMembership::Active);
        check_relay_stream_public(&published, "claw_alpha").unwrap();

        // Unpublished / unknown claw fails closed.
        assert!(check_relay_stream_public(&ProjectedState::default(), "claw_alpha").is_err());
        let mut unpub = ProjectedState::default();
        unpub
            .published_claws
            .insert("claw_alpha".to_string(), MeshMembership::Removed);
        assert!(check_relay_stream_public(&unpub, "claw_alpha").is_err());
    }

    fn attacker() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x55; 32]).unwrap()
    }

    fn owner_pub() -> P256PublicKey {
        signer().public()
    }

    fn guest() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x33; 32]).unwrap()
    }

    fn guest_pub() -> P256PublicKey {
        guest().public()
    }

    fn other_guest_pub() -> P256PublicKey {
        P256Keypair::from_secret_scalar(&[0x44; 32])
            .unwrap()
            .public()
    }

    fn token(label: u8) -> RendezvousToken {
        RendezvousToken::try_new(vec![label; 16]).unwrap()
    }

    fn static_pub(label: u8) -> RelayStreamClawStaticPublicKey {
        RelayStreamClawStaticPublicKey::try_new([label; 32]).unwrap()
    }

    fn payload() -> RelayStreamOfferPayload {
        RelayStreamOfferPayload::new(
            token(0x42),
            "claw_alpha".to_string(),
            SlotId([0x22; 16]),
            guest_pub(),
            RelayStreamResource::Pty,
            RelayStreamExpectedPath::RelayStream,
            "relay-stream://127.0.0.1:49152".to_string(),
            static_pub(0x33),
            NOT_AFTER,
        )
    }

    fn credential() -> GuestCredential {
        GuestCredential::sign(
            derive_household_id(&owner_pub()),
            derive_person_id(&owner_pub()),
            owner_pub(),
            "claw_alpha".to_string(),
            guest_pub(),
            SlotId([0x22; 16]),
            NOW - 60,
            NOW + 600,
            &signer(),
        )
        .unwrap()
    }

    fn credential_for_guest(guest_pub: P256PublicKey) -> GuestCredential {
        GuestCredential::sign(
            derive_household_id(&owner_pub()),
            derive_person_id(&owner_pub()),
            owner_pub(),
            "claw_alpha".to_string(),
            guest_pub,
            SlotId([0x22; 16]),
            NOW - 60,
            NOW + 600,
            &signer(),
        )
        .unwrap()
    }

    fn mint_input_for(credential: &GuestCredential) -> RelayStreamOfferMintInput<'_> {
        RelayStreamOfferMintInput {
            rendezvous_token: token(0x42),
            credential,
            resource: RelayStreamResource::Pty,
            expected_path: RelayStreamExpectedPath::RelayStream,
            relay_endpoint: "relay-stream://127.0.0.1:49152".to_string(),
            claw_static_pub: static_pub(0x33),
            not_after: NOT_AFTER,
            now_unix: NOW,
        }
    }

    fn minted_offer() -> RelayStreamOfferContract {
        let credential = credential();
        mint_relay_stream_offer(mint_input_for(&credential), &signer()).unwrap()
    }

    fn signed_offer() -> RelayStreamOfferContract {
        RelayStreamOfferContract::sign(payload(), &signer()).unwrap()
    }

    fn signed_offer_with(
        edit: impl FnOnce(&mut RelayStreamOfferPayload),
    ) -> RelayStreamOfferContract {
        let mut payload = payload();
        edit(&mut payload);
        RelayStreamOfferContract::sign(payload, &signer()).unwrap()
    }

    fn noise_prologue_for(offer: &RelayStreamOfferContract) -> RelayStreamNoisePrologue {
        offer.to_noise_prologue(&owner_pub(), NOW).unwrap()
    }

    #[test]
    fn rendezvous_stream_relay_contract_mints_offer_from_guest_credential() {
        let credential = credential();

        let offer = mint_relay_stream_offer(mint_input_for(&credential), &signer()).unwrap();

        assert_eq!(offer.payload.guest_device_pub, credential.guest_device_pub);
        assert_eq!(offer.payload.slot_id, credential.slot_id);
        assert_eq!(offer.payload.claw_id, credential.claw_id);
        assert_eq!(offer.payload.not_after, NOT_AFTER);
        offer.verify_owner_signature(&owner_pub(), NOW).unwrap();
        offer
            .verify_for_audience(&owner_pub(), &credential.guest_device_pub, NOW)
            .unwrap();
        assert!(
            !offer
                .to_noise_prologue_for_audience(&owner_pub(), &credential.guest_device_pub, NOW)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rendezvous_stream_relay_contract_minted_offer_rejects_wrong_guest_audience() {
        let offer = minted_offer();

        assert!(matches!(
            offer.verify_for_audience(&owner_pub(), &other_guest_pub(), NOW),
            Err(RelayStreamContractError::AudienceMismatch)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_mint_rejects_not_after_beyond_credential_expiry() {
        let credential = credential();
        let mut input = mint_input_for(&credential);
        input.not_after = credential.expires_at + 1;

        assert!(matches!(
            mint_relay_stream_offer(input, &signer()),
            Err(RelayStreamContractError::MintNotAfterExceedsCredentialExpiry)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_mint_rejects_not_after_not_in_future() {
        let credential = credential();
        let mut input = mint_input_for(&credential);
        input.not_after = NOW;

        assert!(matches!(
            mint_relay_stream_offer(input, &signer()),
            Err(RelayStreamContractError::Expired)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_mint_rejects_wrong_owner_signer() {
        let credential = credential();

        assert!(matches!(
            mint_relay_stream_offer(mint_input_for(&credential), &attacker()),
            Err(RelayStreamContractError::MintOwnerMismatch)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_mint_uses_credential_guest_by_construction() {
        let credential = credential_for_guest(other_guest_pub());

        let offer = mint_relay_stream_offer(mint_input_for(&credential), &signer()).unwrap();

        assert_eq!(offer.payload.guest_device_pub, other_guest_pub());
        assert!(
            offer
                .verify_for_audience(&owner_pub(), &other_guest_pub(), NOW)
                .is_ok()
        );
        assert!(matches!(
            offer.verify_for_audience(&owner_pub(), &guest_pub(), NOW),
            Err(RelayStreamContractError::AudienceMismatch)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_mint_debug_and_errors_do_not_leak_token_or_secret() {
        let credential = credential();
        let input = RelayStreamOfferMintInput {
            rendezvous_token: RendezvousToken::try_new(b"0123456789abcdef").unwrap(),
            credential: &credential,
            resource: RelayStreamResource::Pty,
            expected_path: RelayStreamExpectedPath::RelayStream,
            relay_endpoint: "relay-stream://127.0.0.1:49152".to_string(),
            claw_static_pub: static_pub(0x33),
            not_after: NOT_AFTER,
            now_unix: NOW,
        };
        let debug = format!("{input:?}");

        assert!(!debug.contains("0123456789abcdef"));
        assert!(!debug.contains("30313233343536373839616263646566"));
        assert!(debug.contains("redacted"));

        let err = mint_relay_stream_offer(input, &attacker()).unwrap_err();
        let error_text = format!("{err:?}");
        assert!(!error_text.contains("0123456789abcdef"));
        assert!(!error_text.contains("30313233343536373839616263646566"));
    }

    #[test]
    fn rendezvous_stream_relay_contract_roundtrip_and_canonical_bytes_are_deterministic() {
        let offer = signed_offer();

        offer.verify_owner_signature(&owner_pub(), NOW).unwrap();
        offer
            .verify_for_audience(&owner_pub(), &guest_pub(), NOW)
            .unwrap();
        let payload_a = offer.payload.to_canonical_bytes().unwrap();
        let payload_b = offer.payload.to_canonical_bytes().unwrap();
        assert_eq!(payload_a, payload_b);

        let encoded = offer.to_canonical_bytes().unwrap();
        let decoded = RelayStreamOfferContract::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(decoded, offer);
        assert_eq!(decoded.to_canonical_bytes().unwrap(), encoded);
    }

    #[test]
    fn rendezvous_stream_relay_contract_token_change_fails_binding() {
        let mut offer = signed_offer();
        offer.payload.rendezvous_token = token(0x99);

        assert!(matches!(
            offer.verify(&owner_pub(), NOW),
            Err(RelayStreamContractError::SignatureRejected)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_audience_change_fails_binding() {
        let mut offer = signed_offer();
        offer.payload.guest_device_pub = other_guest_pub();

        assert!(matches!(
            offer.verify_owner_signature(&owner_pub(), NOW),
            Err(RelayStreamContractError::SignatureRejected)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_claw_id_change_fails_binding() {
        let mut offer = signed_offer();
        offer.payload.claw_id = "claw_beta".to_string();

        assert!(matches!(
            offer.verify(&owner_pub(), NOW),
            Err(RelayStreamContractError::SignatureRejected)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_slot_and_static_key_changes_fail_binding() {
        let mut slot_changed = signed_offer();
        slot_changed.payload.slot_id = SlotId([0x23; 16]);
        assert!(matches!(
            slot_changed.verify(&owner_pub(), NOW),
            Err(RelayStreamContractError::SignatureRejected)
        ));

        let mut static_key_changed = signed_offer();
        static_key_changed.payload.claw_static_pub = static_pub(0x44);
        assert!(matches!(
            static_key_changed.verify(&owner_pub(), NOW),
            Err(RelayStreamContractError::SignatureRejected)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_resource_change_fails_binding() {
        let mut offer = signed_offer();
        offer.payload.resource = RelayStreamResource::ClawSite;

        assert!(matches!(
            offer.verify(&owner_pub(), NOW),
            Err(RelayStreamContractError::SignatureRejected)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_relay_endpoint_and_path_change_fail_binding() {
        let mut endpoint_changed = signed_offer();
        endpoint_changed.payload.relay_endpoint = "relay-stream://127.0.0.1:49153".to_string();
        assert!(matches!(
            endpoint_changed.verify(&owner_pub(), NOW),
            Err(RelayStreamContractError::SignatureRejected)
        ));

        let mut path_changed = signed_offer();
        path_changed.payload.expected_path = RelayStreamExpectedPath::CommunityRelay;
        assert!(matches!(
            path_changed.verify(&owner_pub(), NOW),
            Err(RelayStreamContractError::SignatureRejected)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_expired_offer_fails_validation() {
        let mut offer = signed_offer();
        offer.payload.not_after = NOW;

        assert!(matches!(
            offer.verify(&owner_pub(), NOW),
            Err(RelayStreamContractError::Expired)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_attacker_signed_offer_fails_owner_anchor() {
        let offer = RelayStreamOfferContract::sign(payload(), &attacker()).unwrap();

        assert!(matches!(
            offer.verify(&owner_pub(), NOW),
            Err(RelayStreamContractError::SignerMismatch)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_wrong_audience_fails_guest_verification() {
        let offer = signed_offer();

        assert!(matches!(
            offer.verify_for_audience(&owner_pub(), &other_guest_pub(), NOW),
            Err(RelayStreamContractError::AudienceMismatch)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_audience_changes_canonical_payload() {
        let base = payload().to_canonical_bytes().unwrap();
        let changed = signed_offer_with(|payload| payload.guest_device_pub = other_guest_pub())
            .payload
            .to_canonical_bytes()
            .unwrap();

        assert_ne!(changed, base);
    }

    #[test]
    fn rendezvous_stream_relay_contract_debug_does_not_leak_token_or_secret() {
        let secret_text = b"0123456789abcdef";
        let payload = RelayStreamOfferPayload::new(
            RendezvousToken::try_new(secret_text).unwrap(),
            "claw_alpha".to_string(),
            SlotId([0x22; 16]),
            guest_pub(),
            RelayStreamResource::Pty,
            RelayStreamExpectedPath::RelayStream,
            "relay-stream://127.0.0.1:49152".to_string(),
            static_pub(0x33),
            NOT_AFTER,
        );
        let offer = RelayStreamOfferContract::sign(payload, &signer()).unwrap();
        let debug = format!("{offer:?}");

        assert!(!debug.contains("0123456789abcdef"));
        assert!(!debug.contains("30313233343536373839616263646566"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn rendezvous_stream_relay_contract_noise_prologue_roundtrip_and_bytes_are_deterministic() {
        let offer = signed_offer();

        let prologue_a = noise_prologue_for(&offer);
        let prologue_b = noise_prologue_for(&offer);
        assert_eq!(prologue_a, prologue_b);
        assert!(!prologue_a.is_empty());

        let decoded =
            RelayStreamNoisePrologue::from_canonical_bytes(prologue_a.as_bytes()).unwrap();
        assert_eq!(decoded, prologue_a);
    }

    #[test]
    fn rendezvous_stream_relay_contract_noise_prologue_changes_when_bound_fields_change() {
        let base = noise_prologue_for(&signed_offer());

        let variants = [
            signed_offer_with(|payload| payload.rendezvous_token = token(0x99)),
            signed_offer_with(|payload| payload.guest_device_pub = other_guest_pub()),
            signed_offer_with(|payload| payload.claw_static_pub = static_pub(0x44)),
            signed_offer_with(|payload| payload.slot_id = SlotId([0x23; 16])),
            signed_offer_with(|payload| payload.claw_id = "claw_beta".to_string()),
            signed_offer_with(|payload| payload.resource = RelayStreamResource::ClawSite),
            signed_offer_with(|payload| {
                payload.expected_path = RelayStreamExpectedPath::CommunityRelay;
            }),
            signed_offer_with(|payload| {
                payload.relay_endpoint = "relay-stream://127.0.0.1:49153".to_string();
            }),
            signed_offer_with(|payload| payload.not_after = NOT_AFTER + 1),
            // Fase E2: the audience mode is bound into the prologue (via the
            // embedded offer_payload_cbor), so a Group/Public offer can never
            // share a transcript with the Device offer it would be downgraded to.
            signed_offer_with(|payload| {
                payload.authz = Some(RelayStreamAudience::Group {
                    group_id: "g".to_string(),
                    member_id: "g_a".to_string(),
                });
            }),
        ];

        for variant in variants {
            assert_ne!(noise_prologue_for(&variant), base);
        }
    }

    #[test]
    fn rendezvous_stream_relay_contract_noise_prologue_rejects_expired_offer() {
        let offer = signed_offer_with(|payload| payload.not_after = NOW);

        assert!(matches!(
            offer.to_noise_prologue(&owner_pub(), NOW),
            Err(RelayStreamContractError::Expired)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_noise_prologue_rejects_attacker_signed_offer() {
        let offer = RelayStreamOfferContract::sign(payload(), &attacker()).unwrap();

        assert!(matches!(
            offer.to_noise_prologue(&owner_pub(), NOW),
            Err(RelayStreamContractError::SignerMismatch)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_contract_noise_prologue_debug_does_not_leak_token_or_secret() {
        let secret_text = b"0123456789abcdef";
        let offer = signed_offer_with(|payload| {
            payload.rendezvous_token = RendezvousToken::try_new(secret_text).unwrap();
        });
        let prologue = noise_prologue_for(&offer);
        let debug = format!("{prologue:?}");

        assert!(!debug.contains("0123456789abcdef"));
        assert!(!debug.contains("30313233343536373839616263646566"));
        assert!(debug.contains("redacted"));
    }

    // ── Fase E2: authz cannot be downgraded/confused after signing ───────────

    #[test]
    fn rendezvous_stream_relay_contract_authz_downgrade_or_cross_mode_fails_binding() {
        // The audience mode lives inside the signed canonical bytes (invariant
        // #6): a signed Group offer cannot be downgraded to Device (authz
        // stripped) or confused into Public, and a signed Device offer cannot be
        // upgraded to Group, without breaking the owner signature.
        let group = || {
            signed_offer_with(|payload| {
                payload.authz = Some(RelayStreamAudience::Group {
                    group_id: "g".to_string(),
                    member_id: "g_a".to_string(),
                });
            })
        };

        // As signed (Group), it verifies.
        group().verify_owner_signature(&owner_pub(), NOW).unwrap();

        // Downgrade Group -> Device (strip authz) breaks the signature.
        let mut downgraded = group();
        downgraded.payload.authz = None;
        assert!(matches!(
            downgraded.verify_owner_signature(&owner_pub(), NOW),
            Err(RelayStreamContractError::SignatureRejected)
        ));

        // Cross-mode Group -> Public breaks the signature.
        let mut to_public = group();
        to_public.payload.authz = Some(RelayStreamAudience::Public);
        assert!(matches!(
            to_public.verify_owner_signature(&owner_pub(), NOW),
            Err(RelayStreamContractError::SignatureRejected)
        ));

        // Reverse: a signed Device offer (authz None) cannot be upgraded to Group.
        let mut upgraded = signed_offer();
        upgraded.payload.authz = Some(RelayStreamAudience::Group {
            group_id: "g".to_string(),
            member_id: "g_a".to_string(),
        });
        assert!(matches!(
            upgraded.verify_owner_signature(&owner_pub(), NOW),
            Err(RelayStreamContractError::SignatureRejected)
        ));
    }

    #[test]
    fn rendezvous_stream_relay_offer_rejects_unknown_field_and_unknown_audience_variant() {
        // Invariant #7: deny_unknown_fields rejects a stray top-level field, and
        // the closed audience enum rejects an unknown variant tag. We round-trip a
        // real payload through a CBOR Value, mutate it, and assert the typed decode
        // fails — exercising the wire-decode boundary, not just the serde attrs.
        use ciborium::value::Value;

        fn to_value(payload: &RelayStreamOfferPayload) -> Value {
            ciborium::de::from_reader(payload.to_canonical_bytes().unwrap().as_slice()).unwrap()
        }
        fn encode(value: &Value) -> Vec<u8> {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(value, &mut buf).unwrap();
            buf
        }

        // (1) Extra unknown top-level field -> rejected.
        let mut with_extra = to_value(&payload());
        if let Value::Map(entries) = &mut with_extra {
            entries.push((Value::Text("bogus".to_string()), Value::Bool(true)));
        } else {
            panic!("offer payload must encode as a CBOR map");
        }
        let decoded: Result<RelayStreamOfferPayload, _> =
            crate::cbor::from_canonical_slice(&encode(&with_extra));
        assert!(
            decoded.is_err(),
            "an unknown extra field must be rejected (deny_unknown_fields)"
        );

        // (2) Unknown audience variant tag -> rejected. A Group audience encodes
        // as a single-key map {"group": {...}}; rename the tag to an unknown one.
        let group = payload().with_authz(RelayStreamAudience::Group {
            group_id: "g".to_string(),
            member_id: "g_a".to_string(),
        });
        let mut with_bogus_variant = to_value(&group);
        if let Value::Map(entries) = &mut with_bogus_variant {
            for (key, val) in entries.iter_mut() {
                if matches!(key, Value::Text(t) if t == "authz") {
                    let Value::Map(inner) = val else {
                        panic!("group authz must encode as a tagged map");
                    };
                    for (variant_key, _) in inner.iter_mut() {
                        if matches!(variant_key, Value::Text(t) if t == "group") {
                            *variant_key = Value::Text("bogus".to_string());
                        }
                    }
                }
            }
        }
        let decoded: Result<RelayStreamOfferPayload, _> =
            crate::cbor::from_canonical_slice(&encode(&with_bogus_variant));
        assert!(
            decoded.is_err(),
            "an unknown audience variant must be rejected by the closed enum"
        );
    }

    // Cross-language fixture (Rust half): a deterministic relay_stream offer
    // payload with authz=None (Device) MUST encode to byte-identical canonical CBOR
    // as a pre-Fase-E2 v2 offer — the authz key is omitted from the wire
    // (skip_serializing_if). This locks the Rust side and the byte-identity-to-v2
    // migration invariant (design risk #5, the merge gate).
    //
    // TODO(cross-repo / iSoyehtTerm): mirror EXPECTED_OFFER_V2_AUTHZ_NONE_HEX below
    // in the Swift RelayStream offer fixture (alongside the existing
    // ClawShareCrossLanguageFixtureTests). The cross-stack guarantee lands when the
    // Swift fixture asserts the SAME literal. Regenerate both in lockstep (run with
    // --nocapture) only on an intentional wire-shape change.
    //
    // Deterministic inputs: rendezvous_token [0x42;16], claw_id "claw_alpha",
    // slot_id [0x22;16], guest_device_pub = P-256 public for secret scalar
    // [0x33;32], resource pty, expected_path relay_stream, relay_endpoint
    // "relay-stream://127.0.0.1:49152", claw_static_pub [0x33;32], not_after
    // 1_800_000_060.
    #[test]
    fn cross_language_fixture_relay_stream_offer_authz_none_v2_hex() {
        // CBOR map header `ab` = map(11): exactly the 11 v2 fields, authz omitted
        // (a Some(authz) offer would be `ac`/map(12)). This IS the byte-identity
        // anchor — the Swift fixture must pin this same literal.
        const EXPECTED_OFFER_V2_AUTHZ_NONE_HEX: &str = "ab617602646b696e64781d636c61772d73686172652f72656c61792d73747265616d2d6f6666657267636c61775f69646a636c61775f616c70686167736c6f745f69645022222222222222222222222222222222687265736f7572636563707479696e6f745f61667465721a6b49d23c6d65787065637465645f706174686c72656c61795f73747265616d6e72656c61795f656e64706f696e74781e72656c61792d73747265616d3a2f2f3132372e302e302e313a34393135326f636c61775f7374617469635f707562582033333333333333333333333333333333333333333333333333333333333333337067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d7072656e64657a766f75735f746f6b656e5042424242424242424242424242424242";

        let payload = RelayStreamOfferPayload::new(
            token(0x42),
            "claw_alpha".to_string(),
            SlotId([0x22; 16]),
            guest_pub(),
            RelayStreamResource::Pty,
            RelayStreamExpectedPath::RelayStream,
            "relay-stream://127.0.0.1:49152".to_string(),
            static_pub(0x33),
            NOT_AFTER,
        );
        assert!(payload.authz.is_none());
        assert_eq!(payload.audience(), RelayStreamAudience::Device);

        let bytes = payload.to_canonical_bytes().unwrap();
        // Byte-identity to a pre-authz v2 offer: the authz key never appears.
        assert!(
            !bytes.windows(5).any(|w| w == b"authz"),
            "authz must be omitted from the wire when None"
        );

        let hex_actual = hex::encode(&bytes);
        assert_eq!(
            hex_actual, EXPECTED_OFFER_V2_AUTHZ_NONE_HEX,
            "relay_stream offer v2 wire drift — regenerate the Swift fixture in lockstep"
        );

        // Canonical encoding is deterministic within the same build.
        assert_eq!(
            hex::encode(payload.to_canonical_bytes().unwrap()),
            hex_actual
        );
    }
}
