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

use crate::claw_share::rendezvous_token::RendezvousToken;

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
    /// Per-Claw VPN IP-packet stream.
    ///
    /// This is a signed contract resource only. Runtime routing intentionally
    /// stays fail-closed until the Phase-1 TUN/utun agent exists.
    IpTunnel,
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
    /// Slice B (ADDITIVE, optional). Stable Share app presentation for the
    /// Device+ClawSite path: the app identity, current display name, and
    /// owner display name AT MINT TIME. This is a signed SNAPSHOT for
    /// presentation, never an authority — routing and authorization key on
    /// `claw_id`/live checks, and a later rename does not invalidate the
    /// offer. `None` is omitted from the wire, so an offer WITHOUT this
    /// field keeps the exact canonical CBOR, signature, and v2 fixtures it
    /// had before the field existed; `Some(_)` is covered by the signature
    /// and the Noise prologue like every other field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_presentation: Option<ShareableAppPresentation>,
}

/// Slice B: the signed app presentation embedded in a Device+ClawSite offer.
/// Constructed through [`Self::try_new`] at mint call sites (provision is
/// required to use it; `RelayStreamOfferContract::sign` does NOT validate)
/// and re-validated by the payload's `validate` at verify: `app_id` is the
/// pinned Share identity shape (`app_` + 32 lowercase hex), both names are
/// nonempty and length-bounded. `deny_unknown_fields` is load-bearing, not
/// hygiene: an ignored nested key would vanish on the re-encode used by
/// signature verification, accepting bytes that were never authenticated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareableAppPresentation {
    pub app_id: String,
    pub display_name: String,
    pub owner_display_name: String,
}

/// `app_` + 32 lowercase hex = 128 bits CSPRNG (pinned `shareable_apps` id).
const SHARE_APP_ID_PREFIX: &str = "app_";
const SHARE_APP_ID_HEX_LEN: usize = 32;
const SHARE_PRESENTATION_NAME_MAX_CHARS: usize = 128;

impl ShareableAppPresentation {
    pub fn try_new(
        app_id: impl Into<String>,
        display_name: impl Into<String>,
        owner_display_name: impl Into<String>,
    ) -> Result<Self, RelayStreamContractError> {
        let presentation = Self {
            app_id: app_id.into(),
            display_name: display_name.into(),
            owner_display_name: owner_display_name.into(),
        };
        presentation.validate()?;
        Ok(presentation)
    }

    fn validate(&self) -> Result<(), RelayStreamContractError> {
        let hex = self
            .app_id
            .strip_prefix(SHARE_APP_ID_PREFIX)
            .filter(|hex| {
                hex.len() == SHARE_APP_ID_HEX_LEN
                    && hex
                        .chars()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            })
            .ok_or(RelayStreamContractError::InvalidPresentation(
                "app_id",
            ))?;
        let _ = hex;
        for (name, field) in [
            (&self.display_name, "display_name"),
            (&self.owner_display_name, "owner_display_name"),
        ] {
            let len = name.chars().count();
            if len == 0 || len > SHARE_PRESENTATION_NAME_MAX_CHARS || name.trim().is_empty() {
                return Err(RelayStreamContractError::InvalidPresentation(field));
            }
        }
        Ok(())
    }
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

/// Fail closed on resource/audience combinations that would turn a broadly
/// shared offer into an interactive shell on the engine host. Device remains
/// the only audience allowed to request PTY until the target router can attach
/// the session to the selected isolated instance.
fn validate_resource_for_audience(
    resource: RelayStreamResource,
    audience: &RelayStreamAudience,
) -> Result<(), RelayStreamContractError> {
    if resource == RelayStreamResource::Pty
        && matches!(
            audience,
            RelayStreamAudience::Group { .. } | RelayStreamAudience::Public
        )
    {
        return Err(RelayStreamContractError::PtyForbiddenForSharedAudience);
    }
    Ok(())
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
    /// Owned so the caller hands over a already-validated snapshot
    /// (`ShareableAppPresentation::try_new`); the mint copies it onto the
    /// payload before signing and does NOT re-validate — `verify` does, via
    /// the payload's `validate`.
    pub app_presentation: Option<ShareableAppPresentation>,
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
            // Presence only: the snapshot carries human names
            // (`display_name`, `owner_display_name`), which must never reach a
            // log line.
            .field("app_presentation", &self.app_presentation.is_some())
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

    let mut payload = RelayStreamOfferPayload::new(
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
    // Copied BEFORE signing so the snapshot is covered by the signature like
    // every other field. Assigned rather than passed through
    // `RelayStreamOfferPayload::new` on purpose: `new` has 19 call sites, and
    // this mirrors how `authz` is already set (target_router.rs). No validation
    // here — `try_new` guarded it at the caller, and `verify` revalidates.
    payload.app_presentation = input.app_presentation;
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
    let audience = RelayStreamAudience::Group {
        group_id,
        member_id,
    };
    validate_resource_for_audience(resource, &audience)?;
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
    .with_authz(audience);
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
    validate_resource_for_audience(resource, &RelayStreamAudience::Public)?;
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
            app_presentation: None,
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
        validate_resource_for_audience(self.resource, &self.audience())?;
        if let Some(presentation) = &self.app_presentation {
            presentation.validate()?;
            // Namespace fences: the signed snapshot may exist ONLY on the
            // Device+ClawSite path it was designed for, and it must describe
            // THIS offer's claw — a covered signature over two contradictory
            // values is still a contradiction.
            if self.audience() != RelayStreamAudience::Device
                || self.resource != RelayStreamResource::ClawSite
            {
                return Err(RelayStreamContractError::InvalidPresentation(
                    "audience-resource",
                ));
            }
            if presentation.app_id != self.claw_id {
                return Err(RelayStreamContractError::InvalidPresentation(
                    "app_id-claw-mismatch",
                ));
            }
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
            // Presence only, same reason as the mint input's Debug: the
            // snapshot holds `display_name`/`owner_display_name`. The derived
            // Debug on ShareableAppPresentation itself is deliberately left
            // intact — this is about what a payload log line emits.
            .field("app_presentation", &self.app_presentation.is_some())
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
        // Device offers may use the single-machine/root fallback. Credential-less
        // Group/Public offers must be authorized by the machine-cert chain because
        // they carry no per-guest credential.
        let allow_root_signer = matches!(self.payload.audience(), RelayStreamAudience::Device);
        is_machine_issuer_active(
            record,
            cert,
            Some(projection),
            &self.signer_pub,
            allow_root_signer,
        )
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

    #[error("relay stream PTY is forbidden for group and public audiences")]
    PtyForbiddenForSharedAudience,

    #[error("relay stream app presentation field is invalid: {0}")]
    InvalidPresentation(&'static str),

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
mod tests;
