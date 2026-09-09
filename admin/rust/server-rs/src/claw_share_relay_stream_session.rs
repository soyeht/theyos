//! Credential-less authorized session for Product A `relay_stream` Group/Public
//! dials (Fase E2.5/E3), plus the data-tunnel verifier and the mid-session
//! liveness predicate the claw responder wires for those audiences.
//!
//! Device (1:1 slot) auth is unchanged: it keeps `authorize_session` (an
//! owner-signed credential bound to a consumed slot) plus the slot-revoke watcher.
//! Group/Public have NO credential
//! and NO slot; their authentication is a proof-of-possession of the offer-pinned
//! dialing device key (a captured public offer is not the private key), bound to
//! THIS exact signed offer + claw + freshness. Authentication proves only
//! POSSESSION; the SOLE authorization authority is the live gate
//! ([`RelayStreamIssuerTrust::verify_offer_with_context`] + the audience branch),
//! re-run at OPEN (the target router) and on a LIVE clock at every mid-session
//! check, so a removed member / revoked grant / unpublished site / expired offer /
//! issuer-removed signer tears the LIVE session down — never fails open.

use std::fmt::Write as _;

use household_rs::claw_share::GuestCredential;
use household_rs::claw_share::data_tunnel::{
    AuthEnvelope, DataTunnelError, DataTunnelSession, ReplayGuard, credential_hash,
};

use crate::claw_share_relay_stream_contract::{
    RelayStreamAudience, RelayStreamOfferContract, RelayStreamResource,
    check_relay_stream_group_membership, check_relay_stream_public,
};
use crate::claw_share_relay_stream_issuer_trust::RelayStreamIssuerTrust;

/// A credential-less authorized session for a Group/Public dial. Carries ONLY
/// local correlation values for the [`TunnelAck`] — it is NOT a credential and
/// NOT a routing/roster/deny-list key. `session_id`/`mesh_ipv6` derive from the
/// FULL BLAKE3 of the connection's verified offer (non-truncated, panel #7), so
/// they are stable per-offer but NOT slot-stable across reconnects (each offer is
/// its own session). The panel's choice A: no synthetic [`GuestCredential`].
///
/// [`TunnelAck`]: household_rs::claw_share::data_tunnel::TunnelAck
/// [`GuestCredential`]: household_rs::claw_share::GuestCredential
pub struct RelayStreamOfferSession {
    session_id: String,
    mesh_ipv6: String,
    allows_persistent_targets: bool,
}

impl RelayStreamOfferSession {
    /// Derive the session correlation values from the connection's verified
    /// offer. `session_id = hex(blake3(canonical offer))`; `mesh_ipv6` is a
    /// non-truncated ULA-style placeholder from the first 8 hash bytes (vs the
    /// Device path's 4-byte derivation). Placeholder, never routed.
    #[must_use = "the derived session is the authorized session value for the ack"]
    pub fn from_offer(offer: &RelayStreamOfferContract) -> Result<Self, DataTunnelError> {
        let bytes = offer
            .payload
            .to_canonical_bytes()
            .map_err(|e| DataTunnelError::Cbor(e.to_string()))?;
        let hash = credential_hash(&bytes); // BLAKE3-256 of the canonical offer
        let mut session_id = String::with_capacity(hash.len() * 2);
        for b in &hash {
            let _ = write!(session_id, "{b:02x}");
        }
        // The `c1a0` hextet is a stable, human-recognizable "claw" label rendered
        // in VALID hex. The earlier `c1aw` spelling is not a hex hextet, so it does
        // not parse as an IPv6 address — and the T1 IpTunnel guest's session-ack
        // check parses this field strictly. Placeholder only, never routed.
        let mesh_ipv6 = format!(
            "fd00:c1a0::{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        );
        Ok(Self {
            session_id,
            mesh_ipv6,
            allows_persistent_targets: offer.payload.resource == RelayStreamResource::ClawSite,
        })
    }
}

impl DataTunnelSession for RelayStreamOfferSession {
    fn session_id(&self) -> String {
        self.session_id.clone()
    }
    fn mesh_ipv6(&self) -> String {
        self.mesh_ipv6.clone()
    }

    fn allows_persistent_targets(&self) -> bool {
        self.allows_persistent_targets
    }
}

/// Device-audience authorized session: the owner-signed [`GuestCredential`]
/// plus persistent-target eligibility keyed on the OFFER's signed resource.
///
/// The ack stays byte-identical to the legacy Device path — `session_id` and
/// `mesh_ipv6` delegate VERBATIM to the inner credential's slot-derived
/// helpers. Only `allows_persistent_targets` is new, and it is keyed on
/// `offer.payload.resource` (verified via the Noise prologue at handshake and
/// re-verified by the live gate), so a caller cannot flip it without breaking
/// the offer's signature. `ClawSite` enables sequential `OpenPersistent`
/// targets; `Pty` and `IpTunnel` retain the legacy single-target shape.
pub struct RelayStreamDeviceSession {
    credential: GuestCredential,
    allows_persistent_targets: bool,
}

impl RelayStreamDeviceSession {
    #[must_use]
    pub fn new(credential: GuestCredential, resource: RelayStreamResource) -> Self {
        Self {
            credential,
            allows_persistent_targets: resource == RelayStreamResource::ClawSite,
        }
    }

    /// The credential the slot-revocation predicate keys on.
    #[must_use]
    pub fn credential(&self) -> &GuestCredential {
        &self.credential
    }
}

impl DataTunnelSession for RelayStreamDeviceSession {
    fn session_id(&self) -> String {
        self.credential.session_id()
    }
    fn mesh_ipv6(&self) -> String {
        self.credential.mesh_ipv6()
    }

    fn allows_persistent_targets(&self) -> bool {
        self.allows_persistent_targets
    }
}

/// Credential-less data-tunnel verifier for a Group/Public dial (panel choice A).
///
/// Proves PRESENT possession of the offer-pinned `guest_device_pub` (the offer is
/// public; capturing it does not yield the private key), binds the token to THIS
/// exact signed offer (`credential_hash == blake3(canonical offer)`, derived
/// server-side from the connection's own verified offer — never from the
/// attacker-supplied `credential_cbor`), to the claw (`target_id == claw_id`), and
/// to freshness (TTL + single-use nonce). It asserts NOTHING about authorization:
/// membership/published is the live gate's job (the open-time target router and
/// the mid-session [`relay_stream_offer_session_revoked`] predicate).
///
/// `offer` MUST be the SAME `&RelayStreamOfferContract` the Noise handshake and
/// the target router used (single-source binding, panel #4) — audience and
/// `guest_device_pub` are read from it, never from the token or another offer.
///
/// The token's `endpoint` and `session_id` are intentionally NOT re-checked
/// field-by-field (audit D3, info-only): `credential_hash == blake3(canonical
/// offer)` already pins the WHOLE offer — including `relay_endpoint` and
/// `guest_device_pub` — and the token is signed by the guest's own key, so the
/// cryptographic binding is complete without per-field comparisons.
#[must_use = "the authorized session must be returned to the serve loop, not discarded"]
pub fn verify_relay_stream_offer_session(
    offer: &RelayStreamOfferContract,
    replay: &ReplayGuard,
    envelope: &AuthEnvelope,
    now_unix: u64,
) -> Result<RelayStreamOfferSession, DataTunnelError> {
    let offer_bytes = offer
        .payload
        .to_canonical_bytes()
        .map_err(|e| DataTunnelError::Cbor(e.to_string()))?;
    let expected = credential_hash(&offer_bytes);
    // PoP under the offer-pinned dialing device key: checks hash == expected,
    // TTL (<= SESSION_TOKEN_MAX_TTL_SECS), and the signature under guest_device_pub.
    envelope
        .token
        .verify(&offer.payload.guest_device_pub, &expected, now_unix)?;
    if envelope.token.target_id != offer.payload.claw_id {
        return Err(DataTunnelError::TokenRejected("target-mismatch".into()));
    }
    // Single-use: reject replays of the same token nonce.
    replay.check_and_record(&envelope.token.nonce, envelope.token.expires_at, now_unix)?;
    RelayStreamOfferSession::from_offer(offer)
}

/// Mid-session liveness predicate for a Group/Public session — the panel's
/// load-bearing fail-closed fix (`true` ⇒ revoked ⇒ tear the session down).
///
/// Re-runs the FULL open gate at the LIVE `now_unix` the caller supplies:
/// [`RelayStreamIssuerTrust::verify_offer_with_context`] (which enforces
/// `not_after` expiry + `is_machine_issuer_active` + a FRESH projection) and then
/// the audience authorization branch (group membership / published flag) on that
/// same single snapshot. So an expired offer, an issuer-removed signer, a removed
/// member, a revoked grant, a retired device, or an unpublished site all tear the
/// LIVE session down — not just a new dial. Pure given `now_unix`; the caller's
/// Rev closure supplies a LIVE clock per invocation (panel #2), and the serve
/// loop polls it on both its `revoke_poll` tick and per inbound `Data` frame
/// (panel #3), so even an idle session is cut within the poll interval.
#[must_use = "the revocation verdict must gate the live session, not be ignored"]
pub fn relay_stream_offer_session_revoked(
    offer: &RelayStreamOfferContract,
    trust: &RelayStreamIssuerTrust,
    now_unix: u64,
) -> bool {
    // not_after expired / signer no longer an active machine issuer (directory
    // kill switch) / signature no longer verifies → fail closed.
    let Ok(ctx) = trust.verify_offer_with_context(offer, now_unix) else {
        return true;
    };
    match offer.payload.audience() {
        RelayStreamAudience::Group {
            group_id,
            member_id,
        } => check_relay_stream_group_membership(
            &ctx.projection,
            &group_id,
            &member_id,
            &offer.payload.claw_id,
            &offer.payload.guest_device_pub,
        )
        .is_err(),
        RelayStreamAudience::Public => {
            check_relay_stream_public(&ctx.projection, &offer.payload.claw_id).is_err()
        }
        // Device never uses this predicate (it keeps the slot-keyed Rev). If a
        // Device offer ever reached here it would be a wiring bug — fail closed.
        RelayStreamAudience::Device => true,
    }
}

#[cfg(test)]
mod tests;
