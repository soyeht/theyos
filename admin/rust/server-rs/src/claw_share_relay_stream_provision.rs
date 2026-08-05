//! Pure provisioning helper for Product A `relay_stream` offers.
//!
//! C7a. `provision_relay_stream_offer` mints a `RelayStreamOfferContract` from an
//! already-signed `GuestCredential` and stores it, so the reverse-connect pool
//! can later pick it up via `RelayStreamOfferStore::list_active`.
//!
//! It is a PURE helper: it does not touch the claim flow (C7b), does not deliver
//! the offer to the guest (C7c), and does not touch the pool/mount/runtime. The
//! offer's identity (`claw_id` / `slot_id` / `guest_device_pub`) comes solely from the
//! credential via the mint API (C1b); this helper adds only a fresh random
//! rendezvous token, the resource, the Noise static key, the relay endpoint, and
//! the expiry. The store stays a cache, not an authority: `put_minted`
//! mints + verifies + persists, and `list_active` re-verifies on read.

use household_rs::claw_share::{GuestCredential, SlotId};
use household_rs::keys::{IdentityKey, P256PublicKey};
use rand::RngCore;
use rand::rngs::OsRng;

use crate::claw_share_relay_stream_contract::{
    RelayStreamClawStaticPublicKey, RelayStreamContractError, RelayStreamExpectedPath,
    RelayStreamOfferContract, RelayStreamOfferMintInput, RelayStreamResource,
    ShareableAppPresentation, mint_relay_stream_group_offer, mint_relay_stream_public_offer,
};
use crate::claw_share_relay_stream_issuer_trust::RelayStreamIssuerTrust;
use crate::claw_share_relay_stream_offer_store::{
    RelayStreamOfferStore, RelayStreamOfferStoreError,
};
use crate::claw_share_rendezvous_stream_relay::{RendezvousToken, RendezvousTokenError};

/// Bytes of CSPRNG entropy per rendezvous token. Above the 16-byte minimum so
/// the token is unguessable; the relay treats it as an opaque routing key.
const RENDEZVOUS_TOKEN_BYTES: usize = 32;

/// Mint and store a `relay_stream` offer for `credential`.
///
/// Generates a fresh random rendezvous token (CSPRNG), assembles the mint input
/// with `expected_path = RelayStream`, and calls `store.put_minted` (which mints,
/// verifies against `trust`, and persists). Returns the minted offer.
///
/// `owner_key` MUST be the key that signed `credential` (the mint enforces
/// `owner_key.public() == credential.owner_p_pub`), and `not_after` MUST be
/// within the credential's lifetime (the mint enforces
/// `now < not_after <= credential.expires_at`). Both are checked by the mint,
/// not duplicated here.
#[allow(clippy::too_many_arguments)]
pub fn provision_relay_stream_offer(
    store: &mut RelayStreamOfferStore,
    credential: &GuestCredential,
    resource: RelayStreamResource,
    claw_static_pub: RelayStreamClawStaticPublicKey,
    relay_endpoint: String,
    not_after: u64,
    owner_key: &dyn IdentityKey,
    trust: &RelayStreamIssuerTrust,
    now: u64,
    app_presentation: Option<ShareableAppPresentation>,
) -> Result<RelayStreamOfferContract, RelayStreamProvisionError> {
    let mut token_bytes = [0u8; RENDEZVOUS_TOKEN_BYTES];
    OsRng.fill_bytes(&mut token_bytes);
    let rendezvous_token =
        RendezvousToken::try_new(token_bytes).map_err(RelayStreamProvisionError::Token)?;

    let input = RelayStreamOfferMintInput {
        rendezvous_token,
        credential,
        resource,
        expected_path: RelayStreamExpectedPath::RelayStream,
        relay_endpoint,
        claw_static_pub,
        not_after,
        now_unix: now,
        app_presentation,
    };

    let offer = store.put_minted(input, owner_key, trust)?;
    Ok(offer)
}

/// Fresh CSPRNG rendezvous token (the relay's opaque routing key).
fn fresh_rendezvous_token() -> Result<RendezvousToken, RelayStreamProvisionError> {
    let mut token_bytes = [0u8; RENDEZVOUS_TOKEN_BYTES];
    OsRng.fill_bytes(&mut token_bytes);
    RendezvousToken::try_new(token_bytes).map_err(RelayStreamProvisionError::Token)
}

/// Fresh random slot id used PURELY as the offer-store key for a Group/Public
/// offer (which has no real slot). Random ⇒ no collision in the store's
/// `(slot_id, resource)` keyspace, and never read on the Group/Public dial path.
fn fresh_store_slot_id() -> SlotId {
    let mut slot_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut slot_bytes);
    SlotId(slot_bytes)
}

/// Fase E2: mint + store a GROUP offer for one member device. The dial gate
/// authorizes it via LIVE group membership (not a slot); this just delivers it
/// to the store so the reverse-connect pool serves it. Fresh token + `slot_id`.
#[allow(clippy::too_many_arguments)]
pub fn provision_relay_stream_group_offer(
    store: &mut RelayStreamOfferStore,
    group_id: String,
    member_id: String,
    member_device_pub: P256PublicKey,
    claw_id: String,
    resource: RelayStreamResource,
    claw_static_pub: RelayStreamClawStaticPublicKey,
    relay_endpoint: String,
    not_after: u64,
    owner_key: &dyn IdentityKey,
    trust: &RelayStreamIssuerTrust,
    now: u64,
) -> Result<RelayStreamOfferContract, RelayStreamProvisionError> {
    let offer = mint_relay_stream_group_offer(
        fresh_rendezvous_token()?,
        fresh_store_slot_id(),
        group_id,
        member_id,
        member_device_pub,
        claw_id,
        resource,
        relay_endpoint,
        claw_static_pub,
        not_after,
        now,
        owner_key,
    )?;
    Ok(store.put_signed(offer, trust, now)?)
}

/// Fase E3: mint + store a PUBLIC offer for one dialer device. The dial gate
/// authorizes it via the LIVE `published_claws` flag (anyone may dial a published
/// claw); this just delivers it to the store. Fresh token + `slot_id`.
#[allow(clippy::too_many_arguments)]
pub fn provision_relay_stream_public_offer(
    store: &mut RelayStreamOfferStore,
    dialer_device_pub: P256PublicKey,
    claw_id: String,
    resource: RelayStreamResource,
    claw_static_pub: RelayStreamClawStaticPublicKey,
    relay_endpoint: String,
    not_after: u64,
    owner_key: &dyn IdentityKey,
    trust: &RelayStreamIssuerTrust,
    now: u64,
) -> Result<RelayStreamOfferContract, RelayStreamProvisionError> {
    let offer = mint_relay_stream_public_offer(
        fresh_rendezvous_token()?,
        fresh_store_slot_id(),
        dialer_device_pub,
        claw_id,
        resource,
        relay_endpoint,
        claw_static_pub,
        not_after,
        now,
        owner_key,
    )?;
    Ok(store.put_signed(offer, trust, now)?)
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamProvisionError {
    #[error("relay stream provision token invalid: {0}")]
    Token(#[source] RendezvousTokenError),

    #[error("relay stream provision contract error: {0}")]
    Contract(#[from] RelayStreamContractError),

    #[error("relay stream provision store error: {0}")]
    Store(#[from] RelayStreamOfferStoreError),
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::claw_share_relay_stream_contract::{RelayStreamAudience, RelayStreamContractError};
    use crate::claw_share_relay_stream_test_support::{
        attacker_signer, data_tunnel_credential, now_unix, owner_pub, owner_signer,
        relay_stream_issuer_trust,
    };
    use household_rs::keys::P256Keypair;

    const ENDPOINT: &str = "relay-stream://127.0.0.1:49152";

    fn static_pub() -> RelayStreamClawStaticPublicKey {
        RelayStreamClawStaticPublicKey::try_new([0x77; 32]).unwrap()
    }

    fn store(dir: &tempfile::TempDir) -> RelayStreamOfferStore {
        RelayStreamOfferStore::load(dir.path(), &relay_stream_issuer_trust(), now_unix()).unwrap()
    }

    fn share_app_id() -> String {
        format!("app_{:032x}", 0x5eed_u128)
    }

    /// A credential whose `claw_id` IS a valid Share app id. The offer's
    /// `claw_id` comes from the credential, and the presentation fence demands
    /// `presentation.app_id == claw_id`, so the credential is where the match
    /// has to be made — not by loosening the fence.
    fn app_credential(app_id: &str) -> GuestCredential {
        let owner = owner_signer();
        let issued_at = now_unix().saturating_sub(60);
        GuestCredential::sign(
            household_rs::ids::derive_household_id(&owner.public()),
            household_rs::person_cert::derive_person_id(&owner.public()),
            owner.public(),
            app_id.to_string(),
            crate::claw_share_relay_stream_test_support::guest_signer().public(),
            SlotId([0x22; 16]),
            issued_at,
            issued_at + 86_400,
            &owner,
        )
        .unwrap()
    }

    #[test]
    fn provision_passes_the_presentation_through_to_the_signed_offer() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(&dir);
        let app_id = share_app_id();
        let credential = app_credential(&app_id);
        let presentation =
            ShareableAppPresentation::try_new(app_id.clone(), "Study", "Caio").unwrap();
        let now = now_unix();

        let offer = provision_relay_stream_offer(
            &mut store,
            &credential,
            RelayStreamResource::ClawSite,
            static_pub(),
            ENDPOINT.to_string(),
            credential.expires_at,
            &owner_signer(),
            &relay_stream_issuer_trust(),
            now,
            Some(presentation.clone()),
        )
        .unwrap();

        // Survives the whole provision → mint → sign → store path.
        assert_eq!(offer.payload.app_presentation.as_ref(), Some(&presentation));
        assert_eq!(offer.payload.claw_id, app_id);
        // And the store re-verifies on read, so a snapshot that broke the fence
        // would not come back out.
        let active = store
            .list_active(&relay_stream_issuer_trust(), now)
            .unwrap();
        assert_eq!(
            active
                .iter()
                .filter_map(|o| o.payload.app_presentation.as_ref())
                .collect::<Vec<_>>(),
            vec![&presentation]
        );
    }

    #[test]
    fn provision_without_a_presentation_leaves_the_offer_snapshot_free() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(&dir);
        let credential = data_tunnel_credential();
        let now = now_unix();

        let offer = provision_relay_stream_offer(
            &mut store,
            &credential,
            RelayStreamResource::Pty,
            static_pub(),
            ENDPOINT.to_string(),
            credential.expires_at,
            &owner_signer(),
            &relay_stream_issuer_trust(),
            now,
            None,
        )
        .unwrap();

        assert!(offer.payload.app_presentation.is_none());
    }

    #[test]
    fn provision_stores_active_offer_verifiable_by_audience() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(&dir);
        let credential = data_tunnel_credential();
        let now = now_unix();

        let offer = provision_relay_stream_offer(
            &mut store,
            &credential,
            RelayStreamResource::Pty,
            static_pub(),
            ENDPOINT.to_string(),
            credential.expires_at,
            &owner_signer(),
            &relay_stream_issuer_trust(),
            now,
            None,
        )
        .unwrap();

        // Identity is credential-derived, not from new params.
        assert_eq!(offer.payload.slot_id, credential.slot_id);
        assert_eq!(offer.payload.claw_id, credential.claw_id);
        assert_eq!(offer.payload.guest_device_pub, credential.guest_device_pub);
        assert_eq!(offer.payload.resource, RelayStreamResource::Pty);

        // The pool would pick it up via list_active.
        let active = store
            .list_active(&relay_stream_issuer_trust(), now)
            .unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0], offer);

        // The guest can verify it for its audience.
        offer
            .verify_for_audience(&owner_pub(), &credential.guest_device_pub, now)
            .unwrap();
    }

    #[test]
    fn provision_uses_a_fresh_random_token_each_call() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(&dir);
        let credential = data_tunnel_credential();
        let now = now_unix();

        let first = provision_relay_stream_offer(
            &mut store,
            &credential,
            RelayStreamResource::Pty,
            static_pub(),
            ENDPOINT.to_string(),
            credential.expires_at,
            &owner_signer(),
            &relay_stream_issuer_trust(),
            now,
            None,
        )
        .unwrap();
        let second = provision_relay_stream_offer(
            &mut store,
            &credential,
            RelayStreamResource::ClawSite,
            static_pub(),
            ENDPOINT.to_string(),
            credential.expires_at,
            &owner_signer(),
            &relay_stream_issuer_trust(),
            now,
            None,
        )
        .unwrap();

        assert_ne!(
            first.payload.rendezvous_token,
            second.payload.rendezvous_token
        );
    }

    #[test]
    fn provision_group_offers_store_with_audience_and_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(&dir);
        let now = now_unix();
        let dev_a = P256Keypair::generate().public();
        let dev_b = P256Keypair::generate().public();

        let o1 = provision_relay_stream_group_offer(
            &mut store,
            "g".to_string(),
            "g_a".to_string(),
            dev_a,
            "claw_alpha".to_string(),
            RelayStreamResource::ClawSite,
            static_pub(),
            ENDPOINT.to_string(),
            now + 60,
            &owner_signer(),
            &relay_stream_issuer_trust(),
            now,
        )
        .unwrap();
        let o2 = provision_relay_stream_group_offer(
            &mut store,
            "g".to_string(),
            "g_b".to_string(),
            dev_b,
            "claw_alpha".to_string(),
            RelayStreamResource::ClawSite,
            static_pub(),
            ENDPOINT.to_string(),
            now + 60,
            &owner_signer(),
            &relay_stream_issuer_trust(),
            now,
        )
        .unwrap();

        assert_eq!(
            o1.payload.audience(),
            RelayStreamAudience::Group {
                group_id: "g".to_string(),
                member_id: "g_a".to_string(),
            }
        );
        // Distinct random slot ids → both stored, no overwrite (the collision the
        // E2.5 map flagged for a shared sentinel).
        assert_ne!(o1.payload.slot_id, o2.payload.slot_id);
        let active = store
            .list_active(&relay_stream_issuer_trust(), now)
            .unwrap();
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn provision_public_offer_stores_with_public_audience() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(&dir);
        let now = now_unix();
        let dialer = P256Keypair::generate().public();

        let offer = provision_relay_stream_public_offer(
            &mut store,
            dialer,
            "claw_alpha".to_string(),
            RelayStreamResource::ClawSite,
            static_pub(),
            ENDPOINT.to_string(),
            now + 60,
            &owner_signer(),
            &relay_stream_issuer_trust(),
            now,
        )
        .unwrap();

        assert_eq!(offer.payload.audience(), RelayStreamAudience::Public);
        assert_eq!(
            store
                .list_active(&relay_stream_issuer_trust(), now)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn provision_rejects_not_after_beyond_credential_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(&dir);
        let credential = data_tunnel_credential();
        let now = now_unix();

        let error = provision_relay_stream_offer(
            &mut store,
            &credential,
            RelayStreamResource::Pty,
            static_pub(),
            ENDPOINT.to_string(),
            credential.expires_at + 1,
            &owner_signer(),
            &relay_stream_issuer_trust(),
            now,
            None,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            RelayStreamProvisionError::Store(RelayStreamOfferStoreError::Contract(_))
        ));
    }

    #[test]
    fn provision_rejects_owner_key_not_matching_credential() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(&dir);
        let credential = data_tunnel_credential();
        let now = now_unix();

        // attacker_signer() is not the credential's owner key.
        let error = provision_relay_stream_offer(
            &mut store,
            &credential,
            RelayStreamResource::Pty,
            static_pub(),
            ENDPOINT.to_string(),
            credential.expires_at,
            &attacker_signer(),
            &relay_stream_issuer_trust(),
            now,
            None,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            RelayStreamProvisionError::Store(RelayStreamOfferStoreError::Contract(
                RelayStreamContractError::MintOwnerMismatch
            ))
        ));
        // Nothing was persisted on the rejected path.
        assert!(store.is_empty());
    }

    #[test]
    fn provision_error_debug_does_not_leak_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(&dir);
        let credential = data_tunnel_credential();
        let now = now_unix();

        let error = provision_relay_stream_offer(
            &mut store,
            &credential,
            RelayStreamResource::Pty,
            static_pub(),
            ENDPOINT.to_string(),
            credential.expires_at + 1,
            &owner_signer(),
            &relay_stream_issuer_trust(),
            now,
            None,
        )
        .unwrap_err();

        // The secret is the rendezvous token BYTES; the errors carry only error
        // shape (lengths, variant names), never key/token material.
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("private"));
        assert!(!rendered.contains("secret"));
    }
}
