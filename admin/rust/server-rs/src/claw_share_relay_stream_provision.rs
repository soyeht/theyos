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
mod tests;
