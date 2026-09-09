//! Claw-share orchestration — transport boundary + the engine-side
//! claim handler and friend-side claim performer that ride it.
//!
//! The wire envelopes live in [`crate::claw_share`]. This module is the
//! imperative layer that connects them across a transport channel. For
//! the slice the only transport is an in-process `LoopbackTransport`;
//! a second relay-backed transport impl can take its place without
//! touching `engine_handle_claim` / `friend_perform_claim`.

use tokio::sync::mpsc;

use crate::claw_share::{
    ClaimNonce, ClawShareAck, ClawShareClaim, ClawShareError, ClawShareInvite, ClawShareSlotStore,
    GuestCredential, MAX_CREDENTIAL_TTL_SECS, TunnelHandle,
};
use crate::ids::HouseholdId;
use crate::keys::{IdentityKey, P256Keypair};
use crate::machine_cert::PersonId;

// ─── Transport ───────────────────────────────────────────────────────────────

/// Frames carried over the slice's loopback channel. The variants double
/// as the data plane: once a claim is acknowledged, both sides switch to
/// emitting `Data` frames over the same channel pair.
#[derive(Debug)]
pub enum Frame {
    Claim(Box<ClawShareClaim>),
    Ack(Box<ClawShareAck>),
    Data(Vec<u8>),
}

/// Friend-side endpoint: `tx` sends frames to the engine; `rx` receives
/// frames from the engine.
pub struct FriendEndpoint {
    pub tx: mpsc::Sender<Frame>,
    pub rx: mpsc::Receiver<Frame>,
}

/// Engine-side endpoint: `tx` sends frames to the friend; `rx` receives
/// frames from the friend.
pub struct EngineEndpoint {
    pub tx: mpsc::Sender<Frame>,
    pub rx: mpsc::Receiver<Frame>,
}

/// Build a connected friend/engine pair. Channels are bounded so that a
/// runaway producer cannot push the test into unbounded memory growth.
#[must_use]
pub fn loopback_pair(capacity: usize) -> (FriendEndpoint, EngineEndpoint) {
    let (friend_tx, engine_rx) = mpsc::channel(capacity);
    let (engine_tx, friend_rx) = mpsc::channel(capacity);
    (
        FriendEndpoint {
            tx: friend_tx,
            rx: friend_rx,
        },
        EngineEndpoint {
            tx: engine_tx,
            rx: engine_rx,
        },
    )
}

// ─── Engine handler ──────────────────────────────────────────────────────────

/// Engine-side parameters that don't change per claim. Held by the engine
/// task between claims. `owner_key` is type-erased so the HTTP wrapper can
/// pass the `Box<dyn IdentityKey>` it owns via `LoadedIdentity.m_priv`
/// without unboxing.
pub struct EngineContext<'a> {
    pub owner_key: &'a dyn IdentityKey,
    pub owner_p_id: &'a PersonId,
    pub hh_id: &'a HouseholdId,
    pub slot_store: &'a ClawShareSlotStore,
    pub credential_ttl_secs: u64,
    pub tunnel_factory: &'a (dyn Fn(&str) -> TunnelHandle + Send + Sync),
}

/// Pure function: take a verified claim, consume the matching slot, mint
/// a `GuestCredential`, return the `ClawShareAck` the engine will send
/// back over the transport.
///
/// **Does NOT touch the transport.** That separation is what makes the
/// handler testable without any channel plumbing — the e2e tests in this
/// module wrap it with a transport loop; the future HTTP handler in
/// `server-rs` wraps it with axum. Both wrappers call the same function.
pub fn engine_handle_claim(
    ctx: &EngineContext<'_>,
    claim: &ClawShareClaim,
    now_unix: u64,
) -> Result<ClawShareAck, ClawShareError> {
    // 1. Claim signature + freshness.
    claim.verify(now_unix)?;

    // 2. Look up the slot to learn the claw_id we're consuming. The
    //    snapshot read is cheap and the CAS that follows resolves any
    //    race against revoke / parallel consume correctly.
    let slot_snapshot = ctx
        .slot_store
        .get(&claim.slot_id)
        .ok_or(ClawShareError::SlotNotFound)?;

    // 3. Atomic CAS: state Open → Consumed.
    let consumed = ctx.slot_store.consume_atomic(
        &claim.slot_id,
        &slot_snapshot.claw_id,
        claim.guest_device_pub.clone(),
        now_unix,
    )?;

    // 4. Cap the credential lifetime to whichever is shorter:
    //    - configured `credential_ttl_secs`
    //    - remaining lifetime of the invite (slot's expires_at)
    //    - the global cap.
    let configured_lifetime = ctx.credential_ttl_secs.min(MAX_CREDENTIAL_TTL_SECS);
    let by_configured = now_unix.saturating_add(configured_lifetime);
    let by_invite = consumed.expires_at;
    let credential_expires_at = by_configured.min(by_invite);
    if credential_expires_at <= now_unix {
        return Err(ClawShareError::CredentialExpiryInvalid);
    }

    // 5. Mint the credential.
    let credential = GuestCredential::sign(
        ctx.hh_id.clone(),
        ctx.owner_p_id.clone(),
        ctx.owner_key.public(),
        consumed.claw_id.clone(),
        claim.guest_device_pub.clone(),
        claim.slot_id.clone(),
        now_unix,
        credential_expires_at,
        ctx.owner_key,
    )?;

    let tunnel = (ctx.tunnel_factory)(&consumed.claw_id);

    Ok(ClawShareAck {
        v: 1,
        credential,
        tunnel,
        // C7c-1 will deliver the relay_stream offer on the confidential relay
        // path only; for now it is always absent.
        relay_stream_offer: None,
    })
}

// ─── Mesh transport seam ─────────────────────────────────────────────────────

/// Frame channel between two peers. Implemented by [`FriendEndpoint`] and
/// [`EngineEndpoint`] for the in-process loopback.
///
/// `async fn` in trait → 1.75+ stable. Not `dyn`-compatible — impls
/// participate as concrete generic parameters. Slice scope uses concrete
/// types throughout. The `async_fn_in_trait` lint is allowed because we
/// don't want callers to constrain auto-traits on the returned future
/// beyond what the impl naturally provides.
#[allow(async_fn_in_trait)]
pub trait MeshChannel: Send {
    async fn send_frame(&mut self, frame: Frame) -> Result<(), ClawShareError>;
    async fn recv_frame(&mut self) -> Option<Frame>;
}

impl MeshChannel for FriendEndpoint {
    async fn send_frame(&mut self, frame: Frame) -> Result<(), ClawShareError> {
        self.tx
            .send(frame)
            .await
            .map_err(|_| ClawShareError::TransportClosed)
    }

    async fn recv_frame(&mut self) -> Option<Frame> {
        self.rx.recv().await
    }
}

impl MeshChannel for EngineEndpoint {
    async fn send_frame(&mut self, frame: Frame) -> Result<(), ClawShareError> {
        self.tx
            .send(frame)
            .await
            .map_err(|_| ClawShareError::TransportClosed)
    }

    async fn recv_frame(&mut self) -> Option<Frame> {
        self.rx.recv().await
    }
}

// ─── Friend-side ─────────────────────────────────────────────────────────────

/// Result of the friend-side claim. `credential` is what the friend stores
/// for subsequent reconnects; `tunnel` is what the friend dials right now.
pub struct ClaimedSession {
    pub credential: GuestCredential,
    pub tunnel: TunnelHandle,
    pub guest_key: P256Keypair,
}

impl std::fmt::Debug for ClaimedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Elide the keypair — the secret scalar is sensitive even in test logs.
        f.debug_struct("ClaimedSession")
            .field("credential.claw_id", &self.credential.claw_id)
            .field("credential.expires_at", &self.credential.expires_at)
            .field("tunnel", &self.tunnel)
            .finish_non_exhaustive()
    }
}

/// Friend-side claim performance: build + sign the claim from a freshly
/// minted guest device key, push it over the transport, wait for the ack,
/// verify the credential bindings.
///
/// `now_unix_fn` lets tests pin the wall clock; production wires the system
/// clock through it.
pub async fn friend_perform_claim<F>(
    invite: &ClawShareInvite,
    endpoint: &mut FriendEndpoint,
    now_unix_fn: F,
) -> Result<ClaimedSession, ClawShareError>
where
    F: Fn() -> u64,
{
    let now = now_unix_fn();
    invite.verify(now)?;

    // Fresh per-share device keypair. No reuse across shares, no link
    // to Apple-ID, email, phone, or any other long-lived identity.
    let guest_key = P256Keypair::generate();
    let claim = ClawShareClaim::sign(
        invite.slot_id.clone(),
        guest_key.public(),
        ClaimNonce::random(),
        now,
        &guest_key,
    )?;

    endpoint
        .tx
        .send(Frame::Claim(Box::new(claim)))
        .await
        .map_err(|_| ClawShareError::TransportClosed)?;

    let frame = endpoint
        .rx
        .recv()
        .await
        .ok_or(ClawShareError::TransportClosed)?;
    let ack = match frame {
        Frame::Ack(ack) => *ack,
        Frame::Claim(_) | Frame::Data(_) => return Err(ClawShareError::UnexpectedFrame),
    };

    // Verify the credential the engine returned: signature under
    // invite.owner_p_pub, binding to the same claw_id and our guest key.
    let now_post = now_unix_fn();
    ack.credential.verify(now_post)?;
    if ack.credential.owner_p_pub != invite.owner_p_pub {
        return Err(ClawShareError::CredentialIssuerMismatch);
    }
    if ack.credential.claw_id != invite.claw_id {
        return Err(ClawShareError::CredentialClawMismatch);
    }
    if ack.credential.guest_device_pub != guest_key.public() {
        return Err(ClawShareError::CredentialGuestMismatch);
    }
    if ack.credential.slot_id != invite.slot_id {
        return Err(ClawShareError::CredentialSlotMismatch);
    }

    Ok(ClaimedSession {
        credential: ack.credential,
        tunnel: ack.tunnel,
        guest_key,
    })
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
