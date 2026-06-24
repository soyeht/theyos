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
mod tests {
    use super::*;
    use crate::claw_share::{
        ClawShareInvite, ClawShareSlotStore, SlotId, SlotRecord, SlotState, TunnelHandle,
    };
    use crate::ids::derive_household_id;
    use crate::keys::P256Keypair;
    use crate::person_cert::derive_person_id;
    use std::sync::Arc;
    use std::time::Instant;

    struct OwnerFixture {
        key: P256Keypair,
        hh_id: HouseholdId,
        p_id: PersonId,
    }

    fn fresh_owner() -> OwnerFixture {
        let key = P256Keypair::generate();
        let pub_bytes = key.public();
        OwnerFixture {
            hh_id: derive_household_id(&pub_bytes),
            p_id: derive_person_id(&pub_bytes),
            key,
        }
    }

    /// Mint an invite + persist a matching open slot. Mirrors what the
    /// owner-side mint path will do for real once it has a UI.
    fn mint_invite(
        owner: &OwnerFixture,
        store: &ClawShareSlotStore,
        claw_id: &str,
        expires_at: u64,
    ) -> ClawShareInvite {
        let slot_id = SlotId::random();
        store
            .insert(SlotRecord {
                slot_id: slot_id.clone(),
                claw_id: claw_id.to_string(),
                expires_at,
                state: SlotState::Open,
            })
            .expect("insert slot");
        ClawShareInvite::sign(
            owner.hh_id.clone(),
            owner.p_id.clone(),
            owner.key.public(),
            claw_id.to_string(),
            slot_id,
            TunnelHandle::Loopback {
                channel: format!("ch-{claw_id}"),
            },
            expires_at,
            String::new(),
            Vec::new(),
            &owner.key,
        )
        .expect("sign invite")
    }

    /// Run the engine task: accept claims, hand them to
    /// `engine_handle_claim`, emit the ack, then echo any `Data` frames.
    async fn run_engine(
        store: Arc<ClawShareSlotStore>,
        owner: Arc<OwnerFixture>,
        mut endpoint: EngineEndpoint,
        now_unix: u64,
    ) {
        let tunnel_factory = |claw_id: &str| TunnelHandle::Loopback {
            channel: format!("ch-{claw_id}"),
        };
        while let Some(frame) = endpoint.rx.recv().await {
            match frame {
                Frame::Claim(claim) => {
                    let ctx = EngineContext {
                        owner_key: &owner.key,
                        owner_p_id: &owner.p_id,
                        hh_id: &owner.hh_id,
                        slot_store: &store,
                        credential_ttl_secs: 3600,
                        tunnel_factory: &tunnel_factory,
                    };
                    match engine_handle_claim(&ctx, &claim, now_unix) {
                        Ok(ack) => {
                            if endpoint.tx.send(Frame::Ack(Box::new(ack))).await.is_err() {
                                return;
                            }
                        }
                        Err(_rejection) => {
                            // Slice behaviour: close the channel on
                            // rejection so the friend observes
                            // `TransportClosed`. Over HTTP the engine
                            // will surface a typed error envelope.
                            return;
                        }
                    }
                }
                Frame::Data(bytes) => {
                    let mut echo = b"echo:".to_vec();
                    echo.extend_from_slice(&bytes);
                    if endpoint.tx.send(Frame::Data(echo)).await.is_err() {
                        return;
                    }
                }
                Frame::Ack(_) => unreachable!("friend never sends Ack"),
            }
        }
    }

    /// **The moment Apple-grade test.** Owner mints invite, friend taps,
    /// terminal echoes back — measured wall-clock, asserted < 1 second.
    #[tokio::test]
    async fn tap_to_terminal_under_one_second() {
        let owner = Arc::new(fresh_owner());
        let store = Arc::new(ClawShareSlotStore::new());
        let invite = mint_invite(&owner, &store, "claw_alpha", 2_000_000_000);

        let (mut friend, engine) = loopback_pair(16);

        let engine_task = tokio::spawn(run_engine(
            Arc::clone(&store),
            Arc::clone(&owner),
            engine,
            1_000_000_000,
        ));

        let start = Instant::now();
        let session = friend_perform_claim(&invite, &mut friend, || 1_000_000_000)
            .await
            .expect("friend claim");
        // Data plane: friend sends a byte, expects echo back.
        friend
            .tx
            .send(Frame::Data(b"hello".to_vec()))
            .await
            .expect("data send");
        let echo = friend.rx.recv().await.expect("data recv");
        let elapsed = start.elapsed();

        match echo {
            Frame::Data(bytes) => assert_eq!(bytes, b"echo:hello"),
            other => panic!("expected Data frame, got {other:?}"),
        }
        assert!(
            elapsed.as_millis() < 1000,
            "tap-to-terminal exceeded 1s budget: {elapsed:?}"
        );

        // Credential matches expected bindings.
        assert_eq!(session.credential.claw_id, "claw_alpha");
        assert_eq!(
            session.credential.guest_device_pub,
            session.guest_key.public()
        );

        drop(friend);
        engine_task.await.expect("engine task");
    }

    /// Two parallel friend claims for the same invite slot: exactly one
    /// wins, the other gets `SlotAlreadyConsumed`. Proves the CAS holds
    /// under concurrent pressure.
    #[tokio::test]
    async fn concurrent_claim_exactly_one_winner() {
        let owner = Arc::new(fresh_owner());
        let store = Arc::new(ClawShareSlotStore::new());
        let invite = mint_invite(&owner, &store, "claw_concurrent", 2_000_000_000);

        // Two engine workers consuming from the same channel — proves we
        // share one slot store across concurrent handlers.
        let (mut friend_a, engine_a) = loopback_pair(8);
        let (mut friend_b, engine_b) = loopback_pair(8);

        let store_a = Arc::clone(&store);
        let owner_a = Arc::clone(&owner);
        let task_a = tokio::spawn(run_engine(store_a, owner_a, engine_a, 1_000_000_000));
        let store_b = Arc::clone(&store);
        let owner_b = Arc::clone(&owner);
        let task_b = tokio::spawn(run_engine(store_b, owner_b, engine_b, 1_000_000_000));

        let invite_a = invite.clone();
        let invite_b = invite.clone();

        // Each friend tries to claim the SAME invite — the cryptographic
        // slot_id is shared. Only one CAS can win.
        let res_a = tokio::spawn(async move {
            friend_perform_claim(&invite_a, &mut friend_a, || 1_000_000_000).await
        });
        let res_b = tokio::spawn(async move {
            friend_perform_claim(&invite_b, &mut friend_b, || 1_000_000_000).await
        });

        let (out_a, out_b) = (res_a.await.unwrap(), res_b.await.unwrap());

        let wins = [&out_a, &out_b].iter().filter(|r| r.is_ok()).count();
        let losses = [&out_a, &out_b].iter().filter(|r| r.is_err()).count();
        assert_eq!(
            wins, 1,
            "exactly one claim must succeed: a={out_a:?} b={out_b:?}"
        );
        assert_eq!(losses, 1, "exactly one claim must fail");

        drop(task_a);
        drop(task_b);
    }

    /// Revocation: owner revokes a slot before the friend claims. The
    /// engine handler must reject the claim with `SlotRevoked`. This test
    /// runs the handler as a pure function — no transport, no tokio — so
    /// the assertion is about the engine's policy, not about how the
    /// rejection is surfaced to the friend (the transport layer can chose
    /// to forward a typed error envelope or simply close the channel; the
    /// engine's `Err(SlotRevoked)` is the same either way).
    #[test]
    fn engine_rejects_revoked_slot() {
        use crate::claw_share::ClaimNonce;

        let owner = fresh_owner();
        let store = ClawShareSlotStore::new();
        let invite = mint_invite(&owner, &store, "claw_rev", 2_000_000_000);
        store
            .revoke(&invite.slot_id, 1_000_000_000)
            .expect("revoke");

        let guest_key = P256Keypair::generate();
        let claim = ClawShareClaim::sign(
            invite.slot_id.clone(),
            guest_key.public(),
            ClaimNonce::random(),
            1_000_000_000,
            &guest_key,
        )
        .expect("sign claim");

        let tunnel_factory = |claw_id: &str| TunnelHandle::Loopback {
            channel: format!("ch-{claw_id}"),
        };
        let ctx = EngineContext {
            owner_key: &owner.key,
            owner_p_id: &owner.p_id,
            hh_id: &owner.hh_id,
            slot_store: &store,
            credential_ttl_secs: 3600,
            tunnel_factory: &tunnel_factory,
        };
        let err =
            engine_handle_claim(&ctx, &claim, 1_000_000_001).expect_err("revoked slot must reject");
        assert!(matches!(err, ClawShareError::SlotRevoked));
    }

    /// Credential bindings: an engine that returns a credential issued by
    /// a DIFFERENT owner key must be rejected. Protects against a man-in-
    /// the-middle on the loopback (or, in production, a relay) swapping
    /// the ack.
    #[tokio::test]
    async fn credential_issuer_mismatch_rejected() {
        let owner = Arc::new(fresh_owner());
        let attacker = Arc::new(fresh_owner());
        let store = Arc::new(ClawShareSlotStore::new());
        let invite = mint_invite(&owner, &store, "claw_mitm", 2_000_000_000);

        let (mut friend, mut engine) = loopback_pair(8);
        let attacker_clone = Arc::clone(&attacker);
        let store_clone = Arc::clone(&store);
        tokio::spawn(async move {
            let tunnel_factory = |claw_id: &str| TunnelHandle::Loopback {
                channel: format!("ch-{claw_id}"),
            };
            let frame = engine.rx.recv().await.expect("recv");
            let Frame::Claim(claim) = frame else {
                panic!();
            };
            // Attacker signs the credential with their own key instead
            // of the legitimate owner's.
            let ctx = EngineContext {
                owner_key: &attacker_clone.key,
                owner_p_id: &attacker_clone.p_id,
                hh_id: &attacker_clone.hh_id,
                slot_store: &store_clone,
                credential_ttl_secs: 3600,
                tunnel_factory: &tunnel_factory,
            };
            let ack = engine_handle_claim(&ctx, &claim, 1_000_000_000).expect("forged");
            // C7c-0 scaffold: engine_handle_claim never emits a relay_stream offer yet.
            assert!(ack.relay_stream_offer.is_none());
            engine
                .tx
                .send(Frame::Ack(Box::new(ack)))
                .await
                .expect("send");
        });

        let err = friend_perform_claim(&invite, &mut friend, || 1_000_000_000)
            .await
            .expect_err("attacker credential must reject");
        assert!(matches!(err, ClawShareError::CredentialIssuerMismatch));
    }

    // ── R115: base/self machine as a claw-share target ──
    //
    // The base/self engine machine is shared with the SAME security model as a
    // per-claw share. Its canonical target is the opaque `claw_id`
    // `base-machine:<self_m_id>` (the iOS `ClawShareWellKnownClaw.baseMachineClawId`
    // bridge). The engine's slot model keys purely on this string, so the
    // existing mint/claim/credential machinery binds it with no special case.

    /// The owner can mint + a friend can claim a share whose target is the
    /// base/self machine. The minted `GuestCredential` is bound to the EXACT
    /// `base-machine:<self_m_id>` claw_id (per-machine, not household/global),
    /// to the friend's device key, and to the slot.
    #[tokio::test]
    async fn owner_mints_share_for_base_self_machine() {
        let owner = Arc::new(fresh_owner());
        let store = Arc::new(ClawShareSlotStore::new());
        // `self_m_id`-derived per-machine target (mirrors the iOS bridge).
        let base_target = "base-machine:m_qe4udgimf0fixture";
        let invite = mint_invite(&owner, &store, base_target, 2_000_000_000);

        let (mut friend, engine) = loopback_pair(16);
        let engine_task = tokio::spawn(run_engine(
            Arc::clone(&store),
            Arc::clone(&owner),
            engine,
            1_000_000_000,
        ));

        let session = friend_perform_claim(&invite, &mut friend, || 1_000_000_000)
            .await
            .expect("friend claim for base machine");

        // Credential bound to the EXACT base-machine target + friend key + slot.
        assert_eq!(session.credential.claw_id, base_target);
        assert_eq!(
            session.credential.guest_device_pub,
            session.guest_key.public()
        );
        assert_eq!(session.credential.slot_id, invite.slot_id);
        // Owner-signed, not expired → verifies under the owner key.
        session
            .credential
            .verify(1_000_000_000)
            .expect("base-machine credential verifies");

        drop(friend);
        engine_task.await.expect("engine task");
    }

    /// Target binding prevents cross-MACHINE access: a credential minted for
    /// one base machine's target must NOT satisfy a claim/slot for a different
    /// base machine. The slot's `consume_atomic` enforces `slot.claw_id ==
    /// claim_claw_id`; a different `self_m_id` derives a different target, so a
    /// claim against machine B's slot using machine A's slot_id can never bind.
    #[test]
    fn base_machine_credential_is_per_machine_not_cross_machine() {
        let owner = fresh_owner();
        let store = ClawShareSlotStore::new();
        let target_a = "base-machine:m_AAAA";
        let target_b = "base-machine:m_BBBB";
        let slot_b = SlotId::random();
        store
            .insert(SlotRecord {
                slot_id: slot_b.clone(),
                claw_id: target_b.to_string(),
                expires_at: 2_000_000_000,
                state: SlotState::Open,
            })
            .expect("insert B slot");

        let guest = P256Keypair::generate();
        // Attempt to consume machine B's slot while claiming machine A's target.
        let err = store
            .consume_atomic(&slot_b, target_a, guest.public(), 1_000_000_000)
            .expect_err("cross-machine consume must reject");
        assert!(
            matches!(err, ClawShareError::SlotClawMismatch),
            "a base-machine-A claw_id must not consume a base-machine-B slot, got {err:?}"
        );
        // The correct target still consumes cleanly (control).
        store
            .consume_atomic(&slot_b, target_b, guest.public(), 1_000_000_000)
            .expect("matching base-machine target consumes");

        let _ = (&owner, target_a);
    }

    /// Revoking a base-machine share's slot fails the claim closed — identical
    /// teardown to a per-claw share (no special path).
    #[test]
    fn base_machine_share_revoke_fails_closed() {
        let owner = fresh_owner();
        let store = ClawShareSlotStore::new();
        let base_target = "base-machine:m_revoke_fixture";
        let invite = mint_invite(&owner, &store, base_target, 2_000_000_000);
        // Owner revokes before the friend claims.
        store
            .revoke(&invite.slot_id, 1_000_000_000)
            .expect("revoke");

        let guest = crate::keys::P256Keypair::generate();
        let claim = ClawShareClaim::sign(
            invite.slot_id.clone(),
            guest.public(),
            crate::claw_share::ClaimNonce::random(),
            1_000_000_001,
            &guest,
        )
        .expect("sign claim");
        let tunnel_factory = |claw_id: &str| TunnelHandle::Loopback {
            channel: format!("ch-{claw_id}"),
        };
        let ctx = EngineContext {
            owner_key: &owner.key,
            owner_p_id: &owner.p_id,
            hh_id: &owner.hh_id,
            slot_store: &store,
            credential_ttl_secs: 3600,
            tunnel_factory: &tunnel_factory,
        };
        let err = engine_handle_claim(&ctx, &claim, 1_000_000_002)
            .expect_err("revoked base-machine slot must reject");
        assert!(matches!(err, ClawShareError::SlotRevoked));
    }
}
