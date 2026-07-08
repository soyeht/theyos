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

use household_rs::claw_share_data_tunnel::{
    AuthEnvelope, DataTunnelError, DataTunnelSession, ReplayGuard, credential_hash,
};

use crate::claw_share_relay_stream_contract::{
    RelayStreamAudience, RelayStreamOfferContract, check_relay_stream_group_membership,
    check_relay_stream_public,
};
use crate::claw_share_relay_stream_issuer_trust::RelayStreamIssuerTrust;

/// A credential-less authorized session for a Group/Public dial. Carries ONLY
/// local correlation values for the [`TunnelAck`] — it is NOT a credential and
/// NOT a routing/roster/deny-list key. `session_id`/`mesh_ipv6` derive from the
/// FULL BLAKE3 of the connection's verified offer (non-truncated, panel #7), so
/// they are stable per-offer but NOT slot-stable across reconnects (each offer is
/// its own session). The panel's choice A: no synthetic [`GuestCredential`].
///
/// [`TunnelAck`]: household_rs::claw_share_data_tunnel::TunnelAck
/// [`GuestCredential`]: household_rs::claw_share::GuestCredential
pub struct RelayStreamOfferSession {
    session_id: String,
    mesh_ipv6: String,
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
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use household_rs::claw_share::SlotId;
    use household_rs::claw_share_data_tunnel::{
        SessionAuthToken, TcpStreamRouter, TunnelAck, client_authenticate, client_open_stream,
        recv_frame, serve_connection_io_with_auth_deadline,
    };
    use household_rs::household_mesh_log::{
        DirectoryDeviceStatus, MeshMembership, ProjectedDirectoryDevice, ProjectedGroup,
        ProjectedMemberDevice, ProjectedState,
    };
    use household_rs::keys::P256Keypair;
    use tokio::io::duplex;

    use crate::claw_share_relay_stream_contract::{
        RelayStreamClawStaticPublicKey, RelayStreamResource, mint_relay_stream_group_offer,
        mint_relay_stream_public_offer,
    };
    use crate::claw_share_relay_stream_issuer_trust::RelayStreamTrustContext;
    use crate::claw_share_relay_stream_test_support::{
        RELAY_STREAM_CLAW_ID, RELAY_STREAM_ENDPOINT, attacker_signer, guest_pub, guest_signer,
        now_unix, owner_pub, owner_signer, relay_stream_household_record,
        relay_stream_machine_cert, rendezvous_token, spawn_ack_target,
    };

    fn static_pub() -> RelayStreamClawStaticPublicKey {
        RelayStreamClawStaticPublicKey::try_new([0x77; 32]).unwrap()
    }

    // Group offer for member g_a's device guest_pub(), signed by the authorized
    // machine issuer owner_signer().
    fn group_offer(not_after: u64) -> RelayStreamOfferContract {
        mint_relay_stream_group_offer(
            rendezvous_token(0x42),
            SlotId([0x99; 16]),
            "g".to_string(),
            "g_a".to_string(),
            guest_pub(),
            RELAY_STREAM_CLAW_ID.to_string(),
            RelayStreamResource::Pty,
            RELAY_STREAM_ENDPOINT.to_string(),
            static_pub(),
            not_after,
            now_unix(),
            &owner_signer(),
        )
        .unwrap()
    }

    fn public_offer(not_after: u64) -> RelayStreamOfferContract {
        mint_relay_stream_public_offer(
            rendezvous_token(0x43),
            SlotId([0x98; 16]),
            guest_pub(),
            RELAY_STREAM_CLAW_ID.to_string(),
            RelayStreamResource::Pty,
            RELAY_STREAM_ENDPOINT.to_string(),
            static_pub(),
            not_after,
            now_unix(),
            &owner_signer(),
        )
        .unwrap()
    }

    fn group_projection(
        member_active: bool,
        claw_granted: bool,
        device_active: bool,
    ) -> ProjectedState {
        let st = |on: bool| {
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
                members: [("g_a".to_string(), st(member_active))]
                    .into_iter()
                    .collect(),
                member_labels: Default::default(),
                granted_claws: [(RELAY_STREAM_CLAW_ID.to_string(), st(claw_granted))]
                    .into_iter()
                    .collect(),
                revision: 1,
            },
        );
        p.member_devices.insert(
            "g_a".to_string(),
            [(
                guest_pub().as_bytes()[..].to_vec(),
                ProjectedMemberDevice {
                    participant_npub: "npub".to_string(),
                    status: st(device_active),
                },
            )]
            .into_iter()
            .collect(),
        );
        p
    }

    fn published_projection(active: bool) -> ProjectedState {
        let mut p = ProjectedState::default();
        p.published_claws.insert(
            RELAY_STREAM_CLAW_ID.to_string(),
            if active {
                MeshMembership::Active
            } else {
                MeshMembership::Removed
            },
        );
        p
    }

    fn trust_with(projection: ProjectedState) -> RelayStreamIssuerTrust {
        RelayStreamIssuerTrust::new(move || RelayStreamTrustContext {
            record: relay_stream_household_record(),
            cert: relay_stream_machine_cert(),
            projection: projection.clone(),
        })
    }

    fn offer_token(
        offer: &RelayStreamOfferContract,
        signer: &P256Keypair,
        target_id: &str,
        nonce: &[u8],
        expires_at: u64,
    ) -> SessionAuthToken {
        let offer_bytes = offer.payload.to_canonical_bytes().unwrap();
        SessionAuthToken::sign(
            "relay-stream-session".to_string(),
            &offer_bytes,
            RELAY_STREAM_ENDPOINT.to_string(),
            target_id.to_string(),
            nonce.to_vec(),
            expires_at,
            signer,
        )
        .unwrap()
    }

    fn envelope(offer: &RelayStreamOfferContract, token: SessionAuthToken) -> AuthEnvelope {
        AuthEnvelope {
            credential_cbor: offer.payload.to_canonical_bytes().unwrap(),
            token,
        }
    }

    #[test]
    fn offer_session_id_is_full_hash_non_truncated_and_per_offer() {
        let now = now_unix();
        let offer = group_offer(now + 60);
        let s1 = RelayStreamOfferSession::from_offer(&offer).unwrap();
        let s2 = RelayStreamOfferSession::from_offer(&offer).unwrap();
        // hex of the 32-byte BLAKE3 = 64 chars, deterministic per offer.
        assert_eq!(s1.session_id().len(), 64);
        assert_eq!(s1.session_id(), s2.session_id());
        // Non-truncated mesh_ipv6: 4 hextet groups after `::` (8 hash bytes) vs the
        // Device path's 2 groups — 6 colons total.
        assert!(s1.mesh_ipv6().starts_with("fd00:c1a0::"));
        assert_eq!(s1.mesh_ipv6().matches(':').count(), 6);
        // Regression guard: the mesh placeholder MUST parse as a real IPv6 address.
        // The T1 IpTunnel guest rejects a malformed session-ack mesh address, so an
        // invalid-hex placeholder (e.g. the earlier `c1aw`) would break the datapath.
        s1.mesh_ipv6()
            .parse::<std::net::Ipv6Addr>()
            .expect("mesh_ipv6 placeholder must be a valid IPv6 address");
        // Different offer → different session id.
        let other = RelayStreamOfferSession::from_offer(&public_offer(now + 60)).unwrap();
        assert_ne!(s1.session_id(), other.session_id());
    }

    #[test]
    fn verify_accepts_valid_pop_and_rejects_attacks() {
        let now = now_unix();
        let offer = group_offer(now + 60);

        // Valid: PoP under the offer-pinned device key, bound to blake3(offer) + claw.
        let ok = envelope(
            &offer,
            offer_token(
                &offer,
                &guest_signer(),
                RELAY_STREAM_CLAW_ID,
                b"n1",
                now + 60,
            ),
        );
        let sess =
            verify_relay_stream_offer_session(&offer, &ReplayGuard::new(), &ok, now).unwrap();
        assert_eq!(sess.session_id().len(), 64);

        // Wrong device: token signed by a stranger → rejected.
        let wrong_dev = envelope(
            &offer,
            offer_token(
                &offer,
                &attacker_signer(),
                RELAY_STREAM_CLAW_ID,
                b"n2",
                now + 60,
            ),
        );
        assert!(
            verify_relay_stream_offer_session(&offer, &ReplayGuard::new(), &wrong_dev, now)
                .is_err()
        );

        // Wrong target: token target_id != claw → rejected.
        let wrong_target = envelope(
            &offer,
            offer_token(&offer, &guest_signer(), "other_claw", b"n3", now + 60),
        );
        assert!(
            verify_relay_stream_offer_session(&offer, &ReplayGuard::new(), &wrong_target, now)
                .is_err()
        );

        // Cross-offer: a token bound to offer A presented on a connection serving
        // offer B → credential-hash mismatch (server derives expected from ITS offer).
        let offer_b = public_offer(now + 60);
        let token_for_a = offer_token(
            &offer,
            &guest_signer(),
            RELAY_STREAM_CLAW_ID,
            b"n4",
            now + 60,
        );
        let a_token_on_b = envelope(&offer_b, token_for_a);
        assert!(
            verify_relay_stream_offer_session(&offer_b, &ReplayGuard::new(), &a_token_on_b, now)
                .is_err()
        );

        // Replay: the same nonce twice on the same ReplayGuard → second rejected.
        let replay = ReplayGuard::new();
        let e1 = envelope(
            &offer,
            offer_token(
                &offer,
                &guest_signer(),
                RELAY_STREAM_CLAW_ID,
                b"dup",
                now + 60,
            ),
        );
        let e2 = envelope(
            &offer,
            offer_token(
                &offer,
                &guest_signer(),
                RELAY_STREAM_CLAW_ID,
                b"dup",
                now + 60,
            ),
        );
        assert!(verify_relay_stream_offer_session(&offer, &replay, &e1, now).is_ok());
        assert!(verify_relay_stream_offer_session(&offer, &replay, &e2, now).is_err());
    }

    #[test]
    fn revoked_predicate_is_the_full_live_gate() {
        let now = now_unix();
        let offer = group_offer(now + 60);

        // Fully active group → NOT revoked.
        assert!(!relay_stream_offer_session_revoked(
            &offer,
            &trust_with(group_projection(true, true, true)),
            now
        ));
        // Member removed / grant revoked / device retired / unknown group → revoked.
        for proj in [
            group_projection(false, true, true),
            group_projection(true, false, true),
            group_projection(true, true, false),
            ProjectedState::default(),
        ] {
            assert!(relay_stream_offer_session_revoked(
                &offer,
                &trust_with(proj),
                now
            ));
        }
        // Expiry: now past not_after, membership unchanged → revoked (full gate).
        assert!(relay_stream_offer_session_revoked(
            &offer,
            &trust_with(group_projection(true, true, true)),
            now + 120
        ));
        // Issuer removed: the offer signer is removed from the directory → revoked.
        let mut removed = group_projection(true, true, true);
        removed.directory_devices.insert(
            owner_pub().as_bytes().to_vec(),
            ProjectedDirectoryDevice {
                label: "engine".to_string(),
                status: DirectoryDeviceStatus::Removed,
            },
        );
        assert!(relay_stream_offer_session_revoked(
            &offer,
            &trust_with(removed),
            now
        ));

        // Public: published → not revoked; unpublished / unknown → revoked.
        let pub_offer = public_offer(now + 60);
        assert!(!relay_stream_offer_session_revoked(
            &pub_offer,
            &trust_with(published_projection(true)),
            now
        ));
        assert!(relay_stream_offer_session_revoked(
            &pub_offer,
            &trust_with(published_projection(false)),
            now
        ));
        assert!(relay_stream_offer_session_revoked(
            &pub_offer,
            &trust_with(ProjectedState::default()),
            now
        ));
    }

    // ── Serve-loop liveness (merge gates) ────────────────────────────────────
    // Drive the REAL serve loop over a duplex with the credential-less verifier +
    // the full-live-gate Rev (clock + mutable projection injected), proving the
    // mid-session teardown fires through the idle revoke-poll arm.

    async fn drive_until_torn_down(
        offer: RelayStreamOfferContract,
        trust: RelayStreamIssuerTrust,
        clock: Arc<AtomicU64>,
        base: u64,
        mutate_after_open: impl FnOnce(),
    ) {
        let router = TcpStreamRouter::new(spawn_ack_target().await);
        let replay = Arc::new(ReplayGuard::new());
        let v_offer = offer.clone();
        let v_replay = Arc::clone(&replay);
        let r_offer = offer.clone();
        let r_trust = trust.clone();
        let r_clock = Arc::clone(&clock);

        let (mut client, server_io) = duplex(64 * 1024);
        let server = serve_connection_io_with_auth_deadline(
            server_io,
            base,
            move |env: &AuthEnvelope, now| {
                verify_relay_stream_offer_session(&v_offer, &v_replay, env, now)
            },
            &router,
            move |_s: &RelayStreamOfferSession| {
                relay_stream_offer_session_revoked(
                    &r_offer,
                    &r_trust,
                    r_clock.load(Ordering::SeqCst),
                )
            },
            Duration::from_secs(5),
        );
        let client_side = async {
            let token = offer_token(
                &offer,
                &guest_signer(),
                RELAY_STREAM_CLAW_ID,
                b"live",
                base + 60,
            );
            let cbor = offer.payload.to_canonical_bytes().unwrap();
            assert!(matches!(
                client_authenticate(&mut client, &cbor, token)
                    .await
                    .unwrap(),
                TunnelAck::Ok { .. }
            ));
            client_open_stream(&mut client).await.unwrap();
            // Trigger revocation (advance clock / mutate projection), then send
            // NOTHING — the idle revoke-poll must tear the live session down.
            mutate_after_open();
            match tokio::time::timeout(Duration::from_secs(3), recv_frame(&mut client)).await {
                Ok(res) => assert!(res.is_err(), "live session must tear down, got {res:?}"),
                Err(elapsed) => {
                    panic!("live session NOT torn down within 3s (idle revoke-poll): {elapsed}")
                }
            }
        };
        let (server_res, ()) = tokio::join!(server, client_side);
        assert!(
            matches!(server_res, Err(DataTunnelError::Rejected(_))),
            "server must report a revoked teardown, got {server_res:?}"
        );
    }

    #[tokio::test]
    async fn group_session_tears_down_on_expiry_via_live_clock() {
        // The panel canary: advance the INJECTED CLOCK past not_after WITHOUT
        // touching membership; the full live gate must catch the expiry and tear
        // the idle session down. A frozen now (instead of a clock handle) fails this.
        let base = now_unix();
        let offer = group_offer(base + 60);
        let trust = trust_with(group_projection(true, true, true));
        let clock = Arc::new(AtomicU64::new(base));
        let advance = {
            let c = Arc::clone(&clock);
            move || c.store(base + 120, Ordering::SeqCst)
        };
        drive_until_torn_down(offer, trust, clock, base, advance).await;
    }

    #[tokio::test]
    async fn group_session_tears_down_when_member_removed_via_poll() {
        // Member removed mid-session in the LIVE projection (clock unchanged) →
        // the idle revoke-poll tears the session down within the poll interval.
        let base = now_unix();
        let offer = group_offer(base + 60);
        let proj = Arc::new(Mutex::new(group_projection(true, true, true)));
        let trust = {
            let p = Arc::clone(&proj);
            RelayStreamIssuerTrust::new(move || RelayStreamTrustContext {
                record: relay_stream_household_record(),
                cert: relay_stream_machine_cert(),
                projection: p.lock().unwrap().clone(),
            })
        };
        let clock = Arc::new(AtomicU64::new(base));
        let remove = move || *proj.lock().unwrap() = group_projection(false, true, true);
        drive_until_torn_down(offer, trust, clock, base, remove).await;
    }
}
