#![cfg(test)]

use super::*;
use crate::claw_store_routes;
use crate::owner_site::ake::{
    OwnerSiteAkeEffectSnapshot, OwnerSiteAkeFixture, OwnerSiteAkeHarness,
};
use crate::owner_site::authority::{OwnerSiteAuthoritySnapshot, active_authority_fixture};
use crate::owner_site::capability::{
    OwnerSiteBackend, OwnerSiteCapability, OwnerSiteCapabilityScope, OwnerSiteCapabilityStore,
    OwnerSiteEffectCounters, OwnerSiteEffectSnapshot, OwnerSiteIntent, OwnerSiteResource,
};
use axum::{
    Extension, Router,
    body::Body,
    extract::ConnectInfo,
    http::Request,
    routing::{get, post},
};
use axum_test::{TestServer, WsMessage};
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::{BootstrapOpts, KeyBackingPolicy};
use std::sync::Arc;
use tokio::time::{Duration, timeout};
use tower::ServiceExt;

fn owner_site_store(
    claw_name: &str,
    actor_id: &str,
    authority: OwnerSiteAuthoritySnapshot,
) -> (Arc<OwnerSiteCapabilityStore>, Arc<OwnerSiteEffectCounters>) {
    let resource = OwnerSiteResource::from_route_claw(claw_name).expect("owner-site resource");
    let intent = OwnerSiteIntent::injected_for_harness("household-alpha", actor_id, resource)
        .expect("owner-site intent");
    let backend = OwnerSiteBackend::numeric_loopback(
        "127.0.0.1:7411".parse().expect("numeric loopback backend"),
    )
    .expect("loopback backend");
    let scope = OwnerSiteCapabilityScope::new(intent, authority, backend);
    let (store, effects) = OwnerSiteCapabilityStore::injected_for_harness(
        OwnerSiteCapability::injected_for_harness(scope),
    );
    (Arc::new(store), effects)
}

fn owner_site_route(provider: Option<Arc<OwnerSiteCapabilityStore>>) -> Router {
    let app = Router::new().route(
        claw_store_routes::household::OWNER_SITE_PREFLIGHT,
        post(handle_household_owner_site_preflight),
    );
    match provider {
        Some(store) => app.layer(Extension(store)),
        None => app,
    }
}

fn owner_site_ake_route(provider: Option<Arc<OwnerSiteAkeProvider>>) -> Router {
    let app = Router::new().route(
        claw_store_routes::household::OWNER_SITE_AKE,
        get(handle_household_owner_site_ake),
    );
    match provider {
        Some(provider) => app.layer(Extension(provider)),
        None => app,
    }
}

fn assert_ake_never_effected(snapshot: &OwnerSiteAkeEffectSnapshot) {
    assert_eq!(snapshot.verified_peers, 0);
    assert_eq!(snapshot.dial_permits_issued, 0);
    assert_eq!(snapshot.mints, 0);
    assert_eq!(snapshot.consumes, 0);
    assert_eq!(snapshot.proxy_dials, 0);
    assert_eq!(snapshot.site_bytes, 0);
}

async fn owner_site_preflight_request(
    app: Router,
    claw_name: &str,
    peer: Option<SocketAddr>,
    attach_token: Option<&str>,
) -> StatusCode {
    let path = format!("/api/v1/household/claws/{claw_name}/owner-site/preflight");
    let mut builder = Request::builder().method(Method::POST).uri(path);
    if let Some(peer) = peer {
        builder = builder.extension(ConnectInfo(peer));
    }
    if let Some(attach_token) = attach_token {
        builder = builder.header(HOUSEHOLD_ATTACH_TOKEN_HEADER, attach_token);
    }
    owner_site_route_response(app, builder).await.status()
}

async fn owner_site_route_response(app: Router, builder: axum::http::request::Builder) -> Response {
    app.oneshot(builder.body(Body::empty()).expect("owner-site request"))
        .await
        .expect("owner-site response")
}

fn assert_owner_site_zero_effects(effects: &OwnerSiteEffectCounters, pre_effect_admissions: usize) {
    assert_eq!(
        effects.snapshot(),
        OwnerSiteEffectSnapshot {
            listener_binds: 0,
            mints: 0,
            consumes: 0,
            proxy_dials: 0,
            site_bytes: 0,
            challenge_issues: 0,
            challenge_claims: 0,
            pre_effect_admissions,
        },
        "pre-effect owner-site route must not bind, mint, issue/claim a challenge, dial, or expose bytes"
    );
}

#[tokio::test]
async fn owner_site_ake_default_denies_and_unverified_mesh_stops_before_provider() {
    let path = "/api/v1/household/claws/picoclaw/owner-site/ake";
    let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");
    let default_server = TestServer::builder()
        .http_transport()
        .build(owner_site_ake_route(None).layer(Extension(ConnectInfo(loopback))))
        .expect("default-deny A2 test server");
    let response = default_server.get_websocket(path).await;
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

    let OwnerSiteAkeFixture {
        provider, effects, ..
    } = OwnerSiteAkeHarness::fixture_for_harness("picoclaw").expect("A2 fixture");
    let unverified = SocketAddr::from(([10, 44, 0, 2], 41001));
    let server = TestServer::builder()
        .http_transport()
        .build(
            owner_site_ake_route(Some(Arc::new(provider)))
                .layer(Extension(ConnectInfo(unverified))),
        )
        .expect("unverified A2 test server");
    let response = server.get_websocket(path).await;
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(effects.snapshot().sessions_started, 0);
    assert_eq!(effects.snapshot().challenge_issues, 0);
    assert_eq!(effects.snapshot().challenge_claims, 0);
    assert_ake_never_effected(&effects.snapshot());
}

#[tokio::test]
async fn owner_site_ake_uses_one_binary_ws_for_s2_c3_then_closes_pre_effect() {
    let OwnerSiteAkeFixture {
        provider,
        client,
        effects,
    } = OwnerSiteAkeHarness::fixture_for_harness("picoclaw").expect("A2 fixture");
    let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");
    let app =
        owner_site_ake_route(Some(Arc::new(provider))).layer(Extension(ConnectInfo(loopback)));
    let server = TestServer::builder()
        .http_transport()
        .build(app)
        .expect("A2 WS test server");
    let path = "/api/v1/household/claws/picoclaw/owner-site/ake";
    let response = server.get_websocket(path).await;
    assert_eq!(response.status_code(), StatusCode::SWITCHING_PROTOCOLS);
    let mut websocket = response.into_websocket().await;

    let (mut client_session, m1) = client.start().expect("M1");
    websocket.send_message(WsMessage::Binary(m1.into())).await;
    let m2 = websocket.receive_bytes().await;
    let m3 = client_session
        .accept_m2_and_make_m3(&m2)
        .expect("M3 after authenticated M2");
    websocket.send_message(WsMessage::Binary(m3.into())).await;

    let s2 = websocket.receive_bytes().await;
    assert!(!s2.is_empty(), "S2 must be an encrypted A2 record");
    let c3 = client_session
        .accept_s2_and_make_c3(&s2)
        .expect("C3 only after authenticating the exact S2");
    websocket.send_message(WsMessage::Binary(c3.into())).await;

    for _ in 0..128 {
        if effects.snapshot().c3_records_accepted == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    let snapshot = effects.snapshot();
    assert_eq!(snapshot.sessions_started, 1);
    assert_eq!(snapshot.challenge_issues, 1);
    assert_eq!(snapshot.challenge_claims, 1);
    assert_eq!(snapshot.validated_pending_finished, 1);
    assert_eq!(snapshot.post_claim_recheck_rejections, 0);
    assert_eq!(snapshot.s2_records_emitted, 1);
    assert_eq!(snapshot.c3_records_accepted, 1);
    assert_eq!(snapshot.post_c3_recheck_rejections, 0);
    assert_eq!(snapshot.completed_m3_closures, 1);
    assert_ake_never_effected(&snapshot);
    assert_eq!(client.action_pop_signature_count(), 1);
    // The same WS closes after authenticated C3. There is still no raw
    // stream, second WebSocket, resumable credential, peer, or site byte.
    let close = timeout(Duration::from_secs(1), websocket.receive_bytes())
        .await
        .expect("post-C3 pre-effect state must close the same WebSocket");
    assert!(
        close.is_empty(),
        "the record-confirmed pre-effect state must emit zero raw bytes"
    );
}

#[tokio::test]
async fn owner_site_ake_route_real_rejects_raw_c3_and_closes_without_effects() {
    let OwnerSiteAkeFixture {
        provider,
        client,
        effects,
    } = OwnerSiteAkeHarness::fixture_for_harness("picoclaw").expect("A2 fixture");
    let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");
    let app =
        owner_site_ake_route(Some(Arc::new(provider))).layer(Extension(ConnectInfo(loopback)));
    let server = TestServer::builder()
        .http_transport()
        .build(app)
        .expect("A2 WS test server");
    let path = "/api/v1/household/claws/picoclaw/owner-site/ake";
    let response = server.get_websocket(path).await;
    assert_eq!(response.status_code(), StatusCode::SWITCHING_PROTOCOLS);
    let mut websocket = response.into_websocket().await;

    let (mut client_session, m1) = client.start().expect("M1");
    websocket.send_message(WsMessage::Binary(m1.into())).await;
    let m2 = websocket.receive_bytes().await;
    let m3 = client_session
        .accept_m2_and_make_m3(&m2)
        .expect("M3 after authenticated M2");
    websocket.send_message(WsMessage::Binary(m3.into())).await;
    let s2 = websocket.receive_bytes().await;
    assert!(
        !s2.is_empty(),
        "server reaches the encrypted S2 state first"
    );

    // A text application message is plaintext, never an A2 record. The
    // A2 state machine must close rather than parse or downgrade it.
    websocket
        .send_message(WsMessage::Text("not-an-a2-record".into()))
        .await;

    let close = timeout(Duration::from_secs(1), websocket.receive_bytes())
        .await
        .expect("malformed C3 must close the same WebSocket");
    assert!(
        close.is_empty(),
        "malformed C3 cannot reveal raw response bytes"
    );
    let snapshot = effects.snapshot();
    assert_eq!(snapshot.sessions_started, 1);
    assert_eq!(snapshot.challenge_claims, 1);
    assert_eq!(snapshot.validated_pending_finished, 1);
    assert_eq!(snapshot.s2_records_emitted, 1);
    assert_eq!(snapshot.c3_records_accepted, 0);
    assert_eq!(snapshot.post_c3_recheck_rejections, 0);
    assert_eq!(snapshot.completed_m3_closures, 1);
    assert_ake_never_effected(&snapshot);
}

#[tokio::test]
async fn owner_site_ake_route_real_c3_timeout_closes_without_effects() {
    let OwnerSiteAkeFixture {
        provider,
        client,
        effects,
    } = OwnerSiteAkeHarness::fixture_for_harness("picoclaw").expect("A2 fixture");
    let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");
    let app =
        owner_site_ake_route(Some(Arc::new(provider))).layer(Extension(ConnectInfo(loopback)));
    let server = TestServer::builder()
        .http_transport()
        .build(app)
        .expect("A2 WS test server");
    let path = "/api/v1/household/claws/picoclaw/owner-site/ake";
    let response = server.get_websocket(path).await;
    assert_eq!(response.status_code(), StatusCode::SWITCHING_PROTOCOLS);
    let mut websocket = response.into_websocket().await;

    let (mut client_session, m1) = client.start().expect("M1");
    websocket.send_message(WsMessage::Binary(m1.into())).await;
    let m2 = websocket.receive_bytes().await;
    let m3 = client_session
        .accept_m2_and_make_m3(&m2)
        .expect("M3 after authenticated M2");
    websocket.send_message(WsMessage::Binary(m3.into())).await;
    let s2 = websocket.receive_bytes().await;
    assert!(
        !s2.is_empty(),
        "server reaches PendingFinished before the timeout"
    );

    let close = timeout(Duration::from_secs(2), websocket.receive_bytes())
        .await
        .expect("withheld C3 must expire and close the same WebSocket");
    assert!(close.is_empty(), "timeout cannot reveal raw response bytes");
    let snapshot = effects.snapshot();
    assert_eq!(snapshot.sessions_started, 1);
    assert_eq!(snapshot.challenge_claims, 1);
    assert_eq!(snapshot.validated_pending_finished, 1);
    assert_eq!(snapshot.s2_records_emitted, 1);
    assert_eq!(snapshot.c3_records_accepted, 0);
    assert_eq!(snapshot.post_c3_recheck_rejections, 0);
    assert_eq!(snapshot.completed_m3_closures, 1);
    assert_ake_never_effected(&snapshot);
}

#[tokio::test]
async fn owner_site_ake_route_real_revoke_after_consume_closes_without_effects() {
    let OwnerSiteAkeFixture {
        provider,
        client,
        effects,
    } = OwnerSiteAkeHarness::fixture_for_harness("picoclaw").expect("A2 fixture");
    let harness = provider
        .harness_for_test()
        .expect("test-only A2 harness provider");
    let pause = harness.pause_after_claim_for_harness();
    let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");
    let app =
        owner_site_ake_route(Some(Arc::new(provider))).layer(Extension(ConnectInfo(loopback)));
    let server = TestServer::builder()
        .http_transport()
        .build(app)
        .expect("A2 WS test server");
    let path = "/api/v1/household/claws/picoclaw/owner-site/ake";
    let response = server.get_websocket(path).await;
    assert_eq!(response.status_code(), StatusCode::SWITCHING_PROTOCOLS);
    let mut websocket = response.into_websocket().await;

    let (mut client_session, m1) = client.start().expect("M1");
    websocket.send_message(WsMessage::Binary(m1.into())).await;
    let m2 = websocket.receive_bytes().await;
    let m3 = client_session
        .accept_m2_and_make_m3(&m2)
        .expect("M3 after authenticated M2");
    websocket.send_message(WsMessage::Binary(m3.into())).await;

    timeout(Duration::from_secs(1), pause.wait_until_reached())
        .await
        .expect("one-shot challenge must be claimed before the re-read");
    harness.revoke_before_recheck_for_harness();
    pause.resume();

    for _ in 0..128 {
        if effects.snapshot().post_claim_recheck_rejections == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    let snapshot = effects.snapshot();
    assert_eq!(snapshot.sessions_started, 1);
    assert_eq!(snapshot.challenge_issues, 1);
    assert_eq!(snapshot.challenge_claims, 1);
    assert_eq!(snapshot.validated_pending_finished, 0);
    assert_eq!(snapshot.post_claim_recheck_rejections, 1);
    assert_eq!(snapshot.s2_records_emitted, 0);
    assert_eq!(snapshot.c3_records_accepted, 0);
    assert_eq!(snapshot.post_c3_recheck_rejections, 0);
    assert_eq!(snapshot.completed_m3_closures, 1);
    assert_ake_never_effected(&snapshot);
    assert_eq!(client.action_pop_signature_count(), 1);

    let close = timeout(Duration::from_secs(1), websocket.receive_bytes())
        .await
        .expect("revocation must close the same WebSocket");
    assert!(close.is_empty(), "revocation must emit zero raw bytes");
}

#[tokio::test]
async fn owner_site_ake_route_real_revoke_between_s2_and_c3_closes_without_effects() {
    let OwnerSiteAkeFixture {
        provider,
        client,
        effects,
    } = OwnerSiteAkeHarness::fixture_for_harness("picoclaw").expect("A2 fixture");
    let harness = provider
        .harness_for_test()
        .expect("test-only A2 harness provider");
    let pause = harness.pause_after_s2_for_harness();
    let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");
    let app =
        owner_site_ake_route(Some(Arc::new(provider))).layer(Extension(ConnectInfo(loopback)));
    let server = TestServer::builder()
        .http_transport()
        .build(app)
        .expect("A2 WS test server");
    let path = "/api/v1/household/claws/picoclaw/owner-site/ake";
    let response = server.get_websocket(path).await;
    assert_eq!(response.status_code(), StatusCode::SWITCHING_PROTOCOLS);
    let mut websocket = response.into_websocket().await;

    let (mut client_session, m1) = client.start().expect("M1");
    websocket.send_message(WsMessage::Binary(m1.into())).await;
    let m2 = websocket.receive_bytes().await;
    let m3 = client_session
        .accept_m2_and_make_m3(&m2)
        .expect("M3 after authenticated M2");
    websocket.send_message(WsMessage::Binary(m3.into())).await;
    let s2 = websocket.receive_bytes().await;
    assert!(!s2.is_empty(), "S2 must be encrypted before the pause");

    timeout(Duration::from_secs(1), pause.wait_until_reached())
        .await
        .expect("S2 pause must be reached before C3 finalization");
    let before_c3 = effects.snapshot();
    assert_eq!(before_c3.validated_pending_finished, 1);
    assert_eq!(before_c3.s2_records_emitted, 1);
    assert_eq!(before_c3.c3_records_accepted, 0);
    assert_eq!(before_c3.verified_peers, 0);
    assert_eq!(before_c3.mints, 0);
    assert_eq!(before_c3.consumes, 0);
    assert_eq!(before_c3.proxy_dials, 0);
    assert_eq!(before_c3.site_bytes, 0);
    harness.revoke_before_recheck_for_harness();
    let c3 = client_session
        .accept_s2_and_make_c3(&s2)
        .expect("the device can only acknowledge the received S2");
    websocket.send_message(WsMessage::Binary(c3.into())).await;
    pause.resume();

    for _ in 0..128 {
        if effects.snapshot().post_c3_recheck_rejections == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    let snapshot = effects.snapshot();
    assert_eq!(snapshot.sessions_started, 1);
    assert_eq!(snapshot.challenge_issues, 1);
    assert_eq!(snapshot.challenge_claims, 1);
    assert_eq!(snapshot.validated_pending_finished, 1);
    assert_eq!(snapshot.post_claim_recheck_rejections, 0);
    assert_eq!(snapshot.s2_records_emitted, 1);
    assert_eq!(snapshot.c3_records_accepted, 0);
    assert_eq!(snapshot.post_c3_recheck_rejections, 1);
    assert_eq!(snapshot.completed_m3_closures, 1);
    assert_ake_never_effected(&snapshot);
    assert_eq!(client.action_pop_signature_count(), 1);

    let close = timeout(Duration::from_secs(1), websocket.receive_bytes())
        .await
        .expect("revoked pending channel must close the same WebSocket");
    assert!(close.is_empty(), "revoke must expose no raw site bytes");
}

#[tokio::test]
async fn household_scope_uses_loaded_engine_identity_not_caller_identity() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let identity = household_rs::bootstrap_or_load(
        state_dir.path(),
        BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some("mac-alpha".into()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .unwrap();
    let expected_household_id = identity.record.hh_id.to_string();
    let expected_machine_id = identity.cert.m_id.to_string();
    let caller = P256Keypair::generate();
    let caller_person_id = household_rs::derive_person_id(&caller.public()).0;

    let state = HouseholdState::loaded(Arc::new(identity));
    let scope = household_scope_from_state(&state)
        .await
        .expect("loaded household scope");

    assert_eq!(scope.household_id, expected_household_id);
    assert_eq!(scope.household_machine_id, expected_machine_id);
    assert_ne!(scope.household_machine_id, caller_person_id);
}

#[tokio::test]
async fn owner_site_pre_effect_route_is_typed_fail_closed_and_zero_effect() {
    let path_resource = "picoclaw";
    let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");

    // The production router has no owner-site provider in PR1. A valid
    // source alone therefore cannot produce a pre-effect admission.
    let status =
        owner_site_preflight_request(owner_site_route(None), path_resource, Some(loopback), None)
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The production no-extension path above is the real default. This
    // empty test provider additionally makes its zero-effect observation
    // explicit without granting a capability.
    let (absent, absent_effects) = OwnerSiteCapabilityStore::unavailable_for_harness();
    let absent = Arc::new(absent);
    let absent_pending = absent.pending_count();
    let status = owner_site_preflight_request(
        owner_site_route(Some(Arc::clone(&absent))),
        path_resource,
        Some(loopback),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(absent.pending_count(), absent_pending);
    assert_owner_site_zero_effects(&absent_effects, 1);

    let (stale, stale_effects) = owner_site_store(
        path_resource,
        "owner-alpha",
        OwnerSiteAuthoritySnapshot::Stale,
    );
    let stale_pending = stale.pending_count();
    let status = owner_site_preflight_request(
        owner_site_route(Some(Arc::clone(&stale))),
        path_resource,
        Some(loopback),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(stale.pending_count(), stale_pending);
    assert_owner_site_zero_effects(&stale_effects, 1);

    let (mismatch, mismatch_effects) = owner_site_store(
        path_resource,
        "owner-alpha",
        OwnerSiteAuthoritySnapshot::Mismatch,
    );
    let mismatch_pending = mismatch.pending_count();
    let status = owner_site_preflight_request(
        owner_site_route(Some(Arc::clone(&mismatch))),
        path_resource,
        Some(loopback),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(mismatch.pending_count(), mismatch_pending);
    assert_owner_site_zero_effects(&mismatch_effects, 1);

    let (revoked, revoked_effects) = owner_site_store(
        path_resource,
        "owner-alpha",
        OwnerSiteAuthoritySnapshot::Revoked,
    );
    let revoked_pending = revoked.pending_count();
    let status = owner_site_preflight_request(
        owner_site_route(Some(Arc::clone(&revoked))),
        path_resource,
        Some(loopback),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(revoked.pending_count(), revoked_pending);
    assert_owner_site_zero_effects(&revoked_effects, 1);

    let resource = OwnerSiteResource::from_route_claw(path_resource).expect("owner-site resource");
    let (actor_id, authority) =
        active_authority_fixture("household-alpha", resource).expect("typed authority fixture");
    let (admitted, effects) = owner_site_store(path_resource, &actor_id, authority);
    let admitted_pending = admitted.pending_count();

    // An exact typed capability is the only positive path in PR1. This
    // loopback case exercises the wire harness only; a Mesh success stays
    // deferred until the reviewed VerifiedMesh provider exists. The route
    // still invokes the shared live peer gate before this provider.
    let status = owner_site_preflight_request(
        owner_site_route(Some(Arc::clone(&admitted))),
        path_resource,
        Some(loopback),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(admitted.pending_count(), admitted_pending);
    assert_owner_site_zero_effects(&effects, 1);

    // A different resource cannot use the injected capability.
    let status = owner_site_preflight_request(
        owner_site_route(Some(Arc::clone(&admitted))),
        "otherclaw",
        Some(loopback),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(admitted.pending_count(), admitted_pending);
    assert_owner_site_zero_effects(&effects, 2);

    // The shared live gate still wins over the injected capability: neither
    // an unverified Mesh source nor a missing peer reaches the provider.
    let unverified = SocketAddr::from(([10, 44, 0, 2], 41001));
    for peer in [Some(unverified), None] {
        let status = owner_site_preflight_request(
            owner_site_route(Some(Arc::clone(&admitted))),
            path_resource,
            peer,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "peer={peer:?}");
        assert_eq!(admitted.pending_count(), admitted_pending);
        assert_owner_site_zero_effects(&effects, 2);
    }

    // A terminal attach bearer cannot be presented at this route and the
    // terminal token remains untouched after the rejection.
    let attach_tokens = HouseholdAttachTokenStore::new();
    let attach = attach_tokens.mint(HouseholdAttachScope {
        household_id: "household-alpha".to_string(),
        container: path_resource.to_string(),
        session_id: "workspace-alpha".to_string(),
        actor_person_id: "owner-alpha".to_string(),
    });
    let attach_pending = attach_tokens.pending_count();
    let status = owner_site_preflight_request(
        owner_site_route(Some(Arc::clone(&admitted))),
        path_resource,
        Some(loopback),
        Some(&attach.token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(attach_tokens.pending_count(), attach_pending);
    assert_eq!(admitted.pending_count(), admitted_pending);
    assert_owner_site_zero_effects(&effects, 2);
}

#[tokio::test]
async fn owner_site_pre_effect_rejections_have_zero_body_and_no_challenge_delta() {
    let path_resource = "picoclaw";
    let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");
    let (store, effects) = OwnerSiteCapabilityStore::unavailable_for_harness();
    let app = owner_site_route(Some(Arc::new(store)));
    let path = format!("/api/v1/household/claws/{path_resource}/owner-site/preflight");
    let response = owner_site_route_response(
        app,
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .extension(ConnectInfo(loopback)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), 1_024)
        .await
        .expect("forbidden body");
    assert!(body.is_empty(), "pre-effect denial must expose zero bytes");
    assert_owner_site_zero_effects(&effects, 1);
}
