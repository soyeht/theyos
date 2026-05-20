//! Contract tests for `POST /bootstrap/accept-household` and confirm.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use core_rs::env::set_test_env;
use household_rs::bootstrap_state::BootstrapState;
use household_rs::ids::derive_household_id;
use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
use household_rs::machine_cert::{MachineCert, Platform, SignOptions};
use household_rs::pair_device::PairDeviceWindow;
use household_rs::{BootstrapOpts, KeyBackingPolicy};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use server_rs::bonjour_publisher::{HouseholdBonjour, PairMachineBonjourRole, PublishParams};
use server_rs::handlers_bootstrap::{BootstrapHandlerState, BootstrapStateArc, bootstrap_router};
use server_rs::household_state::HouseholdState;
use server_rs::setup_invitation::{SetupInvitationEntry, cache_insert, cache_lookup};
use tokio::sync::RwLock;
use tower::ServiceExt;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn make_state_dir() -> PathBuf {
    let dir = tempfile::tempdir().unwrap().keep();
    std::fs::create_dir_all(dir.join("household")).unwrap();
    dir
}

fn make_state(bs: BootstrapState, state_dir: PathBuf) -> BootstrapHandlerState {
    BootstrapHandlerState {
        bootstrap: Arc::new(RwLock::new(bs)) as BootstrapStateArc,
        household: HouseholdState::empty(),
        state_dir,
        pair_device_window: Arc::new(PairDeviceWindow::new()),
        started_at: Instant::now(),
        setup_invitation_cache: server_rs::setup_invitation::new_cache(),
    }
}

fn token(seed: u8) -> [u8; 32] {
    let mut out = [seed; 32];
    out[0] = seed.wrapping_add(1);
    out
}

async fn populate_invitation(
    state: &BootstrapHandlerState,
    token: [u8; 32],
    hh_id: &str,
    expires_at: u64,
) {
    cache_insert(
        &state.setup_invitation_cache,
        SetupInvitationEntry {
            token,
            iphone_endpoint: "127.0.0.1:9".to_string(),
            iphone_addrs: vec!["100.64.1.1".parse().unwrap()],
            owner_display_name: "Owner".to_string(),
            hh_id: Some(hh_id.to_string()),
            expires_at,
        },
    )
    .await;
}

#[derive(Serialize)]
struct AcceptReq<'a> {
    #[serde(rename = "v")]
    version: u8,
    hh_id: &'a str,
    hh_pub: &'a serde_bytes::Bytes,
    hh_name: &'a str,
    invitation_token: &'a serde_bytes::Bytes,
}

fn cbor_accept(hh_id: &str, hh_pub: &[u8], hh_name: &str, token: &[u8]) -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&AcceptReq {
        version: 1,
        hh_id,
        hh_pub: serde_bytes::Bytes::new(hh_pub),
        hh_name,
        invitation_token: serde_bytes::Bytes::new(token),
    })
    .unwrap()
}

fn cbor_accept_with_extra(hh_id: &str, hh_pub: &[u8], token: &[u8]) -> Vec<u8> {
    #[derive(Serialize)]
    struct Req<'a> {
        #[serde(rename = "v")]
        version: u8,
        hh_id: &'a str,
        hh_pub: &'a serde_bytes::Bytes,
        hh_name: &'a str,
        invitation_token: &'a serde_bytes::Bytes,
        extra: u8,
    }
    household_rs::cbor::to_canonical_vec(&Req {
        version: 1,
        hh_id,
        hh_pub: serde_bytes::Bytes::new(hh_pub),
        hh_name: "Existing Home",
        invitation_token: serde_bytes::Bytes::new(token),
        extra: 1,
    })
    .unwrap()
}

async fn call_accept(state: BootstrapHandlerState, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let app = bootstrap_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/bootstrap/accept-household")
        .header("content-type", "application/cbor")
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

#[derive(Serialize)]
struct ConfirmReq<'a> {
    #[serde(rename = "v")]
    version: u8,
    m_id: &'a str,
    machine_cert: &'a serde_bytes::Bytes,
    challenge_sig: &'a serde_bytes::Bytes,
}

fn cbor_confirm(m_id: &str, machine_cert: &[u8], challenge_sig: &[u8]) -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&ConfirmReq {
        version: 1,
        m_id,
        machine_cert: serde_bytes::Bytes::new(machine_cert),
        challenge_sig: serde_bytes::Bytes::new(challenge_sig),
    })
    .unwrap()
}

async fn call_confirm(state: BootstrapHandlerState, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let app = bootstrap_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/bootstrap/accept-household/confirm")
        .header("content-type", "application/cbor")
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

#[derive(Deserialize)]
struct AcceptOk {
    #[serde(rename = "v")]
    version: u8,
    m_id: String,
    m_pub: ByteBuf,
    join_challenge: ByteBuf,
    challenge_sig_required: bool,
}

#[derive(Deserialize)]
struct ConfirmOk {
    #[serde(rename = "v")]
    version: u8,
    bootstrap_state: String,
    m_id: String,
    hh_id: String,
}

#[derive(Deserialize)]
struct ErrBody {
    #[serde(rename = "v")]
    _version: u8,
    error: String,
}

fn decode_accept_ok(bytes: &[u8]) -> AcceptOk {
    household_rs::cbor::from_canonical_slice(bytes).unwrap()
}

fn decode_confirm_ok(bytes: &[u8]) -> ConfirmOk {
    household_rs::cbor::from_canonical_slice(bytes).unwrap()
}

fn decode_err(bytes: &[u8]) -> ErrBody {
    household_rs::cbor::from_canonical_slice(bytes).unwrap()
}

async fn accepted_state() -> (BootstrapHandlerState, P256Keypair, String, AcceptOk) {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");
    let hh_key = P256Keypair::generate();
    let hh_pub = hh_key.public();
    let hh_id = derive_household_id(&hh_pub).to_string();
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let invite = token(7);
    populate_invitation(&state, invite, &hh_id, unix_now() + 1800).await;

    let (status, body) = call_accept(
        state.clone(),
        cbor_accept(&hh_id, hh_pub.as_bytes(), "Existing Home", &invite),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    let accept = decode_accept_ok(&body);
    (state, hh_key, hh_id, accept)
}

fn machine_cert_for_accept(hh_key: &P256Keypair, hh_id: &str, accept: &AcceptOk) -> Vec<u8> {
    let m_pub = P256PublicKey::from_bytes(accept.m_pub.as_ref()).unwrap();
    let cert = MachineCert::sign(
        hh_key,
        &m_pub,
        &SignOptions {
            hh_id: household_rs::HouseholdId::parse(hh_id.to_string()).unwrap(),
            hostname: "test-mac".to_string(),
            platform: Platform::Macos,
            joined_at: unix_now(),
        },
    )
    .unwrap();
    household_rs::cbor::to_canonical_vec(&cert).unwrap()
}

#[tokio::test]
async fn accept_household_happy_path_reaches_ready_and_publishes_ready_txt() {
    let (state, hh_key, hh_id, accept) = accepted_state().await;
    assert_eq!(accept.version, 1);
    assert_eq!(accept.m_pub.len(), 33);
    assert!(!accept.join_challenge.is_empty());
    assert!(accept.challenge_sig_required);
    assert_eq!(
        *state.bootstrap.read().await,
        BootstrapState::ReadyForNaming
    );

    let sig = hh_key.sign(accept.join_challenge.as_ref()).unwrap();
    let cert = machine_cert_for_accept(&hh_key, &hh_id, &accept);
    let (status, body) = call_confirm(
        state.clone(),
        cbor_confirm(&accept.m_id, &cert, sig.as_bytes()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");

    let confirm = decode_confirm_ok(&body);
    assert_eq!(confirm.version, 1);
    assert_eq!(confirm.bootstrap_state, "ready");
    assert_eq!(confirm.hh_id, hh_id);
    assert_eq!(confirm.m_id, accept.m_id);
    assert_eq!(*state.bootstrap.read().await, BootstrapState::Ready);

    let identity = state.household.current().await.expect("identity loaded");
    assert!(identity.record.is_follower);
    assert!(identity.hh_priv.is_none());
    assert_eq!(identity.record.shamir_n, 0);
    assert_eq!(identity.cert.m_id.to_string(), accept.m_id);
    assert_eq!(
        household_rs::bootstrap_state::load(&state.state_dir).unwrap(),
        BootstrapState::Ready
    );

    let reloaded = household_rs::try_load_existing(
        &state.state_dir,
        household_rs::KeyBackingPolicy::ForceSoftware,
    )
    .unwrap()
    .expect("confirmed follower identity reloads");
    assert!(reloaded.record.is_follower);
    assert!(reloaded.hh_priv.is_none());

    let txt = HouseholdBonjour::txt_for_state(
        &PublishParams {
            hh_id,
            hh_name: identity.record.name.clone(),
            m_id: accept.m_id,
            port: 8091,
            host_label: "test-mac".to_string(),
            host_dns: "test-mac.local".to_string(),
            pair_machine_role: Some(PairMachineBonjourRole::Founder),
            owner_display_name: String::new(),
            device_count: 1,
            bootstrap_state: "ready".to_string(),
        },
        None,
        None,
    );
    assert_eq!(
        txt.get("bootstrap_state").map(String::as_str),
        Some("ready")
    );
}

#[tokio::test]
async fn accept_409_when_already_initialized_states() {
    let hh_key = P256Keypair::generate();
    let hh_id = derive_household_id(&hh_key.public()).to_string();
    for bs in [
        BootstrapState::NamedAwaitingPair,
        BootstrapState::Ready,
        BootstrapState::Recovering,
    ] {
        let state = make_state(bs, make_state_dir());
        let (status, body) = call_accept(
            state,
            cbor_accept(&hh_id, hh_key.public().as_bytes(), "Home", &token(1)),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(decode_err(&body).error, "already_initialized");
    }
}

#[tokio::test]
async fn confirm_409_without_pending_accept_state() {
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let (status, body) = call_confirm(state, b"not cbor".to_vec()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(decode_err(&body).error, "accept_household_not_pending");
}

#[tokio::test]
async fn accept_400_on_malformed_cbor() {
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let (status, body) = call_accept(state, b"not cbor".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(decode_err(&body).error, "invalid_cbor");
}

#[tokio::test]
async fn accept_400_on_unknown_top_level_key() {
    let hh_key = P256Keypair::generate();
    let hh_pub = hh_key.public();
    let hh_id = derive_household_id(&hh_pub).to_string();
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let invite = token(2);
    populate_invitation(&state, invite, &hh_id, unix_now() + 1800).await;
    let (status, body) = call_accept(
        state,
        cbor_accept_with_extra(&hh_id, hh_pub.as_bytes(), &invite),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(decode_err(&body).error, "invalid_cbor");
}

#[tokio::test]
async fn accept_404_on_unknown_invitation_token() {
    let hh_key = P256Keypair::generate();
    let hh_pub = hh_key.public();
    let hh_id = derive_household_id(&hh_pub).to_string();
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let (status, body) = call_accept(
        state,
        cbor_accept(&hh_id, hh_pub.as_bytes(), "Home", &token(3)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(decode_err(&body).error, "invitation_not_found");
}

#[tokio::test]
async fn accept_410_on_expired_token_and_overlong_ttl() {
    let hh_key = P256Keypair::generate();
    let hh_pub = hh_key.public();
    let hh_id = derive_household_id(&hh_pub).to_string();
    for (invite, expires_at) in [(token(4), 1), (token(5), unix_now() + 7200)] {
        let state = make_state(BootstrapState::Uninitialized, make_state_dir());
        populate_invitation(&state, invite, &hh_id, expires_at).await;
        let (status, body) = call_accept(
            state,
            cbor_accept(&hh_id, hh_pub.as_bytes(), "Home", &invite),
        )
        .await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(decode_err(&body).error, "invitation_expired_or_spent");
    }
}

#[tokio::test]
async fn accept_410_on_invitation_token_reuse() {
    let hh_key = P256Keypair::generate();
    let hh_pub = hh_key.public();
    let hh_id = derive_household_id(&hh_pub).to_string();
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let invite = token(6);
    populate_invitation(&state, invite, &hh_id, unix_now() + 1800).await;
    let body = cbor_accept(&hh_id, hh_pub.as_bytes(), "Home", &invite);
    assert_eq!(
        call_accept(state.clone(), body.clone()).await.0,
        StatusCode::OK
    );
    let (status, body) = call_accept(state, body).await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(decode_err(&body).error, "invitation_expired_or_spent");
}

#[tokio::test]
async fn accept_reinserts_invitation_token_when_prepare_fails() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");
    let hh_key = P256Keypair::generate();
    let hh_pub = hh_key.public();
    let hh_id = derive_household_id(&hh_pub).to_string();
    let state_dir = make_state_dir();
    let _existing = household_rs::bootstrap_or_load(
        &state_dir,
        BootstrapOpts {
            household_name: "Already Here".to_string(),
            hostname_label: Some("existing-mac".to_string()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .unwrap();
    let state = make_state(BootstrapState::Uninitialized, state_dir);
    let invite = token(10);
    populate_invitation(&state, invite, &hh_id, unix_now() + 1800).await;

    let (status, body) = call_accept(
        state.clone(),
        cbor_accept(&hh_id, hh_pub.as_bytes(), "Home", &invite),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(decode_err(&body).error, "keygen_failed");
    assert!(
        cache_lookup(&state.setup_invitation_cache, &invite)
            .await
            .is_some(),
        "transient prepare failure must not burn the one-time invitation token"
    );
}

#[tokio::test]
async fn accept_reinserts_invitation_token_on_advertised_household_mismatch() {
    let hh_key = P256Keypair::generate();
    let hh_id = derive_household_id(&hh_key.public()).to_string();
    let other_hh_id = derive_household_id(&P256Keypair::generate().public()).to_string();
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let invite = token(11);
    populate_invitation(&state, invite, &other_hh_id, unix_now() + 1800).await;

    let (status, body) = call_accept(
        state.clone(),
        cbor_accept(&hh_id, hh_key.public().as_bytes(), "Home", &invite),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(decode_err(&body).error, "crypto_validation_failed");
    assert!(
        cache_lookup(&state.setup_invitation_cache, &invite)
            .await
            .is_some(),
        "household mismatch after cache_take must not burn the invitation token"
    );
}

#[tokio::test]
async fn accept_422_on_invalid_hh_pub_length() {
    let hh_key = P256Keypair::generate();
    let hh_id = derive_household_id(&hh_key.public()).to_string();
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let invite = token(8);
    populate_invitation(&state, invite, &hh_id, unix_now() + 1800).await;
    let (status, body) =
        call_accept(state, cbor_accept(&hh_id, &[0x02; 32], "Home", &invite)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(decode_err(&body).error, "crypto_validation_failed");
}

#[tokio::test]
async fn accept_422_on_hh_id_hash_mismatch() {
    let hh_key = P256Keypair::generate();
    let other = P256Keypair::generate();
    let hh_id = derive_household_id(&other.public()).to_string();
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let invite = token(9);
    populate_invitation(&state, invite, &hh_id, unix_now() + 1800).await;
    let (status, body) = call_accept(
        state,
        cbor_accept(&hh_id, hh_key.public().as_bytes(), "Home", &invite),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(decode_err(&body).error, "crypto_validation_failed");
}

#[tokio::test]
async fn confirm_422_on_invalid_challenge_signature() {
    let (state, hh_key, hh_id, accept) = accepted_state().await;
    let cert = machine_cert_for_accept(&hh_key, &hh_id, &accept);
    let (status, body) = call_confirm(state, cbor_confirm(&accept.m_id, &cert, &[0_u8; 64])).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(decode_err(&body).error, "crypto_validation_failed");
}

#[tokio::test]
async fn confirm_422_on_machine_cert_subject_mismatch() {
    let (state, hh_key, hh_id, accept) = accepted_state().await;
    let wrong_m = P256Keypair::generate();
    let cert = MachineCert::sign(
        &hh_key,
        &wrong_m.public(),
        &SignOptions {
            hh_id: household_rs::HouseholdId::parse(hh_id).unwrap(),
            hostname: "test-mac".to_string(),
            platform: Platform::Macos,
            joined_at: unix_now(),
        },
    )
    .unwrap();
    let cert = household_rs::cbor::to_canonical_vec(&cert).unwrap();
    let sig = hh_key.sign(accept.join_challenge.as_ref()).unwrap();
    let (status, body) =
        call_confirm(state, cbor_confirm(&accept.m_id, &cert, sig.as_bytes())).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(decode_err(&body).error, "crypto_validation_failed");
}
