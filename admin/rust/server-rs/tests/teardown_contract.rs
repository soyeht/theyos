//! T074 — Contract tests for `POST /bootstrap/teardown`.
//!
//! Coverage per `contracts/bootstrap-teardown.md` validation order:
//!
//! - 409 when engine state is not in {`named_awaiting_pair`, ready, recovering}
//! - 400 on non-decodable CBOR body
//! - 400 on op != "teardown"
//! - 400 on malformed field (wrong `signed_by` or `nonce` byte length)
//! - 401 on `ts` skew > 300 s
//! - 401 on nonce replay (nonce used twice)
//! - 401 when `signed_by` not in owner cert set (unknown `D_pub`)
//! - 401 on signature mismatch (tampered body)
//! - 200 success — correct `TeardownAck` shape, state resets to uninitialized

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
};
use household_rs::bootstrap_state::BootstrapState;
use household_rs::machine_cert::SignOptions;
use household_rs::pair_device::PairDeviceWindow;
use household_rs::person_cert::SignOwnerOptions;
use household_rs::{
    HouseholdAuthState, HouseholdRecord, IdentityKey, LoadedIdentity, MachineCert, P256Keypair,
    PersonCert, Platform, derive_household_id, derive_machine_id,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use server_rs::handlers_bootstrap::{BootstrapHandlerState, BootstrapStateArc, bootstrap_router};
use server_rs::household_state::HouseholdState;
use tokio::sync::RwLock;
use tower::ServiceExt;

// ── Wire types (mirror of handlers_bootstrap private types) ───────────────────

#[derive(Serialize, Deserialize)]
struct TeardownPayload {
    #[serde(rename = "v")]
    version: u8,
    op: String,
    hh_id: String,
    m_id: String,
    nonce: ByteBuf,
    ts: u64,
    signed_by: ByteBuf,
}

#[derive(Serialize, Deserialize)]
struct TeardownRequest {
    #[serde(rename = "v")]
    version: u8,
    op: String,
    hh_id: String,
    m_id: String,
    nonce: ByteBuf,
    ts: u64,
    signed_by: ByteBuf,
    signature: ByteBuf,
}

#[derive(Deserialize)]
struct TeardownAck {
    #[serde(rename = "v")]
    version: u8,
    torn_at: u64,
}

// ── Test fixture ──────────────────────────────────────────────────────────────

struct Fixture {
    state_dir: PathBuf,
    hh_id: String,
    m_id: String,
    owner_key: P256Keypair,
    _tempdir: PathBuf,
}

/// Like `make_fixture` but skips `auth_state.save()` — state dir has NO owner
/// cert on disk. Used to verify the `NamedAwaitingPair` bypass invariant: teardown
/// must succeed without a cert when the state machine is pre-pairing.
///
/// Only valid for `NamedAwaitingPair` — the bypass only exists for that state.
fn make_fixture_no_auth(bs: BootstrapState) -> (Fixture, Router) {
    assert!(
        matches!(bs, BootstrapState::NamedAwaitingPair),
        "make_fixture_no_auth is for NamedAwaitingPair only (got {bs:?})"
    );
    let hh_key = P256Keypair::generate();
    let owner_key = P256Keypair::generate();
    let m_key = P256Keypair::generate();

    let hh_pub = hh_key.public();
    let hh_id = derive_household_id(&hh_pub);
    let m_pub = m_key.public();
    let m_id = derive_machine_id(&m_pub);

    let record = HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: hh_id.clone(),
        hh_pub: hh_pub.clone(),
        name: "Test Home".to_string(),
        shamir_n: 1,
        shamir_k: 1,
        members: vec![m_id.clone()],
        created_at: 1_000,
        is_follower: false,
    };

    let machine_cert = MachineCert::sign(
        &hh_key as &dyn IdentityKey,
        &m_pub,
        &SignOptions {
            hh_id: hh_id.clone(),
            hostname: "test-machine".to_string(),
            platform: Platform::Macos,
            joined_at: 1_000,
        },
    )
    .expect("machine cert");

    let tmpdir = tempfile::tempdir().unwrap().keep();
    let state_dir = tmpdir.clone();
    std::fs::create_dir_all(state_dir.join("household")).unwrap();
    household_rs::storage::atomic_write_cbor(
        &household_rs::storage::household_record_path(&state_dir),
        &record,
    )
    .unwrap();
    household_rs::machine_cert::save_self_cert(&state_dir, &machine_cert).unwrap();
    // Intentionally no auth_state.save() — state_dir has no owner cert on disk.

    let identity = Arc::new(LoadedIdentity {
        record,
        cert: machine_cert,
        hh_priv: None,
        m_priv: Box::new(m_key),
        backing: "software",
    });

    let handler_state = BootstrapHandlerState {
        bootstrap: Arc::new(RwLock::new(bs)) as BootstrapStateArc,
        household: HouseholdState::loaded(identity),
        state_dir: state_dir.clone(),
        pair_device_window: Arc::new(PairDeviceWindow::new()),
        pair_machine_window: Arc::new(
            household_rs::pair_machine::PairMachineWindow::new_in_memory(),
        ),
        started_at: Instant::now(),
        setup_invitation_cache: server_rs::setup_invitation::new_cache(),
        engine_port: 8091,
        tailnet_resolver: || None,
    };

    let app = bootstrap_router(handler_state);

    let fixture = Fixture {
        state_dir,
        hh_id: hh_id.to_string(),
        m_id: m_id.to_string(),
        owner_key,
        _tempdir: tmpdir,
    };

    (fixture, app)
}

fn make_fixture(bs: BootstrapState) -> (Fixture, Router) {
    let hh_key = P256Keypair::generate();
    let owner_key = P256Keypair::generate();
    let m_key = P256Keypair::generate();

    let hh_pub = hh_key.public();
    let hh_id = derive_household_id(&hh_pub);
    let m_pub = m_key.public();
    let m_id = derive_machine_id(&m_pub);

    let record = HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: hh_id.clone(),
        hh_pub: hh_pub.clone(),
        name: "Test Home".to_string(),
        shamir_n: 1,
        shamir_k: 1,
        members: vec![m_id.clone()],
        created_at: 1_000,
        is_follower: false,
    };

    let machine_cert = MachineCert::sign(
        &hh_key as &dyn IdentityKey,
        &m_pub,
        &SignOptions {
            hh_id: hh_id.clone(),
            hostname: "test-machine".to_string(),
            platform: Platform::Macos,
            joined_at: 1_000,
        },
    )
    .expect("machine cert");

    let owner_cert = PersonCert::sign_owner(
        &hh_key as &dyn IdentityKey,
        SignOwnerOptions {
            hh_id: hh_id.clone(),
            p_pub: owner_key.public(),
            display_name: "Owner".to_string(),
            issued_at: 1_000,
        },
    )
    .expect("owner cert");

    let auth_state = HouseholdAuthState::new(&record, owner_cert);

    let tmpdir = tempfile::tempdir().unwrap().keep();
    let state_dir = tmpdir.clone();
    std::fs::create_dir_all(state_dir.join("household")).unwrap();
    household_rs::storage::atomic_write_cbor(
        &household_rs::storage::household_record_path(&state_dir),
        &record,
    )
    .unwrap();
    household_rs::machine_cert::save_self_cert(&state_dir, &machine_cert).unwrap();
    auth_state.save(&state_dir).unwrap();

    let identity = Arc::new(LoadedIdentity {
        record,
        cert: machine_cert,
        hh_priv: None,
        m_priv: Box::new(m_key),
        backing: "software",
    });

    let handler_state = BootstrapHandlerState {
        bootstrap: Arc::new(RwLock::new(bs)) as BootstrapStateArc,
        household: HouseholdState::loaded(identity),
        state_dir: state_dir.clone(),
        pair_device_window: Arc::new(PairDeviceWindow::new()),
        pair_machine_window: Arc::new(
            household_rs::pair_machine::PairMachineWindow::new_in_memory(),
        ),
        started_at: Instant::now(),
        setup_invitation_cache: server_rs::setup_invitation::new_cache(),
        engine_port: 8091,
        tailnet_resolver: || None,
    };

    let app = bootstrap_router(handler_state);

    let fixture = Fixture {
        state_dir,
        hh_id: hh_id.to_string(),
        m_id: m_id.to_string(),
        owner_key,
        _tempdir: tmpdir,
    };

    (fixture, app)
}

// ── Request builder ───────────────────────────────────────────────────────────

fn build_request(
    hh_id: &str,
    m_id: &str,
    ts: u64,
    nonce: [u8; 32],
    owner_key: &P256Keypair,
) -> Bytes {
    let signed_by = ByteBuf::from(owner_key.public().as_bytes().to_vec());
    let payload = TeardownPayload {
        version: 1,
        op: "teardown".into(),
        hh_id: hh_id.into(),
        m_id: m_id.into(),
        nonce: ByteBuf::from(nonce.to_vec()),
        ts,
        signed_by: signed_by.clone(),
    };
    let msg = household_rs::cbor::to_canonical_vec(&payload).unwrap();
    let sig = owner_key.sign(&msg).unwrap();
    let req = TeardownRequest {
        version: 1,
        op: "teardown".into(),
        hh_id: hh_id.into(),
        m_id: m_id.into(),
        nonce: ByteBuf::from(nonce.to_vec()),
        ts,
        signed_by,
        signature: ByteBuf::from(sig.as_bytes().to_vec()),
    };
    Bytes::from(household_rs::cbor::to_canonical_vec(&req).unwrap())
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

async fn post_teardown(app: Router, body: Bytes) -> (StatusCode, Bytes) {
    let req = Request::builder()
        .method("POST")
        .uri("/bootstrap/teardown")
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, body)
}

// Stable test nonce (different per test to avoid cross-test replay collisions).
fn nonce(seed: u8) -> [u8; 32] {
    let mut n = [0u8; 32];
    n[0] = seed;
    n[1] = 0xAB;
    n
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn state_gate_uninitialized_returns_409() {
    let (fix, app) = make_fixture(BootstrapState::Uninitialized);
    let body = build_request(&fix.hh_id, &fix.m_id, 1_000, nonce(1), &fix.owner_key);
    let (status, _) = post_teardown(app, body).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn state_gate_ready_for_naming_returns_409() {
    let (fix, app) = make_fixture(BootstrapState::ReadyForNaming);
    let body = build_request(&fix.hh_id, &fix.m_id, 1_000, nonce(2), &fix.owner_key);
    let (status, _) = post_teardown(app, body).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn bad_cbor_returns_400() {
    let (_, app) = make_fixture(BootstrapState::Ready);
    let garbage = Bytes::from(b"\xFF\xFE\x00\x01" as &[u8]);
    let (status, _) = post_teardown(app, garbage).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn wrong_op_returns_400() {
    let (fix, app) = make_fixture(BootstrapState::Ready);
    let signed_by = ByteBuf::from(fix.owner_key.public().as_bytes().to_vec());
    let payload = TeardownPayload {
        version: 1,
        op: "not_teardown".into(),
        hh_id: fix.hh_id.clone(),
        m_id: fix.m_id.clone(),
        nonce: ByteBuf::from(nonce(3).to_vec()),
        ts: 1_000,
        signed_by: signed_by.clone(),
    };
    let msg = household_rs::cbor::to_canonical_vec(&payload).unwrap();
    let sig = fix.owner_key.sign(&msg).unwrap();
    let req = TeardownRequest {
        version: 1,
        op: "not_teardown".into(),
        hh_id: fix.hh_id,
        m_id: fix.m_id,
        nonce: ByteBuf::from(nonce(3).to_vec()),
        ts: 1_000,
        signed_by,
        signature: ByteBuf::from(sig.as_bytes().to_vec()),
    };
    let body = Bytes::from(household_rs::cbor::to_canonical_vec(&req).unwrap());
    let (status, _) = post_teardown(app, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn wrong_signed_by_size_returns_400() {
    let (fix, app) = make_fixture(BootstrapState::Ready);
    // signed_by must be exactly 33 bytes (SEC1-compressed P-256); send 32.
    let short_key = ByteBuf::from(vec![0u8; 32]);
    let req = TeardownRequest {
        version: 1,
        op: "teardown".into(),
        hh_id: fix.hh_id,
        m_id: fix.m_id,
        nonce: ByteBuf::from(nonce(4).to_vec()),
        ts: 1_000,
        signed_by: short_key,
        signature: ByteBuf::from(vec![0u8; 64]),
    };
    let body = Bytes::from(household_rs::cbor::to_canonical_vec(&req).unwrap());
    let (status, _) = post_teardown(app, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn wrong_nonce_size_returns_400() {
    let (fix, app) = make_fixture(BootstrapState::Ready);
    let signed_by = ByteBuf::from(fix.owner_key.public().as_bytes().to_vec());
    let req = TeardownRequest {
        version: 1,
        op: "teardown".into(),
        hh_id: fix.hh_id,
        m_id: fix.m_id,
        nonce: ByteBuf::from(vec![0u8; 16]), // wrong — must be 32
        ts: 1_000,
        signed_by,
        signature: ByteBuf::from(vec![0u8; 64]),
    };
    let body = Bytes::from(household_rs::cbor::to_canonical_vec(&req).unwrap());
    let (status, _) = post_teardown(app, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ts_skew_too_large_returns_401() {
    let (fix, app) = make_fixture(BootstrapState::Ready);
    // ts = 0, now ≈ unix epoch + however long the test runner has been alive.
    // Use a ts 400s in the past to guarantee skew > 300s.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let stale_ts = now.saturating_sub(400);
    let body = build_request(&fix.hh_id, &fix.m_id, stale_ts, nonce(5), &fix.owner_key);
    let (status, _) = post_teardown(app, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn nonce_replay_returns_401() {
    let (fix, app) = make_fixture(BootstrapState::NamedAwaitingPair);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let replay_nonce = nonce(6);

    // Pre-seed the nonce cache so the handler sees it as already used.
    server_rs::nonce_cache::check_and_persist(&fix.state_dir, &replay_nonce, now).unwrap();

    let body = build_request(&fix.hh_id, &fix.m_id, now, replay_nonce, &fix.owner_key);
    let (status, _) = post_teardown(app, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_signer_returns_401() {
    let (fix, app) = make_fixture(BootstrapState::Ready);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Use a different key — not in the owner cert set.
    let attacker_key = P256Keypair::generate();
    let body = build_request(&fix.hh_id, &fix.m_id, now, nonce(7), &attacker_key);
    let (status, _) = post_teardown(app, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn tampered_signature_returns_401() {
    let (fix, app) = make_fixture(BootstrapState::Recovering);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Build a valid payload but flip a signature byte.
    let signed_by = ByteBuf::from(fix.owner_key.public().as_bytes().to_vec());
    let payload = TeardownPayload {
        version: 1,
        op: "teardown".into(),
        hh_id: fix.hh_id.clone(),
        m_id: fix.m_id.clone(),
        nonce: ByteBuf::from(nonce(8).to_vec()),
        ts: now,
        signed_by: signed_by.clone(),
    };
    let msg = household_rs::cbor::to_canonical_vec(&payload).unwrap();
    let mut sig_bytes = *fix.owner_key.sign(&msg).unwrap().as_bytes();
    sig_bytes[0] ^= 0xFF; // tamper
    let req = TeardownRequest {
        version: 1,
        op: "teardown".into(),
        hh_id: fix.hh_id,
        m_id: fix.m_id,
        nonce: ByteBuf::from(nonce(8).to_vec()),
        ts: now,
        signed_by,
        signature: ByteBuf::from(sig_bytes.to_vec()),
    };
    let body = Bytes::from(household_rs::cbor::to_canonical_vec(&req).unwrap());
    let (status, _) = post_teardown(app, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn valid_request_returns_200_and_resets_state() {
    let (fix, app) = make_fixture(BootstrapState::Ready);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let body = build_request(&fix.hh_id, &fix.m_id, now, nonce(9), &fix.owner_key);
    let (status, resp_bytes) = post_teardown(app, body).await;
    assert_eq!(status, StatusCode::OK, "expected 200, got {status}");

    let ack: TeardownAck = household_rs::cbor::from_canonical_slice(&resp_bytes)
        .expect("TeardownAck must be valid CBOR");
    assert_eq!(ack.version, 1);
    assert!(ack.torn_at > 0);

    // Household directory must be gone (renamed away by the handler).
    assert!(
        !fix.state_dir.join("household").exists(),
        "household/ should be renamed"
    );
}

/// R6-D: Verify that teardown succeeds in `NamedAwaitingPair` state even when
/// there is NO owner cert on disk. This exercises the bypass invariant: the
/// cert+sig check must be skipped entirely (not just found-and-passed) for the
/// pre-pairing state. `make_fixture_no_auth` guarantees no cert is written.
#[tokio::test]
async fn named_awaiting_pair_teardown_succeeds_without_cert_on_disk() {
    let (fix, app) = make_fixture_no_auth(BootstrapState::NamedAwaitingPair);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let body = build_request(&fix.hh_id, &fix.m_id, now, nonce(10), &fix.owner_key);
    let (status, resp_bytes) = post_teardown(app, body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200 — bypass must work without cert on disk"
    );

    let ack: TeardownAck = household_rs::cbor::from_canonical_slice(&resp_bytes)
        .expect("TeardownAck must be valid CBOR");
    assert_eq!(ack.version, 1);
    assert!(ack.torn_at > 0);
}
