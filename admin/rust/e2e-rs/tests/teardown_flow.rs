//! T075 — Integration test: teardown flow (state machine reset).
//!
//! Exercises `POST /bootstrap/teardown` end-to-end against an in-process
//! engine. Validates:
//!
//! 1. Ready → teardown → Uninitialized (in-memory + persisted).
//! 2. `GET /bootstrap/status` reflects `uninitialized` after teardown.
//! 3. Second teardown returns 409 (state gate: uninitialized not valid).
//! 4. `NamedAwaitingPair` → teardown succeeds without owner cert (R5-E bypass).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
};
use core_rs::env::set_test_env;
use household_rs::bootstrap_state::BootstrapState;
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::machine_cert::{SignOptions, save_self_cert};
use household_rs::pair_device::PairDeviceWindow;
use household_rs::person_cert::SignOwnerOptions;
use household_rs::storage::{atomic_write_cbor, household_record_path};
use household_rs::{
    HouseholdAuthState, HouseholdRecord, LoadedIdentity, MachineCert, PersonCert, Platform,
    derive_household_id, derive_machine_id,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use server_rs::handlers_bootstrap::{BootstrapHandlerState, BootstrapStateArc, bootstrap_router};
use server_rs::household_state::HouseholdState;
use tokio::sync::RwLock;
use tower::ServiceExt;

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
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
    _version: u8,
    torn_at: u64,
}

// ── Fixture ───────────────────────────────────────────────────────────────────

struct Fixture {
    state_dir: PathBuf,
    hh_id: String,
    m_id: String,
    owner_key: P256Keypair,
    identity: Arc<LoadedIdentity>,
    bs_arc: BootstrapStateArc,
    _tempdir: PathBuf,
}

fn make_fixture(bs: BootstrapState) -> Fixture {
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
        name: "Flow Test Home".to_string(),
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
    auth_state.save(&state_dir).unwrap();
    // `teardown_household_on_disk` decides household existence from disk
    // (`household_lifecycle.rs::household_exists`), not from the in-memory
    // identity below — sibling fixtures (phase1_identity_chain,
    // phase3_generic_failures, phase3_support) already persist this.
    atomic_write_cbor(&household_record_path(&state_dir), &record).unwrap();
    // The disk-side recheck also loads the self machine cert
    // (`verify_installed_household_for_teardown` -> `load_self_cert`), which
    // needs both the cert file and the `self_m_id` marker `save_self_cert`
    // writes together.
    save_self_cert(&state_dir, &machine_cert).unwrap();

    let identity = Arc::new(LoadedIdentity {
        record,
        cert: machine_cert,
        hh_priv: None,
        m_priv: Box::new(m_key),
        backing: "software",
    });

    Fixture {
        state_dir,
        hh_id: hh_id.to_string(),
        m_id: m_id.to_string(),
        owner_key,
        identity,
        bs_arc: Arc::new(RwLock::new(bs)),
        _tempdir: tmpdir,
    }
}

fn make_app(fix: &Fixture) -> Router {
    let handler_state = BootstrapHandlerState {
        bootstrap: Arc::clone(&fix.bs_arc),
        household: HouseholdState::loaded(Arc::clone(&fix.identity)),
        state_dir: fix.state_dir.clone(),
        pair_device_window: Arc::new(PairDeviceWindow::new()),
        pair_machine_window: Arc::new(
            household_rs::pair_machine::PairMachineWindow::new_in_memory(),
        ),
        started_at: Instant::now(),
        setup_invitation_cache: server_rs::setup_invitation::new_cache(),
        engine_port: 8091,
        tailnet_resolver: || None,
        phase3_runtime: None,
        pair_code_rate_limiter: None,
    };
    bootstrap_router(handler_state)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn nonce(seed: u8) -> [u8; 32] {
    let mut n = [0u8; 32];
    n[0] = seed;
    n[1] = 0xCD;
    n
}

fn signed_teardown(fix: &Fixture, ts: u64, nonce_bytes: [u8; 32]) -> Bytes {
    let signed_by = ByteBuf::from(fix.owner_key.public().as_bytes().to_vec());
    let payload = TeardownPayload {
        version: 1,
        op: "teardown".into(),
        hh_id: fix.hh_id.clone(),
        m_id: fix.m_id.clone(),
        nonce: ByteBuf::from(nonce_bytes.to_vec()),
        ts,
        signed_by: signed_by.clone(),
    };
    let msg = household_rs::cbor::to_canonical_vec(&payload).unwrap();
    let sig = fix.owner_key.sign(&msg).unwrap();
    let req = TeardownRequest {
        version: 1,
        op: "teardown".into(),
        hh_id: fix.hh_id.clone(),
        m_id: fix.m_id.clone(),
        nonce: ByteBuf::from(nonce_bytes.to_vec()),
        ts,
        signed_by,
        signature: ByteBuf::from(sig.as_bytes().to_vec()),
    };
    Bytes::from(household_rs::cbor::to_canonical_vec(&req).unwrap())
}

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

async fn get_status(app: Router) -> serde_json::Value {
    let req = Request::builder()
        .uri("/bootstrap/status")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Full teardown round-trip: Ready → Uninitialized (in-memory + persisted).
#[tokio::test]
async fn teardown_flow_ready_state_resets_to_uninitialized() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");

    let fix = make_fixture(BootstrapState::Ready);
    let ts = now();

    let app = make_app(&fix);
    let body = signed_teardown(&fix, ts, nonce(1));
    let (status, resp_bytes) = post_teardown(app, body).await;
    assert_eq!(status, StatusCode::OK, "teardown must succeed from Ready");

    let ack: TeardownAck = household_rs::cbor::from_canonical_slice(&resp_bytes)
        .expect("TeardownAck must be valid CBOR");
    assert!(ack.torn_at > 0, "torn_at must be non-zero");

    // In-memory state.
    assert_eq!(*fix.bs_arc.read().await, BootstrapState::Uninitialized);

    // Persisted state.
    let persisted = household_rs::bootstrap_state::load(&fix.state_dir).unwrap();
    assert_eq!(persisted, BootstrapState::Uninitialized);

    // household/ dir must be gone (renamed by the handler).
    assert!(
        !fix.state_dir.join("household").exists(),
        "household/ should be renamed away"
    );
}

/// Status endpoint reflects `uninitialized` after teardown.
#[tokio::test]
async fn teardown_flow_status_shows_uninitialized_after_teardown() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");

    let fix = make_fixture(BootstrapState::Ready);
    let ts = now();

    // Teardown.
    let app = make_app(&fix);
    let (status, _) = post_teardown(app, signed_teardown(&fix, ts, nonce(2))).await;
    assert_eq!(status, StatusCode::OK);

    // Status shows uninitialized.
    let app = make_app(&fix);
    let body = get_status(app).await;
    assert_eq!(body["state"], "uninitialized");
    assert!(body["hh_id"].is_null(), "hh_id must be null after teardown");
}

/// Second teardown returns 409 — state gate rejects uninitialized.
#[tokio::test]
async fn teardown_flow_second_call_returns_409() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");

    let fix = make_fixture(BootstrapState::Ready);
    let ts = now();

    // First teardown — succeeds.
    let app = make_app(&fix);
    let (status, _) = post_teardown(app, signed_teardown(&fix, ts, nonce(3))).await;
    assert_eq!(status, StatusCode::OK);

    // Second teardown — state gate rejects it.
    let app = make_app(&fix);
    let (status, _) = post_teardown(app, signed_teardown(&fix, ts, nonce(4))).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "second teardown must return 409"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_teardown_allows_exactly_one_success() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");

    let fix = make_fixture(BootstrapState::Ready);
    let ts = now();
    let app = make_app(&fix);
    let barrier = Arc::new(tokio::sync::Barrier::new(17));

    let mut tasks = Vec::new();
    for idx in 0..16 {
        let app = app.clone();
        let body = signed_teardown(&fix, ts, nonce((idx + 10) as u8));
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            post_teardown(app, body).await.0
        }));
    }
    barrier.wait().await;

    let mut ok = 0;
    let mut conflict = 0;
    for task in tasks {
        match task.await.unwrap() {
            StatusCode::OK => ok += 1,
            StatusCode::CONFLICT => conflict += 1,
            other => panic!("unexpected teardown status {other}"),
        }
    }
    assert_eq!(ok, 1, "exactly one teardown transaction may win");
    assert_eq!(
        conflict, 15,
        "all losing races must observe torn-down state"
    );
}

/// `NamedAwaitingPair` teardown succeeds without owner cert (R5-E: cert+sig skipped).
#[tokio::test]
async fn teardown_flow_named_awaiting_pair_no_cert_required() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");

    let fix = make_fixture(BootstrapState::NamedAwaitingPair);
    let ts = now();

    let app = make_app(&fix);
    let body = signed_teardown(&fix, ts, nonce(5));
    let (status, _) = post_teardown(app, body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "teardown from NamedAwaitingPair must succeed without cert"
    );

    assert_eq!(*fix.bs_arc.read().await, BootstrapState::Uninitialized);
}
