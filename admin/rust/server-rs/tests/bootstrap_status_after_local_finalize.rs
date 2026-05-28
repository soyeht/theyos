//! Regression coverage for the Linux pair-machine `/bootstrap/status`
//! staleness bug surfaced by the Claw Store E2E.
//!
//! Before the fix, `local_finalize_handler` persisted
//! `BootstrapState::Ready` to disk but did NOT update the in-memory
//! `Arc<RwLock<BootstrapState>>` that `GET /bootstrap/status` reads
//! from. The endpoint kept replying `"state":"uninitialized"` until the
//! daemon process restarted and re-read the on-disk flag at boot.
//!
//! This test mirrors the daemon wiring: it constructs ONE
//! `Arc<RwLock<BootstrapState>>`, mounts the pre-household router with
//! that lock plumbed via `PreHouseholdRouterState::bootstrap`, mounts
//! the bootstrap router with the SAME lock in `BootstrapHandlerState`,
//! drives a successful local finalize, and then asserts
//! `GET /bootstrap/status` returns `state: "ready"` — without any
//! restart, without reloading state from disk.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use core_rs::env::set_test_env;
use household_rs::bootstrap_state::BootstrapState;
use household_rs::machine_cert::Platform;
use household_rs::pair_device::PairDeviceWindow;
use household_rs::pair_machine::{
    CeremonyInputs, CeremonyTxn, JoinResponse, JoinResponseUnsigned, JoinTransport,
    PairMachineWindow, PeerEntry, PrepareCandidateOpts, join_request_hash, prepare_candidate,
};
use household_rs::{BootstrapOpts, KeyBackingPolicy};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use server_rs::handlers_bootstrap::{BootstrapHandlerState, BootstrapStateArc, bootstrap_router};
use server_rs::handlers_pair_machine::{PreHouseholdRouterState, pre_household_router};
use server_rs::household_state::HouseholdState;
use tokio::sync::RwLock;
use tower::ServiceExt;
use zeroize::Zeroizing;

const FINALIZE_PATH: &str = "/pair-machine/local/finalize";
const STATUS_PATH: &str = "/bootstrap/status";

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn no_tailnet() -> Option<std::net::Ipv4Addr> {
    None
}

fn bootstrap(state_dir: &std::path::Path) -> household_rs::LoadedIdentity {
    household_rs::bootstrap_or_load(
        state_dir,
        BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some("studio-test".into()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .unwrap()
}

fn build_join_response(
    m1_state_dir: &std::path::Path,
    m1: &household_rs::LoadedIdentity,
    prepared: &household_rs::pair_machine::PreparedCandidate,
) -> JoinResponse {
    let txn = CeremonyTxn::prepare(CeremonyInputs {
        hh_priv: Zeroizing::new(
            *m1.hh_priv
                .as_ref()
                .and_then(|k| k.as_software_secret())
                .expect("software hh_priv pre-Shamir"),
        ),
        hh_id: m1.record.hh_id.clone(),
        hh_pub_sec1: *m1.record.hh_pub.as_bytes(),
        m1_priv_scalar: Zeroizing::new(*m1.m_priv.as_software_secret().unwrap()),
        m1_pub_sec1: *m1.cert.m_pub.as_bytes(),
        m1_id: m1.cert.m_id.to_string(),
        candidate_m_pub_sec1: prepared.m_pub_sec1,
        candidate_hostname: prepared.join_request.hostname.clone(),
        candidate_platform: prepared.join_request.platform.clone(),
        joined_at: unix_now(),
        state_dir: m1_state_dir.to_path_buf(),
        existing_record: m1.record.clone(),
        policy: KeyBackingPolicy::ForceSoftware,
    })
    .unwrap();
    JoinResponseUnsigned {
        version: 1,
        join_request_hash: ByteBuf::from(join_request_hash(&prepared.join_request_cbor).to_vec()),
        machine_cert: txn.candidate_cert().clone(),
        encrypted_shard: txn.peer_encrypted_shard().clone(),
        household_record: txn.new_household_record().clone(),
        peer_list: vec![PeerEntry {
            m_id: m1.cert.m_id.to_string(),
            m_pub: ByteBuf::from(m1.cert.m_pub.as_bytes().to_vec()),
            hostname: m1.cert.hostname.clone(),
            tailscale_addr: None,
            machine_cert: Some(m1.cert.clone()),
        }],
        push_token_seed: None,
    }
    .sign(m1.m_priv.as_ref())
    .unwrap()
}

fn make_bootstrap_handler_state(
    bs: BootstrapStateArc,
    state_dir: PathBuf,
    window: Arc<PairMachineWindow>,
) -> BootstrapHandlerState {
    BootstrapHandlerState {
        bootstrap: bs,
        household: HouseholdState::empty(),
        state_dir,
        pair_device_window: Arc::new(PairDeviceWindow::new()),
        pair_machine_window: window,
        started_at: Instant::now(),
        setup_invitation_cache: server_rs::setup_invitation::new_cache(),
        engine_port: 8091,
        tailnet_resolver: no_tailnet,
    }
}

#[derive(Deserialize)]
struct BootstrapStatusBody {
    state: String,
}

async fn get_bootstrap_status_state(handler_state: BootstrapHandlerState) -> String {
    let app = bootstrap_router(handler_state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(STATUS_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "/bootstrap/status must be 200"
    );
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body: BootstrapStatusBody = serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("decode /bootstrap/status JSON: {e} body={bytes:?}"));
    body.state
}

#[tokio::test]
async fn bootstrap_status_flips_to_ready_immediately_after_local_finalize() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");

    // ── M1 (founder) and M2 (candidate) state dirs ─────────────────────
    let m1_dir = tempfile::tempdir().unwrap();
    let m2_dir = tempfile::tempdir().unwrap();
    let m1 = bootstrap(m1_dir.path());

    // ── M2's pair-machine window + the SHARED bootstrap RwLock ─────────
    // The shared lock is the whole point of this test: the daemon wires
    // the SAME Arc<RwLock<BootstrapState>> into both routers, and
    // local_finalize_handler must update it in place for /bootstrap/status
    // to surface the transition without a process restart.
    let window =
        Arc::new(PairMachineWindow::with_persistence(m2_dir.path().to_path_buf()).unwrap());
    let shared_bootstrap: BootstrapStateArc = Arc::new(RwLock::new(BootstrapState::Uninitialized));

    let prepared = prepare_candidate(
        &window,
        PrepareCandidateOpts {
            state_dir: m2_dir.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: "127.0.0.1:8091".into(),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: Duration::from_secs(300),
            now_unix: unix_now(),
        },
    )
    .await
    .unwrap();

    let join_response = build_join_response(m1_dir.path(), &m1, &prepared);
    let join_response_bytes = join_response.to_canonical_bytes().unwrap();

    // Simulate the iPhone delivering POST /pair-machine/local/anchor.
    window
        .pin_household_anchor(m1.record.hh_id.to_string(), *m1.record.hh_pub.as_bytes())
        .await
        .unwrap();

    // ── Build BOTH routers backed by the same lock ────────────────────
    let pre_household = pre_household_router(PreHouseholdRouterState {
        window: Arc::clone(&window),
        state_dir: m2_dir.path().to_path_buf(),
        key_policy: KeyBackingPolicy::ForceSoftware,
        bootstrap: Some(Arc::clone(&shared_bootstrap)),
    });
    let handler_state_pre = make_bootstrap_handler_state(
        Arc::clone(&shared_bootstrap),
        m2_dir.path().to_path_buf(),
        Arc::clone(&window),
    );

    // ── Sanity: /bootstrap/status starts at uninitialized ─────────────
    assert_eq!(
        get_bootstrap_status_state(handler_state_pre).await,
        "uninitialized",
        "pre-finalize sanity check"
    );

    // ── Drive the finalize ────────────────────────────────────────────
    let resp = pre_household
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(FINALIZE_PATH)
                .header("content-type", "application/cbor")
                .body(Body::from(join_response_bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "finalize must succeed; body={}",
        String::from_utf8_lossy(&bytes),
    );

    // ── The critical assertion: status flips to "ready" WITHOUT restart ─
    // Build a fresh BootstrapHandlerState pointing at the SAME shared
    // bootstrap lock and call GET /bootstrap/status. The endpoint reads
    // from the in-memory RwLock; if the fix is missing, this assertion
    // observes the regression with no waiting, no retries, no restart.
    let handler_state_post = make_bootstrap_handler_state(
        Arc::clone(&shared_bootstrap),
        m2_dir.path().to_path_buf(),
        Arc::clone(&window),
    );
    let observed = get_bootstrap_status_state(handler_state_post).await;
    assert_eq!(
        observed, "ready",
        "GET /bootstrap/status should report ready immediately after local finalize, \
         no restart required; observed: {observed:?}"
    );
}

#[tokio::test]
async fn local_finalize_with_bootstrap_none_does_not_panic() {
    // The CLI install path (`theyos install --pair-machine`) wires the
    // pre-household router with `bootstrap: None` because the install
    // binary IS the pre-household phase by construction — there's no
    // running daemon and no live status endpoint. The in-memory bootstrap
    // flip in local_finalize_handler must therefore be guarded by
    // `if let Some(bs_lock) = state.bootstrap.as_ref()` and must NOT
    // panic on the None path.
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");

    let m1_dir = tempfile::tempdir().unwrap();
    let m2_dir = tempfile::tempdir().unwrap();
    let m1 = bootstrap(m1_dir.path());
    let window =
        Arc::new(PairMachineWindow::with_persistence(m2_dir.path().to_path_buf()).unwrap());

    let prepared = prepare_candidate(
        &window,
        PrepareCandidateOpts {
            state_dir: m2_dir.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: "127.0.0.1:8091".into(),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: Duration::from_secs(300),
            now_unix: unix_now(),
        },
    )
    .await
    .unwrap();

    let join_response = build_join_response(m1_dir.path(), &m1, &prepared);
    let join_response_bytes = join_response.to_canonical_bytes().unwrap();
    window
        .pin_household_anchor(m1.record.hh_id.to_string(), *m1.record.hh_pub.as_bytes())
        .await
        .unwrap();

    let router = pre_household_router(PreHouseholdRouterState {
        window: Arc::clone(&window),
        state_dir: m2_dir.path().to_path_buf(),
        key_policy: KeyBackingPolicy::ForceSoftware,
        bootstrap: None,
    });

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(FINALIZE_PATH)
                .header("content-type", "application/cbor")
                .body(Body::from(join_response_bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "CLI install path (bootstrap: None) must complete without panic"
    );
}
