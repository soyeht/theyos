//! Regression coverage for candidate-install lifecycle rotation.
//!
//! The process that commits the candidate install owns G0-scoped router and
//! window capabilities. Once the durable transaction rotates G0→G1 it must
//! return `restart_required`, publish only `Recovering`, and never serve a
//! `FinalizeAck`. A genuinely fresh G1 router may then replay the exact
//! retained Ack and publish Ready. These tests exercise both halves.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use core_rs::env::set_test_env;
use household_rs::bootstrap_state::BootstrapState;
use household_rs::household_lifecycle::HouseholdLifecycleLock;
use household_rs::machine_cert::Platform;
use household_rs::pair_device::PairDeviceWindow;
use household_rs::pair_machine::{
    CeremonyInputs, CeremonyTxn, FinalizeAck, JoinResponse, JoinResponseUnsigned, JoinTransport,
    PairMachineWindow, PeerEntry, PrepareCandidateOpts, join_request_hash, prepare_candidate,
};
use household_rs::{BootstrapOpts, KeyBackingPolicy};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use server_rs::handlers_bootstrap::{BootstrapHandlerState, BootstrapStateArc, bootstrap_router};
use server_rs::handlers_pair_machine::{
    PreHouseholdRouterState, PreHouseholdRuntimeSignal, pre_household_router,
};
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
        installation: server_rs::pairing_addresses::PairingInstallation::new("release".into(), 8091),
        invitation_verifier: server_rs::setup_invitation::callback_verify_blocking,
        phase3_runtime: None,
        pair_code_rate_limiter: None,
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
async fn only_a_fresh_g1_router_publishes_ready_and_replays_the_exact_ack() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");

    // ── M1 (founder) and M2 (candidate) state dirs ─────────────────────
    let m1_dir = tempfile::tempdir().unwrap();
    let m2_dir = tempfile::tempdir().unwrap();
    let m1 = bootstrap(m1_dir.path());

    // The first router and window retain G0 for their whole lifetime.
    let window =
        Arc::new(PairMachineWindow::with_persistence(m2_dir.path().to_path_buf()).unwrap());
    let g0 = window
        .snapshot()
        .await
        .lifecycle_generation
        .expect("G0 generation token");
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

    // Build the stale G0 router and status route backed by the same lock.
    let pre_household = pre_household_router(PreHouseholdRouterState {
        window: Arc::clone(&window),
        state_dir: m2_dir.path().to_path_buf(),
        key_policy: KeyBackingPolicy::ForceSoftware,
        bootstrap: Some(Arc::clone(&shared_bootstrap)),
        runtime_signal: None,
    });
    let handler_state_pre = make_bootstrap_handler_state(
        Arc::clone(&shared_bootstrap),
        m2_dir.path().to_path_buf(),
        Arc::clone(&window),
    );

    assert_eq!(
        get_bootstrap_status_state(handler_state_pre).await,
        "uninitialized",
        "pre-finalize sanity check"
    );

    // The first request commits the install and G1 terminal result, but this
    // G0 router is forbidden from returning the Ack or publishing Ready.
    let resp = pre_household
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(FINALIZE_PATH)
                .header("content-type", "application/cbor")
                .body(Body::from(join_response_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "G0 finalize must require restart; body={}",
        String::from_utf8_lossy(&bytes),
    );
    assert_eq!(
        household_rs::bootstrap_state::load(m2_dir.path()).unwrap(),
        BootstrapState::PairMachineInstallRestartRequired,
        "G0 may only publish the install-specific restart state"
    );
    assert_eq!(
        *shared_bootstrap.read().await,
        BootstrapState::PairMachineInstallRestartRequired
    );
    assert_eq!(
        get_bootstrap_status_state(make_bootstrap_handler_state(
            Arc::clone(&shared_bootstrap),
            m2_dir.path().to_path_buf(),
            Arc::clone(&window),
        ))
        .await,
        "pair_machine_install_restart_required"
    );

    // Retrying through the same stale router remains restart-only. It cannot
    // use the now-visible G1 token through its fresh lifecycle guard to bless
    // the G0 window retained in memory.
    let stale_retry = pre_household
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(FINALIZE_PATH)
                .header("content-type", "application/cbor")
                .body(Body::from(join_response_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale_retry.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        *shared_bootstrap.read().await,
        BootstrapState::PairMachineInstallRestartRequired
    );

    // The old G0 namespace is stale for every mutation after rotation.
    let lifecycle = HouseholdLifecycleLock::open_verified(m2_dir.path()).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();
    assert!(
        window
            .under_lifecycle(&guard)
            .return_to_idle()
            .await
            .is_err(),
        "a retained G0 capability must not mutate G1"
    );
    drop(guard);

    // A cold start opens a genuinely fresh G1 window and a new bootstrap Arc.
    let fresh_window =
        Arc::new(PairMachineWindow::with_persistence(m2_dir.path().to_path_buf()).unwrap());
    let g1 = fresh_window
        .snapshot()
        .await
        .lifecycle_generation
        .expect("G1 generation token");
    assert_ne!(g0, g1, "candidate install must rotate exactly away from G0");
    let fresh_bootstrap: BootstrapStateArc = Arc::new(RwLock::new(
        household_rs::bootstrap_state::load(m2_dir.path()).unwrap(),
    ));
    let fresh_router = pre_household_router(PreHouseholdRouterState {
        window: Arc::clone(&fresh_window),
        state_dir: m2_dir.path().to_path_buf(),
        key_policy: KeyBackingPolicy::ForceSoftware,
        bootstrap: Some(Arc::clone(&fresh_bootstrap)),
        runtime_signal: None,
    });

    // Same identity but different exact request bytes are divergent and may
    // neither receive the retained Ack nor publish Ready.
    let mut divergent = join_response.clone();
    divergent.peer_list[0].tailscale_addr = Some("100.64.0.77:8091".into());
    let divergent_bytes = divergent.to_canonical_bytes().unwrap();
    let divergent_response = fresh_router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(FINALIZE_PATH)
                .header("content-type", "application/cbor")
                .body(Body::from(divergent_bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(divergent_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        *fresh_bootstrap.read().await,
        BootstrapState::PairMachineInstallRestartRequired
    );
    assert_eq!(
        household_rs::bootstrap_state::load(m2_dir.path()).unwrap(),
        BootstrapState::PairMachineInstallRestartRequired
    );

    let expected_ack = FinalizeAck::for_machine_cert(&join_response.machine_cert)
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    let exact_response = fresh_router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(FINALIZE_PATH)
                .header("content-type", "application/cbor")
                .body(Body::from(join_response_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exact_response.status(), StatusCode::OK);
    let exact_ack = to_bytes(exact_response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(exact_ack.as_ref(), expected_ack.as_slice());
    assert_eq!(*fresh_bootstrap.read().await, BootstrapState::Ready);
    assert_eq!(
        household_rs::bootstrap_state::load(m2_dir.path()).unwrap(),
        BootstrapState::Ready
    );

    let handler_state_post = make_bootstrap_handler_state(
        Arc::clone(&fresh_bootstrap),
        m2_dir.path().to_path_buf(),
        Arc::clone(&fresh_window),
    );
    let observed = get_bootstrap_status_state(handler_state_post).await;
    assert_eq!(
        observed, "ready",
        "GET /bootstrap/status should report ready only from the fresh G1 runtime"
    );

    // Ready does not suppress exact lost-Ack recovery: the retained body is
    // replayed byte-for-byte without reinstalling or rotating again.
    let second_exact = fresh_router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(FINALIZE_PATH)
                .header("content-type", "application/cbor")
                .body(Body::from(join_response_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_exact.status(), StatusCode::OK);
    let second_ack = to_bytes(second_exact.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(second_ack, exact_ack);
    assert_eq!(
        fresh_window
            .snapshot()
            .await
            .lifecycle_generation
            .expect("fresh generation"),
        g1,
        "exact retry must not rotate again"
    );

    // Ready is the durable one-time delivery-applied phase. A later exact
    // retry must not roll a newer reachability hint back to the original
    // join-time address.
    let peer = &join_response.peer_list[0];
    household_rs::storage::write_known_peer_addr(m2_dir.path(), &peer.m_id, "100.64.0.250:8091")
        .unwrap();
    let byte_only_replay = fresh_router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(FINALIZE_PATH)
                .header("content-type", "application/cbor")
                .body(Body::from(join_response_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(byte_only_replay.status(), StatusCode::OK);
    assert_eq!(
        household_rs::storage::read_known_peer_addr(m2_dir.path(), &peer.m_id).unwrap(),
        Some("100.64.0.250:8091".into())
    );

    // An unrelated fail-stop Recovering state is never healed by a historical
    // exact terminal result. The retained result remains replay authority only
    // after the surrounding subsystem is made healthy independently.
    household_rs::bootstrap_state::persist(m2_dir.path(), BootstrapState::Recovering).unwrap();
    *fresh_bootstrap.write().await = BootstrapState::Recovering;
    let fail_stop_replay = fresh_router
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
    assert_eq!(fail_stop_replay.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        household_rs::bootstrap_state::load(m2_dir.path()).unwrap(),
        BootstrapState::Recovering
    );
    assert_eq!(
        household_rs::storage::read_known_peer_addr(m2_dir.path(), &peer.m_id).unwrap(),
        Some("100.64.0.250:8091".into())
    );
}

#[tokio::test]
async fn cli_finalize_with_bootstrap_none_signals_cold_restart_without_ack() {
    // The CLI install path (`theyos install --pair-machine`) wires the
    // pre-household router with `bootstrap: None` because the install
    // binary IS the pre-household phase by construction — there's no
    // running daemon and no live status endpoint. The in-memory bootstrap
    // terminal result must not depend on an in-memory bootstrap lock. Success
    // is reported only through the typed restart signal.
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

    let (broken_signal, broken_signal_rx) =
        tokio::sync::watch::channel(PreHouseholdRuntimeSignal::Running);
    drop(broken_signal_rx);
    let router = pre_household_router(PreHouseholdRouterState {
        window: Arc::clone(&window),
        state_dir: m2_dir.path().to_path_buf(),
        key_policy: KeyBackingPolicy::ForceSoftware,
        bootstrap: None,
        runtime_signal: Some(broken_signal),
    });

    let first = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(FINALIZE_PATH)
                .header("content-type", "application/cbor")
                .body(Body::from(join_response_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        to_bytes(first.into_body(), 65_536).await.is_err(),
        "a disappeared runtime receiver must break delivery when Hyper polls the body"
    );
    assert_eq!(
        household_rs::bootstrap_state::load(m2_dir.path()).unwrap(),
        BootstrapState::PairMachineInstallRestartRequired
    );

    // An exact retry through the retained stale G0 router must repair the
    // previously failed restart signal instead of returning a bare 503.
    let (runtime_signal, mut runtime_signal_rx) =
        tokio::sync::watch::channel(PreHouseholdRuntimeSignal::Running);
    let repair_router = pre_household_router(PreHouseholdRouterState {
        window: Arc::clone(&window),
        state_dir: m2_dir.path().to_path_buf(),
        key_policy: KeyBackingPolicy::ForceSoftware,
        bootstrap: None,
        runtime_signal: Some(runtime_signal),
    });
    let resp = repair_router
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
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let retry_body = to_bytes(resp.into_body(), 65_536).await.unwrap();
    assert_eq!(
        retry_body.as_ref(),
        household_rs::pair_machine::FinalizeRestartRequired::new()
            .to_canonical_bytes()
            .unwrap()
    );
    runtime_signal_rx.changed().await.unwrap();
    assert_eq!(
        *runtime_signal_rx.borrow(),
        PreHouseholdRuntimeSignal::RestartRequired
    );
    assert_ne!(
        window.snapshot().await.state,
        household_rs::pair_machine::PairMachineState::Committed,
        "G0 window must not be used as a synthetic success notification"
    );
    assert_eq!(
        household_rs::bootstrap_state::load(m2_dir.path()).unwrap(),
        BootstrapState::PairMachineInstallRestartRequired
    );
}

/// Mechanically enumerate every production gateway that can persist Ready.
///
/// Reproduce outside the test with:
/// `rg -n 'persist_ready_under_lifecycle\s*\(' admin/rust/server-rs/src --glob '*.rs'`.
/// Generic `bootstrap_state::persist` rejects Ready at runtime, while this
/// inventory makes adding or removing a guarded writer an explicit review.
#[test]
fn every_ready_writer_is_in_the_lifecycle_generation_inventory() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut actual = Vec::new();
    for entry in std::fs::read_dir(&src).expect("read server src") {
        let entry = entry.expect("read server source entry");
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read server source");
        let production_end = source.find("\n#[cfg(test)]\nmod ").unwrap_or(source.len());
        let production = &source[..production_end];
        let count = production
            .match_indices("persist_ready_under_lifecycle(")
            .count();
        if count != 0 {
            actual.push((
                path.file_name()
                    .expect("source file name")
                    .to_string_lossy()
                    .into_owned(),
                count,
            ));
        }
    }
    actual.sort();
    assert_eq!(
        actual,
        vec![
            ("handlers_bootstrap.rs".to_string(), 1),
            ("handlers_pair_device.rs".to_string(), 1),
            ("handlers_pair_machine.rs".to_string(), 1),
            ("household_bootstrap.rs".to_string(), 1),
        ],
        "Ready writer inventory changed; prove the new writer retains the same lifecycle guard and expected generation before updating this list",
    );
}
