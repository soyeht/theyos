use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use core_rs::env::set_test_env;
use household_rs::bootstrap::{BootstrapOpts, KeyBackingPolicy, bootstrap_or_load_under_lifecycle};
use household_rs::bootstrap_state::BootstrapState;
use household_rs::first_owner_test_support::{FirstOwnerTrace, register_deterministic};
use household_rs::household_lifecycle::HouseholdLifecycleLock;
use household_rs::pair_device::{PairDeviceWindow, PairDeviceWindowState, PairNonce};
use household_rs::pair_machine::PairMachineWindow;
use household_rs::pair_window_namespace::PairWindowNamespaceV2;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use tokio::sync::RwLock;
use tower::ServiceExt;

use super::{BootstrapHandlerState, bootstrap_router};
use crate::household_state::HouseholdState;

#[derive(serde::Serialize)]
struct InitializeRequest<'a> {
    v: u8,
    name: &'a str,
}

#[derive(Deserialize)]
struct InitializeResponse {
    #[serde(rename = "v")]
    version: u8,
    hh_id: String,
    hh_pub: ByteBuf,
    name: String,
    pair_qr_uri: String,
}

#[derive(Deserialize)]
struct PairDeviceUriResponse {
    #[serde(rename = "v")]
    version: u8,
    house_name: String,
    hh_id: String,
    hh_pub: ByteBuf,
    pair_device_uri: String,
}

fn query_value(uri: &str, key: &str) -> Option<String> {
    let (_, query) = uri.split_once('?')?;
    query.split('&').find_map(|part| {
        let (candidate, value) = part.split_once('=')?;
        (candidate == key).then(|| value.to_string())
    })
}

fn same_public_attempt(
    initialize: &InitializeResponse,
    recovery: &PairDeviceUriResponse,
) -> Result<(), &'static str> {
    if initialize.hh_id != recovery.hh_id {
        return Err("household identity drift");
    }
    if initialize.hh_pub != recovery.hh_pub {
        return Err("household key drift");
    }
    if initialize.name != recovery.house_name {
        return Err("house name drift");
    }

    let initialize_nonce =
        query_value(&initialize.pair_qr_uri, "nonce").ok_or("initialize URI missing nonce")?;
    let recovery_nonce =
        query_value(&recovery.pair_device_uri, "nonce").ok_or("recovery URI missing nonce")?;
    PairNonce::from_b64(&initialize_nonce).map_err(|_| "initialize nonce is not canonical")?;
    PairNonce::from_b64(&recovery_nonce).map_err(|_| "recovery nonce is not canonical")?;
    if initialize_nonce != recovery_nonce {
        return Err("pair attempt drift");
    }
    Ok(())
}

fn trace_violations(trace: &FirstOwnerTrace, installed_generation: &[u8]) -> Vec<&'static str> {
    let mut violations = Vec::new();
    if trace.exclusive_acquire_successes == 0 {
        violations.push("observer channel did not see a successful acquisition");
    }
    if trace.exclusive_acquire_attempts != 1 || trace.exclusive_acquire_successes != 1 {
        violations.push("initialize exclusive acquisition cardinality");
    }
    if trace.shared_acquire_attempts != 0 || trace.shared_acquire_successes != 0 {
        violations.push("nested lifecycle reacquisition");
    }
    for (label, evidence) in [
        ("rebind witness", trace.rebinds.as_slice()),
        ("mint-under-guard witness", trace.mints.as_slice()),
        ("persist-under-guard witness", trace.persists.as_slice()),
    ] {
        if evidence.len() != 1 {
            violations.push(label);
            continue;
        }
        if evidence[0].namespace != evidence[0].lifecycle
            || evidence[0].namespace.as_slice() != installed_generation
        {
            violations.push(match label {
                "rebind witness" => "rebind generation identity",
                "mint-under-guard witness" => "mint generation identity",
                _ => "persist generation identity",
            });
        }
        if !evidence[0].under_exclusive {
            violations.push(match label {
                "rebind witness" => "rebind occurred outside lifecycle-exclusive",
                "mint-under-guard witness" => "mint occurred outside lifecycle-exclusive",
                _ => "persist occurred outside lifecycle-exclusive",
            });
        }
    }
    violations
}

async fn response_bytes(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body")
        .to_vec()
}

async fn measured_initialize_once(sample: usize) -> std::time::Duration {
    let state_root = tempfile::tempdir().expect("state root");
    let pair_device_window = Arc::new(
        PairDeviceWindow::with_persistence(state_root.path().to_path_buf())
            .expect("pre-household pair window"),
    );
    let state = BootstrapHandlerState {
        bootstrap: Arc::new(RwLock::new(BootstrapState::Uninitialized)),
        household: HouseholdState::empty(),
        state_dir: state_root.path().to_path_buf(),
        started_at: Instant::now(),
        pair_device_window,
        pair_machine_window: Arc::new(PairMachineWindow::new_in_memory()),
        setup_invitation_cache: crate::setup_invitation::new_cache(),
        engine_port: 8091,
        tailnet_resolver: || None,
    };
    let body = household_rs::cbor::to_canonical_vec(&InitializeRequest {
        v: 1,
        name: "Measured Home",
    })
    .expect("initialize CBOR");
    let started = Instant::now();
    let response = bootstrap_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/bootstrap/initialize")
                .header("content-type", "application/cbor")
                .body(Body::from(body))
                .expect("initialize request"),
        )
        .await
        .expect("initialize response");
    let elapsed = started.elapsed();
    assert_eq!(response.status(), StatusCode::OK, "sample {sample}");
    let decoded: InitializeResponse =
        household_rs::cbor::from_canonical_slice(&response_bytes(response).await)
            .expect("initialize response CBOR");
    assert!(
        !decoded.pair_qr_uri.is_empty(),
        "sample {sample} returned an empty URI"
    );
    elapsed
}

/// Operational characterization only. The causal gate is the deterministic
/// contention test; this ignored test measures the healthy symptom with 60
/// independent state roots and no listener or external network. It publishes
/// every duration and an explicit nearest-rank percentile method instead of
/// turning one local sample into an SLA.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "SPECULATIVE wall-clock characterization; run explicitly"]
async fn first_owner_healthy_wall_clock_distribution() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");
    let mut durations_ms = Vec::with_capacity(60);
    for sample in 0..60 {
        durations_ms.push(measured_initialize_once(sample).await.as_millis());
    }
    let mut sorted = durations_ms.clone();
    sorted.sort_unstable();
    let nearest_rank = |percent: usize| sorted[(percent * sorted.len()).div_ceil(100) - 1];
    eprintln!(
        "SPECULATIVE/NON-TRANSFERABLE n=60 successes=60 failures=0 cancelled=0 \
         method=nearest-rank median_ms={} p95_ms={} max_ms={} durations_ms={durations_ms:?}",
        nearest_rank(50),
        nearest_rank(95),
        sorted.last().expect("non-empty samples")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_owner_loopback_http_smoke_has_liveness_before_and_after() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");
    let state_root = tempfile::tempdir().expect("state root");
    let pair_device_window = Arc::new(
        PairDeviceWindow::with_persistence(state_root.path().to_path_buf())
            .expect("pre-household pair window"),
    );
    let state = BootstrapHandlerState {
        bootstrap: Arc::new(RwLock::new(BootstrapState::Uninitialized)),
        household: HouseholdState::empty(),
        state_dir: state_root.path().to_path_buf(),
        started_at: Instant::now(),
        pair_device_window,
        pair_machine_window: Arc::new(PairMachineWindow::new_in_memory()),
        setup_invitation_cache: crate::setup_invitation::new_cache(),
        engine_port: 8091,
        tailnet_resolver: || None,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("bound address");
    assert!(
        address.ip().is_loopback(),
        "smoke listener must be loopback-only"
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            bootstrap_router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .await
    });
    let client = reqwest::Client::new();
    let origin = format!("http://{address}");

    let before = client
        .get(format!("{origin}/health"))
        .send()
        .await
        .expect("health before initialize");
    assert_eq!(before.status(), StatusCode::OK);

    let request_body = household_rs::cbor::to_canonical_vec(&InitializeRequest {
        v: 1,
        name: "Loopback Smoke Home",
    })
    .expect("initialize CBOR");
    let initialize_response = client
        .post(format!("{origin}/bootstrap/initialize"))
        .header("content-type", "application/cbor")
        .body(request_body)
        .send()
        .await
        .expect("initialize over loopback");
    assert_eq!(initialize_response.status(), StatusCode::OK);
    let initialize: InitializeResponse = household_rs::cbor::from_canonical_slice(
        &initialize_response.bytes().await.expect("initialize body"),
    )
    .expect("initialize response CBOR");
    assert!(!initialize.pair_qr_uri.is_empty());

    let recovery_response = client
        .get(format!("{origin}/bootstrap/pair-device-uri"))
        .send()
        .await
        .expect("recovery over loopback");
    assert_eq!(recovery_response.status(), StatusCode::OK);
    let recovery: PairDeviceUriResponse = household_rs::cbor::from_canonical_slice(
        &recovery_response.bytes().await.expect("recovery body"),
    )
    .expect("recovery response CBOR");
    same_public_attempt(&initialize, &recovery).expect("same public attempt over loopback");

    let after = client
        .get(format!("{origin}/health"))
        .send()
        .await
        .expect("health after recovery");
    assert_eq!(after.status(), StatusCode::OK);
    shutdown_tx.send(()).expect("shutdown signal");
    server
        .await
        .expect("server task")
        .expect("graceful shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_owner_initialize_rebinds_and_persists_one_recoverable_attempt() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");
    let state_root = tempfile::tempdir().expect("state root");

    // The daemon constructs this shared Arc before initialize, establishing
    // generation G0. Initialize rotates to G1 and must rebind this exact Arc.
    let pair_device_window = Arc::new(
        PairDeviceWindow::with_persistence(state_root.path().to_path_buf())
            .expect("pre-household pair window"),
    );
    let mut notifier = pair_device_window.subscribe();
    let observer = register_deterministic(state_root.path());
    let state = BootstrapHandlerState {
        bootstrap: Arc::new(RwLock::new(BootstrapState::Uninitialized)),
        household: HouseholdState::empty(),
        state_dir: state_root.path().to_path_buf(),
        started_at: Instant::now(),
        pair_device_window: Arc::clone(&pair_device_window),
        pair_machine_window: Arc::new(PairMachineWindow::new_in_memory()),
        setup_invitation_cache: crate::setup_invitation::new_cache(),
        engine_port: 8091,
        tailnet_resolver: || None,
    };
    let app = bootstrap_router(state.clone());

    let request_body = household_rs::cbor::to_canonical_vec(&InitializeRequest {
        v: 1,
        name: "Observer Home",
    })
    .expect("initialize CBOR");
    let initialize_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/bootstrap/initialize")
                .header("content-type", "application/cbor")
                .body(Body::from(request_body))
                .expect("initialize request"),
        )
        .await
        .expect("initialize response");
    assert_eq!(initialize_response.status(), StatusCode::OK);
    let initialize: InitializeResponse =
        household_rs::cbor::from_canonical_slice(&response_bytes(initialize_response).await)
            .expect("initialize response CBOR");
    assert_eq!(initialize.version, 1);
    assert!(
        !initialize.pair_qr_uri.is_empty(),
        "initialize returned an empty QR URI"
    );
    assert_eq!(
        *state.bootstrap.read().await,
        BootstrapState::NamedAwaitingPair
    );

    // Capture initialize in isolation. The snapshot read below legitimately
    // takes a shared lifecycle guard and is a separate operation.
    let initialize_trace = observer.trace();

    let snapshot = pair_device_window
        .read_persisted_snapshot()
        .expect("read persisted window")
        .expect("persisted window exists");
    let initialize_nonce =
        query_value(&initialize.pair_qr_uri, "nonce").expect("initialize URI nonce");
    assert_eq!(snapshot.nonce_b64, initialize_nonce);
    assert_eq!(snapshot.lifecycle_generation.len(), 32);
    assert!(Arc::ptr_eq(&state.pair_device_window, &pair_device_window));
    assert!(matches!(
        notifier.try_recv(),
        Ok(PairDeviceWindowState::Open { short_nonce })
            if initialize_nonce.starts_with(&short_nonce)
    ));
    assert!(trace_violations(&initialize_trace, snapshot.lifecycle_generation.as_ref()).is_empty());

    // Independent single-clause mutants derived from the real trace. Each
    // keeps every other witness intact, so a reject-everything predicate or a
    // check that only counts events cannot pass this battery accidentally.
    let mut missing_rebind = initialize_trace.clone();
    missing_rebind.rebinds.clear();
    assert_eq!(
        trace_violations(&missing_rebind, snapshot.lifecycle_generation.as_ref()),
        vec!["rebind witness"]
    );
    let mut mint_wrong_generation = initialize_trace.clone();
    mint_wrong_generation.mints[0].namespace[0] ^= 1;
    assert_eq!(
        trace_violations(
            &mint_wrong_generation,
            snapshot.lifecycle_generation.as_ref()
        ),
        vec!["mint generation identity"]
    );
    let mut persist_outside_guard = initialize_trace.clone();
    persist_outside_guard.persists[0].under_exclusive = false;
    assert_eq!(
        trace_violations(
            &persist_outside_guard,
            snapshot.lifecycle_generation.as_ref()
        ),
        vec!["persist occurred outside lifecycle-exclusive"]
    );
    let mut mint_outside_guard = initialize_trace.clone();
    mint_outside_guard.mints[0].under_exclusive = false;
    assert_eq!(
        trace_violations(&mint_outside_guard, snapshot.lifecycle_generation.as_ref()),
        vec!["mint occurred outside lifecycle-exclusive"]
    );
    let mut guard_released_early = initialize_trace.clone();
    guard_released_early.shared_acquire_attempts = 1;
    guard_released_early.shared_acquire_successes = 1;
    assert_eq!(
        trace_violations(
            &guard_released_early,
            snapshot.lifecycle_generation.as_ref()
        ),
        vec!["nested lifecycle reacquisition"]
    );

    let recovery_response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/bootstrap/pair-device-uri")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 41991))))
                .body(Body::empty())
                .expect("recovery request"),
        )
        .await
        .expect("recovery response");
    assert_eq!(recovery_response.status(), StatusCode::OK);
    let recovery: PairDeviceUriResponse =
        household_rs::cbor::from_canonical_slice(&response_bytes(recovery_response).await)
            .expect("recovery response CBOR");
    assert_eq!(recovery.version, 1);
    same_public_attempt(&initialize, &recovery).expect("public recovery must name one attempt");

    // The test-support channel is alive because it saw the expected exclusive
    // acquisition. No nested lifecycle acquisition occurred while that guard
    // was retained. Rebind, mint, and persist each saw the same G1.
    for evidence in initialize_trace
        .rebinds
        .iter()
        .chain(initialize_trace.mints.iter())
        .chain(initialize_trace.persists.iter())
    {
        assert_eq!(evidence.namespace, evidence.lifecycle);
        assert_eq!(
            evidence.namespace.as_slice(),
            snapshot.lifecycle_generation.as_ref()
        );
    }
}

#[tokio::test]
async fn unguarded_mint_under_a_live_exclusive_guard_is_caught_without_wall_clock_wait() {
    let state_root = tempfile::tempdir().expect("state root");
    let lifecycle = HouseholdLifecycleLock::open_verified(state_root.path()).expect("lifecycle");
    let observer = register_deterministic(state_root.path());
    let guard = lifecycle.lock_exclusive().expect("exclusive guard");
    let window =
        PairDeviceWindow::with_persistence_under_lifecycle(state_root.path().to_path_buf(), &guard)
            .expect("pair window");

    let error = window
        .mint_token(std::time::Duration::from_secs(30), None)
        .await
        .expect_err("unguarded mint must not reacquire beneath exclusive");
    assert!(error.contains("timed out"), "unexpected error: {error}");
    let trace = observer.trace();
    assert_eq!(trace.exclusive_acquire_attempts, 1);
    assert_eq!(trace.exclusive_acquire_successes, 1);
    assert_eq!(trace.shared_acquire_attempts, 1);
    assert_eq!(trace.shared_acquire_successes, 0);
}

#[tokio::test]
async fn old_generation_window_fails_until_same_arc_is_rebound() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");
    let state_root = tempfile::tempdir().expect("state root");
    let lifecycle = HouseholdLifecycleLock::open_verified(state_root.path()).expect("lifecycle");
    let observer = register_deterministic(state_root.path());
    let guard = lifecycle.lock_exclusive().expect("exclusive guard");
    let window =
        PairDeviceWindow::with_persistence_under_lifecycle(state_root.path().to_path_buf(), &guard)
            .expect("old-generation pair window");

    bootstrap_or_load_under_lifecycle(
        &guard,
        state_root.path(),
        BootstrapOpts {
            household_name: "Rebind Home".into(),
            hostname_label: None,
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .expect("install new lifecycle generation");
    let stale_error = window
        .mint_token_under_lifecycle(std::time::Duration::from_secs(30), None, &guard)
        .await
        .expect_err("old generation must fail closed");
    assert!(
        stale_error.contains("no longer matches the current lifecycle generation"),
        "unexpected stale-generation error: {stale_error}"
    );

    let current =
        PairWindowNamespaceV2::current_under_lifecycle(state_root.path().to_path_buf(), &guard)
            .expect("current namespace");
    window
        .rebind_namespace_under_lifecycle(current, &guard)
        .await
        .expect("rebind same Arc");
    let token = window
        .mint_token_under_lifecycle(std::time::Duration::from_secs(30), None, &guard)
        .await
        .expect("mint in installed generation");
    let snapshot = window
        .read_persisted_snapshot_under_lifecycle(&guard)
        .expect("read snapshot")
        .expect("snapshot exists");
    assert_eq!(snapshot.nonce_b64, token.nonce.as_b64());
    let trace = observer.trace();
    assert_eq!(trace.rebinds.len(), 1);
    assert_eq!(trace.mints.len(), 1);
    assert_eq!(trace.persists.len(), 1);
}

#[test]
fn public_attempt_matcher_accepts_one_valid_case_and_rejects_each_divergence() {
    let base = InitializeResponse {
        version: 1,
        hh_id: "hh_same".into(),
        hh_pub: ByteBuf::from(vec![2; 33]),
        name: "Same Home".into(),
        pair_qr_uri: format!(
            "soyeht://household/pair-device?v=1&nonce={}",
            household_rs::pair_device::PairNonce([7; 32]).as_b64()
        ),
    };
    let valid = PairDeviceUriResponse {
        version: 1,
        hh_id: base.hh_id.clone(),
        hh_pub: base.hh_pub.clone(),
        house_name: base.name.clone(),
        pair_device_uri: base.pair_qr_uri.clone(),
    };
    assert_eq!(same_public_attempt(&base, &valid), Ok(()));

    let mut divergences = Vec::new();
    divergences.push(PairDeviceUriResponse {
        hh_id: "hh_other".into(),
        ..valid
    });
    divergences.push(PairDeviceUriResponse {
        version: 1,
        hh_id: base.hh_id.clone(),
        hh_pub: ByteBuf::from(vec![3; 33]),
        house_name: base.name.clone(),
        pair_device_uri: base.pair_qr_uri.clone(),
    });
    divergences.push(PairDeviceUriResponse {
        version: 1,
        hh_id: base.hh_id.clone(),
        hh_pub: base.hh_pub.clone(),
        house_name: "Other Home".into(),
        pair_device_uri: base.pair_qr_uri.clone(),
    });
    divergences.push(PairDeviceUriResponse {
        version: 1,
        hh_id: base.hh_id.clone(),
        hh_pub: base.hh_pub.clone(),
        house_name: base.name.clone(),
        pair_device_uri: format!(
            "soyeht://household/pair-device?v=1&nonce={}",
            household_rs::pair_device::PairNonce([8; 32]).as_b64()
        ),
    });
    let errors: Vec<_> = divergences
        .iter()
        .map(|divergence| same_public_attempt(&base, divergence).unwrap_err())
        .collect();
    assert_eq!(
        errors,
        vec![
            "household identity drift",
            "household key drift",
            "house name drift",
            "pair attempt drift"
        ]
    );
}
