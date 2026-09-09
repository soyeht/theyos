#![cfg(test)]

use super::*;
use axum::body::to_bytes;
use household_rs::household_lifecycle::HouseholdLifecycleLockError;
use household_rs::keys::{IdentityKey, P256Keypair};
use std::net::Ipv4Addr;
use std::sync::mpsc;

#[test]
fn terminal_anchor_rejects_a_valid_same_key_request_with_substituted_address() {
    let key = P256Keypair::generate();
    let m_pub = key.public();
    let nonce = [0x51; 32];
    let challenge = household_rs::pair_machine::JoinChallenge::build(
        m_pub.as_bytes(),
        &nonce,
        "terminal-anchor-test",
        household_rs::machine_cert::Platform::LinuxNix,
    );
    let signature = key.sign(&challenge.to_canonical_bytes().unwrap()).unwrap();
    let request = JoinRequest {
        version: household_rs::pair_machine::PAIR_MACHINE_VERSION,
        m_pub: ByteBuf::from(m_pub.as_bytes().to_vec()),
        hostname: "terminal-anchor-test".into(),
        platform: household_rs::machine_cert::Platform::LinuxNix,
        nonce: ByteBuf::from(nonce.to_vec()),
        addr: "192.0.2.44:18091".into(),
        transport: JoinTransport::Lan,
        challenge_sig: ByteBuf::from(signature.0.to_vec()),
    };
    let request_bytes = request.to_canonical_bytes().unwrap();
    let mut snapshot = PairMachineWindowSnapshot::idle();
    snapshot.cached_join_request = Some(ByteBuf::from(request_bytes.clone()));
    snapshot.m_pub = Some(request.m_pub.clone());
    snapshot.nonce = Some(request.nonce.clone());
    snapshot.addr_hint = Some(request.addr.clone());
    snapshot.transport = Some(request.transport);
    assert!(validate_terminal_join_request_binding(&snapshot, &request_bytes).is_ok());

    let mut substituted = request;
    substituted.addr = "192.0.2.99:18091".into();
    verify_join_request(&substituted)
        .expect("the request remains self-consistent, so exact terminal equality is load-bearing");
    let substituted_bytes = substituted.to_canonical_bytes().unwrap();
    assert!(
        validate_terminal_join_request_binding(&snapshot, &substituted_bytes).is_err(),
        "a different valid request must not replace the G0 terminal anchor"
    );
}

// This loopback-only test observes Hyper draining the response body
// during graceful shutdown. It goes through the shared choke-point
// wrapper (`core_rs::product_a_phase0::serve`), not the raw `axum::serve`
// primitive: the phase0 gate permits the disallowed-clippy-method escape
// hatch in exactly one file (core-rs/src/product_a_phase0.rs), so a
// second file carrying that same escape hatch trips it and silently
// stops exercising the module-crossing negative control for the
// Product A boundary. The wrapper only intercepts
// `/api/v1/mobile/claw-vpn*` paths; this test's route is `/terminal`,
// so the swap does not change what the test observes.
async fn signaled_response_survives_immediate_tcp_graceful_shutdown(
    status: StatusCode,
    body: Vec<u8>,
    value: PreHouseholdRuntimeSignal,
    retry_after: bool,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (signal, mut signal_rx) = tokio::sync::watch::channel(PreHouseholdRuntimeSignal::Running);
    let expected = body.clone();
    let app =
        axum::Router::new().route(
            "/terminal",
            axum::routing::get(move || {
                let signal = signal.clone();
                let body = body.clone();
                async move {
                    runtime_signaled_cbor_response(status, body, Some(signal), value, retry_after)
                }
            }),
        );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        core_rs::product_a_phase0::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    let shutdown = tokio::spawn(async move {
        signal_rx.changed().await.unwrap();
        assert_eq!(*signal_rx.borrow(), value);
        let _ = shutdown_tx.send(());
    });

    let response = reqwest::get(format!("http://{addr}/terminal"))
        .await
        .unwrap();
    assert_eq!(response.status(), status);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(CBOR_CONTENT_TYPE)
    );
    assert_eq!(
        response.headers().contains_key(header::RETRY_AFTER),
        retry_after
    );
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        expected.as_slice()
    );
    shutdown.await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("graceful server drains the in-flight terminal body")
        .unwrap();
}

#[tokio::test]
async fn typed_503_body_fully_drains_before_restart_shutdown() {
    let body = household_rs::pair_machine::FinalizeRestartRequired::new()
        .to_canonical_bytes()
        .unwrap();
    signaled_response_survives_immediate_tcp_graceful_shutdown(
        StatusCode::SERVICE_UNAVAILABLE,
        body,
        PreHouseholdRuntimeSignal::RestartRequired,
        true,
    )
    .await;
}

#[tokio::test]
async fn retained_ack_body_fully_drains_before_cold_listener_shutdown() {
    signaled_response_survives_immediate_tcp_graceful_shutdown(
        StatusCode::OK,
        vec![0xa1, 0x61, b'v', 0x01],
        PreHouseholdRuntimeSignal::AckDeliveryStarted,
        false,
    )
    .await;
}

fn bootstrap_named(state_dir: &Path, name: &str) -> household_rs::LoadedIdentity {
    household_rs::bootstrap_or_load(
        state_dir,
        household_rs::BootstrapOpts {
            household_name: name.to_owned(),
            hostname_label: Some(format!("{}-host", name.to_lowercase().replace(' ', "-"))),
        },
        household_rs::KeyBackingPolicy::ForceSoftware,
    )
    .expect("bootstrap household")
}

#[test]
fn cached_response_binding_is_exact_not_semantic() {
    let canonical_a = b"signed response A";
    let fingerprint = household_rs::household_install_transaction::FinalizeRequestFingerprintV1::for_canonical_request_bytes(canonical_a);
    assert!(cached_response_matches_request_fingerprint(
        canonical_a,
        fingerprint
    ));
    assert!(
        !cached_response_matches_request_fingerprint(b"signed response B", fingerprint,),
        "a separately signed response with equivalent authority fields must not satisfy A's durable intent",
    );
}

#[test]
fn candidate_tailnet_addr_uses_local_resolver_and_household_port() {
    #[allow(clippy::unnecessary_wraps)]
    fn tailnet_addr() -> Option<Ipv4Addr> {
        Some(Ipv4Addr::new(100, 64, 0, 10))
    }

    assert_eq!(
        candidate_tailnet_addr(8091, tailnet_addr),
        Some("100.64.0.10:8091".to_string())
    );
}

#[test]
fn candidate_tailnet_addr_is_absent_without_local_tailnet() {
    fn no_tailnet_addr() -> Option<Ipv4Addr> {
        None
    }

    assert_eq!(candidate_tailnet_addr(8091, no_tailnet_addr), None);
}

#[tokio::test]
async fn finalize_response_adds_hint_without_changing_ack_body() {
    #[allow(clippy::unnecessary_wraps)]
    fn tailnet_addr() -> Option<Ipv4Addr> {
        Some(Ipv4Addr::new(100, 64, 0, 10))
    }

    let state_dir = tempfile::tempdir().unwrap();
    let identity = household_rs::bootstrap_or_load(
        state_dir.path(),
        household_rs::BootstrapOpts {
            household_name: "Sample Home".to_string(),
            hostname_label: Some("candidate-alpha".to_string()),
        },
        household_rs::KeyBackingPolicy::ForceSoftware,
    )
    .unwrap();
    let expected_ack = FinalizeAck::for_machine_cert(&identity.cert).unwrap();
    let response = finalize_ack_response_with_resolver(&identity.cert, tailnet_addr);
    let expected_header = format!(
        "100.64.0.10:{}",
        crate::household_bootstrap::household_port_from_env()
    );
    assert_eq!(
        response
            .headers()
            .get(FINALIZE_CANDIDATE_TAILSCALE_ADDR_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some(expected_header.as_str())
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let actual_ack: FinalizeAck = household_rs::cbor::from_canonical_slice(&body).unwrap();
    assert_eq!(actual_ack, expected_ack);
}

#[tokio::test]
async fn finalize_ready_publication_remains_inside_lifecycle_exclusive() {
    let state = tempfile::tempdir().expect("state dir");
    let _identity = bootstrap_named(state.path(), "Pair Machine Lock Home");
    let guard = acquire_pair_lifecycle_exclusive(state.path()).expect("exclusive");
    let contender_path = state.path().to_path_buf();
    let (started_tx, started_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let contender = std::thread::spawn(move || {
        let lifecycle =
            HouseholdLifecycleLock::open_verified(&contender_path).expect("open contender");
        started_tx.send(()).expect("signal contender");
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(100))
            .expect("deadline");
        result_tx
            .send(lifecycle.lock_exclusive_until(deadline).map(|_| ()))
            .expect("send contender result");
    });

    let generation = guard.ensure_lifecycle_generation().unwrap();
    persist_ready_then_publish(&guard, state.path(), generation, async {
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("contender started");
        assert_eq!(
            result_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("contender result"),
            Err(HouseholdLifecycleLockError::LockTimeout),
            "teardown/replacement acquired between durable Ready and publication",
        );
    })
    .await
    .expect("persist and publish");
    contender.join().expect("contender thread");
    drop(guard);

    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).expect("reopen");
    lifecycle.lock_exclusive().expect("lock after publication");
}

#[test]
fn stale_finalize_rejects_replacement_household() {
    let old_state = tempfile::tempdir().expect("old state");
    let replacement_state = tempfile::tempdir().expect("replacement state");
    let old = bootstrap_named(old_state.path(), "Old Candidate Home");
    let replacement = bootstrap_named(replacement_state.path(), "Replacement Candidate Home");
    household_rs::storage::atomic_write_cbor(
        &household_rs::storage::household_record_path(old_state.path()),
        &replacement.record,
    )
    .expect("install replacement record");

    let guard = acquire_pair_lifecycle_exclusive(old_state.path()).expect("exclusive");
    let error = verify_installed_household_for_finalize(
        &guard,
        old_state.path(),
        old.record.hh_id.as_str(),
    )
    .expect_err("stale finalize must not mutate replacement");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn stale_founder_stage_rejects_replacement_household() {
    let old_state = tempfile::tempdir().expect("old state");
    let replacement_state = tempfile::tempdir().expect("replacement state");
    let old = bootstrap_named(old_state.path(), "Old Founder Home");
    let replacement = bootstrap_named(replacement_state.path(), "New Founder Home");
    household_rs::storage::atomic_write_cbor(
        &household_rs::storage::household_record_path(old_state.path()),
        &replacement.record,
    )
    .expect("install replacement record");

    let guard = acquire_pair_lifecycle_exclusive(old_state.path()).expect("exclusive");
    let error = verify_installed_household_id(&guard, old_state.path(), old.record.hh_id.as_str())
        .expect_err("stale founder process must not stage against replacement");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn stale_candidate_anchor_rejects_an_installed_household() {
    let state = tempfile::tempdir().expect("state");
    let _installed = bootstrap_named(state.path(), "Already Installed Home");
    let guard = acquire_pair_lifecycle_exclusive(state.path()).expect("exclusive");
    let error = verify_household_absent_for_candidate(&guard, state.path())
        .expect_err("candidate anchor must not mutate an installed household");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
}
