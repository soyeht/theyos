#![cfg(test)]

use super::*;
use axum::http::{Method, Request, StatusCode};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::claw_share::{SlotId, SlotState};
use household_rs::household_mesh_log::{LogEntry, MeshEvent};
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::person_cert::SignOwnerOptions;
use household_rs::pop::{PairingProofContext, RequestSigningContext};
use serde::Serialize;

static RECOVERY_TIMEOUT_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static PHASE3_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[test]
fn phase3_surface_has_one_production_factory() {
    let source = include_str!("../household_bootstrap.rs");
    let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
    assert_eq!(production.matches("fn phase3_router(").count(), 1);
    assert!(!production.contains("pair_machine_router"));
    let device_routes = include_str!("../handlers_device_pairing.rs");
    assert_eq!(
        production
            .matches("handlers_device_pairing::device_pairing_router(owner_events_state)")
            .count(),
        1
    );
    for path in [
        "/api/v1/household/join-request",
        "/api/v1/household/owner-events",
        "/api/v1/household/owner-device/push-token",
        "/api/v1/household/owner-webauthn/registration/start",
        "/api/v1/household/owner-webauthn/registration/finish",
        "/api/v1/household/owner-webauthn/registration/status",
        "/api/v1/household/owner-webauthn/revoke/start",
        "/api/v1/household/owner-webauthn/revoke/finish",
        "/api/v1/household/owner-webauthn/add-credential/start",
        "/api/v1/household/owner-webauthn/add-credential/finish",
        "/api/v1/household/owner-webauthn/recovery/status",
        "/api/v1/household/owner-webauthn/recovery/start",
        "/api/v1/household/owner-webauthn/recovery/finish",
        "/api/v1/household/owner-webauthn/recovery/consume/start",
        "/api/v1/household/owner-webauthn/recovery/consume/finish",
        "/api/v1/household/owner-events/{cursor}/approve",
        "/api/v1/household/owner-events/{cursor}/approval-v2/start",
        "/api/v1/household/owner-events/{cursor}/decline",
        "/api/v1/household/device-pairing/request",
        "/api/v1/household/device-pairing/approve",
        "/api/v1/household/device-pairing/requests",
        "/api/v1/household/device-pairing/reject",
        "/api/v1/household/device-pairing/{request_id}",
    ] {
        let literal = format!("\"{path}\"");
        assert_eq!(
            if path.contains("/device-pairing/") {
                device_routes.matches(&literal).count()
            } else {
                production.matches(&literal).count()
            },
            1,
            "Phase 3 path must be declared only by the single factory: {path}"
        );
    }
    for symbol in [
        "SECURE_UPGRADE_APP_ATTEST_START_PATH",
        "SECURE_UPGRADE_APP_ATTEST_FINISH_PATH",
        "sign_machine_cert_router(",
        "spawn_owner_timeout_watchdog(",
        "spawn_macos_local_registration_listener(",
        "spawn_bonjour_browser(",
        "OwnerWebauthnRuntime::build(",
        ".with_owner_webauthn_rp_shared(",
        ".with_owner_webauthn_anchor(",
        "let owner_webauthn_network = owner_webauthn_network_enabled();",
    ] {
        assert_eq!(
            production.matches(symbol).count(),
            1,
            "Phase 3 resource/route must have one production owner: {symbol}"
        );
    }
    // Building a second RP is how the two routers would silently end up
    // with a challenge store each.
    assert!(
        !production.contains(".with_owner_webauthn_rp("),
        "owner passkey RP must reach both routers as one shared instance"
    );
}

#[tokio::test]
async fn phase3_router_slot_rejects_a_router_from_an_old_generation() {
    let temp = tempfile::tempdir().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    let generation = write.ensure_lifecycle_generation().unwrap();
    drop(write);

    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_for_handler = Arc::clone(&calls);
    let router = axum::Router::new().fallback(move || {
        let calls = Arc::clone(&calls_for_handler);
        async move {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            StatusCode::NO_CONTENT
        }
    });
    let slot = Phase3RouterSlot::new(temp.path().to_path_buf());
    slot.publish(generation, router).await;

    let live = slot
        .route_or_reject(Request::new(axum::body::Body::empty()))
        .await;
    assert_eq!(live.status(), StatusCode::NO_CONTENT);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    std::fs::create_dir(temp.path().join("household")).unwrap();
    std::fs::write(
        temp.path().join("household/household_record.cbor"),
        b"generation-rotation-fixture",
    )
    .unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    assert!(write.rename_household_to_tearing_down().unwrap());
    drop(write);

    let stale = slot
        .route_or_reject(Request::new(axum::body::Body::empty()))
        .await;
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the stale generation must be rejected before its handler runs"
    );
}

#[tokio::test]
async fn phase3_retire_cancels_a_pending_request_before_exclusive_rotation() {
    let temp = tempfile::tempdir().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    let generation = write.ensure_lifecycle_generation().unwrap();
    drop(write);

    let entered = Arc::new(tokio::sync::Notify::new());
    let entered_by_handler = Arc::clone(&entered);
    let router = axum::Router::new().route(
        "/pending",
        axum::routing::get(move || {
            let entered = Arc::clone(&entered_by_handler);
            async move {
                entered.notify_one();
                std::future::pending::<StatusCode>().await
            }
        }),
    );
    let slot = Phase3RouterSlot::new(temp.path().to_path_buf());
    slot.publish(generation, router).await;
    let request_slot = slot.clone();
    let request = tokio::spawn(async move {
        request_slot
            .route_or_reject(
                Request::builder()
                    .uri("/pending")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .expect("pending handler entered");

    tokio::time::timeout(Duration::from_secs(2), slot.retire())
        .await
        .expect("retire cancels and joins the pending route lease");
    let response = tokio::time::timeout(Duration::from_secs(2), request)
        .await
        .expect("request cancellation completes")
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    std::fs::create_dir(temp.path().join("household")).unwrap();
    std::fs::write(
        temp.path().join("household/household_record.cbor"),
        b"concurrent-generation-rotation-fixture",
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::task::spawn_blocking({
            let state_dir = temp.path().to_path_buf();
            move || {
                let lifecycle = HouseholdLifecycleLock::open_verified(&state_dir).unwrap();
                let write = lifecycle.lock_exclusive().unwrap();
                assert!(write.rename_household_to_tearing_down().unwrap());
            }
        })
        .await
        .unwrap();
    })
    .await
    .expect("exclusive lifecycle rotation is not starved by the long-poll");

    let stale = slot
        .route_or_reject(Request::new(axum::body::Body::empty()))
        .await;
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
}

#[derive(Serialize)]
struct TestInitializeRequest<'a> {
    v: u8,
    name: &'a str,
}

#[allow(unsafe_code)]
async fn initialize_and_confirm_phase3_owner(
    state: BootstrapHandlerState,
    household: &HouseholdState,
    pair_device_window: &Arc<household_rs::pair_device::PairDeviceWindow>,
    state_dir: &Path,
) -> P256Keypair {
    let prior_force_software = std::env::var_os("THEYOS_FORCE_SOFTWARE_KEYS");
    // SAFETY: the value is restored immediately after the initialize
    // request. Existing first-owner tests use the same process fixture.
    unsafe { std::env::set_var("THEYOS_FORCE_SOFTWARE_KEYS", "1") };
    let initialize_body = household_rs::cbor::to_canonical_vec(&TestInitializeRequest {
        v: 1,
        name: "Phase Three Home",
    })
    .unwrap();
    let initialized = crate::handlers_bootstrap::bootstrap_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/bootstrap/initialize")
                .body(axum::body::Body::from(initialize_body))
                .unwrap(),
        )
        .await
        .unwrap();
    match prior_force_software {
        Some(value) => unsafe { std::env::set_var("THEYOS_FORCE_SOFTWARE_KEYS", value) },
        None => unsafe { std::env::remove_var("THEYOS_FORCE_SOFTWARE_KEYS") },
    }
    assert_eq!(initialized.status(), StatusCode::OK);

    let identity = household.current().await.expect("identity published");
    let token = pair_device_window
        .current_token()
        .await
        .expect("initialize opened pair-device window");
    let owner = P256Keypair::generate();
    let pairing_context =
        PairingProofContext::new(identity.record.hh_id.clone(), token.nonce.0, owner.public());
    let proof = owner
        .sign(&pairing_context.canonical_bytes().unwrap())
        .unwrap();
    let confirm_body = serde_json::json!({
        "v": 1,
        "nonce": token.nonce.as_b64(),
        "p_pub": B64URL.encode(owner.public().as_bytes()),
        "display_name": "Owner",
        "proof_sig": B64URL.encode(proof.as_bytes()),
    });
    let confirmed = axum::Router::new()
        .route(
            "/api/v1/household/pair-device/confirm",
            axum::routing::post(handlers_pair_device::confirm),
        )
        .with_state(handlers_pair_device::PairDeviceState {
            window: Arc::clone(pair_device_window),
            household: household.clone(),
            state_dir: state_dir.to_path_buf(),
        })
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/household/pair-device/confirm")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&confirm_body).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(confirmed.status(), StatusCode::OK);
    assert!(household.current_owner_auth().await.is_some());
    owner
}

#[tokio::test]
async fn cold_initialize_confirm_installs_the_full_phase3_router_before_success() {
    let _phase3_test = PHASE3_TEST_LOCK.lock().await;
    let temp = tempfile::tempdir().unwrap();
    let bootstrap = Arc::new(RwLock::new(BootstrapState::Uninitialized));
    let household = HouseholdState::empty();
    let pair_device_window = Arc::new(
        household_rs::pair_device::PairDeviceWindow::with_persistence(temp.path().to_path_buf())
            .unwrap(),
    );
    let pair_machine_window = Arc::new(PairMachineWindow::new_in_memory());
    let runtime = Phase3RuntimeController::new(
        temp.path().to_path_buf(),
        household.clone(),
        Arc::clone(&pair_machine_window),
        KeyBackingPolicy::ForceSoftware,
        None,
    );
    let state = BootstrapHandlerState::new(
        Arc::clone(&bootstrap),
        household.clone(),
        temp.path().to_path_buf(),
        Arc::clone(&pair_device_window),
        Arc::clone(&pair_machine_window),
        8091,
    )
    .with_phase3_runtime(runtime.clone());

    let pre_initialize_dispatch =
        PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst);
    let before = runtime
        .route_or_reject(
            Request::builder()
                .uri("/api/v1/household/owner-events?since=AA")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(before.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        pre_initialize_dispatch,
        "an absent cold runtime must reject before any Phase 3 handler"
    );

    let owner =
        initialize_and_confirm_phase3_owner(state, &household, &pair_device_window, temp.path())
            .await;
    let generation0 = runtime.inner.read().await.as_ref().unwrap().generation;

    let dispatch_before = PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst);
    let invented = runtime
        .route_or_reject(
            Request::builder()
                .uri("/api/v1/household/not-a-route")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(invented.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        dispatch_before,
        "an invented route must not enter the Phase 3 handler surface"
    );

    let invalid_pop = runtime
        .route_or_reject(
            Request::builder()
                .uri("/api/v1/household/owner-events?since=AA")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(invalid_pop.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        dispatch_before + 1,
        "invalid PoP must reach the mounted owner-events handler"
    );

    let complete_surface = [
        (Method::POST, "/api/v1/household/join-request"),
        (Method::POST, "/api/v1/household/owner-device/push-token"),
        (
            Method::POST,
            "/api/v1/household/owner-webauthn/registration/start",
        ),
        (
            Method::POST,
            "/api/v1/household/owner-webauthn/registration/finish",
        ),
        (
            Method::POST,
            "/api/v1/household/owner-webauthn/registration/status",
        ),
        (
            Method::POST,
            handlers_owner_events::SECURE_UPGRADE_APP_ATTEST_START_PATH,
        ),
        (
            Method::POST,
            handlers_owner_events::SECURE_UPGRADE_APP_ATTEST_FINISH_PATH,
        ),
        (
            Method::POST,
            "/api/v1/household/owner-webauthn/revoke/start",
        ),
        (
            Method::POST,
            "/api/v1/household/owner-webauthn/revoke/finish",
        ),
        (
            Method::POST,
            "/api/v1/household/owner-webauthn/add-credential/start",
        ),
        (
            Method::POST,
            "/api/v1/household/owner-webauthn/add-credential/finish",
        ),
        (
            Method::POST,
            "/api/v1/household/owner-webauthn/recovery/status",
        ),
        (
            Method::POST,
            "/api/v1/household/owner-webauthn/recovery/start",
        ),
        (
            Method::POST,
            "/api/v1/household/owner-webauthn/recovery/finish",
        ),
        (
            Method::POST,
            "/api/v1/household/owner-webauthn/recovery/consume/start",
        ),
        (
            Method::POST,
            "/api/v1/household/owner-webauthn/recovery/consume/finish",
        ),
        (Method::POST, "/api/v1/household/owner-events/AA/approve"),
        (
            Method::POST,
            "/api/v1/household/owner-events/AA/approval-v2/start",
        ),
        (Method::POST, "/api/v1/household/owner-events/AA/decline"),
        (Method::POST, "/api/v1/household/device-pairing/request"),
        (Method::POST, "/api/v1/household/device-pairing/approve"),
        (Method::GET, "/api/v1/household/device-pairing/requests"),
        (Method::POST, "/api/v1/household/device-pairing/reject"),
        (
            Method::GET,
            "/api/v1/household/device-pairing/request-alpha",
        ),
        (Method::POST, "/api/v1/household/sign-machine-cert"),
    ];
    for (method, path) in complete_surface {
        let before = PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            runtime.route_or_reject(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("Phase 3 route did not complete: {path}"));
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "missing route: {path}"
        );
        assert_ne!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "wrong method binding: {path}"
        );
        assert_eq!(
            PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            before + 1,
            "route bypassed the sole Phase 3 factory: {path}"
        );
    }

    let uri = "/api/v1/household/owner-events?since=AA";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signing = RequestSigningContext::new("GET", uri, now, b"");
    let signature = owner.sign(&signing.canonical_bytes().unwrap()).unwrap();
    let authorization = format!(
        "Soyeht-PoP v1:{}:{}:{}",
        household_rs::derive_person_id(&owner.public()).0,
        now,
        B64URL.encode(signature.as_bytes())
    );
    let pending_runtime = runtime.clone();
    let pending = tokio::spawn(async move {
        pending_runtime
            .route_or_reject(
                Request::builder()
                    .uri(uri)
                    .header(axum::http::header::AUTHORIZATION, authorization)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !pending.is_finished(),
        "valid owner-events request must remain in long-poll"
    );
    tokio::time::timeout(Duration::from_secs(2), runtime.deactivate())
        .await
        .expect("teardown cancels the owner-events long-poll")
        .unwrap();
    assert_eq!(pending.await.unwrap().status(), StatusCode::UNAUTHORIZED);

    let state_dir = temp.path().to_path_buf();
    tokio::task::spawn_blocking({
        let state_dir = state_dir.clone();
        move || {
            let lifecycle = HouseholdLifecycleLock::open_verified(&state_dir).unwrap();
            let write = lifecycle.lock_exclusive().unwrap();
            assert!(write.rename_household_to_tearing_down().unwrap());
            assert!(write.remove_tearing_down().unwrap());
        }
    })
    .await
    .unwrap();
    household.clear().await;
    household_rs::bootstrap_or_load(
        &state_dir,
        household_rs::BootstrapOpts {
            household_name: "Generation One Home".to_string(),
            hostname_label: Some("engine-beta".to_string()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .unwrap();
    let generation1_load =
        acquire_and_load_identity_under_lifecycle(&state_dir, KeyBackingPolicy::ForceSoftware)
            .unwrap();
    let generation1_identity = Arc::clone(generation1_load.loaded.as_ref().unwrap());
    generation1_load.publish_into(&household).await;
    runtime
        .install_under_lifecycle(generation1_load.lifecycle_guard(), generation1_identity)
        .await
        .unwrap();
    let generation1 = runtime.inner.read().await.as_ref().unwrap().generation;
    assert_ne!(
        generation1, generation0,
        "reinitialize must rotate generation"
    );
    drop(generation1_load);

    let old_owner_before = PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let old_owner_signing = RequestSigningContext::new("GET", uri, now, b"");
    let old_owner_signature = owner
        .sign(&old_owner_signing.canonical_bytes().unwrap())
        .unwrap();
    let old_owner_authorization = format!(
        "Soyeht-PoP v1:{}:{}:{}",
        household_rs::derive_person_id(&owner.public()).0,
        now,
        B64URL.encode(old_owner_signature.as_bytes())
    );
    let old_owner_response = runtime
        .route_or_reject(
            Request::builder()
                .uri(uri)
                .header(axum::http::header::AUTHORIZATION, old_owner_authorization)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(old_owner_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        old_owner_before + 1,
        "G1 handles the request but must reject G0 owner authority"
    );
    runtime.deactivate().await.unwrap();
}

#[tokio::test]
async fn cold_initialize_without_runtime_install_stays_on_generic_401() {
    let _phase3_test = PHASE3_TEST_LOCK.lock().await;
    let temp = tempfile::tempdir().unwrap();
    let bootstrap = Arc::new(RwLock::new(BootstrapState::Uninitialized));
    let household = HouseholdState::empty();
    let pair_device_window = Arc::new(
        household_rs::pair_device::PairDeviceWindow::with_persistence(temp.path().to_path_buf())
            .unwrap(),
    );
    let pair_machine_window = Arc::new(PairMachineWindow::new_in_memory());
    let runtime = Phase3RuntimeController::new(
        temp.path().to_path_buf(),
        household.clone(),
        Arc::clone(&pair_machine_window),
        KeyBackingPolicy::ForceSoftware,
        None,
    );
    let state_without_install = BootstrapHandlerState::new(
        bootstrap,
        household.clone(),
        temp.path().to_path_buf(),
        Arc::clone(&pair_device_window),
        pair_machine_window,
        8091,
    );
    initialize_and_confirm_phase3_owner(
        state_without_install,
        &household,
        &pair_device_window,
        temp.path(),
    )
    .await;

    let before = PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst);
    let response = runtime
        .route_or_reject(
            Request::builder()
                .uri("/api/v1/household/owner-events?since=AA")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        before,
        "mutant without the cold install must never reach owner-events"
    );
}

#[tokio::test]
async fn warm_identity_installs_and_retires_the_complete_phase3_bundle() {
    let _phase3_test = PHASE3_TEST_LOCK.lock().await;
    let temp = tempfile::tempdir().unwrap();
    household_rs::bootstrap_or_load(
        temp.path(),
        household_rs::BootstrapOpts {
            household_name: "Warm Home".to_string(),
            hostname_label: Some("engine-alpha".to_string()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .unwrap();
    let household = HouseholdState::empty();
    let pair_machine_window =
        Arc::new(PairMachineWindow::with_persistence(temp.path().to_path_buf()).unwrap());
    let runtime = Phase3RuntimeController::new(
        temp.path().to_path_buf(),
        household.clone(),
        pair_machine_window,
        KeyBackingPolicy::ForceSoftware,
        None,
    );
    let identity_load =
        acquire_and_load_identity_under_lifecycle(temp.path(), KeyBackingPolicy::ForceSoftware)
            .unwrap();
    let loaded = Arc::clone(identity_load.loaded.as_ref().unwrap());
    identity_load.publish_into(&household).await;
    runtime
        .install_under_lifecycle(identity_load.lifecycle_guard(), loaded)
        .await
        .unwrap();
    let expected_generation = identity_load
        .lifecycle_guard()
        .lifecycle_generation()
        .unwrap()
        .unwrap();
    assert_eq!(
        runtime.inner.read().await.as_ref().unwrap().generation,
        expected_generation
    );
    #[cfg(target_os = "macos")]
    let socket_path = runtime
        .inner
        .read()
        .await
        .as_ref()
        .unwrap()
        .macos_local_listener
        .as_ref()
        .unwrap()
        .socket_path()
        .to_path_buf();
    #[cfg(target_os = "macos")]
    assert!(socket_path.exists(), "warm bundle owns the local UDS");
    drop(identity_load);

    let before = PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst);
    let invalid_pop = runtime
        .route_or_reject(
            Request::builder()
                .uri("/api/v1/household/owner-events?since=AA")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(invalid_pop.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        before + 1,
        "warm startup must publish the complete Phase 3 factory"
    );

    runtime.deactivate().await.unwrap();
    assert!(runtime.inner.read().await.is_none());
    #[cfg(target_os = "macos")]
    assert!(
        !socket_path.exists(),
        "retiring the warm bundle removes its owned local UDS"
    );
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn phase3_deactivate_propagates_replaced_uds_ownership_failure() {
    let _phase3_test = PHASE3_TEST_LOCK.lock().await;
    let temp = tempfile::tempdir().unwrap();
    household_rs::bootstrap_or_load(
        temp.path(),
        household_rs::BootstrapOpts {
            household_name: "Socket Ownership Home".to_string(),
            hostname_label: Some("engine-alpha".to_string()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .unwrap();
    let household = HouseholdState::empty();
    let runtime = Phase3RuntimeController::new(
        temp.path().to_path_buf(),
        household.clone(),
        Arc::new(PairMachineWindow::with_persistence(temp.path().to_path_buf()).unwrap()),
        KeyBackingPolicy::ForceSoftware,
        None,
    );
    let identity_load =
        acquire_and_load_identity_under_lifecycle(temp.path(), KeyBackingPolicy::ForceSoftware)
            .unwrap();
    let loaded = Arc::clone(identity_load.loaded.as_ref().unwrap());
    identity_load.publish_into(&household).await;
    runtime
        .install_under_lifecycle(identity_load.lifecycle_guard(), loaded)
        .await
        .unwrap();
    let socket_path = runtime
        .inner
        .read()
        .await
        .as_ref()
        .unwrap()
        .macos_local_listener
        .as_ref()
        .unwrap()
        .socket_path()
        .to_path_buf();
    drop(identity_load);

    std::fs::remove_file(&socket_path).unwrap();
    let replacement = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    let error = runtime.deactivate().await.unwrap_err();
    assert!(
        error.contains("refusing to remove replaced macOS local socket identity"),
        "ownership failure must propagate through the runtime: {error}"
    );
    assert!(
        socket_path.exists(),
        "runtime must not unlink a replacement socket"
    );
    drop(replacement);
    std::fs::remove_file(socket_path).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn phase3_replace_stops_before_binding_over_any_replaced_uds_path() {
    let _phase3_test = PHASE3_TEST_LOCK.lock().await;
    for replacement_kind in ["file", "symlink", "socket"] {
        let temp = tempfile::tempdir().unwrap();
        household_rs::bootstrap_or_load(
            temp.path(),
            household_rs::BootstrapOpts {
                household_name: format!("Replacement {replacement_kind} Home"),
                hostname_label: Some("engine-alpha".to_string()),
            },
            KeyBackingPolicy::ForceSoftware,
        )
        .unwrap();
        let household = HouseholdState::empty();
        let runtime = Phase3RuntimeController::new(
            temp.path().to_path_buf(),
            household.clone(),
            Arc::new(PairMachineWindow::with_persistence(temp.path().to_path_buf()).unwrap()),
            KeyBackingPolicy::ForceSoftware,
            None,
        );
        let identity_load =
            acquire_and_load_identity_under_lifecycle(temp.path(), KeyBackingPolicy::ForceSoftware)
                .unwrap();
        let loaded = Arc::clone(identity_load.loaded.as_ref().unwrap());
        identity_load.publish_into(&household).await;
        runtime
            .install_under_lifecycle(identity_load.lifecycle_guard(), Arc::clone(&loaded))
            .await
            .unwrap();
        let old_generation = runtime.inner.read().await.as_ref().unwrap().generation;
        let socket_path = runtime
            .inner
            .read()
            .await
            .as_ref()
            .unwrap()
            .macos_local_listener
            .as_ref()
            .unwrap()
            .socket_path()
            .to_path_buf();
        std::fs::remove_file(&socket_path).unwrap();

        let mut replacement_socket = None;
        let mut symlink_target = None;
        match replacement_kind {
            "file" => std::fs::write(&socket_path, b"replacement").unwrap(),
            "symlink" => {
                let target = temp.path().join("replacement-target");
                std::fs::write(&target, b"target").unwrap();
                std::os::unix::fs::symlink(&target, &socket_path).unwrap();
                symlink_target = Some(target);
            }
            "socket" => {
                replacement_socket =
                    Some(std::os::unix::net::UnixListener::bind(&socket_path).unwrap());
            }
            _ => unreachable!(),
        }

        let error = runtime
            .install_under_lifecycle(identity_load.lifecycle_guard(), loaded)
            .await
            .unwrap_err();
        assert!(
            error.contains("refusing to remove replaced macOS local socket"),
            "{replacement_kind} ownership failure must stop replacement install: {error}"
        );
        assert!(runtime.inner.read().await.is_none());
        assert!(runtime.router.router.read().await.is_none());
        assert!(
            socket_path.exists() || socket_path.symlink_metadata().is_ok(),
            "{replacement_kind} path must not be removed or rebound"
        );
        assert_ne!(
            runtime
                .inner
                .read()
                .await
                .as_ref()
                .map(|bundle| bundle.generation),
            Some(old_generation),
            "no old or new generation may remain published after failed replacement"
        );

        drop(replacement_socket);
        std::fs::remove_file(&socket_path).unwrap();
        drop(symlink_target);
    }
}

struct RecoveryTimeoutEnvRestore(Option<std::ffi::OsString>);

#[allow(unsafe_code)]
impl Drop for RecoveryTimeoutEnvRestore {
    fn drop(&mut self) {
        match self.0.take() {
            Some(value) => {
                // SAFETY: every mutation of this process-global variable in
                // this test binary is serialized by RECOVERY_TIMEOUT_ENV_LOCK.
                unsafe {
                    std::env::set_var(household_rs::pair_machine::RECOVERY_TIMEOUT_ENV, value);
                }
            }
            None => {
                // SAFETY: see the serialized-environment invariant above.
                unsafe {
                    std::env::remove_var(household_rs::pair_machine::RECOVERY_TIMEOUT_ENV);
                }
            }
        }
    }
}

#[allow(unsafe_code)]
fn with_recovery_timeout_env<T>(value: Option<&str>, inspect: impl FnOnce() -> T) -> T {
    let _lock = RECOVERY_TIMEOUT_ENV_LOCK
        .lock()
        .expect("recovery-timeout env lock poisoned");
    let _restore = RecoveryTimeoutEnvRestore(std::env::var_os(
        household_rs::pair_machine::RECOVERY_TIMEOUT_ENV,
    ));
    match value {
        Some(value) => {
            // SAFETY: this helper holds RECOVERY_TIMEOUT_ENV_LOCK until the
            // original value is restored by _restore.
            unsafe {
                std::env::set_var(household_rs::pair_machine::RECOVERY_TIMEOUT_ENV, value);
            }
        }
        None => {
            // SAFETY: see the serialized-environment invariant above.
            unsafe {
                std::env::remove_var(household_rs::pair_machine::RECOVERY_TIMEOUT_ENV);
            }
        }
    }
    inspect()
}

#[test]
fn server_bootstrap_uses_the_shared_recovery_timeout_policy() {
    use household_rs::pair_machine::{
        RECOVERY_TIMEOUT, RecoveryTimeoutResolution, RecoveryTimeoutSource,
    };

    for raw in [None, Some("invalid"), Some("0"), Some("301")] {
        let resolved = with_recovery_timeout_env(raw, phase3_recovery_timeout);
        let expected_source = if raw.is_none() {
            RecoveryTimeoutSource::Default
        } else {
            RecoveryTimeoutSource::RejectedEnvironment
        };
        assert_eq!(
            resolved,
            RecoveryTimeoutResolution {
                timeout: RECOVERY_TIMEOUT,
                source: expected_source,
            },
            "raw value {raw:?} must preserve the production ceiling"
        );
    }
    for (raw, seconds) in [("1", 1), ("300", 300)] {
        assert_eq!(
            with_recovery_timeout_env(Some(raw), phase3_recovery_timeout),
            RecoveryTimeoutResolution {
                timeout: Duration::from_secs(seconds),
                source: RecoveryTimeoutSource::Environment,
            }
        );
    }
}

#[test]
fn terminal_replay_keeps_the_listener_only_for_real_lock_contention() {
    assert!(terminal_replay_lock_failure_is_contention(
        HouseholdLifecycleLockError::LockTimeout
    ));
    for permanent in [
        HouseholdLifecycleLockError::UnsafePath,
        HouseholdLifecycleLockError::UnsupportedFilesystem,
        HouseholdLifecycleLockError::RecoveryRequired,
        HouseholdLifecycleLockError::Io,
    ] {
        assert!(
            !terminal_replay_lock_failure_is_contention(permanent),
            "{permanent:?} must shut the retained listener down fail-closed"
        );
    }
}

#[test]
fn failed_inferred_bootstrap_persist_never_publishes_the_inference() {
    let result = bootstrap_state_after_inferred_persist(
        BootstrapState::Uninitialized,
        BootstrapState::NamedAwaitingPair,
        Err(household_rs::bootstrap_state::BootstrapStateError::Io(
            std::io::Error::other("injected persistence failure"),
        )),
    );
    assert_eq!(result, BootstrapState::Uninitialized);

    let committed = bootstrap_state_after_inferred_persist(
        BootstrapState::Uninitialized,
        BootstrapState::NamedAwaitingPair,
        Ok(()),
    );
    assert_eq!(committed, BootstrapState::NamedAwaitingPair);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lifecycle_load_blocks_teardown_until_identity_is_published() {
    let td = tempfile::tempdir().unwrap();
    household_rs::bootstrap_or_load(
        td.path(),
        household_rs::BootstrapOpts {
            household_name: "Lifecycle Home".to_string(),
            hostname_label: Some("lifecycle-host".to_string()),
        },
        household_rs::KeyBackingPolicy::ForceSoftware,
    )
    .expect("install fixture household");

    // This is the same transaction used by both cold startup and the hot
    // watcher. It has observed household A but has not published A yet.
    let identity_load = acquire_and_load_identity_under_lifecycle(
        td.path(),
        household_rs::KeyBackingPolicy::ForceSoftware,
    )
    .expect("load fixture under lifecycle exclusive");
    let expected_hh_id = identity_load
        .loaded
        .as_ref()
        .expect("fixture identity is present")
        .record
        .hh_id
        .clone();

    let state_dir = td.path().to_path_buf();
    let (attempting_tx, attempting_rx) = std::sync::mpsc::sync_channel(1);
    let (renamed_tx, renamed_rx) = std::sync::mpsc::sync_channel(1);
    let contender = std::thread::spawn(move || {
        let lifecycle = HouseholdLifecycleLock::open_verified(&state_dir)
            .expect("teardown opens stable lifecycle lock");
        attempting_tx
            .send(())
            .expect("signal teardown acquisition attempt");
        let guard = lifecycle
            .lock_exclusive_until(Instant::now() + Duration::from_secs(5))
            .expect("teardown eventually acquires lifecycle exclusive");
        let renamed = guard
            .rename_household_to_tearing_down()
            .expect("teardown rename succeeds after publication");
        renamed_tx
            .send(renamed)
            .expect("report teardown rename result");
    });

    attempting_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("teardown contender started");
    assert!(
        matches!(
            renamed_rx.recv_timeout(Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ),
        "teardown must not rename after load and before memory publication"
    );

    let identity_state = HouseholdState::empty();
    identity_load.publish_into(&identity_state).await;
    assert_eq!(
        identity_state
            .current()
            .await
            .expect("identity is published before lifecycle release")
            .record
            .hh_id,
        expected_hh_id
    );
    drop(identity_load);

    assert!(
        renamed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("teardown completes after publication"),
        "installed household should be detached"
    );
    contender.join().expect("teardown contender does not panic");
}

#[test]
fn clamp_pair_window_ttl_secs_passes_through_in_range() {
    assert_eq!(clamp_pair_window_ttl_secs(Some(900)), 900);
    assert_eq!(
        clamp_pair_window_ttl_secs(Some(PAIR_WINDOW_TTL_MIN_SECS)),
        PAIR_WINDOW_TTL_MIN_SECS
    );
    assert_eq!(
        clamp_pair_window_ttl_secs(Some(PAIR_WINDOW_TTL_MAX_SECS)),
        PAIR_WINDOW_TTL_MAX_SECS
    );
}

#[test]
fn clamp_pair_window_ttl_secs_defaults_when_absent_or_out_of_range() {
    assert_eq!(
        clamp_pair_window_ttl_secs(None),
        DEFAULT_PAIR_WINDOW_TTL_SECS
    );
    assert_eq!(
        clamp_pair_window_ttl_secs(Some(PAIR_WINDOW_TTL_MIN_SECS - 1)),
        DEFAULT_PAIR_WINDOW_TTL_SECS
    );
    assert_eq!(
        clamp_pair_window_ttl_secs(Some(PAIR_WINDOW_TTL_MAX_SECS + 1)),
        DEFAULT_PAIR_WINDOW_TTL_SECS
    );
    // The historical default the migrated sites used.
    assert_eq!(DEFAULT_PAIR_WINDOW_TTL_SECS, 300);
}

/// SSOT guard for the pairing-window TTL clamp. Both the anti-literal check
/// (no site re-inlines the `60..=3600` clamp) and the positive-consumption
/// check (each site actually calls the owner) are required: a site that drops
/// the literal but also stops resolving the TTL would pass the former alone.
#[test]
fn pair_window_ttl_clamp_has_a_single_owner() {
    let sites = [
        (
            "server-rs/src/install_cli.rs",
            include_str!("../install_cli.rs"),
        ),
        (
            "server-rs/src/pair_machine_local.rs",
            include_str!("../pair_machine_local.rs"),
        ),
    ];
    for (path, source) in sites {
        assert!(
            !source.contains("60..=3600"),
            "{path} re-inlined the pairing-window TTL clamp `60..=3600`; \
                 call household_bootstrap::pair_window_ttl_secs_from_env instead"
        );
        assert!(
            source.contains("pair_window_ttl_secs_from_env"),
            "{path} no longer consumes the pairing-window TTL owner \
                 (household_bootstrap::pair_window_ttl_secs_from_env); a site that \
                 stops calling the owner can silently drift from its clamp/default"
        );
    }
}

#[test]
fn macos_local_app_profile_tracks_state_namespace() {
    use crate::macos_local_caller_auth::MacosLocalAppProfile;

    let prod = Path::new("/Users/example/Library/Application Support/Soyeht/household-state");
    assert_eq!(
        macos_local_app_profile_for_state_dir(prod),
        MacosLocalAppProfile::Production
    );

    let dev = Path::new("/Users/example/Library/Application Support/SoyehtDev/household-state");
    assert_eq!(
        macos_local_app_profile_for_state_dir(dev),
        MacosLocalAppProfile::Development
    );

    let prefixed =
        Path::new("/Users/example/Library/Application Support/SoyehtDevelopment/household-state");
    assert_eq!(
        macos_local_app_profile_for_state_dir(prefixed),
        MacosLocalAppProfile::Production,
        "dev selection must require an exact SoyehtDev path component"
    );

    let username_match =
        Path::new("/Users/SoyehtDev/Library/Application Support/Soyeht/household-state");
    assert_eq!(
        macos_local_app_profile_for_state_dir(username_match),
        MacosLocalAppProfile::Production,
        "dev selection must use the state namespace, not an earlier path component"
    );

    let explicit_dev_state_dir = Path::new("/Users/example/Library/Application Support/SoyehtDev");
    assert_eq!(
        macos_local_app_profile_for_state_dir(explicit_dev_state_dir),
        MacosLocalAppProfile::Development
    );
}

#[test]
fn owner_webauthn_registration_state_shares_one_rp_across_both_routers() {
    let td = tempfile::tempdir().unwrap();
    let identity = household_rs::bootstrap_or_load(
        td.path(),
        household_rs::BootstrapOpts {
            household_name: "Owner Events Test".into(),
            hostname_label: Some("owner-events-test".into()),
        },
        household_rs::KeyBackingPolicy::ForceSoftware,
    )
    .unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(td.path()).unwrap();
    let lifecycle_guard = lifecycle.lock_exclusive().unwrap();
    let broadcaster = OwnerEventsBroadcaster::new();
    let event_log = OwnerEventLog::open_with_broadcaster_under_lifecycle(
        &lifecycle_guard,
        td.path().to_path_buf(),
        identity.record.hh_id.as_str(),
        broadcaster.clone(),
    )
    .unwrap();
    drop(lifecycle_guard);
    let window = Arc::new(PairMachineWindow::new_in_memory());
    let state = handlers_owner_events::OwnerEventsRouterState::new(
        HouseholdState::empty(),
        window,
        event_log,
        broadcaster,
        td.path().to_path_buf(),
        household_rs::KeyBackingPolicy::ForceSoftware,
    );
    let verifier: Arc<dyn crate::macos_local_caller_auth::MacosLocalCallerAuth> =
        Arc::new(crate::macos_local_caller_auth::FailClosedMacosLocalCallerAuth);

    let runtime = OwnerWebauthnRuntime::build(td.path()).unwrap();
    let network_state = runtime.apply(state.clone());
    let local_state = macos_local_owner_webauthn_registration_state(state, &runtime, verifier);

    assert!(local_state.macos_local_caller_auth.is_some());
    assert!(local_state.owner_webauthn_anchor.is_some());
    assert!(network_state.owner_webauthn_anchor.is_some());
    // The phone presents no SecCode, so the macOS caller check must not
    // ride along onto the network router; owner Soyeht-PoP authenticates
    // that side.
    assert!(network_state.macos_local_caller_auth.is_none());
    // One RP per generation reaches both states. This is a
    // build-it-once invariant, NOT a cross-router ceremony requirement:
    // the two routers serve disjoint paths and disjoint challenge kinds,
    // so no registration is ever started on one and finished on the other
    // (see `OwnerWebauthnRuntime`).
    assert!(Arc::ptr_eq(
        local_state
            .owner_webauthn_rp
            .as_ref()
            .expect("local registration runtime state wires RP"),
        network_state
            .owner_webauthn_rp
            .as_ref()
            .expect("network registration runtime state wires RP"),
    ));
    let rp = local_state
        .owner_webauthn_rp
        .as_ref()
        .expect("local registration runtime state wires RP")
        .try_lock()
        .expect("RP lock is uncontended in unit test");
    assert_eq!(rp.config().rp_id(), DEFAULT_OWNER_WEBAUTHN_RP_ID);
    assert_eq!(
        rp.config().rp_origin().as_str(),
        "https://household.example.test/"
    );
}

/// A `tracing` sink for the tests below.
///
/// The owner-events handlers are deliberately anti-oracle: every rejection
/// is the same generic 401, and the reason exists only as a `tracing` field.
/// Reading that field is the only way to tell WHICH gate a request hit, so
/// these tests capture the log instead of guessing from the status code.
#[derive(Clone)]
struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

impl CapturedLogs {
    fn new() -> Self {
        Self(Arc::new(std::sync::Mutex::new(Vec::new())))
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Dispatch one request through `router` on this thread, with `logs`
/// installed as the thread-local subscriber for the whole poll.
fn dispatch_capturing_logs(
    router: axum::Router,
    request: Request<axum::body::Body>,
    logs: &CapturedLogs,
) -> axum::response::Response {
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move { router.oneshot(request).await.unwrap() })
    })
}

struct OwnerWebauthnScopeFixture {
    _td: tempfile::TempDir,
    household: HouseholdState,
    event_log: Arc<OwnerEventLog>,
    broadcaster: OwnerEventsBroadcaster,
    window: Arc<PairMachineWindow>,
    state_dir: PathBuf,
    person: P256Keypair,
}

impl OwnerWebauthnScopeFixture {
    fn new() -> Self {
        let td = tempfile::tempdir().unwrap();
        let identity = household_rs::bootstrap_or_load(
            td.path(),
            household_rs::BootstrapOpts {
                household_name: "Owner Webauthn Scope".into(),
                hostname_label: Some("owner-webauthn-scope".into()),
            },
            household_rs::KeyBackingPolicy::ForceSoftware,
        )
        .unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(td.path()).unwrap();
        let lifecycle_guard = lifecycle.lock_exclusive().unwrap();
        let broadcaster = OwnerEventsBroadcaster::new();
        let event_log = OwnerEventLog::open_with_broadcaster_under_lifecycle(
            &lifecycle_guard,
            td.path().to_path_buf(),
            identity.record.hh_id.as_str(),
            broadcaster.clone(),
        )
        .unwrap();
        drop(lifecycle_guard);

        let person = P256Keypair::generate();
        let cert = household_rs::PersonCert::sign_owner(
            identity
                .hh_priv
                .as_deref()
                .expect("hh_priv present in single-machine household"),
            SignOwnerOptions {
                hh_id: identity.record.hh_id.clone(),
                p_pub: person.public(),
                display_name: "Owner".into(),
                // Backdated: `PersonCert::verify` refuses a cert whose
                // `not_before` is still in the future, and the household
                // record is created inside this same second.
                issued_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .saturating_sub(60),
            },
        )
        .unwrap();
        let owner_auth = household_rs::HouseholdAuthState::new(&identity.record, cert);
        let household = HouseholdState::empty();
        let state_dir = td.path().to_path_buf();
        let window = Arc::new(PairMachineWindow::new_in_memory());
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(
                household
                    .set_loaded_with_owner_auth(Arc::new(identity), Some(Arc::new(owner_auth))),
            );
        Self {
            _td: td,
            household,
            event_log,
            broadcaster,
            window,
            state_dir,
            person,
        }
    }

    /// The state every owner-events route except enrollment is given, under
    /// the reviewed-core-v2 approval rollout.
    fn base_state(&self) -> handlers_owner_events::OwnerEventsRouterState {
        handlers_owner_events::OwnerEventsRouterState::new(
            self.household.clone(),
            Arc::clone(&self.window),
            Arc::clone(&self.event_log),
            self.broadcaster.clone(),
            self.state_dir.clone(),
            household_rs::KeyBackingPolicy::ForceSoftware,
        )
        .with_owner_approval_policy(
            handlers_owner_events::owner_approval_policy_from_rollout_value(Some(
                handlers_owner_events::OWNER_AUTH_V2_REVIEWED_CORE_ROLLOUT,
            )),
        )
    }

    fn phase3_router_with(
        &self,
        base: handlers_owner_events::OwnerEventsRouterState,
        enrollment: handlers_owner_events::OwnerEventsRouterState,
    ) -> axum::Router {
        phase3_router(
            handlers_pair_machine::PairMachineRouterState {
                window: Arc::clone(&self.window),
                household: self.household.clone(),
                event_log: Arc::clone(&self.event_log),
                event_broadcaster: self.broadcaster.clone(),
                state_dir: self.state_dir.clone(),
            },
            base,
            enrollment,
            self.household.clone(),
            Arc::clone(&self.event_log),
            self.state_dir.clone(),
        )
    }

    fn owner_pop_request(
        &self,
        method: &str,
        uri: &str,
        body: Vec<u8>,
    ) -> Request<axum::body::Body> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signing = RequestSigningContext::new(method, uri, now, &body);
        let signature = self
            .person
            .sign(&signing.canonical_bytes().unwrap())
            .unwrap();
        let authorization = format!(
            "Soyeht-PoP v1:{}:{}:{}",
            household_rs::derive_person_id(&self.person.public()).0,
            now,
            B64URL.encode(signature.as_bytes())
        );
        Request::builder()
            .method(method)
            .uri(uri)
            .header(axum::http::header::AUTHORIZATION, authorization)
            .header(axum::http::header::CONTENT_TYPE, "application/cbor")
            .body(axum::body::Body::from(body))
            .unwrap()
    }
}

#[derive(Serialize)]
struct TestVersionOnlyRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[test]
fn owner_webauthn_network_switch_unset_hands_phase3_no_rp_and_no_anchor() {
    let td = tempfile::tempdir().unwrap();
    let fixture = OwnerWebauthnScopeFixture::new();
    let base = fixture.base_state();
    let runtime = OwnerWebauthnRuntime::build(td.path()).unwrap();

    // Closed switch: the enrollment state IS the base state, so both
    // arguments phase3_router receives are RP-less and anchor-less. This is
    // the "byte-for-byte what shipped" claim, asserted rather than
    // described.
    let closed = owner_webauthn_enrollment_router_state(&base, Some(&runtime), false).unwrap();
    assert!(closed.owner_webauthn_rp.is_none());
    assert!(closed.owner_webauthn_anchor.is_none());
    assert!(base.owner_webauthn_rp.is_none());
    assert!(base.owner_webauthn_anchor.is_none());

    // Open switch: only the enrollment state gains them; `base`, which the
    // caller keeps handing to every other owner-events route, is untouched.
    let open = owner_webauthn_enrollment_router_state(&base, Some(&runtime), true).unwrap();
    assert!(open.owner_webauthn_rp.is_some());
    assert!(open.owner_webauthn_anchor.is_some());
    assert!(base.owner_webauthn_rp.is_none());
    assert!(base.owner_webauthn_anchor.is_none());
}

#[test]
fn open_owner_webauthn_network_switch_leaves_pair_machine_approval_fail_closed() {
    let td = tempfile::tempdir().unwrap();
    let fixture = OwnerWebauthnScopeFixture::new();
    let base = fixture.base_state();
    let runtime = OwnerWebauthnRuntime::build(td.path()).unwrap();
    let enrollment = owner_webauthn_enrollment_router_state(&base, Some(&runtime), true).unwrap();
    let router = fixture.phase3_router_with(base, enrollment);

    // The enrollment surface really is open: with the RP and the anchor in
    // reach, a never-enrolled owner gets a registration challenge back.
    // Without this the assertion below would pass vacuously.
    let start_uri = "/api/v1/household/owner-webauthn/registration/start";
    let start_body =
        household_rs::cbor::to_canonical_vec(&TestVersionOnlyRequest { version: 1 }).unwrap();
    let start_logs = CapturedLogs::new();
    let started = dispatch_capturing_logs(
        router.clone(),
        fixture.owner_pop_request("POST", start_uri, start_body),
        &start_logs,
    );
    assert_eq!(
        started.status(),
        StatusCode::OK,
        "enrollment must be reachable with the switch open; log: {}",
        start_logs.text()
    );

    // Same router, same open switch: machine approval must still see NO
    // anchor. `pair_machine_owner_webauthn_policy_snapshot` returns
    // `anchor_invalid()` without one, which under reviewed-core-v2 is
    // `RejectFailClosed` — the handler rejects on
    // `owner_webauthn_trust_not_satisfied` before ever reading the body.
    // Hand the anchor to this route instead and the trust state becomes
    // `NeverEnrolled`, the mode becomes `LegacyV1`, and this same empty
    // body would be rejected as `cbor_decode` — a legacy approval body
    // would be ACCEPTED. Every rejection here is the same generic 401, so
    // the reason field is the only thing that tells the two apart.
    let approve_logs = CapturedLogs::new();
    let approved = dispatch_capturing_logs(
        router,
        fixture.owner_pop_request(
            "POST",
            "/api/v1/household/owner-events/1/approve",
            Vec::new(),
        ),
        &approve_logs,
    );
    assert_eq!(approved.status(), StatusCode::UNAUTHORIZED);
    let approve_log = approve_logs.text();
    assert!(
        approve_log.contains("reason=\"owner_webauthn_trust_not_satisfied\""),
        "pair-machine approval must stay fail-closed with the enrollment \
             switch open; log: {approve_log}"
    );
    assert!(
        !approve_log.contains("reason=\"cbor_decode\""),
        "an anchor on the approve route would downgrade the body mode to \
             LegacyV1; log: {approve_log}"
    );
}

#[derive(Serialize)]
struct TestRevokeCredentialStartRequest {
    #[serde(rename = "v")]
    version: u8,
    target_credential_id: serde_bytes::ByteBuf,
}

#[test]
fn open_owner_webauthn_network_switch_leaves_revoke_and_add_credential_shut() {
    let td = tempfile::tempdir().unwrap();
    let fixture = OwnerWebauthnScopeFixture::new();
    let base = fixture.base_state();
    let runtime = OwnerWebauthnRuntime::build(td.path()).unwrap();
    let enrollment = owner_webauthn_enrollment_router_state(&base, Some(&runtime), true).unwrap();
    let router = fixture.phase3_router_with(base, enrollment);

    // These routes gate on `owner_webauthn_anchor` and `owner_webauthn_rp`,
    // the same two fields enrollment needs. Bodies are valid and the owner
    // PoP is real, so each request reaches the anchor check: with the anchor
    // scoped to enrollment it stops at `missing_anchor_verifier`. Put the
    // anchor on this state instead and the same request walks past it into
    // `never_enrolled`, which is the credential-management surface opening.
    let revoke_body = household_rs::cbor::to_canonical_vec(&TestRevokeCredentialStartRequest {
        version: 1,
        target_credential_id: serde_bytes::ByteBuf::from(vec![7_u8; 16]),
    })
    .unwrap();
    let add_body =
        household_rs::cbor::to_canonical_vec(&TestVersionOnlyRequest { version: 1 }).unwrap();
    for (uri, body) in [
        ("/api/v1/household/owner-webauthn/revoke/start", revoke_body),
        (
            "/api/v1/household/owner-webauthn/add-credential/start",
            add_body,
        ),
    ] {
        let logs = CapturedLogs::new();
        let response = dispatch_capturing_logs(
            router.clone(),
            fixture.owner_pop_request("POST", uri, body),
            &logs,
        );
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        let text = logs.text();
        assert!(
            text.contains("reason=\"missing_anchor_verifier\""),
            "{uri} must stop at the absent anchor; log: {text}"
        );
    }
}

#[test]
fn owner_webauthn_rp_defaults_to_the_placeholder_when_no_domain_is_configured() {
    let rp = owner_webauthn_rp_from_values(None, None).unwrap();
    assert_eq!(rp.config().rp_id(), DEFAULT_OWNER_WEBAUTHN_RP_ID);
    assert_eq!(
        rp.config().rp_origin().as_str(),
        "https://household.example.test/"
    );
}

#[test]
fn owner_webauthn_rp_takes_the_configured_tenant_domain() {
    let rp = owner_webauthn_rp_from_values(
        Some("passkeys.example.org"),
        Some("https://passkeys.example.org"),
    )
    .unwrap();
    assert_eq!(rp.config().rp_id(), "passkeys.example.org");
    assert_eq!(
        rp.config().rp_origin().as_str(),
        "https://passkeys.example.org/"
    );
}

#[test]
fn owner_webauthn_rp_rejects_an_origin_outside_the_rp_id() {
    // webauthn-rs refuses the pair, so a mistyped domain fails the phase-3
    // install instead of minting credentials no origin can present.
    assert!(
        owner_webauthn_rp_from_values(
            Some("passkeys.example.org"),
            Some("https://unrelated.example.net"),
        )
        .is_err()
    );
}

#[test]
fn owner_webauthn_network_surface_is_closed_unless_explicitly_opened() {
    for closed in [
        None,
        Some(""),
        Some("0"),
        Some("true"),
        Some("yes"),
        Some("on"),
    ] {
        assert!(
            !owner_webauthn_network_enabled_from_value(closed),
            "{closed:?} must leave the network passkey surface closed"
        );
    }
    assert!(owner_webauthn_network_enabled_from_value(Some("1")));
    assert!(owner_webauthn_network_enabled_from_value(Some(" 1 ")));
}

#[test]
fn claw_share_bootstrap_state_rehydrates_slots_from_persisted_log() {
    let td = tempfile::tempdir().unwrap();
    let log = MeshLogStore::open(&claw_share_log_path(td.path())).unwrap();
    let owner = P256Keypair::from_secret_scalar(&[0x11u8; 32]).unwrap();
    let guest = P256Keypair::from_secret_scalar(&[0x22u8; 32]).unwrap();
    let now = 1_800_000_000;

    let open_slot = SlotId([0x01u8; 16]);
    let consumed_slot = SlotId([0x02u8; 16]);
    let revoked_slot = SlotId([0x03u8; 16]);
    append_log_event(
        &log,
        &owner,
        now,
        MeshEvent::ClawShareSlotMinted {
            slot_id: open_slot.clone(),
            claw_id: "claw-open".to_string(),
            expires_at: now + 600,
            app_presentation: None,
        },
    );
    append_log_event(
        &log,
        &owner,
        now + 1,
        MeshEvent::ClawShareSlotMinted {
            slot_id: consumed_slot.clone(),
            claw_id: "claw-consumed".to_string(),
            expires_at: now + 600,
            app_presentation: None,
        },
    );
    append_log_event(
        &log,
        &owner,
        now + 2,
        MeshEvent::ClawShareSlotConsumed {
            slot_id: consumed_slot.clone(),
            guest_device_pub: guest.public(),
            claw_id: "claw-consumed".to_string(),
            expires_at: now + 600,
            participant_npub: None,
        },
    );
    append_log_event(
        &log,
        &owner,
        now + 3,
        MeshEvent::ClawShareSlotMinted {
            slot_id: revoked_slot.clone(),
            claw_id: "claw-revoked".to_string(),
            expires_at: now + 600,
            app_presentation: None,
        },
    );
    append_log_event(
        &log,
        &owner,
        now + 4,
        MeshEvent::ClawShareSlotRevoked {
            slot_id: revoked_slot.clone(),
        },
    );
    drop(log);

    let state = prepare_claw_share_bootstrap_state(td.path(), None, None);

    assert!(state.engine_relay_identity.is_none());
    assert!(state.relay_urls.is_empty());
    assert!(matches!(
        state.runtime.slot_store.get(&open_slot).unwrap().state,
        SlotState::Open
    ));
    let consumed = state.runtime.slot_store.get(&consumed_slot).unwrap();
    match consumed.state {
        SlotState::Consumed {
            guest_device_pub, ..
        } => assert_eq!(guest_device_pub, guest.public()),
        other => panic!("expected consumed slot, got {other:?}"),
    }
    assert!(matches!(
        state.runtime.slot_store.get(&revoked_slot).unwrap().state,
        SlotState::Revoked { .. }
    ));
}

#[test]
fn engine_relay_identity_is_default_off_and_pins_advertised_npub_to_subscription_key() {
    let td = tempfile::tempdir().unwrap();

    let disabled = prepare_engine_relay_identity(td.path(), &[]).unwrap();
    assert!(disabled.is_none());
    assert!(!td.path().join("nostr_engine_key.hex").exists());

    let relay_urls = vec!["wss://relay.example.test".to_string()];
    let identity = prepare_engine_relay_identity(td.path(), &relay_urls)
        .unwrap()
        .unwrap();
    assert_eq!(identity.npub_hex, identity.keys.public_key().to_hex());
    assert!(td.path().join("nostr_engine_key.hex").exists());

    let reloaded = prepare_engine_relay_identity(td.path(), &relay_urls)
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.npub_hex, identity.npub_hex);
}

#[test]
fn household_bootstrap_relay_mount_stays_mesh_runtime_free() {
    // Production plus this extracted test module, as when the tests were inline.
    let source = concat!(
        include_str!("../household_bootstrap.rs"),
        include_str!("tests.rs")
    );
    let forbidden = [
        concat!("mesh", "_rs"),
        concat!("THEYOS", "_MESH"),
        concat!("transit", "_bootstrap_store"),
        concat!("community", "_relay_catalog"),
        concat!("mesh", "_admin_dir"),
        concat!("mesh", ".clone"),
        concat!("private_share", "_transit"),
    ];
    for symbol in forbidden {
        assert!(
            !source.contains(symbol),
            "household_bootstrap.rs reintroduced forbidden relay mount dependency `{symbol}`"
        );
    }
    assert!(source.contains(".merge(claw_share_router)"));
    assert!(source.contains("mount_claw_share_relay_stream_live_if_enabled"));
}

#[tokio::test]
async fn snapshot_watcher_installs_reissued_token_without_restart() {
    let td = tempfile::tempdir().unwrap();
    let daemon_window = Arc::new(
        household_rs::pair_device::PairDeviceWindow::with_persistence(td.path().to_path_buf())
            .unwrap(),
    );
    let cli_window =
        household_rs::pair_device::PairDeviceWindow::with_persistence(td.path().to_path_buf())
            .unwrap();

    let watcher = spawn_pair_device_window_snapshot_watcher_with_interval(
        td.path().to_path_buf(),
        Arc::clone(&daemon_window),
        HouseholdState::empty(),
        Duration::from_millis(20),
    );

    let first = cli_window
        .mint_token(Duration::from_secs(60), None)
        .await
        .unwrap();
    wait_for_nonce(&daemon_window, first.nonce.as_b64()).await;

    let second = cli_window
        .mint_token(Duration::from_secs(60), None)
        .await
        .unwrap();
    wait_for_nonce(&daemon_window, second.nonce.as_b64()).await;
    assert_ne!(first.nonce.as_b64(), second.nonce.as_b64());

    watcher.abort();
}

#[tokio::test]
async fn snapshot_watcher_closes_and_exits_after_owner_auth_exists() {
    let td = tempfile::tempdir().unwrap();
    // Installing household authority rotates the lifecycle generation.
    // Open both watcher handles only after that rotation so they retain
    // the same generation-scoped namespace the watcher is allowed to
    // close.
    let identity = household_rs::bootstrap_or_load(
        td.path(),
        household_rs::BootstrapOpts {
            household_name: "Sample Home".to_string(),
            hostname_label: Some("studio-mac".to_string()),
        },
        household_rs::KeyBackingPolicy::ForceSoftware,
    )
    .expect("bootstrap identity from install path");
    let daemon_window = Arc::new(
        household_rs::pair_device::PairDeviceWindow::with_persistence(td.path().to_path_buf())
            .unwrap(),
    );
    let cli_window =
        household_rs::pair_device::PairDeviceWindow::with_persistence(td.path().to_path_buf())
            .unwrap();
    let owner_auth = owner_auth_for(&identity);
    let identity_state =
        HouseholdState::loaded_with_owner_auth(Arc::new(identity), Some(Arc::new(owner_auth)));

    cli_window
        .mint_token(Duration::from_secs(60), None)
        .await
        .unwrap();
    assert!(cli_window.read_persisted_snapshot().unwrap().is_some());

    let watcher = spawn_pair_device_window_snapshot_watcher_with_interval(
        td.path().to_path_buf(),
        Arc::clone(&daemon_window),
        identity_state,
        Duration::from_millis(20),
    );

    tokio::time::timeout(Duration::from_secs(2), watcher)
        .await
        .expect("snapshot watcher should stop after owner auth exists")
        .expect("snapshot watcher should not panic");
    assert!(!daemon_window.is_open().await);
    assert!(cli_window.read_persisted_snapshot().unwrap().is_none());
}

#[tokio::test]
async fn identity_watcher_hot_loads_after_install_without_restart() {
    let _phase3_test = PHASE3_TEST_LOCK.lock().await;
    let td = tempfile::tempdir().unwrap();
    let identity_state = HouseholdState::empty();
    let pair_device_window = Arc::new(
        household_rs::pair_device::PairDeviceWindow::with_persistence(td.path().to_path_buf())
            .unwrap(),
    );
    let pair_machine_window = Arc::new(
        household_rs::pair_machine::PairMachineWindow::with_persistence(td.path().to_path_buf())
            .unwrap(),
    );
    let phase3_runtime = Phase3RuntimeController::new(
        td.path().to_path_buf(),
        identity_state.clone(),
        Arc::clone(&pair_machine_window),
        household_rs::KeyBackingPolicy::ForceSoftware,
        None,
    );
    let phase3_runtime_for_assertion = phase3_runtime.clone();
    let watcher = spawn_household_identity_watcher_with_interval(
        td.path().to_path_buf(),
        identity_state.clone(),
        household_rs::KeyBackingPolicy::ForceSoftware,
        Duration::from_millis(20),
        HouseholdIdentityWatcherDeps {
            pair_device_window,
            pair_machine_window,
            local_network_visibility: Arc::new(
                crate::local_network_visibility::LocalNetworkVisibility::new(),
            ),
            targets: household_listener::BoundSet::default(),
            port: 8091,
            claw_share: None,
            phase3_runtime,
            shared_state: None,
        },
    );

    assert!(identity_state.current().await.is_none());
    household_rs::bootstrap_or_load(
        td.path(),
        household_rs::BootstrapOpts {
            household_name: "Sample Home".to_string(),
            hostname_label: Some("studio-mac".to_string()),
        },
        household_rs::KeyBackingPolicy::ForceSoftware,
    )
    .expect("bootstrap identity from install path");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(identity) = identity_state.current().await {
            assert_eq!(identity.record.name, "Sample Home");
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for household identity hot-load"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::timeout(Duration::from_secs(2), watcher)
        .await
        .expect("hot-load watcher completed")
        .expect("hot-load watcher did not panic");
    let before = PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst);
    let invalid_pop = phase3_runtime_for_assertion
        .route_or_reject(
            Request::builder()
                .uri("/api/v1/household/owner-events?since=AA")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(invalid_pop.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        before + 1,
        "hot-loaded identity must install the whole Phase 3 router before the watcher exits"
    );
    phase3_runtime_for_assertion.deactivate().await.unwrap();
}

async fn wait_for_nonce(
    window: &household_rs::pair_device::PairDeviceWindow,
    expected_nonce_b64: String,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(token) = window.current_token().await {
            if token.nonce.as_b64() == expected_nonce_b64 {
                return;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for daemon pair-window snapshot reload"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn owner_auth_for(identity: &household_rs::LoadedIdentity) -> household_rs::HouseholdAuthState {
    let person = P256Keypair::generate();
    let cert = household_rs::PersonCert::sign_owner(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv present in single-machine household"),
        SignOwnerOptions {
            hh_id: identity.record.hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: identity.record.created_at + 1,
        },
    )
    .unwrap();
    household_rs::HouseholdAuthState::new(&identity.record, cert)
}

fn append_log_event(log: &MeshLogStore, owner: &P256Keypair, timestamp: u64, event: MeshEvent) {
    let entry = LogEntry::sign(timestamp, owner.public(), event, owner).unwrap();
    log.append(entry).unwrap();
}
