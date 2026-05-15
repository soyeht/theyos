use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use axum::{Router, routing::post};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::pair_device::PairDeviceWindow;
use household_rs::pop::PairingProofContext;
use household_rs::{BootstrapOpts, KeyBackingPolicy};
use serde_json::{Value, json};
use server_rs::handlers_pair_device::{self, PairDeviceState};
use server_rs::household_state::HouseholdState;
use tower::ServiceExt;

fn app(
    state_dir: &std::path::Path,
    identity: Arc<household_rs::LoadedIdentity>,
    window: Arc<PairDeviceWindow>,
) -> Router {
    Router::new()
        .route(
            "/api/v1/household/pair-device/confirm",
            post(handlers_pair_device::confirm),
        )
        .with_state(PairDeviceState {
            window,
            household: HouseholdState::loaded(identity),
            state_dir: state_dir.to_path_buf(),
        })
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

fn signed_body(
    identity: &household_rs::LoadedIdentity,
    nonce: &household_rs::pair_device::PairNonce,
    key: &P256Keypair,
) -> Value {
    let p_pub = key.public();
    let ctx = PairingProofContext::new(identity.record.hh_id.clone(), nonce.0, p_pub.clone());
    let sig = key.sign(&ctx.canonical_bytes().unwrap()).unwrap();
    json!({
        "v": 1,
        "nonce": nonce.as_b64(),
        "p_pub": B64URL.encode(p_pub.as_bytes()),
        "display_name": "Owner",
        "proof_sig": B64URL.encode(sig.as_bytes()),
    })
}

async fn post_json(app: Router, body: Value) -> (StatusCode, Vec<u8>) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/household/pair-device/confirm")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, body)
}

#[tokio::test]
async fn confirm_success_returns_person_cert_and_no_device_cert() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let window = Arc::new(PairDeviceWindow::new());
    let token = window
        .mint_token(Duration::from_secs(60), None)
        .await
        .unwrap();
    let person = P256Keypair::generate();
    let app = app(td.path(), Arc::clone(&identity), Arc::clone(&window));

    let (status, body) = post_json(app, signed_body(&identity, &token.nonce, &person)).await;
    assert_eq!(status, StatusCode::OK);
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["v"], 1);
    assert_eq!(json["hh_id"], identity.record.hh_id.to_string());
    assert!(json.get("device_cert_cbor").is_none());
    assert!(json.get("d_pub").is_none());
    assert!(!window.is_open().await);
}

#[tokio::test]
async fn confirm_failures_do_not_consume_token() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let window = Arc::new(PairDeviceWindow::new());
    let token = window
        .mint_token(Duration::from_secs(60), None)
        .await
        .unwrap();
    let app = app(td.path(), Arc::clone(&identity), Arc::clone(&window));

    assert_eq!(
        post_json(app.clone(), json!({})).await.0,
        StatusCode::NOT_FOUND
    );
    assert!(window.is_open().await);
    assert_eq!(
        post_json(
            app.clone(),
            json!({ "v": 1, "nonce": token.nonce.as_b64(), "p_pub": "bad", "proof_sig": "bad" }),
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert!(window.is_open().await);

    let person = P256Keypair::generate();
    let wrong_nonce = household_rs::pair_device::PairNonce::random();
    assert_eq!(
        post_json(app.clone(), signed_body(&identity, &wrong_nonce, &person))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert!(window.is_open().await);

    let mut invalid = signed_body(&identity, &token.nonce, &person);
    invalid["proof_sig"] =
        json!(B64URL.encode(P256Keypair::generate().sign(b"wrong").unwrap().as_bytes()));
    assert_eq!(post_json(app, invalid).await.0, StatusCode::NOT_FOUND);
    assert!(window.is_open().await);
}

#[tokio::test]
async fn no_active_window_returns_not_found() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let window = Arc::new(PairDeviceWindow::new());
    let app = app(td.path(), Arc::clone(&identity), window);
    let person = P256Keypair::generate();
    let nonce = household_rs::pair_device::PairNonce::random();

    assert_eq!(
        post_json(app, signed_body(&identity, &nonce, &person))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn confirm_after_owner_exists_closes_reissued_window() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let window = Arc::new(PairDeviceWindow::new());
    let token = window
        .mint_token(Duration::from_secs(60), None)
        .await
        .unwrap();
    let app = app(td.path(), Arc::clone(&identity), Arc::clone(&window));

    let owner = P256Keypair::generate();
    assert_eq!(
        post_json(app.clone(), signed_body(&identity, &token.nonce, &owner))
            .await
            .0,
        StatusCode::OK
    );
    assert!(!window.is_open().await);

    let token = window
        .mint_token(Duration::from_secs(60), None)
        .await
        .unwrap();
    let other = P256Keypair::generate();
    assert_eq!(
        post_json(app, signed_body(&identity, &token.nonce, &other))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert!(!window.is_open().await);
}
