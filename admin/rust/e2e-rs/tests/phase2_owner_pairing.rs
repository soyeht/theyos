mod phase1_helpers;
mod phase2_helpers;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use household_rs::pair_device::PairDeviceWindow;

#[tokio::test]
async fn first_owner_pairing_returns_person_cert_under_10_seconds() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(phase1_helpers::bootstrap_identity(
        td.path(),
        "Sample Home",
        "studio-mac",
    ));
    let window = Arc::new(PairDeviceWindow::new());
    let token = window
        .mint_token(Duration::from_secs(60), None)
        .await
        .unwrap();
    let app =
        phase1_helpers::household_router(Arc::clone(&identity), Arc::clone(&window), td.path());
    let person = phase2_helpers::TestPersonKey::generate();

    let started = Instant::now();
    let resp = phase1_helpers::post_json(
        &app,
        "/api/v1/household/pair-device/confirm",
        phase2_helpers::signed_pair_confirm_body(
            &identity.record.hh_id,
            &token.nonce,
            &person,
            "Owner",
        ),
    )
    .await;
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(resp.status, StatusCode::OK);
    let body: phase2_helpers::PairConfirmBody = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(body.v, 1);
    assert_eq!(body.hh_id, identity.record.hh_id.to_string());
    assert_eq!(body.p_id, person.p_id);
    assert!(body.consumed.unwrap_or(false));
    assert!(body.capabilities.contains(&"household.invite".to_string()));
    assert!(!body.person_cert_cbor.is_empty());
    assert!(!window.is_open().await);
    assert!(household_rs::storage::owner_person_cert_path(td.path()).exists());
    assert!(household_rs::storage::household_auth_state_path(td.path()).exists());
}
