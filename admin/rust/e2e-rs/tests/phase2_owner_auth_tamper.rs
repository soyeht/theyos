mod phase1_helpers;
mod phase2_helpers;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::{Router, routing::get};
use household_rs::pair_device::PairDeviceWindow;
use server_rs::handlers_household;
use server_rs::household_state::HouseholdState;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn tampered_owner_auth_state_is_not_loaded_as_trusted() {
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
    let pair = phase1_helpers::post_json(
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
    assert_eq!(pair.status, StatusCode::OK);

    let cert_path = household_rs::storage::owner_person_cert_path(td.path());
    let mut cert: household_rs::PersonCert = household_rs::storage::read_optional_cbor(&cert_path)
        .unwrap()
        .unwrap();
    cert.display_name = "Mallory".into();
    household_rs::storage::atomic_write_cbor(&cert_path, &cert).unwrap();

    let loaded = phase1_helpers::load_existing_identity(td.path());
    assert!(
        household_rs::HouseholdAuthState::load_optional(td.path(), &loaded.record, unix_now())
            .is_err()
    );
    let app = Router::new()
        .route(
            "/api/v1/household/snapshot",
            get(handlers_household::snapshot),
        )
        .with_state(HouseholdState::loaded(Arc::new(loaded)));
    let auth = phase2_helpers::pop_header(
        &person,
        "GET",
        "/api/v1/household/snapshot",
        unix_now(),
        b"",
    );
    assert_eq!(
        phase1_helpers::get_with_auth(&app, "/api/v1/household/snapshot", &auth)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}
