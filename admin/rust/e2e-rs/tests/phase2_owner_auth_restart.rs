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

fn reloaded_snapshot_router(state_dir: &std::path::Path) -> Router {
    let identity = phase1_helpers::load_existing_identity(state_dir);
    let auth =
        household_rs::HouseholdAuthState::load_optional(state_dir, &identity.record, unix_now())
            .unwrap()
            .expect("owner auth should load");
    Router::new()
        .route(
            "/api/v1/household/snapshot",
            get(handlers_household::snapshot).post(handlers_household::snapshot),
        )
        .with_state(HouseholdState::loaded_with_owner_auth(
            Arc::new(identity),
            Some(Arc::new(auth)),
        ))
}

#[tokio::test]
async fn owner_auth_survives_50_reload_cycles() {
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

    for _ in 0..50 {
        let app = reloaded_snapshot_router(td.path());
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
            StatusCode::OK
        );
    }
}
