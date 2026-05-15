mod phase1_helpers;
mod phase2_helpers;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use household_rs::pair_device::PairDeviceWindow;

#[tokio::test]
async fn bearer_only_is_rejected_for_household_scoped_authenticated_route() {
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

    assert_eq!(
        phase1_helpers::get_with_auth(&app, "/api/v1/household/snapshot", "Bearer legacy-token",)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        phase1_helpers::get(&app, "/api/v1/household/identity")
            .await
            .status,
        StatusCode::OK
    );
}
