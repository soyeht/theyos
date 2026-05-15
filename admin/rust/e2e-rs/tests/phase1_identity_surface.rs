mod phase1_helpers;
mod phase2_helpers;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use household_rs::pair_device::PairDeviceWindow;
use serde_json::json;

#[tokio::test]
async fn negative_routes_and_pair_device_window_surface_contract() {
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

    for path in [
        "/metrics",
        "/api/v1/household/members",
        "/api/v1/household/devices",
        "/api/v1/household/people",
    ] {
        assert_eq!(
            phase1_helpers::get(&app, path).await.status,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        phase1_helpers::get(&app, "/api/v1/household/identity")
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        phase1_helpers::post_json(&app, "/api/v1/household/pair-device/initiate", json!({}))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        phase1_helpers::post_json(&app, "/api/v1/household/pair-device/confirm", json!({}))
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    let consumed = phase1_helpers::post_json(
        &app,
        "/api/v1/household/pair-device/confirm",
        phase2_helpers::signed_pair_confirm_body(
            &identity.record.hh_id,
            &token.nonce,
            &phase2_helpers::TestPersonKey::generate(),
            "Owner",
        ),
    )
    .await;
    assert_eq!(consumed.status, StatusCode::OK);
    assert!(phase1_helpers::parse_confirm(&consumed).consumed);
    assert_eq!(
        phase1_helpers::post_json(&app, "/api/v1/household/pair-device/initiate", json!({}))
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    let _reissued = window
        .mint_token(Duration::from_secs(60), None)
        .await
        .unwrap();
    assert_eq!(
        phase1_helpers::post_json(&app, "/api/v1/household/pair-device/initiate", json!({}))
            .await
            .status,
        StatusCode::OK
    );
}
