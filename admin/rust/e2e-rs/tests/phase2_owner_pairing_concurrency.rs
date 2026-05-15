mod phase1_helpers;
mod phase2_helpers;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use household_rs::pair_device::PairDeviceWindow;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_confirm_allows_exactly_one_success() {
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
    let body = phase2_helpers::signed_pair_confirm_body(
        &identity.record.hh_id,
        &token.nonce,
        &person,
        "Owner",
    );

    let mut tasks = Vec::new();
    for _ in 0..100 {
        let app = app.clone();
        let body = body.clone();
        tasks.push(tokio::spawn(async move {
            phase1_helpers::post_json(&app, "/api/v1/household/pair-device/confirm", body)
                .await
                .status
        }));
    }
    let mut ok = 0;
    let mut not_found = 0;
    for task in tasks {
        match task.await.unwrap() {
            StatusCode::OK => ok += 1,
            StatusCode::NOT_FOUND => not_found += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(ok, 1);
    assert_eq!(not_found, 99);
    assert!(!window.is_open().await);
}
