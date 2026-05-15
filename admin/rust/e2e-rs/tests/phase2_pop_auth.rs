mod phase1_helpers;
mod phase2_helpers;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use household_rs::pair_device::PairDeviceWindow;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn paired_app() -> (
    axum::Router,
    phase2_helpers::TestPersonKey,
    tempfile::TempDir,
    Arc<household_rs::LoadedIdentity>,
) {
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
    (app, person, td, identity)
}

#[tokio::test]
async fn pop_auth_accepts_valid_and_rejects_stale_tampered_wrong_path() {
    let (app, person, _td, _identity) = paired_app().await;
    let now = unix_now();
    let valid =
        phase2_helpers::pop_header(&person, "GET", "/api/v1/household/snapshot?x=y", now, b"");
    assert_eq!(
        phase1_helpers::get_with_auth(&app, "/api/v1/household/snapshot?x=y", &valid)
            .await
            .status,
        StatusCode::OK
    );

    let stale = phase2_helpers::pop_header(
        &person,
        "GET",
        "/api/v1/household/snapshot",
        now.saturating_sub(120),
        b"",
    );
    assert_eq!(
        phase1_helpers::get_with_auth(&app, "/api/v1/household/snapshot", &stale)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );

    let wrong_path =
        phase2_helpers::pop_header(&person, "GET", "/api/v1/household/other", now, b"");
    assert_eq!(
        phase1_helpers::get_with_auth(&app, "/api/v1/household/snapshot", &wrong_path)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );

    let signed_body = phase2_helpers::pop_header(
        &person,
        "POST",
        "/api/v1/household/snapshot",
        now,
        b"original",
    );
    assert_eq!(
        phase1_helpers::post_body_with_auth(
            &app,
            "/api/v1/household/snapshot",
            b"tampered".to_vec(),
            &signed_body,
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
}
