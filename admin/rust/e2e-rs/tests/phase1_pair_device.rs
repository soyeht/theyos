mod phase1_helpers;
mod phase2_helpers;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use household_rs::pair_device::PairDeviceWindow;
use serde_json::json;

#[tokio::test]
async fn pair_device_flow_consumes_token_and_reissue_invalidates_prior_token() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(phase1_helpers::bootstrap_identity(
        td.path(),
        "Sample Home",
        "studio-mac",
    ));
    let window = Arc::new(PairDeviceWindow::new());
    let first = window
        .mint_token(Duration::from_secs(60), None)
        .await
        .unwrap();
    let app =
        phase1_helpers::household_router(Arc::clone(&identity), Arc::clone(&window), td.path());

    let initiated =
        phase1_helpers::post_json(&app, "/api/v1/household/pair-device/initiate", json!({})).await;
    assert_eq!(initiated.status, StatusCode::OK);
    let uri = phase1_helpers::parse_initiate(&initiated).uri;
    assert!(uri.starts_with("soyeht://household/pair-device?"));
    assert_eq!(phase1_helpers::uri_param(&uri, "v").as_deref(), Some("1"));
    assert_eq!(
        phase1_helpers::uri_param(&uri, "nonce").as_deref(),
        Some(first.nonce.as_b64().as_str())
    );
    assert!(phase1_helpers::uri_param(&uri, "hh_pub").is_some());
    assert!(phase1_helpers::uri_param(&uri, "ttl").is_some());

    let malformed_device_key = phase1_helpers::post_json(
        &app,
        "/api/v1/household/pair-device/confirm",
        json!({ "v": 1, "nonce": first.nonce.as_b64(), "p_pub": "not-base64url", "proof_sig": "not-base64url" }),
    )
    .await;
    assert_eq!(malformed_device_key.status, StatusCode::NOT_FOUND);
    assert!(
        window.is_open().await,
        "malformed d_pub must not consume token"
    );

    let person = phase2_helpers::TestPersonKey::generate();
    let confirmed = phase1_helpers::post_json(
        &app,
        "/api/v1/household/pair-device/confirm",
        phase2_helpers::signed_pair_confirm_body(
            &identity.record.hh_id,
            &first.nonce,
            &person,
            "Owner",
        ),
    )
    .await;
    assert_eq!(confirmed.status, StatusCode::OK);
    assert!(phase1_helpers::parse_confirm(&confirmed).consumed);
    assert_eq!(
        phase1_helpers::post_json(
            &app,
            "/api/v1/household/pair-device/confirm",
            json!({ "nonce": first.nonce.as_b64() }),
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );

    let expiring = window
        .mint_token(Duration::from_millis(20), None)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(!window.is_open().await);
    assert_eq!(
        phase1_helpers::post_json(
            &app,
            "/api/v1/household/pair-device/confirm",
            json!({ "nonce": expiring.nonce.as_b64() }),
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );

    let old = window
        .mint_token(Duration::from_secs(60), None)
        .await
        .unwrap();
    let new = window
        .mint_token(Duration::from_secs(60), None)
        .await
        .unwrap();
    assert_ne!(old.nonce.as_b64(), new.nonce.as_b64());
    assert_eq!(
        phase1_helpers::post_json(
            &app,
            "/api/v1/household/pair-device/confirm",
            json!({ "nonce": old.nonce.as_b64() }),
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    let person = phase2_helpers::TestPersonKey::generate();
    assert_eq!(
        phase1_helpers::post_json(
            &app,
            "/api/v1/household/pair-device/confirm",
            phase2_helpers::signed_pair_confirm_body(
                &identity.record.hh_id,
                &new.nonce,
                &person,
                "Owner"
            ),
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
}
