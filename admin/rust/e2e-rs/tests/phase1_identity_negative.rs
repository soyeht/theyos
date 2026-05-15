mod phase1_helpers;

use std::sync::Arc;

use axum::http::StatusCode;
use household_rs::storage::household_record_path;

#[tokio::test]
async fn identity_negative_conformance_c2_c4_c6() {
    let empty = phase1_helpers::identity_router(None);
    let not_bootstrapped = phase1_helpers::get(&empty, "/api/v1/household/identity").await;
    assert_eq!(not_bootstrapped.status, StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = serde_json::from_slice(&not_bootstrapped.body).unwrap();
    assert_eq!(body["code"], "HOUSEHOLD_NOT_BOOTSTRAPPED");

    let targets = server_rs::household_listener::enumerate_bind_targets();
    assert!(targets.iter().all(|(ip, _)| !ip.is_unspecified()));

    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(phase1_helpers::bootstrap_identity(
        td.path(),
        "Sample Home",
        "studio-mac",
    ));
    let app = phase1_helpers::identity_router(Some(identity));
    assert_eq!(
        phase1_helpers::get(&app, "/api/v1/household/identity")
            .await
            .status,
        StatusCode::OK
    );

    let path = household_record_path(td.path());
    let mut bytes = std::fs::read(&path).unwrap();
    let idx = bytes.len() / 2;
    bytes[idx] ^= 0x01;
    std::fs::write(&path, bytes).unwrap();
    let Err(err) =
        household_rs::try_load_existing(td.path(), household_rs::KeyBackingPolicy::ForceSoftware)
    else {
        panic!("corrupt household record loaded successfully");
    };
    assert!(
        matches!(err.stage(), "load.household_record" | "load.verify_chain"),
        "unexpected corrupt-record stage: {}",
        err.stage()
    );
}
