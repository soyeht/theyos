mod phase1_helpers;

use std::sync::Arc;

use axum::http::StatusCode;

#[tokio::test]
async fn restart_determinism_50_cycles() {
    let td = tempfile::tempdir().unwrap();
    let first = Arc::new(phase1_helpers::bootstrap_identity(
        td.path(),
        "Sample Home",
        "studio-mac",
    ));
    let first_app = phase1_helpers::identity_router(Some(first));
    let baseline = phase1_helpers::get(&first_app, "/api/v1/household/identity").await;
    assert_eq!(baseline.status, StatusCode::OK);

    for _ in 0..50 {
        let loaded = Arc::new(phase1_helpers::load_existing_identity(td.path()));
        let app = phase1_helpers::identity_router(Some(loaded));
        let response = phase1_helpers::get(&app, "/api/v1/household/identity").await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, baseline.body);
    }
}
