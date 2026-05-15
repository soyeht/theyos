mod phase1_helpers;

use std::sync::Arc;

use axum::http::{StatusCode, header};

#[tokio::test]
async fn identity_endpoint_conformance_c1_c3_c5_and_restart_determinism() {
    let td = tempfile::tempdir().unwrap();
    let first = Arc::new(phase1_helpers::bootstrap_identity(
        td.path(),
        "Sample Home",
        "studio-mac",
    ));
    let app = phase1_helpers::identity_router(Some(Arc::clone(&first)));

    let response1 = phase1_helpers::get(&app, "/api/v1/household/identity").await;
    assert_eq!(response1.status, StatusCode::OK);
    assert_eq!(
        response1.headers.get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body = phase1_helpers::parse_identity(&response1);
    phase1_helpers::assert_identity_contract(&body, "Sample Home");

    let response2 = phase1_helpers::get(&app, "/api/v1/household/identity").await;
    assert_eq!(response2.status, StatusCode::OK);
    assert_eq!(response1.body, response2.body);

    let rerun = phase1_helpers::bootstrap_identity(td.path(), "Sample Home", "studio-renamed");
    assert_eq!(first.record.hh_id, rerun.record.hh_id);
    assert_eq!(first.record.created_at, rerun.record.created_at);
    let restarted = Arc::new(phase1_helpers::load_existing_identity(td.path()));
    let restarted_app = phase1_helpers::identity_router(Some(restarted));
    let response3 = phase1_helpers::get(&restarted_app, "/api/v1/household/identity").await;
    assert_eq!(response1.body, response3.body);
}
