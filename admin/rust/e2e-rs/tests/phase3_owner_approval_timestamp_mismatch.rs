//! Negative coverage for owner-approval body/PoP timestamp binding.
//!
//! Happy-path owner approval uses one timestamp for both the signed
//! `OwnerApprovalContext` body and the request PoP. This test keeps the
//! low-level path available and proves a deliberate mismatch is rejected
//! instead of relying on the old incidental second-boundary flake.

mod phase3_support;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use phase3_support::{
    JOIN_REQUEST_PATH, JoinRequestAccepted, candidate_harness, founder_harness,
    owner_approval_body, pop_header, post_cbor, post_local_anchor, unix_now,
};

#[tokio::test]
async fn owner_approval_rejects_body_pop_timestamp_mismatch() {
    let founder = founder_harness();
    let candidate = candidate_harness().await;

    let (status, _, body) = post_cbor(
        founder.router.clone(),
        JOIN_REQUEST_PATH,
        candidate.prepared.join_request_cbor.clone(),
        Some(&founder.owner),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let accepted: JoinRequestAccepted =
        household_rs::cbor::from_canonical_slice(&body).expect("decode accepted");

    post_local_anchor(&candidate, &founder, &candidate.prepared.anchor_secret).await;

    let path = format!(
        "/api/v1/household/owner-events/{}/approve",
        accepted.owner_event_cursor
    );
    let body_timestamp = unix_now();
    let pop_timestamp = body_timestamp + 1;
    let body = owner_approval_body(
        &founder,
        &candidate.prepared.join_request,
        accepted.owner_event_cursor,
        body_timestamp,
    );
    let request = Request::builder()
        .method("POST")
        .uri(path.as_str())
        .header(header::CONTENT_TYPE, "application/cbor")
        .header(
            header::AUTHORIZATION,
            pop_header(&founder.owner, "POST", &path, pop_timestamp, &body),
        )
        .body(Body::from(body))
        .expect("request body");

    let response = founder
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("router response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
