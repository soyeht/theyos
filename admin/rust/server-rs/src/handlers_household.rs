//! `GET /api/v1/household/identity` handler.
//!
//! Contract: see `specs/001-phase-1-crypto-skeleton/contracts/identity-endpoint.md`.

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::Serialize;

use crate::household_auth;
use crate::household_state::HouseholdState;
use crate::time_util;

#[derive(Serialize)]
struct IdentityResponse {
    version: u8,
    hh_id: String,
    hh_pub_b64: String,
    name: String,
    created_at: u64,
}

#[derive(Serialize)]
struct NotBootstrappedResponse {
    error: &'static str,
    code: &'static str,
    hint: &'static str,
}

/// `GET /api/v1/household/identity` — returns 200 with public identity, or 503
/// during the narrow bootstrap-incomplete window.
pub async fn get_identity(State(state): State<HouseholdState>) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let Some(loaded) = state.current().await else {
        let body = NotBootstrappedResponse {
            error: "not_bootstrapped",
            code: "HOUSEHOLD_NOT_BOOTSTRAPPED",
            hint: "Run `theyos install` to bootstrap a household.",
        };
        let mut resp = (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response();
        resp.headers_mut().extend(headers);
        return resp;
    };

    let body = IdentityResponse {
        version: loaded.record.version,
        hh_id: loaded.record.hh_id.to_string(),
        hh_pub_b64: B64.encode(loaded.record.hh_pub.as_bytes()),
        name: loaded.record.name.clone(),
        created_at: loaded.record.created_at,
    };
    let mut resp = (StatusCode::OK, Json(body)).into_response();
    resp.headers_mut().extend(headers);
    resp
}

#[derive(Serialize)]
struct SnapshotResponse {
    v: u8,
    hh_id: String,
    owner_p_id: String,
}

pub async fn snapshot(
    State(state): State<HouseholdState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let Some(now) = time_util::unix_now_secs_checked("household.snapshot.clock") else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(owner_auth) = household_auth::authorize_request(
        &state,
        &headers,
        &method,
        &path_and_query,
        &body,
        household_rs::caveats::Operation::ClawsList,
        now,
    )
    .await
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    Json(SnapshotResponse {
        v: 1,
        hh_id: owner_auth.hh_id.to_string(),
        owner_p_id: owner_auth.owner_person_cert.p_id.0.clone(),
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request, routing::get};
    use household_rs::{BootstrapOpts, KeyBackingPolicy, bootstrap_or_load};
    use std::sync::Arc;
    use tempfile::tempdir;
    use tower::util::ServiceExt;

    fn router_with_state(state: HouseholdState) -> Router {
        Router::new()
            .route("/api/v1/household/identity", get(get_identity))
            .with_state(state)
    }

    #[tokio::test]
    async fn returns_503_when_not_bootstrapped() {
        let app = router_with_state(HouseholdState::empty());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/household/identity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn returns_200_when_loaded() {
        // Force software keys via the typed policy — never mutate env vars
        // in tests (UB under Rust 2024 with parallel test runner).
        let td = tempdir().unwrap();
        let identity = bootstrap_or_load(
            td.path(),
            BootstrapOpts {
                household_name: "Sample Home".into(),
                hostname_label: Some("studio-test".into()),
            },
            KeyBackingPolicy::ForceSoftware,
        )
        .expect("bootstrap");
        let app = router_with_state(HouseholdState::loaded(Arc::new(identity)));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/household/identity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    /// Bootstrap a real (software-keyed) household and wrap it in a loaded state.
    /// The returned `TempDir` must be kept alive for the duration of the test.
    fn loaded_state_with_dir() -> (HouseholdState, tempfile::TempDir) {
        let td = tempdir().unwrap();
        let identity = bootstrap_or_load(
            td.path(),
            BootstrapOpts {
                household_name: "Sample Home".into(),
                hostname_label: Some("studio-test".into()),
            },
            KeyBackingPolicy::ForceSoftware,
        )
        .expect("bootstrap");
        (HouseholdState::loaded(Arc::new(identity)), td)
    }

    fn snapshot_router(state: HouseholdState) -> Router {
        Router::new()
            .route("/api/v1/household/snapshot", get(snapshot))
            .with_state(state)
    }

    // The snapshot endpoint is the owner-PoP gate the iPhone hits to read claws.
    // `get_identity` is public (503/200 above), but snapshot MUST reject any caller
    // that does not present a valid PoP — even on a fully bootstrapped household.

    #[tokio::test]
    async fn snapshot_returns_401_without_authorization_header() {
        let (state, _td) = loaded_state_with_dir();
        let resp = snapshot_router(state)
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/household/snapshot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Loaded household, but no PoP → AuthError::Missing → 401, not a 200 leak.
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn snapshot_returns_401_with_malformed_pop_header() {
        let (state, _td) = loaded_state_with_dir();
        let resp = snapshot_router(state)
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/household/snapshot")
                    // Right prefix, but not the version/p_id/ts/sig structure the
                    // parser requires → AuthError::Malformed → 401.
                    .header(header::AUTHORIZATION, "Soyeht-PoP garbage")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
