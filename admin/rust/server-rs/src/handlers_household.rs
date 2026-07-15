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
use std::path::PathBuf;

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

/// Combined router state for the owner-authed machines list: the in-memory
/// household identity (for the `PoP` gate, same as `snapshot`) plus the on-disk
/// `state_dir` needed to read `machine_certs/<m_id>.cbor`.
#[derive(Clone)]
pub struct MachinesRouterState {
    pub household: HouseholdState,
    pub state_dir: PathBuf,
}

#[derive(Serialize)]
struct MachineEntry {
    machine_id: String,
    /// Hex of the 33-byte SEC1 PUBLIC key — never secret.
    machine_pub: String,
    host_label: String,
    platform: &'static str,
    is_self: bool,
    capabilities: Vec<&'static str>,
    joined_at: u64,
}

#[derive(Serialize)]
struct MachinesResponse {
    v: u8,
    hh_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    self_m_id: Option<String>,
    machines: Vec<MachineEntry>,
}

fn platform_str(p: &household_rs::Platform) -> &'static str {
    match p {
        household_rs::Platform::Macos => "macos",
        household_rs::Platform::LinuxNix => "linux-nix",
        household_rs::Platform::LinuxOther => "linux-other",
    }
}

/// `GET /api/v1/household/machines` — owner-authed list of the household's own
/// machine certs (the base/self engine machine included). Same `PoP` gate as
/// `snapshot` (`Operation::ClawsList`); a ±60s timestamp-tolerance gate, no
/// nonce cache. Returns identity-only fields; NEVER any secret, signature, or
/// native endpoint. Guest/no-auth → 401. Each cert is hh_id-filtered AND
/// signature-verified against the household root before it is served, so a
/// tampered/foreign cert file is never returned.
pub async fn machines(
    State(state): State<MachinesRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let Some(now) = time_util::unix_now_secs_checked("household.machines.clock") else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // Identical owner-auth gate to `snapshot`.
    let Ok(owner_auth) = household_auth::authorize_request(
        &state.household,
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

    // Household root pubkey + hh_id for per-cert verification. The loaded
    // identity is the same source `authorize_request` verifies against.
    let Some(identity) = state.household.current().await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let hh_pub = &identity.record.hh_pub;
    let expected_hh_id = &identity.record.hh_id;

    let self_m_id = match household_rs::storage::read_self_m_id(&state.state_dir) {
        Ok(opt) => opt,
        Err(e) => {
            tracing::warn!(stage = "household.machines.self_m_id_read_failed", error = %e);
            None
        }
    };

    let certs_dir = household_rs::storage::machine_certs_dir(&state.state_dir);
    let mut machines: Vec<MachineEntry> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&certs_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("cbor") {
                continue; // skip .staged / non-cert files
            }
            let cert: household_rs::MachineCert =
                match household_rs::storage::read_optional_cbor(&path) {
                    Ok(Some(c)) => c,
                    Ok(None) => continue,
                    Err(e) => {
                        tracing::warn!(
                            stage = "household.machines.cert_decode_failed",
                            path = %path.display(),
                            error = %e,
                        );
                        continue;
                    }
                };
            // SECURITY: only serve certs that belong to THIS household AND
            // verify under the household root key. Skip (fail-soft) otherwise.
            if &cert.hh_id != expected_hh_id {
                tracing::warn!(
                    stage = "household.machines.cert_foreign_hh",
                    path = %path.display(),
                );
                continue;
            }
            if cert.verify(hh_pub).is_err() {
                tracing::warn!(
                    stage = "household.machines.cert_verify_failed",
                    path = %path.display(),
                );
                continue;
            }
            let m_id = cert.m_id.to_string();
            let is_self = self_m_id.as_deref() == Some(m_id.as_str());
            machines.push(MachineEntry {
                machine_id: m_id,
                machine_pub: hex::encode(cert.m_pub.as_bytes()),
                host_label: cert.hostname.clone(),
                platform: platform_str(&cert.platform),
                is_self,
                capabilities: vec!["engine", "pty", "clawsite"],
                joined_at: cert.joined_at,
            });
        }
    }
    machines.sort_by(|a, b| {
        b.is_self
            .cmp(&a.is_self)
            .then_with(|| a.machine_id.cmp(&b.machine_id))
    });

    tracing::info!(
        stage = "household.machines.served",
        hh_id = %owner_auth.hh_id,
        count = machines.len(),
        has_self = self_m_id.is_some(),
    );

    Json(MachinesResponse {
        v: 1,
        hh_id: owner_auth.hh_id.to_string(),
        self_m_id,
        machines,
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
