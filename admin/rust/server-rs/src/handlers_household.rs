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
use std::path::{Path, PathBuf};

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
    online: bool,
    capabilities: Vec<&'static str>,
    joined_at: u64,
}

/// Timeout for the on-demand `/healthz` liveness probe used by
/// [`machines`] to fill in `MachineEntry::online` for non-self members.
const HEALTHZ_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1500);

/// Rejects loopback/unspecified/link-local literals as probe targets. The
/// sidecar address comes from a peer's own self-announced `JoinRequest.addr`
/// (validated only for well-formed `host:port` shape, not IP range) — without
/// this, a joined-but-malicious peer could plant e.g. `127.0.0.1:<port>` and
/// turn this founder's own probe into a blind reachability oracle against the
/// founder's local-only services. Ordinary LAN/Tailscale ranges (the actual
/// expected target space) are unaffected; non-IP hostnames pass through
/// unchanged, matching what `validate_join_addr` already accepted at capture
/// time.
fn is_safe_probe_host(host: &str) -> bool {
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            !(v4.is_loopback() || v4.is_unspecified() || v4.is_link_local())
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            !(v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
        Err(_) => true,
    }
}

/// Best-effort liveness probe for a non-self household member. Looks up the
/// last-known address from the ceremony-populated, non-authoritative
/// sidecar cache (`household_rs::storage::read_known_peer_addr`) and probes
/// its unauthenticated `/healthz`. Every failure mode — unknown address,
/// unsafe target, timeout, connection error, non-2xx — collapses to `false`:
/// this is a demo-grade presence signal probed synchronously per request,
/// not a hardened availability guarantee.
async fn probe_online(client: &reqwest::Client, state_dir: &Path, m_id: &str) -> bool {
    let Ok(Some(addr)) = household_rs::storage::read_known_peer_addr(state_dir, m_id) else {
        return false;
    };
    let host = addr
        .strip_prefix('[')
        .and_then(|rest| rest.split_once("]:"))
        .map(|(h, _)| h)
        .or_else(|| addr.rsplit_once(':').map(|(h, _)| h))
        .unwrap_or(addr.as_str());
    if !is_safe_probe_host(host) {
        return false;
    }
    probe_healthz(client, &addr).await
}

/// GET `addr`'s `/healthz` and report whether it answered 2xx within
/// [`HEALTHZ_PROBE_TIMEOUT`]. Separated from [`probe_online`] so the address
/// safety gate and the HTTP mechanics can each be tested at their own level.
async fn probe_healthz(client: &reqwest::Client, addr: &str) -> bool {
    let url = format!("http://{addr}/healthz");
    matches!(
        client.get(&url).timeout(HEALTHZ_PROBE_TIMEOUT).send().await,
        Ok(resp) if resp.status().is_success()
    )
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
    let http_client = reqwest::Client::new();
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
            let online = if is_self {
                true
            } else {
                probe_online(&http_client, &state.state_dir, &m_id).await
            };
            machines.push(MachineEntry {
                machine_id: m_id,
                machine_pub: hex::encode(cert.m_pub.as_bytes()),
                host_label: cert.hostname.clone(),
                platform: platform_str(&cert.platform),
                is_self,
                online,
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

    // `probe_online` backs `MachineEntry::online` for non-self machines.
    // These exercise it directly against the sidecar cache rather than
    // through the owner-PoP-gated `machines` handler, matching this file's
    // existing preference for testing the narrowest unit that carries the
    // behavior (see the `snapshot` 401-reason tests above).

    /// Accepts exactly one TCP connection and replies with a bare
    /// `200 OK`. The task is detached (not awaited) — it exits on its own
    /// once the single expected probe request lands.
    async fn spawn_ok_http_server() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn probe_online_false_when_address_unknown() {
        let td = tempdir().unwrap();
        let client = reqwest::Client::new();
        assert!(!probe_online(&client, td.path(), "m_unknown").await);
    }

    // `probe_online` itself rejects loopback (see `probe_online_false_*_gate`
    // tests below), so the "a real server answers" case is exercised at the
    // `probe_healthz` level — the HTTP-GET-and-check-status mechanic is what
    // this test verifies, not the address safety gate.
    #[tokio::test]
    async fn probe_healthz_true_when_server_responds() {
        let addr = spawn_ok_http_server().await;
        let client = reqwest::Client::new();
        assert!(probe_healthz(&client, &addr.to_string()).await);
    }

    #[test]
    fn is_safe_probe_host_rejects_loopback_link_local_unspecified() {
        assert!(!is_safe_probe_host("127.0.0.1"));
        assert!(!is_safe_probe_host("127.53.0.1"));
        assert!(!is_safe_probe_host("169.254.1.1"));
        assert!(!is_safe_probe_host("0.0.0.0"));
        assert!(!is_safe_probe_host("::1"));
        assert!(!is_safe_probe_host("::"));
    }

    #[test]
    fn is_safe_probe_host_accepts_ordinary_lan_and_tailscale_and_hostnames() {
        assert!(is_safe_probe_host("192.168.1.42"));
        assert!(is_safe_probe_host("10.0.0.5"));
        assert!(is_safe_probe_host("100.83.30.100")); // Tailscale CGNAT range
        assert!(is_safe_probe_host("some-machine.local"));
    }

    #[tokio::test]
    async fn probe_online_false_when_sidecar_address_is_loopback() {
        let td = tempdir().unwrap();
        let addr = spawn_ok_http_server().await;
        // Same server a real probe would reach — but stored under a loopback
        // literal, which the safety gate must reject before ever dialing it.
        household_rs::storage::write_known_peer_addr(td.path(), "m_peer", &addr.to_string())
            .unwrap();
        assert!(addr.ip().is_loopback());
        let client = reqwest::Client::new();
        assert!(!probe_online(&client, td.path(), "m_peer").await);
    }

    #[tokio::test]
    async fn probe_online_false_when_known_address_unreachable() {
        let td = tempdir().unwrap();
        // Bind then drop to obtain a loopback port nothing is listening on.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        household_rs::storage::write_known_peer_addr(td.path(), "m_peer", &addr.to_string())
            .unwrap();
        let client = reqwest::Client::new();
        assert!(!probe_online(&client, td.path(), "m_peer").await);
    }
}
