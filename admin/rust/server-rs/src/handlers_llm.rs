//! Reverse-proxy for the host-side LLM proxy's `/admin/llm/*` endpoints.
//!
//! `server-rs` owns the admin session boundary (cookie auth, `AdminUser`
//! middleware) for the whole admin frontend. The LLM proxy daemon owns
//! the on-disk profile and credential storage — it runs as the primary
//! theyOS user with read/write access to `$HOME/.theyos/`, whereas
//! server-rs runs as the `soyeht` service account.
//!
//! The boundary between them is one HTTP hop on loopback: every
//! `/api/v1/llm/*` admin request lands here, gets the admin-cookie check,
//! then is forwarded verbatim to the default LLM proxy loopback port.
//! Method, headers we care about, body, and status all pass through; the
//! proxy's typed error JSON is forwarded so the frontend sees one shape
//! regardless of which crate produced the error.
//!
//! No state is kept in this module — `ProxyClient` is built from env at
//! startup and cloned through the axum `State` machinery via
//! `SharedState::llm_proxy_client()`.

use axum::body::{Body, Bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::Response;
use core_rs::{claw_llm::DEFAULT_LLM_PROXY_PORT, error::ApiError};
use std::sync::Arc;
use std::time::Duration;

use crate::auth::{AdminUser, AuthUser};
use crate::state::SharedState;

fn default_proxy_url() -> String {
    format!("http://127.0.0.1:{DEFAULT_LLM_PROXY_PORT}")
}

/// Thin reqwest wrapper. Cheap to clone (`reqwest::Client` is internally
/// `Arc`'d). Held inside `SharedState` so handlers don't construct a
/// fresh connection pool on every request.
#[derive(Clone)]
pub struct ProxyClient {
    inner: reqwest::Client,
    base: Arc<String>,
}

impl ProxyClient {
    /// Build from env. `THEYOS_LLM_PROXY_URL` overrides the loopback
    /// default, but is rejected unless:
    /// - the scheme is `http` (the proxy daemon is loopback HTTP, no
    ///   TLS), AND
    /// - the host is `127.0.0.1`, `::1`, or `localhost`.
    ///
    /// Why so strict: every admin LLM mutation — including provider
    /// adds, credential storage, active-profile swaps — passes through
    /// this client. The threat model in `docs/llm-proxy.md` rests on
    /// "credentials never leave the host". An operator typo
    /// (`http://0.0.0.0:18900`), a stale DNS entry, or a malicious env
    /// dump that swaps the URL would silently leak API keys to a remote
    /// endpoint. The hardcoded host list is intentional: we'd rather
    /// fail closed and force a code change than allow this knob to be
    /// the weakest link.
    ///
    /// Also pins `redirect::Policy::none()` so a 3xx response from a
    /// compromised endpoint cannot pivot the next hop.
    ///
    /// # Panics
    ///
    /// Panics if `reqwest::Client::builder().build()` fails. This only
    /// happens if the runtime can't allocate the connection pool — the
    /// proxy is loopback HTTP so there are no TLS roots / cert paths
    /// to mis-resolve. In every observed case the panic indicates the
    /// process is already broken.
    #[must_use]
    pub fn from_env() -> Self {
        let raw = std::env::var("THEYOS_LLM_PROXY_URL").unwrap_or_else(|_| default_proxy_url());
        let base = match validate_loopback_url(&raw) {
            Ok(normalized) => normalized,
            Err(reason) => {
                // Loud failure mode: log + use the default. A panic here
                // would prevent the entire admin server from starting,
                // which is worse — better to keep the rest of the admin
                // surface alive while the operator fixes the env.
                tracing::error!(
                    invalid = %raw,
                    reason = reason,
                    "THEYOS_LLM_PROXY_URL rejected; falling back to default loopback. LLM admin endpoints will only function if the proxy listens on the default."
                );
                default_proxy_url()
            }
        };

        let inner = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            // No redirects: the proxy is loopback HTTP; a 3xx is either a
            // misconfiguration or an attempt to redirect us off-box.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest::Client build (no TLS roots needed for loopback HTTP) must succeed");
        Self {
            inner,
            base: Arc::new(base),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }
}

/// Parse `raw` as an HTTP URL and verify the host is loopback. Returns
/// the URL with trailing slashes trimmed, ready for path concatenation.
fn validate_loopback_url(raw: &str) -> Result<String, &'static str> {
    let url = reqwest::Url::parse(raw).map_err(|_| "not a valid URL")?;
    if url.scheme() != "http" {
        return Err("scheme must be http (loopback only, no TLS needed)");
    }
    let host = url.host_str().ok_or("missing host")?;
    if !matches!(host, "127.0.0.1" | "::1" | "[::1]" | "localhost") {
        return Err("host must be 127.0.0.1, ::1, or localhost");
    }
    Ok(raw.trim_end_matches('/').to_string())
}

/// `GET /api/v1/llm/catalog` — static provider catalog. Read-only, so the
/// frontend can populate dropdowns without round-tripping through the
/// admin DB.
pub async fn handle_catalog(
    State(state): State<SharedState>,
    AdminUser(AuthUser { .. }): AdminUser,
) -> Result<Response, ApiError> {
    forward(
        &state,
        Method::GET,
        "/admin/catalog",
        HeaderMap::new(),
        Bytes::new(),
    )
    .await
}

/// `GET /api/v1/llm/active` — current default + per-claw overlays.
pub async fn handle_get_active(
    State(state): State<SharedState>,
    AdminUser(AuthUser { .. }): AdminUser,
) -> Result<Response, ApiError> {
    forward(
        &state,
        Method::GET,
        "/admin/llm/active",
        HeaderMap::new(),
        Bytes::new(),
    )
    .await
}

/// `PUT /api/v1/llm/active` — change the global default provider/model.
pub async fn handle_put_active(
    State(state): State<SharedState>,
    AdminUser(AuthUser { .. }): AdminUser,
    request: Request,
) -> Result<Response, ApiError> {
    let (headers, body) = take_json_body(request).await?;
    forward(&state, Method::PUT, "/admin/llm/active", headers, body).await
}

/// `PUT /api/v1/llm/active/{claw_type}` — install or update a per-claw
/// overlay. The path segment is forwarded verbatim; the proxy validates
/// it against `[A-Za-z0-9_-]+` and rejects path traversal.
pub async fn handle_put_active_claw(
    State(state): State<SharedState>,
    AdminUser(AuthUser { .. }): AdminUser,
    Path(claw_type): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let (headers, body) = take_json_body(request).await?;
    let path = format!(
        "/admin/llm/active/{}",
        percent_encoding::utf8_percent_encode(&claw_type, percent_encoding::NON_ALPHANUMERIC,)
    );
    forward(&state, Method::PUT, &path, headers, body).await
}

/// `DELETE /api/v1/llm/active/{claw_type}` — remove a per-claw overlay.
pub async fn handle_delete_active_claw(
    State(state): State<SharedState>,
    AdminUser(AuthUser { .. }): AdminUser,
    Path(claw_type): Path<String>,
) -> Result<Response, ApiError> {
    let path = format!(
        "/admin/llm/active/{}",
        percent_encoding::utf8_percent_encode(&claw_type, percent_encoding::NON_ALPHANUMERIC,)
    );
    forward(
        &state,
        Method::DELETE,
        &path,
        HeaderMap::new(),
        Bytes::new(),
    )
    .await
}

/// `GET /api/v1/llm/providers` — list all configured providers.
pub async fn handle_list_providers(
    State(state): State<SharedState>,
    AdminUser(AuthUser { .. }): AdminUser,
) -> Result<Response, ApiError> {
    forward(
        &state,
        Method::GET,
        "/admin/llm/providers",
        HeaderMap::new(),
        Bytes::new(),
    )
    .await
}

/// `POST /api/v1/llm/providers` — create or update a provider config +
/// (optionally) write its credential to the host keystore.
pub async fn handle_upsert_provider(
    State(state): State<SharedState>,
    AdminUser(AuthUser { .. }): AdminUser,
    request: Request,
) -> Result<Response, ApiError> {
    let (headers, body) = take_json_body(request).await?;
    forward(&state, Method::POST, "/admin/llm/providers", headers, body).await
}

/// `DELETE /api/v1/llm/providers/{id}` — remove a provider from the
/// profile and best-effort delete its credential. Rejected if the
/// provider is currently active.
pub async fn handle_delete_provider(
    State(state): State<SharedState>,
    AdminUser(AuthUser { .. }): AdminUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let path = format!(
        "/admin/llm/providers/{}",
        percent_encoding::utf8_percent_encode(&id, percent_encoding::NON_ALPHANUMERIC)
    );
    forward(
        &state,
        Method::DELETE,
        &path,
        HeaderMap::new(),
        Bytes::new(),
    )
    .await
}

/// `POST /api/v1/llm/providers/{id}/test` — live probe against the
/// upstream. One-token chat call, returns `{ok, latency_ms, error?}`.
pub async fn handle_test_provider(
    State(state): State<SharedState>,
    AdminUser(AuthUser { .. }): AdminUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let path = format!(
        "/admin/llm/providers/{}/test",
        percent_encoding::utf8_percent_encode(&id, percent_encoding::NON_ALPHANUMERIC)
    );
    forward(&state, Method::POST, &path, HeaderMap::new(), Bytes::new()).await
}

/// `GET /api/v1/llm/audit?limit=N&before=ISO-8601` — paginated audit log.
pub async fn handle_get_audit(
    State(state): State<SharedState>,
    AdminUser(AuthUser { .. }): AdminUser,
    axum::extract::Query(q): axum::extract::Query<std::collections::BTreeMap<String, String>>,
) -> Result<Response, ApiError> {
    // Forward arbitrary query params (limit, before) verbatim so the
    // proxy's typed deserialization stays the single validation point.
    let qs = q
        .into_iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                percent_encoding::utf8_percent_encode(&k, percent_encoding::NON_ALPHANUMERIC),
                percent_encoding::utf8_percent_encode(&v, percent_encoding::NON_ALPHANUMERIC),
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    let path = if qs.is_empty() {
        "/admin/llm/audit".to_string()
    } else {
        format!("/admin/llm/audit?{qs}")
    };
    forward(&state, Method::GET, &path, HeaderMap::new(), Bytes::new()).await
}

/// Buffer the request body (admin endpoints are tiny JSON payloads, well
/// under any reasonable cap) and capture the headers we want to forward.
async fn take_json_body(request: Request) -> Result<(HeaderMap, Bytes), ApiError> {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|e| ApiError::bad_request(format!("read body: {e}")))?;
    let mut headers = HeaderMap::new();
    if let Some(ct) = parts.headers.get("content-type") {
        headers.insert("content-type", ct.clone());
    }
    Ok((headers, bytes))
}

/// Make the upstream call and translate the response back into a
/// `Response`. Errors from the loopback hop itself surface as
/// `INTERNAL` `ApiErrors` because they represent a misconfiguration of
/// the host, not a user error.
async fn forward(
    state: &SharedState,
    method: Method,
    path: &str,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let client = &state.llm_proxy_client;
    let url = client.url(path);
    let mut req_builder = client.inner.request(method.clone(), &url);
    for (name, value) in &headers {
        req_builder = req_builder.header(name.as_str(), value);
    }
    if !body.is_empty() {
        req_builder = req_builder.body(body.clone());
    }
    let resp = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                error = %e,
                method = %method,
                upstream = %url,
                "llm-proxy reverse-proxy: upstream call failed"
            );
            return Err(ApiError::internal("llm proxy unreachable on loopback"));
        }
    };
    let status = resp.status();
    let mut out_headers = HeaderMap::new();
    if let Some(ct) = resp.headers().get("content-type") {
        if let Ok(v) = HeaderValue::from_bytes(ct.as_bytes()) {
            out_headers.insert("content-type", v);
        }
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| ApiError::internal(format!("llm proxy response read: {e}")))?;
    let status_code =
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status_code;
    *response.headers_mut() = out_headers;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_default_loopback() {
        assert!(validate_loopback_url(&default_proxy_url()).is_ok());
    }

    #[test]
    fn validate_accepts_localhost_and_ipv6() {
        assert!(validate_loopback_url("http://localhost:18900").is_ok());
        assert!(validate_loopback_url("http://[::1]:18900").is_ok());
    }

    #[test]
    fn validate_rejects_non_loopback_v4() {
        assert!(validate_loopback_url("http://0.0.0.0:18900").is_err());
        assert!(validate_loopback_url("http://10.0.0.1:18900").is_err());
        assert!(validate_loopback_url("http://192.168.1.1:18900").is_err());
    }

    #[test]
    fn validate_rejects_https_and_non_http_schemes() {
        assert!(validate_loopback_url("https://127.0.0.1:18900").is_err());
        assert!(validate_loopback_url("file:///etc/passwd").is_err());
        assert!(validate_loopback_url("unix:///tmp/sock").is_err());
    }

    #[test]
    fn validate_rejects_dns_lookalike_hosts() {
        assert!(validate_loopback_url("http://127.0.0.1.evil.com:18900").is_err());
        assert!(validate_loopback_url("http://localhost.evil.com:18900").is_err());
    }

    #[test]
    fn trailing_slash_is_stripped() {
        let raw = format!("{}/", default_proxy_url());
        assert_eq!(validate_loopback_url(&raw).unwrap(), default_proxy_url());
    }
}
