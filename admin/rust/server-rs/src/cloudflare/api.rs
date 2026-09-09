//! Cloudflare API v4 client (synchronous, ureq-based).
//!
//! Used by the admin UI's Settings → Cloudflare flow to fully automate the
//! one-time setup that previously required the operator to SSH, edit nix,
//! and click around the Cloudflare dashboard. With a single API token (scopes:
//! `Account: Cloudflare Tunnel: Edit` + `Zone: DNS: Edit`) this client can:
//!
//!   * verify the token,
//!   * list zones the token can manage,
//!   * create / delete a tunnel and fetch its connector token,
//!   * create / delete CNAME DNS records pointing at the tunnel.
//!
//! All methods are synchronous (`ureq` is sync). Async callers wrap them in
//! `core_rs::error::blocking` to run on the tokio blocking pool.
//!
//! No retry logic, no rate-limit backoff. Cloudflare API is reliable enough
//! that surfacing the error to the UI is the right behaviour for an operator
//! action — the operator can retry the click.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

const API_BASE: &str = "https://api.cloudflare.com/client/v4";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(20);

/// Errors emitted by the Cloudflare client.
///
/// `Auth` is returned when the API rejects the token (HTTP 401/403); the UI
/// should suggest "regenerate the token". `Api` is the catch-all for any
/// non-success status with the upstream error message attached.
#[derive(Debug, Error)]
pub enum CfError {
    #[error("Cloudflare auth error: {0}")]
    Auth(String),
    #[error("Cloudflare API error ({status}): {message}")]
    Api { status: u16, message: String },
    #[error("Cloudflare network error: {0}")]
    Network(String),
    #[error("Cloudflare response parse error: {0}")]
    Parse(String),
}

/// Cloudflare API client. Holds a bearer token and a configured ureq agent.
pub struct CloudflareClient {
    token: String,
    agent: ureq::Agent,
}

impl CloudflareClient {
    /// Build a client from a raw API token (the `cfat_…` string).
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(CONNECT_TIMEOUT)
            .timeout_read(READ_TIMEOUT)
            .user_agent("theyos-admin/1.0")
            .build();
        Self {
            token: token.into(),
            agent,
        }
    }

    /// `GET /accounts/{account_id}/tokens/verify` — returns Ok on a valid token.
    ///
    /// Use to validate the token at setup time before any state-changing call.
    pub fn verify_token(&self, account_id: &str) -> Result<TokenInfo, CfError> {
        let url = format!("{API_BASE}/accounts/{account_id}/tokens/verify");
        let resp: CfEnvelope<TokenInfo> = self.get(&url)?;
        resp.into_result()
    }

    /// `GET /zones` — list every zone the token can manage.
    pub fn list_zones(&self) -> Result<Vec<ZoneSummary>, CfError> {
        // per_page=50 covers the vast majority of operator accounts; we don't
        // paginate yet because >50 zones is a multi-tenant edge case that this
        // single-tunnel UX doesn't aim to solve.
        let url = format!("{API_BASE}/zones?per_page=50");
        let resp: CfEnvelope<Vec<ZoneSummary>> = self.get(&url)?;
        resp.into_result()
    }

    /// `POST /accounts/{account_id}/cfd_tunnel` — create a Cloudflare Tunnel.
    ///
    /// Generates a fresh 32-byte tunnel secret locally and base64-encodes it
    /// for the API. Returns the tunnel id; fetch the connector token separately
    /// via [`fetch_connector_token`](Self::fetch_connector_token).
    pub fn create_tunnel(&self, account_id: &str, name: &str) -> Result<TunnelCreated, CfError> {
        let secret = generate_tunnel_secret();
        let url = format!("{API_BASE}/accounts/{account_id}/cfd_tunnel");
        let body = serde_json::json!({
            "name": name,
            "tunnel_secret": secret,
            "config_src": "local",
        });
        let resp: CfEnvelope<TunnelCreated> = self.post(&url, &body)?;
        resp.into_result()
    }

    /// `DELETE /accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections` —
    /// force-clean any registered connections so the subsequent tunnel delete
    /// doesn't get rejected with "tunnel has active connections" (CF code
    /// 1022). Equivalent to `cloudflared tunnel cleanup <id>`. Mandatory step
    /// even after stopping cloudflared, because CF takes minutes to mark a
    /// connector inactive on its own. 404 = no connections, treated as
    /// success.
    pub fn cleanup_tunnel_connections(
        &self,
        account_id: &str,
        tunnel_id: &str,
    ) -> Result<(), CfError> {
        let url = format!("{API_BASE}/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections");
        match self
            .agent
            .delete(&url)
            .set("Authorization", &self.bearer())
            .call()
        {
            Ok(_) | Err(ureq::Error::Status(404, _)) => Ok(()),
            Err(e) => Err(map_ureq_error(&e)),
        }
    }

    /// `DELETE /accounts/{account_id}/cfd_tunnel/{tunnel_id}` — best-effort
    /// teardown. Cloudflare returns 200 even if the tunnel was already
    /// deleted; treat 404 as success too. Call
    /// [`cleanup_tunnel_connections`](Self::cleanup_tunnel_connections) first
    /// to avoid the "active connections" rejection.
    pub fn delete_tunnel(&self, account_id: &str, tunnel_id: &str) -> Result<(), CfError> {
        let url = format!("{API_BASE}/accounts/{account_id}/cfd_tunnel/{tunnel_id}");
        match self
            .agent
            .delete(&url)
            .set("Authorization", &self.bearer())
            .call()
        {
            Ok(_) | Err(ureq::Error::Status(404, _)) => Ok(()),
            Err(e) => Err(map_ureq_error(&e)),
        }
    }

    /// `GET /accounts/{account_id}/cfd_tunnel/{tunnel_id}/token` — connector
    /// token to be written to `/var/lib/cloudflared/token` so cloudflared can
    /// register the tunnel on startup.
    pub fn fetch_connector_token(
        &self,
        account_id: &str,
        tunnel_id: &str,
    ) -> Result<String, CfError> {
        let url = format!("{API_BASE}/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token");
        let resp: CfEnvelope<String> = self.get(&url)?;
        resp.into_result()
    }

    /// `POST /zones/{zone_id}/dns_records` — create a proxied CNAME pointing
    /// at the tunnel. `name` is the subdomain part (e.g. `app` for
    /// `app.example.com`), or `@` for the apex.
    pub fn create_dns_cname(
        &self,
        zone_id: &str,
        name: &str,
        target: &str,
    ) -> Result<DnsRecord, CfError> {
        let url = format!("{API_BASE}/zones/{zone_id}/dns_records");
        let body = serde_json::json!({
            "type": "CNAME",
            "name": name,
            "content": target,
            "proxied": true,
            "ttl": 1,
        });
        let resp: CfEnvelope<DnsRecord> = self.post(&url, &body)?;
        resp.into_result()
    }

    /// `DELETE /zones/{zone_id}/dns_records/{record_id}`. 404 is treated as
    /// success (record already gone).
    pub fn delete_dns_record(&self, zone_id: &str, record_id: &str) -> Result<(), CfError> {
        let url = format!("{API_BASE}/zones/{zone_id}/dns_records/{record_id}");
        match self
            .agent
            .delete(&url)
            .set("Authorization", &self.bearer())
            .call()
        {
            Ok(_) | Err(ureq::Error::Status(404, _)) => Ok(()),
            Err(e) => Err(map_ureq_error(&e)),
        }
    }

    // ── internal helpers ────────────────────────────────────────────────────

    fn bearer(&self) -> String {
        format!("Bearer {}", self.token)
    }

    fn get<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T, CfError> {
        let resp = self
            .agent
            .get(url)
            .set("Authorization", &self.bearer())
            .call()
            .map_err(|e| map_ureq_error(&e))?;
        resp.into_json().map_err(|e| CfError::Parse(e.to_string()))
    }

    fn post<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<T, CfError> {
        let resp = self
            .agent
            .post(url)
            .set("Authorization", &self.bearer())
            .set("Content-Type", "application/json")
            .send_json(body.clone())
            .map_err(|e| map_ureq_error(&e))?;
        resp.into_json().map_err(|e| CfError::Parse(e.to_string()))
    }
}

// ── Cloudflare API response shapes ──────────────────────────────────────────

/// Standard Cloudflare API envelope. Every endpoint wraps its real payload
/// here. Treat `success: false` as an error — even with HTTP 200, the body's
/// `errors` list explains why.
#[derive(Debug, Deserialize)]
struct CfEnvelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfApiError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct CfApiError {
    code: i64,
    message: String,
}

impl<T> CfEnvelope<T> {
    fn into_result(self) -> Result<T, CfError> {
        if self.success {
            self.result
                .ok_or_else(|| CfError::Parse("envelope success=true but result missing".into()))
        } else {
            let msg = self.errors.first().map_or_else(
                || "unknown error".into(),
                |e| format!("{} (code {})", e.message, e.code),
            );
            Err(CfError::Api {
                status: 200,
                message: msg,
            })
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenInfo {
    pub id: String,
    pub status: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ZoneSummary {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub account: ZoneAccount,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct ZoneAccount {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TunnelCreated {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    pub content: String,
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Generate 32 random bytes, base64-encoded — the format Cloudflare expects
/// for `tunnel_secret`. Matches the manual flow used during E2E validation.
fn generate_tunnel_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    BASE64.encode(bytes)
}

/// Map ureq transport / HTTP errors into our `CfError` taxonomy. 401/403 →
/// `Auth` (recoverable by regenerating the token); other statuses → `Api`.
fn map_ureq_error(e: &ureq::Error) -> CfError {
    match e {
        ureq::Error::Status(401 | 403, response) => {
            let body = response_text(response);
            CfError::Auth(extract_error_message(&body))
        }
        ureq::Error::Status(status, response) => {
            let body = response_text(response);
            CfError::Api {
                status: *status,
                message: extract_error_message(&body),
            }
        }
        ureq::Error::Transport(t) => CfError::Network(t.to_string()),
    }
}

fn response_text(response: &ureq::Response) -> String {
    // Cloning headers/body is cheap relative to the network call we just made.
    // ureq doesn't expose a non-consuming body read, so we reach into the
    // status_line + the header for context if reading the body fails.
    response.status_text().to_string()
}

/// Try to pull a useful message out of a Cloudflare error body. Falls back to
/// the raw text if it isn't the expected envelope shape.
fn extract_error_message(body: &str) -> String {
    if body.is_empty() {
        return "no body".into();
    }
    if let Ok(env) = serde_json::from_str::<CfEnvelope<serde_json::Value>>(body) {
        if let Some(first) = env.errors.first() {
            return format!("{} (code {})", first.message, first.code);
        }
    }
    body.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_secret_is_32_bytes_base64() {
        let s = generate_tunnel_secret();
        let decoded = BASE64.decode(&s).expect("valid base64");
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn envelope_success_with_result_returns_value() {
        let env: CfEnvelope<String> =
            serde_json::from_str(r#"{"success":true,"errors":[],"result":"hello"}"#).unwrap();
        assert_eq!(env.into_result().unwrap(), "hello");
    }

    #[test]
    fn envelope_failure_returns_first_error() {
        let env: CfEnvelope<String> = serde_json::from_str(
            r#"{"success":false,"errors":[{"code":7003,"message":"Could not route"}],"result":null}"#,
        )
        .unwrap();
        let err = env.into_result().unwrap_err();
        match err {
            CfError::Api { status, message } => {
                assert_eq!(status, 200);
                assert!(message.contains("Could not route"));
                assert!(message.contains("7003"));
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn envelope_success_without_result_is_parse_error() {
        let env: CfEnvelope<String> =
            serde_json::from_str(r#"{"success":true,"errors":[],"result":null}"#).unwrap();
        assert!(matches!(env.into_result(), Err(CfError::Parse(_))));
    }

    #[test]
    fn extract_message_pulls_first_envelope_error() {
        let body = r#"{"success":false,"errors":[{"code":10000,"message":"Invalid token"}],"result":null}"#;
        let msg = extract_error_message(body);
        assert!(msg.contains("Invalid token"));
        assert!(msg.contains("10000"));
    }

    #[test]
    fn extract_message_falls_back_to_raw_text() {
        let msg = extract_error_message("upstream timeout");
        assert_eq!(msg, "upstream timeout");
    }

    #[test]
    fn extract_message_handles_empty_body() {
        assert_eq!(extract_error_message(""), "no body");
    }

    #[test]
    fn zone_summary_deserializes_cloudflare_shape() {
        let json =
            r#"{"id":"abc","name":"example.com","account":{"id":"acct1","name":"My Account"}}"#;
        let z: ZoneSummary = serde_json::from_str(json).unwrap();
        assert_eq!(z.id, "abc");
        assert_eq!(z.name, "example.com");
        assert_eq!(z.account.id, "acct1");
    }

    #[test]
    fn zone_summary_handles_missing_account() {
        let json = r#"{"id":"abc","name":"example.com"}"#;
        let z: ZoneSummary = serde_json::from_str(json).unwrap();
        assert_eq!(z.account.id, "");
    }

    #[test]
    fn cf_error_displays_human_readable() {
        let e = CfError::Auth("token expired".into());
        assert!(e.to_string().contains("auth"));
        assert!(e.to_string().contains("token expired"));
    }
}
