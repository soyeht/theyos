//! Network status + Tailscale exposure handler.
//!
//!   GET  /api/v1/network/status
//!   POST /api/v1/network/expose

use axum::Json;
use axum::response::IntoResponse;
use core_rs::error::{ApiError, blocking};
use serde::Deserialize;

/// GET /api/v1/network/status
///
/// Returns detected network access channels (local, LAN, Tailscale, Cloudflare)
/// and Caddy reverse proxy status. Read-only — does not modify any state.
///
/// # Errors
///
/// Returns `ApiError` if detection fails (unlikely — individual probes are best-effort).
pub async fn handle_network_status() -> Result<impl IntoResponse, ApiError> {
    let status =
        blocking(|| Ok::<_, ApiError>(core_rs::network_detect::detect_network_status())).await??;
    Ok(Json(status))
}

#[derive(Deserialize)]
pub struct ExposeRequest {
    pub channel: String,
    pub enabled: bool,
}

/// POST /api/v1/network/expose
///
/// Toggle panel exposure via a network channel (currently only "tailscale").
/// When enabled, configures Caddy to serve HTTPS on the Tailscale hostname
/// with auto-provisioned Let's Encrypt certs.
///
/// # Errors
///
/// Returns `ApiError` if Tailscale is not detected or cert generation fails.
#[allow(clippy::too_many_lines)]
pub async fn handle_expose(Json(req): Json<ExposeRequest>) -> Result<impl IntoResponse, ApiError> {
    if req.channel != "tailscale" {
        return Err(ApiError::bad_request(
            "only 'tailscale' channel is supported",
        ));
    }

    let result = blocking(move || {
        let status = core_rs::network_detect::detect_network_status();
        let ts = status
            .channels
            .iter()
            .find(|c| c.channel_type == "tailscale" && c.detected)
            .ok_or_else(|| ApiError::bad_request("Tailscale not detected"))?;
        let hostname = ts
            .hostname
            .as_deref()
            .ok_or_else(|| ApiError::bad_request("Tailscale hostname not available"))?;

        if !req.enabled {
            // Remove the tailscale_https server from Caddy via admin API
            let caddy_url =
                std::env::var("CADDY_ADMIN_URL").unwrap_or_else(|_| "http://localhost:2019".into());
            let agent = ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(5))
                .build();
            // Best-effort: ignore errors if Caddy is not running or route doesn't exist
            let _ = agent
                .delete(&format!(
                    "{caddy_url}/config/apps/http/servers/tailscale_https"
                ))
                .call();
            let _ = agent.delete(&format!("{caddy_url}/config/apps/tls")).call();
            return Ok(serde_json::json!({"status": "disabled", "channel": "tailscale"}));
        }

        // Find Tailscale CLI via the shared resolver (supports NixOS, macOS, PATH)
        let ts_bin = core_rs::network_detect::find_tailscale_cli()
            .ok_or_else(|| ApiError::bad_request("Tailscale CLI not found"))?;

        // Generate Tailscale cert
        let cert_path = "/tmp/ts-cert.pem";
        let key_path = "/tmp/ts-key.pem";

        let cert_out = std::process::Command::new(&ts_bin)
            .args([
                "cert",
                "--cert-file",
                cert_path,
                "--key-file",
                key_path,
                hostname,
            ])
            .output()
            .map_err(|e| ApiError::internal(format!("tailscale cert: {e}")))?;

        if !cert_out.status.success() {
            let err = String::from_utf8_lossy(&cert_out.stderr);
            return Err(ApiError::internal(format!("tailscale cert failed: {err}")));
        }

        // Configure Caddy with the cert
        let caddy_config = serde_json::json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {"listen": [":80"], "routes": []},
                        "tailscale_https": {
                            "listen": [":443"],
                            "routes": [{
                                "handle": [{
                                    "handler": "reverse_proxy",
                                    "upstreams": [{"dial": "127.0.0.1:8892"}]
                                }]
                            }],
                            "tls_connection_policies": [{}]
                        }
                    }
                },
                "tls": {
                    "certificates": {
                        "load_files": [{
                            "certificate": cert_path,
                            "key": key_path
                        }]
                    }
                }
            }
        });

        let caddy_url =
            std::env::var("CADDY_ADMIN_URL").unwrap_or_else(|_| "http://localhost:2019".into());

        // Use ureq instead of shelling out to curl
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(5))
            .build();
        let resp = agent
            .post(&format!("{caddy_url}/load"))
            .set("Content-Type", "application/json")
            .send_string(&caddy_config.to_string())
            .map_err(|e| ApiError::internal(format!("caddy load: {e}")))?;
        if resp.status() != 200 {
            return Err(ApiError::internal(format!(
                "caddy load returned {}",
                resp.status()
            )));
        }

        Ok(serde_json::json!({
            "status": "enabled",
            "channel": "tailscale",
            "hostname": hostname,
            "url": format!("https://{hostname}")
        }))
    })
    .await??;

    Ok(Json(result))
}
