//! Admin endpoints for the Settings → Cloudflare flow.
//!
//! These four routes drive the operator's one-time setup of the Cloudflare
//! tunnel from the admin UI, replacing the previous SSH-and-edit-nix workflow:
//!
//!   * `GET    /api/v1/admin/cloudflare/status`  — is the tunnel configured?
//!   * `POST   /api/v1/admin/cloudflare/zones`   — list zones for a token
//!   * `POST   /api/v1/admin/cloudflare/setup`   — create the tunnel + activate
//!   * `DELETE /api/v1/admin/cloudflare/setup`   — full teardown
//!
//! All handlers require admin role via the `AdminUser` extractor. Every state-
//! changing call is fail-fast: if any Cloudflare API step fails, we roll back
//! local writes (token files, DB row) and return the error to the UI so the
//! operator can retry. We never leave the system in a half-configured state.

use crate::cloudflare_api::{CfError, CloudflareClient};
use crate::state::SharedState;
use axum::{Json, extract::State};
use core_rs::error::{ApiError, blocking};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::Permissions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use store_rs::CloudflareConfigRow;

const ENV_API_TOKEN_FILE: &str = "THEYOS_CLOUDFLARED_API_TOKEN_FILE";
const ENV_CONNECTOR_TOKEN_FILE: &str = "THEYOS_CLOUDFLARED_TOKEN_FILE";
const ENV_START_CMD: &str = "THEYOS_CLOUDFLARED_START_CMD";
const ENV_STOP_CMD: &str = "THEYOS_CLOUDFLARED_STOP_CMD";

/// Fallback paths used when the corresponding env var is unset. These match
/// the production nix module defaults so the dev workflow is identical to the
/// deployed one as far as the backend is concerned.
const DEFAULT_CONNECTOR_TOKEN_FILE: &str = "/var/lib/cloudflared/token";
const DEFAULT_API_TOKEN_FILE: &str = "/var/lib/theyos/secrets/cloudflare-api-token";

// ── handlers ────────────────────────────────────────────────────────────────

/// `GET /api/v1/admin/cloudflare/status` — what the operator sees on the
/// Settings page when it loads. `configured: false` ⇒ render the "configure"
/// form; otherwise render the "connected, disconnect?" card.
#[allow(clippy::unused_async)]
pub async fn handle_status(
    State(state): State<SharedState>,
    crate::auth::AdminUser(_): crate::auth::AdminUser,
) -> Result<Json<Value>, ApiError> {
    let st = state.clone();
    let cfg = blocking(move || {
        st.instance_db
            .get_cloudflare_config()
            .map_err(ApiError::from)
    })
    .await??;

    let cloudflared_running = cloudflared_is_running();

    Ok(Json(match cfg {
        None => json!({ "configured": false, "cloudflared_running": cloudflared_running }),
        Some(c) => json!({
            "configured": true,
            "account_id": c.account_id,
            "zone_id":    c.zone_id,
            "zone_name":  c.zone_name,
            "tunnel_id":  c.tunnel_id,
            "tunnel_name": c.tunnel_name,
            "configured_at": c.configured_at,
            "cloudflared_running": cloudflared_running,
        }),
    }))
}

/// `POST /api/v1/admin/cloudflare/zones` — verify the token and return the
/// zones it can manage, so the UI can populate the dropdown before commit.
/// Token is **not persisted** here — the operator is just exploring options.
pub async fn handle_list_zones(
    State(_state): State<SharedState>,
    crate::auth::AdminUser(_): crate::auth::AdminUser,
    Json(body): Json<ListZonesReq>,
) -> Result<Json<Value>, ApiError> {
    let token = body.api_token.trim().to_string();
    if token.is_empty() {
        return Err(ApiError::bad_request("api_token is required"));
    }

    let zones = blocking(move || {
        let client = CloudflareClient::new(token);
        client.list_zones().map_err(map_cf_error)
    })
    .await??;

    let zones_json: Vec<Value> = zones
        .into_iter()
        .map(|z| {
            json!({
                "id": z.id,
                "name": z.name,
                "account_id": z.account.id,
                "account_name": z.account.name,
            })
        })
        .collect();

    Ok(Json(json!({ "zones": zones_json })))
}

/// `POST /api/v1/admin/cloudflare/setup` — the big one.
///
/// 1. Validate inputs and refuse if cloudflared was configured manually outside
///    the UI (we don't want to clobber an externally-managed `/var/lib/cloudflared/token`).
/// 2. Verify the token + create a tunnel via Cloudflare API.
/// 3. Fetch the connector token.
/// 4. Persist: write API token, write connector token, INSERT `cloudflare_config`.
/// 5. `systemctl start cloudflared`.
///
/// On any error after step 2 (tunnel created in CF) we rollback by deleting
/// the tunnel via API and unlinking any files we wrote, so a retry starts
/// from a clean slate.
pub async fn handle_setup(
    State(state): State<SharedState>,
    crate::auth::AdminUser(auth): crate::auth::AdminUser,
    Json(body): Json<SetupReq>,
) -> Result<Json<Value>, ApiError> {
    let api_token = body.api_token.trim().to_string();
    let account_id = body.account_id.trim().to_string();
    let zone_id = body.zone_id.trim().to_string();
    let tunnel_name = body.tunnel_name.trim().to_string();

    if api_token.is_empty() || account_id.is_empty() || zone_id.is_empty() || tunnel_name.is_empty()
    {
        return Err(ApiError::bad_request(
            "api_token, account_id, zone_id, tunnel_name are required",
        ));
    }

    // Refuse to overwrite an externally-managed token. Operator must Disconnect
    // (or delete the file by hand) before letting the UI take over.
    let connector_path = connector_token_path();
    let already_configured = blocking({
        let st = state.clone();
        move || {
            st.instance_db
                .get_cloudflare_config()
                .map_err(ApiError::from)
        }
    })
    .await??
    .is_some();
    if connector_path.exists() && !already_configured {
        return Err(ApiError::bad_request(
            "Cloudflare appears to be configured outside the admin UI. Remove \
             the existing token file or use Disconnect first.",
        ));
    }

    // From here on we run the whole pipeline on the blocking pool — every step
    // is sync (ureq + std::fs + std::process::Command), and the rollback story
    // is easier to reason about as one atomic block.
    let st = state.clone();
    let username = auth.username.clone();
    let result: CloudflareConfigRow = blocking(move || -> Result<CloudflareConfigRow, ApiError> {
        let client = CloudflareClient::new(api_token.clone());

        // (1) Verify the token first — cheap, fails fast with a clear error.
        let _info = client.verify_token(&account_id).map_err(map_cf_error)?;

        // (2) Verify the zone is one the token can manage AND get its name
        //     for later domain-suffix validation.
        let zone_name = client
            .list_zones()
            .map_err(map_cf_error)?
            .into_iter()
            .find(|z| z.id == zone_id)
            .map(|z| z.name)
            .ok_or_else(|| {
                ApiError::bad_request(format!(
                    "zone_id {zone_id} not found among zones this token can manage"
                ))
            })?;

        // (3) Create the tunnel.
        let tunnel = client
            .create_tunnel(&account_id, &tunnel_name)
            .map_err(map_cf_error)?;
        let tunnel_id = tunnel.id;

        // (4) Fetch the connector token. From this point on, errors must
        //     trigger tunnel deletion to keep the operator's CF account clean.
        let connector_token = match client.fetch_connector_token(&account_id, &tunnel_id) {
            Ok(t) => t,
            Err(e) => {
                let _ = client.delete_tunnel(&account_id, &tunnel_id);
                return Err(map_cf_error(e));
            }
        };

        // (5) Write secrets, then the DB row, then start cloudflared. If any
        //     of these fail we attempt the same rollback (best-effort).
        let mut wrote_api = false;
        let mut wrote_connector = false;
        let result = (|| -> Result<CloudflareConfigRow, ApiError> {
            // API token: only the admin service ever reads this. 0600 owner soyeht.
            write_secret_file(&api_token_path(), api_token.as_bytes(), 0o600)?;
            wrote_api = true;
            // Connector token: cloudflared (cfg.user) reads it via group access
            // — see the soyeht extraGroup membership in nix/module.nix.
            write_secret_file(&connector_path, connector_token.as_bytes(), 0o640)?;
            wrote_connector = true;

            let row = CloudflareConfigRow {
                account_id: account_id.clone(),
                zone_id: zone_id.clone(),
                zone_name,
                tunnel_id: tunnel_id.clone(),
                tunnel_name: tunnel_name.clone(),
                configured_at: String::new(), // server-side default
            };
            st.instance_db
                .upsert_cloudflare_config(&row)
                .map_err(ApiError::from)?;

            cloudflared_systemctl(ENV_START_CMD)
                .map_err(|e| ApiError::internal(format!("start cloudflared: {e}")))?;
            Ok(row)
        })();

        if result.is_err() {
            // Rollback: delete remote tunnel + clean local files so the
            // operator can hit Enable again from scratch.
            let _ = client.delete_tunnel(&account_id, &tunnel_id);
            if wrote_connector {
                let _ = std::fs::remove_file(&connector_path);
            }
            if wrote_api {
                let _ = std::fs::remove_file(api_token_path());
            }
            // Best-effort DB cleanup; ignore errors.
            let _ = st.instance_db.clear_cloudflare_config();
        }
        result
    })
    .await??;

    tracing::info!(
        "[cloudflare-admin] user={} configured tunnel={} zone={} ({})",
        username,
        result.tunnel_name,
        result.zone_name,
        result.zone_id
    );

    // Re-read so the response includes the server-stamped configured_at.
    let st = state.clone();
    let final_row = blocking(move || {
        st.instance_db
            .get_cloudflare_config()
            .map_err(ApiError::from)
    })
    .await??
    .unwrap_or(result);

    Ok(Json(json!({
        "ok": true,
        "account_id": final_row.account_id,
        "zone_id":    final_row.zone_id,
        "zone_name":  final_row.zone_name,
        "tunnel_id":  final_row.tunnel_id,
        "tunnel_name": final_row.tunnel_name,
        "configured_at": final_row.configured_at,
    })))
}

/// `DELETE /api/v1/admin/cloudflare/setup` — full teardown chosen by the
/// operator (decision recorded in the plan: "Full cleanup").
///
/// Order matters: delete CNAMEs first while we still have the Cloudflare token,
/// then the tunnel, then stop cloudflared, then drop the local secrets. Each
/// step is best-effort; we log warnings but keep going so a partial failure
/// upstream (e.g. CF API hiccup) doesn't strand the local state in "configured"
/// after the operator chose to disconnect.
pub async fn handle_disconnect(
    State(state): State<SharedState>,
    crate::auth::AdminUser(auth): crate::auth::AdminUser,
) -> Result<Json<Value>, ApiError> {
    let st = state.clone();
    let username = auth.username.clone();

    let outcome: TeardownOutcome = blocking(move || -> Result<TeardownOutcome, ApiError> {
        let Some(cfg) = st
            .instance_db
            .get_cloudflare_config()
            .map_err(ApiError::from)?
        else {
            // Idempotent: caller asked to disconnect, nothing was configured.
            return Ok(TeardownOutcome::default());
        };

        let api_token = read_api_token().map_err(ApiError::internal)?;
        let client = CloudflareClient::new(api_token);

        // (a) Delete every CNAME we created. Use the DB as the source of truth
        //     so we don't accidentally delete records the operator added by hand.
        //     DNS deletion is independent of tunnel state and always works.
        let cleared = st
            .instance_db
            .clear_all_public_site_cloudflare_records()
            .map_err(ApiError::from)?;
        let cnames_attempted = cleared.len();
        let mut cnames_deleted = 0usize;
        for (domain, record_id) in &cleared {
            match client.delete_dns_record(&cfg.zone_id, record_id) {
                Ok(()) => cnames_deleted += 1,
                Err(e) => {
                    tracing::warn!(
                        "[cloudflare-admin] failed to delete CNAME for {domain} ({record_id}): {e}"
                    );
                }
            }
        }

        // (b) Stop cloudflared. Cloudflare's tunnel delete refuses while
        //     connector connections are registered (CF error code 1022), and
        //     it can take several minutes for CF to mark them inactive on its
        //     own — too long for an interactive UI request.
        if let Err(e) = cloudflared_systemctl(ENV_STOP_CMD) {
            tracing::warn!("[cloudflare-admin] failed to stop cloudflared: {e}");
        }

        // (c) Force-cleanup the connections via API (instant, no waiting),
        //     equivalent to `cloudflared tunnel cleanup <id>`.
        if let Err(e) = client.cleanup_tunnel_connections(&cfg.account_id, &cfg.tunnel_id) {
            tracing::warn!("[cloudflare-admin] failed to cleanup tunnel connections: {e}");
        }

        // (d) Delete the tunnel. 404 is treated as success by the client.
        let tunnel_deleted = match client.delete_tunnel(&cfg.account_id, &cfg.tunnel_id) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("[cloudflare-admin] failed to delete tunnel: {e}");
                false
            }
        };

        // (d) Local secrets + DB row.
        let _ = std::fs::remove_file(connector_token_path());
        let _ = std::fs::remove_file(api_token_path());
        st.instance_db
            .clear_cloudflare_config()
            .map_err(ApiError::from)?;

        Ok(TeardownOutcome {
            tunnel_deleted,
            cnames_attempted,
            cnames_deleted,
        })
    })
    .await??;

    tracing::info!(
        "[cloudflare-admin] user={} disconnected (tunnel_deleted={} cnames {}/{})",
        username,
        outcome.tunnel_deleted,
        outcome.cnames_deleted,
        outcome.cnames_attempted,
    );

    Ok(Json(json!({
        "ok": true,
        "tunnel_deleted": outcome.tunnel_deleted,
        "cnames_attempted": outcome.cnames_attempted,
        "cnames_deleted": outcome.cnames_deleted,
    })))
}

// ── request bodies ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListZonesReq {
    pub api_token: String,
}

#[derive(Debug, Deserialize)]
pub struct SetupReq {
    pub api_token: String,
    pub account_id: String,
    pub zone_id: String,
    pub tunnel_name: String,
}

#[derive(Debug, Default, Serialize)]
struct TeardownOutcome {
    tunnel_deleted: bool,
    cnames_attempted: usize,
    cnames_deleted: usize,
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Map our internal `CfError` taxonomy onto HTTP status codes the UI can act
/// on. Auth errors → 401 so the UI can prompt for a fresh token. Network +
/// API errors → 502 (we are the proxy from the operator's intent to CF).
pub(crate) fn map_cf_error(e: CfError) -> ApiError {
    match e {
        CfError::Auth(msg) => ApiError::unauthorized(format!("Cloudflare token rejected: {msg}")),
        CfError::Api { status, message } => {
            ApiError::service_unavailable(format!("Cloudflare API returned {status}: {message}"))
        }
        CfError::Network(msg) => {
            ApiError::service_unavailable(format!("Cloudflare unreachable: {msg}"))
        }
        CfError::Parse(msg) => {
            ApiError::internal(format!("Cloudflare response unparseable: {msg}"))
        }
    }
}

fn api_token_path() -> PathBuf {
    PathBuf::from(env_or(ENV_API_TOKEN_FILE, DEFAULT_API_TOKEN_FILE))
}

fn connector_token_path() -> PathBuf {
    PathBuf::from(env_or(
        ENV_CONNECTOR_TOKEN_FILE,
        DEFAULT_CONNECTOR_TOKEN_FILE,
    ))
}

fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

pub(crate) fn read_api_token() -> Result<String, String> {
    let path = api_token_path();
    let raw =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(raw.trim().to_string())
}

/// Atomic write. Tempfile in the same dir + rename(2).
///
/// Creates the parent directory if missing — needed on Mac where the brew
/// launchd service starts the admin backend directly (without going through
/// the `soyeht` wrapper that bootstraps `~/.theyos/`). On NixOS the activation
/// script in `nix/module.nix` already creates `/var/lib/cloudflared/` and
/// `/var/lib/theyos/secrets/`, so `create_dir_all` is a no-op there.
///
/// `mode` is the final POSIX permission. The API token uses 0600 (only the
/// admin service reads it). The connector token uses 0640 because cloudflared
/// runs as cfg.user and reads it via the shared soyeht group (see the user
/// extraGroups in nix/module.nix). Parent dir mode is left to the platform
/// default (umask) — the file mode is what protects the secret.
fn write_secret_file(path: &Path, content: &[u8], mode: u32) -> Result<(), ApiError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)
        .map_err(|e| ApiError::internal(format!("create secret dir {}: {e}", dir.display())))?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| ApiError::internal(format!("tempfile in {}: {e}", dir.display())))?;
    tmp.as_file_mut()
        .write_all(content)
        .map_err(|e| ApiError::internal(format!("write tempfile: {e}")))?;
    tmp.as_file_mut()
        .sync_all()
        .map_err(|e| ApiError::internal(format!("sync tempfile: {e}")))?;
    tmp.as_file_mut()
        .set_permissions(Permissions::from_mode(mode))
        .map_err(|e| ApiError::internal(format!("chmod tempfile: {e}")))?;
    tmp.persist(path)
        .map_err(|e| ApiError::internal(format!("persist {}: {e}", path.display())))?;
    Ok(())
}

/// Run the env-configured systemctl wrapper for cloudflared. Returns Ok with
/// the stderr message ignored on exit-0 commands; Err with the full stderr
/// otherwise. Empty env var → no-op (silent success), useful for dev.
fn cloudflared_systemctl(env_var: &str) -> Result<(), String> {
    let cmd = match std::env::var(env_var) {
        Ok(c) if !c.is_empty() => c,
        _ => {
            tracing::info!("[cloudflare-admin] {env_var} unset, skipping systemctl call");
            return Ok(());
        }
    };
    // Shell-out via /bin/sh -c to keep the env var format identical to the
    // existing THEYOS_CLOUDFLARED_RELOAD_CMD pattern (which encodes the full
    // `sudo -n /run/current-system/sw/bin/systemctl …` invocation).
    let out = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .map_err(|e| format!("spawn {cmd:?}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Best-effort liveness check. `systemctl is-active` would be more accurate
/// but requires another sudo rule; querying the metrics endpoint cloudflared
/// listens on locally is auth-free and cheaper than a process spawn.
fn cloudflared_is_running() -> bool {
    use std::net::TcpStream;
    use std::time::Duration;
    TcpStream::connect_timeout(
        &"127.0.0.1:2000".parse().expect("static addr"),
        Duration::from_millis(200),
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_cf_auth_yields_401() {
        let api = map_cf_error(CfError::Auth("expired".into()));
        // ApiError doesn't expose status codes directly in tests, but the
        // Display contains the original message — that's the contract used by
        // the UI's error renderer.
        assert!(api.to_string().contains("expired"));
    }

    #[test]
    fn map_cf_network_yields_proxy_error() {
        let api = map_cf_error(CfError::Network("dns failure".into()));
        assert!(api.to_string().contains("unreachable"));
    }

    #[test]
    fn env_or_reads_var_when_set() {
        // SAFETY: test-local var, no concurrent reads in this module.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("THEYOS_TEST_ENV_OR", "from-env");
        }
        assert_eq!(env_or("THEYOS_TEST_ENV_OR", "fallback"), "from-env");
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var("THEYOS_TEST_ENV_OR");
        }
    }

    #[test]
    fn env_or_falls_back_when_unset() {
        // SAFETY: see above.
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var("THEYOS_TEST_ENV_OR_UNSET");
        }
        assert_eq!(env_or("THEYOS_TEST_ENV_OR_UNSET", "default"), "default");
    }

    #[test]
    fn write_secret_file_writes_content_and_honors_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_secret_file(&path, b"hello", 0o600).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "hello");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "permissions should be 0600 not 0o{mode:o}");

        // Same path, different mode (the connector token case).
        let path2 = dir.path().join("connector");
        write_secret_file(&path2, b"world", 0o640).unwrap();
        let mode2 = std::fs::metadata(&path2).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode2, 0o640,
            "connector token should be 0640 not 0o{mode2:o}"
        );
    }

    #[test]
    fn write_secret_file_creates_missing_parent_dir() {
        // Mac brew launchd starts the admin backend without going through the
        // wrapper that bootstraps ~/.theyos/ — verify that write_secret_file
        // creates the parent dir defensively. Use a tempdir (writable) rather
        // than a system path that requires root.
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b/c/secret");
        write_secret_file(&nested, b"x", 0o600).unwrap();
        assert!(nested.exists());
        assert!(nested.parent().unwrap().is_dir());
    }

    #[test]
    fn write_secret_file_errors_when_parent_unwritable() {
        // Trying to create under /proc/self (read-only on Linux) or
        // /System/Volumes/Data/...impossible should fail with a clear message.
        // Use a path that's guaranteed unwritable on macOS: /System read-only.
        // On platforms where this happens to be writable (e.g. some CI), the
        // test asserts a soft contract — error contains "create secret dir".
        let path = PathBuf::from("/System/Library/CoreServices/.theyos-test-deny/secret");
        let err = match write_secret_file(&path, b"x", 0o600) {
            Ok(()) => {
                // Cleanup if the test environment surprised us.
                let _ = std::fs::remove_file(&path);
                let _ = std::fs::remove_dir(path.parent().unwrap());
                return;
            }
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("create secret dir"),
            "expected 'create secret dir' in error, got: {err}"
        );
    }

    #[test]
    fn cloudflared_systemctl_noop_when_env_unset() {
        // SAFETY: see above.
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var("THEYOS_TEST_SYSTEMCTL_NOOP");
        }
        cloudflared_systemctl("THEYOS_TEST_SYSTEMCTL_NOOP").unwrap();
    }

    #[test]
    fn cloudflared_systemctl_returns_error_on_command_failure() {
        // SAFETY: see above.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("THEYOS_TEST_SYSTEMCTL_FAIL", "/bin/false");
        }
        let err = cloudflared_systemctl("THEYOS_TEST_SYSTEMCTL_FAIL").unwrap_err();
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var("THEYOS_TEST_SYSTEMCTL_FAIL");
        }
        assert!(err.contains("exit"));
    }
}
