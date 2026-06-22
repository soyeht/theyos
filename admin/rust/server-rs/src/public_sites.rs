//! Public claw site configuration and reverse proxy.

use crate::auth::AdminUser;
use crate::handlers_instances::require_instance;
use crate::state::SharedState;
use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::{
        HeaderValue, Request, StatusCode, Uri,
        header::{
            AUTHORIZATION, CONNECTION, COOKIE, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE,
            TRAILER, TRANSFER_ENCODING, UPGRADE,
        },
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use core_rs::error::{ApiError, blocking};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::{IpAddr, TcpListener};
use std::str::FromStr;
use store_rs::{InstanceRow, InstanceStatus, NewPublicSite, PublicSiteRow};

const PUBLIC_SITE_HEADER: &str = "x-theyos-public-site";
const DEFAULT_GUEST_PORT: u16 = 3000;

#[derive(Deserialize)]
pub struct UpsertPublicSitesReq {
    pub domain: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    pub guest_port: Option<u16>,
}

/// GET /api/v1/instances/{id}/public-sites
///
/// # Errors
///
/// Returns `ApiError` if the instance is not found or the store query fails.
pub async fn handle_list_public_sites(
    State(state): State<SharedState>,
    AdminUser(auth): AdminUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_instance(&state, &auth, &id).await?;

    let st = state.clone();
    let iid = id.clone();
    let sites = blocking(move || {
        st.instance_db
            .list_public_sites_for_instance(&iid)
            .map_err(ApiError::from)
    })
    .await??;

    let domains_for_check: Vec<String> = sites.iter().map(|s| s.domain.clone()).collect();
    let missing = missing_cloudflared_ingress(&domains_for_check);

    let mut body = json!({
        "sites": public_site_rows_json(&sites),
        "instructions": public_site_instructions(),
    });
    if !missing.is_empty() {
        body["cloudflared_warning"] = json!({
            "message": "These domains are not present in the cloudflared config. Add an `ingress` entry pointing to http://localhost:8080 and run `cloudflared service restart`.",
            "missing": missing,
            "config_path": crate::cloudflared_sync::cloudflared_config_path(),
        });
    }
    Ok(Json(body))
}

/// POST /api/v1/instances/{id}/public-sites
///
/// # Errors
///
/// Returns `ApiError` if validation fails, the instance is not active, or the
/// target cannot be prepared.
#[allow(clippy::too_many_lines)]
pub async fn handle_upsert_public_sites(
    State(state): State<SharedState>,
    AdminUser(auth): AdminUser,
    Path(id): Path<String>,
    Json(req): Json<UpsertPublicSitesReq>,
) -> Result<Json<Value>, ApiError> {
    let row = require_instance(&state, &auth, &id).await?;
    if row.status != InstanceStatus::Active {
        return Err(ApiError::bad_request(
            "instance must be active before publishing a public site",
        ));
    }

    let guest_port = req.guest_port.unwrap_or(DEFAULT_GUEST_PORT);
    if guest_port == 0 {
        return Err(ApiError::bad_request(
            "guest_port must be between 1 and 65535",
        ));
    }

    let domains = normalize_public_domains(req.domain, req.domains)?;
    let mut sites = Vec::with_capacity(domains.len());
    for domain in domains {
        let domain_for_rollback = domain.clone();
        let site = configure_public_site(&state, &row, domain, guest_port).await?;
        // If the operator has the API-driven Cloudflare flow set up (Settings →
        // Cloudflare), automatically create the matching CNAME record so the
        // domain works publicly the moment this call returns. Best-effort: if
        // creation fails we rollback this individual site so the user's UI
        // stays consistent ("the add either succeeded or it didn't").
        let site = match ensure_cloudflare_cname_for_site(&state, site).await {
            Ok(s) => s,
            Err(e) => {
                let st = state.clone();
                let iid = row.id.clone();
                let _ = blocking(move || {
                    st.instance_db
                        .delete_public_site(&iid, &domain_for_rollback)
                })
                .await;
                return Err(e);
            }
        };
        sites.push(site);
    }

    tracing::info!(
        "[public-sites] user={} instance={} guest_port={} sites={}",
        auth.username,
        id,
        guest_port,
        sites
            .iter()
            .map(|s| s.domain.as_str())
            .collect::<Vec<_>>()
            .join(",")
    );

    let domains_for_check: Vec<String> = sites.iter().map(|s| s.domain.clone()).collect();
    let missing = missing_cloudflared_ingress(&domains_for_check);

    let mut body = json!({
        "sites": public_site_rows_json(&sites),
        "instructions": public_site_instructions(),
    });
    if !missing.is_empty() {
        body["cloudflared_warning"] = json!({
            "message": "These domains are not present in the cloudflared config. Add an `ingress` entry pointing to http://localhost:8080 and run `cloudflared service restart`.",
            "missing": missing,
            "config_path": crate::cloudflared_sync::cloudflared_config_path(),
        });
    }

    // Regenerate cloudflared config and reload (env-gated; no-op on dev hosts).
    crate::cloudflared_sync::sync_cloudflared_config(&state).await;

    Ok(Json(body))
}

/// DELETE /api/v1/instances/{id}/public-sites/{domain}
///
/// # Errors
///
/// Returns `ApiError` if the instance/site is not found or deletion fails.
pub async fn handle_delete_public_site(
    State(state): State<SharedState>,
    AdminUser(auth): AdminUser,
    Path((id, domain)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    require_instance(&state, &auth, &id).await?;
    let domain = normalize_public_domain(&domain)?;

    let st = state.clone();
    let iid = id.clone();
    let domain_for_delete = domain.clone();
    let deleted_row = blocking(move || {
        st.instance_db
            .delete_public_site(&iid, &domain_for_delete)
            .map_err(ApiError::from)
    })
    .await??;
    let Some(deleted_row) = deleted_row else {
        return Err(ApiError::not_found("public site not found"));
    };
    // Best-effort: drop the matching CNAME in Cloudflare so the domain stops
    // resolving. Failure here is non-fatal; the local row is already gone.
    cleanup_cloudflare_cname_for_deleted_site(&state, &deleted_row).await;

    tracing::info!(
        "[public-sites] user={} deleted domain={} instance={}",
        auth.username,
        domain,
        id
    );

    // Regenerate cloudflared config and reload (env-gated; no-op on dev hosts).
    crate::cloudflared_sync::sync_cloudflared_config(&state).await;

    Ok(Json(json!({ "deleted": true, "domain": domain })))
}

/// Middleware for requests Caddy marks as public claw site traffic.
///
/// Mapped hosts are reverse-proxied to the configured VM target. Marked but
/// unmapped hosts return 404 and never fall through to the admin SPA/API.
pub async fn public_site_gateway(
    State(state): State<SharedState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let marked_public = req
        .headers()
        .get(PUBLIC_SITE_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    if !marked_public {
        return next.run(req).await;
    }

    let Some(host) = req.headers().get(HOST).and_then(|v| v.to_str().ok()) else {
        return public_site_not_found();
    };
    let Ok(domain) = normalize_public_domain(host) else {
        return public_site_not_found();
    };

    let st = state.clone();
    let domain_for_lookup = domain.clone();
    let target = match blocking(move || {
        st.instance_db
            .lookup_public_site_target(&domain_for_lookup)
            .map_err(ApiError::from)
    })
    .await
    {
        Ok(Ok(Some(site))) => site,
        Ok(Ok(None)) => return public_site_not_found(),
        Ok(Err(err)) => {
            tracing::warn!("[public-sites] lookup failed for {domain}: {err}");
            return ApiError::internal("public site lookup failed").into_response();
        }
        Err(err) => {
            tracing::warn!("[public-sites] lookup task failed for {domain}: {err}");
            return ApiError::internal("public site lookup failed").into_response();
        }
    };

    match proxy_public_site(req, &target).await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!(
                "[public-sites] proxy failed domain={} target={}:{}: {}",
                target.domain,
                target.target_host,
                target.target_port,
                err
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "public site upstream unavailable"})),
            )
                .into_response()
        }
    }
}

/// Re-apply public site targets for an instance after a VM start/restart.
///
/// Linux/Firecracker instances need their slirp host forwards recreated after
/// restart. macOS targets are refreshed if the VM IP changed.
///
/// # Errors
///
/// Returns `ApiError` when store access fails or a Linux host forward cannot be
/// restored.
pub async fn ensure_public_site_targets_for_instance(
    state: &SharedState,
    instance_id: &str,
) -> Result<(), ApiError> {
    let st = state.clone();
    let iid = instance_id.to_string();
    blocking(move || -> Result<(), ApiError> {
        let Some(inst) = st.instance_db.get(&iid).map_err(ApiError::from)? else {
            return Ok(());
        };
        if inst.status != InstanceStatus::Active {
            return Ok(());
        }
        let sites = st
            .instance_db
            .list_public_sites_for_instance(&iid)
            .map_err(ApiError::from)?;

        for site in sites.into_iter().filter(|site| site.enabled) {
            let guest_port = u16::try_from(site.guest_port)
                .map_err(|_| ApiError::internal("stored public site guest_port is invalid"))?;
            // Re-derive the target. On Mac the vm_ip may have changed across
            // restarts (DHCP); on Linux the existing target_port is reused and
            // the slirp4netns hostfwd is reinstalled idempotently.
            let target = derive_public_site_target(&st, &inst, guest_port, Some(site.target_port));
            let (target_host, target_port) = match target {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(
                        "[public-sites] cannot refresh target for {}: {e}",
                        site.domain
                    );
                    continue;
                }
            };
            // Idempotent on Linux (target unchanged); persists DHCP-renewed
            // vm_ip on Mac.
            st.instance_db
                .upsert_public_site(&NewPublicSite {
                    domain: &site.domain,
                    instance_id: &inst.id,
                    guest_port: site.guest_port,
                    target_host: &target_host,
                    target_port,
                    enabled: true,
                })
                .map_err(ApiError::from)?;
        }
        Ok(())
    })
    .await?
}

/// Create the matching CNAME for a freshly upserted public site, if the
/// operator has configured the API-driven Cloudflare flow.
///
/// Idempotent against repeated upserts: if the row already carries a
/// `cloudflare_dns_record_id` we assume the CNAME exists and skip the API
/// call. If Cloudflare isn't configured (Settings page never used), this is
/// a silent no-op — the site row is fine on its own and Caddy / external
/// cloudflared can still serve it.
async fn ensure_cloudflare_cname_for_site(
    state: &SharedState,
    site: PublicSiteRow,
) -> Result<PublicSiteRow, ApiError> {
    if site.cloudflare_dns_record_id.is_some() {
        return Ok(site);
    }

    let st = state.clone();
    let cfg = blocking(move || {
        st.instance_db
            .get_cloudflare_config()
            .map_err(ApiError::from)
    })
    .await??;
    let Some(cfg) = cfg else { return Ok(site) };

    let cname_name = derive_cname_name(&site.domain, &cfg.zone_name).ok_or_else(|| {
        ApiError::bad_request(format!(
            "domain '{}' is not under the configured Cloudflare zone '{}' — \
             pick a domain ending in .{} or reconfigure Cloudflare with a different zone",
            site.domain, cfg.zone_name, cfg.zone_name
        ))
    })?;
    let target = format!("{}.cfargotunnel.com", cfg.tunnel_id);

    let token = crate::cloudflare_admin::read_api_token().map_err(ApiError::internal)?;
    let zone_id = cfg.zone_id.clone();
    let record = blocking(move || {
        let client = crate::cloudflare_api::CloudflareClient::new(token);
        client
            .create_dns_cname(&zone_id, &cname_name, &target)
            .map_err(crate::cloudflare_admin::map_cf_error)
    })
    .await??;

    let st = state.clone();
    let domain_for_persist = site.domain.clone();
    let record_id_for_persist = record.id.clone();
    blocking(move || {
        st.instance_db
            .set_public_site_cloudflare_record(&domain_for_persist, &record_id_for_persist)
            .map_err(ApiError::from)
    })
    .await??;

    let mut updated = site;
    updated.cloudflare_dns_record_id = Some(record.id);
    Ok(updated)
}

/// Best-effort CNAME deletion for a removed public site. Errors are logged
/// but not surfaced — the local row is already gone, and a stranded CNAME
/// in Cloudflare just makes the domain return 404 from the tunnel (no
/// matching ingress), which is the same observable outcome.
async fn cleanup_cloudflare_cname_for_deleted_site(state: &SharedState, deleted: &PublicSiteRow) {
    let Some(record_id) = deleted.cloudflare_dns_record_id.clone() else {
        return;
    };
    let st = state.clone();
    let Ok(Ok(Some(cfg))) = blocking(move || {
        st.instance_db
            .get_cloudflare_config()
            .map_err(ApiError::from)
    })
    .await
    else {
        return;
    };
    let token = match crate::cloudflare_admin::read_api_token() {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("[public-sites] cannot read CF api token for cleanup: {e}");
            return;
        }
    };
    let zone_id = cfg.zone_id;
    let domain = deleted.domain.clone();
    let _ = blocking(move || {
        let client = crate::cloudflare_api::CloudflareClient::new(token);
        if let Err(e) = client.delete_dns_record(&zone_id, &record_id) {
            tracing::warn!("[public-sites] failed to delete CNAME for {domain} ({record_id}): {e}");
        }
    })
    .await;
}

/// Split a FQDN into its hostname-relative-to-zone part.
/// `app.example.com` + zone `example.com` → `Some("app")`.
/// `example.com` + zone `example.com` → `Some("@")` (Cloudflare apex marker).
/// Returns `None` if the domain is not under the zone.
fn derive_cname_name(domain: &str, zone_name: &str) -> Option<String> {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let zone = zone_name.trim_end_matches('.').to_ascii_lowercase();
    if domain == zone {
        return Some("@".to_string());
    }
    let suffix = format!(".{zone}");
    domain
        .strip_suffix(&suffix)
        .filter(|prefix| !prefix.is_empty())
        .map(std::string::ToString::to_string)
}

/// Pure decision: should this site use the VZ NAT `vm_ip` target instead of a
/// slirp4netns hostfwd?
///
/// Returns `true` when:
/// - the host is macOS (Apple VZ exposes guest VMs at a NAT IP reachable from
///   the host directly — no port forwarding needed), OR
/// - the guest itself is macOS (always implies host is macOS in practice, but
///   keep the explicit branch for clarity and forward-compat).
///
/// Returns `false` for the historical Linux-host + Linux-guest setup, which
/// must allocate a host port and add a slirp4netns hostfwd.
///
/// Pure for testability: `host_is_mac` is injected so tests pass on any
/// platform. Production callers should pass `cfg!(target_os = "macos")`.
fn should_use_vm_ip_target(guest_os: &str, host_is_mac: bool) -> bool {
    host_is_mac || guest_os.eq_ignore_ascii_case("macos")
}

/// Resolve the cloudflared / Caddy ingress target for a public site.
///
/// On Mac (host or guest = macOS): returns `(vm_ip, guest_port)` directly —
/// VZ NAT is reachable from the host without setup.
///
/// On Linux host + Linux guest: allocates a host port (or reuses the existing
/// one when `existing_target_port` is `Some`), installs a slirp4netns hostfwd
/// `127.0.0.1:host_port → guest:guest_port`, and returns
/// `("127.0.0.1", host_port)`.
///
/// `existing_target_port` is for the VM-restart refresh path where the host
/// port was already allocated and must be reused. Pass `None` for the create
/// path; the helper consults the DB and allocates if needed.
fn derive_public_site_target(
    state: &SharedState,
    inst: &InstanceRow,
    guest_port: u16,
    existing_target_port: Option<i64>,
) -> Result<(String, i64), ApiError> {
    let guest_port_i64 = i64::from(guest_port);
    let host_is_mac = cfg!(target_os = "macos");

    if should_use_vm_ip_target(&inst.guest_os, host_is_mac) {
        let vm_ip = inst
            .vm_ip
            .as_deref()
            .filter(|ip| !ip.trim().is_empty())
            .ok_or_else(|| {
                ApiError::bad_request("instance has no vm_ip yet (VM may still be booting)")
            })?;
        return Ok((vm_ip.to_string(), guest_port_i64));
    }

    let target_port = match existing_target_port {
        Some(port) => port,
        None => match state
            .instance_db
            .find_public_site_for_instance_guest_port(&inst.id, guest_port_i64)
            .map_err(ApiError::from)?
        {
            Some(existing) => existing.target_port,
            None => i64::from(allocate_public_site_host_port(&state.instance_db)?),
        },
    };
    let host_port = u16::try_from(target_port)
        .map_err(|_| ApiError::internal("stored public site target_port is invalid"))?;
    state
        .vm_runner
        .ensure_public_hostfwd(&inst.container, host_port, guest_port)
        .map_err(|e| {
            ApiError::service_unavailable(format!(
                "failed to configure Linux public site forward: {e}"
            ))
        })?;
    Ok(("127.0.0.1".to_string(), target_port))
}

async fn configure_public_site(
    state: &SharedState,
    row: &InstanceRow,
    domain: String,
    guest_port: u16,
) -> Result<PublicSiteRow, ApiError> {
    let st = state.clone();
    let inst = row.clone();
    blocking(move || -> Result<PublicSiteRow, ApiError> {
        let guest_port_i64 = i64::from(guest_port);
        let (target_host, target_port) = derive_public_site_target(&st, &inst, guest_port, None)?;

        st.instance_db
            .upsert_public_site(&NewPublicSite {
                domain: &domain,
                instance_id: &inst.id,
                guest_port: guest_port_i64,
                target_host: &target_host,
                target_port,
                enabled: true,
            })
            .map_err(ApiError::from)
    })
    .await?
}

fn allocate_public_site_host_port(db: &store_rs::InstanceDb) -> Result<u16, ApiError> {
    let used: HashSet<u16> = db
        .list_public_site_target_ports()
        .map_err(ApiError::from)?
        .into_iter()
        .filter_map(|port| u16::try_from(port).ok())
        .collect();

    for port in core_rs::guest_net::public_site_host_port_range() {
        if used.contains(&port) {
            continue;
        }
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }

    Err(ApiError::service_unavailable(format!(
        "no free public site host ports in {}-{}",
        core_rs::guest_net::PUBLIC_SITE_HOST_PORT_RANGE_START,
        core_rs::guest_net::PUBLIC_SITE_HOST_PORT_RANGE_END
    )))
}

async fn proxy_public_site(
    mut req: Request<Body>,
    target: &PublicSiteRow,
) -> Result<Response, String> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or("/", axum::http::uri::PathAndQuery::as_str);
    let uri = format!(
        "http://{}:{}{}",
        target.target_host, target.target_port, path_and_query
    )
    .parse::<Uri>()
    .map_err(|e| format!("target URI: {e}"))?;

    let original_host = req.headers().get(HOST).cloned();
    sanitize_public_site_request_headers(req.headers_mut());
    if let Some(host) = original_host.clone() {
        req.headers_mut().insert(HOST, host.clone());
        req.headers_mut().insert("x-forwarded-host", host);
    }
    req.headers_mut()
        .insert("x-forwarded-server", HeaderValue::from_static("theyos"));
    if !req.headers().contains_key("x-forwarded-proto") {
        req.headers_mut()
            .insert("x-forwarded-proto", HeaderValue::from_static("http"));
    }
    *req.uri_mut() = uri;

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<_, Body> = Client::builder(TokioExecutor::new()).build(connector);
    let upstream = client.request(req).await.map_err(|e| e.to_string())?;

    let (parts, body) = upstream.into_parts();
    let mut resp = Response::from_parts(parts, Body::new(body));
    sanitize_public_site_response_headers(resp.headers_mut());
    Ok(resp)
}

fn sanitize_public_site_request_headers(headers: &mut axum::http::HeaderMap) {
    for name in [
        CONNECTION,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
        AUTHORIZATION,
        COOKIE,
    ] {
        headers.remove(name);
    }
    headers.remove(PUBLIC_SITE_HEADER);
}

fn sanitize_public_site_response_headers(headers: &mut axum::http::HeaderMap) {
    for name in [
        CONNECTION,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
}

fn public_site_not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

fn public_site_rows_json(sites: &[PublicSiteRow]) -> Vec<Value> {
    sites
        .iter()
        .map(|site| {
            json!({
                "domain": site.domain,
                "instance_id": site.instance_id,
                "guest_port": site.guest_port,
                "target_host": site.target_host,
                "target_port": site.target_port,
                "enabled": site.enabled,
                "created_at": site.created_at,
                "updated_at": site.updated_at,
            })
        })
        .collect()
}

fn public_site_instructions() -> Value {
    json!({
        "step1": "Configure Cloudflare in Settings (one-time, ~30 seconds): paste an API token, pick a zone, click Enable.",
        "step2": "Inside the claw, run your service on 0.0.0.0:<port> (default 3000). Bind to 0.0.0.0, not 127.0.0.1, or the host port-forward can't reach it.",
        "step3": "Type the public domain above and click add. The CNAME and tunnel ingress are wired automatically — the URL is live in seconds.",
        "settings_link": "/settings",
        "default_guest_port": DEFAULT_GUEST_PORT,
    })
}

fn normalize_public_domains(
    domain: Option<String>,
    mut domains: Vec<String>,
) -> Result<Vec<String>, ApiError> {
    if let Some(domain) = domain {
        domains.push(domain);
    }
    if domains.is_empty() {
        return Err(ApiError::bad_request("domain or domains is required"));
    }

    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(domains.len());
    for domain in domains {
        let normalized = normalize_public_domain(&domain)?;
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    Ok(out)
}

pub(crate) fn normalize_public_domain(input: &str) -> Result<String, ApiError> {
    let mut host = input.trim();
    if host.is_empty() {
        return Err(ApiError::bad_request("domain is required"));
    }
    if let Some((_, rest)) = host.split_once("://") {
        host = rest;
    }
    if let Some((_, rest)) = host.rsplit_once('@') {
        host = rest;
    }
    host = host
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim();
    host = host.trim_end_matches('.');
    if host.starts_with('[') || host.ends_with(']') {
        return Err(ApiError::bad_request(
            "public site domain cannot be an IP address",
        ));
    }
    if host.matches(':').count() == 1 {
        host = host.split_once(':').map_or(host, |(h, _)| h);
    }

    let domain = host.to_ascii_lowercase();
    validate_public_domain(&domain)?;
    Ok(domain)
}

fn validate_public_domain(domain: &str) -> Result<(), ApiError> {
    if domain.is_empty() || domain.len() > 253 {
        return Err(ApiError::bad_request("invalid domain"));
    }
    if domain.contains('*') {
        return Err(ApiError::bad_request("wildcard domains are not supported"));
    }
    if domain == "localhost" || domain.ends_with(".localhost") {
        return Err(ApiError::bad_request(
            "localhost is not valid for a public site",
        ));
    }
    if IpAddr::from_str(domain).is_ok() {
        return Err(ApiError::bad_request(
            "public site domain cannot be an IP address",
        ));
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err(ApiError::bad_request("domain must include a public suffix"));
    }
    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return Err(ApiError::bad_request("invalid domain label"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ApiError::bad_request("invalid domain label"));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(ApiError::bad_request("domain must be ASCII"));
        }
    }
    Ok(())
}

/// Best-effort check: which of `domains` are missing from the cloudflared
/// config's ingress block?
///
/// Returns an empty vec when the config file can't be read (operator may not
/// be using Cloudflare Tunnel — DNS-only / proxied DNS are valid alternatives,
/// see docs/public-claw-sites.md). Never errors; the warning is informational.
fn missing_cloudflared_ingress(domains: &[String]) -> Vec<String> {
    let path = crate::cloudflared_sync::cloudflared_config_path();
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    domains
        .iter()
        .filter(|d| !ingress_contains_domain(&content, d))
        .cloned()
        .collect()
}

/// Does `yaml` declare an `ingress: - hostname: <domain>` covering `domain`?
///
/// Hand-rolled to avoid pulling a YAML parser into server-rs for one shallow
/// lookup. Recognizes:
///   - exact match: `hostname: livre.org` or `- hostname: "livre.org"`
///   - wildcards covering one extra label: `hostname: "*.livre.org"` matches
///     `app.livre.org` but NOT `deep.app.livre.org` (cloudflared's own
///     wildcard semantics).
///
/// Comment lines (after trimming) starting with `#` are ignored.
fn ingress_contains_domain(yaml: &str, domain: &str) -> bool {
    let needle = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    yaml.lines()
        .map(str::trim_start)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            l.strip_prefix("- hostname:")
                .or_else(|| l.strip_prefix("hostname:"))
        })
        .map(|v| {
            v.trim()
                .trim_matches(|c: char| c == '"' || c == '\'')
                .to_ascii_lowercase()
        })
        .any(|host| {
            if host == needle {
                return true;
            }
            if let Some(suffix) = host.strip_prefix("*.")
                && let Some(prefix) = needle.strip_suffix(suffix)
                && let Some(prefix) = prefix.strip_suffix('.')
            {
                return !prefix.is_empty() && !prefix.contains('.');
            }
            false
        })
}

#[cfg(test)]
mod tests {
    use super::{
        derive_cname_name, ingress_contains_domain, missing_cloudflared_ingress,
        normalize_public_domain, should_use_vm_ip_target,
    };

    #[test]
    fn vm_ip_target_when_host_is_mac() {
        // Linux guest on Mac host (the natural case for users running services
        // in Linux VMs on a Mac dev machine) — VZ NAT lets the host reach the
        // guest IP directly, skip slirp4netns hostfwd.
        assert!(should_use_vm_ip_target("linux", true));
        assert!(should_use_vm_ip_target("Linux", true));
    }

    #[test]
    fn vm_ip_target_when_guest_is_macos() {
        // macOS guest is always on Mac host (no Apple VZ on Linux) but be
        // explicit so the branch is documented and case-insensitive.
        assert!(should_use_vm_ip_target("macos", true));
        assert!(should_use_vm_ip_target("MacOS", true));
        // Same flag works even if host detection said Linux (impossible
        // combination, but be defensive — guest_os == macos always wins).
        assert!(should_use_vm_ip_target("macos", false));
    }

    #[test]
    fn slirp_hostfwd_when_linux_host_linux_guest() {
        // The historical NixOS path: Linux host running Linux Firecracker VMs.
        // Must allocate a host port + slirp4netns hostfwd.
        assert!(!should_use_vm_ip_target("linux", false));
        assert!(!should_use_vm_ip_target("Linux", false));
        assert!(!should_use_vm_ip_target("LINUX", false));
    }

    #[test]
    fn derive_cname_handles_subdomains() {
        assert_eq!(
            derive_cname_name("app.example.com", "example.com"),
            Some("app".to_string())
        );
        assert_eq!(
            derive_cname_name("api.staging.example.com", "example.com"),
            Some("api.staging".to_string())
        );
    }

    #[test]
    fn derive_cname_apex_returns_at() {
        assert_eq!(
            derive_cname_name("example.com", "example.com"),
            Some("@".to_string())
        );
    }

    #[test]
    fn derive_cname_rejects_unrelated_domain() {
        assert_eq!(derive_cname_name("app.other.com", "example.com"), None);
    }

    #[test]
    fn derive_cname_rejects_partial_match() {
        // "foo.notexample.com" must NOT be treated as a subdomain of example.com
        assert_eq!(derive_cname_name("foo.notexample.com", "example.com"), None);
    }

    #[test]
    fn derive_cname_is_case_insensitive() {
        assert_eq!(
            derive_cname_name("APP.Example.COM", "example.COM"),
            Some("app".to_string())
        );
    }

    #[test]
    fn derive_cname_handles_trailing_dots() {
        assert_eq!(
            derive_cname_name("app.example.com.", "example.com."),
            Some("app".to_string())
        );
    }

    #[test]
    fn normalizes_pasted_urls() {
        assert_eq!(
            normalize_public_domain("https://Example.COM:8443/path?q=1").unwrap(),
            "example.com"
        );
        assert_eq!(
            normalize_public_domain("  personasgpt.ai.  ").unwrap(),
            "personasgpt.ai"
        );
    }

    #[test]
    fn rejects_non_public_hosts() {
        assert!(normalize_public_domain("localhost:3000").is_err());
        assert!(normalize_public_domain("127.0.0.1").is_err());
        assert!(normalize_public_domain("*.example.com").is_err());
        assert!(normalize_public_domain("singlelabel").is_err());
    }

    #[test]
    fn ingress_matcher_exact() {
        let yaml = "ingress:\n  - hostname: livre.org\n    service: http://localhost:8080\n";
        assert!(ingress_contains_domain(yaml, "livre.org"));
        assert!(!ingress_contains_domain(yaml, "www.livre.org"));
    }

    #[test]
    fn ingress_matcher_quoted_and_case() {
        let yaml = "  - hostname: \"Livre.ORG\"\n  - hostname: 'app.example.com'\n";
        assert!(ingress_contains_domain(yaml, "livre.org"));
        assert!(ingress_contains_domain(yaml, "app.example.com"));
    }

    #[test]
    fn ingress_matcher_wildcard_covers_one_label() {
        let yaml = "  - hostname: \"*.example.com\"\n";
        assert!(ingress_contains_domain(yaml, "app.example.com"));
        assert!(ingress_contains_domain(yaml, "www.example.com"));
        // cloudflared wildcards only match one label deep
        assert!(!ingress_contains_domain(yaml, "a.b.example.com"));
        // Wildcard does NOT cover the apex
        assert!(!ingress_contains_domain(yaml, "example.com"));
    }

    #[test]
    fn ingress_matcher_ignores_comments() {
        let yaml = "# - hostname: livre.org\n  - hostname: personasgpt.ai\n";
        assert!(!ingress_contains_domain(yaml, "livre.org"));
        assert!(ingress_contains_domain(yaml, "personasgpt.ai"));
    }

    #[test]
    #[allow(unsafe_code)]
    fn missing_returns_empty_when_file_absent() {
        // SAFETY: setting/removing this env var is sound here — Rust's
        // 2024 set_var marker is conservative for the multithreaded case,
        // but `cargo test` runs each #[test] on its own (uncontended for
        // this var, which is read only inside missing_cloudflared_ingress
        // synchronously below).
        unsafe {
            std::env::set_var(
                "THEYOS_CLOUDFLARED_CONFIG",
                "/tmp/theyos-test-does-not-exist.yml",
            );
        }
        let missing = missing_cloudflared_ingress(&["livre.org".into()]);
        assert!(missing.is_empty(), "expected empty, got {missing:?}");
        // SAFETY: see set_var above — same single-threaded reasoning.
        unsafe {
            std::env::remove_var("THEYOS_CLOUDFLARED_CONFIG");
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn missing_reports_domains_not_in_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(
            &path,
            "ingress:\n  - hostname: livre.org\n  - hostname: \"*.example.com\"\n",
        )
        .unwrap();
        // SAFETY: see missing_returns_empty_when_file_absent — single test,
        // single synchronous read, value lives only for this test.
        unsafe {
            std::env::set_var("THEYOS_CLOUDFLARED_CONFIG", &path);
        }
        let missing = missing_cloudflared_ingress(&[
            "livre.org".into(),
            "app.example.com".into(),
            "personasgpt.ai".into(),
        ]);
        assert_eq!(missing, vec!["personasgpt.ai".to_string()]);
        // SAFETY: see set_var above.
        unsafe {
            std::env::remove_var("THEYOS_CLOUDFLARED_CONFIG");
        }
    }
}
