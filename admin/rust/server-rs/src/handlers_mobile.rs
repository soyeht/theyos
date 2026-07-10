//! Mobile API handlers — QR-based authentication for the Flutter app.
//!
//! Routes:
//!   POST /api/v1/instances/{id}/qr-token   (admin-authed — generates QR token)
//!   POST /api/v1/mobile/auth               (public — exchanges QR token for session)
//!   GET  /api/v1/mobile/status             (mobile-authed — validates session)
//!   GET  /api/v1/mobile/instances          (mobile-authed — lists instances)
//!   POST /api/v1/mobile/logout             (mobile-authed — revokes session)

use crate::auth::{AdminUser, AuthUser};
use crate::claw_store_service;
use crate::handlers_instances::require_instance;
use crate::mobile_token::capabilities_for;
use crate::responses::{ClawListItemResponse, ListResponse, claw_list_response};
use crate::state::SharedState;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use core_rs::{
    availability::ClawAvailability,
    error::{ApiError, blocking},
};
use household_rs::{
    claw_share_rendezvous_hello::{RendezvousHello, RendezvousRole},
    claw_share_rendezvous_token::RendezvousToken,
    claw_vpn_mobile_mesh_store::{
        ClawVpnMobileMeshStore, ClawVpnMobileMeshStoreError, ClawVpnMobileMeshStoreErrorKind,
        ClawVpnMobileMeshStoreStatus,
    },
    claw_vpn_mobile_state::{
        ClawVpnMobileAclGrant, ClawVpnMobileClawId, ClawVpnMobileDeviceId, ClawVpnMobileMemberId,
        ClawVpnMobileMeshError, ClawVpnMobileOfferToken, ClawVpnMobileRendezvousToken,
    },
};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use vmrunner_common_rs::VmCreateResourceSpec;

const DEEP_LINK_QUERY_VALUE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'/')
    .add(b':')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'`');

#[must_use]
pub fn mobile_deep_link(action: &str, query_items: &[(&str, &str)]) -> String {
    let query = query_items
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                key,
                utf8_percent_encode(value, DEEP_LINK_QUERY_VALUE_SET)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("theyos://{action}?{query}")
}

// ─── Request / response types ─────────────────────────────────────────────────

/// Optional query-string filter for `GET /api/v1/mobile/claws`.
///
/// `tier` — if present, only entries at the matching tier variant are returned.
/// Values: `catalog` / `detected` / `available` / `supported`. Unknown values
/// are silently ignored (returns the full catalog) so newer clients don't
/// break older servers. Absent = every tier.
#[derive(Deserialize, Debug, Default)]
pub struct ClawsQuery {
    #[serde(default)]
    pub tier: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MobileAuthRequest {
    /// The QR token scanned by the mobile app.
    pub qr_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct MobileAuthResponse {
    session_token: String,
    expires_at: String,
    instances: Vec<MobileInstanceInfo>,
    /// Set when the QR token was a "continue on iPhone" handoff.
    /// Client uses this to skip the instance picker and land directly on the
    /// pre-existing tmux workspace. `None` on regular pair/auth flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    target_instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_conversation_id: Option<String>,
    /// Pre-built WebSocket URL including session + bearer token as query params.
    /// Present iff the other two `target_*` are present. The server builds it
    /// here (rather than on the client) so the host/scheme detection matches
    /// what the generating device saw — no risk of drift between `best_qr_host`
    /// at generation time vs. client-side URL assembly.
    #[serde(skip_serializing_if = "Option::is_none")]
    target_ws_url: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct MobileInstanceInfo {
    id: String,
    name: String,
    container: String,
    claw_type: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    capabilities: crate::mobile_token::ClawCapabilities,
    /// Present while `status == "provisioning"`. Mirrors the single-instance
    /// status endpoint so the mobile app can render in-progress deploys in
    /// the list without maintaining local-only state. `None` for terminal
    /// statuses (active, stopped, failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning_phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning_error: Option<String>,
    /// Sanitized machine-readable failure reason (`snake_case` `InstanceFailureCode`),
    /// kept for parity with the single-instance status endpoint. Additive and
    /// absent for the non-failed instances this list currently includes.
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning_failure_code: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct QrTokenResponse {
    token: String,
    expires_at: String,
    /// Best host for the mobile app to connect to (auto-detected from channels).
    qr_host: String,
    /// Which channel is being used (e.g., "cloudflare", "tailscale", "lan", "local").
    qr_channel: String,
    /// Ready-to-use deep link for the mobile app: `theyos://connect?token=X&host=Y`.
    deep_link: String,
    /// Image ID for the QR code PNG endpoint (`GET /qr/{image_id}`).
    image_id: String,
    instance: QrInstanceInfo,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct QrInstanceInfo {
    id: String,
    name: String,
    container: String,
    claw_type: String,
}

const RESOURCE_OPTIONS_RETRY_AFTER_SECS: u32 = 30;

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ResourceOptionRange {
    min: u32,
    max: u32,
    default: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    disabled: Option<bool>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ResourceOptionsResponse {
    cpu_cores: ResourceOptionRange,
    ram_mb: ResourceOptionRange,
    disk_gb: ResourceOptionRange,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
struct MobileClawVpnStatusResponse {
    product: &'static str,
    mode: &'static str,
    production_activation: bool,
    state: &'static str,
    snapshot_present: bool,
    enrolled_device_count: usize,
    available_claw_count: usize,
    grant_count: usize,
    offer_count: usize,
    session_count: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MobileClawVpnDeviceRequest {
    device_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MobileClawVpnClawAvailabilityRequest {
    claw_id: String,
    available: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MobileClawVpnAclGrantRequest {
    #[serde(rename = "member_id")]
    member: String,
    #[serde(rename = "device_id")]
    device: String,
    #[serde(rename = "claw_id")]
    claw: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MobileClawVpnOfferRequest {
    #[serde(rename = "device_id")]
    device: String,
    #[serde(rename = "claw_id")]
    claw: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MobileClawVpnSessionRequest {
    #[serde(rename = "device_id")]
    device: String,
    #[serde(rename = "claw_id")]
    claw: String,
    #[serde(rename = "offer_token")]
    offer: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MobileClawVpnRendezvousAuthorizeRequest {
    #[serde(rename = "device_id")]
    device: String,
    #[serde(rename = "claw_id")]
    claw: String,
    #[serde(rename = "rendezvous_token")]
    rendezvous: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
struct MobileClawVpnOwnerMutationResponse {
    product: &'static str,
    mode: &'static str,
    production_activation: bool,
    operation: &'static str,
    changed: bool,
    revoked_offer_count: usize,
    closed_session_count: usize,
    status: MobileClawVpnStatusResponse,
}

#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
struct MobileClawVpnOfferResponse {
    product: &'static str,
    mode: &'static str,
    production_activation: bool,
    operation: &'static str,
    offer_token: String,
    status: MobileClawVpnStatusResponse,
}

#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
struct MobileClawVpnSessionResponse {
    product: &'static str,
    mode: &'static str,
    production_activation: bool,
    operation: &'static str,
    rendezvous_token: String,
    status: MobileClawVpnStatusResponse,
}

#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
struct MobileClawVpnRendezvousAuthorizeResponse {
    product: &'static str,
    mode: &'static str,
    production_activation: bool,
    operation: &'static str,
    authorized: bool,
    status: MobileClawVpnStatusResponse,
}

struct MobileClawVpnRendezvousDialPreflight {
    hello: RendezvousHello,
}

impl MobileClawVpnRendezvousDialPreflight {
    fn guest(relay_token: RendezvousToken) -> Self {
        Self {
            hello: RendezvousHello::new(RendezvousRole::Guest, relay_token),
        }
    }

    fn into_hello_bytes(self) -> Vec<u8> {
        self.hello.encode()
    }
}

fn build_resource_option_range(
    label: &'static str,
    min: u32,
    max: u32,
    preferred_default: u32,
    disabled: Option<bool>,
) -> Result<ResourceOptionRange, crate::capacity::CapacityError> {
    if max < min {
        return Err(crate::capacity::CapacityError {
            message: format!(
                "insufficient {label}: minimum supported is {min}, but only {max} available"
            ),
            retry_after_secs: RESOURCE_OPTIONS_RETRY_AFTER_SECS,
        });
    }

    Ok(ResourceOptionRange {
        min,
        max,
        default: preferred_default.clamp(min, max),
        disabled,
    })
}

fn build_resource_options_response(
    cpu_max: u32,
    ram_max: u32,
    disk_max: u32,
    is_macos: bool,
) -> Result<ResourceOptionsResponse, crate::capacity::CapacityError> {
    let defaults = VmCreateResourceSpec::default().resolve();
    Ok(ResourceOptionsResponse {
        cpu_cores: build_resource_option_range("CPU", 1, cpu_max, defaults.cpu_cores, None)?,
        ram_mb: build_resource_option_range("RAM", 512, ram_max, defaults.ram_mb, None)?,
        disk_gb: build_resource_option_range(
            "disk",
            5,
            disk_max,
            defaults.disk_gb,
            Some(is_macos),
        )?,
    })
}

fn resource_options_capacity_response(cap_err: &crate::capacity::CapacityError) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": cap_err.message,
            "code": "SERVICE_UNAVAILABLE",
            "retry_after_secs": cap_err.retry_after_secs,
        })),
    )
        .into_response()
}

fn mobile_claw_vpn_status_response(
    status: ClawVpnMobileMeshStoreStatus,
) -> MobileClawVpnStatusResponse {
    MobileClawVpnStatusResponse {
        product: "product_a_mobile_claw_vpn",
        mode: "mesh_c_status_only",
        production_activation: false,
        state: if status.snapshot_present() {
            "configured"
        } else {
            "not_configured"
        },
        snapshot_present: status.snapshot_present(),
        enrolled_device_count: status.enrolled_device_count(),
        available_claw_count: status.available_claw_count(),
        grant_count: status.grant_count(),
        offer_count: status.offer_count(),
        session_count: status.session_count(),
    }
}

fn mobile_claw_vpn_status_error(error: ClawVpnMobileMeshStoreError) -> ApiError {
    mobile_claw_vpn_store_error(error, "mobile Claw VPN mesh status unavailable")
}

fn mobile_claw_vpn_store_error(
    error: ClawVpnMobileMeshStoreError,
    public_message: &'static str,
) -> ApiError {
    mobile_claw_vpn_log_store_error(&error, public_message);
    ApiError::service_unavailable(public_message)
}

fn mobile_claw_vpn_offer_store_error(
    error: ClawVpnMobileMeshStoreError,
    public_message: &'static str,
) -> ApiError {
    mobile_claw_vpn_log_store_error(&error, public_message);
    match error.kind() {
        ClawVpnMobileMeshStoreErrorKind::Storage => ApiError::service_unavailable(public_message),
        ClawVpnMobileMeshStoreErrorKind::Model => match error.model_error() {
            Some(ClawVpnMobileMeshError::EmptyId | ClawVpnMobileMeshError::InvalidId) => {
                ApiError::bad_request("invalid mobile Claw VPN mesh request")
            }
            Some(
                ClawVpnMobileMeshError::DeviceNotEnrolled
                | ClawVpnMobileMeshError::Unauthorized
                | ClawVpnMobileMeshError::SelectedClawMismatch,
            ) => ApiError::forbidden("mobile Claw VPN offer action denied"),
            Some(ClawVpnMobileMeshError::ClawUnavailable) => {
                ApiError::conflict("mobile Claw VPN offer action unavailable")
            }
            Some(
                ClawVpnMobileMeshError::UnknownOffer
                | ClawVpnMobileMeshError::OfferExpired
                | ClawVpnMobileMeshError::OfferAlreadyConsumed
                | ClawVpnMobileMeshError::Revoked,
            ) => ApiError::gone("mobile Claw VPN offer unavailable"),
            Some(
                ClawVpnMobileMeshError::ZeroOfferTtl
                | ClawVpnMobileMeshError::TimeOverflow
                | ClawVpnMobileMeshError::IdExhausted
                | ClawVpnMobileMeshError::UnknownSession
                | ClawVpnMobileMeshError::UnsupportedSnapshotSchema
                | ClawVpnMobileMeshError::DuplicateSnapshotEntry
                | ClawVpnMobileMeshError::InvalidSnapshotCounter,
            )
            | None => ApiError::service_unavailable(public_message),
        },
    }
}

fn mobile_claw_vpn_rendezvous_store_error(
    error: ClawVpnMobileMeshStoreError,
    public_message: &'static str,
) -> ApiError {
    mobile_claw_vpn_log_store_error(&error, public_message);
    match error.kind() {
        ClawVpnMobileMeshStoreErrorKind::Storage => ApiError::service_unavailable(public_message),
        ClawVpnMobileMeshStoreErrorKind::Model => match error.model_error() {
            Some(ClawVpnMobileMeshError::EmptyId | ClawVpnMobileMeshError::InvalidId) => {
                ApiError::bad_request("invalid mobile Claw VPN mesh request")
            }
            Some(
                ClawVpnMobileMeshError::DeviceNotEnrolled
                | ClawVpnMobileMeshError::Unauthorized
                | ClawVpnMobileMeshError::SelectedClawMismatch,
            ) => ApiError::forbidden("mobile Claw VPN rendezvous denied"),
            Some(ClawVpnMobileMeshError::ClawUnavailable) => {
                ApiError::conflict("mobile Claw VPN rendezvous unavailable")
            }
            Some(
                ClawVpnMobileMeshError::UnknownOffer
                | ClawVpnMobileMeshError::UnknownSession
                | ClawVpnMobileMeshError::OfferExpired
                | ClawVpnMobileMeshError::OfferAlreadyConsumed
                | ClawVpnMobileMeshError::Revoked,
            ) => ApiError::gone("mobile Claw VPN rendezvous unavailable"),
            Some(
                ClawVpnMobileMeshError::ZeroOfferTtl
                | ClawVpnMobileMeshError::TimeOverflow
                | ClawVpnMobileMeshError::IdExhausted
                | ClawVpnMobileMeshError::UnsupportedSnapshotSchema
                | ClawVpnMobileMeshError::DuplicateSnapshotEntry
                | ClawVpnMobileMeshError::InvalidSnapshotCounter,
            )
            | None => ApiError::service_unavailable(public_message),
        },
    }
}

fn mobile_claw_vpn_log_store_error(
    error: &ClawVpnMobileMeshStoreError,
    public_message: &'static str,
) {
    tracing::warn!(
        operation = error.operation(),
        kind = mobile_mesh_store_error_kind_label(error.kind()),
        storage_kind = error.storage_kind().unwrap_or("none"),
        model_error = error
            .model_error()
            .map_or("none", mobile_mesh_model_error_label),
        public_message
    );
}

fn mobile_mesh_store_error_kind_label(kind: ClawVpnMobileMeshStoreErrorKind) -> &'static str {
    match kind {
        ClawVpnMobileMeshStoreErrorKind::Storage => "storage",
        ClawVpnMobileMeshStoreErrorKind::Model => "model",
    }
}

fn mobile_mesh_model_error_label(error: ClawVpnMobileMeshError) -> &'static str {
    match error {
        ClawVpnMobileMeshError::EmptyId => "empty_id",
        ClawVpnMobileMeshError::InvalidId => "invalid_id",
        ClawVpnMobileMeshError::ZeroOfferTtl => "zero_offer_ttl",
        ClawVpnMobileMeshError::TimeOverflow => "time_overflow",
        ClawVpnMobileMeshError::IdExhausted => "id_exhausted",
        ClawVpnMobileMeshError::DeviceNotEnrolled => "device_not_enrolled",
        ClawVpnMobileMeshError::ClawUnavailable => "claw_unavailable",
        ClawVpnMobileMeshError::Unauthorized => "unauthorized",
        ClawVpnMobileMeshError::UnknownOffer => "unknown_offer",
        ClawVpnMobileMeshError::OfferExpired => "offer_expired",
        ClawVpnMobileMeshError::OfferAlreadyConsumed => "offer_already_consumed",
        ClawVpnMobileMeshError::Revoked => "revoked",
        ClawVpnMobileMeshError::SelectedClawMismatch => "selected_claw_mismatch",
        ClawVpnMobileMeshError::UnknownSession => "unknown_session",
        ClawVpnMobileMeshError::UnsupportedSnapshotSchema => "unsupported_snapshot_schema",
        ClawVpnMobileMeshError::DuplicateSnapshotEntry => "duplicate_snapshot_entry",
        ClawVpnMobileMeshError::InvalidSnapshotCounter => "invalid_snapshot_counter",
    }
}

fn mobile_claw_vpn_request_error(_error: ClawVpnMobileMeshError) -> ApiError {
    ApiError::bad_request("invalid mobile Claw VPN mesh request")
}

fn mobile_claw_vpn_member_id(value: String) -> Result<ClawVpnMobileMemberId, ApiError> {
    ClawVpnMobileMemberId::try_new(value).map_err(mobile_claw_vpn_request_error)
}

fn mobile_claw_vpn_device_id(value: String) -> Result<ClawVpnMobileDeviceId, ApiError> {
    ClawVpnMobileDeviceId::try_new(value).map_err(mobile_claw_vpn_request_error)
}

fn mobile_claw_vpn_claw_id(value: String) -> Result<ClawVpnMobileClawId, ApiError> {
    ClawVpnMobileClawId::try_new(value).map_err(mobile_claw_vpn_request_error)
}

fn mobile_claw_vpn_acl_grant(
    req: MobileClawVpnAclGrantRequest,
) -> Result<ClawVpnMobileAclGrant, ApiError> {
    Ok(ClawVpnMobileAclGrant::new(
        mobile_claw_vpn_member_id(req.member)?,
        mobile_claw_vpn_device_id(req.device)?,
        mobile_claw_vpn_claw_id(req.claw)?,
    ))
}

fn mobile_claw_vpn_offer_grant(
    username: String,
    req: MobileClawVpnOfferRequest,
) -> Result<ClawVpnMobileAclGrant, ApiError> {
    Ok(ClawVpnMobileAclGrant::new(
        mobile_claw_vpn_member_id(username)?,
        mobile_claw_vpn_device_id(req.device)?,
        mobile_claw_vpn_claw_id(req.claw)?,
    ))
}

fn mobile_claw_vpn_session_grant(
    username: String,
    req: &MobileClawVpnSessionRequest,
) -> Result<ClawVpnMobileAclGrant, ApiError> {
    Ok(ClawVpnMobileAclGrant::new(
        mobile_claw_vpn_member_id(username)?,
        mobile_claw_vpn_device_id(req.device.clone())?,
        mobile_claw_vpn_claw_id(req.claw.clone())?,
    ))
}

fn mobile_claw_vpn_rendezvous_grant(
    username: String,
    req: &MobileClawVpnRendezvousAuthorizeRequest,
) -> Result<ClawVpnMobileAclGrant, ApiError> {
    Ok(ClawVpnMobileAclGrant::new(
        mobile_claw_vpn_member_id(username)?,
        mobile_claw_vpn_device_id(req.device.clone())?,
        mobile_claw_vpn_claw_id(req.claw.clone())?,
    ))
}

fn mobile_claw_vpn_offer_token(value: String) -> Result<ClawVpnMobileOfferToken, ApiError> {
    ClawVpnMobileOfferToken::try_new(value).map_err(mobile_claw_vpn_request_error)
}

fn mobile_claw_vpn_rendezvous_token(
    value: String,
) -> Result<ClawVpnMobileRendezvousToken, ApiError> {
    ClawVpnMobileRendezvousToken::try_new(value).map_err(mobile_claw_vpn_request_error)
}

fn mobile_claw_vpn_now_unix() -> Result<u64, ApiError> {
    crate::time_util::unix_now_secs_checked("mobile_claw_vpn_mesh_offer.now")
        .ok_or_else(|| ApiError::service_unavailable("mobile Claw VPN clock unavailable"))
}

fn mobile_claw_vpn_owner_mutation_response(
    operation: &'static str,
    changed: bool,
    revoked_offer_count: usize,
    closed_session_count: usize,
    status: ClawVpnMobileMeshStoreStatus,
) -> MobileClawVpnOwnerMutationResponse {
    MobileClawVpnOwnerMutationResponse {
        product: "product_a_mobile_claw_vpn",
        mode: "mesh_c_owner_admin",
        production_activation: false,
        operation,
        changed,
        revoked_offer_count,
        closed_session_count,
        status: mobile_claw_vpn_status_response(status),
    }
}

fn mobile_claw_vpn_offer_response(
    operation: &'static str,
    offer_token: &ClawVpnMobileOfferToken,
    status: ClawVpnMobileMeshStoreStatus,
) -> MobileClawVpnOfferResponse {
    MobileClawVpnOfferResponse {
        product: "product_a_mobile_claw_vpn",
        mode: "mesh_c_offer_control",
        production_activation: false,
        operation,
        offer_token: offer_token.public_token().to_string(),
        status: mobile_claw_vpn_status_response(status),
    }
}

fn mobile_claw_vpn_session_response(
    operation: &'static str,
    rendezvous_token: &ClawVpnMobileRendezvousToken,
    status: ClawVpnMobileMeshStoreStatus,
) -> MobileClawVpnSessionResponse {
    MobileClawVpnSessionResponse {
        product: "product_a_mobile_claw_vpn",
        mode: "mesh_c_offer_control",
        production_activation: false,
        operation,
        rendezvous_token: rendezvous_token.public_token().to_string(),
        status: mobile_claw_vpn_status_response(status),
    }
}

fn mobile_claw_vpn_rendezvous_authorize_response(
    operation: &'static str,
    status: ClawVpnMobileMeshStoreStatus,
) -> MobileClawVpnRendezvousAuthorizeResponse {
    MobileClawVpnRendezvousAuthorizeResponse {
        product: "product_a_mobile_claw_vpn",
        mode: "mesh_c_rendezvous_preflight",
        production_activation: false,
        operation,
        authorized: true,
        status: mobile_claw_vpn_status_response(status),
    }
}

fn mobile_claw_vpn_rendezvous_dial_preflight(
    store: &ClawVpnMobileMeshStore,
    rendezvous_token: &ClawVpnMobileRendezvousToken,
    grant: &ClawVpnMobileAclGrant,
) -> Result<MobileClawVpnRendezvousDialPreflight, ClawVpnMobileMeshStoreError> {
    let relay_token = store.authorize_rendezvous_token(rendezvous_token, grant)?;
    Ok(MobileClawVpnRendezvousDialPreflight::guest(relay_token))
}

/// Detect the best host for the QR code based on available network channels.
///
/// Priority: Cloudflare (public) > Tailscale (private) > LAN > localhost.
#[must_use]
pub fn best_qr_host() -> (String, String) {
    let status = core_rs::network_detect::detect_network_status();
    best_qr_host_from_status(&status)
}

/// Platform metadata exposed to mobile clients.
#[must_use]
pub fn server_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// Testable inner function — selects the best host from a pre-built [`NetworkStatus`].
fn best_qr_host_from_status(status: &core_rs::network_detect::NetworkStatus) -> (String, String) {
    let admin_port = status
        .channels
        .iter()
        .find(|c| c.channel_type == "local")
        .and_then(|c| c.urls.first())
        .and_then(|u| u.rsplit(':').next())
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8892);

    // Priority 1: Cloudflare (public, works from anywhere)
    for ch in &status.channels {
        if ch.channel_type == "cloudflare" && ch.detected {
            if let Some(ref hostname) = ch.hostname {
                return (hostname.clone(), "cloudflare".into());
            }
        }
    }

    // Priority 2: Tailscale (private, works on tailnet)
    // has_https is the effective per-node HTTPS availability computed by
    // network detection after considering tailscale serve and local Caddy.
    for ch in &status.channels {
        if ch.channel_type == "tailscale" && ch.detected {
            let has_https = ch.has_https == Some(true);
            if has_https {
                if let Some(ref hostname) = ch.hostname {
                    return (format!("https://{hostname}"), "tailscale".into());
                }
            }
            if let Some(ref ip) = ch.ip {
                return (format!("http://{ip}:{admin_port}"), "tailscale".into());
            }
            if let Some(ref hostname) = ch.hostname {
                return (
                    format!("http://{hostname}:{admin_port}"),
                    "tailscale".into(),
                );
            }
        }
    }

    // Priority 3: LAN IP
    for ch in &status.channels {
        if ch.channel_type == "lan" && ch.detected {
            if let Some(ref ip) = ch.ip {
                return (format!("{ip}:{admin_port}"), "lan".into());
            }
        }
    }

    // Fallback: localhost
    (format!("localhost:{admin_port}"), "local".into())
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// `POST /api/v1/instances/{id}/qr-token`
///
/// Admin-authenticated. Generates a short-lived QR token for the given instance.
/// The frontend renders this token as a QR code for the mobile app to scan.
///
/// # Errors
///
/// Returns `ApiError` if the instance doesn't exist or the DB query fails.
#[tracing::instrument(skip(state))]
pub async fn handle_generate_qr_token(
    State(state): State<SharedState>,
    AdminUser(AuthUser { username, .. }): AdminUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    // Look up the instance in the database.
    let st = state.clone();
    let iid = id.clone();
    let row = blocking(move || st.instance_db.get(&iid).map_err(ApiError::from)).await??;
    let row = row.ok_or_else(|| ApiError::not_found("instance not found"))?;

    // Generate QR token (carries the generating admin's username)
    let (token, expires_at) = state.mobile_tokens.create_qr_token(&id, &username);

    let (qr_host, qr_channel) = best_qr_host();
    let deep_link = mobile_deep_link("connect", &[("token", &token), ("host", &qr_host)]);
    let image_id = state.mobile_tokens.store_image_link(&deep_link);

    tracing::info!(
        "[mobile] user={username} generated QR token for instance={id} container={} qr_host={qr_host} channel={qr_channel}",
        row.container
    );

    Ok((
        StatusCode::OK,
        Json(QrTokenResponse {
            token,
            expires_at,
            qr_host,
            qr_channel,
            deep_link,
            image_id,
            instance: QrInstanceInfo {
                id: row.id,
                name: row.name,
                container: row.container,
                claw_type: row.claw_type,
            },
        }),
    )
        .into_response())
}

/// `POST /api/v1/mobile/auth`
///
/// Public (no auth required). Exchanges a QR token for a mobile session token.
/// The QR token is single-use and consumed on successful exchange.
///
/// # Errors
///
/// Returns 401 if the QR token is invalid or expired.
#[tracing::instrument(skip_all)]
pub async fn handle_mobile_auth(
    State(state): State<SharedState>,
    Json(req): Json<MobileAuthRequest>,
) -> Result<Response, ApiError> {
    if req.qr_token.is_empty() {
        return Err(ApiError::bad_request("qr_token is required"));
    }

    // Validate and consume the QR token (single-use).
    // `workspace_id_opt` is `Some` for "continue on iPhone" tokens — handled below.
    let (instance_id, qr_username, workspace_id_opt) = state
        .mobile_tokens
        .redeem_qr_token(&req.qr_token)
        .ok_or_else(|| ApiError::unauthorized("invalid or expired QR token"))?;

    // Look up the instance to confirm it still exists.
    let st = state.clone();
    let iid = instance_id.clone();
    let target_row = blocking(move || st.instance_db.get(&iid).map_err(ApiError::from)).await??;
    let target_row = target_row.ok_or_else(|| ApiError::not_found("instance no longer exists"))?;

    // Create a persistent mobile session with the real admin username from the
    // QR token — workspace (container, username) matches between web and mobile,
    // so both devices get the same tmux session.
    let (session_token, expires_at) = state
        .mobile_sessions
        .create_session(&qr_username)
        .map_err(|e| ApiError::internal(format!("create session: {e}")))?;

    let instances = build_instance_list(&state, &qr_username).await?;

    // Continue-on-iPhone handoff: the QR was minted for a specific tmux workspace.
    // Re-validate ownership + instance status at redeem time (not trust-on-mint)
    // so that workspace deletions / instance stops between generation and scan
    // gracefully degrade to the instance-picker fallback on iOS.
    let (target_instance_id, target_conversation_id, target_ws_url) = match workspace_id_opt {
        Some(workspace_id) if target_row.status == store_rs::InstanceStatus::Active => {
            let st = state.clone();
            let ws_id = workspace_id.clone();
            let container = target_row.container.clone();
            let username = qr_username.clone();
            let is_owner = blocking(move || {
                st.instance_db
                    .verify_conversation_owner(&ws_id, &container, &username)
                    .map_err(ApiError::from)
            })
            .await??;

            if is_owner {
                // Touch last_attach_at so `list_conversations` ordering reflects this
                // new attach (mirrors what `resume_or_create_conversation` does).
                let st = state.clone();
                let ws_id = workspace_id.clone();
                let _ = blocking(move || {
                    st.instance_db
                        .touch_conversation_attached(&ws_id)
                        .map_err(ApiError::from)
                })
                .await?;

                let ws_url = build_pty_ws_url(&target_row.container, &workspace_id, &session_token);
                (
                    Some(target_row.id.clone()),
                    Some(workspace_id),
                    Some(ws_url),
                )
            } else {
                tracing::warn!(
                    "[mobile] continue QR workspace ownership check failed: \
                     workspace={workspace_id} container={} user={qr_username}",
                    target_row.container
                );
                (None, None, None)
            }
        }
        Some(workspace_id) => {
            tracing::info!(
                "[mobile] continue QR redeemed but instance is {} (not Active) — \
                 falling back to instance list: container={} workspace={workspace_id}",
                target_row.status,
                target_row.container
            );
            (None, None, None)
        }
        None => (None, None, None),
    };

    tracing::info!(
        "[mobile] QR auth success: instance={} container={} continue={}",
        target_row.id,
        target_row.container,
        target_ws_url.is_some()
    );

    Ok((
        StatusCode::OK,
        Json(MobileAuthResponse {
            session_token,
            expires_at,
            instances,
            target_instance_id,
            target_conversation_id,
            target_ws_url,
        }),
    )
        .into_response())
}

/// Build a PTY WebSocket URL using the same scheme/host detection that
/// `handle_simulator_token` applies — keeps behaviour consistent across every
/// handoff path (simulator one-shot, continue-on-iPhone).
fn build_pty_ws_url(container: &str, session_id: &str, bearer: &str) -> String {
    let (host, _channel) = best_qr_host();
    let bare = host
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let scheme = if bare.starts_with("localhost")
        || bare.starts_with("127.0.0.1")
        || bare.starts_with("192.168.")
        || bare.starts_with("10.")
    {
        "ws"
    } else {
        "wss"
    };
    format!(
        "{scheme}://{bare}/api/v1/terminals/{container}/pty?session={session_id}&token={bearer}"
    )
}

/// `GET /api/v1/mobile/status`
///
/// Mobile-authenticated (Bearer token). Validates the session token.
///
/// # Errors
///
/// Returns 401 if the Bearer token is missing or invalid.
#[tracing::instrument(skip_all)]
pub async fn handle_mobile_status(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let _username = extract_mobile_bearer(&state, &headers)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/v1/mobile/claw-vpn/status`
///
/// Mobile-authenticated. Returns a redacted, count-only status view of the
/// Product A mobile per-Claw VPN Mesh-C store. This endpoint does not grant
/// ACLs, mint offers, open relay sessions, or mutate host networking.
///
/// # Errors
///
/// Returns 401 if not authenticated, or 503 if the persisted mesh state cannot
/// be read or validated.
#[tracing::instrument(skip_all)]
pub async fn handle_mobile_claw_vpn_status(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let _username = extract_mobile_bearer(&state, &headers)?;
    let store = state.mobile_claw_vpn_mesh.clone();
    let status = blocking(move || store.status().map_err(mobile_claw_vpn_status_error)).await??;
    Ok((
        StatusCode::OK,
        Json(mobile_claw_vpn_status_response(status)),
    )
        .into_response())
}

/// `POST /api/v1/mobile/claw-vpn/offers`
///
/// Mobile-authenticated. Mints one Mesh-C offer for the authenticated member,
/// Device-D, and selected Claw only after the persisted owner-approved ACL,
/// device enrollment, Claw availability, and revocation state are checked by
/// the store model. This does not open relay sessions or mutate host networking.
///
/// # Errors
///
/// Returns 401 without a valid mobile bearer, 400 for invalid redacted
/// identifiers, 403/409/410 for fail-closed Mesh-C denies, or 503 for storage
/// and clock failures.
#[tracing::instrument(skip_all)]
pub async fn handle_mobile_claw_vpn_mint_offer(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MobileClawVpnOfferRequest>,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;
    let grant = mobile_claw_vpn_offer_grant(username, req)?;
    let now_unix = mobile_claw_vpn_now_unix()?;
    let store = state.mobile_claw_vpn_mesh.clone();
    let (offer_token, status) = blocking(move || {
        let offer_token = store.mint_offer_token(&grant, now_unix).map_err(|error| {
            mobile_claw_vpn_offer_store_error(error, "mobile Claw VPN offer action failed")
        })?;
        let status = store.status().map_err(|error| {
            mobile_claw_vpn_offer_store_error(error, "mobile Claw VPN offer action failed")
        })?;
        Ok::<_, ApiError>((offer_token, status))
    })
    .await??;
    Ok((
        StatusCode::OK,
        Json(mobile_claw_vpn_offer_response(
            "mint_offer",
            &offer_token,
            status,
        )),
    )
        .into_response())
}

/// `POST /api/v1/mobile/claw-vpn/sessions`
///
/// Mobile-authenticated. Consumes a Mesh-C offer for the authenticated member,
/// Device-D, and selected Claw. The offer remains single-use and TTL-bound in
/// the persisted model. This creates only a Mesh-C session record plus an
/// opaque relay rendezvous capability; it does not open a relay, TUN/utun,
/// route, or `NetworkExtension` tunnel.
///
/// # Errors
///
/// Returns 401 without a valid mobile bearer, 400 for invalid redacted
/// identifiers, 403/409/410 for fail-closed Mesh-C denies, or 503 for storage
/// and clock failures.
#[tracing::instrument(skip_all)]
pub async fn handle_mobile_claw_vpn_consume_offer(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MobileClawVpnSessionRequest>,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;
    let grant = mobile_claw_vpn_session_grant(username, &req)?;
    let offer_token = mobile_claw_vpn_offer_token(req.offer)?;
    let now_unix = mobile_claw_vpn_now_unix()?;
    let store = state.mobile_claw_vpn_mesh.clone();
    let (rendezvous_token, status) = blocking(move || {
        let rendezvous_token = store
            .consume_offer_token(&offer_token, &grant, now_unix)
            .map_err(|error| {
                mobile_claw_vpn_offer_store_error(error, "mobile Claw VPN offer action failed")
            })?;
        let status = store.status().map_err(|error| {
            mobile_claw_vpn_offer_store_error(error, "mobile Claw VPN offer action failed")
        })?;
        Ok::<_, ApiError>((rendezvous_token, status))
    })
    .await??;
    Ok((
        StatusCode::OK,
        Json(mobile_claw_vpn_session_response(
            "consume_offer",
            &rendezvous_token,
            status,
        )),
    )
        .into_response())
}

/// `POST /api/v1/mobile/claw-vpn/rendezvous/authorize`
///
/// Mobile-authenticated. Revalidates an existing Mesh-C rendezvous capability
/// for the authenticated member, Device-D, and selected Claw before any future
/// relay dial. This is a read-only preflight: it does not return the decoded
/// relay token, open relay sessions, install routes, or mutate host networking.
///
/// # Errors
///
/// Returns 401 without a valid mobile bearer, 400 for invalid redacted
/// identifiers or token shape, 403/409/410 for fail-closed Mesh-C denies, or
/// 503 for storage failures.
#[tracing::instrument(skip_all)]
pub async fn handle_mobile_claw_vpn_authorize_rendezvous(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MobileClawVpnRendezvousAuthorizeRequest>,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;
    let grant = mobile_claw_vpn_rendezvous_grant(username, &req)?;
    let rendezvous_token = mobile_claw_vpn_rendezvous_token(req.rendezvous)?;
    let store = state.mobile_claw_vpn_mesh.clone();
    let status = blocking(move || {
        let dial_preflight = mobile_claw_vpn_rendezvous_dial_preflight(
            &store,
            &rendezvous_token,
            &grant,
        )
        .map_err(|error| {
            mobile_claw_vpn_rendezvous_store_error(error, "mobile Claw VPN rendezvous unavailable")
        })?;
        let _hello_bytes = dial_preflight.into_hello_bytes();
        store.status().map_err(|error| {
            mobile_claw_vpn_rendezvous_store_error(error, "mobile Claw VPN rendezvous unavailable")
        })
    })
    .await??;
    Ok((
        StatusCode::OK,
        Json(mobile_claw_vpn_rendezvous_authorize_response(
            "authorize_rendezvous",
            status,
        )),
    )
        .into_response())
}

/// `POST /api/v1/mobile/claw-vpn/owner/enroll-device`
///
/// Admin-authenticated owner action. Persists Device-D enrollment in Mesh-C.
/// This does not grant ACLs, mint offers, open relay sessions, or mutate host
/// networking.
///
/// # Errors
///
/// Returns 403 for non-admin users, 400 for invalid redacted identifiers, or
/// 503 if the persisted mesh state cannot be read or written.
#[tracing::instrument(skip_all)]
pub async fn handle_admin_mobile_claw_vpn_enroll_device(
    State(state): State<SharedState>,
    AdminUser(_auth): AdminUser,
    Json(req): Json<MobileClawVpnDeviceRequest>,
) -> Result<Response, ApiError> {
    let device = mobile_claw_vpn_device_id(req.device_id)?;
    let store = state.mobile_claw_vpn_mesh.clone();
    let (changed, status) = blocking(move || {
        let changed = store
            .owner_approved_enroll_device(device)
            .map_err(|error| {
                mobile_claw_vpn_store_error(error, "mobile Claw VPN owner action failed")
            })?;
        let status = store.status().map_err(|error| {
            mobile_claw_vpn_store_error(error, "mobile Claw VPN owner action failed")
        })?;
        Ok::<_, ApiError>((changed, status))
    })
    .await??;
    Ok((
        StatusCode::OK,
        Json(mobile_claw_vpn_owner_mutation_response(
            "enroll_device",
            changed,
            0,
            0,
            status,
        )),
    )
        .into_response())
}

/// `POST /api/v1/mobile/claw-vpn/owner/claw-availability`
///
/// Admin-authenticated owner/operator action. Updates Mesh-C responder
/// availability only; it does not start a responder or mutate TUN/utun/routes.
///
/// # Errors
///
/// Returns 403 for non-admin users, 400 for invalid redacted identifiers, or
/// 503 if the persisted mesh state cannot be read or written.
#[tracing::instrument(skip_all)]
pub async fn handle_admin_mobile_claw_vpn_set_claw_availability(
    State(state): State<SharedState>,
    AdminUser(_auth): AdminUser,
    Json(req): Json<MobileClawVpnClawAvailabilityRequest>,
) -> Result<Response, ApiError> {
    let available = req.available;
    let claw = mobile_claw_vpn_claw_id(req.claw_id)?;
    let store = state.mobile_claw_vpn_mesh.clone();
    let (changed, revoked_offer_count, closed_session_count, status) = blocking(move || {
        let (changed, revoked_offer_count, closed_session_count) = if available {
            let changed = store.set_claw_available(claw).map_err(|error| {
                mobile_claw_vpn_store_error(error, "mobile Claw VPN owner action failed")
            })?;
            (changed, 0, 0)
        } else {
            let change = store.set_claw_unavailable(&claw).map_err(|error| {
                mobile_claw_vpn_store_error(error, "mobile Claw VPN owner action failed")
            })?;
            (
                change.changed(),
                change.revoked_offer_count(),
                change.closed_session_count(),
            )
        };
        let status = store.status().map_err(|error| {
            mobile_claw_vpn_store_error(error, "mobile Claw VPN owner action failed")
        })?;
        Ok::<_, ApiError>((changed, revoked_offer_count, closed_session_count, status))
    })
    .await??;
    Ok((
        StatusCode::OK,
        Json(mobile_claw_vpn_owner_mutation_response(
            if available {
                "set_claw_available"
            } else {
                "set_claw_unavailable"
            },
            changed,
            revoked_offer_count,
            closed_session_count,
            status,
        )),
    )
        .into_response())
}

/// `POST /api/v1/mobile/claw-vpn/owner/grant`
///
/// Admin-authenticated owner action. Persists the ACL relation for one member,
/// one Device-D, and one selected Claw. It does not mint a usable offer.
///
/// # Errors
///
/// Returns 403 for non-admin users, 400 for invalid redacted identifiers, or
/// 503 if the persisted mesh state cannot be read or written.
#[tracing::instrument(skip_all)]
pub async fn handle_admin_mobile_claw_vpn_grant(
    State(state): State<SharedState>,
    AdminUser(_auth): AdminUser,
    Json(req): Json<MobileClawVpnAclGrantRequest>,
) -> Result<Response, ApiError> {
    let grant = mobile_claw_vpn_acl_grant(req)?;
    let store = state.mobile_claw_vpn_mesh.clone();
    let (changed, status) = blocking(move || {
        let changed = store.owner_approved_grant(grant).map_err(|error| {
            mobile_claw_vpn_store_error(error, "mobile Claw VPN owner action failed")
        })?;
        let status = store.status().map_err(|error| {
            mobile_claw_vpn_store_error(error, "mobile Claw VPN owner action failed")
        })?;
        Ok::<_, ApiError>((changed, status))
    })
    .await??;
    Ok((
        StatusCode::OK,
        Json(mobile_claw_vpn_owner_mutation_response(
            "grant", changed, 0, 0, status,
        )),
    )
        .into_response())
}

/// `POST /api/v1/mobile/claw-vpn/owner/revoke-grant`
///
/// Admin-authenticated owner action. Revokes one ACL relation and closes only
/// sessions minted for that relation. It does not touch any host interface or
/// route.
///
/// # Errors
///
/// Returns 403 for non-admin users, 400 for invalid redacted identifiers, or
/// 503 if the persisted mesh state cannot be read or written.
#[tracing::instrument(skip_all)]
pub async fn handle_admin_mobile_claw_vpn_revoke_grant(
    State(state): State<SharedState>,
    AdminUser(_auth): AdminUser,
    Json(req): Json<MobileClawVpnAclGrantRequest>,
) -> Result<Response, ApiError> {
    let grant = mobile_claw_vpn_acl_grant(req)?;
    let store = state.mobile_claw_vpn_mesh.clone();
    let (revocation, status) = blocking(move || {
        let revocation = store.owner_approved_revoke(&grant).map_err(|error| {
            mobile_claw_vpn_store_error(error, "mobile Claw VPN owner action failed")
        })?;
        let status = store.status().map_err(|error| {
            mobile_claw_vpn_store_error(error, "mobile Claw VPN owner action failed")
        })?;
        Ok::<_, ApiError>((revocation, status))
    })
    .await??;
    let changed = revocation.grant_removed()
        || revocation.revoked_offer_count() > 0
        || revocation.closed_session_count() > 0;
    Ok((
        StatusCode::OK,
        Json(mobile_claw_vpn_owner_mutation_response(
            "revoke_grant",
            changed,
            revocation.revoked_offer_count(),
            revocation.closed_session_count(),
            status,
        )),
    )
        .into_response())
}

/// `GET /api/v1/mobile/instances`
///
/// Mobile-authenticated. Returns the list of all active instances with capabilities.
///
/// # Errors
///
/// Returns 401 if not authenticated, or 500 on DB failure.
#[tracing::instrument(skip_all)]
pub async fn handle_mobile_instances(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;
    let instances = build_instance_list(&state, &username).await?;
    Ok((
        StatusCode::OK,
        Json(json!({"data": instances, "has_more": false, "next_cursor": null})),
    )
        .into_response())
}

/// `POST /api/v1/mobile/logout`
///
/// Mobile-authenticated (Bearer token). Revokes the session token.
/// Does NOT call `validate_session` first — that would needlessly extend TTL
/// via the sliding window. `delete_session` is idempotent (0 rows deleted if
/// already expired).
///
/// # Errors
///
/// Returns 401 if the Authorization header is missing/malformed, or 500 on DB error.
#[tracing::instrument(skip_all)]
pub async fn handle_mobile_logout(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("missing Authorization header"))?;
    state
        .mobile_sessions
        .delete_session(token)
        .map_err(|e| ApiError::internal(format!("delete session: {e}")))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ─── Simulator Token ─────────────────────────────────────────────────────────

/// 365 days in seconds.
const SIMULATOR_TOKEN_TTL: u64 = 365 * 24 * 3600;

#[derive(Debug, Deserialize)]
pub struct SimulatorTokenRequest {
    pub container: String,
}

/// `POST /api/v1/admin/simulator-token`
///
/// Admin-authenticated. Creates a long-lived mobile session token (365 days)
/// and a workspace for the given container. Returns everything the iOS
/// simulator needs to connect directly without the QR flow.
///
/// # Errors
///
/// Returns `ApiError` if the container doesn't exist, isn't active, or on DB failure.
#[tracing::instrument(skip(state), fields(container = %body.container))]
pub async fn handle_simulator_token(
    State(state): State<SharedState>,
    AdminUser(AuthUser { username, .. }): AdminUser,
    Json(body): Json<SimulatorTokenRequest>,
) -> Result<Response, ApiError> {
    let container = body.container.trim().to_string();
    if container.is_empty() {
        return Err(ApiError::bad_request("container is required"));
    }

    // Verify instance exists and is Active.
    let st = state.clone();
    let c = container.clone();
    let row =
        blocking(move || st.instance_db.get_by_container(&c).map_err(ApiError::from)).await??;
    let row = row.ok_or_else(|| ApiError::not_found("container not found"))?;
    if row.status != store_rs::InstanceStatus::Active {
        return Err(ApiError::bad_request(format!(
            "instance is {}, must be Active",
            row.status
        )));
    }

    // Create long-lived mobile session (365 days).
    let (session_token, expires_at) = state
        .mobile_sessions
        .create_session_with_ttl(&username, SIMULATOR_TOKEN_TTL)
        .map_err(|e| ApiError::internal(format!("create session: {e}")))?;

    // Create or resume a workspace for this container + user.
    let st = state.clone();
    let c = container.clone();
    let u = username.clone();
    let ws = blocking(move || {
        st.instance_db
            .resume_or_create_conversation(&c, &u)
            .map_err(ApiError::from)
    })
    .await??;

    let (host, _channel) = best_qr_host();
    let bare = host
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let scheme = if bare.starts_with("localhost")
        || bare.starts_with("127.0.0.1")
        || bare.starts_with("192.168.")
        || bare.starts_with("10.")
    {
        "ws"
    } else {
        "wss"
    };
    let ws_url = format!(
        "{scheme}://{bare}/api/v1/terminals/{}/pty?session={}&token={}",
        container, ws.id, session_token
    );

    tracing::info!(
        "[simulator] token created: user={username} container={container} workspace={}",
        ws.id
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "session_token": session_token,
            "session_id": ws.id,
            "container": container,
            "ws_url": ws_url,
            "expires_at": expires_at
        })),
    )
        .into_response())
}

// ─── Continue on iPhone (mobile-authed) ──────────────────────────────────────

/// Short TTL for "continue on iPhone" QR tokens. The flow is synchronous —
/// user holds the phone in one hand while the Mac shows the QR — so a 2-minute
/// window balances retry room against exposure time for a single-use token.
const CONTINUE_QR_TTL_SECS: u64 = 120;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ContinueQrRequest {
    pub container: String,
    pub workspace_id: String,
}

/// `POST /api/v1/mobile/continue-qr`
///
/// Mobile-authenticated. Generates a short-lived QR token that, when scanned
/// by the iOS app, lands the user in the specific tmux workspace the caller
/// is currently attached to — bypassing the instance picker.
///
/// Ownership is enforced: the caller must own (or be admin for) the container,
/// AND the workspace must belong to the caller's username+container tuple.
///
/// # Errors
///
/// - 400 invalid container string
/// - 404 container not owned by user (ownership leak protection)
/// - 404 workspace doesn't exist or doesn't belong to user
#[tracing::instrument(skip(state), fields(container = %body.container, workspace_id = %body.workspace_id))]
pub async fn handle_generate_continue_qr(
    State(state): State<SharedState>,
    auth: AuthUser,
    Json(body): Json<ContinueQrRequest>,
) -> Result<Response, ApiError> {
    let container = crate::handlers_terminal::validate_container(&body.container)?;
    let workspace_id = body.workspace_id.trim().to_string();
    if workspace_id.is_empty() {
        return Err(ApiError::bad_request("workspace_id is required"));
    }

    // Ownership: user must be able to touch this container at all.
    crate::handlers_terminal::require_terminal_access(&state, &auth, &container).await?;

    // Resolve container → instance_id (used to populate the QR entry).
    let st = state.clone();
    let c = container.clone();
    let row =
        blocking(move || st.instance_db.get_by_container(&c).map_err(ApiError::from)).await??;
    let row = row.ok_or_else(|| ApiError::not_found("container not found"))?;

    // Workspace must be active AND belong to this (container, username).
    // `verify_conversation_owner` handles both checks atomically in one SQL round-trip.
    let st = state.clone();
    let ws_id = workspace_id.clone();
    let c = container.clone();
    let u = auth.username.clone();
    let is_owner = blocking(move || {
        st.instance_db
            .verify_conversation_owner(&ws_id, &c, &u)
            .map_err(ApiError::from)
    })
    .await??;
    if !is_owner {
        return Err(ApiError::not_found("workspace not found"));
    }

    let ttl = std::time::Duration::from_secs(CONTINUE_QR_TTL_SECS);
    let (token, expires_at) =
        state
            .mobile_tokens
            .create_continue_qr_token(&row.id, &auth.username, &workspace_id, ttl);

    let (qr_host, qr_channel) = best_qr_host();
    let deep_link = mobile_deep_link("connect", &[("token", &token), ("host", &qr_host)]);
    let image_id = state
        .mobile_tokens
        .store_image_link_with_ttl(&deep_link, ttl);

    tracing::info!(
        "[mobile] user={} generated continue QR for container={} workspace={} qr_host={} channel={}",
        auth.username,
        row.container,
        workspace_id,
        qr_host,
        qr_channel
    );

    Ok((
        StatusCode::OK,
        Json(QrTokenResponse {
            token,
            expires_at,
            qr_host,
            qr_channel,
            deep_link,
            image_id,
            instance: QrInstanceInfo {
                id: row.id,
                name: row.name,
                container: row.container,
                claw_type: row.claw_type,
            },
        }),
    )
        .into_response())
}

/// `GET /api/v1/mobile/qr-status/{token}`
///
/// Mobile-authenticated. Returns 200 while the continue-QR token is still
/// active (not yet consumed, not expired), 410 Gone once it's been consumed
/// or expired, 403 if the caller isn't the token's owner.
///
/// Used by the macOS app to dismiss the QR popover automatically when the
/// phone scans successfully. Peek (not redeem) — does not invalidate the token.
///
/// # Errors
///
/// - 403 token belongs to another user
/// - 410 token consumed or expired
#[tracing::instrument(skip(state), fields(token_hint = %token.chars().take(8).collect::<String>()))]
pub async fn handle_continue_qr_status(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(token): Path<String>,
) -> Result<Response, ApiError> {
    match state.mobile_tokens.peek_qr_token(&token) {
        Some(entry) if entry.username == auth.username => Ok(StatusCode::OK.into_response()),
        Some(_) => Err(ApiError::forbidden("token belongs to another user")),
        None => Ok(StatusCode::GONE.into_response()),
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Extract and validate the mobile Bearer token from the `Authorization` header.
fn extract_mobile_bearer(
    state: &SharedState,
    headers: &axum::http::HeaderMap,
) -> Result<String, ApiError> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing Authorization header"))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::unauthorized("invalid Authorization header format"))?;

    state
        .mobile_sessions
        .validate_session(token)
        .ok_or_else(|| ApiError::unauthorized("invalid or expired session token"))
}

/// Resolve a mobile bearer username into an `AuthUser` by looking up the users table.
async fn resolve_mobile_auth_user(
    state: &SharedState,
    username: &str,
) -> Result<AuthUser, ApiError> {
    let st = state.clone();
    let uname = username.to_string();
    let user = blocking(move || {
        st.instance_db
            .get_user_by_username(&uname)
            .map_err(ApiError::from)
    })
    .await??
    .ok_or_else(|| ApiError::unauthorized("user not found"))?;
    Ok(AuthUser {
        user_id: user.id,
        username: user.username,
        role: user.role,
    })
}

/// Build the mobile instance list from the database, scoped by user role.
/// Admin users see all active instances; regular users see only their owned instances.
async fn build_instance_list(
    state: &SharedState,
    username: &str,
) -> Result<Vec<MobileInstanceInfo>, ApiError> {
    let st = state.clone();
    let uname = username.to_string();
    let (rows, user) = blocking(move || {
        let rows = st.instance_db.list().map_err(ApiError::from)?;
        let user = st
            .instance_db
            .get_user_by_username(&uname)
            .map_err(ApiError::from)?;
        Ok::<_, ApiError>((rows, user))
    })
    .await??;

    let user = user.ok_or_else(|| {
        tracing::warn!("[mobile] user '{}' not found in users table", username);
        ApiError::unauthorized("user not found")
    })?;
    let is_admin = user.role == store_rs::UserRole::Admin;
    let user_id = Some(user.id.as_str());

    Ok(rows
        .into_iter()
        .filter(|r| {
            matches!(
                r.status,
                store_rs::InstanceStatus::Active
                    | store_rs::InstanceStatus::Stopped
                    | store_rs::InstanceStatus::Provisioning
            )
        })
        .filter(|r| is_admin || r.owner_id.as_deref() == user_id)
        .map(|row| {
            let capabilities = capabilities_for(&row.claw_type);
            // On macOS, read the VM IP so the mobile app can reach the instance
            let host = if cfg!(target_os = "macos") {
                let home = std::env::var("HOME").unwrap_or_default();
                let ip_path = std::path::PathBuf::from(&home)
                    .join("Library/Application Support/theyos/vms")
                    .join(&row.container)
                    .join("vm_ip");
                std::fs::read_to_string(ip_path)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            };
            // Provisioning metadata: only meaningful while the instance is
            // still being created. Once terminal, we drop these so the
            // mobile list stays clean.
            let is_provisioning = matches!(row.status, store_rs::InstanceStatus::Provisioning);
            MobileInstanceInfo {
                id: row.id,
                name: row.name,
                container: row.container,
                claw_type: row.claw_type,
                status: row.status.to_string(),
                host,
                capabilities,
                provisioning_message: if is_provisioning {
                    row.provisioning_message
                } else {
                    None
                },
                provisioning_phase: if is_provisioning {
                    row.provisioning_phase
                } else {
                    None
                },
                provisioning_error: if is_provisioning {
                    row.provisioning_error
                } else {
                    None
                },
                provisioning_failure_code: row.provisioning_failure_code,
            }
        })
        .collect())
}

// ─── Server pairing (US-4) ──────────────────────────────────────────────────

/// Optional JSON body for `POST /api/v1/mobile/pair-token`.
#[derive(Deserialize, Default)]
pub struct PairTokenRequest {
    /// Custom token TTL in seconds. Defaults to 15 minutes if absent.
    pub ttl_secs: Option<u64>,
}

/// Maximum allowed pair-token TTL: 30 days.
const MAX_PAIR_TTL_SECS: u64 = 30 * 24 * 3600;

/// Default pair-token TTL: 15 minutes.
const DEFAULT_PAIR_TTL_SECS: u64 = 15 * 60;

/// POST /api/v1/mobile/pair-token — generate a server-level pairing token.
///
/// Admin-authed. Returns a deep link for the mobile app to scan.
/// Accepts an optional JSON body with `ttl_secs` to set a custom token lifetime.
///
/// # Errors
///
/// Returns `ApiError` if token generation fails.
#[tracing::instrument(skip(state, body))]
pub async fn handle_pair_token(
    State(state): State<SharedState>,
    AdminUser(auth): AdminUser,
    body: Option<Json<PairTokenRequest>>,
) -> Result<Response, ApiError> {
    let ttl_secs = body
        .and_then(|b| b.ttl_secs)
        .unwrap_or(DEFAULT_PAIR_TTL_SECS);

    if ttl_secs == 0 || ttl_secs > MAX_PAIR_TTL_SECS {
        return Err(ApiError::bad_request(format!(
            "ttl_secs must be between 1 and {MAX_PAIR_TTL_SECS}"
        )));
    }

    let ttl = std::time::Duration::from_secs(ttl_secs);

    let (host, channel) = best_qr_host();
    let (token, expires_at) =
        state
            .mobile_tokens
            .create_qr_token_with_ttl("__server_pair__", &auth.username, ttl);

    let server_name = std::env::var("THEYOS_SERVER_NAME").unwrap_or_else(|_| "theyos".to_string());
    let platform = server_platform();

    let deep_link = mobile_deep_link(
        "pair",
        &[
            ("token", &token),
            ("host", &host),
            ("name", &server_name),
            ("platform", platform),
        ],
    );

    // Store a QR image link so the PNG endpoint can render it.
    let image_id = state
        .mobile_tokens
        .store_image_link_with_ttl(&deep_link, ttl);

    tracing::info!(
        "[mobile] user={} generated pair token (channel={channel}, ttl={ttl_secs}s)",
        auth.username
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "token": token,
            "expires_at": expires_at,
            "deep_link": deep_link,
            "host": host,
            "channel": channel,
            "server_name": server_name,
            "server_platform": platform,
            "image_id": image_id,
        })),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct PairRequest {
    pub token: String,
}

/// POST /api/v1/mobile/pair — exchange a pairing token for a mobile session.
///
/// Public endpoint (no auth required). The pairing token is single-use.
///
/// # Errors
///
/// Returns `ApiError` if the token is invalid, expired, or already used.
#[tracing::instrument(skip(state, req))]
pub async fn handle_pair(
    State(state): State<SharedState>,
    Json(req): Json<PairRequest>,
) -> Result<Response, ApiError> {
    let token = req.token.trim().to_string();
    if token.is_empty() {
        return Err(ApiError::bad_request("token is required"));
    }

    // Redeem the pairing token (single-use, 15-min expiry)
    // Server-pair tokens never carry a workspace_id.
    let (instance_id, username, _workspace_id) = state
        .mobile_tokens
        .redeem_qr_token(&token)
        .ok_or_else(|| ApiError::unauthorized("invalid or expired pairing token"))?;

    // Verify it's a server-level pair token
    if instance_id != "__server_pair__" {
        return Err(ApiError::bad_request("not a server pairing token"));
    }

    // Create a persistent mobile session
    let (session_token, expires_at) = state
        .mobile_sessions
        .create_session(&username)
        .map_err(|e| ApiError::internal(format!("create_session: {e}")))?;

    let (host, _channel) = best_qr_host();
    let server_name = std::env::var("THEYOS_SERVER_NAME").unwrap_or_else(|_| "theyos".to_string());
    let platform = server_platform();

    tracing::info!("[mobile] server paired by user={username}");

    Ok((
        StatusCode::OK,
        Json(json!({
            "session_token": session_token,
            "expires_at": expires_at,
            "server": {
                "name": server_name,
                "host": host,
                "platform": platform,
            }
        })),
    )
        .into_response())
}

// ─── QR code PNG endpoint ────────────────────────────────────────────────────

/// `GET /qr/{image_id}`
///
/// Public endpoint (no auth — the image ID is the secret). Returns a QR code
/// as a PNG image for the given image ID. The image ID is returned by
/// `POST /api/v1/mobile/pair-token` alongside the deep link.
///
/// # Errors
///
/// Returns 404 if the image ID is invalid or expired, or 500 on encoding failure.
pub async fn handle_pair_qr_image(
    State(state): State<SharedState>,
    Path(image_id): Path<String>,
) -> Result<Response, ApiError> {
    let deep_link = state
        .mobile_tokens
        .get_image_link(&image_id)
        .ok_or_else(|| ApiError::not_found("QR code not found or expired"))?;

    // QR generation + PNG encoding is CPU-bound — run off the async executor.
    let png_bytes = blocking(move || {
        let code =
            qrcode::QrCode::with_error_correction_level(deep_link.as_bytes(), qrcode::EcLevel::M)
                .map_err(|e| ApiError::internal(format!("QR generation failed: {e}")))?;

        let img = code
            .render::<image::Luma<u8>>()
            .quiet_zone(true)
            .module_dimensions(10, 10)
            .build();

        let mut buf = Vec::new();
        image::DynamicImage::ImageLuma8(img)
            .write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
            .map_err(|e| ApiError::internal(format!("PNG encoding failed: {e}")))?;

        Ok::<_, ApiError>(buf)
    })
    .await??;

    Ok((
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "image/png"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        png_bytes,
    )
        .into_response())
}

// ─── New mobile endpoints ────────────────────────────────────────────────────

/// GET /api/v1/mobile/users — list all users (admin-only).
///
/// # Errors
///
/// Returns `ApiError` if the session is invalid, user is not admin, or DB fails.
pub async fn handle_mobile_users(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;
    require_mobile_admin(&state, &username).await?;

    users_response(state).await
}

/// GET /api/v1/users — list all users (admin-session only).
///
/// # Errors
///
/// Returns `ApiError` if the session is invalid, user is not admin, or DB fails.
pub async fn handle_admin_users(
    State(state): State<SharedState>,
    AdminUser(_auth): AdminUser,
) -> Result<Response, ApiError> {
    users_response(state).await
}

async fn require_mobile_admin(state: &SharedState, username: &str) -> Result<(), ApiError> {
    let user = {
        let st = state.clone();
        let uname = username.to_string();
        blocking(move || {
            st.instance_db
                .get_user_by_username(&uname)
                .map_err(ApiError::from)
        })
        .await??
    };
    match user {
        Some(u) if u.role == store_rs::UserRole::Admin => {}
        _ => return Err(ApiError::forbidden("admin access required")),
    }

    Ok(())
}

async fn users_response(state: SharedState) -> Result<Response, ApiError> {
    let users = {
        let st = state.clone();
        blocking(move || st.instance_db.list_users().map_err(ApiError::from)).await??
    };

    let items: Vec<serde_json::Value> = users
        .into_iter()
        .map(|u| {
            json!({
                "id": u.id,
                "username": u.username,
                "role": u.role.to_string(),
            })
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(json!({ "data": items, "has_more": false, "next_cursor": null })),
    )
        .into_response())
}

/// GET /api/v1/mobile/server-info — server metadata for the mobile app.
///
/// # Errors
///
/// Returns `ApiError` if the session is invalid or version cache is poisoned.
#[allow(clippy::unused_async)]
pub async fn handle_mobile_server_info(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let _username = extract_mobile_bearer(&state, &headers)?;

    let server_name = std::env::var("THEYOS_SERVER_NAME").unwrap_or_else(|_| "theyos".to_string());

    let cache = state
        .ver_cache
        .read()
        .map_err(|e| ApiError::internal(format!("ver_cache: {e}")))?;
    let version = if cache.version.is_empty() {
        "unknown".to_string()
    } else {
        cache.version.clone()
    };

    let (host, _channel) = best_qr_host();
    let access_mode = std::env::var("THEYOS_ACCESS_MODE").unwrap_or_else(|_| "local".to_string());
    let platform = server_platform();

    Ok((
        StatusCode::OK,
        Json(json!({
            "name": server_name,
            "version": version,
            "host": host,
            "access_mode": access_mode,
            "platform": platform,
        })),
    )
        .into_response())
}

/// GET /api/v1/mobile/resource-options — available resource ranges (admin-only).
///
/// # Errors
///
/// Returns `ApiError` if the session is invalid or user is not admin.
pub async fn handle_resource_options(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;
    require_mobile_admin(&state, &username).await?;

    Ok(resource_options_response(&state))
}

/// GET /api/v1/resource-options — available resource ranges (admin-session only).
///
/// # Errors
///
/// Returns `ApiError` if the session is invalid, user is not admin, or capacity
/// projection fails.
pub async fn handle_admin_resource_options(
    State(state): State<SharedState>,
    AdminUser(_auth): AdminUser,
) -> Result<Response, ApiError> {
    Ok(resource_options_response(&state))
}

fn resource_options_response(state: &SharedState) -> Response {
    // Compute capacity projection (single source of truth, includes warm pool)
    let disk_path = core_rs::host_resources::resolve_instance_disk_path();
    let host = core_rs::host_resources::detect_all(&disk_path).ok();

    let (cpu_max, ram_max, disk_max) = if let Some(ref h) = host {
        if let Ok(proj) = crate::capacity::compute_capacity_projection(&state.instance_db, h) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let cpu = proj.available_cpu.max(0) as u32;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let ram = proj.available_ram.max(0) as u32;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let disk = proj.available_disk.max(0) as u32;
            (cpu, ram, disk)
        } else {
            // Fallback: use host limits directly
            let reserve = crate::capacity::cpu_reserve();
            let pct = crate::capacity::ram_budget_percent();
            #[allow(clippy::cast_possible_truncation)]
            let cpu = h.cpu_cores.saturating_sub(reserve);
            #[allow(clippy::cast_possible_truncation)]
            let ram = ((h.total_ram_mb * pct) / 100) as u32;
            #[allow(clippy::cast_possible_truncation)]
            let disk = h.available_disk_gb as u32;
            (cpu, ram, disk)
        }
    } else {
        // No host detection available — return generous defaults
        (8, 16384, 100)
    };

    let options = match build_resource_options_response(
        cpu_max,
        ram_max,
        disk_max,
        cfg!(target_os = "macos"),
    ) {
        Ok(options) => options,
        Err(cap_err) => return resource_options_capacity_response(&cap_err),
    };

    (StatusCode::OK, Json(options)).into_response()
}

// ─── Create Instance (mobile) ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct MobileCreateInstanceReq {
    name: String,
    #[serde(default)]
    claw_type: String,
    #[serde(default)]
    guest_os: String,
    #[serde(default)]
    cpu_cores: Option<u32>,
    #[serde(default)]
    ram_mb: Option<u32>,
    #[serde(default)]
    disk_gb: Option<u32>,
    #[serde(default)]
    owner_id: Option<String>,
}

/// POST /api/v1/mobile/instances — create a new instance (admin-only).
///
/// Mobile-specific: validates resources and returns a flat `snake_case` response
/// suitable for the iOS client.
///
/// # Errors
///
/// Returns `ApiError` on validation failure, rate limiting, name conflict,
/// or database/blocking-task errors.
#[allow(clippy::too_many_lines)]
#[allow(clippy::similar_names)]
#[tracing::instrument(skip(state, req, headers))]
pub async fn handle_mobile_create_instance(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MobileCreateInstanceReq>,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;

    // Admin check
    let user = {
        let st = state.clone();
        let uname = username.clone();
        blocking(move || {
            st.instance_db
                .get_user_by_username(&uname)
                .map_err(ApiError::from)
        })
        .await??
    };
    match user {
        Some(u) if u.role == store_rs::UserRole::Admin => {}
        _ => return Err(ApiError::forbidden("admin access required")),
    }

    create_mobile_instance_for_actor(state, username, req, None).await
}

/// Shared mobile-shaped create-instance implementation.
///
/// The normal `/api/v1/mobile/instances` handler performs bearer-token
/// authentication and admin lookup before calling this. Household `PoP` routes
/// call it after owner-key authorization and pass the owner person id as the
/// actor. Response shape intentionally stays flat `snake_case` for iOS.
pub(crate) async fn create_mobile_instance_for_actor(
    state: SharedState,
    username: String,
    req: MobileCreateInstanceReq,
    household_scope: Option<crate::instance_create::HouseholdInstanceScope>,
) -> Result<Response, ApiError> {
    let inputs = crate::instance_create::CreateInstanceInputs {
        name: req.name,
        claw_type: req.claw_type,
        guest_os: req.guest_os,
        cpu_cores: req.cpu_cores,
        ram_mb: req.ram_mb,
        disk_gb: req.disk_gb,
        owner_id: req.owner_id,
        tools: crate::instance_create::CreateTools::Validated(
            crate::instance_create::default_mobile_tools(),
        ),
    };

    match crate::instance_create::create_instance_core(
        &state,
        &username,
        inputs,
        household_scope.as_ref(),
        crate::instance_create::RateLimitResponseStyle::Bare,
        "[mobile]",
    )
    .await?
    {
        crate::instance_create::CreateOutcome::EarlyResponse(resp) => Ok(resp),
        // Mobile / household keep their FLAT body.
        crate::instance_create::CreateOutcome::Created(facts) => Ok((
            StatusCode::ACCEPTED,
            Json(json!({
                "id":        facts.instance_id,
                "name":      facts.name,
                "container": facts.container,
                "claw_type": facts.claw_type,
                "status":    "provisioning",
                "job_id":    facts.job_id,
            })),
        )
            .into_response()),
    }
}
/// GET /api/v1/mobile/instances/{id}/status — mobile-friendly provisioning status.
///
/// Returns a flat `snake_case` JSON response suitable for iOS `JSONDecoder` (no
/// `keyDecodingStrategy`). Includes the new `provisioning_phase` field for
/// Live Activity phase transitions.
///
/// # Errors
///
/// Returns `ApiError` if the session is invalid or the instance is not found.
pub async fn handle_mobile_instance_status(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;
    let auth = resolve_mobile_auth_user(&state, &username).await?;
    let row = require_instance(&state, &auth, &id).await?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": row.status.to_string(),
            "provisioning_message": row.provisioning_message,
            "provisioning_error": row.provisioning_error,
            "provisioning_failure_code": row.provisioning_failure_code,
            "provisioning_phase": row.provisioning_phase,
        })),
    )
        .into_response())
}

/// GET /api/v1/mobile/claws — claw catalog for the mobile app.
///
/// Each item includes legacy fields (`status`, `installed_at`, `job_id`,
/// `error`) **and** a new `availability` field carrying the full
/// `core_rs::availability::ClawAvailability` projection. The iOS client
/// (`ClawModels.swift`) ignores unknown keys, so adding `availability`
/// is a fully backward-compatible extension.
///
/// Use `GET /api/v1/mobile/claws/{name}/availability` for efficient
/// single-claw polling during install (cheaper than re-listing the
/// whole catalog).
///
/// # Errors
///
/// Returns `ApiError` if the session is invalid.
#[allow(clippy::unused_async)]
pub async fn handle_mobile_claws(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Query(q): Query<ClawsQuery>,
) -> Result<Json<ListResponse<ClawListItemResponse>>, ApiError> {
    let _username = extract_mobile_bearer(&state, &headers)?;
    let verify_path = state.theyos_dir.join("claws/verify-results.json");
    let items = state
        .claw_store
        .catalog_with_status_merged(Some(&verify_path));

    // P-46 Fase F: optional `?tier=supported|available|detected|catalog` filter.
    // Unknown or empty values become "no filter" so older servers don't break.
    let tier_filter = q
        .tier
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| match s {
            "catalog" | "detected" | "available" | "supported" => Some(s.to_string()),
            _ => None,
        });

    // Share one host probe across all claws in the list.
    let availabilities = crate::availability::project_all_claws(&state);
    Ok(Json(claw_list_response(
        items,
        availabilities,
        tier_filter.as_deref(),
    )))
}

/// GET /api/v1/mobile/claws/{name}/availability — full availability projection
/// for a single claw.
///
/// Authoritative endpoint for answering "can this claw be created right
/// now?". Preferred over `GET /api/v1/mobile/claws/{name}` for install
/// progress polling: much cheaper than re-listing the whole catalog.
///
/// Returns the projection even for unknown names — the response will have
/// `overall.state == "unknown"`.
///
/// # Errors
///
/// Returns `ApiError` if the session is invalid.
#[allow(clippy::unused_async)]
pub async fn handle_mobile_claw_availability(
    State(state): State<SharedState>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<ClawAvailability>, ApiError> {
    let _username = extract_mobile_bearer(&state, &headers)?;
    let avail = crate::availability::project_claw(&name, &state);
    Ok(Json(avail))
}

/// POST /api/v1/mobile/claws/{name}/install — trigger claw install (admin-only).
///
/// # Errors
///
/// Returns `ApiError` on auth failure, 404 if unknown claw, 400 if not buildable
/// or already installed, 409 if install already in progress.
pub async fn handle_mobile_install_claw(
    State(state): State<SharedState>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;

    // Admin check
    let user = {
        let st = state.clone();
        blocking(move || {
            st.instance_db
                .get_user_by_username(&username)
                .map_err(ApiError::from)
        })
        .await??
    };
    match user {
        Some(u) if u.role == store_rs::UserRole::Admin => {}
        _ => return Err(ApiError::forbidden("admin access required")),
    }

    let outcome = claw_store_service::install_claw(&state, name).await?;
    let status = if outcome.is_already_installing() {
        StatusCode::CONFLICT
    } else {
        StatusCode::OK
    };
    Ok((status, Json(outcome.into_job_response())).into_response())
}

/// POST /api/v1/mobile/claws/{name}/uninstall — trigger claw uninstall (admin-only).
///
/// # Errors
///
/// Returns `ApiError` on auth failure, 404 if unknown claw, 400 if not installed
/// or instances still exist.
pub async fn handle_mobile_uninstall_claw(
    State(state): State<SharedState>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;

    // Admin check
    let user = {
        let st = state.clone();
        blocking(move || {
            st.instance_db
                .get_user_by_username(&username)
                .map_err(ApiError::from)
        })
        .await??
    };
    match user {
        Some(u) if u.role == store_rs::UserRole::Admin => {}
        _ => return Err(ApiError::forbidden("admin access required")),
    }

    Ok((
        StatusCode::OK,
        Json(
            claw_store_service::uninstall_claw(&state, name)
                .await?
                .into_job_response(),
        ),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_rs::network_detect::{CaddyStatus, ChannelStatus, NetworkStatus};

    fn make_channel(channel_type: &str, detected: bool) -> ChannelStatus {
        ChannelStatus {
            channel_type: channel_type.to_string(),
            configured: detected,
            detected,
            ip: None,
            hostname: None,
            has_dns: None,
            has_https: None,
            has_cert: None,
            has_serve: None,
            urls: Vec::new(),
            status_detail: None,
        }
    }

    fn make_caddy(running: bool) -> CaddyStatus {
        CaddyStatus {
            installed: running,
            running,
            admin_url: "http://localhost:2019".to_string(),
            status_detail: None,
        }
    }

    fn make_status(channels: Vec<ChannelStatus>, caddy: CaddyStatus) -> NetworkStatus {
        NetworkStatus { channels, caddy }
    }

    #[test]
    fn mobile_deep_link_percent_encodes_query_values() {
        let link = mobile_deep_link(
            "pair",
            &[
                ("token", "token-123"),
                ("host", "https://linux.example.test"),
                ("name", "theyOS Linux"),
            ],
        );

        assert_eq!(
            link,
            "theyos://pair?token=token-123&host=https%3A%2F%2Flinux.example.test&name=theyOS%20Linux"
        );
    }

    #[test]
    fn tailscale_with_serve_returns_https() {
        let mut ts = make_channel("tailscale", true);
        ts.hostname = Some("myhost.tail1234.ts.net".to_string());
        ts.has_https = Some(true); // effective: has_serve active

        let local = make_channel("local", true);
        let status = make_status(vec![local, ts], make_caddy(false));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "https://myhost.tail1234.ts.net");
        assert_eq!(channel, "tailscale");
    }

    #[test]
    fn tailscale_with_caddy_running_returns_https() {
        let mut ts = make_channel("tailscale", true);
        ts.hostname = Some("myhost.tail1234.ts.net".to_string());
        // Simulates post-processing in detect_network_status():
        // Caddy running → has_https upgraded to true
        ts.has_https = Some(true);

        let local = make_channel("local", true);
        let status = make_status(vec![local, ts], make_caddy(true));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "https://myhost.tail1234.ts.net");
        assert_eq!(channel, "tailscale");
    }

    #[test]
    fn tailscale_without_https_prefers_ip_with_port() {
        let mut ts = make_channel("tailscale", true);
        ts.hostname = Some("myhost.tail1234.ts.net".to_string());
        ts.ip = Some("100.64.0.5".to_string());
        ts.has_https = Some(false);

        let mut local = make_channel("local", true);
        local.urls = vec!["http://localhost:9000".to_string()];
        let status = make_status(vec![local, ts], make_caddy(false));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "http://100.64.0.5:9000");
        assert_eq!(channel, "tailscale");
    }

    #[test]
    fn tailscale_without_https_falls_back_to_hostname_when_ip_missing() {
        let mut ts = make_channel("tailscale", true);
        ts.hostname = Some("myhost.tail1234.ts.net".to_string());
        ts.has_https = Some(false);

        let mut local = make_channel("local", true);
        local.urls = vec!["http://localhost:9000".to_string()];
        let status = make_status(vec![local, ts], make_caddy(false));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "http://myhost.tail1234.ts.net:9000");
        assert_eq!(channel, "tailscale");
    }

    #[test]
    fn tailscale_ip_only_returns_http_with_port() {
        let mut ts = make_channel("tailscale", true);
        ts.ip = Some("100.64.0.5".to_string());

        let local = make_channel("local", true);
        let status = make_status(vec![local, ts], make_caddy(false));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "http://100.64.0.5:8892");
        assert_eq!(channel, "tailscale");
    }

    #[test]
    fn lan_returns_ip_with_port() {
        let mut lan = make_channel("lan", true);
        lan.ip = Some("192.168.1.10".to_string());

        let local = make_channel("local", true);
        let status = make_status(vec![local, lan], make_caddy(false));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "192.168.1.10:8892");
        assert_eq!(channel, "lan");
    }

    #[test]
    fn fallback_returns_localhost() {
        let local = make_channel("local", true);
        let status = make_status(vec![local], make_caddy(false));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "localhost:8892");
        assert_eq!(channel, "local");
    }

    #[test]
    fn cloudflare_takes_priority_over_tailscale() {
        let mut cf = make_channel("cloudflare", true);
        cf.hostname = Some("admin.example.com".to_string());

        let mut ts = make_channel("tailscale", true);
        ts.hostname = Some("myhost.tail1234.ts.net".to_string());
        ts.has_https = Some(true);

        let local = make_channel("local", true);
        let status = make_status(vec![local, cf, ts], make_caddy(false));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "admin.example.com");
        assert_eq!(channel, "cloudflare");
    }

    #[test]
    fn custom_port_from_local_channel() {
        let mut ts = make_channel("tailscale", true);
        ts.hostname = Some("myhost.tail1234.ts.net".to_string());
        ts.ip = Some("100.64.0.5".to_string());
        ts.has_https = Some(false);

        let mut local = make_channel("local", true);
        local.urls = vec!["http://localhost:7777".to_string()];

        let status = make_status(vec![local, ts], make_caddy(false));

        let (host, _) = best_qr_host_from_status(&status);
        assert_eq!(host, "http://100.64.0.5:7777");
    }

    #[test]
    fn resource_options_clamp_defaults_to_available_max() {
        let response = build_resource_options_response(1, 1024, 7, true).unwrap();

        assert_eq!(
            response,
            ResourceOptionsResponse {
                cpu_cores: ResourceOptionRange {
                    min: 1,
                    max: 1,
                    default: 1,
                    disabled: None,
                },
                ram_mb: ResourceOptionRange {
                    min: 512,
                    max: 1024,
                    default: 1024,
                    disabled: None,
                },
                disk_gb: ResourceOptionRange {
                    min: 5,
                    max: 7,
                    default: 7,
                    disabled: Some(true),
                },
            }
        );
    }

    #[test]
    fn resource_options_fail_when_available_is_below_minimum() {
        let err = build_resource_options_response(0, 4096, 20, false).unwrap_err();

        assert_eq!(
            err.message,
            "insufficient CPU: minimum supported is 1, but only 0 available"
        );
        assert_eq!(err.retry_after_secs, RESOURCE_OPTIONS_RETRY_AFTER_SECS);
    }

    #[test]
    fn mobile_claw_vpn_status_reports_not_configured_without_snapshot() {
        let td = tempfile::tempdir().unwrap();
        let store =
            household_rs::claw_vpn_mobile_mesh_store::ClawVpnMobileMeshStore::new(td.path(), 600)
                .unwrap();

        let response = mobile_claw_vpn_status_response(store.status().unwrap());

        assert_eq!(
            response,
            MobileClawVpnStatusResponse {
                product: "product_a_mobile_claw_vpn",
                mode: "mesh_c_status_only",
                production_activation: false,
                state: "not_configured",
                snapshot_present: false,
                enrolled_device_count: 0,
                available_claw_count: 0,
                grant_count: 0,
                offer_count: 0,
                session_count: 0,
            }
        );
    }

    #[test]
    fn mobile_claw_vpn_status_reports_count_only_configured_mesh() {
        let td = tempfile::tempdir().unwrap();
        let store =
            household_rs::claw_vpn_mobile_mesh_store::ClawVpnMobileMeshStore::new(td.path(), 600)
                .unwrap();
        let member =
            household_rs::claw_vpn_mobile_state::ClawVpnMobileMemberId::try_new("member-alpha")
                .unwrap();
        let device =
            household_rs::claw_vpn_mobile_state::ClawVpnMobileDeviceId::try_new("device-alpha")
                .unwrap();
        let claw = household_rs::claw_vpn_mobile_state::ClawVpnMobileClawId::try_new("claw-alpha")
            .unwrap();
        let grant = household_rs::claw_vpn_mobile_state::ClawVpnMobileAclGrant::new(
            member,
            device.clone(),
            claw.clone(),
        );

        assert!(store.owner_approved_enroll_device(device).unwrap());
        assert!(store.set_claw_available(claw).unwrap());
        assert!(store.owner_approved_grant(grant.clone()).unwrap());
        let offer_token = store.mint_offer_token(&grant, 100).unwrap();
        let _session = store
            .consume_offer_token(&offer_token, &grant, 101)
            .unwrap();

        let response = mobile_claw_vpn_status_response(store.status().unwrap());

        assert_eq!(
            response,
            MobileClawVpnStatusResponse {
                product: "product_a_mobile_claw_vpn",
                mode: "mesh_c_status_only",
                production_activation: false,
                state: "configured",
                snapshot_present: true,
                enrolled_device_count: 1,
                available_claw_count: 1,
                grant_count: 1,
                offer_count: 1,
                session_count: 1,
            }
        );
    }

    #[test]
    fn mobile_claw_vpn_rendezvous_dial_preflight_builds_guest_hello_after_revalidation() {
        let td = tempfile::tempdir().unwrap();
        let store =
            household_rs::claw_vpn_mobile_mesh_store::ClawVpnMobileMeshStore::new(td.path(), 600)
                .unwrap();
        let member =
            household_rs::claw_vpn_mobile_state::ClawVpnMobileMemberId::try_new("member-alpha")
                .unwrap();
        let device =
            household_rs::claw_vpn_mobile_state::ClawVpnMobileDeviceId::try_new("device-alpha")
                .unwrap();
        let claw = household_rs::claw_vpn_mobile_state::ClawVpnMobileClawId::try_new("claw-alpha")
            .unwrap();
        let grant = household_rs::claw_vpn_mobile_state::ClawVpnMobileAclGrant::new(
            member,
            device.clone(),
            claw.clone(),
        );

        assert!(store.owner_approved_enroll_device(device).unwrap());
        assert!(store.set_claw_available(claw).unwrap());
        assert!(store.owner_approved_grant(grant.clone()).unwrap());
        let offer_token = store.mint_offer_token(&grant, 100).unwrap();
        let rendezvous_token = store
            .consume_offer_token(&offer_token, &grant, 101)
            .unwrap();

        let preflight =
            mobile_claw_vpn_rendezvous_dial_preflight(&store, &rendezvous_token, &grant).unwrap();
        let decoded = RendezvousHello::decode(&preflight.into_hello_bytes()).unwrap();

        assert_eq!(decoded.role, RendezvousRole::Guest);
        assert_eq!(decoded.token, rendezvous_token.relay_token().unwrap());
    }
}
