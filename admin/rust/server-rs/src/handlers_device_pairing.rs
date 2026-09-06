//! Delegated household device-pairing request/poll endpoints.
//!
//! A device without an owner session may create a short-lived pending
//! request. That request only appends an owner-event and stores public
//! metadata plus a poll token. Certificate issuance still requires the
//! existing owner `PoP` approval endpoint.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::{
    caveats::Operation,
    cbor,
    household_lifecycle::{HouseholdLifecycleLock, LifecycleReadGuard},
    keys::P256PublicKey,
    owner_events::{DevicePairRequestPayload, OwnerEventPayload, OwnerEventType},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::json;

use crate::pairing_device_certificate::VerifiedPairingDeviceCertificate;

use crate::{handlers_owner_events::OwnerEventsRouterState, household_auth, time_util};

const DEVICE_PAIRING_TTL_SECS: u64 = 300;
const DEVICE_PAIRING_MAX_PENDING: usize = 32;
const DEVICE_PAIRING_ID_BYTES: usize = 16;
const DEVICE_PAIRING_TOKEN_BYTES: usize = 32;
const DEVICE_NAME_MAX_CHARS: usize = 64;
const MAX_APPROVED_CERT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct DevicePairingStore {
    inner: Arc<Mutex<DevicePairingStoreInner>>,
}

#[derive(Debug, Default)]
struct DevicePairingStoreInner {
    records: HashMap<String, DevicePairingRecord>,
}

#[derive(Clone, Debug)]
struct DevicePairingRecord {
    request_id: String,
    token: String,
    d_pub: Vec<u8>,
    device_name: String,
    platform: String,
    expires_at: u64,
    status: DevicePairingStatus,
    approved: Option<ApprovedPairing>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DevicePairingStatus {
    Pending,
    Approved,
    Rejected,
}

impl DevicePairingStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug)]
struct ApprovedPairing {
    household_id: String,
    person_id: String,
    person_cert_cbor: Vec<u8>,
    device_cert_cbor: Vec<u8>,
    capabilities: Vec<String>,
}

#[derive(Debug)]
enum PendingInsert {
    Existing {
        request_id: String,
        token: String,
        expires_at: u64,
    },
    New {
        request_id: String,
        token: String,
        expires_at: u64,
    },
}

#[derive(Debug, PartialEq, Eq)]
enum DevicePairingStoreError {
    Full,
    NotFound,
    TokenMismatch,
    Expired,
    AlreadyFinalized,
    CertificateMismatch,
}

impl Default for DevicePairingStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(DevicePairingStoreInner::default())),
        }
    }
}

impl DevicePairingStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn create_or_dedupe_pending(
        &self,
        d_pub: Vec<u8>,
        device_name: String,
        platform: String,
        now: u64,
    ) -> Result<PendingInsert, DevicePairingStoreError> {
        let mut guard = self.lock();
        cleanup_expired(&mut guard, now);

        if let Some(existing) = guard.records.values().find(|record| {
            record.status == DevicePairingStatus::Pending
                && record.d_pub == d_pub
                && record.expires_at > now
        }) {
            return Ok(PendingInsert::Existing {
                request_id: existing.request_id.clone(),
                token: existing.token.clone(),
                expires_at: existing.expires_at,
            });
        }

        if guard.records.len() >= DEVICE_PAIRING_MAX_PENDING {
            return Err(DevicePairingStoreError::Full);
        }

        let request_id = random_urlsafe(DEVICE_PAIRING_ID_BYTES);
        let token = random_urlsafe(DEVICE_PAIRING_TOKEN_BYTES);
        let expires_at = now.saturating_add(DEVICE_PAIRING_TTL_SECS);
        let record = DevicePairingRecord {
            request_id: request_id.clone(),
            token: token.clone(),
            d_pub,
            device_name,
            platform,
            expires_at,
            status: DevicePairingStatus::Pending,
            approved: None,
        };
        guard.records.insert(request_id.clone(), record);
        Ok(PendingInsert::New {
            request_id,
            token,
            expires_at,
        })
    }

    fn poll(
        &self,
        request_id: &str,
        token: &str,
        now: u64,
    ) -> Result<DevicePairingPollState, DevicePairingStoreError> {
        use subtle::ConstantTimeEq;
        let mut guard = self.lock();
        cleanup_expired(&mut guard, now);
        let Some(record) = guard.records.get(request_id) else {
            return Err(DevicePairingStoreError::NotFound);
        };
        // Constant-time token compare (defense-in-depth; matches the relay_stream crypto
        // posture). NotFound and TokenMismatch already collapse to one client error upstream.
        if !bool::from(record.token.as_bytes().ct_eq(token.as_bytes())) {
            return Err(DevicePairingStoreError::TokenMismatch);
        }
        if record.expires_at <= now {
            return Ok(DevicePairingPollState::Expired);
        }
        match record.status {
            DevicePairingStatus::Pending => Ok(DevicePairingPollState::Pending),
            DevicePairingStatus::Rejected => Ok(DevicePairingPollState::Rejected),
            DevicePairingStatus::Approved => record
                .approved
                .clone()
                .map(DevicePairingPollState::Approved)
                .ok_or(DevicePairingStoreError::NotFound),
        }
    }

    fn approve(
        &self,
        request_id: &str,
        certificate: VerifiedPairingDeviceCertificate,
        approved: ApprovedPairing,
        now: u64,
    ) -> Result<(), DevicePairingStoreError> {
        let mut guard = self.lock();
        cleanup_expired(&mut guard, now);
        let Some(record) = guard.records.get_mut(request_id) else {
            return Err(DevicePairingStoreError::NotFound);
        };
        if record.expires_at <= now {
            return Err(DevicePairingStoreError::Expired);
        }
        if record.status != DevicePairingStatus::Pending {
            return Err(DevicePairingStoreError::AlreadyFinalized);
        }
        // Bind the verified certificate under the same lock that finalizes
        // this request. A delayed approval cannot select a different device.
        if certificate.device_public_key != record.d_pub
            || certificate.device_name != record.device_name
            || certificate.platform != record.platform
        {
            return Err(DevicePairingStoreError::CertificateMismatch);
        }
        record.status = DevicePairingStatus::Approved;
        record.approved = Some(ApprovedPairing {
            device_cert_cbor: certificate.bytes,
            ..approved
        });
        Ok(())
    }

    fn reject(&self, request_id: &str, now: u64) -> Result<(), DevicePairingStoreError> {
        let mut guard = self.lock();
        cleanup_expired(&mut guard, now);
        let Some(record) = guard.records.get_mut(request_id) else {
            return Err(DevicePairingStoreError::NotFound);
        };
        if record.expires_at <= now {
            return Err(DevicePairingStoreError::Expired);
        }
        if record.status != DevicePairingStatus::Pending {
            return Err(DevicePairingStoreError::AlreadyFinalized);
        }
        record.status = DevicePairingStatus::Rejected;
        record.approved = None;
        Ok(())
    }

    fn list_owner_visible(&self, now: u64) -> Vec<DevicePairingRequestSummary> {
        let mut guard = self.lock();
        cleanup_expired(&mut guard, now);
        let mut requests = guard
            .records
            .values()
            .map(|record| DevicePairingRequestSummary {
                request_id: record.request_id.clone(),
                d_pub: B64URL.encode(&record.d_pub),
                device_name: record.device_name.clone(),
                platform: record.platform.clone(),
                expires_at: record.expires_at,
                status: record.status.as_str(),
            })
            .collect::<Vec<_>>();
        requests.sort_by(|a, b| {
            a.expires_at
                .cmp(&b.expires_at)
                .then_with(|| a.request_id.cmp(&b.request_id))
        });
        requests
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DevicePairingStoreInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Clone, Debug)]
enum DevicePairingPollState {
    Pending,
    Approved(ApprovedPairing),
    Rejected,
    Expired,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingRequestBody {
    #[serde(rename = "v")]
    version: u8,
    d_pub: String,
    device_name: String,
    platform: String,
}

#[derive(Serialize)]
struct DevicePairingRequestResponse {
    #[serde(rename = "v")]
    version: u8,
    request_id: String,
    token: String,
    expires_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingApproveBody {
    #[serde(rename = "v")]
    version: u8,
    request_id: String,
    device_cert_cbor: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingRejectBody {
    #[serde(rename = "v")]
    version: u8,
    request_id: String,
}

#[derive(Deserialize)]
pub struct DevicePairingPollQuery {
    token: String,
}

#[derive(Serialize)]
struct DevicePairingRequestSummary {
    request_id: String,
    d_pub: String,
    device_name: String,
    platform: String,
    expires_at: u64,
    status: &'static str,
}

#[derive(Serialize)]
struct DevicePairingRequestsResponse {
    #[serde(rename = "v")]
    version: u8,
    requests: Vec<DevicePairingRequestSummary>,
}

#[derive(Serialize)]
struct DevicePairingPollResponse {
    #[serde(rename = "v")]
    version: u8,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hh_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    person_cert_cbor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_cert_cbor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Option<Vec<String>>,
}

#[derive(Serialize)]
struct DevicePairingApproveResponse {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Serialize)]
struct DevicePairingRejectResponse {
    #[serde(rename = "v")]
    version: u8,
    request_id: String,
    status: &'static str,
}

fn cleanup_expired(inner: &mut DevicePairingStoreInner, now: u64) {
    inner.records.retain(|_, record| record.expires_at > now);
}

fn random_urlsafe(bytes: usize) -> String {
    let mut raw = vec![0u8; bytes];
    OsRng.fill_bytes(&mut raw);
    B64URL.encode(raw)
}

pub async fn device_pairing_request_handler(
    State(state): State<OwnerEventsRouterState>,
    Json(request): Json<DevicePairingRequestBody>,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("device_pairing.request.clock") else {
        return sanitized_error(StatusCode::SERVICE_UNAVAILABLE, "clock_unavailable");
    };
    let Ok(lifecycle_guard) = acquire_lifecycle_read(state.state_dir.clone()).await else {
        return sanitized_error(StatusCode::SERVICE_UNAVAILABLE, "household_unavailable");
    };
    let Some(identity) = state.household.current().await else {
        return sanitized_error(StatusCode::SERVICE_UNAVAILABLE, "household_unavailable");
    };
    let Err(code) = validate_request_version(request.version) else {
        return device_pairing_request_inner(&state, lifecycle_guard, identity, &request, now)
            .await;
    };
    sanitized_error(StatusCode::BAD_REQUEST, code)
}

async fn device_pairing_request_inner(
    state: &OwnerEventsRouterState,
    lifecycle_guard: LifecycleReadGuard,
    identity: Arc<household_rs::LoadedIdentity>,
    request: &DevicePairingRequestBody,
    now: u64,
) -> Response {
    let d_pub = match decode_public_key(&request.d_pub) {
        Ok(d_pub) => d_pub,
        Err(code) => return sanitized_error(StatusCode::BAD_REQUEST, code),
    };
    let device_name = match validate_device_name(&request.device_name) {
        Ok(name) => name,
        Err(code) => return sanitized_error(StatusCode::BAD_REQUEST, code),
    };
    let platform = match validate_platform(&request.platform) {
        Ok(platform) => platform,
        Err(code) => return sanitized_error(StatusCode::BAD_REQUEST, code),
    };

    let pending = match state.device_pairing_store.create_or_dedupe_pending(
        d_pub.as_bytes().to_vec(),
        device_name.clone(),
        platform.clone(),
        now,
    ) {
        Ok(pending) => pending,
        Err(DevicePairingStoreError::Full) => {
            return sanitized_error(
                StatusCode::TOO_MANY_REQUESTS,
                "device_pairing_request_limit",
            );
        }
        Err(_) => return sanitized_error(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    };

    let (request_id, token, expires_at, should_emit_event) = match pending {
        PendingInsert::Existing {
            request_id,
            token,
            expires_at,
        } => (request_id, token, expires_at, false),
        PendingInsert::New {
            request_id,
            token,
            expires_at,
        } => (request_id, token, expires_at, true),
    };

    if should_emit_event {
        let payload = OwnerEventPayload::DevicePairRequest(DevicePairRequestPayload {
            request_id: request_id.clone(),
            d_pub: ByteBuf::from(d_pub.as_bytes().to_vec()),
            device_name,
            platform,
            expiry: expires_at,
        });
        let event_log = Arc::clone(&state.event_log);
        let append_identity = Arc::clone(&identity);
        let append_result = tokio::task::spawn_blocking(move || {
            event_log.append(
                &lifecycle_guard,
                &append_identity.cert.m_id.to_string(),
                append_identity.m_priv.as_ref(),
                OwnerEventType::DevicePairRequest,
                payload,
            )
        })
        .await;
        if let Err(e) = append_result.unwrap_or_else(|join_error| {
            Err(household_rs::owner_events::EventError::Cbor(format!(
                "append worker failed: {join_error}"
            )))
        }) {
            tracing::warn!(
                stage = "device_pairing.request.rejected",
                reason = "owner_event_append_failed",
                error = %e,
            );
            return sanitized_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        }
    }

    Json(DevicePairingRequestResponse {
        version: 1,
        request_id,
        token,
        expires_at,
    })
    .into_response()
}

async fn acquire_lifecycle_read(state_dir: std::path::PathBuf) -> Result<LifecycleReadGuard, ()> {
    tokio::task::spawn_blocking(move || {
        let lifecycle = HouseholdLifecycleLock::open_verified(&state_dir).map_err(|_| ())?;
        lifecycle.lock_shared().map_err(|_| ())
    })
    .await
    .map_err(|_| ())?
}

pub async fn device_pairing_requests_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("device_pairing.requests.clock") else {
        return sanitized_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    if let Err(e) = household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        Operation::HouseholdAddMachine,
        now,
    )
    .await
    {
        tracing::warn!(
            stage = "device_pairing.requests.rejected",
            reason = "pop_auth_failed",
            error = %e,
        );
        return sanitized_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    }

    Json(DevicePairingRequestsResponse {
        version: 1,
        requests: state.device_pairing_store.list_owner_visible(now),
    })
    .into_response()
}

pub async fn device_pairing_poll_handler(
    State(state): State<OwnerEventsRouterState>,
    Path(request_id): Path<String>,
    Query(query): Query<DevicePairingPollQuery>,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("device_pairing.poll.clock") else {
        return sanitized_error(StatusCode::SERVICE_UNAVAILABLE, "clock_unavailable");
    };
    match state
        .device_pairing_store
        .poll(&request_id, &query.token, now)
    {
        Ok(DevicePairingPollState::Pending) => Json(DevicePairingPollResponse {
            version: 1,
            status: DevicePairingStatus::Pending.as_str(),
            hh_id: None,
            p_id: None,
            person_cert_cbor: None,
            device_cert_cbor: None,
            capabilities: None,
        })
        .into_response(),
        Ok(DevicePairingPollState::Rejected) => Json(DevicePairingPollResponse {
            version: 1,
            status: DevicePairingStatus::Rejected.as_str(),
            hh_id: None,
            p_id: None,
            person_cert_cbor: None,
            device_cert_cbor: None,
            capabilities: None,
        })
        .into_response(),
        Ok(DevicePairingPollState::Expired) => Json(DevicePairingPollResponse {
            version: 1,
            status: "expired",
            hh_id: None,
            p_id: None,
            person_cert_cbor: None,
            device_cert_cbor: None,
            capabilities: None,
        })
        .into_response(),
        Ok(DevicePairingPollState::Approved(approved)) => Json(DevicePairingPollResponse {
            version: 1,
            status: DevicePairingStatus::Approved.as_str(),
            hh_id: Some(approved.household_id),
            p_id: Some(approved.person_id),
            person_cert_cbor: Some(B64URL.encode(approved.person_cert_cbor)),
            device_cert_cbor: Some(B64URL.encode(approved.device_cert_cbor)),
            capabilities: Some(approved.capabilities),
        })
        .into_response(),
        Err(DevicePairingStoreError::NotFound | DevicePairingStoreError::TokenMismatch) => {
            sanitized_error(StatusCode::NOT_FOUND, "device_pairing_request_not_found")
        }
        Err(_) => sanitized_error(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

pub async fn device_pairing_reject_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("device_pairing.reject.clock") else {
        return sanitized_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    if let Err(e) = household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        Operation::HouseholdAddMachine,
        now,
    )
    .await
    {
        tracing::warn!(
            stage = "device_pairing.reject.rejected",
            reason = "pop_auth_failed",
            error = %e,
        );
        return sanitized_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    }

    let request: DevicePairingRejectBody = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return sanitized_error(StatusCode::BAD_REQUEST, "request_malformed"),
    };
    if request.version != 1 {
        return sanitized_error(StatusCode::BAD_REQUEST, "version_unsupported");
    }

    match state.device_pairing_store.reject(&request.request_id, now) {
        Ok(()) => Json(DevicePairingRejectResponse {
            version: 1,
            request_id: request.request_id,
            status: DevicePairingStatus::Rejected.as_str(),
        })
        .into_response(),
        Err(DevicePairingStoreError::NotFound) => {
            sanitized_error(StatusCode::NOT_FOUND, "device_pairing_request_not_found")
        }
        Err(DevicePairingStoreError::Expired) => {
            sanitized_error(StatusCode::GONE, "device_pairing_request_expired")
        }
        Err(DevicePairingStoreError::AlreadyFinalized) => {
            sanitized_error(StatusCode::CONFLICT, "device_pairing_request_finalized")
        }
        Err(_) => sanitized_error(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

pub async fn device_pairing_approve_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("device_pairing.approve.clock") else {
        return sanitized_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let owner_auth = match household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        Operation::HouseholdAddMachine,
        now,
    )
    .await
    {
        Ok(owner_auth) => owner_auth,
        Err(e) => {
            tracing::warn!(
                stage = "device_pairing.approve.rejected",
                reason = "pop_auth_failed",
                error = %e,
            );
            return sanitized_error(StatusCode::UNAUTHORIZED, "unauthenticated");
        }
    };
    let request: DevicePairingApproveBody = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return sanitized_error(StatusCode::BAD_REQUEST, "request_malformed"),
    };
    if request.version != 1 {
        return sanitized_error(StatusCode::BAD_REQUEST, "version_unsupported");
    }
    let device_cert_cbor = match B64URL.decode(request.device_cert_cbor.as_bytes()) {
        Ok(bytes) if !bytes.is_empty() && bytes.len() <= MAX_APPROVED_CERT_BYTES => bytes,
        _ => return sanitized_error(StatusCode::BAD_REQUEST, "device_cert_invalid"),
    };
    let certificate = match VerifiedPairingDeviceCertificate::verify(
        device_cert_cbor,
        &owner_auth.owner_person_cert,
        now,
    ) {
        Ok(certificate) => certificate,
        Err(()) => return sanitized_error(StatusCode::BAD_REQUEST, "device_cert_invalid"),
    };
    let person_cert_cbor = match cbor::to_canonical_vec(&owner_auth.owner_person_cert) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                stage = "device_pairing.approve.rejected",
                reason = "person_cert_encode_failed",
                error = %e,
            );
            return sanitized_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        }
    };
    let capabilities = owner_auth
        .owner_person_cert
        .caveats
        .iter()
        .map(|c| c.op.as_str().to_string())
        .collect::<Vec<_>>();
    let approved = ApprovedPairing {
        household_id: owner_auth.hh_id.to_string(),
        person_id: owner_auth.owner_person_cert.p_id.0.clone(),
        person_cert_cbor,
        device_cert_cbor: Vec::new(),
        capabilities,
    };
    match state
        .device_pairing_store
        .approve(&request.request_id, certificate, approved, now)
    {
        Ok(()) => Json(DevicePairingApproveResponse { version: 1 }).into_response(),
        Err(DevicePairingStoreError::NotFound) => {
            sanitized_error(StatusCode::NOT_FOUND, "device_pairing_request_not_found")
        }
        Err(DevicePairingStoreError::Expired) => {
            sanitized_error(StatusCode::GONE, "device_pairing_request_expired")
        }
        Err(DevicePairingStoreError::AlreadyFinalized) => {
            sanitized_error(StatusCode::CONFLICT, "device_pairing_request_finalized")
        }
        Err(DevicePairingStoreError::CertificateMismatch) => {
            sanitized_error(StatusCode::CONFLICT, "device_cert_request_mismatch")
        }
        Err(_) => sanitized_error(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

fn validate_request_version(version: u8) -> Result<(), &'static str> {
    if version == 1 {
        Ok(())
    } else {
        Err("version_unsupported")
    }
}

fn decode_public_key(encoded: &str) -> Result<P256PublicKey, &'static str> {
    let bytes = B64URL
        .decode(encoded.as_bytes())
        .map_err(|_| "device_public_key_invalid")?;
    P256PublicKey::from_bytes(&bytes).map_err(|_| "device_public_key_invalid")
}

fn validate_device_name(value: &str) -> Result<String, &'static str> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > DEVICE_NAME_MAX_CHARS
        || trimmed.chars().any(char::is_control)
    {
        return Err("device_name_invalid");
    }
    Ok(trimmed.to_string())
}

fn validate_platform(value: &str) -> Result<String, &'static str> {
    match value {
        "ios" | "ipados" => Ok(value.to_string()),
        _ => Err("platform_invalid"),
    }
}

fn sanitized_error(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        Json(json!({
            "v": 1,
            "error": code,
            "code": code,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovedPairing, DEVICE_PAIRING_MAX_PENDING, DEVICE_PAIRING_TTL_SECS, DevicePairingStore,
        DevicePairingStoreError, PendingInsert, decode_public_key, validate_device_name,
        validate_platform, validate_request_version,
    };

    use crate::pairing_device_certificate::VerifiedPairingDeviceCertificate;

    const NOW: u64 = 1_700_000_000;

    fn pubkey(seed: u8) -> Vec<u8> {
        // 65-byte uncompressed-style placeholder is rejected by the real
        // key parser, but the store only stores raw bytes, so any unique
        // opaque blob exercises the dedupe / identity logic here.
        let mut bytes = vec![0u8; 33];
        bytes[0] = 0x02;
        bytes[1] = seed;
        bytes
    }

    fn approved_fixture() -> ApprovedPairing {
        ApprovedPairing {
            household_id: "hh_test".to_string(),
            person_id: "p_test".to_string(),
            person_cert_cbor: vec![1, 2, 3],
            device_cert_cbor: Vec::new(),
            capabilities: vec!["household.add_machine".to_string()],
        }
    }

    #[test]
    fn create_returns_new_then_dedupes_same_device() {
        let store = DevicePairingStore::new();
        let first = store
            .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
            .expect("create");
        let (first_id, first_token) = match first {
            PendingInsert::New {
                request_id, token, ..
            } => (request_id, token),
            PendingInsert::Existing { .. } => panic!("first insert should be New"),
        };

        let second = store
            .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
            .expect("dedupe");
        match second {
            PendingInsert::Existing {
                request_id, token, ..
            } => {
                assert_eq!(request_id, first_id);
                assert_eq!(token, first_token);
            }
            PendingInsert::New { .. } => panic!("same device should dedupe to Existing"),
        }
    }

    #[test]
    fn distinct_devices_create_distinct_records() {
        let store = DevicePairingStore::new();
        let a = store
            .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
            .expect("create a");
        let b = store
            .create_or_dedupe_pending(pubkey(2), "beta".into(), "ios".into(), NOW)
            .expect("create b");
        let id_a = match a {
            PendingInsert::New { request_id, .. } => request_id,
            PendingInsert::Existing { .. } => panic!("a should be New"),
        };
        let id_b = match b {
            PendingInsert::New { request_id, .. } => request_id,
            PendingInsert::Existing { .. } => panic!("b should be New"),
        };
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn expired_pending_is_cleaned_up_and_not_deduped() {
        let store = DevicePairingStore::new();
        let first = store
            .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
            .expect("create");
        let first_id = match first {
            PendingInsert::New { request_id, .. } => request_id,
            PendingInsert::Existing { .. } => panic!("first should be New"),
        };

        // Advance past the TTL: the prior record must be cleaned up and a
        // fresh request minted instead of a dedupe.
        let later = NOW + DEVICE_PAIRING_TTL_SECS + 1;
        let second = store
            .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), later)
            .expect("create after expiry");
        let second_id = match second {
            PendingInsert::New { request_id, .. } => request_id,
            PendingInsert::Existing { .. } => panic!("expired record must not dedupe"),
        };
        assert_ne!(first_id, second_id);
    }

    #[test]
    fn max_pending_returns_full() {
        let store = DevicePairingStore::new();
        for i in 0..DEVICE_PAIRING_MAX_PENDING {
            store
                .create_or_dedupe_pending(
                    pubkey(u8::try_from(i).expect("seed fits in u8")),
                    format!("dev-{i}"),
                    "ios".into(),
                    NOW,
                )
                .expect("fill capacity");
        }
        let overflow =
            store.create_or_dedupe_pending(pubkey(250), "overflow".into(), "ios".into(), NOW);
        assert_eq!(overflow.unwrap_err(), DevicePairingStoreError::Full);
    }

    #[test]
    fn poll_token_mismatch_is_rejected() {
        let store = DevicePairingStore::new();
        let created = store
            .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
            .expect("create");
        let request_id = match created {
            PendingInsert::New { request_id, .. } => request_id,
            PendingInsert::Existing { .. } => panic!("should be New"),
        };
        let err = store
            .poll(&request_id, "not-the-token", NOW)
            .expect_err("token mismatch");
        assert_eq!(err, DevicePairingStoreError::TokenMismatch);
    }

    #[test]
    fn poll_unknown_request_is_not_found() {
        let store = DevicePairingStore::new();
        let err = store
            .poll("missing", "token", NOW)
            .expect_err("unknown request");
        assert_eq!(err, DevicePairingStoreError::NotFound);
    }

    #[test]
    fn approve_finalizes_and_blocks_second_finalize() {
        let store = DevicePairingStore::new();
        let created = store
            .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
            .expect("create");
        let (request_id, token) = match created {
            PendingInsert::New {
                request_id, token, ..
            } => (request_id, token),
            PendingInsert::Existing { .. } => panic!("should be New"),
        };

        store
            .approve(
                &request_id,
                VerifiedPairingDeviceCertificate::store_fixture(vec![9, 9, 9], pubkey(1)),
                approved_fixture(),
                NOW,
            )
            .expect("approve");

        // The device-cert bytes passed to approve override the fixture's
        // empty placeholder and surface via poll.
        let state = store.poll(&request_id, &token, NOW).expect("poll approved");
        match state {
            super::DevicePairingPollState::Approved(approved) => {
                assert_eq!(approved.device_cert_cbor, vec![9, 9, 9]);
                assert_eq!(approved.household_id, "hh_test");
            }
            other => panic!("expected Approved, got {other:?}"),
        }

        // A second finalize (approve or reject) must be refused.
        let reapprove = store.approve(
            &request_id,
            VerifiedPairingDeviceCertificate::store_fixture(vec![1], pubkey(1)),
            approved_fixture(),
            NOW,
        );
        assert_eq!(
            reapprove.unwrap_err(),
            DevicePairingStoreError::AlreadyFinalized
        );
        let reject_after = store.reject(&request_id, NOW);
        assert_eq!(
            reject_after.unwrap_err(),
            DevicePairingStoreError::AlreadyFinalized
        );
    }

    #[test]
    fn a_verified_certificate_for_another_request_does_not_finalize() {
        let store = DevicePairingStore::new();
        let PendingInsert::New {
            request_id, token, ..
        } = store
            .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
            .unwrap()
        else {
            panic!("new request expected")
        };
        let wrong = VerifiedPairingDeviceCertificate::store_fixture(vec![9], pubkey(2));
        assert_eq!(
            store
                .approve(&request_id, wrong, approved_fixture(), NOW)
                .unwrap_err(),
            DevicePairingStoreError::CertificateMismatch
        );
        assert!(matches!(
            store.poll(&request_id, &token, NOW).unwrap(),
            super::DevicePairingPollState::Pending
        ));
    }

    #[test]
    fn reject_finalizes_and_blocks_approve() {
        let store = DevicePairingStore::new();
        let created = store
            .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
            .expect("create");
        let (request_id, token) = match created {
            PendingInsert::New {
                request_id, token, ..
            } => (request_id, token),
            PendingInsert::Existing { .. } => panic!("should be New"),
        };

        store.reject(&request_id, NOW).expect("reject");
        let state = store.poll(&request_id, &token, NOW).expect("poll rejected");
        assert!(matches!(state, super::DevicePairingPollState::Rejected));

        let approve_after = store.approve(
            &request_id,
            VerifiedPairingDeviceCertificate::store_fixture(vec![1], pubkey(1)),
            approved_fixture(),
            NOW,
        );
        assert_eq!(
            approve_after.unwrap_err(),
            DevicePairingStoreError::AlreadyFinalized
        );
    }

    #[test]
    fn approve_after_expiry_is_rejected() {
        let store = DevicePairingStore::new();
        let created = store
            .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
            .expect("create");
        let request_id = match created {
            PendingInsert::New { request_id, .. } => request_id,
            PendingInsert::Existing { .. } => panic!("should be New"),
        };
        let later = NOW + DEVICE_PAIRING_TTL_SECS + 1;
        // Expired records are cleaned up on access, so finalizing reports
        // the request as gone (NotFound) rather than Expired.
        let err = store
            .approve(
                &request_id,
                VerifiedPairingDeviceCertificate::store_fixture(vec![1], pubkey(1)),
                approved_fixture(),
                later,
            )
            .expect_err("expired approve");
        assert_eq!(err, DevicePairingStoreError::NotFound);
    }

    #[test]
    fn poll_after_expiry_reports_expired_state() {
        let store = DevicePairingStore::new();
        let created = store
            .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
            .expect("create");
        let (request_id, token) = match created {
            PendingInsert::New {
                request_id, token, ..
            } => (request_id, token),
            PendingInsert::Existing { .. } => panic!("should be New"),
        };
        // Poll exactly at the boundary where the record still exists but is
        // no longer valid: cleanup uses `> now`, so at expires_at the record
        // is removed and poll reports NotFound.
        let at_expiry = NOW + DEVICE_PAIRING_TTL_SECS;
        let err = store
            .poll(&request_id, &token, at_expiry)
            .expect_err("expired poll");
        assert_eq!(err, DevicePairingStoreError::NotFound);
    }

    #[test]
    fn list_owner_visible_reflects_pending_then_finalized() {
        let store = DevicePairingStore::new();
        let created = store
            .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
            .expect("create");
        let request_id = match created {
            PendingInsert::New { request_id, .. } => request_id,
            PendingInsert::Existing { .. } => panic!("should be New"),
        };

        let pending = store.list_owner_visible(NOW);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].status, "pending");
        assert_eq!(pending[0].device_name, "alpha");
        assert_eq!(pending[0].platform, "ios");

        store.reject(&request_id, NOW).expect("reject");
        let after = store.list_owner_visible(NOW);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].status, "rejected");
    }

    #[test]
    fn validate_request_version_accepts_only_v1() {
        assert!(validate_request_version(1).is_ok());
        assert_eq!(
            validate_request_version(0).unwrap_err(),
            "version_unsupported"
        );
        assert_eq!(
            validate_request_version(2).unwrap_err(),
            "version_unsupported"
        );
    }

    #[test]
    fn validate_device_name_trims_and_bounds() {
        assert_eq!(validate_device_name("  My Mac  ").unwrap(), "My Mac");
        assert_eq!(
            validate_device_name("   ").unwrap_err(),
            "device_name_invalid"
        );
        let too_long = "x".repeat(65);
        assert_eq!(
            validate_device_name(&too_long).unwrap_err(),
            "device_name_invalid"
        );
        assert_eq!(
            validate_device_name("bad\u{0007}name").unwrap_err(),
            "device_name_invalid"
        );
    }

    #[test]
    fn validate_platform_allows_known_only() {
        assert_eq!(validate_platform("ios").unwrap(), "ios");
        assert_eq!(validate_platform("ipados").unwrap(), "ipados");
        assert_eq!(
            validate_platform("android").unwrap_err(),
            "platform_invalid"
        );
        assert_eq!(validate_platform("macos").unwrap_err(), "platform_invalid");
    }

    #[test]
    fn decode_public_key_rejects_garbage() {
        assert!(decode_public_key("!!!not-base64!!!").is_err());
        assert!(decode_public_key("").is_err());
    }
}

/// Pairing routes shared by production and the cross-repository contract host.
pub fn device_pairing_router(
    state: crate::handlers_owner_events::OwnerEventsRouterState,
) -> axum::Router {
    axum::Router::new()
        .route(
            "/api/v1/household/device-pairing/request",
            axum::routing::post(device_pairing_request_handler),
        )
        .route(
            "/api/v1/household/device-pairing/approve",
            axum::routing::post(device_pairing_approve_handler),
        )
        .route(
            "/api/v1/household/device-pairing/requests",
            axum::routing::get(device_pairing_requests_handler),
        )
        .route(
            "/api/v1/household/device-pairing/reject",
            axum::routing::post(device_pairing_reject_handler),
        )
        .route(
            "/api/v1/household/device-pairing/{request_id}",
            axum::routing::get(device_pairing_poll_handler),
        )
        .with_state(state)
}
