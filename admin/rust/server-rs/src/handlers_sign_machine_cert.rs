//! `POST /api/v1/household/sign-machine-cert` handler.

use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::post,
};
use household_rs::bootstrap_error::BootstrapErrorCode;
use household_rs::caveats::Operation;
use household_rs::ids::{MachineId, derive_machine_id};
use household_rs::keys::P256PublicKey;
use household_rs::machine_cert::{MachineCert, Platform, SignOptions};
use household_rs::owner_events::{
    OwnerEventLog, OwnerEventPayload, OwnerEventType, SignMachineCertForProxyPayload,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::household_auth::{self, AuthError};
use crate::household_state::HouseholdState;
use crate::time_util;

const CBOR_CONTENT_TYPE: &str = "application/cbor";

#[derive(Clone)]
pub struct SignMachineCertRouterState {
    pub household: HouseholdState,
    pub event_log: Arc<OwnerEventLog>,
}

pub fn sign_machine_cert_router(state: SignMachineCertRouterState) -> Router {
    Router::new()
        .route(
            "/api/v1/household/sign-machine-cert",
            post(sign_machine_cert_handler),
        )
        .with_state(state)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignMachineCertRequest {
    #[serde(rename = "v")]
    version: u8,
    kind: String,
    subject: SignMachineCertSubject,
    challenge: ByteBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignMachineCertSubject {
    m_id: String,
    m_pub: ByteBuf,
    hostname: String,
    platform: String,
}

#[derive(Serialize)]
struct SignMachineCertResponse {
    #[serde(rename = "v")]
    version: u8,
    machine_cert: ByteBuf,
    challenge_signature: ByteBuf,
    m_id: String,
    joined_at: u64,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    #[serde(rename = "v")]
    version: u8,
    error: &'a str,
}

fn cbor_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut resp = (status, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    resp
}

fn cbor_ok<T: Serialize>(value: T) -> Response {
    match household_rs::cbor::to_canonical_vec(&value) {
        Ok(body) => cbor_response(StatusCode::OK, body),
        Err(e) => {
            tracing::error!(stage = "sign_machine_cert.response_encode_failed", error = %e);
            cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::InternalError.as_str(),
            )
        }
    }
}

fn cbor_error(status: StatusCode, error: &'static str) -> Response {
    let body =
        household_rs::cbor::to_canonical_vec(&ErrorBody { version: 1, error }).unwrap_or_default();
    cbor_response(status, body)
}

fn strict_cbor_request<T>(body: &[u8]) -> Result<T, ()>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let decoded: T = household_rs::cbor::from_canonical_slice(body).map_err(|_| ())?;
    let encoded = household_rs::cbor::to_canonical_vec(&decoded).map_err(|_| ())?;
    if encoded == body {
        Ok(decoded)
    } else {
        Err(())
    }
}

/// `POST /api/v1/household/sign-machine-cert`.
pub async fn sign_machine_cert_handler(
    State(state): State<SignMachineCertRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("sign_machine_cert.clock") else {
        return cbor_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            BootstrapErrorCode::InternalError.as_str(),
        );
    };

    let Some(identity) = state.household.current().await else {
        return cbor_error(
            StatusCode::CONFLICT,
            BootstrapErrorCode::HouseholdNotInitialized.as_str(),
        );
    };
    if identity.record.is_follower || identity.hh_priv.is_none() {
        return cbor_error(
            StatusCode::CONFLICT,
            BootstrapErrorCode::HouseholdNotInitialized.as_str(),
        );
    }

    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let authorized = match household_auth::authorize_request_with_actor(
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
        Ok(authorized) => authorized,
        Err(
            AuthError::Missing
            | AuthError::Malformed
            | AuthError::Timestamp
            | AuthError::SignatureRejected,
        ) => {
            return cbor_error(
                StatusCode::UNAUTHORIZED,
                BootstrapErrorCode::InvalidPop.as_str(),
            );
        }
        Err(AuthError::IdentityUnavailable) => {
            return cbor_error(
                StatusCode::CONFLICT,
                BootstrapErrorCode::HouseholdNotInitialized.as_str(),
            );
        }
        Err(
            AuthError::OwnerAuthUnavailable
            | AuthError::NotAMember
            | AuthError::CertRejected
            | AuthError::CaveatRejected,
        ) => {
            return cbor_error(
                StatusCode::FORBIDDEN,
                BootstrapErrorCode::NotAMember.as_str(),
            );
        }
    };

    let req: SignMachineCertRequest = match strict_cbor_request(&body) {
        Ok(req) => req,
        Err(()) => {
            return cbor_error(
                StatusCode::BAD_REQUEST,
                BootstrapErrorCode::InvalidCbor.as_str(),
            );
        }
    };
    if req.version != 1 {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidCbor.as_str(),
        );
    }
    if req.kind != "machine" {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidSubject.as_str(),
        );
    }

    let Ok(m_pub) = P256PublicKey::from_bytes(req.subject.m_pub.as_ref()) else {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidSubject.as_str(),
        );
    };
    let Ok(m_id) = MachineId::parse(req.subject.m_id.clone()) else {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidSubject.as_str(),
        );
    };
    let derived_m_id = derive_machine_id(&m_pub);
    if derived_m_id != m_id {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidSubject.as_str(),
        );
    }
    if !valid_hostname(&req.subject.hostname) {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidSubject.as_str(),
        );
    }
    let Some(platform) = parse_platform(&req.subject.platform) else {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidSubject.as_str(),
        );
    };

    let Some(hh_priv) = identity.hh_priv.as_deref() else {
        return cbor_error(
            StatusCode::CONFLICT,
            BootstrapErrorCode::HouseholdNotInitialized.as_str(),
        );
    };
    let cert = match MachineCert::sign(
        hh_priv,
        &m_pub,
        &SignOptions {
            hh_id: identity.record.hh_id.clone(),
            hostname: req.subject.hostname.clone(),
            platform,
            joined_at: now,
        },
    ) {
        Ok(cert) => cert,
        Err(e) => {
            tracing::error!(stage = "sign_machine_cert.cert_sign_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::KeygenFailed.as_str(),
            );
        }
    };
    let machine_cert = match household_rs::cbor::to_canonical_vec(&cert) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(stage = "sign_machine_cert.cert_encode_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::InternalError.as_str(),
            );
        }
    };
    let challenge_signature = match hh_priv.sign(req.challenge.as_ref()) {
        Ok(sig) => sig,
        Err(e) => {
            tracing::error!(stage = "sign_machine_cert.challenge_sign_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::KeygenFailed.as_str(),
            );
        }
    };

    if let Err(e) = state.event_log.append(
        identity.cert.m_id.as_str(),
        identity.m_priv.as_ref(),
        OwnerEventType::SignMachineCertForProxy,
        OwnerEventPayload::SignMachineCertForProxy(SignMachineCertForProxyPayload {
            actor_person_id: authorized.actor_person_id,
            target_m_id: m_id.to_string(),
            joined_at: now,
            hostname: req.subject.hostname,
            platform: req.subject.platform,
        }),
    ) {
        tracing::error!(stage = "sign_machine_cert.audit_append_failed", error = %e);
        return cbor_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            BootstrapErrorCode::InternalError.as_str(),
        );
    }

    cbor_ok(SignMachineCertResponse {
        version: 1,
        machine_cert: ByteBuf::from(machine_cert),
        challenge_signature: ByteBuf::from(challenge_signature.as_bytes().to_vec()),
        m_id: m_id.to_string(),
        joined_at: now,
    })
}

fn valid_hostname(hostname: &str) -> bool {
    !hostname.is_empty() && hostname.len() <= 64 && !hostname.chars().any(char::is_control)
}

fn parse_platform(platform: &str) -> Option<Platform> {
    match platform {
        "macos" => Some(Platform::Macos),
        "linux-nix" => Some(Platform::LinuxNix),
        "linux-other" => Some(Platform::LinuxOther),
        _ => None,
    }
}
