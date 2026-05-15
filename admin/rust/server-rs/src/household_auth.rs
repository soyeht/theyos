//! Soyeht proof-of-possession auth for household-scoped routes.

use axum::http::{HeaderMap, Method, header};
use household_rs::caveats::{self, Operation};
use household_rs::pop::RequestSigningContext;
use household_rs::{HouseholdAuthState, P256Signature, PersonId};
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::household_state::HouseholdState;

const TIMESTAMP_TOLERANCE_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub struct SoyehtPoP {
    pub p_id: String,
    pub timestamp: u64,
    pub signature: P256Signature,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing proof")]
    Missing,
    #[error("malformed proof")]
    Malformed,
    #[error("timestamp outside replay window")]
    Timestamp,
    #[error("household identity is unavailable")]
    IdentityUnavailable,
    #[error("owner auth state is unavailable")]
    OwnerAuthUnavailable,
    #[error("certificate rejected")]
    CertRejected,
    #[error("signature rejected")]
    SignatureRejected,
    #[error("operation not permitted")]
    CaveatRejected,
}

impl SoyehtPoP {
    pub fn parse(headers: &HeaderMap) -> Result<Self, AuthError> {
        let value = headers
            .get(header::AUTHORIZATION)
            .ok_or(AuthError::Missing)?
            .to_str()
            .map_err(|_| AuthError::Malformed)?;
        let rest = value
            .strip_prefix("Soyeht-PoP ")
            .ok_or(AuthError::Malformed)?;
        let mut parts = rest.split(':');
        let version = parts.next().ok_or(AuthError::Malformed)?;
        let p_id = parts.next().ok_or(AuthError::Malformed)?;
        let ts = parts.next().ok_or(AuthError::Malformed)?;
        let sig = parts.next().ok_or(AuthError::Malformed)?;
        if parts.next().is_some() || version != "v1" || !PersonId::is_well_formed(p_id) {
            return Err(AuthError::Malformed);
        }
        let timestamp = ts.parse::<u64>().map_err(|_| AuthError::Malformed)?;
        let sig_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig)
                .map_err(|_| AuthError::Malformed)?;
        let signature = P256Signature::from_bytes(&sig_bytes).map_err(|_| AuthError::Malformed)?;
        Ok(Self {
            p_id: p_id.to_string(),
            timestamp,
            signature,
        })
    }
}

pub async fn authorize_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    operation: Operation,
    now: u64,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    let pop = SoyehtPoP::parse(headers).inspect_err(log_rejected)?;
    let skew = now.abs_diff(pop.timestamp);
    if skew > TIMESTAMP_TOLERANCE_SECS {
        log_rejected(&AuthError::Timestamp);
        return Err(AuthError::Timestamp);
    }
    let identity = state.current().await.ok_or_else(|| {
        log_rejected(&AuthError::IdentityUnavailable);
        AuthError::IdentityUnavailable
    })?;
    let owner_auth = state.current_owner_auth().await.ok_or_else(|| {
        log_rejected(&AuthError::OwnerAuthUnavailable);
        AuthError::OwnerAuthUnavailable
    })?;
    if !bool::from(
        owner_auth
            .owner_person_cert
            .p_id
            .0
            .as_bytes()
            .ct_eq(pop.p_id.as_bytes()),
    ) {
        log_rejected(&AuthError::CertRejected);
        return Err(AuthError::CertRejected);
    }
    owner_auth
        .owner_person_cert
        .verify(&identity.record.hh_id, &identity.record.hh_pub, now)
        .map_err(|_| {
            log_rejected(&AuthError::CertRejected);
            AuthError::CertRejected
        })?;
    let ctx = RequestSigningContext::new(method.as_str(), path_and_query, pop.timestamp, body);
    ctx.verify(&owner_auth.owner_person_cert.p_pub, &pop.signature)
        .map_err(|_| {
            log_rejected(&AuthError::SignatureRejected);
            AuthError::SignatureRejected
        })?;
    if !caveats::permits(&owner_auth.owner_person_cert.caveats, &operation) {
        log_rejected(&AuthError::CaveatRejected);
        return Err(AuthError::CaveatRejected);
    }
    tracing::info!(
        stage = "household_auth.pop.accepted",
        p_id = %pop.p_id,
        operation = %operation,
    );
    Ok(owner_auth)
}

fn log_rejected(err: &AuthError) {
    tracing::warn!(
        stage = "household_auth.pop.rejected",
        error.kind = ?err,
        "Soyeht-PoP request rejected"
    );
}
