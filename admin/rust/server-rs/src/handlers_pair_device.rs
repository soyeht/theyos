//! `/api/v1/household/pair-device/*` axum handlers.
//!
//! Per FR-018 + spec §3, both routes return **404 (route absent)** when the
//! [`PairDeviceWindow`] is closed. Within the window:
//!
//! - `initiate` is **retrieve-only** — it returns the URI of the currently
//!   active token; it does **not** mint a fresh token. Minting is the sole
//!   prerogative of the install-time CLI flow (`theyos install`,
//!   `theyos install --reissue-pair-qr`) which requires shell access on the
//!   host. Without this restriction, any unauthenticated peer on the LAN
//!   or Tailscale could mint a new token and atomically invalidate the
//!   operator's printed QR — a takeover vector flagged in the Phase 1 review.
//! - `confirm` is the consume side. All error paths collapse to `404` so an
//!   attacker reaching the listener cannot probe for a live pairing flow via
//!   response codes.

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::bootstrap_state::{self, BootstrapState};
use household_rs::caveats;
use household_rs::keys::P256PublicKey;
use household_rs::pair_device::{ConsumeError, ConsumeWithError, PairDeviceWindow, PairNonce};
use household_rs::person_cert::{SignOwnerOptions, derive_person_id};
use household_rs::pop::PairingProofContext;
use household_rs::{HouseholdAuthState, P256Signature};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

use crate::household_bootstrap::global_bootstrap_state;
use crate::household_state::HouseholdState;
use crate::time_util;

#[derive(Clone)]
pub struct PairDeviceState {
    pub window: Arc<PairDeviceWindow>,
    /// Shared identity slot. `initiate` reads this at request time so a daemon
    /// that started cold can serve the pair URI after `theyos install`
    /// hot-loads the household identity.
    pub household: HouseholdState,
    pub state_dir: PathBuf,
}

#[derive(Serialize)]
struct InitiateResponse {
    uri: String,
}

/// Phase 2 confirm body. The submitted person public key becomes the owner's
/// certified key; `proof_sig` proves possession of the matching private key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmRequest {
    #[serde(default)]
    pub v: u8,
    pub nonce: String,
    pub p_pub: String,
    pub display_name: Option<String>,
    pub proof_sig: String,
}

#[derive(Serialize)]
struct ConfirmResponse {
    v: u8,
    hh_id: String,
    p_id: String,
    person_cert_cbor: String,
    capabilities: Vec<String>,
    /// Kept for Phase 1 test compatibility; authority is the `PersonCert`.
    consumed: bool,
}

/// Hard ceiling on the base64-encoded nonce body so that a hostile client
/// can't allocate hundreds of MB by sending an oversized request.
const MAX_NONCE_B64_LEN: usize = 64;

/// `POST /api/v1/household/pair-device/initiate`
///
/// Retrieve-only: returns the current pair URI when the window is open.
/// Returns 404 (route-absent semantics) when the window is closed or
/// identity has not loaded yet.
pub async fn initiate(State(state): State<PairDeviceState>) -> Response {
    let Some(identity) = state.household.current().await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Fingerprint the cert this identity was actually loaded and validated
    // with — not a fresh read of `machine_certs/`, which would only prove that
    // some file decoded. Deriving it here also keeps the failure inert: this
    // handler is retrieve-only, so nothing has been minted to leak.
    let m_cert_fp = match household_rs::machine_cert::fingerprint(&identity.cert) {
        Ok(fp) => fp,
        Err(e) => {
            tracing::warn!(stage = "pair_device.initiate.m_cert_fp_failed", error = %e);
            return StatusCode::NOT_FOUND.into_response();
        }
    };
    let Some(token) = state.window.current_token().await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    Json(InitiateResponse {
        uri: token.to_uri_with_host_and_name(
            &identity.record.hh_pub,
            None,
            Some(&identity.record.name),
            &m_cert_fp,
        ),
    })
    .into_response()
}

/// `POST /api/v1/household/pair-device/confirm`
///
/// Consume side. All failure modes (closed window, expired token, wrong
/// nonce, malformed body) collapse to **404** to avoid leaking that a
/// pairing flow exists to an attacker reaching the listener.
pub async fn confirm(
    State(state): State<PairDeviceState>,
    req: Result<Json<ConfirmRequest>, JsonRejection>,
) -> Response {
    let Ok(Json(req)) = req else {
        log_pair_rejected("malformed_json");
        return StatusCode::NOT_FOUND.into_response();
    };
    if req.v != 1 || req.nonce.is_empty() || req.nonce.len() > MAX_NONCE_B64_LEN {
        // Treat malformed input the same as no-window — no probing oracle.
        log_pair_rejected("malformed_body");
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(p_pub_bytes) = B64URL.decode(&req.p_pub) else {
        log_pair_rejected("malformed_key");
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(p_pub) = P256PublicKey::from_bytes(&p_pub_bytes) else {
        log_pair_rejected("malformed_key");
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(proof_bytes) = B64URL.decode(&req.proof_sig) else {
        log_pair_rejected("malformed_proof");
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(proof_sig) = P256Signature::from_bytes(&proof_bytes) else {
        log_pair_rejected("malformed_proof");
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(nonce) = PairNonce::from_b64(&req.nonce) else {
        log_pair_rejected("malformed_nonce");
        return StatusCode::NOT_FOUND.into_response();
    };
    let display_name = req
        .display_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Owner".to_string());
    let Some(now) = time_util::unix_now_secs_checked("pair_device.confirm.clock") else {
        log_pair_rejected("clock_invalid");
        return StatusCode::NOT_FOUND.into_response();
    };

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;

    // Pair-device confirm writes owner auth, consumes the pairing window, and
    // may advance bootstrap state. Keep that transaction serialized with
    // initialize/teardown and the machine-pairing bootstrap mutations.
    let Some(identity) = state.household.current().await else {
        log_pair_rejected("identity_unavailable");
        return StatusCode::NOT_FOUND.into_response();
    };
    let state_dir = state.state_dir.clone();
    let household = state.household.clone();
    match HouseholdAuthState::load_optional(&state_dir, &identity.record, now) {
        Ok(Some(_)) => {
            state.window.close().await;
            log_pair_rejected("owner_already_paired");
            return StatusCode::NOT_FOUND.into_response();
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(
                stage = "pair_device.confirm.owner_auth_load_failed",
                error = %e,
            );
            state.window.close().await;
            log_pair_rejected("owner_auth_invalid");
            return StatusCode::NOT_FOUND.into_response();
        }
    }

    let result: Result<_, ConsumeWithError<PairConfirmFailure>> = state
        .window
        .consume_token_with(&nonce, |token| {
            let proof_ctx = PairingProofContext::new(
                identity.record.hh_id.clone(),
                token.nonce.0,
                p_pub.clone(),
            );
            proof_ctx.verify(&proof_sig).map_err(|e| {
                tracing::warn!(
                    stage = "pair_device.confirm.proof_rejected",
                    error.kind = %e,
                );
                PairConfirmFailure
            })?;
            let Some(hh_priv) = identity.hh_priv.as_deref() else {
                tracing::warn!(
                    stage = "pair_device.confirm.post_shamir_rejected",
                    hint = "owner pairing requires sole-shard household; cannot mint PersonCert after Shamir transition",
                );
                return Err(PairConfirmFailure);
            };
            let cert = household_rs::PersonCert::sign_owner(
                hh_priv,
                SignOwnerOptions {
                    hh_id: identity.record.hh_id.clone(),
                    p_pub: p_pub.clone(),
                    display_name: display_name.clone(),
                    issued_at: now,
                },
            )
            .map_err(|e| {
                tracing::warn!(
                    stage = "pair_device.confirm.sign_failed",
                    error.kind = e.kind(),
                    error.hint = %e.hint(),
                );
                PairConfirmFailure
            })?;
            let auth = HouseholdAuthState::new(&identity.record, cert.clone());
            auth.save(&state_dir).map_err(|e| {
                tracing::warn!(
                    stage = "pair_device.confirm.persist_failed",
                    error = %e,
                );
                PairConfirmFailure
            })?;
            let cert_bytes = household_rs::cbor::to_canonical_vec(&cert).map_err(|e| {
                tracing::warn!(
                    stage = "pair_device.confirm.encode_failed",
                    error = %e,
                );
                PairConfirmFailure
            })?;
            Ok((
                auth,
                ConfirmResponse {
                    v: 1,
                    hh_id: identity.record.hh_id.to_string(),
                    p_id: derive_person_id(&p_pub).0,
                    person_cert_cbor: B64URL.encode(cert_bytes),
                    capabilities: caveats::owner_capability_names(),
                    consumed: true,
                },
            ))
        })
        .await;

    match result {
        Ok((auth, response)) => {
            household.set_owner_auth(Arc::new(auth)).await;

            // T026 — drive named_awaiting_pair → ready on first successful owner pairing.
            if let Some(bs_arc) = global_bootstrap_state() {
                let mut bs = bs_arc.write().await;
                if *bs == BootstrapState::NamedAwaitingPair {
                    *bs = BootstrapState::Ready;
                    if let Err(e) = bootstrap_state::persist(&state_dir, BootstrapState::Ready) {
                        tracing::warn!(
                            stage = "pair_device.confirm.state_persist_failed",
                            error = %e,
                        );
                    } else {
                        tracing::info!(
                            stage = "pair_device.confirm.state_advanced",
                            new_state = "ready",
                        );
                    }
                }
            }

            tracing::info!(
                stage = "pair_device.confirm.success",
                hh_id = %response.hh_id,
                p_id = %response.p_id,
            );
            Json(response).into_response()
        }
        Err(
            ConsumeWithError::Window(
                ConsumeError::NotOpen | ConsumeError::Expired | ConsumeError::WrongNonce,
            )
            | ConsumeWithError::Callback(_),
        ) => {
            log_pair_rejected("generic");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

#[derive(Debug)]
struct PairConfirmFailure;

fn log_pair_rejected(reason: &'static str) {
    tracing::warn!(
        stage = "pair_device.confirm.rejected",
        reason,
        "pair-device confirm rejected"
    );
}
