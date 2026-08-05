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
use household_rs::household_lifecycle::{HouseholdLifecycleLock, LifecycleWriteGuard};
use household_rs::keys::P256PublicKey;
use household_rs::pair_device::{ConsumeError, ConsumeWithError, PairDeviceWindow, PairNonce};
use household_rs::person_cert::{SignOwnerOptions, derive_person_id};
use household_rs::pop::PairingProofContext;
use household_rs::{HouseholdAuthState, P256Signature};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
const PAIR_LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(30);

fn lifecycle_io(stage: &'static str, error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("{stage}: {error}"))
}

fn acquire_pair_lifecycle_exclusive(state_dir: &Path) -> io::Result<LifecycleWriteGuard> {
    let lifecycle = HouseholdLifecycleLock::open_verified(state_dir)
        .map_err(|error| lifecycle_io("open pair-device household lifecycle", error))?;
    let deadline = Instant::now()
        .checked_add(PAIR_LIFECYCLE_TIMEOUT)
        .ok_or_else(|| io::Error::other("pair-device lifecycle deadline overflow"))?;
    let guard = lifecycle
        .lock_exclusive_until(deadline)
        .map_err(|error| lifecycle_io("acquire pair-device lifecycle exclusive", error))?;
    let recovered =
        household_rs::bootstrap::recover_interrupted_household_teardown_under_lifecycle(
            &guard, state_dir,
        )
        .map_err(|error| lifecycle_io("recover interrupted household teardown", error))?;
    if recovered {
        return Err(io::Error::other(
            "recovered an interrupted teardown; refusing the stale pairing request",
        ));
    }
    Ok(guard)
}

fn verify_installed_household_id(
    guard: &LifecycleWriteGuard,
    state_dir: &Path,
    expected_hh_id: &str,
) -> io::Result<()> {
    guard
        .verify_state_root(state_dir)
        .map_err(|error| lifecycle_io("verify pair-device state root", error))?;
    let record: household_rs::HouseholdRecord = household_rs::storage::read_optional_cbor(
        &household_rs::storage::household_record_path(state_dir),
    )
    .map_err(|error| lifecycle_io("read installed household for pair-device", error))?
    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "installed household is absent"))?;
    if record.hh_id.as_str() != expected_hh_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "installed household changed before pair-device completion",
        ));
    }
    Ok(())
}

async fn persist_ready_then_publish<F>(
    guard: &LifecycleWriteGuard,
    state_dir: &Path,
    expected_generation: household_rs::household_lifecycle::HouseholdLifecycleGenerationV1,
    publish: F,
) -> io::Result<()>
where
    F: Future<Output = ()>,
{
    bootstrap_state::persist_ready_under_lifecycle(guard, state_dir, expected_generation)
        .map_err(|error| lifecycle_io("persist pair-device ready state", error))?;
    publish.await;
    Ok(())
}

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

    // Cross-process lifecycle ordering is deliberately outside every
    // PairDeviceWindow/HouseholdState mutex: mutation lock -> lifecycle
    // exclusive -> process state -> stores. A teardown or replacement cannot
    // land between the authority write and Ready publication.
    let lifecycle_state_dir = state.state_dir.clone();
    let lifecycle_guard = match tokio::task::spawn_blocking(move || {
        acquire_pair_lifecycle_exclusive(&lifecycle_state_dir)
    })
    .await
    {
        Ok(Ok(guard)) => guard,
        Ok(Err(error)) => {
            tracing::warn!(
                stage = "pair_device.confirm.lifecycle_failed",
                error = %error,
            );
            log_pair_rejected("identity_unavailable");
            return StatusCode::NOT_FOUND.into_response();
        }
        Err(error) => {
            tracing::warn!(
                stage = "pair_device.confirm.lifecycle_task_failed",
                error = %error,
            );
            log_pair_rejected("identity_unavailable");
            return StatusCode::NOT_FOUND.into_response();
        }
    };
    let ready_generation = match lifecycle_guard.lifecycle_generation() {
        Ok(Some(generation)) => generation,
        Ok(None) | Err(_) => {
            log_pair_rejected("identity_unavailable");
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    // Pair-device confirm writes owner auth, consumes the pairing window, and
    // may advance bootstrap state. Keep that transaction serialized with
    // initialize/teardown and the machine-pairing bootstrap mutations.
    let Some(identity) = state.household.current().await else {
        log_pair_rejected("identity_unavailable");
        return StatusCode::NOT_FOUND.into_response();
    };
    let state_dir = state.state_dir.clone();
    let household = state.household.clone();
    if let Err(error) =
        verify_installed_household_id(&lifecycle_guard, &state_dir, identity.record.hh_id.as_str())
    {
        tracing::warn!(
            stage = "pair_device.confirm.household_recheck_failed",
            error = %error,
        );
        log_pair_rejected("identity_unavailable");
        return StatusCode::NOT_FOUND.into_response();
    }
    match HouseholdAuthState::load_optional(&state_dir, &identity.record, now) {
        Ok(Some(_)) => {
            let _ = state.window.close_under_lifecycle(&lifecycle_guard).await;
            log_pair_rejected("owner_already_paired");
            return StatusCode::NOT_FOUND.into_response();
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(
                stage = "pair_device.confirm.owner_auth_load_failed",
                error = %e,
            );
            let _ = state.window.close_under_lifecycle(&lifecycle_guard).await;
            log_pair_rejected("owner_auth_invalid");
            return StatusCode::NOT_FOUND.into_response();
        }
    }

    let result: Result<_, ConsumeWithError<PairConfirmFailure>> = state
        .window
        .consume_token_with_under_lifecycle(&nonce, |token| {
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
                PairConfirmFailure::Rejected
            })?;
            let Some(hh_priv) = identity.hh_priv.as_deref() else {
                tracing::warn!(
                    stage = "pair_device.confirm.post_shamir_rejected",
                    hint = "owner pairing requires sole-shard household; cannot mint PersonCert after Shamir transition",
                );
                return Err(PairConfirmFailure::Rejected);
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
                PairConfirmFailure::Rejected
            })?;
            let auth = HouseholdAuthState::new(&identity.record, cert.clone());
            // Finish all pure response construction before the first durable
            // authority write. No fallible encoding step may turn a committed
            // owner into an ordinary callback rejection.
            let cert_bytes = household_rs::cbor::to_canonical_vec(&cert).map_err(|e| {
                tracing::warn!(
                    stage = "pair_device.confirm.encode_failed",
                    error = %e,
                );
                PairConfirmFailure::Rejected
            })?;
            if let Err(error) = auth.save(&state_dir) {
                if matches!(
                    error,
                    household_rs::owner_auth::OwnerAuthError::Storage(
                        household_rs::StorageError::MayHaveTakenEffect { .. }
                    )
                ) {
                    // Only an exact-byte rewrite is safe after the authority
                    // rename may have landed. Its successful parent barrier
                    // stabilizes the same auth and its cert projection.
                    if let Err(retry_error) = auth.save(&state_dir) {
                        tracing::error!(
                            stage = "pair_device.confirm.persist_indeterminate",
                            error = %retry_error,
                        );
                        return Err(PairConfirmFailure::IndeterminateAuthority);
                    }
                } else {
                    tracing::warn!(
                        stage = "pair_device.confirm.persist_failed",
                        error = %error,
                    );
                    return Err(PairConfirmFailure::Rejected);
                }
            }
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
        }, &lifecycle_guard)
        .await;

    match result {
        Ok((auth, response)) => {
            // The auth file is already durable. Commit Ready next, then
            // publish both in-memory views while the same lifecycle-exclusive
            // guard is still live. A persist failure is fail-closed: never
            // claim success from memory when disk does not name Ready.
            let bs_arc = global_bootstrap_state();
            let publish = async {
                household.set_owner_auth(Arc::new(auth)).await;
                if let Some(bs_arc) = bs_arc {
                    *bs_arc.write().await = BootstrapState::Ready;
                }
            };
            if let Err(error) =
                persist_ready_then_publish(
                    &lifecycle_guard,
                    &state_dir,
                    ready_generation,
                    publish,
                )
                .await
            {
                tracing::error!(
                    stage = "pair_device.confirm.state_persist_indeterminate",
                    error = %error,
                );
                // Owner authority is already durable. A lost Ready
                // acknowledgement cannot be reported as a normal 404 while
                // this process keeps serving the pre-owner in-memory view.
                let _ = state.window.close_under_lifecycle(&lifecycle_guard).await;
                household.clear().await;
                if let Some(bs_arc) = global_bootstrap_state() {
                    *bs_arc.write().await = BootstrapState::Recovering;
                }
                #[cfg(not(test))]
                tokio::spawn(async {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    std::process::exit(1);
                });
                log_pair_rejected("ready_persist_indeterminate_fail_stop");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            tracing::info!(
                stage = "pair_device.confirm.state_advanced",
                new_state = "ready",
            );

            tracing::info!(
                stage = "pair_device.confirm.success",
                hh_id = %response.hh_id,
                p_id = %response.p_id,
            );
            Json(response).into_response()
        }
        Err(ConsumeWithError::Callback(PairConfirmFailure::IndeterminateAuthority)) => {
            // Disk may already name the new owner while its durability could
            // not be stabilized. Never continue serving the old in-memory
            // authority or leave the bootstrap surface looking Ready.
            let _ = state.window.close_under_lifecycle(&lifecycle_guard).await;
            household.clear().await;
            if let Some(bs_arc) = global_bootstrap_state() {
                *bs_arc.write().await = BootstrapState::Recovering;
            }
            #[cfg(not(test))]
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                std::process::exit(1);
            });
            log_pair_rejected("authority_indeterminate_fail_stop");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(ConsumeWithError::Window(ConsumeError::Storage(error))) => {
            // The callback may already have durably installed owner
            // authority before exact-generation window cleanup failed. The
            // consume API intentionally closes memory first, but cannot hand
            // its successful callback value back after cleanup fails. Treat
            // this as an authority-indeterminate boundary, never as a normal
            // nonce rejection.
            tracing::error!(
                stage = "pair_device.confirm.window_cleanup_indeterminate",
                error = %error,
            );
            let _ = state.window.close_under_lifecycle(&lifecycle_guard).await;
            household.clear().await;
            if let Some(bs_arc) = global_bootstrap_state() {
                *bs_arc.write().await = BootstrapState::Recovering;
            }
            #[cfg(not(test))]
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                std::process::exit(1);
            });
            log_pair_rejected("window_cleanup_indeterminate_fail_stop");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(
            ConsumeWithError::Window(
                ConsumeError::NotOpen | ConsumeError::Expired | ConsumeError::WrongNonce,
            )
            | ConsumeWithError::Callback(PairConfirmFailure::Rejected),
        ) => {
            log_pair_rejected("generic");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

#[derive(Debug)]
enum PairConfirmFailure {
    Rejected,
    IndeterminateAuthority,
}

fn log_pair_rejected(reason: &'static str) {
    tracing::warn!(
        stage = "pair_device.confirm.rejected",
        reason,
        "pair-device confirm rejected"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::household_lifecycle::HouseholdLifecycleLockError;
    use std::sync::mpsc;

    fn bootstrap_named(state_dir: &Path, name: &str) -> household_rs::LoadedIdentity {
        household_rs::bootstrap_or_load(
            state_dir,
            household_rs::BootstrapOpts {
                household_name: name.to_owned(),
                hostname_label: Some(format!("{}-host", name.to_lowercase().replace(' ', "-"))),
            },
            household_rs::KeyBackingPolicy::ForceSoftware,
        )
        .expect("bootstrap household")
    }

    #[tokio::test]
    async fn ready_publication_remains_inside_lifecycle_exclusive() {
        let state = tempfile::tempdir().expect("state dir");
        let _identity = bootstrap_named(state.path(), "Pair Device Lock Home");
        let guard = acquire_pair_lifecycle_exclusive(state.path()).expect("exclusive");
        let contender_path = state.path().to_path_buf();
        let (started_tx, started_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let contender = std::thread::spawn(move || {
            let lifecycle =
                HouseholdLifecycleLock::open_verified(&contender_path).expect("open contender");
            started_tx.send(()).expect("signal contender");
            let deadline = Instant::now()
                .checked_add(Duration::from_millis(100))
                .expect("deadline");
            result_tx
                .send(lifecycle.lock_exclusive_until(deadline).map(|_| ()))
                .expect("send contender result");
        });

        let generation = guard.ensure_lifecycle_generation().unwrap();
        persist_ready_then_publish(&guard, state.path(), generation, async {
            started_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("contender started");
            assert_eq!(
                result_rx
                    .recv_timeout(Duration::from_secs(1))
                    .expect("contender result"),
                Err(HouseholdLifecycleLockError::LockTimeout),
                "teardown/replacement acquired between durable Ready and publication",
            );
        })
        .await
        .expect("persist and publish");
        contender.join().expect("contender thread");
        drop(guard);

        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).expect("reopen");
        lifecycle.lock_exclusive().expect("lock after publication");
    }

    #[test]
    fn stale_pair_device_process_rejects_replacement_household() {
        let old_state = tempfile::tempdir().expect("old state");
        let replacement_state = tempfile::tempdir().expect("replacement state");
        let old = bootstrap_named(old_state.path(), "Old Pair Device Home");
        let replacement = bootstrap_named(replacement_state.path(), "Replacement Home");
        household_rs::storage::atomic_write_cbor(
            &household_rs::storage::household_record_path(old_state.path()),
            &replacement.record,
        )
        .expect("install replacement record");

        let guard = acquire_pair_lifecycle_exclusive(old_state.path()).expect("exclusive");
        let error =
            verify_installed_household_id(&guard, old_state.path(), old.record.hh_id.as_str())
                .expect_err("stale identity must not mutate replacement");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
