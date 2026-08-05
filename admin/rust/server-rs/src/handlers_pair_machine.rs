//! Phase 3 founding-machine join-request endpoint, candidate's
//! pre-household listener (`/pair-machine/local/seed` and
//! `/pair-machine/local/finalize`), and the shared
//! `founder_stage_join_request` helper.
//!
//! Founder-side staging is transport-neutral: the remote QR endpoint and the
//! LAN Bonjour browser both call [`founder_stage_join_request`] after they have
//! obtained a signed [`JoinRequest`].

use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use household_rs::bootstrap_state::{self, BootstrapState};
use household_rs::caveats::Operation;
use household_rs::household_lifecycle::{HouseholdLifecycleLock, LifecycleWriteGuard};
use household_rs::owner_events::{
    JoinRequestPayload, OwnerEventLog, OwnerEventPayload, OwnerEventType, OwnerEventsBroadcaster,
    owner_push_token_path,
};
use household_rs::pair_machine::{
    FINALIZE_CANDIDATE_TAILSCALE_ADDR_HEADER, FinalizeAck, JoinRequest, JoinResponse,
    JoinTransport, PairMachineState, PairMachineWindow, PairMachineWindowSnapshot,
    join_request_hash, shamir_self_shard_path, verify_join_request,
};
use serde::Serialize;
use serde_bytes::ByteBuf;

use crate::bonjour_trust::{DiscoverySource, classify_source};
use crate::handlers_owner_events;
use crate::household_auth;
use crate::household_state::HouseholdState;
use crate::tailnet_address::{TailnetResolver, current_tailnet_ipv4};
use crate::time_util;

/// Application content type for every Phase 3 join-request response —
/// success, replay, and the generic-failure 401 alike.
const CBOR_CONTENT_TYPE: &str = "application/cbor";
const PAIR_LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(30);

pub const POST_COMMIT_REDUNDANCY_NOTICE: &str = "Household now has 2 machines. Until you add a 3rd machine, losing either machine means losing the household. Add another machine soon.";

fn lifecycle_io(stage: &'static str, error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(format!("{stage}: {error}"))
}

fn acquire_pair_lifecycle_exclusive(state_dir: &Path) -> std::io::Result<LifecycleWriteGuard> {
    let lifecycle = HouseholdLifecycleLock::open_verified(state_dir)
        .map_err(|error| lifecycle_io("open pair-machine household lifecycle", error))?;
    let deadline = Instant::now()
        .checked_add(PAIR_LIFECYCLE_TIMEOUT)
        .ok_or_else(|| std::io::Error::other("pair-machine lifecycle deadline overflow"))?;
    let guard = lifecycle
        .lock_exclusive_until(deadline)
        .map_err(|error| lifecycle_io("acquire pair-machine lifecycle exclusive", error))?;
    let recovered =
        household_rs::bootstrap::recover_interrupted_household_teardown_under_lifecycle(
            &guard, state_dir,
        )
        .map_err(|error| lifecycle_io("recover interrupted household teardown", error))?;
    if recovered {
        return Err(std::io::Error::other(
            "recovered an interrupted teardown; refusing the stale pairing request",
        ));
    }
    Ok(guard)
}

fn verify_installed_household_for_finalize(
    guard: &LifecycleWriteGuard,
    state_dir: &Path,
    requested_hh_id: &str,
) -> std::io::Result<()> {
    guard
        .verify_state_root(state_dir)
        .map_err(|error| lifecycle_io("verify pair-machine state root", error))?;
    let record: Option<household_rs::HouseholdRecord> = household_rs::storage::read_optional_cbor(
        &household_rs::storage::household_record_path(state_dir),
    )
    .map_err(|error| lifecycle_io("read installed household for pair-machine", error))?;
    if record
        .as_ref()
        .is_some_and(|installed| installed.hh_id.as_str() != requested_hh_id)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installed replacement household differs from pair-machine response",
        ));
    }
    Ok(())
}

fn verify_installed_household_id(
    guard: &LifecycleWriteGuard,
    state_dir: &Path,
    expected_hh_id: &str,
) -> std::io::Result<()> {
    guard
        .verify_state_root(state_dir)
        .map_err(|error| lifecycle_io("verify installed household state root", error))?;
    let record: household_rs::HouseholdRecord = household_rs::storage::read_optional_cbor(
        &household_rs::storage::household_record_path(state_dir),
    )
    .map_err(|error| lifecycle_io("read installed household identity", error))?
    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "household is absent"))?;
    if record.hh_id.as_str() != expected_hh_id {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installed household differs from the in-memory authority",
        ));
    }
    Ok(())
}

fn verify_household_absent_for_candidate(
    guard: &LifecycleWriteGuard,
    state_dir: &Path,
) -> std::io::Result<()> {
    guard
        .verify_state_root(state_dir)
        .map_err(|error| lifecycle_io("verify candidate state root", error))?;
    let record: Option<household_rs::HouseholdRecord> = household_rs::storage::read_optional_cbor(
        &household_rs::storage::household_record_path(state_dir),
    )
    .map_err(|error| lifecycle_io("inspect candidate household record", error))?;
    if record.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "candidate state root already contains an installed household record",
        ));
    }
    Ok(())
}

fn verify_candidate_lifecycle_generation(
    guard: &LifecycleWriteGuard,
    snapshot: &PairMachineWindowSnapshot,
) -> std::io::Result<household_rs::household_lifecycle::HouseholdLifecycleGenerationV1> {
    let observed = retained_window_lifecycle_generation(snapshot)?;
    let current = guard
        .lifecycle_generation()
        .map_err(|error| lifecycle_io("read current lifecycle generation", error))?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "candidate lifecycle generation disappeared; restage required",
            )
        })?;
    if current != observed {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "candidate lifecycle generation is stale; restage required",
        ));
    }
    Ok(observed)
}

fn retained_window_lifecycle_generation(
    snapshot: &PairMachineWindowSnapshot,
) -> std::io::Result<household_rs::household_lifecycle::HouseholdLifecycleGenerationV1> {
    let observed = snapshot.lifecycle_generation.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "legacy candidate window has no lifecycle generation; restage required",
        )
    })?;
    let observed =
        household_rs::household_lifecycle::HouseholdLifecycleGenerationV1::from_token_bytes(
            observed.as_ref(),
        )
        .map_err(|error| lifecycle_io("decode candidate lifecycle generation", error))?;
    Ok(observed)
}

fn install_artifacts_error(
    detail: impl Into<String>,
) -> household_rs::household_install_transaction::RequiredInstallArtifactsError {
    household_rs::household_install_transaction::RequiredInstallArtifactsError::new(detail)
}

fn cached_response_matches_request_fingerprint(
    cached: &[u8],
    expected: household_rs::household_install_transaction::FinalizeRequestFingerprintV1,
) -> bool {
    household_rs::household_install_transaction::FinalizeRequestFingerprintV1::for_canonical_request_bytes(
        cached,
    ) == expected
}

/// Resolve the exact candidate listener address anchored in an active
/// finalize terminal result.
///
/// The stable transaction already validates this request while decoding its
/// Prepared/Final records. Revalidation here keeps the network boundary
/// fail-closed and binds the request key to the terminal machine identity.
pub(crate) fn exact_terminal_replay_endpoint(
    terminal: &household_rs::household_install_transaction::FinalizeTerminalResult,
) -> Result<(String, JoinTransport), String> {
    let request: JoinRequest =
        household_rs::cbor::from_canonical_slice_strict(terminal.join_request_bytes())
            .map_err(|error| format!("decode terminal JoinRequest: {error}"))?;
    verify_join_request(&request)
        .map_err(|error| format!("verify terminal JoinRequest: {error}"))?;
    let m_pub: [u8; 33] = request
        .m_pub
        .as_ref()
        .try_into()
        .map_err(|_| "terminal JoinRequest m_pub has invalid length".to_string())?;
    let m_pub = household_rs::keys::P256PublicKey::from_bytes(&m_pub)
        .map_err(|error| format!("decode terminal JoinRequest m_pub: {error}"))?;
    if household_rs::derive_machine_id(&m_pub) != *terminal.m_id() {
        return Err("terminal JoinRequest differs from terminal machine identity".into());
    }
    Ok((request.addr, request.transport))
}

fn validate_terminal_join_request_binding(
    snapshot: &PairMachineWindowSnapshot,
    exact_join_request_bytes: &[u8],
) -> Result<JoinRequest, household_rs::household_install_transaction::RequiredInstallArtifactsError>
{
    let cached = snapshot
        .cached_join_request
        .as_ref()
        .ok_or_else(|| install_artifacts_error("pair window JoinRequest missing"))?;
    if cached.as_ref() != exact_join_request_bytes {
        return Err(install_artifacts_error(
            "pair window JoinRequest differs from terminal anchor",
        ));
    }
    let request: JoinRequest =
        household_rs::cbor::from_canonical_slice_strict(exact_join_request_bytes)
            .map_err(|error| install_artifacts_error(format!("terminal JoinRequest: {error}")))?;
    verify_join_request(&request)
        .map_err(|error| install_artifacts_error(format!("terminal JoinRequest: {error}")))?;
    if snapshot.addr_hint.as_deref() != Some(request.addr.as_str())
        || snapshot.m_pub.as_ref().map(std::convert::AsRef::as_ref) != Some(request.m_pub.as_ref())
        || snapshot.nonce.as_ref().map(std::convert::AsRef::as_ref) != Some(request.nonce.as_ref())
        || snapshot.transport != Some(request.transport)
    {
        return Err(install_artifacts_error(
            "pair window fields differ from terminal JoinRequest",
        ));
    }
    Ok(request)
}

/// Validate every authority artifact whose durable presence permits the
/// candidate install transaction to rotate G0 to its terminal G1.
pub(crate) fn validate_candidate_install_artifacts(
    state_dir: &Path,
    lifecycle: &LifecycleWriteGuard,
    key_policy: household_rs::KeyBackingPolicy,
    expected: &household_rs::household_install_transaction::HouseholdInstallExpectation,
) -> Result<(), household_rs::household_install_transaction::RequiredInstallArtifactsError> {
    lifecycle
        .verify_state_root(state_dir)
        .map_err(|error| install_artifacts_error(format!("state-root binding: {error}")))?;
    let record: household_rs::HouseholdRecord =
        household_rs::cbor::from_canonical_slice_strict(expected.commit_marker_bytes())
            .map_err(|error| install_artifacts_error(format!("commit marker: {error}")))?;
    if record.hh_id != *expected.expected_hh_id()
        || !record
            .members
            .iter()
            .any(|member| member == expected.expected_m_id())
    {
        return Err(install_artifacts_error("commit marker binding mismatch"));
    }
    let retained_ack: FinalizeAck =
        household_rs::cbor::from_canonical_slice_strict(expected.terminal_intent().ack_bytes())
            .map_err(|error| install_artifacts_error(format!("terminal Ack: {error}")))?;
    let self_m_id = household_rs::storage::read_self_m_id(state_dir)
        .map_err(|error| install_artifacts_error(format!("self_m_id read: {error}")))?;
    if self_m_id.as_deref() != Some(expected.expected_m_id().as_str()) {
        return Err(install_artifacts_error("self_m_id mismatch"));
    }
    for member in &record.members {
        let path = household_rs::storage::machine_cert_for(state_dir, member.as_str());
        let cert: household_rs::MachineCert = household_rs::storage::read_optional_cbor(&path)
            .map_err(|error| install_artifacts_error(format!("member cert read: {error}")))?
            .ok_or_else(|| install_artifacts_error(format!("member cert missing: {member}")))?;
        if cert.m_id != *member || cert.hh_id != record.hh_id {
            return Err(install_artifacts_error(format!(
                "member cert binding mismatch: {member}"
            )));
        }
        household_rs::machine_cert::verify_against_household_root(&cert, record.hh_pub.as_bytes())
            .map_err(|error| {
                install_artifacts_error(format!("member cert chain rejected ({member}): {error}"))
            })?;
        if member == expected.expected_m_id() {
            let cert_hash =
                household_rs::pair_machine::machine_cert_hash(&cert).map_err(|error| {
                    install_artifacts_error(format!("candidate cert hash: {error}"))
                })?;
            if retained_ack.m_id != member.as_str()
                || retained_ack.machine_cert_hash.as_ref() != cert_hash
            {
                return Err(install_artifacts_error(
                    "terminal Ack is not bound to the installed candidate cert",
                ));
            }
        }
    }

    let candidate_key = household_rs::ensure_candidate_machine_keypair(state_dir, key_policy)
        .map_err(|error| install_artifacts_error(format!("candidate key: {error}")))?;
    let candidate_pub = candidate_key.public();
    if household_rs::derive_machine_id(&candidate_pub) != *expected.expected_m_id() {
        return Err(install_artifacts_error("candidate key binding mismatch"));
    }
    let candidate_scalar = candidate_key
        .as_software_secret()
        .ok_or_else(|| install_artifacts_error("candidate scalar unavailable"))?;
    let shard_bytes = fs::read(shamir_self_shard_path(state_dir))
        .map_err(|error| install_artifacts_error(format!("self shard read: {error}")))?;
    let shard: household_rs::shard_at_rest::EncryptedShard =
        household_rs::cbor::from_canonical_slice_strict(&shard_bytes)
            .map_err(|error| install_artifacts_error(format!("self shard CBOR: {error}")))?;
    if shard.index != household_rs::shamir::SHARD_X_M2 {
        return Err(install_artifacts_error("candidate shard index is not M2"));
    }
    household_rs::shard_at_rest::decrypt_self(
        &shard,
        candidate_scalar,
        &candidate_pub,
        expected.expected_m_id().as_str(),
    )
    .map_err(|error| install_artifacts_error(format!("self shard decrypt: {error}")))?;

    let snapshot: PairMachineWindowSnapshot = household_rs::pair_window_namespace::PairWindowNamespaceV2::read_pair_machine_generation_under_lifecycle(
        state_dir.to_path_buf(),
        lifecycle,
        expected.candidate_generation(),
    )
        .map_err(|error| install_artifacts_error(format!("pair window read: {error}")))?
        .ok_or_else(|| install_artifacts_error("committed pair window missing"))?;
    if snapshot.state != PairMachineState::Committed {
        return Err(install_artifacts_error("pair window is not committed"));
    }
    let generation = snapshot
        .lifecycle_generation
        .as_ref()
        .ok_or_else(|| install_artifacts_error("pair window generation missing"))?;
    if generation.as_ref() != expected.candidate_generation().token_bytes() {
        return Err(install_artifacts_error("pair window generation mismatch"));
    }
    let _join_request = validate_terminal_join_request_binding(
        &snapshot,
        expected.terminal_intent().join_request_bytes(),
    )?;
    let cached = snapshot
        .cached_response
        .as_ref()
        .ok_or_else(|| install_artifacts_error("pair window response missing"))?;
    if !cached_response_matches_request_fingerprint(
        cached.as_ref(),
        expected.terminal_intent().request_fingerprint(),
    ) {
        return Err(install_artifacts_error(
            "cached response request fingerprint mismatch",
        ));
    }
    let response: JoinResponse =
        household_rs::cbor::from_canonical_slice_strict(cached.as_ref())
            .map_err(|error| install_artifacts_error(format!("cached response: {error}")))?;
    if response.join_request_hash.as_ref()
        != join_request_hash(expected.terminal_intent().join_request_bytes()).as_slice()
    {
        return Err(install_artifacts_error(
            "cached response is not bound to the terminal JoinRequest",
        ));
    }
    let response_record_bytes = household_rs::cbor::to_canonical_vec(&response.household_record)
        .map_err(|error| install_artifacts_error(format!("response record encode: {error}")))?;
    if response_record_bytes != expected.commit_marker_bytes()
        || response.machine_cert.m_id != *expected.expected_m_id()
    {
        return Err(install_artifacts_error("cached response binding mismatch"));
    }
    let (founder_cert, _) = verified_founder_cert_from_peer_list(
        &response,
        response.household_record.hh_pub.as_bytes(),
    )
    .ok_or_else(|| install_artifacts_error("cached response founder chain missing"))?;
    response
        .verify_response_sig(&founder_cert)
        .map_err(|error| install_artifacts_error(format!("cached response signature: {error}")))?;
    Ok(())
}

fn remove_install_path_durably(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("remove {}: {error}", path.display())),
    }
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| format!("fsync {}: {error}", parent.display()))?;
    }
    Ok(())
}

pub(crate) async fn rollback_partial_candidate_install(
    state_dir: &Path,
    lifecycle: &LifecycleWriteGuard,
    window: &PairMachineWindow,
    ticket: household_rs::household_install_transaction::HouseholdInstallRollbackTicket,
) -> Result<(), String> {
    let record: household_rs::HouseholdRecord =
        household_rs::cbor::from_canonical_slice_strict(ticket.expectation().commit_marker_bytes())
            .map_err(|error| format!("decode rollback marker: {error}"))?;
    let mut paths = vec![
        household_rs::storage::household_record_path(state_dir),
        household_rs::storage::self_m_id_marker_path(state_dir),
        shamir_self_shard_path(state_dir),
        owner_push_token_path(state_dir),
    ];
    paths.extend(
        record
            .members
            .iter()
            .map(|member| household_rs::storage::machine_cert_for(state_dir, member.as_str())),
    );
    for path in &paths {
        let staged = PathBuf::from(format!("{}.staged", path.display()));
        remove_install_path_durably(&staged)?;
        remove_install_path_durably(path)?;
    }
    window
        .clear_staged_snapshot_under_lifecycle(lifecycle)
        .map_err(|error| format!("clear staged pair window: {error}"))?;
    window
        .under_lifecycle(lifecycle)
        .return_to_idle()
        .await
        .map_err(|error| format!("abort pair window: {error}"))?;

    household_rs::household_install_transaction::complete_partial_install_rollback_under_lifecycle(
        lifecycle,
        ticket,
        |_| {
            for path in &paths {
                if path.exists() || PathBuf::from(format!("{}.staged", path.display())).exists() {
                    return Err(install_artifacts_error(format!(
                        "rollback residue: {}",
                        path.display()
                    )));
                }
            }
            let snapshot = window
                .read_persisted_snapshot_under_lifecycle(lifecycle)
                .map_err(|error| install_artifacts_error(error.to_string()))?
                .ok_or_else(|| install_artifacts_error("idle pair window missing"))?;
            if snapshot.state != PairMachineState::Idle {
                return Err(install_artifacts_error("pair window rollback is not idle"));
            }
            Ok(())
        },
    )
    .map_err(|error| format!("complete install rollback: {error}"))
}

/// Startup/retry driver for the stable install breadcrumb. Returns `true`
/// only when recovery terminally rotated the lifecycle generation, telling
/// the caller to reopen every generation-scoped capability before publish.
pub(crate) async fn recover_candidate_install_under_lifecycle(
    state_dir: &Path,
    lifecycle: &LifecycleWriteGuard,
    key_policy: household_rs::KeyBackingPolicy,
) -> Result<bool, String> {
    let rotated = match household_rs::household_install_transaction::recover_household_install_under_lifecycle(
        lifecycle,
        |expected| {
            validate_candidate_install_artifacts(
                state_dir,
                lifecycle,
                key_policy,
                expected,
            )
        },
    )
    .map_err(|error| format!("recover household install: {error}"))?
    {
        household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::NotApplicable => false,
        household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::PartialNeedsRollback(ticket) => {
            let window = PairMachineWindow::with_persistence_under_lifecycle(
                state_dir.to_path_buf(),
                lifecycle,
            )
            .map_err(|error| format!("open partial-install pair window: {error}"))?;
            rollback_partial_candidate_install(state_dir, lifecycle, &window, ticket).await?;
            false
        }
        household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::RotatedAndCleared { .. }
        | household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::AlreadyRotatedAndCleared { .. } => true,
    };

    // A crash can land after the breadcrumb is cleared but before the
    // install-specific bootstrap phase is published. Repair only early
    // onboarding states. Generic Recovering and Ready belong to independent
    // authority and are never rewritten merely because a historical terminal
    // result remains active.
    let active_terminal = household_rs::household_install_transaction::has_active_finalize_terminal_result_under_lifecycle(lifecycle)
        .map_err(|error| format!("inspect active finalize result: {error}"))?;
    if active_terminal {
        let current = bootstrap_state::load(state_dir)
            .map_err(|error| format!("load install bootstrap state: {error}"))?;
        if matches!(
            current,
            BootstrapState::Uninitialized
                | BootstrapState::ReadyForNaming
                | BootstrapState::NamedAwaitingPair
        ) {
            bootstrap_state::persist(state_dir, BootstrapState::PairMachineInstallRestartRequired)
                .map_err(|error| format!("persist install restart state: {error}"))?;
            lifecycle
                .sync_state_root()
                .map_err(|error| format!("fsync install restart state: {error}"))?;
        }
    }
    Ok(rotated)
}

async fn persist_ready_then_publish<F>(
    guard: &LifecycleWriteGuard,
    state_dir: &Path,
    expected_generation: household_rs::household_lifecycle::HouseholdLifecycleGenerationV1,
    publish: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()>,
{
    bootstrap_state::persist_ready_under_lifecycle(guard, state_dir, expected_generation)
        .map_err(|error| lifecycle_io("persist pair-machine ready state", error))?;
    publish.await;
    Ok(())
}

async fn persist_bootstrap_state_then_publish<F>(
    guard: &LifecycleWriteGuard,
    state_dir: &Path,
    next: BootstrapState,
    publish: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()>,
{
    bootstrap_state::persist(state_dir, next)
        .map_err(|error| lifecycle_io("persist pair-machine bootstrap state", error))?;
    guard
        .sync_state_root()
        .map_err(|error| lifecycle_io("fsync pair-machine bootstrap state", error))?;
    publish.await;
    Ok(())
}

async fn persist_install_restart_required_then_signal(
    guard: &LifecycleWriteGuard,
    state: &PreHouseholdRouterState,
) -> std::io::Result<()> {
    let current = bootstrap_state::load(&state.state_dir)
        .map_err(|error| lifecycle_io("read pair-machine bootstrap state", error))?;
    match current {
        BootstrapState::Uninitialized
        | BootstrapState::ReadyForNaming
        | BootstrapState::NamedAwaitingPair => {
            let bootstrap = state.bootstrap.clone();
            persist_bootstrap_state_then_publish(
                guard,
                &state.state_dir,
                BootstrapState::PairMachineInstallRestartRequired,
                async move {
                    if let Some(bs_lock) = bootstrap {
                        *bs_lock.write().await = BootstrapState::PairMachineInstallRestartRequired;
                    }
                },
            )
            .await?;
        }
        BootstrapState::PairMachineInstallRestartRequired | BootstrapState::Ready => {
            // Idempotent repair/retry. Ready must never be downgraded by a
            // stale G0 router whose retained terminal result is still active.
        }
        BootstrapState::Recovering => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "generic fail-stop recovery state is not pair-machine delivery authority",
            ));
        }
    }

    Ok(())
}

async fn terminal_install_restart_response(
    guard: &LifecycleWriteGuard,
    state: &PreHouseholdRouterState,
) -> Response {
    if let Err(error) = persist_install_restart_required_then_signal(guard, state).await {
        tracing::error!(
            stage = "pair_machine.local_finalize.restart_signal_failed",
            error = %error,
            hint = "terminal result is durable; fail-stop until a cold restart recovers it",
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    runtime_signaled_cbor_response(
        StatusCode::SERVICE_UNAVAILABLE,
        household_rs::pair_machine::FinalizeRestartRequired::new()
            .to_canonical_bytes()
            .unwrap_or_default(),
        state.runtime_signal.clone(),
        PreHouseholdRuntimeSignal::RestartRequired,
        true,
    )
}

/// State threaded into the `POST /api/v1/household/join-request`
/// handler and (later) the candidate's `local/seed` endpoint when
/// Story 2 lands. The router-side type carries `PairMachineState` (the
/// protocol-state enum imported above) only via the wrapped `PairMachineWindow`.
#[derive(Clone)]
pub struct PairMachineRouterState {
    pub window: Arc<PairMachineWindow>,
    pub household: HouseholdState,
    pub event_log: Arc<OwnerEventLog>,
    pub event_broadcaster: OwnerEventsBroadcaster,
    pub state_dir: PathBuf,
}

/// State for M2's pre-household listener (CLI `theyos install
/// --pair-machine` path) AND for the daemon-mounted `/pair-machine/local/*`
/// routes wired in `household_bootstrap::bootstrap_household`.
///
/// On the CLI path the process has no household identity yet, so
/// `bootstrap` is `None` — the candidate's own install path is the
/// pre-household phase by construction. On the daemon path we plumb
/// the live `BootstrapState` lock so `local_finalize_handler` can
/// re-check the engine has not transitioned into Ready/Recovering
/// while it was waiting on `BOOTSTRAP_MUTATION_LOCK`.
///
/// Single-flight anchor/finalize serialisation is now handled by
/// `bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK` (acquired in
/// `local_anchor_handler` and `local_finalize_handler`) rather than a
/// per-instance mutex; the shared lock also covers `stage()` and
/// `accept_household_confirm`, closing both the QR-regeneration race
/// around anchor pinning and the TOCTOU window where identity writers
/// could race `household_record.cbor` / `machine_cert.cbor` /
/// the self-shard.
#[derive(Clone)]
pub struct PreHouseholdRouterState {
    pub window: Arc<PairMachineWindow>,
    pub state_dir: PathBuf,
    pub key_policy: household_rs::KeyBackingPolicy,
    /// Live engine bootstrap state lock when running inside the daemon;
    /// `None` on the CLI install path, where success is delivered through the
    /// typed restart signal instead of hot-publishing daemon state.
    pub bootstrap: Option<Arc<tokio::sync::RwLock<BootstrapState>>>,
    /// Control-plane notification used only by the one-shot install CLI.
    ///
    /// A successful candidate install rotates the lifecycle generation. The
    /// router that performed that rotation still owns G0-scoped capabilities,
    /// so it must never hot-publish Ready or an Ack. Instead it durably records
    /// `Recovering`, sends this signal after the G1 terminal result is durable,
    /// and lets the CLI tear down every G0 capability before a cold start.
    pub runtime_signal: Option<tokio::sync::watch::Sender<PreHouseholdRuntimeSignal>>,
}

/// One-shot control-plane state for the pre-household install listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreHouseholdRuntimeSignal {
    Running,
    RestartRequired,
    /// A cold G1 listener has selected the exact retained Ack response. The
    /// CLI may begin graceful shutdown, which waits for the in-flight HTTP
    /// response to flush before exiting.
    AckDeliveryStarted,
}

pub fn pre_household_router(state: PreHouseholdRouterState) -> Router {
    Router::new()
        .route("/pair-machine/anchor-handoff", get(anchor_handoff_handler))
        .route("/pair-machine/local/seed", get(local_seed_handler))
        .route("/pair-machine/local/anchor", post(local_anchor_handler))
        .route("/pair-machine/local/finalize", post(local_finalize_handler))
        .fallback(pre_household_reject)
        .with_state(state)
}

/// Minimal retained-terminal surface used on the exact candidate address
/// after install rotation.
///
/// The Ready household router is intentionally not exposed on LAN. This
/// dedicated router keeps only the byte-identical finalize replay reachable
/// across the ambiguous crash window where Ready is durable but the Ack may
/// not yet have reached the founder.
pub fn terminal_replay_router(state: PreHouseholdRouterState) -> Router {
    Router::new()
        .route("/pair-machine/local/finalize", post(local_finalize_handler))
        .fallback(pre_household_reject)
        .with_state(state)
}

fn bootstrap_allows_local_pair_machine(bs: BootstrapState) -> bool {
    matches!(
        bs,
        BootstrapState::Uninitialized | BootstrapState::ReadyForNaming
    )
}

/// `JoinRequestAccepted = {v=1, owner_event_cursor: uint, expiry: uint}` —
/// success body for the join-request endpoint per `contracts/join-request.md`.
#[derive(Serialize)]
struct JoinRequestAccepted {
    #[serde(rename = "v")]
    version: u8,
    owner_event_cursor: u64,
    expiry: u64,
}

/// `LocalAnchor` — the iPhone-delivered trust anchor body per
/// `contracts/local-anchor.md` (B7).
///
/// The wire body carries only what the candidate uses to pin the
/// household identity: `anchor_secret` (the QR-only authenticator),
/// `hh_id`, and `hh_pub`. The owner's `PersonCert` is intentionally
/// omitted — it would be dead weight on the wire (the candidate has
/// no `hh_priv` to validate it against during anchor pinning, and the
/// `anchor_secret` itself is already the gate). Logging the
/// post-anchor identity uses the pinned `hh_id`/`hh_pub` directly.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct LocalAnchor {
    #[serde(rename = "v")]
    version: u8,
    anchor_secret: serde_bytes::ByteBuf,
    hh_id: String,
    hh_pub: serde_bytes::ByteBuf,
}

impl LocalAnchor {
    fn to_canonical_bytes(&self) -> Result<Vec<u8>, household_rs::HouseholdError> {
        household_rs::cbor::to_canonical_vec(self)
    }
}

#[derive(serde::Serialize)]
struct LocalAnchorAck {
    #[serde(rename = "v")]
    version: u8,
}

/// Generic-failure body — deterministic CBOR `{v=1, error="unauthenticated"}`
/// per R14 / FR-019a. Returned for every join-request failure mode.
#[derive(Serialize)]
struct GenericUnauth<'a> {
    #[serde(rename = "v")]
    version: u8,
    error: &'a str,
}

fn restart_required_response() -> Response {
    let body = household_rs::pair_machine::FinalizeRestartRequired::new()
        .to_canonical_bytes()
        .unwrap_or_default();
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [
            (header::CONTENT_TYPE, CBOR_CONTENT_TYPE),
            (header::RETRY_AFTER, "1"),
        ],
        body,
    )
        .into_response()
}

/// Build a response whose one-shot runtime notification fires only when Hyper
/// polls the body for delivery. The install CLI reacts by starting graceful
/// shutdown; Axum then keeps the connection alive until this in-flight body is
/// fully written instead of aborting between handler return and socket flush.
fn runtime_signaled_cbor_response(
    status: StatusCode,
    bytes: Vec<u8>,
    signal: Option<tokio::sync::watch::Sender<PreHouseholdRuntimeSignal>>,
    value: PreHouseholdRuntimeSignal,
    retry_after: bool,
) -> Response {
    let mut response = if let Some(signal) = signal {
        let stream = futures_util::stream::once(async move {
            signal.send(value).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "pre-household runtime receiver disappeared before response delivery",
                )
            })?;
            Ok::<Bytes, std::io::Error>(Bytes::from(bytes))
        });
        let mut response = Response::new(Body::from_stream(stream));
        *response.status_mut() = status;
        response
    } else {
        cbor_response(status, bytes)
    };
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    if retry_after {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    response
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinSource {
    OwnerQr,
    Bonjour,
}

impl JoinSource {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OwnerQr => "owner_qr",
            Self::Bonjour => "bonjour",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FounderStageAccepted {
    pub owner_event_cursor: u64,
    pub expiry: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FounderStageOutcome {
    Accepted(FounderStageAccepted),
    Replay(Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FounderStageError;

fn cbor_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut resp = (status, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    resp
}

fn unauthenticated_response() -> Response {
    let bytes = household_rs::cbor::to_canonical_vec(&GenericUnauth {
        version: 1,
        error: "unauthenticated",
    })
    .unwrap_or_default();
    cbor_response(StatusCode::UNAUTHORIZED, bytes)
}

async fn pre_household_reject() -> Response {
    unauthenticated_response()
}

/// `GET /pair-machine/anchor-handoff` — Tailnet-gated anchor secret delivery.
///
/// Eliminates QR scan when both candidate and owner-iPhone are on the same
/// Tailnet. Caller MUST originate from a Tailnet IP (`100.64.0.0/10` or
/// `fd00::/8` ULA); all other sources receive 403 with no probing oracle.
///
/// Contract: `specs/005-soyeht-onboarding/contracts/anchor-handoff.md`
pub async fn anchor_handoff_handler(
    State(state): State<PreHouseholdRouterState>,
    req: axum::extract::Request,
) -> Response {
    let t0 = Instant::now();
    // 1. Source IP check — Tailnet CGNAT or ULA only.
    // ConnectInfo is injected by `into_make_service_with_connect_info` in
    // production; in tests, inject it directly via `.extension(ConnectInfo(...))`.
    let is_tailnet = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|ci| classify_source(ci.0.ip()) == DiscoverySource::Tailnet);
    if !is_tailnet {
        let bytes = anchor_cbor_error("tailnet_required");
        return (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)],
            bytes,
        )
            .into_response();
    }

    // 2. Load window snapshot.
    let snap = state.window.snapshot().await;

    // 3. State gate.
    match snap.state {
        PairMachineState::Idle => {
            let bytes = anchor_cbor_error("no_active_pair_machine");
            return (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)],
                bytes,
            )
                .into_response();
        }
        PairMachineState::Committed | PairMachineState::Aborted => {
            let bytes = anchor_cbor_error("window_terminated");
            return (
                StatusCode::GONE,
                [(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)],
                bytes,
            )
                .into_response();
        }
        PairMachineState::Staging | PairMachineState::AwaitingOwner => {}
    }

    // 4. Expiry check.
    if let Some(expiry) = snap.expiry {
        let now = time_util::unix_now_secs_checked("anchor_handoff.clock").unwrap_or(u64::MAX);
        if now >= expiry {
            let bytes = anchor_cbor_error("window_terminated");
            return (
                StatusCode::GONE,
                [(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)],
                bytes,
            )
                .into_response();
        }
    }

    // 5. Extract required fields (all populated when window is Staging/AwaitingOwner).
    let (Some(m_pub), Some(nonce), Some(anchor_secret)) = (
        snap.m_pub.as_ref(),
        snap.nonce.as_ref(),
        snap.anchor_secret.as_ref(),
    ) else {
        tracing::warn!(
            stage = "anchor_handoff.missing_fields",
            state = ?snap.state,
        );
        let bytes = anchor_cbor_error("no_active_pair_machine");
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)],
            bytes,
        )
            .into_response();
    };

    let fingerprint = snap.fingerprint.as_deref().unwrap_or("").to_string();
    let expires_at = snap.expiry.unwrap_or(0);

    // u128→u64 truncation impossible in practice (u64 covers ~585 millennia).
    #[allow(clippy::cast_possible_truncation)]
    let elapsed_ms = t0.elapsed().as_millis() as u64;
    tracing::info!(stage = "anchor_handoff.served", expires_at, elapsed_ms,);

    let body = AnchorHandoffResponse {
        v: 1,
        m_pub: ByteBuf::from(m_pub.to_vec()),
        nonce: ByteBuf::from(nonce.to_vec()),
        anchor_secret: ByteBuf::from(anchor_secret.to_vec()),
        fingerprint,
        expires_at,
    };
    match household_rs::cbor::to_canonical_vec(&body) {
        Ok(bytes) => cbor_response(StatusCode::OK, bytes),
        Err(e) => {
            tracing::error!(stage = "anchor_handoff.encode_failed", error = %e);
            let bytes = anchor_cbor_error("internal_error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)],
                bytes,
            )
                .into_response()
        }
    }
}

#[derive(Serialize)]
struct AnchorHandoffResponse {
    v: u8,
    m_pub: ByteBuf,
    nonce: ByteBuf,
    anchor_secret: ByteBuf,
    fingerprint: String,
    expires_at: u64,
}

#[derive(Serialize)]
struct AnchorHandoffError {
    v: u8,
    error: &'static str,
}

fn anchor_cbor_error(error: &'static str) -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&AnchorHandoffError { v: 1, error }).unwrap_or_default()
}

/// `GET /pair-machine/local/seed?nonce=<base32-short>`.
///
/// Used by Story 2 discovery so M1 can fetch the exact signed `JoinRequest` bytes
/// cached by the candidate install path.
pub async fn local_seed_handler(
    State(state): State<PreHouseholdRouterState>,
    uri: Uri,
) -> Response {
    let Some(supplied_nonce) = query_param(&uri, "nonce") else {
        return unauthenticated_response();
    };
    let snap = state.window.snapshot().await;
    // Accept both `Staging` and `AwaitingOwner` per
    // `contracts/local-anchor.md` §"State gate". `AwaitingOwner` is the
    // protocol-correct state once the owner-event has been appended;
    // refusing it here would prevent M1's recovery probe (T073) from
    // re-fetching the cached `JoinRequest` after a daemon restart, and
    // would force the iPhone to race the owner-event append.
    if !matches!(
        snap.state,
        PairMachineState::Staging | PairMachineState::AwaitingOwner
    ) {
        return unauthenticated_response();
    }
    let Some(nonce) = snap.nonce.as_ref() else {
        return unauthenticated_response();
    };
    if nonce.len() < 8 {
        return unauthenticated_response();
    }
    let expected = household_rs::ids::base32_lower_nopad_encode(&nonce.as_ref()[..8]);
    if supplied_nonce != expected {
        return unauthenticated_response();
    }
    let Some(cached) = snap.cached_join_request.as_ref() else {
        return unauthenticated_response();
    };
    cbor_response(StatusCode::OK, cached.to_vec())
}

/// `POST /pair-machine/local/anchor`.
///
/// External trust anchor delivered by the owner iPhone after the human
/// owner has approved the join (B7 / `contracts/local-anchor.md`). The
/// iPhone authenticates by presenting `anchor_secret` from the QR;
/// constant-time comparison against `pair_machine_window.anchor_secret`
/// gates the pin. Idempotent on identical re-pinning; divergent
/// re-pinning is refused.
pub async fn local_anchor_handler(
    State(state): State<PreHouseholdRouterState>,
    body: Bytes,
) -> Response {
    use household_rs::cbor::from_canonical_slice;
    use subtle::ConstantTimeEq;
    let t0 = Instant::now();

    let anchor: LocalAnchor = match from_canonical_slice(&body) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(
                stage = "pair_machine.local_anchor.rejected",
                reason = "cbor_decode",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    match anchor.to_canonical_bytes() {
        Ok(canonical) if canonical == body.as_ref() => {}
        _ => {
            tracing::warn!(
                stage = "pair_machine.local_anchor.rejected",
                reason = "non_canonical_cbor",
            );
            return unauthenticated_response();
        }
    }
    if anchor.version != 1 {
        return unauthenticated_response();
    }
    if anchor.anchor_secret.len() != 32 {
        return unauthenticated_response();
    }
    let Ok(hh_pub_arr) = <[u8; 33]>::try_from(anchor.hh_pub.as_ref()) else {
        return unauthenticated_response();
    };
    let Ok(hh_pub_key) = household_rs::keys::P256PublicKey::from_bytes(&hh_pub_arr) else {
        return unauthenticated_response();
    };
    let derived_hh_id = household_rs::derive_household_id(&hh_pub_key);
    if derived_hh_id.to_string() != anchor.hh_id {
        tracing::warn!(
            stage = "pair_machine.local_anchor.rejected",
            reason = "hh_id_derivation_mismatch",
        );
        return unauthenticated_response();
    }

    // Serialise anchor pinning with `stage()` and `local/finalize`.
    // Without this, a stale QR can pass the anchor-secret check against an
    // old snapshot, then pin that old household anchor onto a freshly
    // regenerated `PairMachineWindow`.
    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;

    let lifecycle_state_dir = state.state_dir.clone();
    let lifecycle_guard = match tokio::task::spawn_blocking(move || {
        acquire_pair_lifecycle_exclusive(&lifecycle_state_dir)
    })
    .await
    {
        Ok(Ok(guard)) => guard,
        Ok(Err(error)) => {
            tracing::warn!(
                stage = "pair_machine.local_anchor.lifecycle_failed",
                error = %error,
            );
            return unauthenticated_response();
        }
        Err(error) => {
            tracing::warn!(
                stage = "pair_machine.local_anchor.lifecycle_task_failed",
                error = %error,
            );
            return unauthenticated_response();
        }
    };
    if let Err(error) = verify_household_absent_for_candidate(&lifecycle_guard, &state.state_dir) {
        tracing::warn!(
            stage = "pair_machine.local_anchor.rejected",
            reason = "installed_household_present",
            error = %error,
        );
        return unauthenticated_response();
    }

    if let Some(bs_lock) = state.bootstrap.as_ref() {
        let bs = *bs_lock.read().await;
        if !bootstrap_allows_local_pair_machine(bs) {
            tracing::warn!(
                stage = "pair_machine.local_anchor.rejected",
                reason = "bootstrap_state_advanced",
                state = bs.as_str(),
            );
            return unauthenticated_response();
        }
    }

    let snap = state.window.snapshot().await;
    if !matches!(
        snap.state,
        PairMachineState::Staging | PairMachineState::AwaitingOwner
    ) {
        return unauthenticated_response();
    }
    if let Err(error) = verify_candidate_lifecycle_generation(&lifecycle_guard, &snap) {
        tracing::warn!(
            stage = "pair_machine.local_anchor.rejected",
            reason = "lifecycle_generation_mismatch",
            error = %error,
        );
        return unauthenticated_response();
    }
    let Some(window_secret) = snap.anchor_secret.as_ref() else {
        // Window was opened by the founder-side staging path
        // (Story 2 fetched JoinRequest), which has no candidate
        // anchor secret to gate against. The candidate's own install
        // path always sets `Some` so this branch only applies to
        // founder-side windows that should never receive
        // `local/anchor`.
        return unauthenticated_response();
    };
    if window_secret.len() != 32 {
        return unauthenticated_response();
    }
    // Constant-time compare across the 32-byte secrets.
    if anchor
        .anchor_secret
        .ct_eq(window_secret.as_ref())
        .unwrap_u8()
        != 1
    {
        tracing::warn!(
            stage = "pair_machine.local_anchor.rejected",
            reason = "anchor_secret_mismatch",
        );
        return unauthenticated_response();
    }
    if let Err(e) = state
        .window
        .under_lifecycle(&lifecycle_guard)
        .pin_household_anchor(anchor.hh_id.clone(), hh_pub_arr)
        .await
    {
        match e {
            household_rs::pair_machine::WindowError::MismatchedCeremony => {
                tracing::warn!(
                    stage = "pair_machine.local_anchor.rejected",
                    reason = "divergent_pin",
                );
            }
            other => {
                tracing::warn!(
                    stage = "pair_machine.local_anchor.rejected",
                    reason = "pin_failed",
                    error = %other,
                );
            }
        }
        return unauthenticated_response();
    }
    // u128→u64 truncation impossible in practice (u64 covers ~585 millennia).
    #[allow(clippy::cast_possible_truncation)]
    let elapsed_ms = t0.elapsed().as_millis() as u64;
    tracing::info!(
        stage = "pair_machine.local_anchor.accepted",
        hh_id = %anchor.hh_id,
        elapsed_ms,
    );
    let bytes =
        household_rs::cbor::to_canonical_vec(&LocalAnchorAck { version: 1 }).unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /pair-machine/local/finalize`.
///
/// M2 validates the `JoinResponse`, unwraps the peer-delivered shard, rewraps
/// it for local at-rest storage, and atomically commits the post-join files.
pub async fn local_finalize_handler(
    State(state): State<PreHouseholdRouterState>,
    body: Bytes,
) -> Response {
    let t0 = Instant::now();
    // Serialise finalize with every other bootstrap-mutation writer
    // (`accept_household`, `accept_household_confirm`, `pair_machine_local
    // stage`). Acquiring the shared lock BEFORE reading the window
    // snapshot and BEFORE re-validating bootstrap state means a
    // concurrent `accept_household_confirm` cannot land mid-finalize and
    // overwrite the candidate's `household_record.cbor` /
    // `machine_cert.cbor` / self-shard. The lock is dropped at the end
    // of the handler (after `staged.commit()` and the bootstrap-state
    // persist).
    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;

    // Cross-process lifecycle ordering is mutation lock -> lifecycle
    // exclusive -> PairMachineWindow/bootstrap state -> stores. Acquire before
    // reading either process-local state so a stale daemon cannot mutate a
    // replacement household after teardown.
    let lifecycle_state_dir = state.state_dir.clone();
    let lifecycle_guard = match tokio::task::spawn_blocking(move || {
        acquire_pair_lifecycle_exclusive(&lifecycle_state_dir)
    })
    .await
    {
        Ok(Ok(guard)) => guard,
        Ok(Err(error)) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.lifecycle_failed",
                error = %error,
            );
            return unauthenticated_response();
        }
        Err(error) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.lifecycle_task_failed",
                error = %error,
            );
            return unauthenticated_response();
        }
    };

    // The exact request fingerprint is the stable retry key. Decode and prove
    // canonical CBOR before consulting the terminal-result store; a caller
    // cannot use a non-canonical alias to retrieve an Ack.
    let request_fingerprint = household_rs::household_install_transaction::FinalizeRequestFingerprintV1::for_canonical_request_bytes(
        body.as_ref(),
    );
    let response: JoinResponse = match household_rs::cbor::from_canonical_slice(&body) {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "cbor_decode",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    match response.to_canonical_bytes() {
        Ok(canonical) if canonical == body.as_ref() => {}
        Ok(_) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "non_canonical_cbor",
            );
            return unauthenticated_response();
        }
        Err(e) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "cbor_reencode",
                error = %e,
            );
            return unauthenticated_response();
        }
    }
    if response.version != 1 {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "bad_version",
            version = response.version,
        );
        return unauthenticated_response();
    }

    // This lookup deliberately precedes both the bootstrap-state gate and the
    // process-local window shortcuts. A cold G1 process must be able to serve
    // the exact retained Ack even when bootstrap state is Recovering/Ready;
    // conversely a stale G0 process must never infer authority from its cached
    // window after the durable lifecycle has rotated to G1.
    let terminal_lookup =
        match household_rs::household_install_transaction::lookup_finalize_terminal_result_under_lifecycle(
            &lifecycle_guard,
            request_fingerprint,
            &response.household_record.hh_id,
            &response.machine_cert.m_id,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::error!(
                    stage = "pair_machine.local_finalize.terminal_lookup_failed",
                    error = %error,
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
    match terminal_lookup {
        household_rs::household_install_transaction::FinalizeTerminalLookupOutcome::Divergent => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "terminal_request_diverged",
            );
            return unauthenticated_response();
        }
        household_rs::household_install_transaction::FinalizeTerminalLookupOutcome::Exact(
            terminal,
        ) => {
            let retained_generation =
                match retained_window_lifecycle_generation(&state.window.snapshot().await) {
                    Ok(generation) => generation,
                    Err(error) => {
                        tracing::error!(
                            stage = "pair_machine.local_finalize.window_generation_unavailable",
                            error = %error,
                        );
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                };
            if &retained_generation != terminal.terminal_generation() {
                tracing::warn!(
                    stage = "pair_machine.local_finalize.restart_required",
                    reason = "router_generation_is_stale",
                );
                return terminal_install_restart_response(&lifecycle_guard, &state).await;
            }
            let current_generation = match lifecycle_guard.lifecycle_generation() {
                Ok(Some(generation)) => generation,
                Ok(None) => {
                    tracing::error!(
                        stage = "pair_machine.local_finalize.terminal_generation_missing",
                    );
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                Err(error) => {
                    tracing::error!(
                        stage = "pair_machine.local_finalize.terminal_generation_read_failed",
                        error = %error,
                    );
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            if &current_generation != terminal.terminal_generation() {
                tracing::error!(stage = "pair_machine.local_finalize.terminal_generation_changed",);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            // Name the ambiguous delivery cut durably before Ready or any
            // response body can become visible. The record embeds the entire
            // validated terminal result (including the exact signed endpoint)
            // and is accepted only under this same lifecycle generation.
            match household_rs::household_install_transaction::prepare_finalize_ack_delivery_under_lifecycle(
                &lifecycle_guard,
                &terminal,
            ) {
                Ok(household_rs::household_install_transaction::FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(retained))
                    if retained.as_ref() == terminal.as_ref() => {}
                Ok(_) => {
                    tracing::error!(stage = "pair_machine.local_finalize.delivery_breadcrumb_mismatch");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                Err(error) => {
                    tracing::error!(
                        stage = "pair_machine.local_finalize.delivery_breadcrumb_failed",
                        error = %error,
                    );
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }

            #[cfg(any(test, feature = "failure-injection"))]
            {
                match crate::failure_injection::apply(
                    crate::failure_injection::InjectionPoint::M2AfterAckDeliveryBreadcrumb,
                )
                .await
                {
                    crate::failure_injection::Outcome::EarlyReject(_) => {
                        return unauthenticated_response();
                    }
                    crate::failure_injection::Outcome::Skip
                    | crate::failure_injection::Outcome::Continue => {}
                }
            }

            let persisted_bootstrap = match bootstrap_state::load(&state.state_dir) {
                Ok(value) => value,
                Err(error) => {
                    tracing::error!(
                        stage = "pair_machine.local_finalize.bootstrap_state_read_failed",
                        error = %error,
                    );
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            match persisted_bootstrap {
                BootstrapState::PairMachineInstallRestartRequired => {
                    // One-time delivery application. The non-authoritative
                    // address hint is written before Ready; a crash retries it
                    // idempotently. Ready is the durable applied phase, so all
                    // later exact replays return only retained Ack bytes.
                    cache_known_peer_addrs(&state.state_dir, &response);
                    let bootstrap = state.bootstrap.clone();
                    if let Err(error) = persist_ready_then_publish(
                        &lifecycle_guard,
                        &state.state_dir,
                        *terminal.terminal_generation(),
                        async move {
                            if let Some(bs_lock) = bootstrap {
                                *bs_lock.write().await = BootstrapState::Ready;
                            }
                        },
                    )
                    .await
                    {
                        tracing::warn!(
                            stage = "pair_machine.local_finalize.bootstrap_state_persist_failed",
                            error = %error,
                            hint = "terminal result retained; refusing Ack until durable Ready is repaired",
                        );
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                }
                BootstrapState::Ready => {
                    // Byte-only replay. Do not rewrite known-peer hints or any
                    // bootstrap state for the rest of this installation.
                }
                BootstrapState::Recovering
                | BootstrapState::Uninitialized
                | BootstrapState::ReadyForNaming
                | BootstrapState::NamedAwaitingPair => {
                    tracing::error!(
                        stage = "pair_machine.local_finalize.delivery_state_invalid",
                        state = persisted_bootstrap.as_str(),
                    );
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }

            #[cfg(any(test, feature = "failure-injection"))]
            {
                match crate::failure_injection::apply(
                    crate::failure_injection::InjectionPoint::M2BeforeAckEncode,
                )
                .await
                {
                    crate::failure_injection::Outcome::EarlyReject(_) => {
                        return unauthenticated_response();
                    }
                    crate::failure_injection::Outcome::Skip
                    | crate::failure_injection::Outcome::Continue => {}
                }
            }

            println!("{POST_COMMIT_REDUNDANCY_NOTICE}");
            #[allow(clippy::cast_possible_truncation)]
            let elapsed_ms = t0.elapsed().as_millis() as u64;
            tracing::info!(
                stage = "pair_machine.local_finalize.terminal_ack_replayed",
                elapsed_ms,
            );
            let mut response = runtime_signaled_cbor_response(
                StatusCode::OK,
                terminal.ack_bytes().to_vec(),
                state.runtime_signal.clone(),
                PreHouseholdRuntimeSignal::AckDeliveryStarted,
                false,
            );
            let port = crate::household_bootstrap::household_port_from_env();
            if let Some(addr) = candidate_tailnet_addr(port, current_tailnet_ipv4)
                && let Ok(value) = HeaderValue::from_str(&addr)
            {
                response
                    .headers_mut()
                    .insert(FINALIZE_CANDIDATE_TAILSCALE_ADDR_HEADER, value);
            }
            return response;
        }
        household_rs::household_install_transaction::FinalizeTerminalLookupOutcome::Absent => {}
    }

    // First-attempt daemon path only: re-check engine bootstrap state inside
    // the critical section. Exact terminal-result replay already returned
    // above, so Ready/Recovering here means a new or divergent request and is
    // rejected. The CLI path uses the durable terminal result plus its typed
    // restart signal instead of a live bootstrap state machine.
    if let Some(bs_lock) = state.bootstrap.as_ref() {
        let bs = *bs_lock.read().await;
        if !bootstrap_allows_local_pair_machine(bs) {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "bootstrap_state_advanced",
                state = bs.as_str(),
            );
            return unauthenticated_response();
        }
    }

    let snap = state.window.snapshot().await;
    if matches!(snap.state, PairMachineState::Committed) {
        tracing::error!(
            stage = "pair_machine.local_finalize.restart_required",
            reason = "committed_window_without_active_terminal_result",
        );
        return restart_required_response();
    }
    if !matches!(
        snap.state,
        PairMachineState::Staging | PairMachineState::AwaitingOwner
    ) {
        return unauthenticated_response();
    }
    let candidate_generation = match verify_candidate_lifecycle_generation(&lifecycle_guard, &snap)
    {
        Ok(generation) => generation,
        Err(error) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "lifecycle_generation_mismatch",
                error = %error,
            );
            return unauthenticated_response();
        }
    };

    // CBOR-shape check (`join_request_hash`) — bind this response to the
    // exact `JoinRequest` cached on the candidate, regardless of the
    // contents of the rest of the body. Per `contracts/local-anchor.md`,
    // this runs BEFORE the external-anchor gate so the anchor gate is
    // applied to a response that is already shape-checked.
    let Some(cached_join_request) = snap.cached_join_request.as_ref() else {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "missing_cached_join_request",
        );
        return unauthenticated_response();
    };
    let expected_join_request_hash = join_request_hash(cached_join_request.as_ref());
    if response.join_request_hash.as_ref() != expected_join_request_hash.as_slice() {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "join_request_hash_mismatch",
        );
        return unauthenticated_response();
    }
    // External-anchor gate (B7 / contracts/local-anchor.md). The
    // `JoinResponse` is otherwise self-contained: an attacker on the
    // network can mint their own household root, forge a founder
    // cert, encrypt a shard for the candidate's `m_pub` (publicly
    // known via `local/seed`), sign the response, and POST it — every
    // internal cross-check passes. The fix is to require the iPhone
    // to deliver `(hh_id, hh_pub)` ahead of finalize via
    // `POST /pair-machine/local/anchor`, authenticated by the
    // QR-only `anchor_secret`. The candidate refuses to accept any
    // `JoinResponse` whose household identity does not bit-equal
    // the pinned anchor. Runs AFTER `join_request_hash` and BEFORE
    // any cert-chain verification per the contract sequence.
    let Some(pinned_hh_pub) = snap.pinned_hh_pub.as_ref() else {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "trust_anchor_missing",
            hint = "iPhone has not delivered POST /pair-machine/local/anchor yet",
        );
        return unauthenticated_response();
    };
    if pinned_hh_pub.as_ref() != response.household_record.hh_pub.as_bytes() {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "trust_anchor_hh_pub_mismatch",
        );
        return unauthenticated_response();
    }
    if snap
        .pinned_hh_id
        .as_deref()
        .is_none_or(|id| id != response.household_record.hh_id.as_str())
    {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "trust_anchor_hh_id_mismatch",
        );
        return unauthenticated_response();
    }
    if let Err(e) = response.household_record.validate() {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "record_invalid",
            error = %e,
        );
        return unauthenticated_response();
    }
    if let Err(error) = verify_installed_household_for_finalize(
        &lifecycle_guard,
        &state.state_dir,
        response.household_record.hh_id.as_str(),
    ) {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "installed_household_changed",
            error = %error,
        );
        return unauthenticated_response();
    }
    let Ok(trust_hh_pub) = <&[u8; 33]>::try_from(pinned_hh_pub.as_ref()) else {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "trust_anchor_hh_pub_length",
        );
        return unauthenticated_response();
    };
    if let Err(e) = household_rs::machine_cert::verify_against_household_root(
        &response.machine_cert,
        trust_hh_pub,
    ) {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "candidate_cert_invalid",
            error = %e,
        );
        return unauthenticated_response();
    }

    let candidate_key =
        match household_rs::ensure_candidate_machine_keypair(&state.state_dir, state.key_policy) {
            Ok(key) => key,
            Err(e) => {
                tracing::warn!(
                    stage = "pair_machine.local_finalize.rejected",
                    reason = "candidate_key_unavailable",
                    error = %e,
                );
                return unauthenticated_response();
            }
        };
    let candidate_pub = candidate_key.public();
    let candidate_m_id = household_rs::derive_machine_id(&candidate_pub);
    let candidate_m_id_str = candidate_m_id.to_string();
    if response.machine_cert.m_pub != candidate_pub || response.machine_cert.m_id != candidate_m_id
    {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "candidate_cert_mismatch",
        );
        return unauthenticated_response();
    }
    if !response
        .household_record
        .members
        .iter()
        .any(|member| member == &candidate_m_id)
    {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "candidate_missing_from_record",
        );
        return unauthenticated_response();
    }

    let Some((founder_cert, founder_entry_m_pub)) =
        verified_founder_cert_from_peer_list(&response, trust_hh_pub)
    else {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "founder_cert_missing",
        );
        return unauthenticated_response();
    };
    if let Err(e) = response.verify_response_sig(&founder_cert) {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "response_sig_invalid",
            error = %e,
        );
        return unauthenticated_response();
    }
    // Phase 3 candidate-side shard decryption uses ECDH with the
    // founder's m_pub (`shard_at_rest::decrypt_from_peer`), which
    // needs the candidate's M_priv as a raw 32-byte scalar. SE-backed
    // keys are non-exportable by design and return `None` here.
    // Same architectural limitation as `owner_approve_handler`:
    // Phase 3 candidates on macOS MUST run with
    // `THEYOS_FORCE_SOFTWARE_KEYS=1` at install time. The wire
    // response is the generic 401 per FR-019a / R14; the WARN log
    // surfaces the actionable reason for the operator on M2. See
    // `contracts/local-anchor.md` §"Story 2 anchor mechanism".
    let Some(candidate_scalar) = candidate_key.as_software_secret().copied() else {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "candidate_scalar_unavailable",
            hint = "SE-backed M_priv is non-exportable; Phase 3 shard decryption requires THEYOS_FORCE_SOFTWARE_KEYS=1 at install time",
        );
        return unauthenticated_response();
    };
    let plaintext_shard = match household_rs::shard_at_rest::decrypt_from_peer(
        &response.encrypted_shard,
        &candidate_scalar,
        &founder_entry_m_pub,
        &candidate_m_id_str,
    ) {
        Ok(shard) => shard,
        Err(e) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "shard_decrypt_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    let self_shard = match household_rs::shard_at_rest::encrypt_for_self(
        &plaintext_shard,
        &candidate_scalar,
        &candidate_pub,
        &candidate_m_id_str,
        household_rs::shamir::SHARD_X_M2,
    ) {
        Ok(shard) => shard,
        Err(e) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "shard_rewrap_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
    };

    let mut committed_snap = snap.clone();
    committed_snap.state = PairMachineState::Committed;
    committed_snap.cached_response = Some(ByteBuf::from(body.to_vec()));

    // R6.2: order matches the M1 `CeremonyTxn::prepare` invariant —
    // `household_record.cbor` rename is the canonical "candidate is
    // committed" marker and MUST be the LAST file promoted. A crash
    // between any of [cert, marker, self_shard, window, push_token]
    // and the record promotion leaves the on-disk record at
    // `shamir_n=1` (or absent), which boot-time
    // `recover_partial_phase3_commit` correctly classifies as
    // logically rolled back — the orphan `.staged` files are unlinked
    // and the candidate stays uncommitted. Without this ordering, a
    // crash after the record promotion but before later files would
    // cross the commit marker while M1 sees finalize as failed,
    // producing the R5.7 split-brain on the candidate side.
    let mut staged_files = Vec::new();
    staged_files.push((
        household_rs::storage::machine_cert_for(&state.state_dir, &founder_cert.m_id.to_string()),
        match household_rs::cbor::to_canonical_vec(&founder_cert) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    stage = "pair_machine.local_finalize.rejected",
                    reason = "founder_cert_encode",
                    error = %e,
                );
                return unauthenticated_response();
            }
        },
    ));
    staged_files.push((
        household_rs::storage::machine_cert_for(&state.state_dir, &candidate_m_id_str),
        match household_rs::cbor::to_canonical_vec(&response.machine_cert) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    stage = "pair_machine.local_finalize.rejected",
                    reason = "candidate_cert_encode",
                    error = %e,
                );
                return unauthenticated_response();
            }
        },
    ));
    let mut marker_bytes = candidate_m_id_str.as_bytes().to_vec();
    marker_bytes.push(b'\n');
    staged_files.push((
        household_rs::storage::self_m_id_marker_path(&state.state_dir),
        marker_bytes,
    ));
    staged_files.push((
        shamir_self_shard_path(&state.state_dir),
        match self_shard.to_canonical_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    stage = "pair_machine.local_finalize.rejected",
                    reason = "self_shard_encode",
                    error = %e,
                );
                return unauthenticated_response();
            }
        },
    ));
    let committed_window_bytes = match household_rs::cbor::to_canonical_vec(&committed_snap) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "window_encode",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    if let Some(push_token_seed) = &response.push_token_seed {
        if push_token_seed.version != 1 || push_token_seed.platform != "ios" {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "bad_push_token_seed",
            );
            return unauthenticated_response();
        }
        staged_files.push((
            owner_push_token_path(&state.state_dir),
            match household_rs::cbor::to_canonical_vec(push_token_seed) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(
                        stage = "pair_machine.local_finalize.rejected",
                        reason = "push_token_seed_encode",
                        error = %e,
                    );
                    return unauthenticated_response();
                }
            },
        ));
    }
    // R6.2: `household_record.cbor` MUST be the LAST staged entry —
    // its promotion is the canonical "candidate is committed" marker.
    let commit_marker = (
        household_rs::storage::household_record_path(&state.state_dir),
        match household_rs::cbor::to_canonical_vec(&response.household_record) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    stage = "pair_machine.local_finalize.rejected",
                    reason = "record_encode",
                    error = %e,
                );
                return unauthenticated_response();
            }
        },
    );

    // Intent is durable before the first household staging write. The
    // breadcrumb, not directory visibility, lets restart distinguish a
    // partial install from an exact committed marker.
    let exact_ack_bytes = match FinalizeAck::for_machine_cert(&response.machine_cert)
        .and_then(|ack| ack.to_canonical_bytes())
    {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!(
                stage = "pair_machine.local_finalize.ack_encode_failed",
                error = %error,
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let terminal_intent = match household_rs::household_install_transaction::FinalizeTerminalIntent::from_exact_ack_bytes(
        request_fingerprint,
        &response.machine_cert.m_id,
        cached_join_request.as_ref(),
        &exact_ack_bytes,
    ) {
        Ok(intent) => intent,
        Err(error) => {
            tracing::error!(
                stage = "pair_machine.local_finalize.terminal_intent_failed",
                error = %error,
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let install_expectation =
        match household_rs::household_install_transaction::begin_household_install_under_lifecycle(
            &lifecycle_guard,
            candidate_generation,
            &response.household_record,
            &response.machine_cert.m_id,
            &terminal_intent,
        ) {
            Ok(expectation) => expectation,
            Err(error) => {
                tracing::error!(
                    stage = "pair_machine.local_finalize.install_intent_failed",
                    error = %error,
                );
                match household_rs::household_install_transaction::recover_household_install_under_lifecycle(
                &lifecycle_guard,
                |expected| {
                    validate_candidate_install_artifacts(
                        &state.state_dir,
                        &lifecycle_guard,
                        state.key_policy,
                        expected,
                    )
                },
            ) {
                Ok(household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::PartialNeedsRollback(ticket)) => {
                    if let Err(rollback_error) = rollback_partial_candidate_install(
                        &state.state_dir,
                        &lifecycle_guard,
                        &state.window,
                        ticket,
                    )
                    .await
                    {
                        tracing::error!(
                            stage = "pair_machine.local_finalize.install_rollback_failed",
                            error = %rollback_error,
                        );
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    return unauthenticated_response();
                }
                Ok(
                    household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::RotatedAndCleared { .. }
                    | household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::AlreadyRotatedAndCleared { .. },
                ) => {
                    tracing::warn!(
                        stage = "pair_machine.local_finalize.install_recovered_requires_restart",
                        hint = "terminal generation recovered; refusing to serve with stale generation capabilities",
                    );
                    return terminal_install_restart_response(&lifecycle_guard, &state).await;
                }
                Ok(household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::NotApplicable)
                | Err(_) => {}
            }
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    // T064: failure-injection crash point — fires before any
    // staged file lands on disk. A registered Panic aborts M2
    // here, simulating an M1 transport failure on the finalize
    // POST. Compiled out in production builds.
    #[cfg(any(test, feature = "failure-injection"))]
    {
        match crate::failure_injection::apply(
            crate::failure_injection::InjectionPoint::M2BeforeStage,
        )
        .await
        {
            crate::failure_injection::Outcome::EarlyReject(_) => {
                return unauthenticated_response();
            }
            crate::failure_injection::Outcome::Skip
            | crate::failure_injection::Outcome::Continue => {}
        }
    }

    let staged = match state.window.stage_commit_under_lifecycle(
        &lifecycle_guard,
        staged_files,
        committed_window_bytes,
        commit_marker,
    ) {
        Ok(staged) => staged,
        Err(e) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "stage_files_failed",
                error = %e,
            );
            match household_rs::household_install_transaction::recover_household_install_under_lifecycle(
                &lifecycle_guard,
                |expected| {
                    validate_candidate_install_artifacts(
                        &state.state_dir,
                        &lifecycle_guard,
                        state.key_policy,
                        expected,
                    )
                },
            ) {
                Ok(household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::PartialNeedsRollback(ticket)) => {
                    if let Err(rollback_error) = rollback_partial_candidate_install(
                        &state.state_dir,
                        &lifecycle_guard,
                        &state.window,
                        ticket,
                    )
                    .await
                    {
                        tracing::error!(
                            stage = "pair_machine.local_finalize.install_rollback_failed",
                            error = %rollback_error,
                        );
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                }
                Ok(
                    household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::RotatedAndCleared { .. }
                    | household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::AlreadyRotatedAndCleared { .. },
                ) => {
                    return terminal_install_restart_response(&lifecycle_guard, &state).await;
                }
                Ok(household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::NotApplicable) => {}
                Err(recovery_error) => {
                    tracing::error!(
                        stage = "pair_machine.local_finalize.install_recovery_failed",
                        error = %recovery_error,
                    );
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
            return unauthenticated_response();
        }
    };
    // T064: failure-injection crash point — fires after every
    // `.staged` file lands on disk but before `staged.commit()`
    // promotes them. A registered Panic leaves a full `.staged` set
    // (no final files) on disk, exercising boot-time
    // `recover_partial_phase3_commit`'s M2-side rollback branch. A
    // registered SkipWrite skips the commit entirely (same on-disk
    // state but the handler returns 200, which is wrong-for-protocol
    // but the harness expects M1 to crash before observing it).
    #[cfg(any(test, feature = "failure-injection"))]
    {
        match crate::failure_injection::apply(
            crate::failure_injection::InjectionPoint::M2AfterFounderCertStaged,
        )
        .await
        {
            crate::failure_injection::Outcome::Skip => {
                // Drop staged set without unlinking — Drop impl on
                // StagedCommit removes them; the test should arm Panic
                // instead if it needs the .staged files preserved.
                drop(staged);
                return unauthenticated_response();
            }
            crate::failure_injection::Outcome::EarlyReject(_) => {
                drop(staged);
                return unauthenticated_response();
            }
            crate::failure_injection::Outcome::Continue => {}
        }
    }
    let commit_result = staged.commit_preserve_on_error();
    if let Err(error) = &commit_result {
        tracing::warn!(
            stage = "pair_machine.local_finalize.commit_ack_lost",
            error = %error,
            "classifying the install from its durable breadcrumb and exact record marker"
        );
    }
    let recovery =
        household_rs::household_install_transaction::recover_household_install_under_lifecycle(
            &lifecycle_guard,
            |expected| {
                if expected != &install_expectation {
                    return Err(install_artifacts_error("install expectation changed"));
                }
                validate_candidate_install_artifacts(
                    &state.state_dir,
                    &lifecycle_guard,
                    state.key_policy,
                    expected,
                )
            },
        );
    match recovery {
        Ok(
            household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::RotatedAndCleared {
                terminal_result,
                ..
            }
            | household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::AlreadyRotatedAndCleared {
                terminal_result,
                ..
            },
        ) => {
            if terminal_result.request_fingerprint() != &request_fingerprint
                || terminal_result.ack_bytes() != exact_ack_bytes.as_slice()
            {
                tracing::error!(
                    stage = "pair_machine.local_finalize.terminal_result_mismatch",
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            terminal_install_restart_response(&lifecycle_guard, &state).await
        }
        Ok(household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::PartialNeedsRollback(ticket)) => {
            if let Err(error) = rollback_partial_candidate_install(
                &state.state_dir,
                &lifecycle_guard,
                &state.window,
                ticket,
            )
            .await
            {
                tracing::error!(
                    stage = "pair_machine.local_finalize.install_rollback_failed",
                    error = %error,
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            unauthenticated_response()
        }
        Ok(household_rs::household_install_transaction::HouseholdInstallRecoveryOutcome::NotApplicable) => {
            tracing::error!(
                stage = "pair_machine.local_finalize.install_evidence_missing",
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(error) => {
            tracing::error!(
                stage = "pair_machine.local_finalize.install_terminalization_failed",
                error = %error,
                hint = "never rolling back an install whose canonical record may be committed",
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn cache_known_peer_addrs(state_dir: &Path, response: &JoinResponse) {
    for peer in &response.peer_list {
        let Some(addr) = peer.tailscale_addr.as_ref() else {
            continue;
        };
        if let Err(error) =
            household_rs::storage::write_known_peer_addr(state_dir, &peer.m_id, addr)
        {
            tracing::warn!(
                stage = "pair_machine.local_finalize.known_addr_persist_failed",
                peer_m_id = %peer.m_id,
                error = %error,
            );
        }
    }
}

#[cfg(test)]
fn finalize_ack_response_with_resolver(
    cert: &household_rs::MachineCert,
    resolver: TailnetResolver,
) -> Response {
    let bytes = FinalizeAck::for_machine_cert(cert)
        .and_then(|ack| ack.to_canonical_bytes())
        .unwrap_or_default();
    let mut response = cbor_response(StatusCode::OK, bytes);
    let port = crate::household_bootstrap::household_port_from_env();
    if let Some(addr) = candidate_tailnet_addr(port, resolver)
        && let Ok(value) = HeaderValue::from_str(&addr)
    {
        response
            .headers_mut()
            .insert(FINALIZE_CANDIDATE_TAILSCALE_ADDR_HEADER, value);
    }
    response
}

fn candidate_tailnet_addr(port: u16, resolver: TailnetResolver) -> Option<String> {
    resolver().map(|ip| format!("{ip}:{port}"))
}

fn verified_founder_cert_from_peer_list(
    response: &JoinResponse,
    trust_hh_pub: &[u8; 33],
) -> Option<(household_rs::MachineCert, household_rs::keys::P256PublicKey)> {
    // Forward-compat for Phase 4+: a single invalid peer must not
    // abort the lookup. `continue` past entries that fail any
    // verification step (missing cert, cert chain, m_id/m_pub binding,
    // self-cert exclusion) and only return `None` if the whole list
    // yields no founder.
    for peer in &response.peer_list {
        let Some(cert) = peer.machine_cert.as_ref() else {
            continue;
        };
        if household_rs::machine_cert::verify_against_household_root(cert, trust_hh_pub).is_err() {
            continue;
        }
        if peer.m_id != cert.m_id.to_string() || peer.m_pub.as_ref() != cert.m_pub.as_bytes() {
            continue;
        }
        if cert.m_id != response.machine_cert.m_id {
            return Some((cert.clone(), cert.m_pub.clone()));
        }
    }
    None
}

fn query_param(uri: &Uri, key: &str) -> Option<String> {
    uri.query()?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key { Some(v.to_string()) } else { None }
    })
}

/// `POST /api/v1/household/join-request` handler. Per T042–T046.
///
/// **Auth model**: the external Story 1 endpoint is authenticated by
/// owner `Soyeht-PoP` with `Operation::HouseholdAddMachine`; the inner
/// `JoinRequest.challenge_sig` then proves candidate possession of
/// `M_priv`. Story 2's LAN/browser path uses the private
/// `founder_stage_join_request` helper in-process after fetching the
/// same signed `JoinRequest` from the candidate, so it does not transit
/// an HTTP `PoP` boundary.
///
/// **Failure surface**: Every reject collapses to deterministic CBOR
/// `{v=1, error="unauthenticated"}` with HTTP 401 per R14 — no oracle.
/// The typed reasons travel only via `tracing::warn!` for operator
/// observability.
pub async fn founder_join_request_handler(
    State(state): State<PairMachineRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("join_request.clock") else {
        return unauthenticated_response();
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
            stage = "join_request.rejected",
            reason = "pop_auth_failed",
            error = %e,
        );
        return unauthenticated_response();
    }

    let request: JoinRequest = match household_rs::cbor::from_canonical_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                stage = "join_request.rejected",
                reason = "cbor_decode",
                error = %e,
            );
            return unauthenticated_response();
        }
    };

    match founder_stage_join_request(&state, request, JoinSource::OwnerQr, now).await {
        Ok(FounderStageOutcome::Accepted(accepted)) => {
            let bytes = household_rs::cbor::to_canonical_vec(&JoinRequestAccepted {
                version: 1,
                owner_event_cursor: accepted.owner_event_cursor,
                expiry: accepted.expiry,
            })
            .unwrap_or_default();
            cbor_response(StatusCode::CREATED, bytes)
        }
        Ok(FounderStageOutcome::Replay(bytes)) => cbor_response(StatusCode::OK, bytes),
        Err(FounderStageError) => unauthenticated_response(),
    }
}

pub async fn founder_stage_join_request(
    state: &PairMachineRouterState,
    request: JoinRequest,
    source: JoinSource,
    now: u64,
) -> Result<FounderStageOutcome, FounderStageError> {
    // ── 2. Verify signature + field shape ──────────────────────────
    if let Err(e) = verify_join_request(&request) {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "verify_failed",
            error = %e,
        );
        return Err(FounderStageError);
    }

    // The canonical CBOR bytes we cache MUST round-trip the verified
    // request. We re-encode here (rather than reusing `body`) so any
    // non-canonical CBOR sent by a misbehaving client is normalized
    // away before it reaches the owner-event payload — that is the
    // bit-pattern the iPhone re-checks against `challenge_sig`.
    let join_request_cbor = match request.to_canonical_bytes() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                stage = "join_request.rejected",
                source = source.as_str(),
                reason = "cbor_reencode",
                error = %e,
            );
            return Err(FounderStageError);
        }
    };

    // This helper has both HTTP and Bonjour callers, so serialization lives
    // here rather than at either transport boundary. The ordering is the same
    // as every other authority mutation: process mutation lock -> stable
    // lifecycle exclusive -> process window/state -> stores.
    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let lifecycle_state_dir = state.state_dir.clone();
    let lifecycle_guard = match tokio::task::spawn_blocking(move || {
        acquire_pair_lifecycle_exclusive(&lifecycle_state_dir)
    })
    .await
    {
        Ok(Ok(guard)) => guard,
        Ok(Err(error)) => {
            tracing::warn!(
                stage = "join_request.rejected",
                source = source.as_str(),
                reason = "lifecycle_failed",
                error = %error,
            );
            return Err(FounderStageError);
        }
        Err(error) => {
            tracing::warn!(
                stage = "join_request.rejected",
                source = source.as_str(),
                reason = "lifecycle_task_failed",
                error = %error,
            );
            return Err(FounderStageError);
        }
    };

    // ── 3. Household identity must be loaded and owner must be paired ─
    let Some(identity) = state.household.current().await else {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "identity_unavailable",
        );
        return Err(FounderStageError);
    };
    if let Err(error) = verify_installed_household_id(
        &lifecycle_guard,
        &state.state_dir,
        identity.record.hh_id.as_str(),
    ) {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "installed_household_changed",
            error = %error,
        );
        return Err(FounderStageError);
    }
    let Some(_owner_auth) = state.household.current_owner_auth().await else {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "owner_not_paired",
        );
        return Err(FounderStageError);
    };

    // ── 4. Candidate identity + committed replay branch ──────────────
    let Ok(m_pub_arr) = <[u8; 33]>::try_from(request.m_pub.as_ref()) else {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "m_pub_length",
        );
        return Err(FounderStageError);
    };
    let Ok(candidate_m_pub) = household_rs::keys::P256PublicKey::from_bytes(&m_pub_arr) else {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "m_pub_decode",
        );
        return Err(FounderStageError);
    };
    let candidate_m_id = household_rs::ids::derive_machine_id(&candidate_m_pub);

    let snap = state.window.snapshot().await;

    // Replay-after-commit: same (m_pub, nonce), within grace window.
    //
    // This MUST run before the `shamir_n == 1` and already-member gates:
    // a successful Phase 3 ceremony updates the in-memory household record
    // to post-Shamir (`shamir_n=2`) and adds the candidate to `members`.
    // FR-015 still requires the original completed JoinRequest to return
    // the cached response bytes during its replay grace window.
    if matches!(snap.state, PairMachineState::Committed)
        && same_m_pub_and_nonce(&snap, &m_pub_arr, request.nonce.as_ref())
    {
        if within_replay_grace(&snap, now) {
            let Some(cached) = snap.cached_response.as_ref() else {
                tracing::warn!(
                    stage = "join_request.rejected",
                    source = source.as_str(),
                    reason = "committed_replay_missing_cached_response",
                );
                return Err(FounderStageError);
            };
            tracing::info!(
                stage = "join_request.replay_after_commit",
                source = source.as_str(),
                candidate_m_id = %candidate_m_id,
            );
            return Ok(FounderStageOutcome::Replay(cached.to_vec()));
        }
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "replay_after_grace",
            candidate_m_id = %candidate_m_id,
        );
        return Err(FounderStageError);
    }

    // ── 5. Phase 3 only supports 1→2 growth: refuse if shamir_n != 1 ─
    // A household at shamir_n>=2 has already split the root; admitting
    // a 3rd member needs the (deferred) re-sharding ceremony.
    if identity.record.shamir_n != 1 {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "no_active_sole_shard",
            shamir_n = identity.record.shamir_n,
        );
        return Err(FounderStageError);
    }

    // ── 6. Candidate's m_pub must not already be a member ─────────────
    if identity.record.members.iter().any(|m| m == &candidate_m_id) {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "already_member",
            candidate_m_id = %candidate_m_id,
        );
        return Err(FounderStageError);
    }

    // ── 7. Window state branching ─────────────────────────────────────

    // Idempotent re-stage: same (m_pub, nonce) while AwaitingOwner —
    // surface the existing cursor + expiry rather than appending a
    // duplicate event.
    if matches!(
        snap.state,
        PairMachineState::Staging | PairMachineState::AwaitingOwner
    ) {
        if same_m_pub_and_nonce(&snap, &m_pub_arr, request.nonce.as_ref()) {
            if let (Some(cursor), Some(expiry)) = (snap.owner_event_cursor, snap.expiry) {
                tracing::info!(
                    stage = "join_request.idempotent_restage",
                    source = source.as_str(),
                    candidate_m_id = %candidate_m_id,
                    owner_event_cursor = cursor,
                );
                return Ok(FounderStageOutcome::Accepted(FounderStageAccepted {
                    owner_event_cursor: cursor,
                    expiry,
                }));
            }
            // Staging without cursor yet — race: a concurrent request
            // saw the same window in transition. Fall through to the
            // generic-401 to keep the surface oracle-free.
        }
        // Different m_pub or nonce: a different ceremony is in
        // progress. Generic-401 per spec — no leak that there's an
        // open window.
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "window_already_open",
        );
        return Err(FounderStageError);
    }

    // Aborted / expired Committed (outside grace) / Idle — accept and
    // re-stage. For Aborted/Committed we transition through Idle so
    // `enter_staging`'s precondition is met.
    if !matches!(snap.state, PairMachineState::Idle) {
        if let Err(e) = state
            .window
            .under_lifecycle(&lifecycle_guard)
            .return_to_idle()
            .await
        {
            tracing::warn!(
                stage = "join_request.rejected",
                source = source.as_str(),
                reason = "window_reset_failed",
                error = %e,
            );
            return Err(FounderStageError);
        }
    }

    // ── 7. Fingerprint + ttl ──────────────────────────────────────────
    let fingerprint = household_rs::fingerprint::fingerprint(&m_pub_arr);
    let ttl_secs: u64 = 300;
    let Ok(nonce_arr) = <[u8; 32]>::try_from(request.nonce.as_ref()) else {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "nonce_length",
        );
        return Err(FounderStageError);
    };

    // ── 8. Stage the window with the verified request bytes ───────────
    let expiry = match state
        .window
        .under_lifecycle(&lifecycle_guard)
        .enter_staging(
            m_pub_arr,
            nonce_arr,
            request.transport,
            request.addr.clone(),
            fingerprint.clone(),
            join_request_cbor.clone(),
            ttl_secs,
            // Founder-side staging path (Story 1 join-request POST or
            // Story 2 Bonjour fetch). The founder cannot deliver an
            // anchor to itself; the anchor flow only applies on the
            // candidate side via `local/anchor`.
            None,
        )
        .await
    {
        Ok(expiry) => expiry,
        Err(e) => {
            tracing::warn!(
                stage = "join_request.rejected",
                source = source.as_str(),
                reason = "enter_staging_failed",
                error = %e,
            );
            return Err(FounderStageError);
        }
    };

    // Best-effort: cache the candidate's self-announced address as a
    // non-authoritative last-known-location hint (see
    // `household_rs::storage::write_known_peer_addr`). Not part of the
    // ceremony's crash-safe staged-commit set — a write failure here must
    // not abort a join the candidate otherwise validated correctly.
    if let Err(e) = household_rs::storage::write_known_peer_addr(
        &state.state_dir,
        candidate_m_id.as_str(),
        &request.addr,
    ) {
        tracing::warn!(
            stage = "join_request.known_addr_persist_failed",
            source = source.as_str(),
            candidate_m_id = %candidate_m_id,
            error = %e,
        );
    }

    // ── 9. Append OwnerEvent{type=join-request} ───────────────────────
    let payload = OwnerEventPayload::JoinRequest(JoinRequestPayload {
        join_request_cbor: serde_bytes::ByteBuf::from(join_request_cbor.clone()),
        fingerprint: fingerprint.clone(),
        expiry,
    });
    let event_log = Arc::clone(&state.event_log);
    let event_identity = Arc::clone(&identity);
    // Keep the already-held lifecycle-exclusive capability through the
    // blocking append. Reopening the same lifecycle and asking for shared
    // here self-deadlocks against our own writer lock.
    let (lifecycle_guard, event) = match tokio::task::spawn_blocking(move || {
        let append = event_log
            .append_under_lifecycle_write(
                &lifecycle_guard,
                &event_identity.cert.m_id.to_string(),
                event_identity.m_priv.as_ref(),
                OwnerEventType::JoinRequest,
                payload,
            )
            .map_err(|error| error.to_string());
        (lifecycle_guard, append)
    })
    .await
    {
        Ok((guard, Ok(ev))) => (guard, ev),
        Ok((guard, Err(e))) => {
            tracing::warn!(
                stage = "join_request.rejected",
                source = source.as_str(),
                reason = "owner_event_append_failed",
                error = %e,
            );
            // Roll the window back to Idle so the next attempt is not
            // blocked by an orphan staging state.
            let _ = state.window.under_lifecycle(&guard).return_to_idle().await;
            drop(guard);
            return Err(FounderStageError);
        }
        Err(e) => {
            tracing::warn!(
                stage = "join_request.rejected",
                source = source.as_str(),
                reason = "owner_event_append_worker_failed",
                error = %e,
            );
            // The worker owned the lifecycle guard. If it panicked, the
            // guard was released during unwinding; do not mutate the window
            // after losing the authority boundary.
            return Err(FounderStageError);
        }
    };

    // ── 10. Promote window to AwaitingOwner with the event cursor ─────
    if let Err(e) = state
        .window
        .under_lifecycle(&lifecycle_guard)
        .enter_awaiting_owner(event.cursor)
        .await
    {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "enter_awaiting_owner_failed",
            error = %e,
        );
        let _ = state
            .window
            .under_lifecycle(&lifecycle_guard)
            .return_to_idle()
            .await;
        return Err(FounderStageError);
    }
    // Positive observability gate (T093) — the OwnerEvent that
    // becomes the iPhone's approve/decline prompt has been durably
    // appended and broadcast. Distinct from `join_request.accepted`
    // (the wire-level handler outcome): a future regression that
    // splits the prompt-forwarding logic into a separate service
    // would still need to emit this stage to satisfy FR-019.
    tracing::info!(
        stage = "pair_machine.owner_prompt_forwarded",
        source = source.as_str(),
        candidate_m_id = %candidate_m_id,
        owner_event_cursor = event.cursor,
    );
    handlers_owner_events::dispatch_owner_event_tickle_if_idle(
        state.state_dir.clone(),
        &state.event_broadcaster,
    );

    tracing::info!(
        stage = "join_request.accepted",
        source = source.as_str(),
        candidate_m_id = %candidate_m_id,
        owner_event_cursor = event.cursor,
        expiry = expiry,
        fingerprint = %fingerprint,
    );

    Ok(FounderStageOutcome::Accepted(FounderStageAccepted {
        owner_event_cursor: event.cursor,
        expiry,
    }))
}

fn same_m_pub_and_nonce(snap: &PairMachineWindowSnapshot, m_pub: &[u8; 33], nonce: &[u8]) -> bool {
    let Some(snap_m_pub) = snap.m_pub.as_ref() else {
        return false;
    };
    let Some(snap_nonce) = snap.nonce.as_ref() else {
        return false;
    };
    // Constant-time compare not required here: window state is
    // server-side and the comparison gates a logical branch, not a
    // secret. Plain byte equality is sufficient.
    snap_m_pub.as_slice() == m_pub.as_slice() && snap_nonce.as_slice() == nonce
}

fn within_replay_grace(snap: &PairMachineWindowSnapshot, now: u64) -> bool {
    let Some(expiry) = snap.expiry else {
        return false;
    };
    // Grace = TTL + 60 s per R7 / T045.
    let grace_deadline = expiry.saturating_add(60);
    now <= grace_deadline
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use household_rs::household_lifecycle::HouseholdLifecycleLockError;
    use household_rs::keys::{IdentityKey, P256Keypair};
    use std::net::Ipv4Addr;
    use std::sync::mpsc;

    #[test]
    fn terminal_anchor_rejects_a_valid_same_key_request_with_substituted_address() {
        let key = P256Keypair::generate();
        let m_pub = key.public();
        let nonce = [0x51; 32];
        let challenge = household_rs::pair_machine::JoinChallenge::build(
            m_pub.as_bytes(),
            &nonce,
            "terminal-anchor-test",
            household_rs::machine_cert::Platform::LinuxNix,
        );
        let signature = key.sign(&challenge.to_canonical_bytes().unwrap()).unwrap();
        let request = JoinRequest {
            version: household_rs::pair_machine::PAIR_MACHINE_VERSION,
            m_pub: ByteBuf::from(m_pub.as_bytes().to_vec()),
            hostname: "terminal-anchor-test".into(),
            platform: household_rs::machine_cert::Platform::LinuxNix,
            nonce: ByteBuf::from(nonce.to_vec()),
            addr: "192.0.2.44:18091".into(),
            transport: JoinTransport::Lan,
            challenge_sig: ByteBuf::from(signature.0.to_vec()),
        };
        let request_bytes = request.to_canonical_bytes().unwrap();
        let mut snapshot = PairMachineWindowSnapshot::idle();
        snapshot.cached_join_request = Some(ByteBuf::from(request_bytes.clone()));
        snapshot.m_pub = Some(request.m_pub.clone());
        snapshot.nonce = Some(request.nonce.clone());
        snapshot.addr_hint = Some(request.addr.clone());
        snapshot.transport = Some(request.transport);
        assert!(validate_terminal_join_request_binding(&snapshot, &request_bytes).is_ok());

        let mut substituted = request;
        substituted.addr = "192.0.2.99:18091".into();
        verify_join_request(&substituted).expect(
            "the request remains self-consistent, so exact terminal equality is load-bearing",
        );
        let substituted_bytes = substituted.to_canonical_bytes().unwrap();
        assert!(
            validate_terminal_join_request_binding(&snapshot, &substituted_bytes).is_err(),
            "a different valid request must not replace the G0 terminal anchor"
        );
    }

    // This loopback-only test needs the raw serve primitive so it can observe
    // Hyper draining the response body during graceful shutdown. It does not
    // expose a production listener or a Product A route.
    #[allow(clippy::disallowed_methods)]
    async fn signaled_response_survives_immediate_tcp_graceful_shutdown(
        status: StatusCode,
        body: Vec<u8>,
        value: PreHouseholdRuntimeSignal,
        retry_after: bool,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (signal, mut signal_rx) =
            tokio::sync::watch::channel(PreHouseholdRuntimeSignal::Running);
        let expected = body.clone();
        let app = axum::Router::new().route(
            "/terminal",
            axum::routing::get(move || {
                let signal = signal.clone();
                let body = body.clone();
                async move {
                    runtime_signaled_cbor_response(status, body, Some(signal), value, retry_after)
                }
            }),
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        let shutdown = tokio::spawn(async move {
            signal_rx.changed().await.unwrap();
            assert_eq!(*signal_rx.borrow(), value);
            let _ = shutdown_tx.send(());
        });

        let response = reqwest::get(format!("http://{addr}/terminal"))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(CBOR_CONTENT_TYPE)
        );
        assert_eq!(
            response.headers().contains_key(header::RETRY_AFTER),
            retry_after
        );
        assert_eq!(
            response.bytes().await.unwrap().as_ref(),
            expected.as_slice()
        );
        shutdown.await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("graceful server drains the in-flight terminal body")
            .unwrap();
    }

    #[tokio::test]
    async fn typed_503_body_fully_drains_before_restart_shutdown() {
        let body = household_rs::pair_machine::FinalizeRestartRequired::new()
            .to_canonical_bytes()
            .unwrap();
        signaled_response_survives_immediate_tcp_graceful_shutdown(
            StatusCode::SERVICE_UNAVAILABLE,
            body,
            PreHouseholdRuntimeSignal::RestartRequired,
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn retained_ack_body_fully_drains_before_cold_listener_shutdown() {
        signaled_response_survives_immediate_tcp_graceful_shutdown(
            StatusCode::OK,
            vec![0xa1, 0x61, b'v', 0x01],
            PreHouseholdRuntimeSignal::AckDeliveryStarted,
            false,
        )
        .await;
    }

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

    #[test]
    fn cached_response_binding_is_exact_not_semantic() {
        let canonical_a = b"signed response A";
        let fingerprint = household_rs::household_install_transaction::FinalizeRequestFingerprintV1::for_canonical_request_bytes(canonical_a);
        assert!(cached_response_matches_request_fingerprint(
            canonical_a,
            fingerprint
        ));
        assert!(
            !cached_response_matches_request_fingerprint(b"signed response B", fingerprint,),
            "a separately signed response with equivalent authority fields must not satisfy A's durable intent",
        );
    }

    #[test]
    fn candidate_tailnet_addr_uses_local_resolver_and_household_port() {
        #[allow(clippy::unnecessary_wraps)]
        fn tailnet_addr() -> Option<Ipv4Addr> {
            Some(Ipv4Addr::new(100, 64, 0, 10))
        }

        assert_eq!(
            candidate_tailnet_addr(8091, tailnet_addr),
            Some("100.64.0.10:8091".to_string())
        );
    }

    #[test]
    fn candidate_tailnet_addr_is_absent_without_local_tailnet() {
        fn no_tailnet_addr() -> Option<Ipv4Addr> {
            None
        }

        assert_eq!(candidate_tailnet_addr(8091, no_tailnet_addr), None);
    }

    #[tokio::test]
    async fn finalize_response_adds_hint_without_changing_ack_body() {
        #[allow(clippy::unnecessary_wraps)]
        fn tailnet_addr() -> Option<Ipv4Addr> {
            Some(Ipv4Addr::new(100, 64, 0, 10))
        }

        let state_dir = tempfile::tempdir().unwrap();
        let identity = household_rs::bootstrap_or_load(
            state_dir.path(),
            household_rs::BootstrapOpts {
                household_name: "Sample Home".to_string(),
                hostname_label: Some("candidate-alpha".to_string()),
            },
            household_rs::KeyBackingPolicy::ForceSoftware,
        )
        .unwrap();
        let expected_ack = FinalizeAck::for_machine_cert(&identity.cert).unwrap();
        let response = finalize_ack_response_with_resolver(&identity.cert, tailnet_addr);
        let expected_header = format!(
            "100.64.0.10:{}",
            crate::household_bootstrap::household_port_from_env()
        );
        assert_eq!(
            response
                .headers()
                .get(FINALIZE_CANDIDATE_TAILSCALE_ADDR_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(expected_header.as_str())
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let actual_ack: FinalizeAck = household_rs::cbor::from_canonical_slice(&body).unwrap();
        assert_eq!(actual_ack, expected_ack);
    }

    #[tokio::test]
    async fn finalize_ready_publication_remains_inside_lifecycle_exclusive() {
        let state = tempfile::tempdir().expect("state dir");
        let _identity = bootstrap_named(state.path(), "Pair Machine Lock Home");
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
    fn stale_finalize_rejects_replacement_household() {
        let old_state = tempfile::tempdir().expect("old state");
        let replacement_state = tempfile::tempdir().expect("replacement state");
        let old = bootstrap_named(old_state.path(), "Old Candidate Home");
        let replacement = bootstrap_named(replacement_state.path(), "Replacement Candidate Home");
        household_rs::storage::atomic_write_cbor(
            &household_rs::storage::household_record_path(old_state.path()),
            &replacement.record,
        )
        .expect("install replacement record");

        let guard = acquire_pair_lifecycle_exclusive(old_state.path()).expect("exclusive");
        let error = verify_installed_household_for_finalize(
            &guard,
            old_state.path(),
            old.record.hh_id.as_str(),
        )
        .expect_err("stale finalize must not mutate replacement");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn stale_founder_stage_rejects_replacement_household() {
        let old_state = tempfile::tempdir().expect("old state");
        let replacement_state = tempfile::tempdir().expect("replacement state");
        let old = bootstrap_named(old_state.path(), "Old Founder Home");
        let replacement = bootstrap_named(replacement_state.path(), "New Founder Home");
        household_rs::storage::atomic_write_cbor(
            &household_rs::storage::household_record_path(old_state.path()),
            &replacement.record,
        )
        .expect("install replacement record");

        let guard = acquire_pair_lifecycle_exclusive(old_state.path()).expect("exclusive");
        let error =
            verify_installed_household_id(&guard, old_state.path(), old.record.hh_id.as_str())
                .expect_err("stale founder process must not stage against replacement");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn stale_candidate_anchor_rejects_an_installed_household() {
        let state = tempfile::tempdir().expect("state");
        let _installed = bootstrap_named(state.path(), "Already Installed Home");
        let guard = acquire_pair_lifecycle_exclusive(state.path()).expect("exclusive");
        let error = verify_household_absent_for_candidate(&guard, state.path())
            .expect_err("candidate anchor must not mutate an installed household");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    }
}
