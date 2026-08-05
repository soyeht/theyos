//! Phase 3 owner-events long-poll, owner approve/decline, and push-token
//! registration endpoints (`contracts/owner-events.md`,
//! `contracts/push-token-register.md`).
//!
//! Module skeleton committed in T006 of the Phase 3 task list. Endpoint
//! implementations arrive in T047–T057.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Extension, Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::caveats::Operation;
use household_rs::household_lifecycle::{HouseholdLifecycleLock, LifecycleWriteGuard};
use household_rs::owner_approval_v2::{
    AddCredentialContextInput, OwnerApprovalContextV2, OwnerApprovalV2, OwnerApprovalV2Error,
    OwnerOperation, PairMachineTrustedContextInput, ProvisionRecoveryCodeContextInput,
    RecoverCredentialContextInput, RecoveryAuthorityHeadInput, RevokeCredentialContextInput,
};
use household_rs::owner_events::{
    JoinCancelledPayload, MachineJoinedPayload, OwnerDevicePushToken, OwnerEvent, OwnerEventLog,
    OwnerEventPayload, OwnerEventType, OwnerEventsBroadcaster,
};
use household_rs::owner_webauthn::{
    OwnerWebauthnChallengeId, OwnerWebauthnCredentialStore, OwnerWebauthnRegistrationBinding,
    OwnerWebauthnRegistrationStart, OwnerWebauthnRp,
};
use household_rs::owner_webauthn_anchor::{
    OwnerWebauthnAnchorError, OwnerWebauthnAnchorMode, OwnerWebauthnAnchorStatus,
    OwnerWebauthnAuthorityHead, classify_owner_webauthn_authority_anchor_read_only,
    verified_owner_webauthn_authority_head, verify_or_update_owner_webauthn_authority_anchor,
};
use household_rs::owner_webauthn_authority::{
    OwnerWebauthnAuthority, OwnerWebauthnCredentialEventAction, OwnerWebauthnEventActor,
    OwnerWebauthnRecoveryAddInput, SignedOwnerWebauthnCredentialEvent,
};
use household_rs::owner_webauthn_recovery::{
    OwnerWebauthnRecoveryActor, OwnerWebauthnRecoveryAuthority, OwnerWebauthnRecoveryEventAction,
    OwnerWebauthnRecoveryHead, RecoveryCodeVerifier, SignedOwnerWebauthnRecoveryEvent,
    verified_owner_webauthn_recovery_head,
};
use household_rs::owner_webauthn_recovery_anchor::{
    OwnerWebauthnRecoveryAnchorError, OwnerWebauthnRecoveryAnchorStatus,
    advance_owner_webauthn_recovery_anchor_after_commit,
    classify_owner_webauthn_recovery_anchor_read_only,
};
use household_rs::owner_webauthn_recovery_consume::{
    OwnerWebauthnRecoveryConsumeReadiness, classify_owner_webauthn_recovery_consume_readiness,
};
use household_rs::pair_machine::{
    CeremonyError, CeremonyInputs, CeremonyTxn, FinalizeWithM2Options, FinalizeWithM2Outcome,
    JoinRequest, OwnerApproval, OwnerApprovalContext, PairMachineState, PairMachineWindow,
    PairMachineWindowSnapshot, join_request_hash,
};
use household_rs::person_cert::{PersonCert, SignOwnerOptions};
use household_rs::secure_upgrade::{
    SecureUpgradeAppAttestTranscriptInput, SecureUpgradeChallengeStore,
    SecureUpgradeDurableAppAttestReplayStore, SecureUpgradePlatform, SecureUpgradeProofEnvironment,
    SecureUpgradeProofVerificationInput, SecureUpgradeTranscript,
    sign_owner_cert_with_secure_upgrade_verification, verify_secure_upgrade_ceremony_for_challenge,
};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_bytes::ByteBuf;
use tokio::sync::Mutex;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::watch;
use webauthn_rs::prelude::{
    CreationChallengeResponse, RegisterPublicKeyCredential, RequestChallengeResponse, Uuid,
};
use zeroize::Zeroizing;

use crate::apns_dispatcher;
use crate::handlers_device_pairing::DevicePairingStore;
use crate::household_auth;
use crate::household_state::HouseholdState;
use crate::macos_local_caller_auth::{MacosLocalCallerAuth, MacosLocalCallerAuthRequest};
use crate::macos_local_registration_listener::MacosLocalPeerConnectInfo;
use crate::owner_webauthn_recovery_consume_rate_limit::{
    RecoveryConsumeRateLimitDecision, check_recovery_consume_attempt,
};
use crate::ratelimit::Limiter;
use crate::tailnet_address::{TailnetResolver, current_tailnet_ipv4};
use crate::time_util;

const CBOR_CONTENT_TYPE: &str = "application/cbor";
const OWNER_EVENTS_LONG_POLL_TIMEOUT: Duration = Duration::from_secs(45);
pub const OWNER_AUTH_V2_ROLLOUT_ENV: &str = "THEYOS_OWNER_AUTH_V2_ROLLOUT";
pub const OWNER_AUTH_V2_REVIEWED_CORE_ROLLOUT: &str = "reviewed-core-v2";
pub const OWNER_AUTH_V2_SECURE_UPGRADE_ROLLOUT: &str = "reviewed-core-v2-secure-upgrade";
pub const SECURE_UPGRADE_APP_ATTEST_TEAM_ID_ENV: &str = "THEYOS_SECURE_UPGRADE_APP_ATTEST_TEAM_ID";
pub const SECURE_UPGRADE_APP_ATTEST_BUNDLE_ID_ENV: &str =
    "THEYOS_SECURE_UPGRADE_APP_ATTEST_BUNDLE_ID";
pub const SECURE_UPGRADE_APP_ATTEST_ENVIRONMENT_ENV: &str =
    "THEYOS_SECURE_UPGRADE_APP_ATTEST_ENVIRONMENT";
pub const SECURE_UPGRADE_CHALLENGE_TTL_SECS_ENV: &str = "THEYOS_SECURE_UPGRADE_CHALLENGE_TTL_SECS";

const SECURE_UPGRADE_DEFAULT_CHALLENGE_TTL_SECS: u64 = 300;
const SECURE_UPGRADE_APP_ATTEST_REPLAY_DIR: &str = "secure_upgrade_app_attest_replay";
const OWNER_EVENTS_LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(30);

fn owner_events_lifecycle_error(stage: &'static str, error: impl std::fmt::Display) -> String {
    format!("{stage}: {error}")
}

/// Enter the short lifecycle-exclusive commit window for an owner-authority
/// mutation.
///
/// Callers already hold `BOOTSTRAP_MUTATION_LOCK`; all network, prompt, RP,
/// and signing work must finish before this helper is called. Recovering a
/// prior teardown deliberately rejects the stale request instead of applying
/// it to the now-uninitialized state root.
fn acquire_owner_events_lifecycle_exclusive_blocking(
    state_dir: &FsPath,
) -> Result<LifecycleWriteGuard, String> {
    let lifecycle = HouseholdLifecycleLock::open_verified(state_dir)
        .map_err(|error| owner_events_lifecycle_error("open owner-events lifecycle", error))?;
    let deadline = Instant::now()
        .checked_add(OWNER_EVENTS_LIFECYCLE_TIMEOUT)
        .ok_or_else(|| "owner-events lifecycle deadline overflow".to_string())?;
    let guard = lifecycle
        .lock_exclusive_until(deadline)
        .map_err(|error| owner_events_lifecycle_error("acquire owner-events lifecycle", error))?;
    Ok(guard)
}

fn recover_owner_events_lifecycle_or_reject(
    guard: &LifecycleWriteGuard,
    state_dir: &FsPath,
) -> Result<(), String> {
    let recovered =
        household_rs::bootstrap::recover_interrupted_household_teardown_under_lifecycle(
            guard, state_dir,
        )
        .map_err(|error| owner_events_lifecycle_error("recover interrupted teardown", error))?;
    if recovered {
        return Err("recovered an interrupted teardown; refusing stale owner mutation".to_string());
    }
    Ok(())
}

/// Append through the long-lived log only while the exact lifecycle
/// generation it was opened for is retained shared. All filesystem/flock I/O
/// runs on the blocking pool; async handlers never perform log I/O directly.
async fn append_owner_event_with_shared_lifecycle(
    state: &OwnerEventsRouterState,
    identity: Arc<household_rs::LoadedIdentity>,
    event_type: OwnerEventType,
    payload: OwnerEventPayload,
) -> Result<OwnerEvent, String> {
    let state_dir = state.state_dir.clone();
    let event_log = Arc::clone(&state.event_log);
    tokio::task::spawn_blocking(move || {
        let lifecycle = HouseholdLifecycleLock::open_verified(&state_dir)
            .map_err(|error| format!("open owner-event lifecycle: {error}"))?;
        let guard = lifecycle
            .lock_shared()
            .map_err(|error| format!("acquire owner-event lifecycle shared: {error}"))?;
        event_log
            .append(
                &guard,
                &identity.cert.m_id.to_string(),
                identity.m_priv.as_ref(),
                event_type,
                payload,
            )
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("owner-event append worker failed: {error}"))?
}

/// Reconcile the manifest-retained `MachineJoined` outbox before startup may
/// publish listeners, or from an exact handler retry after local promotion.
///
/// The exact candidate certificate in the signed `JoinResponse` supplies the
/// event payload. The log method uses candidate `m_id` as an idempotency key,
/// stabilizes an ambiguous existing tail, and rejects any conflicting event.
/// This function deliberately leaves the manifest in place. Startup must
/// first repair any Phase-3-specific fail-stop bootstrap breadcrumb and only
/// then durably clear the outbox; that ordering makes a crash between those
/// steps retryable without leaving generic `Recovering` permanently latched.
pub(crate) fn reconcile_phase3_machine_joined_outbox_under_lifecycle(
    state_dir: &FsPath,
    lifecycle: &LifecycleWriteGuard,
    identity: &household_rs::LoadedIdentity,
    event_log: &OwnerEventLog,
) -> Result<bool, String> {
    let Some(manifest) = household_rs::storage::read_phase3_recovery_manifest(state_dir)
        .map_err(|error| format!("read Phase-3 terminal outbox: {error}"))?
    else {
        return Ok(false);
    };
    if manifest.hh_id() != identity.record.hh_id.as_str()
        || manifest.founder_m_id() != identity.cert.m_id.as_str()
    {
        return Err("Phase-3 terminal outbox identity binding mismatch".into());
    }
    let response: household_rs::pair_machine::JoinResponse =
        household_rs::cbor::from_canonical_slice_strict(manifest.exact_join_response())
            .map_err(|error| format!("decode Phase-3 terminal outbox response: {error}"))?;
    if response.machine_cert.m_id.as_str() != manifest.candidate_m_id()
        || response.household_record != identity.record
        || !identity
            .record
            .members
            .contains(&response.machine_cert.m_id)
    {
        return Err("Phase-3 terminal outbox candidate/record binding mismatch".into());
    }
    event_log
        .append_machine_joined_exactly_once_under_lifecycle_write(
            lifecycle,
            identity.cert.m_id.as_str(),
            identity.m_priv.as_ref(),
            MachineJoinedPayload {
                m_pub: ByteBuf::from(response.machine_cert.m_pub.as_bytes().to_vec()),
                m_id: response.machine_cert.m_id.to_string(),
                hostname: response.machine_cert.hostname,
                joined_at: response.machine_cert.joined_at,
            },
        )
        .map_err(|error| format!("append Phase-3 MachineJoined outbox: {error}"))?;
    Ok(true)
}

async fn read_owner_events_with_shared_lifecycle(
    state: &OwnerEventsRouterState,
    since: u64,
) -> Result<Vec<OwnerEvent>, String> {
    let state_dir = state.state_dir.clone();
    let event_log = Arc::clone(&state.event_log);
    tokio::task::spawn_blocking(move || {
        let lifecycle = HouseholdLifecycleLock::open_verified(&state_dir)
            .map_err(|error| format!("open owner-event lifecycle: {error}"))?;
        let guard = lifecycle
            .lock_shared()
            .map_err(|error| format!("acquire owner-event lifecycle shared: {error}"))?;
        event_log
            .read_since(&guard, since)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("owner-event read worker failed: {error}"))?
}

async fn acquire_owner_events_lifecycle_exclusive(
    state_dir: &FsPath,
) -> Result<LifecycleWriteGuard, String> {
    let state_dir = state_dir.to_path_buf();
    let waiter_state_dir = state_dir.clone();
    let guard = tokio::task::spawn_blocking(move || {
        acquire_owner_events_lifecycle_exclusive_blocking(&waiter_state_dir)
    })
    .await
    .map_err(|error| owner_events_lifecycle_error("join owner-events lifecycle waiter", error))??;
    recover_owner_events_lifecycle_or_reject(&guard, state_dir.as_path())?;
    Ok(guard)
}

/// Re-read both durable identity authorities while lifecycle-exclusive and
/// require an exact match with the identity used to construct the mutation.
fn verify_installed_identity_under_lifecycle(
    guard: &LifecycleWriteGuard,
    state_dir: &FsPath,
    expected_record: &household_rs::HouseholdRecord,
    expected_cert: &household_rs::MachineCert,
) -> Result<(), String> {
    guard
        .verify_state_root(state_dir)
        .map_err(|error| owner_events_lifecycle_error("verify owner-events state root", error))?;
    let record: household_rs::HouseholdRecord = household_rs::storage::read_optional_cbor(
        &household_rs::storage::household_record_path(state_dir),
    )
    .map_err(|error| owner_events_lifecycle_error("read installed household record", error))?
    .ok_or_else(|| "installed household record is absent".to_string())?;
    let cert = household_rs::machine_cert::load_self_cert(state_dir)
        .map_err(|error| owner_events_lifecycle_error("read installed machine cert", error))?
        .ok_or_else(|| "installed machine cert is absent".to_string())?;
    if &record != expected_record || &cert != expected_cert {
        return Err(
            "installed household identity changed before owner mutation commit".to_string(),
        );
    }
    Ok(())
}

fn durably_remove_phase3_staged_after_definite_reject(
    state_dir: &FsPath,
    candidate_m_id: &str,
) -> Result<(), String> {
    let finals = [
        household_rs::storage::machine_cert_for(state_dir, candidate_m_id),
        household_rs::pair_machine::shamir_self_shard_path(state_dir),
        household_rs::storage::household_record_path(state_dir),
    ];
    let staged = finals
        .iter()
        .map(|path| household_rs::storage::staged_path_for(path))
        .collect::<Vec<_>>();
    for path in &staged {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "remove rejected Phase-3 staged artifact {}: {error}",
                    path.display()
                ));
            }
        }
    }
    let mut parents = staged
        .iter()
        .filter_map(|path| path.parent().map(FsPath::to_path_buf))
        .collect::<Vec<_>>();
    parents.sort();
    parents.dedup();
    for parent in parents {
        fs::File::open(&parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| {
                format!(
                    "stabilize rejected Phase-3 staged absence {}: {error}",
                    parent.display()
                )
            })?;
    }
    Ok(())
}

/// Commit an already-built owner authority and publish the same value to the
/// live state without a teardown/replacement gap.
async fn persist_owner_auth_under_lifecycle(
    state: &OwnerEventsRouterState,
    expected_identity: &household_rs::LoadedIdentity,
    next_auth: &household_rs::HouseholdAuthState,
) -> Result<LifecycleWriteGuard, String> {
    let lifecycle_guard = acquire_owner_events_lifecycle_exclusive(&state.state_dir).await?;
    verify_installed_identity_under_lifecycle(
        &lifecycle_guard,
        &state.state_dir,
        &expected_identity.record,
        &expected_identity.cert,
    )?;
    if let Err(error) = next_auth.save(&state.state_dir) {
        if matches!(
            error,
            household_rs::owner_auth::OwnerAuthError::Storage(
                household_rs::StorageError::MayHaveTakenEffect { .. }
            )
        ) {
            // Rewrite the exact same authority while the lifecycle guard is
            // still retained. A successful retry supplies the missing parent
            // barrier and writes the diagnostic owner-cert projection. Never
            // roll back or substitute different bytes after an indeterminate
            // rename.
            if let Err(retry_error) = next_auth.save(&state.state_dir) {
                state.household.clear().await;
                return Err(owner_events_lifecycle_error(
                    "stabilize indeterminate owner authority; live household cleared",
                    retry_error,
                ));
            }
        } else {
            return Err(owner_events_lifecycle_error(
                "persist owner authority",
                error,
            ));
        }
    }
    state
        .household
        .set_owner_auth(Arc::new(next_auth.clone()))
        .await;
    Ok(lifecycle_guard)
}

#[derive(Clone)]
pub struct OwnerEventsRouterState {
    pub household: HouseholdState,
    pub window: Arc<PairMachineWindow>,
    pub event_log: Arc<OwnerEventLog>,
    pub event_broadcaster: OwnerEventsBroadcaster,
    pub state_dir: PathBuf,
    pub long_poll_timeout: Duration,
    pub device_pairing_store: DevicePairingStore,
    /// Keystore policy under which `HH_priv` was originally persisted.
    /// `owner_approve_handler` forwards it into `CeremonyInputs` so
    /// `CeremonyTxn::commit` can destroy the right backend on Shamir
    /// transition.
    pub key_backing_policy: household_rs::KeyBackingPolicy,
    /// Owner-auth rollout policy. Defaults to legacy behavior for every
    /// operation so introducing S2 primitives cannot brick existing onboarding.
    pub owner_approval_policy: OwnerApprovalEnforcementPolicy,
    /// Tenant-scoped `WebAuthn` relying party for owner-approval ceremonies.
    ///
    /// `None` keeps the v2 owner-approval surface fail-closed. The production
    /// flip must inject a tenant RP; default router construction remains
    /// behavior-preserving.
    pub owner_webauthn_rp: Option<Arc<Mutex<OwnerWebauthnRp>>>,
    /// Keystore-backed rollback anchor verifier for owner passkey authority.
    ///
    /// Pair-machine v2 enforcement requires this before it can decide whether
    /// an owner has active credentials. This prevents a rolled-back credential
    /// log from re-enabling a revoked passkey or downgrading to legacy.
    pub owner_webauthn_anchor: Option<OwnerWebauthnAnchorVerifier>,
    /// Keystore-backed rollback anchor verifier for owner recovery readiness.
    ///
    /// This is intentionally separate from the owner `WebAuthn` authority anchor.
    /// Recovery readiness must never satisfy `WebAuthn` active-credential policy.
    pub owner_webauthn_recovery_anchor: Option<OwnerWebauthnRecoveryAnchorVerifier>,
    /// Durable, recovery-specific limiter used by recovery consume start.
    ///
    /// The limiter is injected only from daemon paths that have `SharedState`.
    /// Short-lived install/listener paths fail closed for recovery consume.
    pub recovery_consume_rate_limiter: Option<Arc<Limiter>>,
    /// macOS local-engine caller verifier for UDS-only enrollment routes.
    ///
    /// `None` is the production M1 default and rejects local enrollment before
    /// request decode or challenge staging. A future M1b must inject a real
    /// audit-token/SecCode designated-requirement verifier; tests may inject a
    /// fake verifier explicitly.
    pub macos_local_caller_auth: Option<Arc<dyn MacosLocalCallerAuth>>,
    /// Runtime state for Secure/Upgrade strong owner minting.
    ///
    /// This is absent by default. Production must opt in with the dedicated
    /// Secure/Upgrade rollout plus explicit App Attest verifier configuration.
    pub secure_upgrade_runtime: Option<SecureUpgradeRuntime>,
    /// Resolver for the founder's own Tailnet IPv4 address.
    ///
    /// Production uses the local interface detector. Tests inject a
    /// documentation-safe address without consulting the host network.
    pub founder_tailnet_resolver: TailnetResolver,
}

#[derive(Clone)]
pub struct OwnerWebauthnAnchorVerifier {
    pub keystore: Arc<dyn keystore_rs::KeystoreBackend>,
}

#[derive(Clone)]
pub struct OwnerWebauthnRecoveryAnchorVerifier {
    pub keystore: Arc<dyn keystore_rs::KeystoreBackend>,
}

#[derive(Clone)]
pub struct SecureUpgradeRuntime {
    pub challenge_store: Arc<SecureUpgradeChallengeStore>,
    pub replay_store: Arc<SecureUpgradeDurableAppAttestReplayStore>,
    pub config: SecureUpgradeRuntimeConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureUpgradeRuntimeConfig {
    pub app_team_id: String,
    pub app_bundle_id: String,
    pub proof_environment: SecureUpgradeProofEnvironment,
    pub challenge_ttl: Duration,
}

impl OwnerEventsRouterState {
    #[must_use]
    pub fn new(
        household: HouseholdState,
        window: Arc<PairMachineWindow>,
        event_log: Arc<OwnerEventLog>,
        event_broadcaster: OwnerEventsBroadcaster,
        state_dir: PathBuf,
        key_backing_policy: household_rs::KeyBackingPolicy,
    ) -> Self {
        Self::with_timeout(
            household,
            window,
            event_log,
            event_broadcaster,
            state_dir,
            key_backing_policy,
            OWNER_EVENTS_LONG_POLL_TIMEOUT,
        )
    }

    #[must_use]
    pub fn with_timeout(
        household: HouseholdState,
        window: Arc<PairMachineWindow>,
        event_log: Arc<OwnerEventLog>,
        event_broadcaster: OwnerEventsBroadcaster,
        state_dir: PathBuf,
        key_backing_policy: household_rs::KeyBackingPolicy,
        long_poll_timeout: Duration,
    ) -> Self {
        Self {
            household,
            window,
            event_log,
            event_broadcaster,
            state_dir,
            long_poll_timeout,
            device_pairing_store: DevicePairingStore::new(),
            key_backing_policy,
            owner_approval_policy: OwnerApprovalEnforcementPolicy::default(),
            owner_webauthn_rp: None,
            owner_webauthn_anchor: None,
            owner_webauthn_recovery_anchor: None,
            recovery_consume_rate_limiter: None,
            macos_local_caller_auth: None,
            secure_upgrade_runtime: None,
            founder_tailnet_resolver: current_tailnet_ipv4,
        }
    }

    #[must_use]
    pub fn with_owner_approval_policy(
        mut self,
        owner_approval_policy: OwnerApprovalEnforcementPolicy,
    ) -> Self {
        self.owner_approval_policy = owner_approval_policy;
        self
    }

    #[must_use]
    pub fn with_owner_webauthn_rp(mut self, rp: OwnerWebauthnRp) -> Self {
        self.owner_webauthn_rp = Some(Arc::new(Mutex::new(rp)));
        self
    }

    #[must_use]
    pub fn with_owner_webauthn_anchor(
        mut self,
        keystore: Arc<dyn keystore_rs::KeystoreBackend>,
    ) -> Self {
        self.owner_webauthn_anchor = Some(OwnerWebauthnAnchorVerifier { keystore });
        self
    }

    #[must_use]
    pub fn with_owner_webauthn_recovery_anchor(
        mut self,
        keystore: Arc<dyn keystore_rs::KeystoreBackend>,
    ) -> Self {
        self.owner_webauthn_recovery_anchor =
            Some(OwnerWebauthnRecoveryAnchorVerifier { keystore });
        self
    }

    #[must_use]
    pub fn with_recovery_consume_rate_limiter(mut self, limiter: Arc<Limiter>) -> Self {
        self.recovery_consume_rate_limiter = Some(limiter);
        self
    }

    #[must_use]
    pub fn with_macos_local_caller_auth(mut self, verifier: Arc<dyn MacosLocalCallerAuth>) -> Self {
        self.macos_local_caller_auth = Some(verifier);
        self
    }

    #[must_use]
    pub fn with_secure_upgrade_runtime(mut self, config: SecureUpgradeRuntimeConfig) -> Self {
        self.secure_upgrade_runtime = Some(SecureUpgradeRuntime {
            challenge_store: Arc::new(SecureUpgradeChallengeStore::new()),
            replay_store: Arc::new(SecureUpgradeDurableAppAttestReplayStore::new(
                self.state_dir.join(SECURE_UPGRADE_APP_ATTEST_REPLAY_DIR),
            )),
            config,
        });
        self
    }

    #[must_use]
    pub fn with_founder_tailnet_resolver(mut self, resolver: TailnetResolver) -> Self {
        self.founder_tailnet_resolver = resolver;
        self
    }
}

pub const OWNER_WEBAUTHN_REGISTRATION_LOCAL_START_PATH: &str =
    "/api/v1/household/owner-webauthn/registration/local/start";
pub const OWNER_WEBAUTHN_REGISTRATION_LOCAL_FINISH_PATH: &str =
    "/api/v1/household/owner-webauthn/registration/local/finish";
pub const OWNER_WEBAUTHN_REGISTRATION_LOCAL_STATUS_PATH: &str =
    "/api/v1/household/owner-webauthn/registration/local/status";
pub const SECURE_UPGRADE_APP_ATTEST_START_PATH: &str =
    "/api/v1/household/secure-upgrade/app-attest/start";
pub const SECURE_UPGRADE_APP_ATTEST_FINISH_PATH: &str =
    "/api/v1/household/secure-upgrade/app-attest/finish";

pub fn owner_webauthn_macos_local_registration_router(
    state: OwnerEventsRouterState,
) -> axum::Router {
    axum::Router::new()
        .route(
            OWNER_WEBAUTHN_REGISTRATION_LOCAL_START_PATH,
            axum::routing::post(owner_webauthn_registration_local_start_handler),
        )
        .route(
            OWNER_WEBAUTHN_REGISTRATION_LOCAL_FINISH_PATH,
            axum::routing::post(owner_webauthn_registration_local_finish_handler),
        )
        .route(
            OWNER_WEBAUTHN_REGISTRATION_LOCAL_STATUS_PATH,
            axum::routing::post(owner_webauthn_registration_local_status_handler),
        )
        .with_state(state)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerApprovalEnforcementPolicy {
    pub pair_machine_approve: OwnerOperationEnforcement,
    pub bootstrap_initialize: OwnerOperationEnforcement,
    pub bootstrap_teardown: OwnerOperationEnforcement,
    pub pair_device_confirm: OwnerOperationEnforcement,
    pub revoke_credential: OwnerOperationEnforcement,
    pub recovery_code: RecoveryCodeEnforcement,
    pub add_credential: OwnerOperationEnforcement,
    pub secure_upgrade: SecureUpgradeEnforcement,
}

impl Default for OwnerApprovalEnforcementPolicy {
    fn default() -> Self {
        Self {
            pair_machine_approve: OwnerOperationEnforcement::LegacyOnly,
            bootstrap_initialize: OwnerOperationEnforcement::LegacyOnly,
            bootstrap_teardown: OwnerOperationEnforcement::LegacyOnly,
            pair_device_confirm: OwnerOperationEnforcement::LegacyOnly,
            revoke_credential: OwnerOperationEnforcement::LegacyOnly,
            recovery_code: RecoveryCodeEnforcement::Disabled,
            add_credential: OwnerOperationEnforcement::LegacyOnly,
            secure_upgrade: SecureUpgradeEnforcement::Disabled,
        }
    }
}

impl OwnerApprovalEnforcementPolicy {
    /// Enables only the owner-auth v2 operations that have landed and been
    /// reviewed. Recovery remains a dedicated break-glass/recovery-code policy
    /// switch; its runtime does not use active credential count as a gate.
    #[must_use]
    pub fn reviewed_core_v2_rollout() -> Self {
        Self::default()
            .with_pair_machine_approve(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential)
            .with_revoke_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential)
            .with_recovery_code(RecoveryCodeEnforcement::BreakGlassEnabled)
            .with_add_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential)
    }

    #[must_use]
    pub fn with_pair_machine_approve(mut self, mode: OwnerOperationEnforcement) -> Self {
        self.pair_machine_approve = mode;
        self
    }

    #[must_use]
    pub fn with_revoke_credential(mut self, mode: OwnerOperationEnforcement) -> Self {
        self.revoke_credential = mode;
        self
    }

    #[must_use]
    pub fn with_recovery_code(mut self, mode: RecoveryCodeEnforcement) -> Self {
        self.recovery_code = mode;
        self
    }

    #[must_use]
    pub fn with_add_credential(mut self, mode: OwnerOperationEnforcement) -> Self {
        self.add_credential = mode;
        self
    }

    #[must_use]
    pub fn with_secure_upgrade(mut self, mode: SecureUpgradeEnforcement) -> Self {
        self.secure_upgrade = mode;
        self
    }

    #[must_use]
    pub fn pair_machine_approval_body_mode(
        &self,
        owner_webauthn_trust_state: OwnerWebauthnTrustState,
    ) -> PairMachineApprovalBodyMode {
        self.pair_machine_approve
            .body_mode(owner_webauthn_trust_state)
    }

    #[must_use]
    fn revoke_credential_start_enabled(&self) -> bool {
        self.revoke_credential == OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential
    }

    #[must_use]
    fn recovery_code_enabled(&self) -> bool {
        self.recovery_code == RecoveryCodeEnforcement::BreakGlassEnabled
    }

    #[must_use]
    fn add_credential_start_enabled(&self) -> bool {
        self.add_credential == OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential
    }

    #[must_use]
    pub fn secure_upgrade_strong_minting_enabled(&self) -> bool {
        self.secure_upgrade == SecureUpgradeEnforcement::StrongMintingEnabled
    }
}

#[must_use]
pub fn owner_approval_policy_from_env() -> OwnerApprovalEnforcementPolicy {
    owner_approval_policy_from_rollout_value(
        std::env::var(OWNER_AUTH_V2_ROLLOUT_ENV).ok().as_deref(),
    )
}

#[must_use]
pub fn owner_approval_policy_from_rollout_value(
    raw: Option<&str>,
) -> OwnerApprovalEnforcementPolicy {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        None | Some("off" | "legacy" | "legacy-only") => OwnerApprovalEnforcementPolicy::default(),
        Some(OWNER_AUTH_V2_REVIEWED_CORE_ROLLOUT) => {
            OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout()
        }
        Some(OWNER_AUTH_V2_SECURE_UPGRADE_ROLLOUT) => {
            OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout()
                .with_secure_upgrade(SecureUpgradeEnforcement::StrongMintingEnabled)
        }
        Some(_) => {
            tracing::warn!(
                env = OWNER_AUTH_V2_ROLLOUT_ENV,
                "unknown owner-auth v2 rollout value; keeping LegacyOnly policy"
            );
            OwnerApprovalEnforcementPolicy::default()
        }
    }
}

pub fn secure_upgrade_runtime_config_from_env() -> Result<SecureUpgradeRuntimeConfig, String> {
    let app_team_id = required_secure_upgrade_env(SECURE_UPGRADE_APP_ATTEST_TEAM_ID_ENV)?;
    let app_bundle_id = required_secure_upgrade_env(SECURE_UPGRADE_APP_ATTEST_BUNDLE_ID_ENV)?;
    let proof_environment =
        match required_secure_upgrade_env(SECURE_UPGRADE_APP_ATTEST_ENVIRONMENT_ENV)?.as_str() {
            "development" => SecureUpgradeProofEnvironment::Development,
            "production" => SecureUpgradeProofEnvironment::Production,
            _ => return Err("invalid_app_attest_environment".to_string()),
        };
    let challenge_ttl_secs = match std::env::var(SECURE_UPGRADE_CHALLENGE_TTL_SECS_ENV) {
        Ok(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse::<u64>()
            .map_err(|_| "invalid_challenge_ttl_secs".to_string())?,
        _ => SECURE_UPGRADE_DEFAULT_CHALLENGE_TTL_SECS,
    };
    if challenge_ttl_secs == 0 {
        return Err("invalid_challenge_ttl_secs".to_string());
    }
    Ok(SecureUpgradeRuntimeConfig {
        app_team_id,
        app_bundle_id,
        proof_environment,
        challenge_ttl: Duration::from_secs(challenge_ttl_secs),
    })
}

fn required_secure_upgrade_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing_{name}"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureUpgradeEnforcement {
    Disabled,
    /// Enables the reviewed Secure/Upgrade ceremony runtime and strong owner
    /// provenance minting. This remains separate from `reviewed-core-v2`.
    StrongMintingEnabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryCodeEnforcement {
    Disabled,
    /// Enables the dedicated recovery-code break-glass runtime. This is not an
    /// active `WebAuthn` credential gate; the recovery runtime treats
    /// pre-active-credential count as telemetry.
    BreakGlassEnabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerOperationEnforcement {
    /// Preserve the existing v1 owner-PoP approval path.
    LegacyOnly,
    /// Require v2 only after the owner has at least one active `WebAuthn`
    /// credential. Before enrollment exists, fall back to legacy so this flag
    /// cannot brick pair-machine onboarding during migration.
    V2WhenOwnerHasActiveCredential,
}

impl OwnerOperationEnforcement {
    #[must_use]
    fn body_mode(
        self,
        owner_webauthn_trust_state: OwnerWebauthnTrustState,
    ) -> PairMachineApprovalBodyMode {
        match (self, owner_webauthn_trust_state) {
            (Self::LegacyOnly, _)
            | (Self::V2WhenOwnerHasActiveCredential, OwnerWebauthnTrustState::NeverEnrolled) => {
                PairMachineApprovalBodyMode::LegacyV1
            }
            (Self::V2WhenOwnerHasActiveCredential, OwnerWebauthnTrustState::Active { .. }) => {
                PairMachineApprovalBodyMode::RequireV2
            }
            (
                Self::V2WhenOwnerHasActiveCredential,
                OwnerWebauthnTrustState::RecoveryRequired | OwnerWebauthnTrustState::AnchorInvalid,
            ) => PairMachineApprovalBodyMode::RejectFailClosed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerWebauthnTrustState {
    NeverEnrolled,
    Active { count: usize },
    RecoveryRequired,
    AnchorInvalid,
}

#[derive(Clone, Debug)]
struct OwnerWebauthnPolicySnapshot {
    trust_state: OwnerWebauthnTrustState,
    credentials: Option<OwnerWebauthnCredentialStore>,
}

impl OwnerWebauthnPolicySnapshot {
    fn never_enrolled() -> Self {
        Self {
            trust_state: OwnerWebauthnTrustState::NeverEnrolled,
            credentials: None,
        }
    }

    fn recovery_required() -> Self {
        Self {
            trust_state: OwnerWebauthnTrustState::RecoveryRequired,
            credentials: None,
        }
    }

    fn anchor_invalid() -> Self {
        Self {
            trust_state: OwnerWebauthnTrustState::AnchorInvalid,
            credentials: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairMachineApprovalBodyMode {
    LegacyV1,
    RequireV2,
    RejectFailClosed,
}

pub fn reassert_pair_machine_approval_context_against_live_window(
    approved_context: &OwnerApprovalContextV2,
    live_snapshot: &PairMachineWindowSnapshot,
) -> Result<(), OwnerApprovalV2Error> {
    if approved_context.op != OwnerOperation::PairMachineApprove {
        return Err(OwnerApprovalV2Error::TrustedState(
            "operation is not pair-machine approve",
        ));
    }
    let cursor = approved_context
        .cursor
        .ok_or(OwnerApprovalV2Error::MissingField("cursor"))?;
    if live_snapshot.state != PairMachineState::AwaitingOwner
        || live_snapshot.owner_event_cursor != Some(cursor)
    {
        return Err(OwnerApprovalV2Error::TrustedState(
            "live window cursor changed",
        ));
    }
    if live_snapshot.approval_claim.is_some() {
        return Err(OwnerApprovalV2Error::TrustedState(
            "live window already claimed",
        ));
    }
    if live_snapshot.expiry != approved_context.ttl_unix {
        return Err(OwnerApprovalV2Error::TrustedState(
            "live window ttl changed",
        ));
    }
    if live_snapshot.addr_hint.as_deref() != approved_context.addr.as_deref() {
        return Err(OwnerApprovalV2Error::TrustedState(
            "live window addr changed",
        ));
    }
    if live_snapshot.transport != approved_context.transport {
        return Err(OwnerApprovalV2Error::TrustedState(
            "live window transport changed",
        ));
    }
    if live_snapshot.nonce.as_ref().map(ByteBuf::as_ref)
        != approved_context.nonce.as_ref().map(ByteBuf::as_ref)
    {
        return Err(OwnerApprovalV2Error::TrustedState(
            "live window nonce changed",
        ));
    }
    let cached_join_request =
        live_snapshot
            .cached_join_request
            .as_ref()
            .ok_or(OwnerApprovalV2Error::TrustedState(
                "missing live cached join request",
            ))?;
    let live_join_request_hash = join_request_hash(cached_join_request);
    if approved_context
        .join_request_hash
        .as_ref()
        .map(ByteBuf::as_ref)
        != Some(live_join_request_hash.as_slice())
    {
        return Err(OwnerApprovalV2Error::TrustedState(
            "live join request changed",
        ));
    }
    Ok(())
}

fn owner_approval_v2_capabilities() -> Vec<String> {
    vec!["machine-cert".to_string(), "shamir-2pc".to_string()]
}

fn owner_revoke_credential_v2_capabilities() -> Vec<String> {
    vec!["owner-auth-revoke".to_string()]
}

fn owner_recovery_code_v2_capabilities() -> Vec<String> {
    vec!["owner-auth-recovery-provision".to_string()]
}

fn owner_add_credential_v2_capabilities() -> Vec<String> {
    vec!["owner-auth-add-credential".to_string()]
}

fn owner_recovery_consume_v2_capabilities() -> Vec<String> {
    vec!["owner-auth-recovery-consume".to_string()]
}

fn pair_machine_window_data(
    cursor: u64,
    snapshot: PairMachineWindowSnapshot,
) -> Result<PairMachineWindowData, &'static str> {
    if snapshot.state != PairMachineState::AwaitingOwner
        || snapshot.owner_event_cursor != Some(cursor)
    {
        return Err("window_cursor_mismatch");
    }
    if snapshot.approval_claim.is_some() {
        return Err("window_already_claimed");
    }
    let active_m_pub = snapshot.m_pub.clone().ok_or("window_missing_m_pub")?;
    let cached_join_request = snapshot
        .cached_join_request
        .clone()
        .ok_or("missing_cached_join_request")?;
    let join_request = household_rs::cbor::from_canonical_slice(cached_join_request.as_ref())
        .map_err(|_| "cached_join_request_decode")?;
    Ok(PairMachineWindowData {
        snapshot,
        active_m_pub,
        cached_join_request,
        join_request,
    })
}

fn pair_machine_expected_context_from_snapshot(
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
    snapshot: &PairMachineWindowSnapshot,
    now: u64,
    challenge_ttl_secs: u64,
    replay_nonce: [u8; 32],
) -> Result<OwnerApprovalContextV2, OwnerApprovalV2Error> {
    OwnerApprovalContextV2::pair_machine_approve_from_trusted_state(
        PairMachineTrustedContextInput {
            hh_id: identity.record.hh_id.clone(),
            owner_p_id: owner_auth.owner_person_cert.p_id.clone(),
            snapshot,
            capabilities: owner_approval_v2_capabilities(),
            issued_at: now,
            challenge_ttl_secs,
            replay_nonce,
        },
    )
}

fn owner_auth_allows_fan_out(
    stage: &'static str,
    owner_auth: &household_rs::HouseholdAuthState,
) -> bool {
    if owner_auth.owner_can_fan_out() {
        return true;
    }
    tracing::warn!(stage = stage, reason = "owner_auth_tier_not_strong",);
    false
}

fn pair_machine_owner_webauthn_policy_snapshot(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
) -> OwnerWebauthnPolicySnapshot {
    if state.owner_approval_policy.pair_machine_approve == OwnerOperationEnforcement::LegacyOnly {
        return OwnerWebauthnPolicySnapshot::never_enrolled();
    }

    let Some(verifier) = state.owner_webauthn_anchor.as_ref() else {
        return OwnerWebauthnPolicySnapshot::anchor_invalid();
    };
    let anchor_status = verify_or_update_owner_webauthn_authority_anchor(
        verifier.keystore.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    );
    match anchor_status {
        Ok(OwnerWebauthnAnchorStatus::EmptyAuthorityNoAnchor) => {
            OwnerWebauthnPolicySnapshot::never_enrolled()
        }
        Ok(
            OwnerWebauthnAnchorStatus::Verified { .. }
            | OwnerWebauthnAnchorStatus::Advanced { .. }
            | OwnerWebauthnAnchorStatus::Migrated { .. },
        ) => match owner_auth.owner_webauthn_credentials(&identity.record) {
            Ok(credentials) => {
                let active_count = credentials.active_count();
                if active_count == 0 {
                    OwnerWebauthnPolicySnapshot::recovery_required()
                } else {
                    OwnerWebauthnPolicySnapshot {
                        trust_state: OwnerWebauthnTrustState::Active {
                            count: active_count,
                        },
                        credentials: Some(credentials),
                    }
                }
            }
            Err(_) => OwnerWebauthnPolicySnapshot::anchor_invalid(),
        },
        Err(_) => OwnerWebauthnPolicySnapshot::anchor_invalid(),
    }
}

struct OwnerWebauthnRevokeCredentialStartSnapshot {
    credentials: OwnerWebauthnCredentialStore,
    authority_head: OwnerWebauthnAuthorityHead,
    pre_active_credential_count: u64,
}

struct OwnerWebauthnRevokeCredentialFinishPlan {
    actor_credential: household_rs::owner_webauthn::OwnerWebauthnCredential,
    expected_context: OwnerApprovalContextV2,
    previous_entry: SignedOwnerWebauthnCredentialEvent,
    target_credential_id: ByteBuf,
    pre_active_credential_count: u64,
}

struct OwnerWebauthnRecoveryStartSnapshot {
    credentials: OwnerWebauthnCredentialStore,
    webauthn_head: OwnerWebauthnAuthorityHead,
    pre_active_credential_count: u64,
    recovery_head: Option<RecoveryAuthorityHeadInput>,
}

struct OwnerWebauthnRecoveryFinishPlan {
    actor_credential: household_rs::owner_webauthn::OwnerWebauthnCredential,
    expected_context: OwnerApprovalContextV2,
    previous_recovery_entry: Option<SignedOwnerWebauthnRecoveryEvent>,
    authoritative_sequence: Option<u64>,
}

struct OwnerWebauthnRecoveryConsumeStartPlan {
    credentials: OwnerWebauthnCredentialStore,
    webauthn_head: OwnerWebauthnAuthorityHead,
    recovery_head: OwnerWebauthnRecoveryHead,
    pre_active_credential_count: u64,
}

struct OwnerWebauthnRecoveryConsumeFinishPlan {
    expected_context: OwnerApprovalContextV2,
    registration_binding: OwnerWebauthnRegistrationBinding,
    recovery_head: OwnerWebauthnRecoveryHead,
    previous_webauthn_entry: SignedOwnerWebauthnCredentialEvent,
    previous_recovery_entry: SignedOwnerWebauthnRecoveryEvent,
    pre_active_credential_count: u64,
}

struct OwnerWebauthnAddCredentialStartPlan {
    credentials: OwnerWebauthnCredentialStore,
    webauthn_head: OwnerWebauthnAuthorityHead,
    pre_active_credential_count: u64,
}

struct OwnerWebauthnAddCredentialFinishPlan {
    actor_credential: household_rs::owner_webauthn::OwnerWebauthnCredential,
    expected_context: OwnerApprovalContextV2,
    registration_binding: OwnerWebauthnRegistrationBinding,
    previous_entry: SignedOwnerWebauthnCredentialEvent,
    pre_active_credential_count: u64,
}

const OWNER_WEBAUTHN_RECOVERY_CONSUME_REGISTRATION_BINDING_PURPOSE: &str =
    "owner-webauthn-recovery-consume-registration-v1";
const OWNER_WEBAUTHN_ADD_CREDENTIAL_REGISTRATION_BINDING_PURPOSE: &str =
    "owner-webauthn-add-credential-registration-v1";

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRecoveryConsumeRegistrationBindingContext {
    #[serde(rename = "v")]
    version: u8,
    purpose: String,
    op: String,
    hh_id: household_rs::HouseholdId,
    owner_p_id: household_rs::PersonId,
    authority_head_sequence: u64,
    authority_head_hash: ByteBuf,
    pre_active_credential_count: u64,
    recovery_head_sequence: u64,
    recovery_head_hash: ByteBuf,
    capabilities: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    replay_nonce: ByteBuf,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnAddCredentialRegistrationBindingContext {
    #[serde(rename = "v")]
    version: u8,
    purpose: String,
    op: String,
    hh_id: household_rs::HouseholdId,
    owner_p_id: household_rs::PersonId,
    authority_head_sequence: u64,
    authority_head_hash: ByteBuf,
    pre_active_credential_count: u64,
    capabilities: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    replay_nonce: ByteBuf,
}

fn owner_webauthn_active_snapshot_read_only(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
) -> Result<
    (
        OwnerWebauthnCredentialStore,
        OwnerWebauthnAuthorityHead,
        u64,
    ),
    &'static str,
> {
    let Some(verifier) = state.owner_webauthn_anchor.as_ref() else {
        return Err("missing_anchor_verifier");
    };
    let webauthn_head = match classify_owner_webauthn_authority_anchor_read_only(
        verifier.keystore.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
    ) {
        Ok(
            OwnerWebauthnAnchorStatus::Verified { head }
            | OwnerWebauthnAnchorStatus::Advanced { head, .. },
        ) => head,
        Ok(OwnerWebauthnAnchorStatus::EmptyAuthorityNoAnchor) => return Err("never_enrolled"),
        Ok(OwnerWebauthnAnchorStatus::Migrated { .. }) => {
            return Err("unexpected_anchor_migration");
        }
        Err(_) => return Err("credential_anchor_invalid"),
    };
    let credentials = owner_auth
        .owner_webauthn_credentials(&identity.record)
        .map_err(|_| "credential_reconstruct_failed")?;
    let active_count = credentials.active_count();
    if active_count == 0 {
        return Err("credential_recovery_required");
    }
    let active_count = u64::try_from(active_count).map_err(|_| "credential_count_overflow")?;
    Ok((credentials, webauthn_head, active_count))
}

fn owner_webauthn_recovery_head_read_only(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
) -> Result<
    (
        Option<RecoveryAuthorityHeadInput>,
        Option<OwnerWebauthnRecoveryHead>,
    ),
    &'static str,
> {
    let Some(verifier) = state.owner_webauthn_recovery_anchor.as_ref() else {
        return Err("missing_recovery_anchor_verifier");
    };
    match classify_owner_webauthn_recovery_anchor_read_only(
        verifier.keystore.as_ref(),
        &owner_auth.owner_webauthn_recovery,
        &identity.record,
        &owner_auth.owner_person_cert,
    ) {
        Ok(OwnerWebauthnRecoveryAnchorStatus::EmptyRecoveryNoAnchor) => Ok((None, None)),
        Ok(
            OwnerWebauthnRecoveryAnchorStatus::Verified { head }
            | OwnerWebauthnRecoveryAnchorStatus::Created { head },
        ) => Ok((
            Some(RecoveryAuthorityHeadInput {
                sequence: head.sequence,
                head_hash: head.head_hash,
            }),
            Some(head),
        )),
        Ok(OwnerWebauthnRecoveryAnchorStatus::Advanced { previous, .. }) => Ok((
            Some(RecoveryAuthorityHeadInput {
                sequence: previous.sequence(),
                head_hash: previous
                    .head_hash()
                    .try_into()
                    .map_err(|_| "recovery_anchor_hash_length")?,
            }),
            Some(OwnerWebauthnRecoveryHead {
                sequence: previous.sequence(),
                head_hash: previous
                    .head_hash()
                    .try_into()
                    .map_err(|_| "recovery_anchor_hash_length")?,
            }),
        )),
        Err(OwnerWebauthnRecoveryAnchorError::MissingAnchor) => {
            let head = verified_owner_webauthn_recovery_head(
                &owner_auth.owner_webauthn_recovery,
                &identity.record,
                &owner_auth.owner_person_cert,
            )
            .map_err(|_| "recovery_anchor_invalid")?
            .ok_or("recovery_anchor_missing_empty")?;
            if head.sequence == 0 {
                Ok((None, None))
            } else {
                Err("recovery_anchor_missing")
            }
        }
        Err(_) => Err("recovery_anchor_invalid"),
    }
}

fn owner_webauthn_recovery_start_snapshot(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
) -> Result<OwnerWebauthnRecoveryStartSnapshot, &'static str> {
    if !state.owner_approval_policy.recovery_code_enabled() {
        return Err("recovery_code_policy_disabled");
    }
    let (credentials, webauthn_head, pre_active_credential_count) =
        owner_webauthn_active_snapshot_read_only(state, identity, owner_auth)?;
    let (recovery_head, _) = owner_webauthn_recovery_head_read_only(state, identity, owner_auth)?;
    Ok(OwnerWebauthnRecoveryStartSnapshot {
        credentials,
        webauthn_head,
        pre_active_credential_count,
        recovery_head,
    })
}

fn owner_webauthn_recovery_finish_plan(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
    submitted_context: &OwnerApprovalContextV2,
    actor_credential_id: &[u8],
) -> Result<OwnerWebauthnRecoveryFinishPlan, &'static str> {
    if !state.owner_approval_policy.recovery_code_enabled() {
        return Err("recovery_code_policy_disabled");
    }
    let bound_sequence = submitted_context
        .authority_head_sequence
        .ok_or("recovery_webauthn_head_sequence_missing")?;
    let bound_hash = submitted_context
        .authority_head_hash
        .as_ref()
        .ok_or("recovery_webauthn_head_hash_missing")?;
    let pre_active_credential_count = submitted_context
        .pre_active_credential_count
        .ok_or("recovery_active_count_missing")?;
    let submitted_recovery_head = match (
        submitted_context.recovery_head_sequence,
        submitted_context.recovery_head_hash.as_ref(),
    ) {
        (None, None) => None,
        (Some(sequence), Some(hash)) => {
            let head_hash: [u8; 32] = hash
                .as_ref()
                .try_into()
                .map_err(|_| "recovery_head_hash_length")?;
            Some(RecoveryAuthorityHeadInput {
                sequence,
                head_hash,
            })
        }
        (Some(_), None) => return Err("recovery_head_hash_missing"),
        (None, Some(_)) => return Err("recovery_head_sequence_missing"),
    };
    let replay_nonce: [u8; 32] = submitted_context
        .replay_nonce
        .as_ref()
        .try_into()
        .map_err(|_| "recovery_replay_nonce_length")?;

    let (credentials, webauthn_head, active_count) =
        owner_webauthn_active_snapshot_read_only(state, identity, owner_auth)?;
    if webauthn_head.sequence != bound_sequence || webauthn_head.head_hash != bound_hash.as_ref() {
        return Err("recovery_webauthn_head_mismatch");
    }
    if active_count != pre_active_credential_count {
        return Err("recovery_active_count_mismatch");
    }
    let Some(actor_credential) = credentials
        .credentials()
        .iter()
        .find(|credential| {
            credential.credential_id_bytes() == actor_credential_id && !credential.is_revoked()
        })
        .cloned()
    else {
        return Err("recovery_actor_not_active");
    };

    let (recovery_head, authoritative_recovery_head) =
        owner_webauthn_recovery_head_read_only(state, identity, owner_auth)?;
    if recovery_head != submitted_recovery_head {
        return Err("recovery_head_mismatch");
    }
    let expected_context =
        OwnerApprovalContextV2::provision_recovery_code(ProvisionRecoveryCodeContextInput {
            hh_id: identity.record.hh_id.clone(),
            owner_p_id: owner_auth.owner_person_cert.p_id.clone(),
            authority_head_sequence: webauthn_head.sequence,
            authority_head_hash: webauthn_head.head_hash,
            pre_active_credential_count: active_count,
            recovery_head,
            capabilities: owner_recovery_code_v2_capabilities(),
            issued_at: submitted_context.issued_at,
            expires_at: submitted_context.expires_at,
            replay_nonce,
        });
    expected_context
        .validate_shape()
        .map_err(|_| "recovery_expected_context_invalid")?;
    Ok(OwnerWebauthnRecoveryFinishPlan {
        actor_credential,
        expected_context,
        previous_recovery_entry: authoritative_recovery_head.as_ref().and_then(|head| {
            usize::try_from(head.sequence)
                .ok()
                .and_then(|index| owner_auth.owner_webauthn_recovery.entries().get(index))
                .cloned()
        }),
        authoritative_sequence: authoritative_recovery_head.map(|head| head.sequence),
    })
}

fn owner_webauthn_recovery_ready_status(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
) -> Result<bool, &'static str> {
    let Some(verifier) = state.owner_webauthn_recovery_anchor.as_ref() else {
        return Err("missing_recovery_anchor_verifier");
    };
    match classify_owner_webauthn_recovery_anchor_read_only(
        verifier.keystore.as_ref(),
        &owner_auth.owner_webauthn_recovery,
        &identity.record,
        &owner_auth.owner_person_cert,
    ) {
        Ok(
            OwnerWebauthnRecoveryAnchorStatus::EmptyRecoveryNoAnchor
            | OwnerWebauthnRecoveryAnchorStatus::Advanced { .. },
        ) => Ok(false),
        Ok(
            OwnerWebauthnRecoveryAnchorStatus::Verified { .. }
            | OwnerWebauthnRecoveryAnchorStatus::Created { .. },
        ) => Ok(owner_auth.owner_webauthn_recovery.recovery_ready()),
        Err(OwnerWebauthnRecoveryAnchorError::MissingAnchor) => {
            let head = verified_owner_webauthn_recovery_head(
                &owner_auth.owner_webauthn_recovery,
                &identity.record,
                &owner_auth.owner_person_cert,
            )
            .map_err(|_| "recovery_anchor_invalid")?
            .ok_or("recovery_anchor_missing_empty")?;
            if head.sequence == 0 {
                Ok(false)
            } else {
                Err("recovery_anchor_missing")
            }
        }
        Err(_) => Err("recovery_anchor_invalid"),
    }
}

fn owner_webauthn_recovery_consume_start_plan(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
    recovery_code: &[u8],
) -> Result<OwnerWebauthnRecoveryConsumeStartPlan, &'static str> {
    if !state.owner_approval_policy.recovery_code_enabled() {
        return Err("recovery_code_policy_disabled");
    }
    let Some(rate_limiter) = state.recovery_consume_rate_limiter.as_ref() else {
        return Err("recovery_consume_rate_limiter_unavailable");
    };
    if check_recovery_consume_attempt(
        rate_limiter.as_ref(),
        &identity.record.hh_id,
        &owner_auth.owner_person_cert.p_id,
    ) != RecoveryConsumeRateLimitDecision::Allowed
    {
        return Err("recovery_consume_rate_limited");
    }

    let Some(webauthn_anchor) = state.owner_webauthn_anchor.as_ref() else {
        return Err("missing_anchor_verifier");
    };
    let webauthn_anchor_status = classify_owner_webauthn_authority_anchor_read_only(
        webauthn_anchor.keystore.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
    )
    .map_err(|_| "credential_anchor_invalid")?;
    let credentials = owner_auth
        .owner_webauthn_credentials(&identity.record)
        .map_err(|_| "credential_reconstruct_failed")?;
    let pre_active_credential_count =
        u64::try_from(credentials.active_count()).map_err(|_| "credential_count_overflow")?;

    let Some(recovery_anchor) = state.owner_webauthn_recovery_anchor.as_ref() else {
        return Err("missing_recovery_anchor_verifier");
    };
    let recovery_anchor_status = classify_owner_webauthn_recovery_anchor_read_only(
        recovery_anchor.keystore.as_ref(),
        &owner_auth.owner_webauthn_recovery,
        &identity.record,
        &owner_auth.owner_person_cert,
    )
    .map_err(|_| "recovery_anchor_invalid")?;
    let readiness = classify_owner_webauthn_recovery_consume_readiness(
        &owner_auth.owner_webauthn,
        &webauthn_anchor_status,
        &owner_auth.owner_webauthn_recovery,
        &recovery_anchor_status,
        pre_active_credential_count,
    )
    .map_err(|_| "recovery_consume_classifier_failed")?;
    let OwnerWebauthnRecoveryConsumeReadiness::Consumable {
        webauthn_head,
        recovery_head,
        pre_active_credential_count,
    } = readiness
    else {
        return Err("recovery_consume_not_consumable");
    };
    let Some(verifier) = owner_auth.owner_webauthn_recovery.latest_verifier() else {
        return Err("recovery_verifier_missing");
    };
    if !verifier
        .matches_code_bytes(recovery_code)
        .map_err(|_| "recovery_verifier_invalid")?
    {
        return Err("recovery_code_mismatch");
    }

    Ok(OwnerWebauthnRecoveryConsumeStartPlan {
        credentials,
        webauthn_head,
        recovery_head,
        pre_active_credential_count,
    })
}

fn owner_webauthn_entry_at_head(
    owner_auth: &household_rs::HouseholdAuthState,
    head: &OwnerWebauthnAuthorityHead,
) -> Result<SignedOwnerWebauthnCredentialEvent, &'static str> {
    let index = usize::try_from(head.sequence).map_err(|_| "credential_head_sequence_overflow")?;
    let entry = owner_auth
        .owner_webauthn
        .entries()
        .get(index)
        .ok_or("credential_head_entry_missing")?;
    if entry
        .entry_hash()
        .map_err(|_| "credential_head_hash_failed")?
        != head.head_hash
    {
        return Err("credential_head_hash_mismatch");
    }
    Ok(entry.clone())
}

fn recovery_entry_at_head(
    owner_auth: &household_rs::HouseholdAuthState,
    head: &OwnerWebauthnRecoveryHead,
) -> Result<SignedOwnerWebauthnRecoveryEvent, &'static str> {
    let index = usize::try_from(head.sequence).map_err(|_| "recovery_head_sequence_overflow")?;
    let entry = owner_auth
        .owner_webauthn_recovery
        .entries()
        .get(index)
        .ok_or("recovery_head_entry_missing")?;
    if entry
        .entry_hash()
        .map_err(|_| "recovery_head_hash_failed")?
        != head.head_hash
    {
        return Err("recovery_head_hash_mismatch");
    }
    Ok(entry.clone())
}

fn owner_webauthn_recovery_consume_finish_plan(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
    context: &OwnerApprovalContextV2,
    recovery_code: &[u8],
) -> Result<OwnerWebauthnRecoveryConsumeFinishPlan, &'static str> {
    if !state.owner_approval_policy.recovery_code_enabled() {
        return Err("recovery_code_policy_disabled");
    }
    let Some(rate_limiter) = state.recovery_consume_rate_limiter.as_ref() else {
        return Err("recovery_consume_rate_limiter_unavailable");
    };
    if check_recovery_consume_attempt(
        rate_limiter.as_ref(),
        &identity.record.hh_id,
        &owner_auth.owner_person_cert.p_id,
    ) != RecoveryConsumeRateLimitDecision::Allowed
    {
        return Err("recovery_consume_rate_limited");
    }

    let Some(webauthn_anchor) = state.owner_webauthn_anchor.as_ref() else {
        return Err("missing_anchor_verifier");
    };
    let webauthn_anchor_status = classify_owner_webauthn_authority_anchor_read_only(
        webauthn_anchor.keystore.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
    )
    .map_err(|_| "credential_anchor_invalid")?;
    let credentials = owner_auth
        .owner_webauthn_credentials(&identity.record)
        .map_err(|_| "credential_reconstruct_failed")?;
    let pre_active_credential_count =
        u64::try_from(credentials.active_count()).map_err(|_| "credential_count_overflow")?;

    let Some(recovery_anchor) = state.owner_webauthn_recovery_anchor.as_ref() else {
        return Err("missing_recovery_anchor_verifier");
    };
    let recovery_anchor_status = classify_owner_webauthn_recovery_anchor_read_only(
        recovery_anchor.keystore.as_ref(),
        &owner_auth.owner_webauthn_recovery,
        &identity.record,
        &owner_auth.owner_person_cert,
    )
    .map_err(|_| "recovery_anchor_invalid")?;
    let readiness = classify_owner_webauthn_recovery_consume_readiness(
        &owner_auth.owner_webauthn,
        &webauthn_anchor_status,
        &owner_auth.owner_webauthn_recovery,
        &recovery_anchor_status,
        pre_active_credential_count,
    )
    .map_err(|_| "recovery_consume_classifier_failed")?;
    let OwnerWebauthnRecoveryConsumeReadiness::Consumable {
        webauthn_head,
        recovery_head,
        pre_active_credential_count,
    } = readiness
    else {
        return Err("recovery_consume_not_consumable");
    };

    let registration_binding =
        owner_webauthn_recovery_consume_registration_binding_from_context(context)?;
    let replay_nonce = bytebuf_to_array_32(
        context.replay_nonce.as_ref(),
        "recovery_consume_replay_nonce_invalid",
    )?;
    let expected_context =
        OwnerApprovalContextV2::recover_credential(RecoverCredentialContextInput {
            hh_id: identity.record.hh_id.clone(),
            owner_p_id: owner_auth.owner_person_cert.p_id.clone(),
            new_credential_binding_hash: registration_binding.binding_digest(),
            authority_head_sequence: webauthn_head.sequence,
            authority_head_hash: webauthn_head.head_hash,
            pre_active_credential_count,
            recovery_head: RecoveryAuthorityHeadInput {
                sequence: recovery_head.sequence,
                head_hash: recovery_head.head_hash,
            },
            capabilities: owner_recovery_consume_v2_capabilities(),
            issued_at: context.issued_at,
            expires_at: context.expires_at,
            replay_nonce,
        });
    if &expected_context != context {
        return Err("recovery_consume_context_mismatch");
    }
    let Some(verifier) = owner_auth.owner_webauthn_recovery.latest_verifier() else {
        return Err("recovery_verifier_missing");
    };
    if !verifier
        .matches_code_bytes(recovery_code)
        .map_err(|_| "recovery_verifier_invalid")?
    {
        return Err("recovery_code_mismatch");
    }

    Ok(OwnerWebauthnRecoveryConsumeFinishPlan {
        expected_context,
        registration_binding,
        previous_webauthn_entry: owner_webauthn_entry_at_head(owner_auth, &webauthn_head)?,
        previous_recovery_entry: recovery_entry_at_head(owner_auth, &recovery_head)?,
        recovery_head,
        pre_active_credential_count,
    })
}

fn owner_webauthn_add_credential_start_plan(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
) -> Result<OwnerWebauthnAddCredentialStartPlan, &'static str> {
    if !state.owner_approval_policy.add_credential_start_enabled() {
        return Err("add_credential_policy_disabled");
    }

    let Some(verifier) = state.owner_webauthn_anchor.as_ref() else {
        return Err("missing_anchor_verifier");
    };
    let webauthn_head = match classify_owner_webauthn_authority_anchor_read_only(
        verifier.keystore.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
    ) {
        Ok(
            OwnerWebauthnAnchorStatus::Verified { head }
            | OwnerWebauthnAnchorStatus::Advanced { head, .. },
        ) => head,
        Ok(OwnerWebauthnAnchorStatus::EmptyAuthorityNoAnchor) => return Err("never_enrolled"),
        Ok(OwnerWebauthnAnchorStatus::Migrated { .. }) => {
            return Err("unexpected_anchor_migration");
        }
        Err(_) => return Err("credential_anchor_invalid"),
    };
    let credentials = owner_auth
        .owner_webauthn_credentials(&identity.record)
        .map_err(|_| "credential_reconstruct_failed")?;
    let active_count = credentials.active_count();
    if active_count == 0 {
        return Err("add_credential_no_active_credentials");
    }
    let pre_active_credential_count =
        u64::try_from(active_count).map_err(|_| "credential_count_overflow")?;
    Ok(OwnerWebauthnAddCredentialStartPlan {
        credentials,
        webauthn_head,
        pre_active_credential_count,
    })
}

fn owner_webauthn_add_credential_finish_plan(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
    submitted_context: &OwnerApprovalContextV2,
    actor_credential_id: &[u8],
) -> Result<OwnerWebauthnAddCredentialFinishPlan, &'static str> {
    if !state.owner_approval_policy.add_credential_start_enabled() {
        return Err("add_credential_policy_disabled");
    }
    let registration_binding =
        owner_webauthn_add_credential_registration_binding_from_context(submitted_context)?;
    let replay_nonce = bytebuf_to_array_32(
        submitted_context.replay_nonce.as_ref(),
        "add_credential_replay_nonce_invalid",
    )?;
    let bound_sequence = submitted_context
        .authority_head_sequence
        .ok_or("add_credential_head_sequence_missing")?;
    let bound_hash = submitted_context
        .authority_head_hash
        .as_ref()
        .ok_or("add_credential_head_hash_missing")?;
    let pre_active_credential_count = submitted_context
        .pre_active_credential_count
        .ok_or("add_credential_count_missing")?;

    let (credentials, webauthn_head, active_count) =
        owner_webauthn_active_snapshot_read_only(state, identity, owner_auth)?;
    if webauthn_head.sequence != bound_sequence || webauthn_head.head_hash != bound_hash.as_ref() {
        return Err("add_credential_head_mismatch");
    }
    if active_count != pre_active_credential_count {
        return Err("add_credential_count_mismatch");
    }
    let Some(actor_credential) = credentials
        .credentials()
        .iter()
        .find(|credential| {
            credential.credential_id_bytes() == actor_credential_id && !credential.is_revoked()
        })
        .cloned()
    else {
        return Err("add_credential_actor_not_active");
    };
    let previous_entry = owner_auth
        .owner_webauthn
        .entries()
        .last()
        .cloned()
        .ok_or("add_credential_authority_head_missing")?;
    if previous_entry
        .entry_hash()
        .map_err(|_| "add_credential_authority_head_failed")?
        != webauthn_head.head_hash
    {
        return Err("add_credential_authority_head_mismatch");
    }

    let expected_context = OwnerApprovalContextV2::add_credential(AddCredentialContextInput {
        hh_id: identity.record.hh_id.clone(),
        owner_p_id: owner_auth.owner_person_cert.p_id.clone(),
        new_credential_binding_hash: registration_binding.binding_digest(),
        authority_head_sequence: webauthn_head.sequence,
        authority_head_hash: webauthn_head.head_hash,
        pre_active_credential_count: active_count,
        capabilities: owner_add_credential_v2_capabilities(),
        issued_at: submitted_context.issued_at,
        expires_at: submitted_context.expires_at,
        replay_nonce,
    });
    expected_context
        .validate_shape()
        .map_err(|_| "add_credential_expected_context_invalid")?;

    Ok(OwnerWebauthnAddCredentialFinishPlan {
        actor_credential,
        expected_context,
        registration_binding,
        previous_entry,
        pre_active_credential_count: active_count,
    })
}

fn owner_webauthn_recovery_consume_registration_binding(
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
    plan: &OwnerWebauthnRecoveryConsumeStartPlan,
    capabilities: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    replay_nonce: [u8; 32],
) -> Result<OwnerWebauthnRegistrationBinding, &'static str> {
    let binding_context = OwnerWebauthnRecoveryConsumeRegistrationBindingContext {
        version: 1,
        purpose: OWNER_WEBAUTHN_RECOVERY_CONSUME_REGISTRATION_BINDING_PURPOSE.to_string(),
        op: "recover-credential".to_string(),
        hh_id: identity.record.hh_id.clone(),
        owner_p_id: owner_auth.owner_person_cert.p_id.clone(),
        authority_head_sequence: plan.webauthn_head.sequence,
        authority_head_hash: ByteBuf::from(plan.webauthn_head.head_hash.to_vec()),
        pre_active_credential_count: plan.pre_active_credential_count,
        recovery_head_sequence: plan.recovery_head.sequence,
        recovery_head_hash: ByteBuf::from(plan.recovery_head.head_hash.to_vec()),
        capabilities,
        issued_at,
        expires_at,
        replay_nonce: ByteBuf::from(replay_nonce.to_vec()),
    };
    let canonical = household_rs::cbor::to_canonical_vec(&binding_context)
        .map_err(|_| "recovery_consume_binding_cbor")?;
    OwnerWebauthnRegistrationBinding::from_canonical_binding(
        OWNER_WEBAUTHN_RECOVERY_CONSUME_REGISTRATION_BINDING_PURPOSE,
        canonical,
    )
    .map_err(|_| "recovery_consume_binding_invalid")
}

fn owner_webauthn_add_credential_registration_binding(
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
    plan: &OwnerWebauthnAddCredentialStartPlan,
    capabilities: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    replay_nonce: [u8; 32],
) -> Result<OwnerWebauthnRegistrationBinding, &'static str> {
    let binding_context = OwnerWebauthnAddCredentialRegistrationBindingContext {
        version: 1,
        purpose: OWNER_WEBAUTHN_ADD_CREDENTIAL_REGISTRATION_BINDING_PURPOSE.to_string(),
        op: "add-credential".to_string(),
        hh_id: identity.record.hh_id.clone(),
        owner_p_id: owner_auth.owner_person_cert.p_id.clone(),
        authority_head_sequence: plan.webauthn_head.sequence,
        authority_head_hash: ByteBuf::from(plan.webauthn_head.head_hash.to_vec()),
        pre_active_credential_count: plan.pre_active_credential_count,
        capabilities,
        issued_at,
        expires_at,
        replay_nonce: ByteBuf::from(replay_nonce.to_vec()),
    };
    let canonical = household_rs::cbor::to_canonical_vec(&binding_context)
        .map_err(|_| "add_credential_binding_cbor")?;
    OwnerWebauthnRegistrationBinding::from_canonical_binding(
        OWNER_WEBAUTHN_ADD_CREDENTIAL_REGISTRATION_BINDING_PURPOSE,
        canonical,
    )
    .map_err(|_| "add_credential_binding_invalid")
}

fn owner_webauthn_add_credential_registration_binding_from_context(
    context: &OwnerApprovalContextV2,
) -> Result<OwnerWebauthnRegistrationBinding, &'static str> {
    let expected_digest = bytebuf_to_array_32(
        context
            .new_credential_binding_hash
            .as_ref()
            .ok_or("add_credential_missing_binding_hash")?
            .as_ref(),
        "add_credential_binding_hash_invalid",
    )?;
    let authority_head_hash = bytebuf_to_array_32(
        context
            .authority_head_hash
            .as_ref()
            .ok_or("add_credential_missing_authority_head_hash")?
            .as_ref(),
        "add_credential_authority_head_hash_invalid",
    )?;
    let binding_context = OwnerWebauthnAddCredentialRegistrationBindingContext {
        version: 1,
        purpose: OWNER_WEBAUTHN_ADD_CREDENTIAL_REGISTRATION_BINDING_PURPOSE.to_string(),
        op: "add-credential".to_string(),
        hh_id: context.hh_id.clone(),
        owner_p_id: context.owner_p_id.clone(),
        authority_head_sequence: context
            .authority_head_sequence
            .ok_or("add_credential_missing_authority_head_sequence")?,
        authority_head_hash: ByteBuf::from(authority_head_hash.to_vec()),
        pre_active_credential_count: context
            .pre_active_credential_count
            .ok_or("add_credential_missing_pre_active_count")?,
        capabilities: context.capabilities.clone(),
        issued_at: context.issued_at,
        expires_at: context.expires_at,
        replay_nonce: context.replay_nonce.clone(),
    };
    let canonical = household_rs::cbor::to_canonical_vec(&binding_context)
        .map_err(|_| "add_credential_binding_cbor")?;
    let binding = OwnerWebauthnRegistrationBinding::from_canonical_binding(
        OWNER_WEBAUTHN_ADD_CREDENTIAL_REGISTRATION_BINDING_PURPOSE,
        canonical,
    )
    .map_err(|_| "add_credential_binding_invalid")?;
    if binding.binding_digest() != expected_digest {
        return Err("add_credential_binding_digest_mismatch");
    }
    Ok(binding)
}

fn bytebuf_to_array_32(bytes: &[u8], reason: &'static str) -> Result<[u8; 32], &'static str> {
    bytes.try_into().map_err(|_| reason)
}

fn recovery_consume_context_webauthn_head(
    context: &OwnerApprovalContextV2,
) -> Result<OwnerWebauthnAuthorityHead, &'static str> {
    Ok(OwnerWebauthnAuthorityHead {
        sequence: context
            .authority_head_sequence
            .ok_or("recovery_consume_missing_authority_head_sequence")?,
        head_hash: bytebuf_to_array_32(
            context
                .authority_head_hash
                .as_ref()
                .ok_or("recovery_consume_missing_authority_head_hash")?
                .as_ref(),
            "recovery_consume_authority_head_hash_invalid",
        )?,
    })
}

fn recovery_consume_context_recovery_head(
    context: &OwnerApprovalContextV2,
) -> Result<OwnerWebauthnRecoveryHead, &'static str> {
    Ok(OwnerWebauthnRecoveryHead {
        sequence: context
            .recovery_head_sequence
            .ok_or("recovery_consume_missing_recovery_head_sequence")?,
        head_hash: bytebuf_to_array_32(
            context
                .recovery_head_hash
                .as_ref()
                .ok_or("recovery_consume_missing_recovery_head_hash")?
                .as_ref(),
            "recovery_consume_recovery_head_hash_invalid",
        )?,
    })
}

fn owner_webauthn_recovery_consume_registration_binding_from_context(
    context: &OwnerApprovalContextV2,
) -> Result<OwnerWebauthnRegistrationBinding, &'static str> {
    let webauthn_head = recovery_consume_context_webauthn_head(context)?;
    let recovery_head = recovery_consume_context_recovery_head(context)?;
    let expected_digest = bytebuf_to_array_32(
        context
            .new_credential_binding_hash
            .as_ref()
            .ok_or("recovery_consume_missing_binding_hash")?
            .as_ref(),
        "recovery_consume_binding_hash_invalid",
    )?;
    let binding_context = OwnerWebauthnRecoveryConsumeRegistrationBindingContext {
        version: 1,
        purpose: OWNER_WEBAUTHN_RECOVERY_CONSUME_REGISTRATION_BINDING_PURPOSE.to_string(),
        op: "recover-credential".to_string(),
        hh_id: context.hh_id.clone(),
        owner_p_id: context.owner_p_id.clone(),
        authority_head_sequence: webauthn_head.sequence,
        authority_head_hash: ByteBuf::from(webauthn_head.head_hash.to_vec()),
        pre_active_credential_count: context
            .pre_active_credential_count
            .ok_or("recovery_consume_missing_pre_active_count")?,
        recovery_head_sequence: recovery_head.sequence,
        recovery_head_hash: ByteBuf::from(recovery_head.head_hash.to_vec()),
        capabilities: context.capabilities.clone(),
        issued_at: context.issued_at,
        expires_at: context.expires_at,
        replay_nonce: context.replay_nonce.clone(),
    };
    let canonical = household_rs::cbor::to_canonical_vec(&binding_context)
        .map_err(|_| "recovery_consume_binding_cbor")?;
    let binding = OwnerWebauthnRegistrationBinding::from_canonical_binding(
        OWNER_WEBAUTHN_RECOVERY_CONSUME_REGISTRATION_BINDING_PURPOSE,
        canonical,
    )
    .map_err(|_| "recovery_consume_binding_invalid")?;
    if binding.binding_digest() != expected_digest {
        return Err("recovery_consume_binding_digest_mismatch");
    }
    Ok(binding)
}

fn recovery_consume_committed_webauthn_add(
    owner_auth: &household_rs::HouseholdAuthState,
    webauthn_head: &OwnerWebauthnAuthorityHead,
    recovery_head: &OwnerWebauthnRecoveryHead,
) -> Result<Option<ByteBuf>, &'static str> {
    let previous_index =
        usize::try_from(webauthn_head.sequence).map_err(|_| "credential_head_sequence_overflow")?;
    let Some(previous_entry) = owner_auth.owner_webauthn.entries().get(previous_index) else {
        return Err("credential_head_entry_missing");
    };
    if previous_entry
        .entry_hash()
        .map_err(|_| "credential_head_hash_failed")?
        != webauthn_head.head_hash
    {
        return Err("credential_head_hash_mismatch");
    }
    let next_index = previous_index
        .checked_add(1)
        .ok_or("credential_next_sequence_overflow")?;
    let Some(entry) = owner_auth.owner_webauthn.entries().get(next_index) else {
        return Ok(None);
    };
    let matches_recovery_actor = matches!(
        &entry.event.actor,
        OwnerWebauthnEventActor::RecoveryProof {
            recovery_head_sequence,
            recovery_head_hash,
        } if *recovery_head_sequence == recovery_head.sequence
            && recovery_head_hash.as_ref() == recovery_head.head_hash
    );
    match (&entry.event.action, matches_recovery_actor) {
        (OwnerWebauthnCredentialEventAction::Add { credential }, true) => Ok(Some(ByteBuf::from(
            credential.credential_id_bytes().to_vec(),
        ))),
        (_, false) => Ok(None),
        _ => Err("recovery_consume_committed_webauthn_event_invalid"),
    }
}

fn recovery_consume_committed_recovery_consume(
    owner_auth: &household_rs::HouseholdAuthState,
    recovery_head: &OwnerWebauthnRecoveryHead,
) -> Result<bool, &'static str> {
    let previous_index =
        usize::try_from(recovery_head.sequence).map_err(|_| "recovery_head_sequence_overflow")?;
    let Some(previous_entry) = owner_auth
        .owner_webauthn_recovery
        .entries()
        .get(previous_index)
    else {
        return Err("recovery_head_entry_missing");
    };
    if previous_entry
        .entry_hash()
        .map_err(|_| "recovery_head_hash_failed")?
        != recovery_head.head_hash
    {
        return Err("recovery_head_hash_mismatch");
    }
    let next_index = previous_index
        .checked_add(1)
        .ok_or("recovery_next_sequence_overflow")?;
    let Some(entry) = owner_auth.owner_webauthn_recovery.entries().get(next_index) else {
        return Ok(false);
    };
    let matches_recovery_actor = matches!(
        &entry.event.actor,
        OwnerWebauthnRecoveryActor::RecoveryProof {
            verifier_head_sequence,
            verifier_head_hash,
        } if *verifier_head_sequence == recovery_head.sequence
            && verifier_head_hash.as_ref() == recovery_head.head_hash
    );
    match (&entry.event.action, matches_recovery_actor) {
        (OwnerWebauthnRecoveryEventAction::Consume, true) => Ok(true),
        (_, false) => Ok(false),
        _ => Err("recovery_consume_committed_recovery_event_invalid"),
    }
}

fn recovery_consume_finish_response(
    owner_auth: &household_rs::HouseholdAuthState,
    identity: &household_rs::LoadedIdentity,
    credential_id: ByteBuf,
) -> Result<OwnerWebauthnRecoveryConsumeFinishResponse, &'static str> {
    let credentials = owner_auth
        .owner_webauthn_credentials(&identity.record)
        .map_err(|_| "credential_reconstruct_failed")?;
    Ok(OwnerWebauthnRecoveryConsumeFinishResponse {
        version: 1,
        credential_id,
        active_credential_count: u64::try_from(credentials.active_count())
            .map_err(|_| "credential_count_overflow")?,
        recovery_ready: owner_auth.owner_webauthn_recovery.recovery_ready(),
    })
}

fn repair_recovery_consume_finish_if_committed(
    webauthn_anchor: &dyn keystore_rs::KeystoreBackend,
    recovery_anchor: &dyn keystore_rs::KeystoreBackend,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
    context: &OwnerApprovalContextV2,
) -> Result<Option<OwnerWebauthnRecoveryConsumeFinishResponse>, &'static str> {
    owner_webauthn_recovery_consume_registration_binding_from_context(context)?;
    if context.hh_id != identity.record.hh_id
        || context.owner_p_id != owner_auth.owner_person_cert.p_id
    {
        return Err("recovery_consume_context_identity_mismatch");
    }
    let webauthn_head = recovery_consume_context_webauthn_head(context)?;
    let recovery_head = recovery_consume_context_recovery_head(context)?;
    let maybe_credential_id =
        recovery_consume_committed_webauthn_add(owner_auth, &webauthn_head, &recovery_head)?;
    let recovery_consumed =
        recovery_consume_committed_recovery_consume(owner_auth, &recovery_head)?;
    match (maybe_credential_id, recovery_consumed) {
        (None, false) => Ok(None),
        (Some(_), false) | (None, true) => Err("recovery_consume_partial_commit"),
        (Some(credential_id), true) => {
            verify_or_update_owner_webauthn_authority_anchor(
                webauthn_anchor,
                &owner_auth.owner_webauthn,
                &identity.record,
                &owner_auth.owner_person_cert,
                OwnerWebauthnAnchorMode::Enforcement,
            )
            .map_err(|_| "recovery_consume_webauthn_anchor_repair_failed")?;
            advance_owner_webauthn_recovery_anchor_after_commit(
                recovery_anchor,
                &owner_auth.owner_webauthn_recovery,
                &identity.record,
                &owner_auth.owner_person_cert,
            )
            .map_err(|_| "recovery_consume_recovery_anchor_repair_failed")?;
            recovery_consume_finish_response(owner_auth, identity, credential_id).map(Some)
        }
    }
}

fn owner_webauthn_revoke_credential_start_snapshot(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
    target_credential_id: &[u8],
) -> Result<OwnerWebauthnRevokeCredentialStartSnapshot, &'static str> {
    if !state
        .owner_approval_policy
        .revoke_credential_start_enabled()
    {
        return Err("revoke_credential_policy_disabled");
    }

    let Some(verifier) = state.owner_webauthn_anchor.as_ref() else {
        return Err("missing_anchor_verifier");
    };
    let authority_head = match classify_owner_webauthn_authority_anchor_read_only(
        verifier.keystore.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
    ) {
        Ok(
            OwnerWebauthnAnchorStatus::Verified { head }
            | OwnerWebauthnAnchorStatus::Advanced { head, .. },
        ) => head,
        Ok(OwnerWebauthnAnchorStatus::EmptyAuthorityNoAnchor) => return Err("never_enrolled"),
        Ok(OwnerWebauthnAnchorStatus::Migrated { .. }) => {
            return Err("unexpected_anchor_migration");
        }
        Err(_) => return Err("credential_anchor_invalid"),
    };
    let credentials = owner_auth
        .owner_webauthn_credentials(&identity.record)
        .map_err(|_| "credential_reconstruct_failed")?;
    let active_count = credentials.active_count();
    if active_count <= 1 {
        return Err("revoke_credential_last_active");
    }
    let target_is_active = credentials
        .active_credentials()
        .iter()
        .any(|credential| credential.credential_id_bytes() == target_credential_id);
    if !target_is_active {
        return Err("revoke_credential_target_not_active");
    }
    let pre_active_credential_count =
        u64::try_from(active_count).map_err(|_| "credential_count_overflow")?;
    Ok(OwnerWebauthnRevokeCredentialStartSnapshot {
        credentials,
        authority_head,
        pre_active_credential_count,
    })
}
fn owner_webauthn_revoke_credential_finish_plan(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
    submitted_context: &OwnerApprovalContextV2,
    actor_credential_id: &[u8],
) -> Result<OwnerWebauthnRevokeCredentialFinishPlan, &'static str> {
    if !state
        .owner_approval_policy
        .revoke_credential_start_enabled()
    {
        return Err("revoke_credential_policy_disabled");
    }

    let target_credential_id = submitted_context
        .target_credential_id
        .as_ref()
        .ok_or("revoke_credential_target_missing")?;
    let bound_sequence = submitted_context
        .authority_head_sequence
        .ok_or("revoke_credential_head_sequence_missing")?;
    let bound_hash = submitted_context
        .authority_head_hash
        .as_ref()
        .ok_or("revoke_credential_head_hash_missing")?;
    let pre_active_credential_count = submitted_context
        .pre_active_credential_count
        .ok_or("revoke_credential_count_missing")?;
    let replay_nonce: [u8; 32] = submitted_context
        .replay_nonce
        .as_ref()
        .try_into()
        .map_err(|_| "revoke_credential_replay_nonce_length")?;

    let Some(verifier) = state.owner_webauthn_anchor.as_ref() else {
        return Err("missing_anchor_verifier");
    };
    let authority_head = match classify_owner_webauthn_authority_anchor_read_only(
        verifier.keystore.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
    ) {
        Ok(
            OwnerWebauthnAnchorStatus::Verified { head }
            | OwnerWebauthnAnchorStatus::Advanced { head, .. },
        ) => head,
        Ok(OwnerWebauthnAnchorStatus::EmptyAuthorityNoAnchor) => return Err("never_enrolled"),
        Ok(OwnerWebauthnAnchorStatus::Migrated { .. }) => {
            return Err("unexpected_anchor_migration");
        }
        Err(_) => return Err("credential_anchor_invalid"),
    };
    let credentials = owner_auth
        .owner_webauthn_credentials(&identity.record)
        .map_err(|_| "credential_reconstruct_failed")?;
    let active_count = credentials.active_count();
    let active_count_u64 = u64::try_from(active_count).map_err(|_| "credential_count_overflow")?;
    if active_count <= 1 {
        return Err("revoke_credential_last_active");
    }
    let target_is_active = credentials
        .active_credentials()
        .iter()
        .any(|credential| credential.credential_id_bytes() == target_credential_id.as_ref());
    if !target_is_active {
        return Err("revoke_credential_target_not_active");
    }
    let Some(actor_credential) = credentials
        .credentials()
        .iter()
        .find(|credential| {
            credential.credential_id_bytes() == actor_credential_id && !credential.is_revoked()
        })
        .cloned()
    else {
        return Err("revoke_credential_actor_not_active");
    };
    if authority_head.sequence != bound_sequence || authority_head.head_hash != bound_hash.as_ref()
    {
        return Err("revoke_credential_head_mismatch");
    }
    if active_count_u64 != pre_active_credential_count {
        return Err("revoke_credential_count_mismatch");
    }
    let previous_entry = owner_auth
        .owner_webauthn
        .entries()
        .last()
        .cloned()
        .ok_or("revoke_credential_authority_head_missing")?;
    if previous_entry
        .entry_hash()
        .map_err(|_| "revoke_credential_authority_head_failed")?
        != authority_head.head_hash
    {
        return Err("revoke_credential_authority_head_mismatch");
    }
    let expected_context =
        OwnerApprovalContextV2::revoke_credential(RevokeCredentialContextInput {
            hh_id: identity.record.hh_id.clone(),
            owner_p_id: owner_auth.owner_person_cert.p_id.clone(),
            target_credential_id: target_credential_id.to_vec(),
            authority_head_sequence: authority_head.sequence,
            authority_head_hash: authority_head.head_hash,
            pre_active_credential_count: active_count_u64,
            capabilities: owner_revoke_credential_v2_capabilities(),
            issued_at: submitted_context.issued_at,
            expires_at: submitted_context.expires_at,
            replay_nonce,
        });
    expected_context
        .validate_shape()
        .map_err(|_| "revoke_credential_expected_context_invalid")?;

    Ok(OwnerWebauthnRevokeCredentialFinishPlan {
        actor_credential,
        expected_context,
        previous_entry,
        target_credential_id: target_credential_id.clone(),
        pre_active_credential_count: active_count_u64,
    })
}

fn parse_pair_machine_approval_body(
    mode: PairMachineApprovalBodyMode,
    cursor: u64,
    body: &[u8],
) -> Result<PairMachineApprovalWireBody, &'static str> {
    match mode {
        PairMachineApprovalBodyMode::RejectFailClosed => Err("owner_webauthn_trust_not_satisfied"),
        PairMachineApprovalBodyMode::LegacyV1 => {
            let approval: OwnerApproval =
                household_rs::cbor::from_canonical_slice(body).map_err(|_| "cbor_decode")?;
            match approval.to_canonical_bytes() {
                Ok(canonical) if canonical == body => {}
                Ok(_) => return Err("non_canonical_cbor"),
                Err(_) => return Err("cbor_reencode"),
            }
            if approval.version != 1 || approval.cursor != cursor {
                return Err("body_cursor_mismatch");
            }
            Ok(PairMachineApprovalWireBody::LegacyV1(approval))
        }
        PairMachineApprovalBodyMode::RequireV2 => {
            let finish: OwnerApprovalV2Finish =
                household_rs::cbor::from_canonical_slice(body).map_err(|_| "cbor_decode")?;
            let canonical =
                household_rs::cbor::to_canonical_vec(&finish).map_err(|_| "cbor_reencode")?;
            if canonical != body {
                return Err("non_canonical_cbor");
            }
            if finish.version != 1 || finish.approval.context.cursor != Some(cursor) {
                return Err("body_cursor_mismatch");
            }
            finish
                .approval
                .validate_shape()
                .map_err(|_| "approval_v2_shape")?;
            Ok(PairMachineApprovalWireBody::V2(Box::new(finish)))
        }
    }
}

#[derive(Serialize)]
struct OwnerEventsResponse {
    #[serde(rename = "v")]
    version: u8,
    events: Vec<OwnerEvent>,
    next_cursor: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerApprovalV2StartRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Serialize)]
struct OwnerApprovalV2StartResponse {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    context: OwnerApprovalContextV2,
    options: RequestChallengeResponse,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SecureUpgradeStartRequest {
    #[serde(rename = "v")]
    version: u8,
    proof_key_id: String,
    platform: SecureUpgradePlatform,
}

#[derive(Serialize)]
struct SecureUpgradeStartResponse {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    canonical_transcript_cbor: ByteBuf,
    challenge_sha256: ByteBuf,
    expires_at: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SecureUpgradeFinishRequest {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    canonical_transcript_cbor: ByteBuf,
    attestation_object_cbor: ByteBuf,
    owner_signature: ByteBuf,
}

#[derive(Serialize)]
struct SecureUpgradeFinishResponse {
    #[serde(rename = "v")]
    version: u8,
    owner_person_cert: PersonCert,
    owner_auth_tier: String,
    owner_provenance: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRevokeCredentialStartRequest {
    #[serde(rename = "v")]
    version: u8,
    target_credential_id: ByteBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRecoveryStartRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRecoveryConsumeStartRequest {
    #[serde(rename = "v")]
    version: u8,
    recovery_code: String,
}

#[derive(Serialize)]
struct OwnerWebauthnRecoveryConsumeStartResponse {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    context: OwnerApprovalContextV2,
    options: CreationChallengeResponse,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnAddCredentialStartRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Serialize)]
struct OwnerWebauthnAddCredentialStartResponse {
    #[serde(rename = "v")]
    version: u8,
    registration: OwnerWebauthnRegistrationStartResponse,
    approval: OwnerApprovalV2StartResponse,
    context: OwnerApprovalContextV2,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnAddCredentialFinishRequest {
    #[serde(rename = "v")]
    version: u8,
    context: OwnerApprovalContextV2,
    registration: OwnerWebauthnRegistrationFinishRequest,
    approval: OwnerApprovalV2Finish,
}

#[derive(Serialize)]
struct OwnerWebauthnAddCredentialFinishResponse {
    #[serde(rename = "v")]
    version: u8,
    credential_id: ByteBuf,
    active_credential_count: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRecoveryConsumeFinishRequest {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    context: OwnerApprovalContextV2,
    credential: RegisterPublicKeyCredential,
    recovery_code: String,
}

#[derive(Serialize)]
struct OwnerWebauthnRecoveryConsumeFinishResponse {
    #[serde(rename = "v")]
    version: u8,
    credential_id: ByteBuf,
    active_credential_count: u64,
    recovery_ready: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRecoveryStatusRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Serialize)]
struct OwnerWebauthnRecoveryStatusResponse {
    #[serde(rename = "v")]
    version: u8,
    ready: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRegistrationStartRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Serialize)]
struct OwnerWebauthnRegistrationStartResponse {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    options: CreationChallengeResponse,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRegistrationFinishRequest {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    credential: RegisterPublicKeyCredential,
}

#[derive(Serialize)]
struct OwnerWebauthnRegistrationFinishResponse {
    #[serde(rename = "v")]
    version: u8,
    credential_id: ByteBuf,
    active_credential_count: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRegistrationStatusRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Serialize)]
struct OwnerWebauthnRegistrationStatusResponse {
    #[serde(rename = "v")]
    version: u8,
    enrolled: bool,
}

#[derive(Serialize)]
struct OwnerWebauthnRevokeCredentialFinishResponse {
    #[serde(rename = "v")]
    version: u8,
    active_credential_count: u64,
}

#[derive(Serialize)]
struct OwnerWebauthnRecoveryFinishResponse {
    #[serde(rename = "v")]
    version: u8,
    recovery_code: String,
    recovery_ready: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnInitialEnrollmentAnchorMarker {
    #[serde(rename = "v")]
    version: u8,
    purpose: String,
    hh_id: household_rs::HouseholdId,
    owner_p_id: household_rs::PersonId,
    credential_id: ByteBuf,
    authority_head_sequence: u64,
    authority_head_hash: ByteBuf,
    active_credential_count: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerApprovalV2Finish {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    approval: OwnerApprovalV2,
}

enum PairMachineApprovalWireBody {
    LegacyV1(OwnerApproval),
    V2(Box<OwnerApprovalV2Finish>),
}

struct PairMachineWindowData {
    snapshot: PairMachineWindowSnapshot,
    active_m_pub: ByteBuf,
    cached_join_request: ByteBuf,
    join_request: JoinRequest,
}

#[derive(Deserialize)]
struct PushTokenRegisterRequest {
    #[serde(rename = "v")]
    version: u8,
    platform: String,
    push_token: ByteBuf,
}

#[derive(Serialize)]
struct PushTokenRegisterResponse {
    #[serde(rename = "v")]
    version: u8,
    updated_at: u64,
}

#[derive(Serialize)]
struct OwnerDeclineAck {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Serialize)]
struct OwnerApprovalAck {
    #[serde(rename = "v")]
    version: u8,
    machine_cert_hash: ByteBuf,
}

#[derive(Serialize)]
struct GenericError<'a> {
    #[serde(rename = "v")]
    version: u8,
    error: &'a str,
}

enum FinalizeAttempt {
    Acked(Box<CeremonyTxn>, Box<FinalizeWithM2Outcome>),
    DefiniteFailure(Box<CeremonyTxn>, CeremonyError),
    AmbiguousFailure(CeremonyError),
}

fn cbor_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut resp = (status, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    resp
}

fn generic_error_response(status: StatusCode, error: &'static str) -> Response {
    let bytes = household_rs::cbor::to_canonical_vec(&GenericError { version: 1, error })
        .unwrap_or_default();
    cbor_response(status, bytes)
}

fn unauthenticated_response() -> Response {
    generic_error_response(StatusCode::UNAUTHORIZED, "unauthenticated")
}

fn internal_error_response() -> Response {
    generic_error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal")
}

fn decode_canonical_cbor<T>(body: &[u8]) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = household_rs::cbor::from_canonical_slice(body).map_err(|e| e.to_string())?;
    let canonical = household_rs::cbor::to_canonical_vec(&value).map_err(|e| e.to_string())?;
    if canonical != body {
        return Err("non_canonical_cbor".into());
    }
    Ok(value)
}

/// `GET /api/v1/household/owner-events?since=<cursor>` long-poll endpoint.
///
/// The cursor is base64url-no-pad over a deterministic-CBOR unsigned integer.
/// Auth failures and malformed cursors collapse to the generic Phase 3
/// unauthenticated surface; operator-only detail is emitted via tracing.
pub async fn owner_events_long_poll(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("owner_events.long_poll.clock") else {
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
            stage = "owner_events.long_poll.rejected",
            reason = "pop_auth_failed",
            error = %e,
        );
        return unauthenticated_response();
    }

    let Ok(since) = decode_since_cursor(&uri) else {
        tracing::warn!(
            stage = "owner_events.long_poll.rejected",
            reason = "cursor_decode",
        );
        return unauthenticated_response();
    };

    if state.event_log.cursor_head() > since {
        return owner_events_since_response(&state, since).await;
    }

    let mut subscription = state.event_broadcaster.subscribe();

    // Close the race where an append lands after the initial head check but
    // before this request subscribes to the broadcaster.
    if state.event_log.cursor_head() > since {
        return owner_events_since_response(&state, since).await;
    }

    let timeout = tokio::time::sleep(state.long_poll_timeout);
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            biased;

            () = &mut timeout => {
                // Positive observability gate (T093) — the long-poll
                // wait elapsed without any matching owner event. Distinct
                // from `long_poll.rejected` (auth/decode failure) so the
                // audit can distinguish "owner is idle / iPhone is
                // backgrounded" from "request was malformed".
                tracing::info!(
                    stage = "owner_events.long_poll.timeout",
                    since = since,
                );
                return StatusCode::NO_CONTENT.into_response();
            }
            received = subscription.receiver_mut().recv() => {
                match received {
                    Ok(event) if event.cursor > since => {
                        return owner_events_since_response(&state, since).await;
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) => {
                        if state.event_log.cursor_head() > since {
                            return owner_events_since_response(&state, since).await;
                        }
                    }
                    Err(RecvError::Closed) => {
                        return StatusCode::NO_CONTENT.into_response();
                    }
                }
            }
        }
    }
}

fn decode_since_cursor(uri: &Uri) -> Result<u64, ()> {
    let query = uri.query().ok_or(())?;
    let raw = query
        .split('&')
        .find_map(|part| {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            (key == "since").then_some(value)
        })
        .ok_or(())?;
    if raw.is_empty() {
        return Err(());
    }
    let bytes = B64URL.decode(raw).map_err(|_| ())?;
    household_rs::cbor::from_canonical_slice::<u64>(&bytes).map_err(|_| ())
}

async fn owner_events_since_response(state: &OwnerEventsRouterState, since: u64) -> Response {
    let events = match read_owner_events_with_shared_lifecycle(state, since).await {
        Ok(events) => events,
        Err(e) => {
            tracing::error!(
                stage = "owner_events.long_poll.read_failed",
                error = %e,
            );
            return internal_error_response();
        }
    };
    let next_cursor = events.last().map_or(since, |event| event.cursor);
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerEventsResponse {
        version: 1,
        events,
        next_cursor,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/secure-upgrade/app-attest/start`.
///
/// Issues a server-authoritative Secure/Upgrade transcript. The client supplies
/// only its App Attest proof key id and target platform; owner identity, app
/// identity, environment, challenge id, and expiry are bound by the server.
pub async fn secure_upgrade_app_attest_start_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("owner_events.secure_upgrade_start.clock")
    else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let authorized_owner_auth = match household_auth::authorize_secure_upgrade_start_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        now,
    )
    .await
    {
        Ok(owner_auth) => owner_auth,
        Err(e) => return reject_secure_upgrade("pop_auth_failed", Some(e.to_string())),
    };
    let request: SecureUpgradeStartRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_secure_upgrade("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_secure_upgrade("bad_version", None);
    }
    let runtime = match secure_upgrade_runtime_or_reject(&state) {
        Ok(runtime) => runtime.clone(),
        Err(response) => return *response,
    };

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_secure_upgrade("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_secure_upgrade("owner_auth_unavailable", None);
    };
    if current_owner_auth.owner_person_cert.p_id != authorized_owner_auth.owner_person_cert.p_id {
        return reject_secure_upgrade("owner_auth_changed", None);
    }
    if current_owner_auth
        .owner_person_cert
        .has_strong_owner_provenance()
    {
        return reject_secure_upgrade("owner_already_strong", None);
    }

    let challenge_id = secure_upgrade_challenge_id();
    let expires_at = now.saturating_add(runtime.config.challenge_ttl.as_secs());
    let transcript = SecureUpgradeTranscript::app_attest(SecureUpgradeAppAttestTranscriptInput {
        hh_id: identity.record.hh_id.clone(),
        owner_p_id: current_owner_auth.owner_person_cert.p_id.clone(),
        owner_key_id: secure_upgrade_owner_key_id(current_owner_auth.as_ref()),
        challenge_id: challenge_id.clone(),
        issued_at: now,
        expires_at,
        app_team_id: runtime.config.app_team_id.clone(),
        app_bundle_id: runtime.config.app_bundle_id.clone(),
        proof_key_id: request.proof_key_id,
        proof_environment: runtime.config.proof_environment,
        platform: request.platform,
    });
    let record = match runtime.challenge_store.issue(&transcript, now) {
        Ok(record) => record,
        Err(e) => return reject_secure_upgrade("challenge_issue_failed", Some(e.to_string())),
    };
    let response = SecureUpgradeStartResponse {
        version: 1,
        challenge_id: record.challenge_id().to_string(),
        canonical_transcript_cbor: ByteBuf::from(record.canonical_transcript_bytes().to_vec()),
        challenge_sha256: ByteBuf::from(record.challenge_digest().to_vec()),
        expires_at: record.expires_at_unix(),
    };
    let bytes = household_rs::cbor::to_canonical_vec(&response).unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/secure-upgrade/app-attest/finish`.
///
/// Consumes the stored challenge, verifies App Attest and owner signature over
/// the same server transcript, records durable App Attest replay state, and
/// only then mints the strong owner `PersonCert`.
pub async fn secure_upgrade_app_attest_finish_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("owner_events.secure_upgrade_finish.clock")
    else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let authorized_owner_auth = match household_auth::authorize_secure_upgrade_finish_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        now,
    )
    .await
    {
        Ok(owner_auth) => owner_auth,
        Err(e) => return reject_secure_upgrade("pop_auth_failed", Some(e.to_string())),
    };
    let request: SecureUpgradeFinishRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_secure_upgrade("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_secure_upgrade("bad_version", None);
    }
    let owner_signature = match household_rs::P256Signature::from_bytes(&request.owner_signature) {
        Ok(signature) => signature,
        Err(e) => return reject_secure_upgrade("owner_signature_invalid", Some(e.to_string())),
    };
    let runtime = match secure_upgrade_runtime_or_reject(&state) {
        Ok(runtime) => runtime.clone(),
        Err(response) => return *response,
    };

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_secure_upgrade("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_secure_upgrade("owner_auth_unavailable", None);
    };
    if current_owner_auth.owner_person_cert.p_id != authorized_owner_auth.owner_person_cert.p_id {
        return reject_secure_upgrade("owner_auth_changed", None);
    }
    if current_owner_auth
        .owner_person_cert
        .has_strong_owner_provenance()
    {
        return reject_secure_upgrade("owner_already_strong", None);
    }
    let Some(hh_priv) = identity.hh_priv.as_deref() else {
        return reject_secure_upgrade("household_root_unavailable", None);
    };
    let verification = match verify_secure_upgrade_ceremony_for_challenge(
        runtime.challenge_store.as_ref(),
        runtime.replay_store.as_ref(),
        &request.challenge_id,
        request.canonical_transcript_cbor.as_ref(),
        SecureUpgradeProofVerificationInput {
            attestation_object_cbor: request.attestation_object_cbor.as_ref(),
            owner_public_key: &current_owner_auth.owner_person_cert.p_pub,
            owner_signature: &owner_signature,
            now_unix: now,
        },
    ) {
        Ok(verification) => verification,
        Err(e) => return reject_secure_upgrade("ceremony_verify_failed", Some(e.to_string())),
    };
    let owner_person_cert = match sign_owner_cert_with_secure_upgrade_verification(
        hh_priv,
        SignOwnerOptions {
            hh_id: identity.record.hh_id.clone(),
            p_pub: current_owner_auth.owner_person_cert.p_pub.clone(),
            display_name: current_owner_auth.owner_person_cert.display_name.clone(),
            issued_at: now,
        },
        &verification,
    ) {
        Ok(cert) => cert,
        Err(e) => return reject_secure_upgrade("owner_cert_mint_failed", Some(e.to_string())),
    };
    let next_auth =
        owner_auth_with_secure_upgrade_cert(current_owner_auth.as_ref(), owner_person_cert.clone());
    if let Err(e) = next_auth.verify(&identity.record, now) {
        return reject_secure_upgrade("owner_auth_verify_failed", Some(e.to_string()));
    }
    let owner_lifecycle_guard =
        match persist_owner_auth_under_lifecycle(&state, &identity, &next_auth).await {
            Ok(guard) => guard,
            Err(e) => return reject_secure_upgrade("owner_auth_save_failed", Some(e)),
        };
    drop(owner_lifecycle_guard);
    let response = SecureUpgradeFinishResponse {
        version: 1,
        owner_auth_tier: owner_person_cert
            .owner_auth_tier_text()
            .unwrap_or_default()
            .to_string(),
        owner_provenance: owner_person_cert
            .owner_provenance_text()
            .unwrap_or_default()
            .to_string(),
        owner_person_cert,
    };
    let bytes = household_rs::cbor::to_canonical_vec(&response).unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

fn owner_webauthn_user_uuid(owner_auth: &household_rs::HouseholdAuthState) -> Uuid {
    let mut input = b"soyeht-owner-webauthn-user-v1\0".to_vec();
    input.extend_from_slice(owner_auth.hh_id.to_string().as_bytes());
    input.push(0);
    input.extend_from_slice(owner_auth.owner_person_cert.p_id.0.as_bytes());
    let digest = blake3::hash(&input);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    // RFC 4122-compatible deterministic UUID shape: version 5, variant 1.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

const INITIAL_ENROLLMENT_MARKER_VERSION: u8 = 1;
const INITIAL_ENROLLMENT_MARKER_PURPOSE: &str = "owner-webauthn-initial-enrollment-anchor-pending";

fn owner_webauthn_initial_enrollment_marker_path(state_dir: &FsPath) -> PathBuf {
    household_rs::storage::household_dir(state_dir)
        .join("owner_webauthn_initial_enrollment_anchor_pending.cbor")
}

fn write_owner_webauthn_initial_enrollment_marker(
    state_dir: &FsPath,
    marker: &OwnerWebauthnInitialEnrollmentAnchorMarker,
) -> Result<(), String> {
    household_rs::storage::atomic_write_cbor(
        &owner_webauthn_initial_enrollment_marker_path(state_dir),
        marker,
    )
    .map_err(|e| e.to_string())
}

fn read_owner_webauthn_initial_enrollment_marker(
    state_dir: &FsPath,
) -> Result<Option<OwnerWebauthnInitialEnrollmentAnchorMarker>, String> {
    household_rs::storage::read_optional_cbor(&owner_webauthn_initial_enrollment_marker_path(
        state_dir,
    ))
    .map_err(|e| e.to_string())
}

fn clear_owner_webauthn_initial_enrollment_marker(state_dir: &FsPath) -> Result<(), String> {
    let path = owner_webauthn_initial_enrollment_marker_path(state_dir);
    match fs::remove_file(&path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                if let Ok(dir) = fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn initial_enrollment_marker_for(
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
    credential_id: ByteBuf,
    head: &OwnerWebauthnAuthorityHead,
    active_credential_count: u64,
) -> Result<OwnerWebauthnInitialEnrollmentAnchorMarker, String> {
    if head.sequence != 0 {
        return Err("initial enrollment marker requires genesis sequence".into());
    }
    if active_credential_count != 1 {
        return Err("initial enrollment marker requires one active credential".into());
    }
    Ok(OwnerWebauthnInitialEnrollmentAnchorMarker {
        version: INITIAL_ENROLLMENT_MARKER_VERSION,
        purpose: INITIAL_ENROLLMENT_MARKER_PURPOSE.to_string(),
        hh_id: identity.record.hh_id.clone(),
        owner_p_id: owner_auth.owner_person_cert.p_id.clone(),
        credential_id,
        authority_head_sequence: head.sequence,
        authority_head_hash: ByteBuf::from(head.head_hash.to_vec()),
        active_credential_count,
    })
}

fn marker_matches_initial_enrollment(
    marker: &OwnerWebauthnInitialEnrollmentAnchorMarker,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
    head: &OwnerWebauthnAuthorityHead,
) -> bool {
    if marker.version != INITIAL_ENROLLMENT_MARKER_VERSION
        || marker.purpose != INITIAL_ENROLLMENT_MARKER_PURPOSE
        || marker.hh_id != identity.record.hh_id
        || marker.owner_p_id != owner_auth.owner_person_cert.p_id
        || marker.authority_head_sequence != head.sequence
        || marker.authority_head_hash.as_ref() != head.head_hash.as_slice()
        || marker.authority_head_sequence != 0
        || marker.active_credential_count != 1
    {
        return false;
    }

    let Ok(credentials) = owner_auth.owner_webauthn_credentials(&identity.record) else {
        return false;
    };
    if credentials.active_count() != usize::try_from(marker.active_credential_count).unwrap_or(0) {
        return false;
    }
    let marker_credential_is_active = credentials
        .active_credentials()
        .iter()
        .any(|credential| credential.credential_id_bytes() == marker.credential_id.as_ref());
    if !marker_credential_is_active {
        return false;
    }

    let Some(first_entry) = owner_auth.owner_webauthn.entries().first() else {
        return false;
    };
    if first_entry.event.sequence != 0 {
        return false;
    }
    match &first_entry.event.action {
        household_rs::owner_webauthn_authority::OwnerWebauthnCredentialEventAction::Add {
            credential,
        } => credential.credential_id_bytes() == marker.credential_id.as_ref(),
        household_rs::owner_webauthn_authority::OwnerWebauthnCredentialEventAction::Revoke {
            ..
        } => false,
    }
}

fn marker_backed_initial_enrollment_committed(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
) -> Result<bool, String> {
    let Some(marker) = read_owner_webauthn_initial_enrollment_marker(&state.state_dir)? else {
        return Ok(false);
    };
    let Some(head) = verified_owner_webauthn_authority_head(
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
    )
    .map_err(|e| e.to_string())?
    else {
        return Ok(false);
    };
    Ok(marker_matches_initial_enrollment(
        &marker, identity, owner_auth, &head,
    ))
}

fn owner_webauthn_registration_status(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
) -> Result<bool, &'static str> {
    let Some(verifier) = state.owner_webauthn_anchor.as_ref() else {
        return Err("missing_anchor_verifier");
    };
    match classify_owner_webauthn_authority_anchor_read_only(
        verifier.keystore.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
    ) {
        Ok(OwnerWebauthnAnchorStatus::EmptyAuthorityNoAnchor) => Ok(false),
        Ok(
            OwnerWebauthnAnchorStatus::Verified { .. } | OwnerWebauthnAnchorStatus::Advanced { .. },
        ) => Ok(true),
        Ok(OwnerWebauthnAnchorStatus::Migrated { .. }) => Err("unexpected_anchor_migration"),
        Err(OwnerWebauthnAnchorError::MissingAnchor) => {
            if marker_backed_initial_enrollment_committed(state, identity, owner_auth)
                .map_err(|_| "marker_read_failed")?
            {
                Ok(true)
            } else {
                Err("missing_anchor")
            }
        }
        Err(_) => Err("credential_anchor_invalid"),
    }
}

fn reject_owner_webauthn_registration(reason: &'static str, error: Option<String>) -> Response {
    if let Some(error) = error {
        tracing::warn!(
            stage = "owner_events.owner_webauthn_registration.rejected",
            reason,
            error = %error,
        );
    } else {
        tracing::warn!(
            stage = "owner_events.owner_webauthn_registration.rejected",
            reason,
        );
    }
    unauthenticated_response()
}

fn reject_owner_webauthn_revoke_credential_start(
    reason: &'static str,
    error: Option<String>,
) -> Response {
    if let Some(error) = error {
        tracing::warn!(
            stage = "owner_events.owner_webauthn_revoke_credential_start.rejected",
            reason,
            error = %error,
        );
    } else {
        tracing::warn!(
            stage = "owner_events.owner_webauthn_revoke_credential_start.rejected",
            reason,
        );
    }
    unauthenticated_response()
}

fn reject_owner_webauthn_revoke_credential_finish(
    reason: &'static str,
    error: Option<String>,
) -> Response {
    if let Some(error) = error {
        tracing::warn!(
            stage = "owner_events.owner_webauthn_revoke_credential_finish.rejected",
            reason,
            error = %error,
        );
    } else {
        tracing::warn!(
            stage = "owner_events.owner_webauthn_revoke_credential_finish.rejected",
            reason,
        );
    }
    unauthenticated_response()
}

fn reject_owner_webauthn_add_credential_start(
    reason: &'static str,
    error: Option<String>,
) -> Response {
    if let Some(error) = error {
        tracing::warn!(
            stage = "owner_events.owner_webauthn_add_credential_start.rejected",
            reason,
            error = %error,
        );
    } else {
        tracing::warn!(
            stage = "owner_events.owner_webauthn_add_credential_start.rejected",
            reason,
        );
    }
    unauthenticated_response()
}

fn reject_owner_webauthn_add_credential_finish(
    reason: &'static str,
    error: Option<String>,
) -> Response {
    if let Some(error) = error {
        tracing::warn!(
            stage = "owner_events.owner_webauthn_add_credential_finish.rejected",
            reason,
            error = %error,
        );
    } else {
        tracing::warn!(
            stage = "owner_events.owner_webauthn_add_credential_finish.rejected",
            reason,
        );
    }
    unauthenticated_response()
}

fn reject_owner_webauthn_recovery(reason: &'static str, error: Option<String>) -> Response {
    if let Some(error) = error {
        tracing::warn!(
            stage = "owner_events.owner_webauthn_recovery.rejected",
            reason,
            error = %error,
        );
    } else {
        tracing::warn!(
            stage = "owner_events.owner_webauthn_recovery.rejected",
            reason,
        );
    }
    unauthenticated_response()
}

fn reject_secure_upgrade(reason: &'static str, error: Option<String>) -> Response {
    if let Some(error) = error {
        tracing::warn!(
            stage = "owner_events.secure_upgrade.rejected",
            reason,
            error = %error,
        );
    } else {
        tracing::warn!(stage = "owner_events.secure_upgrade.rejected", reason,);
    }
    unauthenticated_response()
}

fn secure_upgrade_runtime_or_reject(
    state: &OwnerEventsRouterState,
) -> Result<&SecureUpgradeRuntime, Box<Response>> {
    if !state
        .owner_approval_policy
        .secure_upgrade_strong_minting_enabled()
    {
        return Err(Box::new(reject_secure_upgrade("policy_disabled", None)));
    }
    state
        .secure_upgrade_runtime
        .as_ref()
        .ok_or_else(|| Box::new(reject_secure_upgrade("runtime_unavailable", None)))
}

fn secure_upgrade_challenge_id() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("su-{}", B64URL.encode(bytes))
}

fn secure_upgrade_owner_key_id(owner_auth: &household_rs::HouseholdAuthState) -> String {
    owner_auth.owner_person_cert.p_id.0.clone()
}

fn owner_auth_with_secure_upgrade_cert(
    current_owner_auth: &household_rs::HouseholdAuthState,
    owner_person_cert: PersonCert,
) -> household_rs::HouseholdAuthState {
    let mut next_auth = current_owner_auth.clone();
    next_auth.owner_person_cert = owner_person_cert;
    next_auth.created_at = next_auth.owner_person_cert.issued_at;
    next_auth.updated_at = next_auth.owner_person_cert.issued_at;
    next_auth
}

fn owner_webauthn_initial_enrollment_policy_snapshot(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
) -> OwnerWebauthnPolicySnapshot {
    let Some(verifier) = state.owner_webauthn_anchor.as_ref() else {
        return OwnerWebauthnPolicySnapshot::anchor_invalid();
    };
    let anchor_status = verify_or_update_owner_webauthn_authority_anchor(
        verifier.keystore.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    );
    match anchor_status {
        Ok(OwnerWebauthnAnchorStatus::EmptyAuthorityNoAnchor) => {
            OwnerWebauthnPolicySnapshot::never_enrolled()
        }
        Ok(
            OwnerWebauthnAnchorStatus::Verified { .. }
            | OwnerWebauthnAnchorStatus::Advanced { .. }
            | OwnerWebauthnAnchorStatus::Migrated { .. },
        ) => match owner_auth.owner_webauthn_credentials(&identity.record) {
            Ok(credentials) => {
                let active_count = credentials.active_count();
                if active_count == 0 {
                    OwnerWebauthnPolicySnapshot::recovery_required()
                } else {
                    OwnerWebauthnPolicySnapshot {
                        trust_state: OwnerWebauthnTrustState::Active {
                            count: active_count,
                        },
                        credentials: Some(credentials),
                    }
                }
            }
            Err(_) => OwnerWebauthnPolicySnapshot::anchor_invalid(),
        },
        Err(_) => OwnerWebauthnPolicySnapshot::anchor_invalid(),
    }
}

fn owner_webauthn_initial_enrollment_policy_snapshot_read_only(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
) -> OwnerWebauthnPolicySnapshot {
    let Some(verifier) = state.owner_webauthn_anchor.as_ref() else {
        return OwnerWebauthnPolicySnapshot::anchor_invalid();
    };
    let anchor_status = classify_owner_webauthn_authority_anchor_read_only(
        verifier.keystore.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
    );
    match anchor_status {
        Ok(OwnerWebauthnAnchorStatus::EmptyAuthorityNoAnchor) => {
            OwnerWebauthnPolicySnapshot::never_enrolled()
        }
        Ok(
            OwnerWebauthnAnchorStatus::Verified { .. }
            | OwnerWebauthnAnchorStatus::Advanced { .. }
            | OwnerWebauthnAnchorStatus::Migrated { .. },
        ) => match owner_auth.owner_webauthn_credentials(&identity.record) {
            Ok(credentials) => {
                let active_count = credentials.active_count();
                if active_count == 0 {
                    OwnerWebauthnPolicySnapshot::recovery_required()
                } else {
                    OwnerWebauthnPolicySnapshot {
                        trust_state: OwnerWebauthnTrustState::Active {
                            count: active_count,
                        },
                        credentials: Some(credentials),
                    }
                }
            }
            Err(_) => OwnerWebauthnPolicySnapshot::anchor_invalid(),
        },
        Err(_) => OwnerWebauthnPolicySnapshot::anchor_invalid(),
    }
}

fn require_owner_webauthn_never_enrolled_for_initial_enrollment(
    snapshot: &OwnerWebauthnPolicySnapshot,
) -> Result<(), &'static str> {
    match snapshot.trust_state {
        OwnerWebauthnTrustState::NeverEnrolled => Ok(()),
        OwnerWebauthnTrustState::Active { .. } => Err("credential_already_enrolled"),
        OwnerWebauthnTrustState::RecoveryRequired => Err("credential_recovery_required"),
        OwnerWebauthnTrustState::AnchorInvalid => Err("credential_anchor_invalid"),
    }
}

fn authorize_macos_local_caller(
    state: &OwnerEventsRouterState,
    peer: Option<&MacosLocalPeerConnectInfo>,
) -> Result<(), String> {
    let Some(peer) = peer.and_then(|connect_info| connect_info.peer.as_ref()) else {
        return Err("local_caller_peer_unavailable".to_string());
    };
    let Some(verifier) = state.macos_local_caller_auth.as_ref() else {
        return Err("local_caller_auth_unavailable".to_string());
    };
    verifier
        .authorize(&MacosLocalCallerAuthRequest { peer })
        .map_err(|e| e.to_string())
}

fn macos_local_peer_connect_info(
    peer: Option<&Extension<ConnectInfo<MacosLocalPeerConnectInfo>>>,
) -> Option<&MacosLocalPeerConnectInfo> {
    peer.map(|extension| &extension.0.0)
}

/// `POST /api/v1/household/owner-webauthn/registration/status`.
///
/// Owner-authenticated enrollment status for the iOS E1 flow. This endpoint is
/// intentionally narrow: it reports only whether the first owner passkey is
/// committed, and it never migrates or repairs the rollback anchor from the read
/// path. The marker fallback covers only the post-save/pre-anchor window in
/// `owner_webauthn_registration_finish_handler`.
pub async fn owner_webauthn_registration_status_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("owner_events.owner_webauthn_status.clock")
    else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let authorized_owner_auth =
        match household_auth::authorize_owner_webauthn_registration_status_request(
            &state.household,
            &headers,
            &method,
            &path_and_query,
            &body,
            now,
        )
        .await
        {
            Ok(owner_auth) => owner_auth,
            Err(e) => {
                return reject_owner_webauthn_registration("pop_auth_failed", Some(e.to_string()));
            }
        };

    let request: OwnerWebauthnRegistrationStatusRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_owner_webauthn_registration("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_owner_webauthn_registration("bad_version", None);
    }

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_registration("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_owner_webauthn_registration("owner_auth_unavailable", None);
    };
    if current_owner_auth.owner_person_cert.p_id != authorized_owner_auth.owner_person_cert.p_id {
        return reject_owner_webauthn_registration("owner_auth_changed", None);
    }
    let enrolled =
        match owner_webauthn_registration_status(&state, &identity, current_owner_auth.as_ref()) {
            Ok(enrolled) => enrolled,
            Err(reason) => return reject_owner_webauthn_registration(reason, None),
        };
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStatusResponse {
        version: 1,
        enrolled,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-webauthn/registration/local/status`.
///
/// macOS local-engine status over a UDS-only router. The local boundary is
/// caller-auth, not `PoP`. M1 production state has no verifier and therefore
/// rejects before decode; tests may inject a fake verifier to exercise wiring.
pub async fn owner_webauthn_registration_local_status_handler(
    State(state): State<OwnerEventsRouterState>,
    peer: Option<Extension<ConnectInfo<MacosLocalPeerConnectInfo>>>,
    body: Bytes,
) -> Response {
    if let Err(e) =
        authorize_macos_local_caller(&state, macos_local_peer_connect_info(peer.as_ref()))
    {
        return reject_owner_webauthn_registration("local_caller_auth_failed", Some(e));
    }

    let request: OwnerWebauthnRegistrationStatusRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_owner_webauthn_registration("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_owner_webauthn_registration("bad_version", None);
    }

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_registration("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_owner_webauthn_registration("owner_auth_unavailable", None);
    };
    let enrolled =
        match owner_webauthn_registration_status(&state, &identity, current_owner_auth.as_ref()) {
            Ok(enrolled) => enrolled,
            Err(reason) => return reject_owner_webauthn_registration(reason, None),
        };
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStatusResponse {
        version: 1,
        enrolled,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-webauthn/revoke/start`.
///
/// Starts an owner passkey step-up challenge for a later revoke finish. This
/// R2 slice is challenge-only: it classifies the authority read-only, binds the
/// challenge to the exact live revoke context, and does not mutate owner auth,
/// the rollback anchor, or any status marker. The bootstrap mutation lock is
/// used only to coordinate the read-only identity/auth snapshot with challenge
/// staging; the real no-brick mutation gate remains in the R3 finish slice.
pub async fn owner_webauthn_revoke_credential_start_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) =
        time_util::unix_now_secs_checked("owner_events.owner_webauthn_revoke_start.clock")
    else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let authorized_owner_auth =
        match household_auth::authorize_owner_webauthn_revoke_credential_start_request(
            &state.household,
            &headers,
            &method,
            &path_and_query,
            &body,
            now,
        )
        .await
        {
            Ok(owner_auth) => owner_auth,
            Err(e) => {
                return reject_owner_webauthn_revoke_credential_start(
                    "pop_auth_failed",
                    Some(e.to_string()),
                );
            }
        };

    let request: OwnerWebauthnRevokeCredentialStartRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_owner_webauthn_revoke_credential_start("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_owner_webauthn_revoke_credential_start("bad_version", None);
    }
    if request.target_credential_id.is_empty() {
        return reject_owner_webauthn_revoke_credential_start("target_credential_empty", None);
    }

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_revoke_credential_start("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_owner_webauthn_revoke_credential_start("owner_auth_unavailable", None);
    };
    if current_owner_auth.owner_person_cert.p_id != authorized_owner_auth.owner_person_cert.p_id {
        return reject_owner_webauthn_revoke_credential_start("owner_auth_changed", None);
    }
    let snapshot = match owner_webauthn_revoke_credential_start_snapshot(
        &state,
        &identity,
        current_owner_auth.as_ref(),
        request.target_credential_id.as_ref(),
    ) {
        Ok(snapshot) => snapshot,
        Err(reason) => return reject_owner_webauthn_revoke_credential_start(reason, None),
    };
    let Some(rp) = state.owner_webauthn_rp.as_ref() else {
        return reject_owner_webauthn_revoke_credential_start("rp_unavailable", None);
    };

    let mut rng = OsRng;
    let mut replay_nonce = [0_u8; 32];
    rng.fill_bytes(&mut replay_nonce);
    let mut rp = rp.lock().await;
    let expected_context =
        OwnerApprovalContextV2::revoke_credential(RevokeCredentialContextInput {
            hh_id: identity.record.hh_id.clone(),
            owner_p_id: current_owner_auth.owner_person_cert.p_id.clone(),
            target_credential_id: request.target_credential_id.to_vec(),
            authority_head_sequence: snapshot.authority_head.sequence,
            authority_head_hash: snapshot.authority_head.head_hash,
            pre_active_credential_count: snapshot.pre_active_credential_count,
            capabilities: owner_revoke_credential_v2_capabilities(),
            issued_at: now,
            expires_at: now.saturating_add(rp.config().challenge_ttl().as_secs()),
            replay_nonce,
        });
    if let Err(e) = expected_context.validate_shape() {
        return reject_owner_webauthn_revoke_credential_start(
            "trusted_context_build_failed",
            Some(e.to_string()),
        );
    }
    let (challenge_id, options) = match rp.start_owner_approval_assertion(
        &mut rng,
        now,
        snapshot.credentials.credentials(),
        &expected_context,
    ) {
        Ok(started) => started,
        Err(e) => {
            return reject_owner_webauthn_revoke_credential_start(
                "webauthn_start_failed",
                Some(e.to_string()),
            );
        }
    };
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerApprovalV2StartResponse {
        version: 1,
        challenge_id: challenge_id.as_str().to_string(),
        context: expected_context,
        options,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-webauthn/add-credential/start`.
///
/// Starts the two ceremonies required to add a backup owner passkey: a
/// registration ceremony for the new credential and an owner-approval assertion
/// from an existing active credential. This is challenge-only; it does not
/// finish either ceremony, append authority events, save owner auth, or advance
/// anchors.
pub async fn owner_webauthn_add_credential_start_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) =
        time_util::unix_now_secs_checked("owner_events.owner_webauthn_add_credential_start.clock")
    else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let authorized_owner_auth =
        match household_auth::authorize_owner_webauthn_add_credential_start_request(
            &state.household,
            &headers,
            &method,
            &path_and_query,
            &body,
            now,
        )
        .await
        {
            Ok(owner_auth) => owner_auth,
            Err(e) => {
                return reject_owner_webauthn_add_credential_start(
                    "pop_auth_failed",
                    Some(e.to_string()),
                );
            }
        };

    let request: OwnerWebauthnAddCredentialStartRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_owner_webauthn_add_credential_start("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_owner_webauthn_add_credential_start("bad_version", None);
    }

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_add_credential_start("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_owner_webauthn_add_credential_start("owner_auth_unavailable", None);
    };
    if current_owner_auth.owner_person_cert.p_id != authorized_owner_auth.owner_person_cert.p_id {
        return reject_owner_webauthn_add_credential_start("owner_auth_changed", None);
    }
    let plan = match owner_webauthn_add_credential_start_plan(
        &state,
        &identity,
        current_owner_auth.as_ref(),
    ) {
        Ok(plan) => plan,
        Err(reason) => return reject_owner_webauthn_add_credential_start(reason, None),
    };
    let Some(rp) = state.owner_webauthn_rp.as_ref() else {
        return reject_owner_webauthn_add_credential_start("rp_unavailable", None);
    };

    let mut rng = OsRng;
    let mut replay_nonce = [0_u8; 32];
    rng.fill_bytes(&mut replay_nonce);
    let mut rp = rp.lock().await;
    let issued_at = now;
    let expires_at = now.saturating_add(rp.config().challenge_ttl().as_secs());
    let capabilities = owner_add_credential_v2_capabilities();
    let registration_binding = match owner_webauthn_add_credential_registration_binding(
        &identity,
        current_owner_auth.as_ref(),
        &plan,
        capabilities.clone(),
        issued_at,
        expires_at,
        replay_nonce,
    ) {
        Ok(binding) => binding,
        Err(reason) => return reject_owner_webauthn_add_credential_start(reason, None),
    };
    let expected_context = OwnerApprovalContextV2::add_credential(AddCredentialContextInput {
        hh_id: identity.record.hh_id.clone(),
        owner_p_id: current_owner_auth.owner_person_cert.p_id.clone(),
        new_credential_binding_hash: registration_binding.binding_digest(),
        authority_head_sequence: plan.webauthn_head.sequence,
        authority_head_hash: plan.webauthn_head.head_hash,
        pre_active_credential_count: plan.pre_active_credential_count,
        capabilities,
        issued_at,
        expires_at,
        replay_nonce,
    });
    if let Err(e) = expected_context.validate_shape() {
        return reject_owner_webauthn_add_credential_start(
            "trusted_context_build_failed",
            Some(e.to_string()),
        );
    }
    let reconstructed_binding =
        match owner_webauthn_add_credential_registration_binding_from_context(&expected_context) {
            Ok(binding) => binding,
            Err(reason) => return reject_owner_webauthn_add_credential_start(reason, None),
        };
    if reconstructed_binding != registration_binding {
        return reject_owner_webauthn_add_credential_start(
            "add_credential_binding_reconstruction_mismatch",
            None,
        );
    }

    let user_id = owner_webauthn_user_uuid(current_owner_auth.as_ref());
    let owner_name = current_owner_auth.owner_person_cert.p_id.0.as_str();
    let owner_display_name = current_owner_auth.owner_person_cert.display_name.as_str();
    let (registration_challenge_id, registration_options) = match rp.start_registration_from(
        &mut rng,
        now,
        OwnerWebauthnRegistrationStart {
            owner_user_id: user_id,
            owner_name,
            owner_display_name,
            existing_credentials: plan.credentials.credentials(),
            binding: Some(registration_binding),
        },
    ) {
        Ok(started) => started,
        Err(e) => {
            return reject_owner_webauthn_add_credential_start(
                "registration_start_failed",
                Some(e.to_string()),
            );
        }
    };
    // If approval start fails after registration is staged, the registration
    // challenge is an orphan until TTL. It is not a grant: finish must present
    // both this registration binding and an approval assertion for this context.
    let (approval_challenge_id, approval_options) = match rp.start_owner_approval_assertion(
        &mut rng,
        now,
        plan.credentials.credentials(),
        &expected_context,
    ) {
        Ok(started) => started,
        Err(e) => {
            return reject_owner_webauthn_add_credential_start(
                "approval_start_failed",
                Some(e.to_string()),
            );
        }
    };
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerWebauthnAddCredentialStartResponse {
        version: 1,
        registration: OwnerWebauthnRegistrationStartResponse {
            version: 1,
            challenge_id: registration_challenge_id.as_str().to_string(),
            options: registration_options,
        },
        approval: OwnerApprovalV2StartResponse {
            version: 1,
            challenge_id: approval_challenge_id.as_str().to_string(),
            context: expected_context.clone(),
            options: approval_options,
        },
        context: expected_context,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-webauthn/revoke/finish`.
///
/// Commits an owner-passkey revoke authorized by a fresh v2 assertion. Unlike
/// R2 start, this is the local mutation point: the bootstrap mutation lock is
/// held from live revalidation through durable save, memory update, and anchor
/// advance.
pub async fn owner_webauthn_revoke_credential_finish_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) =
        time_util::unix_now_secs_checked("owner_events.owner_webauthn_revoke_finish.clock")
    else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let authorized_owner_auth =
        match household_auth::authorize_owner_webauthn_revoke_credential_finish_request(
            &state.household,
            &headers,
            &method,
            &path_and_query,
            &body,
            now,
        )
        .await
        {
            Ok(owner_auth) => owner_auth,
            Err(e) => {
                return reject_owner_webauthn_revoke_credential_finish(
                    "pop_auth_failed",
                    Some(e.to_string()),
                );
            }
        };

    let finish: OwnerApprovalV2Finish = match decode_canonical_cbor(&body) {
        Ok(finish) => finish,
        Err(e) => return reject_owner_webauthn_revoke_credential_finish("cbor_decode", Some(e)),
    };
    if finish.version != 1 {
        return reject_owner_webauthn_revoke_credential_finish("bad_version", None);
    }
    if finish.approval.context.op != OwnerOperation::RevokeCredential {
        return reject_owner_webauthn_revoke_credential_finish("bad_operation", None);
    }
    if let Err(e) = finish.approval.context.validate_at(now) {
        return reject_owner_webauthn_revoke_credential_finish(
            "approval_v2_context_expired",
            Some(e.to_string()),
        );
    }
    let challenge_id = match OwnerWebauthnChallengeId::parse(finish.challenge_id.clone()) {
        Ok(challenge_id) => challenge_id,
        Err(e) => {
            return reject_owner_webauthn_revoke_credential_finish(
                "bad_challenge_id",
                Some(e.to_string()),
            );
        }
    };
    let assertion = match finish.approval.to_public_key_credential() {
        Ok(assertion) => assertion,
        Err(e) => {
            return reject_owner_webauthn_revoke_credential_finish(
                "approval_v2_assertion_invalid",
                Some(e.to_string()),
            );
        }
    };

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_revoke_credential_finish("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_owner_webauthn_revoke_credential_finish("owner_auth_unavailable", None);
    };
    if current_owner_auth.owner_person_cert.p_id != authorized_owner_auth.owner_person_cert.p_id {
        return reject_owner_webauthn_revoke_credential_finish("owner_auth_changed", None);
    }
    let Some(hh_priv) = identity.hh_priv.as_deref() else {
        return reject_owner_webauthn_revoke_credential_finish("household_root_unavailable", None);
    };
    let Some(anchor) = state.owner_webauthn_anchor.clone() else {
        return reject_owner_webauthn_revoke_credential_finish("missing_anchor_verifier", None);
    };
    let Some(rp) = state.owner_webauthn_rp.as_ref() else {
        return reject_owner_webauthn_revoke_credential_finish("rp_unavailable", None);
    };
    let mut plan = match owner_webauthn_revoke_credential_finish_plan(
        &state,
        &identity,
        current_owner_auth.as_ref(),
        &finish.approval.context,
        finish.approval.credential_id.as_ref(),
    ) {
        Ok(plan) => plan,
        Err(reason) => return reject_owner_webauthn_revoke_credential_finish(reason, None),
    };
    if let Err(e) = finish
        .approval
        .require_expected_context(&plan.expected_context)
    {
        return reject_owner_webauthn_revoke_credential_finish(
            "approval_v2_context_mismatch",
            Some(e.to_string()),
        );
    }

    let mut rp = rp.lock().await;
    if let Err(e) =
        rp.require_owner_approval_challenge_context(now, &challenge_id, &finish.approval.context)
    {
        return reject_owner_webauthn_revoke_credential_finish(
            "owner_webauthn_challenge_context_mismatch",
            Some(e.to_string()),
        );
    }
    if let Err(e) = rp.finish_owner_approval_assertion(
        now,
        &challenge_id,
        &assertion,
        &mut plan.actor_credential,
        &finish.approval.context,
    ) {
        return reject_owner_webauthn_revoke_credential_finish(
            "owner_webauthn_finish_failed",
            Some(e.to_string()),
        );
    }
    drop(rp);

    let revoke = match household_rs::owner_webauthn_authority::OwnerWebauthnAuthority::sign_append(
        hh_priv,
        &identity.record,
        &current_owner_auth.owner_person_cert,
        &plan.previous_entry,
        finish.approval.credential_id.as_ref(),
        OwnerWebauthnCredentialEventAction::Revoke {
            credential_id: plan.target_credential_id.clone(),
        },
        now,
    ) {
        Ok(revoke) => revoke,
        Err(e) => {
            return reject_owner_webauthn_revoke_credential_finish(
                "authority_sign_failed",
                Some(e.to_string()),
            );
        }
    };
    let mut next_auth = current_owner_auth.as_ref().clone();
    next_auth.owner_webauthn.push_signed(revoke);
    next_auth.updated_at = now;
    if let Err(e) = next_auth.verify(&identity.record, now) {
        return reject_owner_webauthn_revoke_credential_finish(
            "authority_verify_failed",
            Some(e.to_string()),
        );
    }
    let active_credential_count = match next_auth.owner_webauthn_credentials(&identity.record) {
        Ok(credentials) => credentials.active_count() as u64,
        Err(e) => {
            return reject_owner_webauthn_revoke_credential_finish(
                "credential_reconstruct_failed",
                Some(e.to_string()),
            );
        }
    };
    if active_credential_count + 1 != plan.pre_active_credential_count
        || active_credential_count == 0
    {
        return reject_owner_webauthn_revoke_credential_finish(
            "credential_count_after_revoke_invalid",
            None,
        );
    }

    let owner_lifecycle_guard =
        match persist_owner_auth_under_lifecycle(&state, &identity, &next_auth).await {
            Ok(guard) => guard,
            Err(e) => {
                return reject_owner_webauthn_revoke_credential_finish(
                    "authority_save_failed",
                    Some(e),
                );
            }
        };
    if let Err(e) = verify_or_update_owner_webauthn_authority_anchor(
        anchor.keystore.as_ref(),
        &next_auth.owner_webauthn,
        &identity.record,
        &next_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    ) {
        return reject_owner_webauthn_revoke_credential_finish(
            "anchor_update_failed",
            Some(e.to_string()),
        );
    }
    drop(owner_lifecycle_guard);
    let bytes =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRevokeCredentialFinishResponse {
            version: 1,
            active_credential_count,
        })
        .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-webauthn/add-credential/finish`.
///
/// Commits a fresh owner passkey only after the new registration ceremony and a
/// live owner-passkey approval assertion both prove the same `AddCredential`
/// context. This is the one-anchor mutation point for backup credential add:
/// save the appended `WebAuthn` authority, update memory, then advance the
/// `WebAuthn` anchor.
pub async fn owner_webauthn_add_credential_finish_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) =
        time_util::unix_now_secs_checked("owner_events.owner_webauthn_add_credential_finish.clock")
    else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let authorized_owner_auth =
        match household_auth::authorize_owner_webauthn_add_credential_finish_request(
            &state.household,
            &headers,
            &method,
            &path_and_query,
            &body,
            now,
        )
        .await
        {
            Ok(owner_auth) => owner_auth,
            Err(e) => {
                return reject_owner_webauthn_add_credential_finish(
                    "pop_auth_failed",
                    Some(e.to_string()),
                );
            }
        };

    let request: OwnerWebauthnAddCredentialFinishRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_owner_webauthn_add_credential_finish("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_owner_webauthn_add_credential_finish("bad_version", None);
    }
    if request.registration.version != 1 {
        return reject_owner_webauthn_add_credential_finish("bad_registration_version", None);
    }
    if request.approval.version != 1 {
        return reject_owner_webauthn_add_credential_finish("bad_approval_version", None);
    }
    if request.context.op != OwnerOperation::AddCredential {
        return reject_owner_webauthn_add_credential_finish("bad_operation", None);
    }
    if request.approval.approval.context != request.context {
        return reject_owner_webauthn_add_credential_finish("approval_context_mismatch", None);
    }
    if let Err(e) = request.context.validate_at(now) {
        return reject_owner_webauthn_add_credential_finish(
            "add_credential_context_expired",
            Some(e.to_string()),
        );
    }
    let registration_challenge_id =
        match OwnerWebauthnChallengeId::parse(request.registration.challenge_id.clone()) {
            Ok(challenge_id) => challenge_id,
            Err(e) => {
                return reject_owner_webauthn_add_credential_finish(
                    "bad_registration_challenge_id",
                    Some(e.to_string()),
                );
            }
        };
    let approval_challenge_id =
        match OwnerWebauthnChallengeId::parse(request.approval.challenge_id.clone()) {
            Ok(challenge_id) => challenge_id,
            Err(e) => {
                return reject_owner_webauthn_add_credential_finish(
                    "bad_approval_challenge_id",
                    Some(e.to_string()),
                );
            }
        };
    let assertion = match request.approval.approval.to_public_key_credential() {
        Ok(assertion) => assertion,
        Err(e) => {
            return reject_owner_webauthn_add_credential_finish(
                "approval_v2_assertion_invalid",
                Some(e.to_string()),
            );
        }
    };

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_add_credential_finish("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_owner_webauthn_add_credential_finish("owner_auth_unavailable", None);
    };
    if current_owner_auth.owner_person_cert.p_id != authorized_owner_auth.owner_person_cert.p_id {
        return reject_owner_webauthn_add_credential_finish("owner_auth_changed", None);
    }
    let Some(hh_priv) = identity.hh_priv.as_deref() else {
        return reject_owner_webauthn_add_credential_finish("household_root_unavailable", None);
    };
    let Some(anchor) = state.owner_webauthn_anchor.clone() else {
        return reject_owner_webauthn_add_credential_finish("missing_anchor_verifier", None);
    };
    let Some(rp) = state.owner_webauthn_rp.as_ref() else {
        return reject_owner_webauthn_add_credential_finish("rp_unavailable", None);
    };
    let mut plan = match owner_webauthn_add_credential_finish_plan(
        &state,
        &identity,
        current_owner_auth.as_ref(),
        &request.context,
        request.approval.approval.credential_id.as_ref(),
    ) {
        Ok(plan) => plan,
        Err(reason) => return reject_owner_webauthn_add_credential_finish(reason, None),
    };
    if plan.expected_context != request.context {
        return reject_owner_webauthn_add_credential_finish(
            "add_credential_expected_context_mismatch",
            None,
        );
    }
    if let Err(e) = request
        .approval
        .approval
        .require_expected_context(&plan.expected_context)
    {
        return reject_owner_webauthn_add_credential_finish(
            "approval_v2_context_mismatch",
            Some(e.to_string()),
        );
    }

    let mut rp = rp.lock().await;
    if let Err(e) = rp.require_registration_challenge_binding(
        now,
        &registration_challenge_id,
        &plan.registration_binding,
    ) {
        return reject_owner_webauthn_add_credential_finish(
            "add_credential_registration_context_mismatch",
            Some(e.to_string()),
        );
    }
    if let Err(e) =
        rp.require_owner_approval_challenge_context(now, &approval_challenge_id, &request.context)
    {
        return reject_owner_webauthn_add_credential_finish(
            "add_credential_approval_context_mismatch",
            Some(e.to_string()),
        );
    }
    let credential = match rp.finish_registration_with_binding(
        now,
        &registration_challenge_id,
        &request.registration.credential,
        &plan.registration_binding,
    ) {
        Ok(credential) => credential,
        Err(e) => {
            return reject_owner_webauthn_add_credential_finish(
                "add_credential_registration_finish_failed",
                Some(e.to_string()),
            );
        }
    };
    if let Err(e) = rp.finish_owner_approval_assertion(
        now,
        &approval_challenge_id,
        &assertion,
        &mut plan.actor_credential,
        &request.context,
    ) {
        return reject_owner_webauthn_add_credential_finish(
            "add_credential_approval_finish_failed",
            Some(e.to_string()),
        );
    }
    drop(rp);
    let credential_id = ByteBuf::from(credential.credential_id_bytes().to_vec());

    let add = match OwnerWebauthnAuthority::sign_append(
        hh_priv,
        &identity.record,
        &current_owner_auth.owner_person_cert,
        &plan.previous_entry,
        request.approval.approval.credential_id.as_ref(),
        OwnerWebauthnCredentialEventAction::Add {
            credential: Box::new(credential),
        },
        now,
    ) {
        Ok(add) => add,
        Err(e) => {
            return reject_owner_webauthn_add_credential_finish(
                "add_credential_authority_sign_failed",
                Some(e.to_string()),
            );
        }
    };

    let mut next_auth = current_owner_auth.as_ref().clone();
    next_auth.owner_webauthn.push_signed(add);
    next_auth.updated_at = now;
    if let Err(e) = next_auth.verify(&identity.record, now) {
        return reject_owner_webauthn_add_credential_finish(
            "add_credential_authority_verify_failed",
            Some(e.to_string()),
        );
    }
    let active_credential_count = match next_auth.owner_webauthn_credentials(&identity.record) {
        Ok(credentials) => match u64::try_from(credentials.active_count()) {
            Ok(count) => count,
            Err(_) => {
                return reject_owner_webauthn_add_credential_finish(
                    "credential_count_overflow",
                    None,
                );
            }
        },
        Err(e) => {
            return reject_owner_webauthn_add_credential_finish(
                "credential_reconstruct_failed",
                Some(e.to_string()),
            );
        }
    };
    if active_credential_count != plan.pre_active_credential_count.saturating_add(1) {
        return reject_owner_webauthn_add_credential_finish(
            "add_credential_active_count_after_add_invalid",
            None,
        );
    }

    let owner_lifecycle_guard =
        match persist_owner_auth_under_lifecycle(&state, &identity, &next_auth).await {
            Ok(guard) => guard,
            Err(e) => {
                return reject_owner_webauthn_add_credential_finish(
                    "add_credential_authority_save_failed",
                    Some(e),
                );
            }
        };
    if let Err(e) = verify_or_update_owner_webauthn_authority_anchor(
        anchor.keystore.as_ref(),
        &next_auth.owner_webauthn,
        &identity.record,
        &next_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    ) {
        return reject_owner_webauthn_add_credential_finish(
            "add_credential_anchor_update_failed",
            Some(e.to_string()),
        );
    }
    drop(owner_lifecycle_guard);

    let bytes = household_rs::cbor::to_canonical_vec(&OwnerWebauthnAddCredentialFinishResponse {
        version: 1,
        credential_id,
        active_credential_count,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-webauthn/recovery/status`.
///
/// Owner-authenticated readiness probe. This endpoint is read-only and only
/// reports whether a recovery verifier is already anchor-backed; it never
/// satisfies `WebAuthn` active-credential policy.
pub async fn owner_webauthn_recovery_status_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) =
        time_util::unix_now_secs_checked("owner_events.owner_webauthn_recovery_status.clock")
    else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let authorized_owner_auth =
        match household_auth::authorize_owner_webauthn_recovery_status_request(
            &state.household,
            &headers,
            &method,
            &path_and_query,
            &body,
            now,
        )
        .await
        {
            Ok(owner_auth) => owner_auth,
            Err(e) => {
                return reject_owner_webauthn_recovery("pop_auth_failed", Some(e.to_string()));
            }
        };

    let request: OwnerWebauthnRecoveryStatusRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_owner_webauthn_recovery("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_owner_webauthn_recovery("bad_version", None);
    }

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_recovery("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_owner_webauthn_recovery("owner_auth_unavailable", None);
    };
    if current_owner_auth.owner_person_cert.p_id != authorized_owner_auth.owner_person_cert.p_id {
        return reject_owner_webauthn_recovery("owner_auth_changed", None);
    }
    let ready = match owner_webauthn_recovery_ready_status(
        &state,
        &identity,
        current_owner_auth.as_ref(),
    ) {
        Ok(ready) => ready,
        Err(reason) => return reject_owner_webauthn_recovery(reason, None),
    };
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerWebauthnRecoveryStatusResponse {
        version: 1,
        ready,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-webauthn/recovery/start`.
///
/// Starts a `WebAuthn` step-up ceremony for recovery-code provision/rotation.
/// This is read-only: it stages only the `WebAuthn` challenge state.
pub async fn owner_webauthn_recovery_start_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) =
        time_util::unix_now_secs_checked("owner_events.owner_webauthn_recovery_start.clock")
    else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let authorized_owner_auth =
        match household_auth::authorize_owner_webauthn_recovery_start_request(
            &state.household,
            &headers,
            &method,
            &path_and_query,
            &body,
            now,
        )
        .await
        {
            Ok(owner_auth) => owner_auth,
            Err(e) => {
                return reject_owner_webauthn_recovery("pop_auth_failed", Some(e.to_string()));
            }
        };

    let request: OwnerWebauthnRecoveryStartRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_owner_webauthn_recovery("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_owner_webauthn_recovery("bad_version", None);
    }

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_recovery("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_owner_webauthn_recovery("owner_auth_unavailable", None);
    };
    if current_owner_auth.owner_person_cert.p_id != authorized_owner_auth.owner_person_cert.p_id {
        return reject_owner_webauthn_recovery("owner_auth_changed", None);
    }
    let snapshot = match owner_webauthn_recovery_start_snapshot(
        &state,
        &identity,
        current_owner_auth.as_ref(),
    ) {
        Ok(snapshot) => snapshot,
        Err(reason) => return reject_owner_webauthn_recovery(reason, None),
    };
    let Some(rp) = state.owner_webauthn_rp.as_ref() else {
        return reject_owner_webauthn_recovery("rp_unavailable", None);
    };

    let mut rng = OsRng;
    let mut replay_nonce = [0_u8; 32];
    rng.fill_bytes(&mut replay_nonce);
    let mut rp = rp.lock().await;
    let expected_context =
        OwnerApprovalContextV2::provision_recovery_code(ProvisionRecoveryCodeContextInput {
            hh_id: identity.record.hh_id.clone(),
            owner_p_id: current_owner_auth.owner_person_cert.p_id.clone(),
            authority_head_sequence: snapshot.webauthn_head.sequence,
            authority_head_hash: snapshot.webauthn_head.head_hash,
            pre_active_credential_count: snapshot.pre_active_credential_count,
            recovery_head: snapshot.recovery_head,
            capabilities: owner_recovery_code_v2_capabilities(),
            issued_at: now,
            expires_at: now.saturating_add(rp.config().challenge_ttl().as_secs()),
            replay_nonce,
        });
    if let Err(e) = expected_context.validate_shape() {
        return reject_owner_webauthn_recovery("trusted_context_build_failed", Some(e.to_string()));
    }
    let (challenge_id, options) = match rp.start_owner_approval_assertion(
        &mut rng,
        now,
        snapshot.credentials.credentials(),
        &expected_context,
    ) {
        Ok(started) => started,
        Err(e) => {
            return reject_owner_webauthn_recovery("webauthn_start_failed", Some(e.to_string()));
        }
    };
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerApprovalV2StartResponse {
        version: 1,
        challenge_id: challenge_id.as_str().to_string(),
        context: expected_context,
        options,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-webauthn/recovery/consume/start`.
///
/// Starts a recovery-code add-fresh-credential registration ceremony. This
/// slice is challenge-only: it proves owner `PoP`, records the durable
/// recovery-specific rate-limit attempt, checks the recovery code, binds the
/// registration challenge to the exact `RecoverCredential` context, and does
/// not mutate owner auth or either rollback anchor.
pub async fn owner_webauthn_recovery_consume_start_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked(
        "owner_events.owner_webauthn_recovery_consume_start.clock",
    ) else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let authorized_owner_auth =
        match household_auth::authorize_owner_webauthn_recovery_consume_start_request(
            &state.household,
            &headers,
            &method,
            &path_and_query,
            &body,
            now,
        )
        .await
        {
            Ok(owner_auth) => owner_auth,
            Err(e) => {
                return reject_owner_webauthn_recovery("pop_auth_failed", Some(e.to_string()));
            }
        };

    let request: OwnerWebauthnRecoveryConsumeStartRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_owner_webauthn_recovery("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_owner_webauthn_recovery("bad_version", None);
    }
    let recovery_code = Zeroizing::new(request.recovery_code);

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_recovery("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_owner_webauthn_recovery("owner_auth_unavailable", None);
    };
    if current_owner_auth.owner_person_cert.p_id != authorized_owner_auth.owner_person_cert.p_id {
        return reject_owner_webauthn_recovery("owner_auth_changed", None);
    }
    let plan = match owner_webauthn_recovery_consume_start_plan(
        &state,
        &identity,
        current_owner_auth.as_ref(),
        recovery_code.as_bytes(),
    ) {
        Ok(plan) => plan,
        Err(reason) => return reject_owner_webauthn_recovery(reason, None),
    };
    let Some(rp) = state.owner_webauthn_rp.as_ref() else {
        return reject_owner_webauthn_recovery("rp_unavailable", None);
    };

    let mut rng = OsRng;
    let mut replay_nonce = [0_u8; 32];
    rng.fill_bytes(&mut replay_nonce);
    let mut rp = rp.lock().await;
    let expires_at = now.saturating_add(rp.config().challenge_ttl().as_secs());
    let capabilities = owner_recovery_consume_v2_capabilities();
    let registration_binding = match owner_webauthn_recovery_consume_registration_binding(
        &identity,
        current_owner_auth.as_ref(),
        &plan,
        capabilities.clone(),
        now,
        expires_at,
        replay_nonce,
    ) {
        Ok(binding) => binding,
        Err(reason) => return reject_owner_webauthn_recovery(reason, None),
    };
    let expected_context =
        OwnerApprovalContextV2::recover_credential(RecoverCredentialContextInput {
            hh_id: identity.record.hh_id.clone(),
            owner_p_id: current_owner_auth.owner_person_cert.p_id.clone(),
            new_credential_binding_hash: registration_binding.binding_digest(),
            authority_head_sequence: plan.webauthn_head.sequence,
            authority_head_hash: plan.webauthn_head.head_hash,
            pre_active_credential_count: plan.pre_active_credential_count,
            recovery_head: RecoveryAuthorityHeadInput {
                sequence: plan.recovery_head.sequence,
                head_hash: plan.recovery_head.head_hash,
            },
            capabilities,
            issued_at: now,
            expires_at,
            replay_nonce,
        });
    if let Err(e) = expected_context.validate_shape() {
        return reject_owner_webauthn_recovery("trusted_context_build_failed", Some(e.to_string()));
    }
    let user_id = owner_webauthn_user_uuid(current_owner_auth.as_ref());
    let owner_name = current_owner_auth.owner_person_cert.p_id.0.as_str();
    let owner_display_name = current_owner_auth.owner_person_cert.display_name.as_str();
    let (challenge_id, options) = match rp.start_registration_from(
        &mut rng,
        now,
        OwnerWebauthnRegistrationStart {
            owner_user_id: user_id,
            owner_name,
            owner_display_name,
            existing_credentials: plan.credentials.credentials(),
            binding: Some(registration_binding),
        },
    ) {
        Ok(result) => result,
        Err(e) => {
            return reject_owner_webauthn_recovery(
                "recovery_consume_registration_start_failed",
                Some(e.to_string()),
            );
        }
    };
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerWebauthnRecoveryConsumeStartResponse {
        version: 1,
        challenge_id: challenge_id.as_str().to_string(),
        context: expected_context,
        options,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-webauthn/recovery/consume/finish`.
///
/// Commits the fresh passkey that was challenge-bound by consume/start and
/// records a one-shot recovery consume. The mutation is ordered as `WebAuthn`
/// Add before recovery Consume: both events are saved before anchors move, then
/// the `WebAuthn` anchor advances before the recovery anchor. Retries first try
/// to repair an already-saved Add+Consume pair without requiring the
/// registration challenge to still be live.
pub async fn owner_webauthn_recovery_consume_finish_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked(
        "owner_events.owner_webauthn_recovery_consume_finish.clock",
    ) else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let authorized_owner_auth =
        match household_auth::authorize_owner_webauthn_recovery_consume_finish_request(
            &state.household,
            &headers,
            &method,
            &path_and_query,
            &body,
            now,
        )
        .await
        {
            Ok(owner_auth) => owner_auth,
            Err(e) => {
                return reject_owner_webauthn_recovery("pop_auth_failed", Some(e.to_string()));
            }
        };

    let request: OwnerWebauthnRecoveryConsumeFinishRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_owner_webauthn_recovery("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_owner_webauthn_recovery("bad_version", None);
    }
    if request.context.op != OwnerOperation::RecoverCredential {
        return reject_owner_webauthn_recovery("bad_operation", None);
    }
    if let Err(e) = request.context.validate_shape() {
        return reject_owner_webauthn_recovery(
            "recovery_consume_context_invalid",
            Some(e.to_string()),
        );
    }
    let challenge_id = match OwnerWebauthnChallengeId::parse(request.challenge_id.clone()) {
        Ok(challenge_id) => challenge_id,
        Err(e) => {
            return reject_owner_webauthn_recovery("bad_challenge_id", Some(e.to_string()));
        }
    };
    let recovery_code = Zeroizing::new(request.recovery_code);

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_recovery("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_owner_webauthn_recovery("owner_auth_unavailable", None);
    };
    if current_owner_auth.owner_person_cert.p_id != authorized_owner_auth.owner_person_cert.p_id {
        return reject_owner_webauthn_recovery("owner_auth_changed", None);
    }
    let Some(hh_priv) = identity.hh_priv.as_deref() else {
        return reject_owner_webauthn_recovery("household_root_unavailable", None);
    };
    let Some(webauthn_anchor) = state.owner_webauthn_anchor.clone() else {
        return reject_owner_webauthn_recovery("missing_anchor_verifier", None);
    };
    let Some(recovery_anchor) = state.owner_webauthn_recovery_anchor.clone() else {
        return reject_owner_webauthn_recovery("missing_recovery_anchor_verifier", None);
    };
    let Some(rp) = state.owner_webauthn_rp.as_ref() else {
        return reject_owner_webauthn_recovery("rp_unavailable", None);
    };

    match repair_recovery_consume_finish_if_committed(
        webauthn_anchor.keystore.as_ref(),
        recovery_anchor.keystore.as_ref(),
        &identity,
        current_owner_auth.as_ref(),
        &request.context,
    ) {
        Ok(Some(response)) => {
            let bytes = household_rs::cbor::to_canonical_vec(&response).unwrap_or_default();
            return cbor_response(StatusCode::OK, bytes);
        }
        Ok(None) => {}
        Err(reason) => return reject_owner_webauthn_recovery(reason, None),
    }

    if let Err(e) = request.context.validate_at(now) {
        return reject_owner_webauthn_recovery(
            "recovery_consume_context_expired",
            Some(e.to_string()),
        );
    }
    let plan = match owner_webauthn_recovery_consume_finish_plan(
        &state,
        &identity,
        current_owner_auth.as_ref(),
        &request.context,
        recovery_code.as_bytes(),
    ) {
        Ok(plan) => plan,
        Err(reason) => return reject_owner_webauthn_recovery(reason, None),
    };
    if plan.expected_context != request.context {
        return reject_owner_webauthn_recovery("recovery_consume_expected_context_mismatch", None);
    }

    let mut rp = rp.lock().await;
    let credential = match rp.finish_registration_with_binding(
        now,
        &challenge_id,
        &request.credential,
        &plan.registration_binding,
    ) {
        Ok(credential) => credential,
        Err(e) => {
            return reject_owner_webauthn_recovery(
                "recovery_consume_registration_finish_failed",
                Some(e.to_string()),
            );
        }
    };
    drop(rp);
    let credential_id = ByteBuf::from(credential.credential_id_bytes().to_vec());

    let recovery_add = match OwnerWebauthnAuthority::sign_recovery_add(
        hh_priv,
        &identity.record,
        &current_owner_auth.owner_person_cert,
        OwnerWebauthnRecoveryAddInput {
            previous_entry: &plan.previous_webauthn_entry,
            recovery_head_sequence: plan.recovery_head.sequence,
            recovery_head_hash: plan.recovery_head.head_hash,
            credential,
            issued_at: now,
        },
    ) {
        Ok(event) => event,
        Err(e) => {
            return reject_owner_webauthn_recovery(
                "recovery_consume_webauthn_sign_failed",
                Some(e.to_string()),
            );
        }
    };
    let consume = match OwnerWebauthnRecoveryAuthority::sign_consume(
        hh_priv,
        &identity.record,
        &current_owner_auth.owner_person_cert,
        &plan.previous_recovery_entry,
        now,
    ) {
        Ok(event) => event,
        Err(e) => {
            return reject_owner_webauthn_recovery(
                "recovery_consume_recovery_sign_failed",
                Some(e.to_string()),
            );
        }
    };

    let mut next_auth = current_owner_auth.as_ref().clone();
    next_auth.owner_webauthn.push_signed(recovery_add);
    next_auth.owner_webauthn_recovery.push_signed(consume);
    next_auth.updated_at = now;
    if let Err(e) = next_auth.verify(&identity.record, now) {
        return reject_owner_webauthn_recovery(
            "recovery_consume_authority_verify_failed",
            Some(e.to_string()),
        );
    }
    let active_credential_count = match next_auth.owner_webauthn_credentials(&identity.record) {
        Ok(credentials) => match u64::try_from(credentials.active_count()) {
            Ok(count) => count,
            Err(_) => {
                return reject_owner_webauthn_recovery("credential_count_overflow", None);
            }
        },
        Err(e) => {
            return reject_owner_webauthn_recovery(
                "credential_reconstruct_failed",
                Some(e.to_string()),
            );
        }
    };
    if active_credential_count != plan.pre_active_credential_count.saturating_add(1) {
        return reject_owner_webauthn_recovery(
            "recovery_consume_active_count_after_add_invalid",
            None,
        );
    }

    let owner_lifecycle_guard =
        match persist_owner_auth_under_lifecycle(&state, &identity, &next_auth).await {
            Ok(guard) => guard,
            Err(e) => {
                return reject_owner_webauthn_recovery(
                    "recovery_consume_authority_save_failed",
                    Some(e),
                );
            }
        };
    if let Err(e) = verify_or_update_owner_webauthn_authority_anchor(
        webauthn_anchor.keystore.as_ref(),
        &next_auth.owner_webauthn,
        &identity.record,
        &next_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    ) {
        return reject_owner_webauthn_recovery(
            "recovery_consume_webauthn_anchor_update_failed",
            Some(e.to_string()),
        );
    }
    if let Err(e) = advance_owner_webauthn_recovery_anchor_after_commit(
        recovery_anchor.keystore.as_ref(),
        &next_auth.owner_webauthn_recovery,
        &identity.record,
        &next_auth.owner_person_cert,
    ) {
        return reject_owner_webauthn_recovery(
            "recovery_consume_recovery_anchor_update_failed",
            Some(e.to_string()),
        );
    }
    drop(owner_lifecycle_guard);

    let response = match recovery_consume_finish_response(&next_auth, &identity, credential_id) {
        Ok(response) => response,
        Err(reason) => return reject_owner_webauthn_recovery(reason, None),
    };
    let bytes = household_rs::cbor::to_canonical_vec(&response).unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-webauthn/recovery/finish`.
///
/// Commits a recovery-code verifier after a fresh owner `WebAuthn` step-up. The
/// plaintext recovery code is returned once and never stored in the authority.
pub async fn owner_webauthn_recovery_finish_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) =
        time_util::unix_now_secs_checked("owner_events.owner_webauthn_recovery_finish.clock")
    else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let authorized_owner_auth =
        match household_auth::authorize_owner_webauthn_recovery_finish_request(
            &state.household,
            &headers,
            &method,
            &path_and_query,
            &body,
            now,
        )
        .await
        {
            Ok(owner_auth) => owner_auth,
            Err(e) => {
                return reject_owner_webauthn_recovery("pop_auth_failed", Some(e.to_string()));
            }
        };

    let finish: OwnerApprovalV2Finish = match decode_canonical_cbor(&body) {
        Ok(finish) => finish,
        Err(e) => return reject_owner_webauthn_recovery("cbor_decode", Some(e)),
    };
    if finish.version != 1 {
        return reject_owner_webauthn_recovery("bad_version", None);
    }
    if finish.approval.context.op != OwnerOperation::ProvisionRecoveryCode {
        return reject_owner_webauthn_recovery("bad_operation", None);
    }
    if let Err(e) = finish.approval.context.validate_at(now) {
        return reject_owner_webauthn_recovery("approval_v2_context_expired", Some(e.to_string()));
    }
    let challenge_id = match OwnerWebauthnChallengeId::parse(finish.challenge_id.clone()) {
        Ok(challenge_id) => challenge_id,
        Err(e) => return reject_owner_webauthn_recovery("bad_challenge_id", Some(e.to_string())),
    };
    let assertion = match finish.approval.to_public_key_credential() {
        Ok(assertion) => assertion,
        Err(e) => {
            return reject_owner_webauthn_recovery(
                "approval_v2_assertion_invalid",
                Some(e.to_string()),
            );
        }
    };

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_recovery("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_owner_webauthn_recovery("owner_auth_unavailable", None);
    };
    if current_owner_auth.owner_person_cert.p_id != authorized_owner_auth.owner_person_cert.p_id {
        return reject_owner_webauthn_recovery("owner_auth_changed", None);
    }
    let Some(hh_priv) = identity.hh_priv.as_deref() else {
        return reject_owner_webauthn_recovery("household_root_unavailable", None);
    };
    let Some(anchor) = state.owner_webauthn_recovery_anchor.clone() else {
        return reject_owner_webauthn_recovery("missing_recovery_anchor_verifier", None);
    };
    let Some(rp) = state.owner_webauthn_rp.as_ref() else {
        return reject_owner_webauthn_recovery("rp_unavailable", None);
    };
    let mut plan = match owner_webauthn_recovery_finish_plan(
        &state,
        &identity,
        current_owner_auth.as_ref(),
        &finish.approval.context,
        finish.approval.credential_id.as_ref(),
    ) {
        Ok(plan) => plan,
        Err(reason) => return reject_owner_webauthn_recovery(reason, None),
    };
    if let Err(e) = finish
        .approval
        .require_expected_context(&plan.expected_context)
    {
        return reject_owner_webauthn_recovery("approval_v2_context_mismatch", Some(e.to_string()));
    }

    let mut rp = rp.lock().await;
    if let Err(e) =
        rp.require_owner_approval_challenge_context(now, &challenge_id, &finish.approval.context)
    {
        return reject_owner_webauthn_recovery(
            "owner_webauthn_challenge_context_mismatch",
            Some(e.to_string()),
        );
    }
    if let Err(e) = rp.finish_owner_approval_assertion(
        now,
        &challenge_id,
        &assertion,
        &mut plan.actor_credential,
        &finish.approval.context,
    ) {
        return reject_owner_webauthn_recovery("owner_webauthn_finish_failed", Some(e.to_string()));
    }
    drop(rp);

    let mut rng = OsRng;
    let mut code_bytes = Zeroizing::new([0_u8; 32]);
    rng.fill_bytes(&mut code_bytes[..]);
    let recovery_code = Zeroizing::new(B64URL.encode(&code_bytes[..]));
    let mut salt = [0_u8; 32];
    rng.fill_bytes(&mut salt);
    let verifier = RecoveryCodeVerifier::from_code_bytes(salt, recovery_code.as_bytes());
    let recovery_event = match OwnerWebauthnRecoveryAuthority::sign_next(
        hh_priv,
        &identity.record,
        &current_owner_auth.owner_person_cert,
        plan.previous_recovery_entry.as_ref(),
        finish.approval.credential_id.as_ref(),
        verifier,
        now,
    ) {
        Ok(event) => event,
        Err(e) => {
            return reject_owner_webauthn_recovery("recovery_sign_failed", Some(e.to_string()));
        }
    };
    let mut next_auth = current_owner_auth.as_ref().clone();
    if let Err(e) = next_auth
        .owner_webauthn_recovery
        .replace_after_authoritative_prefix(plan.authoritative_sequence, recovery_event)
    {
        return reject_owner_webauthn_recovery("recovery_replace_failed", Some(e.to_string()));
    }
    next_auth.updated_at = now;
    if let Err(e) = next_auth.verify(&identity.record, now) {
        return reject_owner_webauthn_recovery("recovery_verify_failed", Some(e.to_string()));
    }

    let owner_lifecycle_guard =
        match persist_owner_auth_under_lifecycle(&state, &identity, &next_auth).await {
            Ok(guard) => guard,
            Err(e) => return reject_owner_webauthn_recovery("authority_save_failed", Some(e)),
        };
    if let Err(e) = advance_owner_webauthn_recovery_anchor_after_commit(
        anchor.keystore.as_ref(),
        &next_auth.owner_webauthn_recovery,
        &identity.record,
        &next_auth.owner_person_cert,
    ) {
        return reject_owner_webauthn_recovery(
            "recovery_anchor_update_failed",
            Some(e.to_string()),
        );
    }
    drop(owner_lifecycle_guard);
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerWebauthnRecoveryFinishResponse {
        version: 1,
        recovery_code: recovery_code.to_string(),
        recovery_ready: true,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-webauthn/registration/start`.
///
/// Starts enrollment for the first owner passkey. This is an S3 backend
/// scaffold: the default router has no RP/anchor and therefore fails closed.
/// Additional credentials and revocation stay in later owner-gated slices.
pub async fn owner_webauthn_registration_start_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("owner_events.owner_webauthn_start.clock")
    else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let owner_auth = match household_auth::authorize_owner_auth_enroll_initial_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        now,
    )
    .await
    {
        Ok(owner_auth) => owner_auth,
        Err(e) => {
            return reject_owner_webauthn_registration("pop_auth_failed", Some(e.to_string()));
        }
    };

    let request: OwnerWebauthnRegistrationStartRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_owner_webauthn_registration("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_owner_webauthn_registration("bad_version", None);
    }

    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_registration("identity_unavailable", None);
    };
    let snapshot =
        owner_webauthn_initial_enrollment_policy_snapshot(&state, &identity, owner_auth.as_ref());
    if let Err(reason) = require_owner_webauthn_never_enrolled_for_initial_enrollment(&snapshot) {
        return reject_owner_webauthn_registration(reason, None);
    }
    let Some(rp) = &state.owner_webauthn_rp else {
        return reject_owner_webauthn_registration("rp_unavailable", None);
    };

    let mut rng = OsRng;
    let user_id = owner_webauthn_user_uuid(&owner_auth);
    let owner_name = owner_auth.owner_person_cert.p_id.0.as_str();
    let owner_display_name = owner_auth.owner_person_cert.display_name.as_str();
    let (challenge_id, options) = match rp.lock().await.start_registration(
        &mut rng,
        now,
        user_id,
        owner_name,
        owner_display_name,
        &[],
    ) {
        Ok(result) => result,
        Err(e) => {
            return reject_owner_webauthn_registration(
                "registration_start_failed",
                Some(e.to_string()),
            );
        }
    };
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartResponse {
        version: 1,
        challenge_id: challenge_id.as_str().to_string(),
        options,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-webauthn/registration/local/start`.
///
/// Starts first-passkey registration through the macOS local UDS boundary. This
/// wrapper never accepts network `PoP` as a substitute for local caller-auth.
/// Production M1 remains fail-closed because no real caller verifier is wired.
pub async fn owner_webauthn_registration_local_start_handler(
    State(state): State<OwnerEventsRouterState>,
    peer: Option<Extension<ConnectInfo<MacosLocalPeerConnectInfo>>>,
    body: Bytes,
) -> Response {
    let Some(now) =
        time_util::unix_now_secs_checked("owner_events.owner_webauthn_local_start.clock")
    else {
        return unauthenticated_response();
    };
    if let Err(e) =
        authorize_macos_local_caller(&state, macos_local_peer_connect_info(peer.as_ref()))
    {
        return reject_owner_webauthn_registration("local_caller_auth_failed", Some(e));
    }

    let request: OwnerWebauthnRegistrationStartRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_owner_webauthn_registration("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_owner_webauthn_registration("bad_version", None);
    }

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_registration("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_owner_webauthn_registration("owner_auth_unavailable", None);
    };
    let snapshot = owner_webauthn_initial_enrollment_policy_snapshot_read_only(
        &state,
        &identity,
        current_owner_auth.as_ref(),
    );
    if let Err(reason) = require_owner_webauthn_never_enrolled_for_initial_enrollment(&snapshot) {
        return reject_owner_webauthn_registration(reason, None);
    }
    let Some(rp) = &state.owner_webauthn_rp else {
        return reject_owner_webauthn_registration("rp_unavailable", None);
    };

    let mut rng = OsRng;
    let user_id = owner_webauthn_user_uuid(current_owner_auth.as_ref());
    let owner_name = current_owner_auth.owner_person_cert.p_id.0.as_str();
    let owner_display_name = current_owner_auth.owner_person_cert.display_name.as_str();
    let (challenge_id, options) = match rp
        .lock()
        .await
        .start_macos_local_attested_registration_from(
            &mut rng,
            now,
            &household_rs::owner_webauthn::OwnerWebauthnRegistrationStart {
                owner_user_id: user_id,
                owner_name,
                owner_display_name,
                existing_credentials: &[],
                binding: None,
            },
        ) {
        Ok(result) => result,
        Err(e) => {
            return reject_owner_webauthn_registration(
                "registration_start_failed",
                Some(e.to_string()),
            );
        }
    };
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartResponse {
        version: 1,
        challenge_id: challenge_id.as_str().to_string(),
        options,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-webauthn/registration/local/finish`.
///
/// M1 does not make local enrollment finish production-active. Caller-auth is
/// still mandatory, but commit remains blocked until M1b lands a real peer
/// verifier and platform+UV attestation constraints.
pub async fn owner_webauthn_registration_local_finish_handler(
    State(state): State<OwnerEventsRouterState>,
    peer: Option<Extension<ConnectInfo<MacosLocalPeerConnectInfo>>>,
) -> Response {
    if let Err(e) =
        authorize_macos_local_caller(&state, macos_local_peer_connect_info(peer.as_ref()))
    {
        return reject_owner_webauthn_registration("local_caller_auth_failed", Some(e));
    }
    reject_owner_webauthn_registration("local_attestation_constraints_unavailable", None)
}

/// `POST /api/v1/household/owner-webauthn/registration/finish`.
///
/// Commits the first owner passkey into the HH-root-signed authority log, then
/// advances the keystore-backed anchor. Enforcement remains off until a later,
/// explicitly approved flip.
pub async fn owner_webauthn_registration_finish_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("owner_events.owner_webauthn_finish.clock")
    else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let authorized_owner_auth = match household_auth::authorize_owner_auth_enroll_initial_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        now,
    )
    .await
    {
        Ok(owner_auth) => owner_auth,
        Err(e) => {
            return reject_owner_webauthn_registration("pop_auth_failed", Some(e.to_string()));
        }
    };

    let request: OwnerWebauthnRegistrationFinishRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_owner_webauthn_registration("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_owner_webauthn_registration("bad_version", None);
    }
    let challenge_id = match OwnerWebauthnChallengeId::parse(request.challenge_id) {
        Ok(challenge_id) => challenge_id,
        Err(e) => {
            return reject_owner_webauthn_registration("bad_challenge_id", Some(e.to_string()));
        }
    };

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_registration("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_owner_webauthn_registration("owner_auth_unavailable", None);
    };
    if current_owner_auth.owner_person_cert.p_id != authorized_owner_auth.owner_person_cert.p_id {
        return reject_owner_webauthn_registration("owner_auth_changed", None);
    }
    let snapshot = owner_webauthn_initial_enrollment_policy_snapshot(
        &state,
        &identity,
        current_owner_auth.as_ref(),
    );
    if let Err(reason) = require_owner_webauthn_never_enrolled_for_initial_enrollment(&snapshot) {
        return reject_owner_webauthn_registration(reason, None);
    }
    let Some(hh_priv) = identity.hh_priv.as_deref() else {
        return reject_owner_webauthn_registration("household_root_unavailable", None);
    };
    let Some(rp) = &state.owner_webauthn_rp else {
        return reject_owner_webauthn_registration("rp_unavailable", None);
    };
    let Some(anchor) = state.owner_webauthn_anchor.clone() else {
        return reject_owner_webauthn_registration("missing_anchor_verifier", None);
    };

    let credential =
        match rp
            .lock()
            .await
            .finish_registration(now, &challenge_id, &request.credential)
        {
            Ok(credential) => credential,
            Err(e) => {
                return reject_owner_webauthn_registration(
                    "registration_finish_failed",
                    Some(e.to_string()),
                );
            }
        };
    let credential_id = ByteBuf::from(credential.credential_id_bytes().to_vec());
    let genesis = match household_rs::owner_webauthn_authority::OwnerWebauthnAuthority::sign_genesis(
        hh_priv,
        &identity.record,
        &current_owner_auth.owner_person_cert,
        credential,
        now,
    ) {
        Ok(genesis) => genesis,
        Err(e) => {
            return reject_owner_webauthn_registration(
                "authority_sign_failed",
                Some(e.to_string()),
            );
        }
    };
    let mut next_auth = current_owner_auth.as_ref().clone();
    next_auth.owner_webauthn.push_signed(genesis);
    next_auth.updated_at = now;
    if let Err(e) = next_auth.verify(&identity.record, now) {
        return reject_owner_webauthn_registration("authority_verify_failed", Some(e.to_string()));
    }
    let active_credential_count = match next_auth.owner_webauthn_credentials(&identity.record) {
        Ok(credentials) => credentials.active_count() as u64,
        Err(e) => {
            return reject_owner_webauthn_registration(
                "credential_reconstruct_failed",
                Some(e.to_string()),
            );
        }
    };
    let authority_head = match verified_owner_webauthn_authority_head(
        &next_auth.owner_webauthn,
        &identity.record,
        &next_auth.owner_person_cert,
    ) {
        Ok(Some(head)) => head,
        Ok(None) => return reject_owner_webauthn_registration("authority_head_missing", None),
        Err(e) => {
            return reject_owner_webauthn_registration(
                "authority_head_failed",
                Some(e.to_string()),
            );
        }
    };
    let pending_marker = match initial_enrollment_marker_for(
        &identity,
        &next_auth,
        credential_id.clone(),
        &authority_head,
        active_credential_count,
    ) {
        Ok(marker) => marker,
        Err(e) => {
            return reject_owner_webauthn_registration("anchor_marker_invalid", Some(e));
        }
    };

    // `household_auth_state.cbor` is the durable log commit point. Advance the
    // rollback anchor only after this file is safely persisted, otherwise the
    // next boot could see an anchor ahead of the log and fail closed.
    // Keep in-memory owner auth aligned with the durable commit before any
    // post-save anchor failure can return. The lifecycle-exclusive helper also
    // prevents a teardown/replacement from splitting this disk/memory pair.
    let owner_lifecycle_guard =
        match persist_owner_auth_under_lifecycle(&state, &identity, &next_auth).await {
            Ok(guard) => guard,
            Err(e) => {
                return reject_owner_webauthn_registration("authority_save_failed", Some(e));
            }
        };
    if let Err(e) =
        write_owner_webauthn_initial_enrollment_marker(&state.state_dir, &pending_marker)
    {
        return reject_owner_webauthn_registration("anchor_marker_write_failed", Some(e));
    }
    if let Err(e) = verify_or_update_owner_webauthn_authority_anchor(
        anchor.keystore.as_ref(),
        &next_auth.owner_webauthn,
        &identity.record,
        &next_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::MigrationDefaultOff,
    ) {
        return reject_owner_webauthn_registration("anchor_update_failed", Some(e.to_string()));
    }
    if let Err(e) = clear_owner_webauthn_initial_enrollment_marker(&state.state_dir) {
        return reject_owner_webauthn_registration("anchor_marker_clear_failed", Some(e));
    }
    drop(owner_lifecycle_guard);
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationFinishResponse {
        version: 1,
        credential_id,
        active_credential_count,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-device/push-token`.
///
/// Persists the current iOS APNS device token for future opaque tickles.
pub async fn push_token_register_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("owner_events.push_token.clock") else {
        return unauthenticated_response();
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
                stage = "owner_events.push_token.rejected",
                reason = "pop_auth_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
    };

    let request: PushTokenRegisterRequest = match household_rs::cbor::from_canonical_slice(&body) {
        Ok(request) => request,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.push_token.rejected",
                reason = "cbor_decode",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    if request.version != 1 {
        tracing::warn!(
            stage = "owner_events.push_token.rejected",
            reason = "bad_version",
            version = request.version,
        );
        return unauthenticated_response();
    }

    let token = OwnerDevicePushToken {
        version: 1,
        p_id: owner_auth.owner_person_cert.p_id.0.clone(),
        platform: request.platform,
        push_token: request.push_token,
        updated_at: now,
    };
    if let Err(e) = household_rs::owner_events::put_owner_push_token(&state.state_dir, &token) {
        tracing::warn!(
            stage = "owner_events.push_token.rejected",
            reason = "persist_failed",
            error = %e,
        );
        return unauthenticated_response();
    }

    let bytes = household_rs::cbor::to_canonical_vec(&PushTokenRegisterResponse {
        version: 1,
        updated_at: now,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-events/<cursor>/approval-v2/start`.
pub async fn owner_approval_v2_start_handler(
    State(state): State<OwnerEventsRouterState>,
    Path(cursor_raw): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(cursor) = cursor_raw.parse::<u64>() else {
        tracing::warn!(
            stage = "owner_events.approval_v2_start.rejected",
            reason = "bad_cursor_path",
        );
        return unauthenticated_response();
    };
    let Some(now) = time_util::unix_now_secs_checked("owner_events.approval_v2_start.clock") else {
        return unauthenticated_response();
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
                stage = "owner_events.approval_v2_start.rejected",
                reason = "pop_auth_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    let request: OwnerApprovalV2StartRequest = match household_rs::cbor::from_canonical_slice(&body)
    {
        Ok(request) => request,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approval_v2_start.rejected",
                reason = "cbor_decode",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    if request.version != 1 {
        tracing::warn!(
            stage = "owner_events.approval_v2_start.rejected",
            reason = "unsupported_version",
        );
        return unauthenticated_response();
    }
    match household_rs::cbor::to_canonical_vec(&request) {
        Ok(canonical) if canonical == body.as_ref() => {}
        Ok(_) => {
            tracing::warn!(
                stage = "owner_events.approval_v2_start.rejected",
                reason = "non_canonical_cbor",
            );
            return unauthenticated_response();
        }
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approval_v2_start.rejected",
                reason = "cbor_reencode",
                error = %e,
            );
            return unauthenticated_response();
        }
    }

    let Some(identity) = state.household.current().await else {
        tracing::warn!(
            stage = "owner_events.approval_v2_start.rejected",
            reason = "identity_unavailable",
        );
        return unauthenticated_response();
    };
    let policy_snapshot =
        pair_machine_owner_webauthn_policy_snapshot(&state, &identity, owner_auth.as_ref());
    if state
        .owner_approval_policy
        .pair_machine_approval_body_mode(policy_snapshot.trust_state)
        != PairMachineApprovalBodyMode::RequireV2
    {
        tracing::warn!(
            stage = "owner_events.approval_v2_start.rejected",
            reason = "owner_webauthn_trust_not_active",
            trust_state = ?policy_snapshot.trust_state,
        );
        return unauthenticated_response();
    }
    if !owner_auth_allows_fan_out(
        "owner_events.approval_v2_start.rejected",
        owner_auth.as_ref(),
    ) {
        return unauthenticated_response();
    }
    let Some(credentials) = policy_snapshot.credentials else {
        tracing::warn!(
            stage = "owner_events.approval_v2_start.rejected",
            reason = "owner_webauthn_credentials_unavailable",
            trust_state = ?policy_snapshot.trust_state,
        );
        return unauthenticated_response();
    };
    let Some(rp) = state.owner_webauthn_rp.as_ref() else {
        tracing::warn!(
            stage = "owner_events.approval_v2_start.rejected",
            reason = "owner_webauthn_rp_unavailable",
        );
        return unauthenticated_response();
    };

    let snapshot = state.window.snapshot().await;
    if let Err(reason) = pair_machine_window_data(cursor, snapshot.clone()) {
        tracing::warn!(
            stage = "owner_events.approval_v2_start.rejected",
            reason = reason,
            cursor = cursor,
            window_cursor = ?snapshot.owner_event_cursor,
        );
        return unauthenticated_response();
    }

    let mut rng = rand::rngs::OsRng;
    let mut replay_nonce = [0_u8; 32];
    rng.fill_bytes(&mut replay_nonce);
    let mut rp = rp.lock().await;
    let expected_context = match pair_machine_expected_context_from_snapshot(
        &identity,
        owner_auth.as_ref(),
        &snapshot,
        now,
        rp.config().challenge_ttl().as_secs(),
        replay_nonce,
    ) {
        Ok(context) => context,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approval_v2_start.rejected",
                reason = "trusted_context_build_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    let (challenge_id, options) = match rp.start_owner_approval_assertion(
        &mut rng,
        now,
        credentials.credentials(),
        &expected_context,
    ) {
        Ok(started) => started,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approval_v2_start.rejected",
                reason = "webauthn_start_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
    };

    let bytes = household_rs::cbor::to_canonical_vec(&OwnerApprovalV2StartResponse {
        version: 1,
        challenge_id: challenge_id.as_str().to_string(),
        context: expected_context,
        options,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-events/<cursor>/approve`.
pub async fn owner_approve_handler(
    State(state): State<OwnerEventsRouterState>,
    Path(cursor_raw): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(cursor) = cursor_raw.parse::<u64>() else {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "bad_cursor_path",
        );
        return unauthenticated_response();
    };
    let Some(now) = time_util::unix_now_secs_checked("owner_events.approve.clock") else {
        return unauthenticated_response();
    };
    let pop = match household_auth::SoyehtPoP::parse(&headers) {
        Ok(pop) => pop,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "pop_parse_failed",
                error = ?e,
            );
            return unauthenticated_response();
        }
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
                stage = "owner_events.approve.rejected",
                reason = "pop_auth_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    let Some(identity) = state.household.current().await else {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "identity_unavailable",
        );
        return unauthenticated_response();
    };
    let policy_snapshot =
        pair_machine_owner_webauthn_policy_snapshot(&state, &identity, owner_auth.as_ref());
    let body_mode = state
        .owner_approval_policy
        .pair_machine_approval_body_mode(policy_snapshot.trust_state);
    if body_mode == PairMachineApprovalBodyMode::RequireV2
        && !owner_auth_allows_fan_out("owner_events.approve.rejected", owner_auth.as_ref())
    {
        return unauthenticated_response();
    }
    let approval_wire = match parse_pair_machine_approval_body(body_mode, cursor, &body) {
        Ok(approval) => approval,
        Err(reason) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = reason,
                path_cursor = cursor,
            );
            return unauthenticated_response();
        }
    };
    let mut window_data = match pair_machine_window_data(cursor, state.window.snapshot().await) {
        Ok(data) => data,
        Err(reason) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = reason,
                cursor = cursor,
            );
            return unauthenticated_response();
        }
    };
    let approved_v2_context = match &approval_wire {
        PairMachineApprovalWireBody::LegacyV1(approval) => {
            let approval_context = OwnerApprovalContext::build(
                identity.record.hh_id.clone(),
                owner_auth.owner_person_cert.p_id.clone(),
                cursor,
                window_data.join_request.challenge_sig.clone(),
                pop.timestamp,
            );
            if now.abs_diff(approval_context.timestamp) > 60 {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "approval_timestamp_skew",
                );
                return unauthenticated_response();
            }
            if let Err(e) =
                approval_context.verify(&owner_auth.owner_person_cert.p_pub, &approval.approval_sig)
            {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "approval_sig_invalid",
                    error = %e,
                );
                abort_with_cancel_event(
                    &state,
                    &identity,
                    window_data.active_m_pub.clone(),
                    "prepare_failed",
                )
                .await;
                return unauthenticated_response();
            }
            None
        }
        PairMachineApprovalWireBody::V2(finish) => {
            if let Err(e) = finish.approval.context.validate_at(now) {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "approval_v2_context_expired",
                    error = %e,
                );
                return unauthenticated_response();
            }
            let Some(credentials) = policy_snapshot.credentials.as_ref() else {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "owner_webauthn_credentials_unavailable",
                    trust_state = ?policy_snapshot.trust_state,
                );
                return unauthenticated_response();
            };
            let Some(mut credential) = credentials
                .credentials()
                .iter()
                .find(|credential| {
                    credential.credential_id_bytes() == finish.approval.credential_id.as_ref()
                })
                .cloned()
            else {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "owner_webauthn_credential_not_found",
                );
                return unauthenticated_response();
            };
            let Ok(challenge_id) = OwnerWebauthnChallengeId::parse(finish.challenge_id.clone())
            else {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "owner_webauthn_challenge_id_invalid",
                );
                return unauthenticated_response();
            };
            let assertion = match finish.approval.to_public_key_credential() {
                Ok(assertion) => assertion,
                Err(e) => {
                    tracing::warn!(
                        stage = "owner_events.approve.rejected",
                        reason = "approval_v2_assertion_invalid",
                        error = %e,
                    );
                    return unauthenticated_response();
                }
            };
            let Some(rp) = state.owner_webauthn_rp.as_ref() else {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "owner_webauthn_rp_unavailable",
                );
                return unauthenticated_response();
            };
            let Ok(replay_nonce) =
                <[u8; 32]>::try_from(finish.approval.context.replay_nonce.as_ref())
            else {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "approval_v2_replay_nonce_length",
                );
                return unauthenticated_response();
            };
            let mut rp = rp.lock().await;
            let expected_context = match pair_machine_expected_context_from_snapshot(
                &identity,
                owner_auth.as_ref(),
                &window_data.snapshot,
                finish.approval.context.issued_at,
                rp.config().challenge_ttl().as_secs(),
                replay_nonce,
            ) {
                Ok(context) => context,
                Err(e) => {
                    tracing::warn!(
                        stage = "owner_events.approve.rejected",
                        reason = "trusted_context_build_failed",
                        error = %e,
                    );
                    return unauthenticated_response();
                }
            };
            if let Err(e) = rp.finish_owner_approval_assertion(
                now,
                &challenge_id,
                &assertion,
                &mut credential,
                &finish.approval.context,
            ) {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "owner_webauthn_finish_failed",
                    error = %e,
                );
                return unauthenticated_response();
            }
            if let Err(e) = finish.approval.require_expected_context(&expected_context) {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "approval_v2_context_mismatch",
                    error = %e,
                );
                return unauthenticated_response();
            }
            Some(finish.approval.context.clone())
        }
    };
    let mutation_guard = if let Some(context) = approved_v2_context.as_ref() {
        let guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
            .lock()
            .await;
        let live_snapshot = state.window.snapshot().await;
        let live_window_data = match pair_machine_window_data(cursor, live_snapshot) {
            Ok(data) => data,
            Err(reason) => {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = reason,
                    cursor = cursor,
                );
                return unauthenticated_response();
            }
        };
        if let Err(e) = reassert_pair_machine_approval_context_against_live_window(
            context,
            &live_window_data.snapshot,
        ) {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "approval_v2_live_window_mismatch",
                error = %e,
            );
            return unauthenticated_response();
        }
        let mut claim_id = [0_u8; 32];
        OsRng.fill_bytes(&mut claim_id);
        if let Err(e) = state
            .window
            .claim_owner_approval(cursor, claim_id, now)
            .await
        {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "approval_v2_claim_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
        window_data = live_window_data;
        Some(guard)
    } else {
        None
    };

    let Some(hh_priv_handle) = identity.hh_priv.as_ref() else {
        // Post-Shamir household: the keystore custody of HH_priv has been
        // destroyed. There is no path here that can issue a new
        // MachineCert under the household root. The pre-prepare gate
        // (`shamir_n == 1` in `founder_stage_join_request`) should have
        // refused this ceremony already; this is defense-in-depth.
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "post_shamir_household",
        );
        abort_with_cancel_event(
            &state,
            &identity,
            window_data.active_m_pub.clone(),
            "prepare_failed",
        )
        .await;
        return unauthenticated_response();
    };
    // Phase 3 Shamir splitting requires the raw HH_priv scalar bytes
    // (`split_2_of_2` operates on the 32-byte EC scalar). Secure-Enclave
    // backed keys are non-exportable by design, so an SE-backed
    // `hh_priv` returns `None` here and the ceremony refuses. This is
    // a fundamental architectural limitation of Phase 3 (a key you
    // cannot read cannot be split); a Phase 6+ work item would
    // replace n-of-n Shamir with a threshold-signature primitive
    // that operates over the SE handle. For Phase 3, the founder
    // bootstrap path on macOS MUST run with
    // `THEYOS_FORCE_SOFTWARE_KEYS=1` if the household is intended to
    // grow beyond one machine. See `contracts/local-anchor.md`
    // §"Story 2 anchor mechanism" for the broader SE-backend
    // discussion. The wire response is the generic 401 per
    // FR-019a / R14; the WARN log surfaces the actionable reason
    // for the operator on M1.
    let Some(hh_priv) = hh_priv_handle.as_software_secret().copied() else {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "hh_scalar_unavailable",
            hint = "SE-backed HH_priv is non-exportable; Phase 3 Shamir splitting requires THEYOS_FORCE_SOFTWARE_KEYS=1 at bootstrap",
        );
        abort_with_cancel_event(
            &state,
            &identity,
            window_data.active_m_pub.clone(),
            "prepare_failed",
        )
        .await;
        return unauthenticated_response();
    };
    let Some(m1_priv) = identity.m_priv.as_software_secret().copied() else {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "m1_scalar_unavailable",
            hint = "SE-backed M_priv is non-exportable; Phase 3 ECDH for shard encryption requires THEYOS_FORCE_SOFTWARE_KEYS=1 at bootstrap",
        );
        abort_with_cancel_event(
            &state,
            &identity,
            window_data.active_m_pub.clone(),
            "prepare_failed",
        )
        .await;
        return unauthenticated_response();
    };
    let Ok(candidate_m_pub_sec1) = <[u8; 33]>::try_from(window_data.join_request.m_pub.as_ref())
    else {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "candidate_m_pub_length",
        );
        abort_with_cancel_event(
            &state,
            &identity,
            window_data.active_m_pub.clone(),
            "prepare_failed",
        )
        .await;
        return unauthenticated_response();
    };
    let push_token_seed = match household_rs::owner_events::get_owner_push_token(&state.state_dir) {
        Ok(token) => token,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "push_token_seed_read_failed",
                error = %e,
            );
            abort_with_cancel_event(
                &state,
                &identity,
                window_data.active_m_pub.clone(),
                "prepare_failed",
            )
            .await;
            return unauthenticated_response();
        }
    };
    // Bind staging and the single recovery manifest to the exact live
    // lifecycle. The guard is released before any network I/O, but no staged
    // artifact or manifest can be built against an identity that teardown has
    // already replaced.
    let pre_dispatch_lifecycle_guard =
        match acquire_owner_events_lifecycle_exclusive(&state.state_dir).await {
            Ok(guard) => guard,
            Err(error) => {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "pre_dispatch_lifecycle_unavailable",
                    error = %error,
                );
                drop(mutation_guard);
                abort_with_cancel_event(
                    &state,
                    &identity,
                    window_data.active_m_pub.clone(),
                    "prepare_failed",
                )
                .await;
                return unauthenticated_response();
            }
        };
    if let Err(error) = verify_installed_identity_under_lifecycle(
        &pre_dispatch_lifecycle_guard,
        &state.state_dir,
        &identity.record,
        &identity.cert,
    ) {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "pre_dispatch_identity_changed",
            error = %error,
        );
        drop(pre_dispatch_lifecycle_guard);
        drop(mutation_guard);
        abort_with_cancel_event(
            &state,
            &identity,
            window_data.active_m_pub.clone(),
            "prepare_failed",
        )
        .await;
        return unauthenticated_response();
    }
    let lifecycle_generation = match pre_dispatch_lifecycle_guard.lifecycle_generation() {
        Ok(Some(generation)) => generation,
        Ok(None) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "pre_dispatch_lifecycle_generation_missing",
            );
            drop(pre_dispatch_lifecycle_guard);
            drop(mutation_guard);
            return unauthenticated_response();
        }
        Err(error) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "pre_dispatch_lifecycle_generation_read_failed",
                error = %error,
            );
            drop(pre_dispatch_lifecycle_guard);
            drop(mutation_guard);
            return unauthenticated_response();
        }
    };
    if window_data
        .snapshot
        .lifecycle_generation
        .as_ref()
        .is_none_or(|value| value.as_ref() != lifecycle_generation.token_bytes())
    {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "pre_dispatch_window_generation_changed",
        );
        drop(pre_dispatch_lifecycle_guard);
        drop(mutation_guard);
        return unauthenticated_response();
    }
    let mut txn = match CeremonyTxn::prepare(CeremonyInputs {
        hh_priv: Zeroizing::new(hh_priv),
        hh_id: identity.record.hh_id.clone(),
        hh_pub_sec1: *identity.record.hh_pub.as_bytes(),
        m1_priv_scalar: Zeroizing::new(m1_priv),
        m1_pub_sec1: *identity.cert.m_pub.as_bytes(),
        m1_id: identity.cert.m_id.to_string(),
        candidate_m_pub_sec1,
        candidate_hostname: window_data.join_request.hostname.clone(),
        candidate_platform: window_data.join_request.platform.clone(),
        joined_at: now,
        state_dir: state.state_dir.clone(),
        existing_record: identity.record.clone(),
        policy: state.key_backing_policy,
    }) {
        Ok(txn) => txn,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "ceremony_prepare_failed",
                error = %e,
            );
            drop(pre_dispatch_lifecycle_guard);
            drop(mutation_guard);
            abort_with_cancel_event(
                &state,
                &identity,
                window_data.active_m_pub.clone(),
                "prepare_failed",
            )
            .await;
            return unauthenticated_response();
        }
    };
    let addr = window_data
        .snapshot
        .addr_hint
        .clone()
        .unwrap_or_else(|| window_data.join_request.addr.clone());
    // Resolve the founder hint exactly once. The same value must feed both
    // builds below so the crash-recovery JoinResponse remains byte-identical
    // to the response POSTed to M2.
    let founder_tailscale_addr = build_founder_tailnet_addr(
        crate::household_bootstrap::household_port_from_env(),
        state.founder_tailnet_resolver,
    );
    let cached_join_request_bytes = window_data.cached_join_request.to_vec();
    let manifest_options = FinalizeWithM2Options {
        addr: &addr,
        join_request_cbor: &cached_join_request_bytes,
        founder_cert: &identity.cert,
        founder_tailscale_addr,
        push_token_seed,
        response_signer: identity.m_priv.as_ref(),
    };
    let manifest =
        match txn.build_phase3_recovery_manifest(&manifest_options, &lifecycle_generation) {
            Ok(manifest) => manifest,
            Err(error) => {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "phase3_recovery_manifest_build_failed",
                    error = %error,
                );
                drop(pre_dispatch_lifecycle_guard);
                drop(mutation_guard);
                txn.rollback();
                abort_with_cancel_event(
                    &state,
                    &identity,
                    window_data.active_m_pub.clone(),
                    "prepare_failed",
                )
                .await;
                return unauthenticated_response();
            }
        };
    match household_rs::storage::write_phase3_recovery_manifest(
        &pre_dispatch_lifecycle_guard,
        &state.state_dir,
        &manifest,
    ) {
        Ok(()) => {}
        Err(household_rs::StorageError::MayHaveTakenEffect { .. }) => {
            tracing::error!(
                stage = "owner_events.approve.partially_committed",
                reason = "phase3_manifest_durability_indeterminate",
                hint = "no finalize POST was launched; exact manifest and staged artifacts are retained for boot stabilization",
            );
            drop(pre_dispatch_lifecycle_guard);
            drop(mutation_guard);
            txn.preserve_staged_for_recovery();
            return internal_error_response();
        }
        Err(error) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "phase3_recovery_manifest_write_failed",
                error = %error,
            );
            drop(pre_dispatch_lifecycle_guard);
            drop(mutation_guard);
            txn.rollback();
            abort_with_cancel_event(
                &state,
                &identity,
                window_data.active_m_pub.clone(),
                "prepare_failed",
            )
            .await;
            return unauthenticated_response();
        }
    }
    // From this exact point the manifest is durable recovery authority.
    // Disarm rollback-on-Drop before the transaction can cross a task/panic or
    // launch the remote POST.
    txn.arm_manifest_recovery();
    drop(pre_dispatch_lifecycle_guard);
    drop(mutation_guard);
    let manifest_for_finalize = manifest.clone();
    let finalize_addr = addr.clone();
    let finalized = tokio::task::spawn_blocking(move || {
        match txn.finalize_manifest_with_m2(&finalize_addr, &manifest_for_finalize) {
            Ok(outcome) => FinalizeAttempt::Acked(Box::new(txn), Box::new(outcome)),
            Err(e) if e.is_ambiguous_finalize_outcome() => {
                txn.preserve_staged_for_recovery();
                FinalizeAttempt::AmbiguousFailure(e)
            }
            Err(e) => FinalizeAttempt::DefiniteFailure(Box::new(txn), e),
        }
    })
    .await;
    let (txn, finalize) = match finalized {
        Ok(FinalizeAttempt::Acked(txn, outcome)) => (*txn, *outcome),
        Ok(FinalizeAttempt::DefiniteFailure(txn, e)) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "m2_finalize_failed",
                error = %e,
            );
            // A complete strict reject proves the remote request had no
            // effect. The manifest remains cleanup authority until every
            // staged artifact is durably absent. Only then may its own
            // absence be committed. Reversing that order could leave orphaned
            // staged authority with no record that authorizes cleanup.
            let cleanup_guard =
                match acquire_owner_events_lifecycle_exclusive(&state.state_dir).await {
                    Ok(guard)
                        if guard
                            .lifecycle_generation()
                            .ok()
                            .flatten()
                            .as_ref()
                            .is_some_and(|generation| {
                                generation.token_bytes() == manifest.lifecycle_generation()
                            }) =>
                    {
                        guard
                    }
                    Ok(_) | Err(_) => {
                        txn.preserve_staged_for_recovery();
                        return internal_error_response();
                    }
                };
            // The durable manifest already disarmed rollback-on-Drop before
            // the POST. Consume the transaction without relying on its now
            // intentionally empty staged handle; cleanup below is explicit
            // and remains lifecycle-exclusive.
            txn.preserve_staged_for_recovery();
            if let Err(cleanup_error) = durably_remove_phase3_staged_after_definite_reject(
                &state.state_dir,
                manifest.candidate_m_id(),
            ) {
                tracing::error!(
                    stage = "owner_events.approve.staged_cleanup_failed",
                    reason = "after_definite_finalize_reject_manifest_retained",
                    error = %cleanup_error,
                );
                drop(cleanup_guard);
                return internal_error_response();
            }
            if let Err(clear_error) = household_rs::storage::clear_phase3_recovery_manifest(
                &cleanup_guard,
                &state.state_dir,
            ) {
                tracing::error!(
                    stage = "owner_events.approve.manifest_clear_failed",
                    reason = "after_definite_finalize_reject_staged_absence_committed",
                    error = %clear_error,
                );
                drop(cleanup_guard);
                return internal_error_response();
            }
            drop(cleanup_guard);
            abort_with_cancel_event(
                &state,
                &identity,
                window_data.active_m_pub.clone(),
                "candidate_unreachable",
            )
            .await;
            return unauthenticated_response();
        }
        Ok(FinalizeAttempt::AmbiguousFailure(e)) => {
            tracing::error!(
                stage = "owner_events.approve.partially_committed",
                reason = "m2_finalize_outcome_ambiguous",
                error = %e,
                hint = "finalize POST may have committed M2; M1 .staged files + finalize intent marker left for boot recovery",
            );
            return internal_error_response();
        }
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "m2_finalize_task_failed",
                error = %e,
            );
            // Unknown outcome: keep the manifest. Staged rollback was
            // synchronously disarmed before this task was spawned, so even a
            // panic retains the exact recovery evidence.
            return internal_error_response();
        }
    };
    let candidate_cert = txn.candidate_cert().clone();
    // M2 may return its current Tailnet address as an optional HTTP header.
    // It is deliberately outside the deterministic FinalizeAck body and is
    // never identity authority. Accept only a CGNAT IPv4 at the same port M2
    // signed into its JoinRequest, then cache it as the same best-effort
    // liveness hint used by the machines endpoint. Persist before the local
    // destructive commit so an M1 crash after the verified M2 ack can still
    // recover with the fresher post-Ready location; a stale cache entry alone
    // cannot create membership or make a machine appear in the list.
    match validated_candidate_tailnet_addr(
        finalize.candidate_tailscale_addr.as_deref(),
        &window_data.join_request.addr,
    ) {
        Some(addr) => {
            if let Err(e) = household_rs::storage::write_known_peer_addr(
                &state.state_dir,
                candidate_cert.m_id.as_str(),
                &addr,
            ) {
                tracing::warn!(
                    stage = "owner_events.approve.candidate_tailnet_hint_persist_failed",
                    candidate_m_id = %candidate_cert.m_id,
                    error = %e,
                );
            }
        }
        None if finalize.candidate_tailscale_addr.is_some() => {
            tracing::warn!(
                stage = "owner_events.approve.candidate_tailnet_hint_ignored",
                candidate_m_id = %candidate_cert.m_id,
                reason = "not_tailnet_ipv4_or_port_mismatch",
            );
        }
        None => {}
    }
    // T064: failure-injection crash point — fires immediately after
    // `finalize_with_m2` returns Ok and BEFORE `commit_preserve_on_error`
    // promotes the staged set. A registered Panic models "M1 crash
    // between 2PC step 11 (FinalizeAck received) and step 12 (rename
    // staged files)". On reboot, M1 sees a pre-Shamir record + marker
    // + .staged files and recovery rolls forward via the post-commit
    // probe of M2 per `contracts/shamir-transition.md` §"Recovery on
    // M1 boot".
    #[cfg(any(test, feature = "failure-injection"))]
    {
        match crate::failure_injection::apply(crate::failure_injection::InjectionPoint::M1AfterAck)
            .await
        {
            crate::failure_injection::Outcome::EarlyReject(_) => {
                // Match the post-ack ambiguous-failure surface so the
                // marker + staged set survive for boot recovery.
                txn.preserve_staged_for_recovery();
                return internal_error_response();
            }
            crate::failure_injection::Outcome::Skip
            | crate::failure_injection::Outcome::Continue => {}
        }
    }
    // From this point forward M2 has returned the exact manifest-bound Ack.
    // The single manifest remains the authority for every local roll-forward
    // step and, after promotion, for the terminal MachineJoined outbox. No
    // failure past this line may roll back or clear it.
    let post_ack_mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let post_ack_lifecycle_guard =
        match acquire_owner_events_lifecycle_exclusive(&state.state_dir).await {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!(
                    stage = "owner_events.approve.partially_committed",
                    reason = "post_ack_lifecycle_unavailable",
                    error = %e,
                    hint = "M2 acked; preserving manifest-bound staged files for boot recovery",
                );
                txn.preserve_staged_for_recovery();
                return internal_error_response();
            }
        };
    if let Err(e) = verify_installed_identity_under_lifecycle(
        &post_ack_lifecycle_guard,
        &state.state_dir,
        &identity.record,
        &identity.cert,
    ) {
        tracing::error!(
            stage = "owner_events.approve.partially_committed",
            reason = "post_ack_identity_changed",
            error = %e,
            hint = "M2 acked; preserving manifest-bound staged files for boot recovery",
        );
        txn.preserve_staged_for_recovery();
        return internal_error_response();
    }
    let recovery_namespace =
        match household_rs::pair_window_namespace::PairWindowNamespaceV2::current_under_lifecycle(
            state.state_dir.clone(),
            &post_ack_lifecycle_guard,
        ) {
            Ok(namespace) => namespace,
            Err(error) => {
                tracing::error!(
                    stage = "owner_events.approve.partially_committed",
                    reason = "manifest_namespace_unavailable",
                    error = %error,
                );
                txn.preserve_staged_for_recovery();
                return internal_error_response();
            }
        };
    txn.preserve_staged_for_recovery();
    if let Err(e) = household_rs::pair_machine::finish_phase3_manifest_under_lifecycle(
        &state.state_dir,
        &recovery_namespace,
        &post_ack_lifecycle_guard,
        manifest.clone(),
    )
    .await
    {
        tracing::error!(
            stage = "owner_events.approve.partially_committed",
            reason = "m1_manifest_finish_failed_after_m2_ack",
            error = %e,
            hint = "M2 acked; exact manifest + remaining staged artifacts retained for boot recovery",
        );
        return internal_error_response();
    }
    // T064: failure-injection crash point — fires after
    // exact manifest finish returns Ok and BEFORE
    // `OwnerEvent{type=machine-joined}` is appended. A
    // registered Panic models "M1 crash between 2PC step 13 (sole-shard
    // unlink) and step 14 (event-log append)". On reboot, M1 has a
    // post-Shamir record on disk and the manifest remains the durable outbox;
    // startup/retry appends the exact event before clearing it.
    #[cfg(any(test, feature = "failure-injection"))]
    {
        match crate::failure_injection::apply(
            crate::failure_injection::InjectionPoint::M1AfterStagedCommit,
        )
        .await
        {
            crate::failure_injection::Outcome::EarlyReject(_) => {
                return internal_error_response();
            }
            crate::failure_injection::Outcome::Skip
            | crate::failure_injection::Outcome::Continue => {}
        }
    }
    // Reload `LoadedIdentity` under the same lifecycle transaction: the
    // on-disk record now has
    // `shamir_n=2` and the keystore custody of HH_priv has been
    // destroyed. `try_load_existing` will deliver `hh_priv: None`.
    // Swap it into the shared `HouseholdState` so subsequent requests
    // see the post-Shamir household and `founder_stage_join_request`'s
    // `shamir_n == 1` gate refuses any further add-machine attempts on
    // the now-stale single-machine path. (B6.)
    let reloaded_result = household_rs::bootstrap::try_load_existing_under_lifecycle(
        &post_ack_lifecycle_guard,
        &state.state_dir,
        state.key_backing_policy,
    );
    let Ok(Some(reloaded)) = reloaded_result else {
        // Disk is already authoritative and cannot be rolled back. Refuse
        // to publish the committed window alongside a stale pre-Shamir
        // in-memory identity; boot recovery will reload the durable state.
        tracing::error!(
            stage = "owner_events.approve.identity_reload_failed",
            hint = "post-commit identity unavailable; refusing stale in-memory publication",
        );
        return internal_error_response();
    };
    state.household.set_loaded(Arc::new(reloaded)).await;
    if let Err(e) = state
        .window
        .under_lifecycle(&post_ack_lifecycle_guard)
        .enter_committed(finalize.join_response_bytes.clone())
        .await
    {
        // Same post-commit semantics as above — disk is authoritative.
        tracing::error!(
            stage = "owner_events.approve.window_commit_failed",
            reason = "in_memory_window_update_failed_after_disk_commit",
            error = %e,
        );
        return internal_error_response();
    }
    // Positive observability gate (T093): the household has just grown
    // from N=1 (sole-shard) to N=2 (Shamir 2-of-2). This is the
    // canonical "ceremony committed" + "Shamir transition committed"
    // checkpoint — a successful transition emits exactly one of these
    // events per ceremony, regardless of replay-after-commit re-entry.
    tracing::info!(
        stage = "pair_machine.shamir_transition_committed",
        cursor = cursor,
        candidate_m_id = %candidate_cert.m_id,
    );
    let machine_joined_log = Arc::clone(&state.event_log);
    let machine_joined_identity = Arc::clone(&identity);
    let machine_joined_payload = MachineJoinedPayload {
        m_pub: ByteBuf::from(candidate_cert.m_pub.as_bytes().to_vec()),
        m_id: candidate_cert.m_id.to_string(),
        hostname: candidate_cert.hostname.clone(),
        joined_at: candidate_cert.joined_at,
    };
    let outbox_state_dir = state.state_dir.clone();
    let append_result = tokio::task::spawn_blocking(move || {
        machine_joined_log.append_machine_joined_exactly_once_under_lifecycle_write(
            &post_ack_lifecycle_guard,
            &machine_joined_identity.cert.m_id.to_string(),
            machine_joined_identity.m_priv.as_ref(),
            machine_joined_payload,
        )?;
        Ok::<_, household_rs::owner_events::EventError>(
            household_rs::storage::clear_phase3_recovery_manifest(
                &post_ack_lifecycle_guard,
                &outbox_state_dir,
            ),
        )
    })
    .await;
    drop(post_ack_mutation_guard);
    match append_result {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => {
            // The event is durable and already published, but the outbox
            // absence was not committed. A retry/startup scan reuses the same
            // event and retries only the durable clear.
            dispatch_owner_event_tickle_if_idle(state.state_dir.clone(), &state.event_broadcaster);
            tracing::error!(
                stage = "owner_events.approve.outbox_clear_failed",
                error = %error,
            );
            return internal_error_response();
        }
        Ok(Err(error)) => {
            tracing::error!(
                stage = "owner_events.approve.event_append_failed",
                reason = "machine_joined_event_append_failed_after_commit",
                error = %error,
                hint = "exact manifest retained; startup/retry reconciles without duplication",
            );
            return internal_error_response();
        }
        Err(error) => {
            tracing::error!(
                stage = "owner_events.approve.event_append_worker_failed",
                error = %error,
                hint = "exact manifest retained; startup/retry reconciles without duplication",
            );
            return internal_error_response();
        }
    }
    dispatch_owner_event_tickle_if_idle(state.state_dir.clone(), &state.event_broadcaster);

    tracing::info!(
        stage = "owner_events.approve.accepted",
        cursor = cursor,
        candidate_m_id = %candidate_cert.m_id,
    );
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerApprovalAck {
        version: 1,
        machine_cert_hash: finalize.ack.machine_cert_hash,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-events/<cursor>/decline`.
pub async fn owner_decline_handler(
    State(state): State<OwnerEventsRouterState>,
    Path(cursor_raw): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(cursor) = cursor_raw.parse::<u64>() else {
        tracing::warn!(
            stage = "owner_events.decline.rejected",
            reason = "bad_cursor_path",
        );
        return unauthenticated_response();
    };
    let Some(now) = time_util::unix_now_secs_checked("owner_events.decline.clock") else {
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
            stage = "owner_events.decline.rejected",
            reason = "pop_auth_failed",
            error = %e,
        );
        return unauthenticated_response();
    }

    let Some(identity) = state.household.current().await else {
        tracing::warn!(
            stage = "owner_events.decline.rejected",
            reason = "identity_unavailable",
        );
        return unauthenticated_response();
    };
    let snap = state.window.snapshot().await;
    if snap.state != PairMachineState::AwaitingOwner || snap.owner_event_cursor != Some(cursor) {
        tracing::warn!(
            stage = "owner_events.decline.rejected",
            reason = "window_cursor_mismatch",
            cursor = cursor,
            window_cursor = ?snap.owner_event_cursor,
        );
        return unauthenticated_response();
    }
    let Some(m_pub) = snap.m_pub.as_ref() else {
        tracing::warn!(
            stage = "owner_events.decline.rejected",
            reason = "window_missing_m_pub",
        );
        return unauthenticated_response();
    };
    if let Err(e) = state.window.enter_aborted().await {
        tracing::warn!(
            stage = "owner_events.decline.rejected",
            reason = "window_abort_failed",
            error = %e,
        );
        return unauthenticated_response();
    }
    let event = append_owner_event_with_shared_lifecycle(
        &state,
        Arc::clone(&identity),
        OwnerEventType::JoinCancelled,
        OwnerEventPayload::JoinCancelled(JoinCancelledPayload {
            m_pub: m_pub.clone(),
            reason: "declined".into(),
        }),
    )
    .await;
    if let Err(e) = event {
        tracing::warn!(
            stage = "owner_events.decline.rejected",
            reason = "cancel_event_append_failed",
            error = %e,
        );
        return unauthenticated_response();
    }
    dispatch_owner_event_tickle_if_idle(state.state_dir.clone(), &state.event_broadcaster);
    // Positive observability gate (T093) — the owner has affirmatively
    // declined the join. Distinguished from `decline.rejected` (any
    // failure) so audit consumers can count only successful declines.
    tracing::info!(stage = "owner_events.decline.accepted", cursor = cursor,);

    let bytes =
        household_rs::cbor::to_canonical_vec(&OwnerDeclineAck { version: 1 }).unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

async fn abort_with_cancel_event(
    state: &OwnerEventsRouterState,
    identity: &Arc<household_rs::LoadedIdentity>,
    m_pub: ByteBuf,
    reason: &'static str,
) {
    if let Err(e) = state.window.enter_aborted().await {
        tracing::warn!(
            stage = "owner_events.cancel.abort_failed",
            reason = reason,
            error = %e,
        );
        return;
    }
    match append_owner_event_with_shared_lifecycle(
        state,
        Arc::clone(identity),
        OwnerEventType::JoinCancelled,
        OwnerEventPayload::JoinCancelled(JoinCancelledPayload {
            m_pub,
            reason: reason.into(),
        }),
    )
    .await
    {
        Ok(_) => {
            dispatch_owner_event_tickle_if_idle(state.state_dir.clone(), &state.event_broadcaster);
            // Positive observability gate (T093) — the ceremony was
            // aborted from an internal path (2PC failure during
            // approve) rather than an explicit owner decline. The
            // `reason` carries the source: `2pc_failed`, `internal`,
            // etc. Production audit consumers count this against
            // `decline.accepted` to distinguish owner-initiated
            // declines from system-driven aborts.
            tracing::info!(stage = "pair_machine.ceremony_aborted", reason = reason,);
        }
        Err(e) => tracing::warn!(
            stage = "owner_events.cancel.append_failed",
            reason = reason,
            error = %e,
        ),
    }
}

/// Dispatch an opaque APNS tickle after an owner event was durably appended and
/// published, but only when no long-poll request is currently subscribed.
///
/// The APNS dispatcher accepts only the registered push token, never the event
/// itself, so no household metadata can reach Apple through this path.
pub fn dispatch_owner_event_tickle_if_idle(
    state_dir: PathBuf,
    event_broadcaster: &OwnerEventsBroadcaster,
) {
    if event_broadcaster.active_subscribers() > 0 {
        return;
    }
    tokio::spawn(async move {
        let token = match household_rs::owner_events::get_owner_push_token(&state_dir) {
            Ok(Some(token)) => token,
            Ok(None) => {
                tracing::info!(
                    stage = "owner_events.apns.skipped",
                    reason = "no_registered_token",
                );
                return;
            }
            Err(e) => {
                tracing::warn!(
                    stage = "owner_events.apns.skipped",
                    reason = "token_read_failed",
                    error = %e,
                );
                return;
            }
        };
        match apns_dispatcher::dispatch_tickle(&token).await {
            Ok(()) => {
                // Positive observability gate (T093) — the dispatcher
                // returned successfully. Note: this fires AFTER the
                // dispatcher's own internal `apns.disabled_at_runtime`
                // short-circuit (which still returns Ok), so a build
                // running with `THEYOS_PUSH_DISABLED=1` produces a
                // pair of events: the disabled-at-runtime info plus
                // this dispatched info. Audit consumers cross-check
                // both layers.
                tracing::info!(stage = "owner_events.apns.dispatched");
            }
            Err(e) => tracing::warn!(
                stage = "owner_events.apns.dispatch_failed",
                error = %e,
            ),
        }
    });
}

/// Spawn a runtime watchdog that fires when the `PairMachineWindow`
/// reaches its TTL expiry without owner action. This is the active
/// half of FR-019's "owner timed out" requirement — the boot-time
/// recovery in `load_state_dir` only handles the case where the
/// daemon was DOWN during expiry; this watchdog handles the in-process
/// case where the daemon is up but the owner never approved or
/// declined.
///
/// On fire the watchdog:
///
///  1. Emits `pair_machine.owner_timed_out` (T093 / FR-019 stage).
///  2. Calls [`abort_with_cancel_event`] with `reason = "timeout"`,
///     which transitions the window `awaiting_owner → aborted`,
///     appends a `JoinCancelled{reason="timeout"}` owner event so any
///     iPhone long-poll wakes up with the cancellation, and tickles
///     the broadcaster (which fires APNS for backgrounded clients).
///
/// The watchdog re-arms on every state transition into `Staging` or
/// `AwaitingOwner` and cancels itself early if the window leaves
/// those states before expiry. Production callers MUST hold the
/// returned [`tokio::task::JoinHandle`] for the lifetime of the
/// owner-events router; dropping it does not abort the task.
///
/// # Shutdown
///
/// Pass a `watch::Receiver<bool>` whose channel sender is owned by
/// the caller. Callers wishing to stop the watchdog cleanly (test
/// teardown, in-process daemon restart) invoke
/// `cancel_tx.send(true)`. The watch primitive *latches*: every
/// subsequent `*cancel_rx.borrow()` returns `true`, so a regression
/// where the wake lands during a non-`select!` await (e.g.,
/// `state.window.snapshot().await`,
/// `state.household.current().await`,
/// `abort_with_cancel_event(...).await`) is still observed at the
/// next sticky check at the top of the loop. This closes the
/// lost-wakeup race that an edge-triggered primitive like
/// [`tokio::sync::Notify`] would have exposed.
///
/// The watchdog also exits if all senders drop (`changed()` returns
/// `Err`). In production the sender MUST be retained — see
/// `household_bootstrap.rs` for the canonical leak pattern — or the
/// watchdog will exit immediately on first `changed()` poll.
#[must_use]
pub fn spawn_owner_timeout_watchdog(
    state: OwnerEventsRouterState,
    mut cancel_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut state_rx = state.window.subscribe();
        loop {
            // Sticky cancel check — closes the lost-wakeup race that
            // an edge-triggered shutdown primitive would have. Any
            // prior `cancel_tx.send(true)` is observed here regardless
            // of whether the watchdog was suspended on a `select!`
            // arm, a non-`select!` await (snapshot, current, abort),
            // or between iterations. Subsequent `changed()` arms in
            // the body remain useful for waking from sleeps.
            if *cancel_rx.borrow() {
                return;
            }
            let snap = state.window.snapshot().await;
            let in_timed_state = matches!(
                snap.state,
                PairMachineState::Staging | PairMachineState::AwaitingOwner
            );
            if !in_timed_state {
                tokio::select! {
                    cancel = cancel_rx.changed() => {
                        // Either a true `send(true)` landed or all
                        // senders dropped — either way exit.
                        let _ = cancel;
                        return;
                    }
                    changed = state_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
                continue;
            }
            let Some(expiry) = snap.expiry else {
                tokio::select! {
                    cancel = cancel_rx.changed() => {
                        let _ = cancel;
                        return;
                    }
                    changed = state_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
                continue;
            };
            let Some(now) = time_util::unix_now_secs_checked("pair_machine.timeout_watchdog.clock")
            else {
                if backoff_or_cancel(&mut cancel_rx).await {
                    return;
                }
                continue;
            };
            let sleep_secs = expiry.saturating_sub(now);
            if sleep_secs > 0 {
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_secs(sleep_secs)) => {}
                    changed = state_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        continue;
                    }
                    cancel = cancel_rx.changed() => {
                        let _ = cancel;
                        return;
                    }
                }
            }
            // Re-snapshot. The state may have advanced during sleep
            // (approve/decline races the timeout); fire only if the
            // window is STILL in a timed state and the wall clock has
            // truly passed expiry. This avoids a spurious abort on a
            // clock skew or premature wake.
            let snap = state.window.snapshot().await;
            if !matches!(
                snap.state,
                PairMachineState::Staging | PairMachineState::AwaitingOwner
            ) {
                continue;
            }
            // The three "transient None" branches below all use
            // `backoff_or_cancel` so a stuck condition (clock
            // failure, household unloaded, missing m_pub) cannot
            // tight-loop the CPU — every retry waits 1s OR exits on
            // cancel. Without this, an elapsed-TTL window where any
            // of these returned None would spin the loop because
            // `sleep_secs == 0` skips the pre-sleep `select!` arm.
            let Some(now) = time_util::unix_now_secs_checked("pair_machine.timeout_watchdog.clock")
            else {
                if backoff_or_cancel(&mut cancel_rx).await {
                    return;
                }
                continue;
            };
            if let Some(expiry) = snap.expiry {
                if now < expiry {
                    continue;
                }
            }
            let Some(identity) = state.household.current().await else {
                if backoff_or_cancel(&mut cancel_rx).await {
                    return;
                }
                continue;
            };
            let Some(m_pub) = snap.m_pub.clone() else {
                if backoff_or_cancel(&mut cancel_rx).await {
                    return;
                }
                continue;
            };
            tracing::info!(
                stage = "pair_machine.owner_timed_out",
                cursor = ?snap.owner_event_cursor,
                expiry = ?snap.expiry,
            );
            abort_with_cancel_event(&state, &identity, m_pub, "timeout").await;
            // Loop and wait for the next state transition; the abort
            // moves the window to `Aborted`, so the next iteration
            // hits the !in_timed_state branch and waits. The sticky
            // cancel check at the top of the loop catches a cancel
            // that landed mid-`abort_with_cancel_event`.
        }
    })
}

/// 1-second back-pressure that races the cancel signal. Returns
/// `true` if the caller should exit because cancel was triggered.
/// Used by [`spawn_owner_timeout_watchdog`] in transient-`None`
/// branches (clock failure, household unloaded, missing `m_pub`) so a
/// stuck condition does not tight-loop the CPU after the TTL has
/// elapsed (the `sleep_secs > 0` pre-sleep arm is bypassed once
/// `expiry` is in the past).
async fn backoff_or_cancel(cancel_rx: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(Duration::from_secs(1)) => false,
        cancel = cancel_rx.changed() => {
            let _ = cancel;
            true
        }
    }
}

fn build_founder_tailnet_addr(port: u16, resolver: TailnetResolver) -> Option<String> {
    resolver().map(|ip| format!("{ip}:{port}"))
}

fn validated_candidate_tailnet_addr(hint: Option<&str>, signed_join_addr: &str) -> Option<String> {
    let hinted: std::net::SocketAddr = hint?.parse().ok()?;
    let signed_join: std::net::SocketAddr = signed_join_addr.parse().ok()?;
    let std::net::SocketAddr::V4(hinted_v4) = hinted else {
        return None;
    };
    if hinted_v4.port() != signed_join.port()
        || !crate::tailnet_address::is_tailnet_ipv4(*hinted_v4.ip())
    {
        return None;
    }
    Some(hinted.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::ids::{HouseholdId, MachineId};
    use household_rs::machine_cert::PersonId;
    use household_rs::owner_approval_v2::PairMachineApprovalContextInput;
    use household_rs::pair_machine::{
        JoinTransport, PAIR_MACHINE_VERSION, PairMachineApprovalClaim,
    };
    use std::net::Ipv4Addr;

    fn bootstrap_lifecycle_test_identity(state_dir: &FsPath) -> household_rs::LoadedIdentity {
        household_rs::bootstrap_or_load(
            state_dir,
            household_rs::BootstrapOpts {
                household_name: "Owner Events Lifecycle Home".to_string(),
                hostname_label: Some("owner-events-lifecycle-host".to_string()),
            },
            household_rs::KeyBackingPolicy::ForceSoftware,
        )
        .expect("bootstrap lifecycle test identity")
    }

    #[test]
    fn owner_authority_commit_revalidates_exact_record_and_cert() {
        let state_dir = tempfile::tempdir().expect("state dir");
        let identity = bootstrap_lifecycle_test_identity(state_dir.path());
        let guard = acquire_owner_events_lifecycle_exclusive_blocking(state_dir.path())
            .expect("acquire lifecycle");

        verify_installed_identity_under_lifecycle(
            &guard,
            state_dir.path(),
            &identity.record,
            &identity.cert,
        )
        .expect("exact identity matches");

        let mut stale_record = identity.record.clone();
        stale_record.name.push_str(" stale");
        let error = verify_installed_identity_under_lifecycle(
            &guard,
            state_dir.path(),
            &stale_record,
            &identity.cert,
        )
        .expect_err("stale identity must not authorize owner mutation");
        assert!(error.contains("identity changed"));
    }

    #[test]
    fn interrupted_teardown_is_recovered_but_stale_owner_mutation_is_rejected() {
        let state_dir = tempfile::tempdir().expect("state dir");
        let _identity = bootstrap_lifecycle_test_identity(state_dir.path());
        let lifecycle =
            HouseholdLifecycleLock::open_verified(state_dir.path()).expect("open lifecycle");
        let guard = lifecycle.lock_exclusive().expect("lock lifecycle");
        assert!(
            guard
                .rename_household_to_tearing_down()
                .expect("detach household")
        );
        drop(guard);

        let recovered_guard = acquire_owner_events_lifecycle_exclusive_blocking(state_dir.path())
            .expect("reacquire lifecycle for recovery");
        let error = recover_owner_events_lifecycle_or_reject(&recovered_guard, state_dir.path())
            .expect_err("recovered teardown must reject stale request");
        assert!(error.contains("recovered an interrupted teardown"));
        assert!(!state_dir.path().join("household").exists());
        assert!(!state_dir.path().join("household.tearing-down").exists());
    }

    #[test]
    fn owner_authority_guard_blocks_same_household_teardown_until_anchor_finishes() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let state_dir = tempfile::tempdir().expect("state dir");
        let _identity = bootstrap_lifecycle_test_identity(state_dir.path());
        let owner_guard = acquire_owner_events_lifecycle_exclusive_blocking(state_dir.path())
            .expect("owner mutation lifecycle");
        let anchor_finished = Arc::new(AtomicBool::new(false));
        let contender_saw_anchor = Arc::clone(&anchor_finished);
        let contender_path = state_dir.path().to_path_buf();
        let (attempting_tx, attempting_rx) = std::sync::mpsc::channel();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let contender = std::thread::spawn(move || {
            let lifecycle = HouseholdLifecycleLock::open_verified(&contender_path)
                .expect("open teardown contender lifecycle");
            attempting_tx.send(()).expect("signal contender attempt");
            let _teardown_guard = lifecycle
                .lock_exclusive()
                .expect("teardown contender acquires after owner mutation");
            acquired_tx
                .send(contender_saw_anchor.load(Ordering::Acquire))
                .expect("signal contender acquisition");
        });

        attempting_rx.recv().expect("contender started");
        assert!(
            acquired_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "same-household teardown must not enter before the anchor side effect"
        );
        // Model the last authority-coupled anchor/marker side effect while the
        // finish handler still owns the lifecycle guard.
        anchor_finished.store(true, Ordering::Release);
        drop(owner_guard);
        assert!(
            acquired_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("teardown enters after guard drop"),
            "teardown observed acquisition before the anchor side effect"
        );
        contender.join().expect("teardown contender");
    }

    #[test]
    fn every_owner_authority_finish_uses_the_lifecycle_commit_helper() {
        let source = include_str!("handlers_owner_events.rs");
        let production = source
            .split_once("#[cfg(test)]")
            .expect("owner-events test module boundary")
            .0;
        assert_eq!(
            production
                .matches("persist_owner_auth_under_lifecycle(&state, &identity, &next_auth).await")
                .count(),
            6,
            "all six owner-authority finish handlers must share the exact lifecycle commit path"
        );
        assert_eq!(
            production.matches("drop(owner_lifecycle_guard)").count(),
            6,
            "each finish handler must retain and explicitly release its lifecycle guard"
        );
    }

    #[test]
    fn post_ack_commit_holds_lifecycle_through_reload_and_window_publication() {
        let source = include_str!("handlers_owner_events.rs");
        // Bound the search to production text before searching for anything.
        // `include_str!` makes this test part of its own haystack: unbounded,
        // every marker below is found inside this function's own literals, in
        // the order they are written here, and the assertions pass against an
        // empty handler.
        let production = source
            .split_once("#[cfg(test)]")
            .expect("owner-events test module boundary")
            .0;
        let anchor = "From this point forward M2 has returned the exact manifest-bound Ack";
        assert_eq!(
            production.matches(anchor).count(),
            1,
            "post-ACK window anchor must exist exactly once in production text"
        );
        let commit_window = production
            .split_once(anchor)
            .expect("post-ACK lifecycle commit window")
            .1;
        let ordered = [
            "BOOTSTRAP_MUTATION_LOCK",
            "acquire_owner_events_lifecycle_exclusive",
            "verify_installed_identity_under_lifecycle",
            "try_load_existing_under_lifecycle",
            "set_loaded",
            "under_lifecycle(&post_ack_lifecycle_guard)",
            "enter_committed",
            "drop(post_ack_mutation_guard)",
        ];
        let mut remainder = commit_window;
        for marker in ordered {
            let (_, after) = remainder
                .split_once(marker)
                .unwrap_or_else(|| panic!("missing or out-of-order post-ACK marker: {marker}"));
            remainder = after;
        }
        // Ordering is not the property that matters here. The window commit
        // must RECEIVE the guard acquired above; the reacquiring variant
        // (`enter_committed` on the bare window) takes a shared lock on the
        // lifecycle file this task already holds exclusively, blocks against
        // itself for CURRENT_LOCK_TIMEOUT, and returns 500 over a commit that
        // is already durable on disk.
        let commit_call = commit_window
            .find(".enter_committed(")
            .expect("post-ACK window commit call");
        let guarded = commit_window
            .find(".under_lifecycle(&post_ack_lifecycle_guard)")
            .expect("post-ACK window commit must reuse the retained lifecycle guard");
        assert!(
            guarded < commit_call && commit_call - guarded < 80,
            "post-ACK enter_committed must be chained onto the retained guard, never reacquire it"
        );
    }

    fn household_id() -> HouseholdId {
        HouseholdId::parse(format!("hh_{}", "a".repeat(52))).unwrap()
    }

    fn machine_id() -> MachineId {
        MachineId::parse(format!("m_{}", "b".repeat(52))).unwrap()
    }

    fn owner_person_id() -> PersonId {
        PersonId("p_owner-alpha".to_string())
    }

    #[test]
    fn candidate_tailnet_hint_requires_cgnat_and_signed_join_port() {
        assert_eq!(
            validated_candidate_tailnet_addr(Some("100.64.0.10:8091"), "192.0.2.10:8091"),
            Some("100.64.0.10:8091".to_string())
        );
        assert_eq!(
            validated_candidate_tailnet_addr(Some("100.64.0.10:9091"), "192.0.2.10:8091"),
            None
        );
        assert_eq!(
            validated_candidate_tailnet_addr(Some("192.0.2.20:8091"), "192.0.2.10:8091"),
            None
        );
        assert_eq!(
            validated_candidate_tailnet_addr(None, "192.0.2.10:8091"),
            None
        );
    }

    #[test]
    fn founder_tailnet_hint_uses_resolved_ip_and_household_port() {
        fn resolver() -> Option<Ipv4Addr> {
            Some(Ipv4Addr::new(100, 64, 0, 10))
        }

        assert_eq!(
            build_founder_tailnet_addr(9_091, resolver).as_deref(),
            Some("100.64.0.10:9091")
        );
    }

    #[test]
    fn founder_tailnet_hint_is_absent_when_resolver_has_no_address() {
        fn resolver() -> Option<Ipv4Addr> {
            None
        }

        assert!(build_founder_tailnet_addr(9_091, resolver).is_none());
    }

    fn approval_context(join_request_bytes: &[u8]) -> OwnerApprovalContextV2 {
        OwnerApprovalContextV2::pair_machine_approve(PairMachineApprovalContextInput {
            hh_id: household_id(),
            owner_p_id: owner_person_id(),
            cursor: 7,
            m_id: machine_id(),
            addr: "192.0.2.10:8091".to_string(),
            transport: JoinTransport::Lan,
            ttl_unix: 1_800,
            nonce: [0x11; 32],
            join_request_hash: join_request_hash(join_request_bytes),
            capabilities: vec!["machine-cert".to_string(), "shamir-2pc".to_string()],
            issued_at: 1_000,
            expires_at: 1_120,
            replay_nonce: [0x22; 32],
        })
    }

    fn live_snapshot(join_request_bytes: &[u8]) -> PairMachineWindowSnapshot {
        PairMachineWindowSnapshot {
            version: PAIR_MACHINE_VERSION,
            state: PairMachineState::AwaitingOwner,
            m_pub: Some(ByteBuf::from(vec![0x03; 33])),
            nonce: Some(ByteBuf::from(vec![0x11; 32])),
            expiry: Some(1_800),
            transport: Some(JoinTransport::Lan),
            addr_hint: Some("192.0.2.10:8091".to_string()),
            fingerprint: Some("fp-neutral".to_string()),
            owner_event_cursor: Some(7),
            cached_join_request: Some(ByteBuf::from(join_request_bytes.to_vec())),
            cached_response: None,
            anchor_secret: None,
            pinned_hh_pub: None,
            pinned_hh_id: None,
            approval_claim: None,
            lifecycle_generation: None,
        }
    }

    #[test]
    fn owner_approval_policy_is_per_operation_and_default_off() {
        let policy = OwnerApprovalEnforcementPolicy::default();
        assert_eq!(
            policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::NeverEnrolled),
            PairMachineApprovalBodyMode::LegacyV1
        );
        assert_eq!(
            policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::Active { count: 1 }),
            PairMachineApprovalBodyMode::LegacyV1
        );
        assert_eq!(
            policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::RecoveryRequired),
            PairMachineApprovalBodyMode::LegacyV1
        );
        assert_eq!(
            policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::AnchorInvalid),
            PairMachineApprovalBodyMode::LegacyV1
        );
        assert_eq!(
            policy.bootstrap_initialize,
            OwnerOperationEnforcement::LegacyOnly
        );
        assert_eq!(
            policy.bootstrap_teardown,
            OwnerOperationEnforcement::LegacyOnly
        );
        assert_eq!(
            policy.pair_device_confirm,
            OwnerOperationEnforcement::LegacyOnly
        );
        assert_eq!(
            policy.revoke_credential,
            OwnerOperationEnforcement::LegacyOnly
        );
        assert_eq!(policy.recovery_code, RecoveryCodeEnforcement::Disabled);
        assert_eq!(policy.add_credential, OwnerOperationEnforcement::LegacyOnly);
    }

    #[test]
    fn owner_auth_v2_rollout_absent_and_rollback_values_are_legacy_only() {
        for value in [
            None,
            Some(""),
            Some("off"),
            Some("legacy"),
            Some("legacy-only"),
        ] {
            assert_eq!(
                owner_approval_policy_from_rollout_value(value),
                OwnerApprovalEnforcementPolicy::default()
            );
        }
    }

    #[test]
    fn owner_auth_v2_rollout_reviewed_core_enables_only_reviewed_operations() {
        let policy =
            owner_approval_policy_from_rollout_value(Some(OWNER_AUTH_V2_REVIEWED_CORE_ROLLOUT));

        assert_eq!(
            policy.pair_machine_approve,
            OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential
        );
        assert_eq!(
            policy.revoke_credential,
            OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential
        );
        assert_eq!(
            policy.recovery_code,
            RecoveryCodeEnforcement::BreakGlassEnabled,
            "recovery uses the break-glass policy switch, not an active-count gate"
        );
        assert_eq!(
            policy.add_credential,
            OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential
        );
        assert_eq!(
            policy.bootstrap_initialize,
            OwnerOperationEnforcement::LegacyOnly
        );
        assert_eq!(
            policy.bootstrap_teardown,
            OwnerOperationEnforcement::LegacyOnly
        );
        assert_eq!(
            policy.pair_device_confirm,
            OwnerOperationEnforcement::LegacyOnly
        );
    }

    #[test]
    fn owner_auth_v2_rollout_unknown_value_fails_closed() {
        assert_eq!(
            owner_approval_policy_from_rollout_value(Some("1")),
            OwnerApprovalEnforcementPolicy::default()
        );
        assert_eq!(
            owner_approval_policy_from_rollout_value(Some("reviewed-core-v2 ")),
            OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout(),
            "operator whitespace should not disable an otherwise explicit value"
        );
    }

    #[test]
    fn pair_machine_v2_policy_requires_active_owner_passkey_before_requiring_v2() {
        let policy = OwnerApprovalEnforcementPolicy::default()
            .with_pair_machine_approve(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);

        assert_eq!(
            policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::NeverEnrolled),
            PairMachineApprovalBodyMode::LegacyV1,
            "owners who never enrolled passkeys keep the legacy path during migration"
        );
        assert_eq!(
            policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::Active { count: 1 }),
            PairMachineApprovalBodyMode::RequireV2
        );
        assert_eq!(
            policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::RecoveryRequired),
            PairMachineApprovalBodyMode::RejectFailClosed,
            "zero active credentials after prior enrollment must not downgrade to legacy"
        );
        assert_eq!(
            policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::AnchorInvalid),
            PairMachineApprovalBodyMode::RejectFailClosed,
            "anchor failures must not downgrade to legacy"
        );
    }

    #[test]
    fn pair_machine_reassertion_accepts_unchanged_live_window() {
        let join_request_bytes = b"neutral canonical join request";
        let context = approval_context(join_request_bytes);
        let snapshot = live_snapshot(join_request_bytes);

        reassert_pair_machine_approval_context_against_live_window(&context, &snapshot).unwrap();
    }

    #[test]
    fn pair_machine_reassertion_rejects_window_changed_after_approval() {
        let join_request_bytes = b"neutral canonical join request";
        let context = approval_context(join_request_bytes);
        let mut snapshot = live_snapshot(join_request_bytes);
        snapshot.cached_join_request = Some(ByteBuf::from(b"mutated join request".to_vec()));

        let err = reassert_pair_machine_approval_context_against_live_window(&context, &snapshot)
            .unwrap_err();
        assert!(matches!(
            err,
            OwnerApprovalV2Error::TrustedState("live join request changed")
        ));
    }

    #[test]
    fn pair_machine_reassertion_rejects_cursor_or_state_change_after_approval() {
        let join_request_bytes = b"neutral canonical join request";
        let context = approval_context(join_request_bytes);
        let mut snapshot = live_snapshot(join_request_bytes);
        snapshot.owner_event_cursor = Some(8);

        let err = reassert_pair_machine_approval_context_against_live_window(&context, &snapshot)
            .unwrap_err();
        assert!(matches!(
            err,
            OwnerApprovalV2Error::TrustedState("live window cursor changed")
        ));

        let mut snapshot = live_snapshot(join_request_bytes);
        snapshot.state = PairMachineState::Committed;
        let err = reassert_pair_machine_approval_context_against_live_window(&context, &snapshot)
            .unwrap_err();
        assert!(matches!(
            err,
            OwnerApprovalV2Error::TrustedState("live window cursor changed")
        ));
    }

    #[test]
    fn pair_machine_reassertion_rejects_claimed_window() {
        let join_request_bytes = b"neutral canonical join request";
        let context = approval_context(join_request_bytes);
        let mut snapshot = live_snapshot(join_request_bytes);
        snapshot.approval_claim = Some(PairMachineApprovalClaim {
            claim_id: ByteBuf::from(vec![0xA5; 32]),
            owner_event_cursor: 7,
            claimed_at: 1_700,
        });

        let err = reassert_pair_machine_approval_context_against_live_window(&context, &snapshot)
            .unwrap_err();
        assert!(matches!(
            err,
            OwnerApprovalV2Error::TrustedState("live window already claimed")
        ));
    }
}
