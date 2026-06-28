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
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Extension, Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::caveats::Operation;
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
use crate::time_util;

const CBOR_CONTENT_TYPE: &str = "application/cbor";
const OWNER_EVENTS_LONG_POLL_TIMEOUT: Duration = Duration::from_secs(45);
pub const OWNER_AUTH_V2_ROLLOUT_ENV: &str = "THEYOS_OWNER_AUTH_V2_ROLLOUT";
pub const OWNER_AUTH_V2_REVIEWED_CORE_ROLLOUT: &str = "reviewed-core-v2";

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
}

#[derive(Clone)]
pub struct OwnerWebauthnAnchorVerifier {
    pub keystore: Arc<dyn keystore_rs::KeystoreBackend>,
}

#[derive(Clone)]
pub struct OwnerWebauthnRecoveryAnchorVerifier {
    pub keystore: Arc<dyn keystore_rs::KeystoreBackend>,
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
}

pub const OWNER_WEBAUTHN_REGISTRATION_LOCAL_START_PATH: &str =
    "/api/v1/household/owner-webauthn/registration/local/start";
pub const OWNER_WEBAUTHN_REGISTRATION_LOCAL_FINISH_PATH: &str =
    "/api/v1/household/owner-webauthn/registration/local/finish";
pub const OWNER_WEBAUTHN_REGISTRATION_LOCAL_STATUS_PATH: &str =
    "/api/v1/household/owner-webauthn/registration/local/status";

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
        Some(_) => {
            tracing::warn!(
                env = OWNER_AUTH_V2_ROLLOUT_ENV,
                "unknown owner-auth v2 rollout value; keeping LegacyOnly policy"
            );
            OwnerApprovalEnforcementPolicy::default()
        }
    }
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
    DefiniteFailure(CeremonyError),
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
        return owner_events_since_response(&state, since);
    }

    let mut subscription = state.event_broadcaster.subscribe();

    // Close the race where an append lands after the initial head check but
    // before this request subscribes to the broadcaster.
    if state.event_log.cursor_head() > since {
        return owner_events_since_response(&state, since);
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
                        return owner_events_since_response(&state, since);
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) => {
                        if state.event_log.cursor_head() > since {
                            return owner_events_since_response(&state, since);
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

fn owner_events_since_response(state: &OwnerEventsRouterState, since: u64) -> Response {
    let events = match state.event_log.read_since(since) {
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

    if let Err(e) = next_auth.save(&state.state_dir) {
        return reject_owner_webauthn_revoke_credential_finish(
            "authority_save_failed",
            Some(e.to_string()),
        );
    }
    state
        .household
        .set_owner_auth(Arc::new(next_auth.clone()))
        .await;
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

    if let Err(e) = next_auth.save(&state.state_dir) {
        return reject_owner_webauthn_add_credential_finish(
            "add_credential_authority_save_failed",
            Some(e.to_string()),
        );
    }
    state
        .household
        .set_owner_auth(Arc::new(next_auth.clone()))
        .await;
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

    if let Err(e) = next_auth.save(&state.state_dir) {
        return reject_owner_webauthn_recovery(
            "recovery_consume_authority_save_failed",
            Some(e.to_string()),
        );
    }
    state
        .household
        .set_owner_auth(Arc::new(next_auth.clone()))
        .await;
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

    if let Err(e) = next_auth.save(&state.state_dir) {
        return reject_owner_webauthn_recovery("authority_save_failed", Some(e.to_string()));
    }
    state
        .household
        .set_owner_auth(Arc::new(next_auth.clone()))
        .await;
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
    let snapshot = owner_webauthn_initial_enrollment_policy_snapshot(
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
    if let Err(e) = next_auth.save(&state.state_dir) {
        return reject_owner_webauthn_registration("authority_save_failed", Some(e.to_string()));
    }
    // Keep in-memory owner auth aligned with the durable commit before any
    // post-save anchor failure can return. A retry must see the committed
    // credential and fail closed instead of re-enrolling against stale memory.
    state
        .household
        .set_owner_auth(Arc::new(next_auth.clone()))
        .await;
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
    let txn = match CeremonyTxn::prepare(CeremonyInputs {
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
    drop(mutation_guard);
    let addr = window_data
        .snapshot
        .addr_hint
        .clone()
        .unwrap_or_else(|| window_data.join_request.addr.clone());
    // T073: persist the JoinResponse bytes we are about to POST so
    // boot-time `recover_phase3_ceremony` can re-POST them after a
    // crash. `HH_priv` is destroyed during commit, so the
    // encrypted-shard-for-M2 inside `JoinResponse` cannot be
    // reconstructed post-crash. Build the response here using the same
    // options finalize_with_m2 will use.
    let cached_join_request_bytes = window_data.cached_join_request.to_vec();
    let pending_response_bytes = {
        let opts_for_build = FinalizeWithM2Options {
            addr: &addr,
            join_request_cbor: &cached_join_request_bytes,
            founder_cert: &identity.cert,
            founder_tailscale_addr: None,
            push_token_seed: push_token_seed.clone(),
            response_signer: identity.m_priv.as_ref(),
        };
        match txn.build_join_response(&opts_for_build) {
            Ok(jr) => match jr.to_canonical_bytes() {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(
                        stage = "owner_events.approve.rejected",
                        reason = "join_response_canonical_encode_failed",
                        error = %e,
                    );
                    let _ =
                        household_rs::storage::clear_phase3_finalize_ack_marker(&state.state_dir);
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
            },
            Err(e) => {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "join_response_build_failed",
                    error = %e,
                );
                let _ = household_rs::storage::clear_phase3_finalize_ack_marker(&state.state_dir);
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
    };
    if let Err(e) = household_rs::storage::write_phase3_pending_join_response(
        &state.state_dir,
        &pending_response_bytes,
    ) {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "phase3_pending_join_response_write_failed",
            error = %e,
            hint = "refusing to launch finalize_with_m2 without durable JoinResponse copy",
        );
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
    // R7.2/R7.3: write the recovery-driver intent pin BEFORE invoking
    // `finalize_with_m2`. The marker says "M1 has launched a join
    // ceremony with this candidate; if the boot path observes a
    // pre-Shamir record AND this marker is durable, recovery MUST
    // preserve `.staged` and dispatch T073/T074's two-state probe
    // instead of rolling back". Writing it AFTER `finalize_with_m2`
    // (the previous R6.1 placement) leaves two split-brain windows:
    //   (a) crash between `finalize_with_m2 Ok` and the marker
    //       fsync+rename becoming durable;
    //   (b) FinalizeAck network response lost in flight (M2's
    //       `staged.commit()` Ok'd, packet dropped) — the Err arm
    //       below would have returned 401 with no marker on disk.
    // Both leave M2 committed, M1 rolled back.
    //
    // The pending JoinResponse is durable before the marker, so a boot
    // that observes the marker also has the bytes needed to re-POST
    // finalize. A crash before this marker leaves only ordinary staged
    // files; boot-time recovery rolls them back and reload clears the
    // owner-approval claim as stale.
    let candidate_m_id_str = txn.candidate_cert().m_id.to_string();
    if let Err(e) = household_rs::storage::write_phase3_finalize_ack_marker(
        &state.state_dir,
        &candidate_m_id_str,
    ) {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "phase3_finalize_ack_marker_write_failed",
            error = %e,
            hint = "refusing to launch finalize_with_m2 without durable intent pin",
        );
        // The txn has not contacted M2 yet; explicit rollback unlinks
        // the staged set cleanly with no residue.
        let _ = household_rs::storage::clear_phase3_pending_join_response(&state.state_dir);
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
    let identity_for_finalize = Arc::clone(&identity);
    let finalized = tokio::task::spawn_blocking(move || {
        let finalize_opts = FinalizeWithM2Options {
            addr: &addr,
            join_request_cbor: &cached_join_request_bytes,
            founder_cert: &identity_for_finalize.cert,
            founder_tailscale_addr: None,
            push_token_seed,
            response_signer: identity_for_finalize.m_priv.as_ref(),
        };
        match txn.finalize_with_m2(&finalize_opts) {
            Ok(outcome) => FinalizeAttempt::Acked(Box::new(txn), Box::new(outcome)),
            Err(e) if e.is_ambiguous_finalize_outcome() => {
                txn.preserve_staged_for_recovery();
                FinalizeAttempt::AmbiguousFailure(e)
            }
            Err(e) => {
                txn.rollback();
                FinalizeAttempt::DefiniteFailure(e)
            }
        }
    })
    .await;
    let (txn, finalize) = match finalized {
        Ok(FinalizeAttempt::Acked(txn, outcome)) => (*txn, *outcome),
        Ok(FinalizeAttempt::DefiniteFailure(e)) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "m2_finalize_failed",
                error = %e,
            );
            // The blocking task already rolled back the M1 staged set.
            // This arm is only for a definitive local/build error or a
            // generic 401-style reject from M2 before it returned an ack.
            if let Err(clear_err) =
                household_rs::storage::clear_phase3_finalize_ack_marker(&state.state_dir)
            {
                tracing::warn!(
                    stage = "owner_events.approve.finalize_ack_marker_clear_failed",
                    reason = "after_finalize_with_m2_err",
                    error = %clear_err,
                );
            }
            if let Err(clear_err) =
                household_rs::storage::clear_phase3_pending_join_response(&state.state_dir)
            {
                tracing::warn!(
                    stage = "owner_events.approve.pending_join_response_clear_failed",
                    reason = "after_finalize_with_m2_err",
                    error = %clear_err,
                );
            }
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
            // Unknown outcome: keep the marker. If the blocking task
            // panicked before preserving the staged set, recovery may
            // have less evidence than desired, but clearing the marker
            // here would make a possible M2 commit strictly worse.
            return internal_error_response();
        }
    };
    let candidate_cert = txn.candidate_cert().clone();
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
    // From this point forward, M2 has already returned `FinalizeAck` and
    // therefore committed cert+shard+record on its side. We must NOT
    // rollback or surface `unauthenticated` for failures past this line —
    // that would create a split-brain (M2 committed, M1 not). Instead we
    // log at ERROR + return `internal_error_response` (500) and rely on
    // three safeguards:
    //   1. `.staged` files left on disk by `CeremonyTxn::prepare` MUST
    //      survive the failure. R7.1: `commit_preserve_on_error()` is
    //      the variant that disarms `StagedCommit::Drop`'s automatic
    //      `.staged` cleanup on commit error. The plain `commit()`
    //      would have unlinked them via the destructor, defeating
    //      recovery.
    //   2. The `phase3_finalize_ack.marker` file written BEFORE
    //      `finalize_with_m2` (R7.2/R7.3) pins the "in-flight ceremony"
    //      state on disk. Boot-time `recover_partial_phase3_commit`
    //      checks for it and refuses to roll back the `.staged` set
    //      even when the on-disk record is still pre-Shamir.
    //   3. `commit_preserve_on_error`'s post-promote cleanup primitives
    //      (keystore destroy, sole-shard unlink) are idempotent, so
    //      retrying them on next boot is safe.
    // T073/T074 will add the explicit `recover_phase3_ceremony` boot path
    // that drives these to completion (see `contracts/shamir-transition.md`
    // §"Recovery on M1 boot"). Until then the marker + staged files remain
    // and an operator can hand-finish via the existing primitives. The 500
    // wire surface is contracted in `contracts/owner-events.md`.
    // T064: post-rename hook synchronously consults the
    // failure-injection registry between staged.commit (step 12) and
    // sole-shard unlink + keystore destroy (step 13). Production
    // builds compile this hook to a constant `Continue` (the
    // closure body is `cfg`-gated; the closure itself is always
    // passed but is a no-op when the feature is off).
    let post_rename_hook = || -> household_rs::pair_machine::PostRenameHookOutcome {
        #[cfg(any(test, feature = "failure-injection"))]
        {
            match crate::failure_injection::apply_sync(
                crate::failure_injection::InjectionPoint::M1AfterStagedRename,
            ) {
                crate::failure_injection::Outcome::EarlyReject(msg) => {
                    return household_rs::pair_machine::PostRenameHookOutcome::EarlyReject(msg);
                }
                crate::failure_injection::Outcome::Skip
                | crate::failure_injection::Outcome::Continue => {}
            }
        }
        household_rs::pair_machine::PostRenameHookOutcome::Continue
    };
    if let Err(e) = txn.commit_preserve_on_error_with_hook(post_rename_hook) {
        tracing::error!(
            stage = "owner_events.approve.partially_committed",
            reason = "m1_commit_failed_after_m2_ack",
            error = %e,
            hint = "M2 acked; sole-shard + .staged + finalize intent marker left for boot recovery",
        );
        return internal_error_response();
    }
    // T064: failure-injection crash point — fires after
    // `commit_preserve_on_error` returns Ok (staged renames + sole-shard
    // unlink + keystore destroy all done) and BEFORE the marker is
    // cleared / `OwnerEvent{type=machine-joined}` is appended. A
    // registered Panic models "M1 crash between 2PC step 13 (sole-shard
    // unlink) and step 14 (event-log append)". On reboot, M1 has a
    // post-Shamir record on disk; boot-time
    // `clear_stale_phase3_marker_if_post_shamir` removes the marker
    // and the household is fully committed. The missing
    // `machine-joined` event is reconciled by the iPhone's next
    // owner-events long-poll, which observes the post-commit state.
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
    // R6.1: ceremony fully committed — the post-Shamir record is durable
    // on disk, so boot-time recovery would correctly roll forward any
    // residual `.staged`. The marker is no longer protective; clear it
    // best-effort. R7.NB2: failures here are also covered by
    // `recover_partial_phase3_commit`'s unconditional post-Shamir clear,
    // so the marker is guaranteed to be cleaned up on next boot.
    if let Err(e) = household_rs::storage::clear_phase3_finalize_ack_marker(&state.state_dir) {
        tracing::warn!(
            stage = "owner_events.approve.finalize_ack_marker_clear_failed",
            error = %e,
            hint = "post-Shamir record on disk; boot-time recovery clears the marker on next start",
        );
    }
    if let Err(e) = household_rs::storage::clear_phase3_pending_join_response(&state.state_dir) {
        tracing::warn!(
            stage = "owner_events.approve.pending_join_response_clear_failed",
            error = %e,
            hint = "post-Shamir record on disk; boot-time recovery clears the pending JoinResponse on next start",
        );
    }
    // Reload `LoadedIdentity` from disk: the on-disk record now has
    // `shamir_n=2` and the keystore custody of HH_priv has been
    // destroyed. `try_load_existing` will deliver `hh_priv: None`.
    // Swap it into the shared `HouseholdState` so subsequent requests
    // see the post-Shamir household and `founder_stage_join_request`'s
    // `shamir_n == 1` gate refuses any further add-machine attempts on
    // the now-stale single-machine path. (B6.)
    match household_rs::try_load_existing(&state.state_dir, state.key_backing_policy) {
        Ok(Some(reloaded)) => {
            state.household.set_loaded(Arc::new(reloaded)).await;
        }
        Ok(None) | Err(_) => {
            // The reload should never fail post-commit (we just wrote
            // those files). Log and continue — the next handler that
            // observes the stale `HouseholdState` will fail closed via
            // its own gates. We do NOT return an error here because the
            // ceremony itself succeeded.
            tracing::error!(
                stage = "owner_events.approve.identity_reload_failed",
                hint = "post-commit identity unavailable; next request will refresh from disk on the slow path",
            );
        }
    }
    if let Err(e) = state
        .window
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
    if let Err(e) = state.event_log.append(
        &identity.cert.m_id.to_string(),
        identity.m_priv.as_ref(),
        OwnerEventType::MachineJoined,
        OwnerEventPayload::MachineJoined(MachineJoinedPayload {
            m_pub: ByteBuf::from(candidate_cert.m_pub.as_bytes().to_vec()),
            m_id: candidate_cert.m_id.to_string(),
            hostname: candidate_cert.hostname.clone(),
            joined_at: candidate_cert.joined_at,
        }),
    ) {
        // The household is committed; only the audit-log append failed.
        // Return 500 so the iPhone knows the ceremony succeeded but the
        // event-log signal was lost — the next long-poll observes the
        // post-commit state (membership=2) and reconciles.
        tracing::error!(
            stage = "owner_events.approve.event_append_failed",
            reason = "machine_joined_event_append_failed_after_commit",
            error = %e,
        );
        return internal_error_response();
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
    let event = state.event_log.append(
        &identity.cert.m_id.to_string(),
        identity.m_priv.as_ref(),
        OwnerEventType::JoinCancelled,
        OwnerEventPayload::JoinCancelled(JoinCancelledPayload {
            m_pub: m_pub.clone(),
            reason: "declined".into(),
        }),
    );
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
    identity: &household_rs::LoadedIdentity,
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
    match state.event_log.append(
        &identity.cert.m_id.to_string(),
        identity.m_priv.as_ref(),
        OwnerEventType::JoinCancelled,
        OwnerEventPayload::JoinCancelled(JoinCancelledPayload {
            m_pub,
            reason: reason.into(),
        }),
    ) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::ids::{HouseholdId, MachineId};
    use household_rs::machine_cert::PersonId;
    use household_rs::owner_approval_v2::PairMachineApprovalContextInput;
    use household_rs::pair_machine::{
        JoinTransport, PAIR_MACHINE_VERSION, PairMachineApprovalClaim,
    };

    fn household_id() -> HouseholdId {
        HouseholdId::parse(format!("hh_{}", "a".repeat(52))).unwrap()
    }

    fn machine_id() -> MachineId {
        MachineId::parse(format!("m_{}", "b".repeat(52))).unwrap()
    }

    fn owner_person_id() -> PersonId {
        PersonId("p_owner-alpha".to_string())
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
