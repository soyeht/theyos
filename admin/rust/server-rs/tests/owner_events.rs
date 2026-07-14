//! T049 integration coverage for
//! `GET /api/v1/household/owner-events?since=<cursor>`.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{
    Router,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::caveats::{Operation, permits};
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::machine_cert::Platform;
use household_rs::owner_approval_v2::{OwnerApprovalContextV2, OwnerApprovalV2, OwnerOperation};
use household_rs::owner_events::{
    JoinRequestPayload, OwnerEvent, OwnerEventLog, OwnerEventPayload, OwnerEventType,
    OwnerEventsBroadcaster,
};
use household_rs::owner_webauthn::{
    OwnerWebauthnConfig, OwnerWebauthnCredential, OwnerWebauthnRegistrationBinding, OwnerWebauthnRp,
};
use household_rs::owner_webauthn_anchor::{
    OwnerWebauthnAnchorMode, OwnerWebauthnAuthorityAnchor, OwnerWebauthnAuthorityHead,
    read_owner_webauthn_authority_anchor, verified_owner_webauthn_authority_head,
    verify_or_update_owner_webauthn_authority_anchor, write_owner_webauthn_authority_anchor,
};
use household_rs::owner_webauthn_authority::{
    OwnerWebauthnAuthority, OwnerWebauthnCredentialEventAction, OwnerWebauthnEventActor,
};
use household_rs::owner_webauthn_recovery::{
    OwnerWebauthnRecoveryEventAction, verified_owner_webauthn_recovery_head,
};
use household_rs::owner_webauthn_recovery_anchor::{
    classify_owner_webauthn_recovery_anchor_read_only, read_owner_webauthn_recovery_anchor,
};
use household_rs::pair_machine::{
    JoinTransport, OwnerApproval, OwnerApprovalContext, PairMachineState, PairMachineWindow,
    PrepareCandidateOpts, household_root_sole_path, machine_cert_hash, prepare_candidate,
    shamir_self_shard_path,
};
use household_rs::person_cert::{PersonCert, SignOwnerOptions, VerifiedOwnerProvenance};
use household_rs::pop::RequestSigningContext;
use household_rs::secure_upgrade::{
    SecureUpgradePlatform, SecureUpgradeProofEnvironment, SecureUpgradeTranscript,
};
use household_rs::storage::{
    household_record_path, machine_cert_for, phase3_finalize_ack_marker_exists, staged_path_for,
};
use household_rs::{BootstrapOpts, HouseholdAuthState, KeyBackingPolicy};
use keystore_rs::{FileKeystore, KeystoreBackend, KeystoreError};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use server_rs::apns_dispatcher::{APNS_TICKLE_BODY, ApnsError, ApnsTransport, install_transport};
use server_rs::handlers_owner_events::{
    self, OwnerApprovalEnforcementPolicy, OwnerEventsRouterState, OwnerOperationEnforcement,
    RecoveryCodeEnforcement, SecureUpgradeEnforcement, SecureUpgradeRuntimeConfig,
};
use server_rs::handlers_pair_machine::{PreHouseholdRouterState, pre_household_router};
use server_rs::household_state::HouseholdState;
use server_rs::macos_local_caller_auth::{
    MacosLocalAppProfile, MacosLocalCallerAuth, MacosLocalCallerAuthError,
    MacosLocalCallerAuthRequest, MacosLocalPeer, SOYEHT_MACOS_DEV_BUNDLE_ID,
    SOYEHT_MACOS_PROD_BUNDLE_ID,
};
use server_rs::macos_local_registration_listener::MacosLocalPeerConnectInfo;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tower::ServiceExt;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{
    AttestationFormat, AuthenticatorAttachment, CreationChallengeResponse, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, Url, Uuid,
};
use webauthn_rs_core::proto::{AttestationConveyancePreference, UserVerificationPolicy};

const OWNER_EVENTS_PATH: &str = "/api/v1/household/owner-events";

type OwnerEventsRouterFixture = (
    TempDir,
    Router,
    Arc<OwnerEventLog>,
    OwnerEventsBroadcaster,
    P256Keypair,
    Arc<household_rs::LoadedIdentity>,
    Arc<PairMachineWindow>,
);

type OwnerEventsRouterFixtureWithState = (
    TempDir,
    Router,
    Arc<OwnerEventLog>,
    OwnerEventsBroadcaster,
    P256Keypair,
    Arc<household_rs::LoadedIdentity>,
    Arc<PairMachineWindow>,
    OwnerEventsRouterState,
);

type V2OwnerRouterFixture = (
    TempDir,
    Router,
    Arc<OwnerEventLog>,
    OwnerEventsBroadcaster,
    P256Keypair,
    Arc<household_rs::LoadedIdentity>,
    Arc<PairMachineWindow>,
    WebauthnAuthenticator<SoftPasskey>,
);

type V2OwnerRouterFixtureWithState = (
    TempDir,
    Router,
    Arc<OwnerEventLog>,
    OwnerEventsBroadcaster,
    P256Keypair,
    Arc<household_rs::LoadedIdentity>,
    Arc<PairMachineWindow>,
    WebauthnAuthenticator<SoftPasskey>,
    OwnerEventsRouterState,
);

type OwnerWebauthnRegistrationRouterFixture = (
    TempDir,
    Router,
    Arc<OwnerEventLog>,
    OwnerEventsBroadcaster,
    P256Keypair,
    Arc<household_rs::LoadedIdentity>,
    Arc<PairMachineWindow>,
    Arc<dyn keystore_rs::KeystoreBackend>,
);

type OwnerWebauthnDualRegistrationRouterFixture = (
    TempDir,
    Router,
    Router,
    Arc<OwnerEventLog>,
    OwnerEventsBroadcaster,
    P256Keypair,
    Arc<household_rs::LoadedIdentity>,
    Arc<PairMachineWindow>,
    Arc<dyn keystore_rs::KeystoreBackend>,
);

#[derive(Debug)]
struct TestMacosLocalCallerAuth {
    allow: bool,
}

impl TestMacosLocalCallerAuth {
    fn allow() -> Arc<dyn MacosLocalCallerAuth> {
        Arc::new(Self { allow: true })
    }

    fn deny() -> Arc<dyn MacosLocalCallerAuth> {
        Arc::new(Self { allow: false })
    }
}

impl MacosLocalCallerAuth for TestMacosLocalCallerAuth {
    fn authorize(
        &self,
        request: &MacosLocalCallerAuthRequest<'_>,
    ) -> Result<(), MacosLocalCallerAuthError> {
        assert_eq!(request.peer.audit_token_words()[0], 0x51);
        if self.allow {
            Ok(())
        } else {
            Err(MacosLocalCallerAuthError::Rejected)
        }
    }
}

fn test_macos_local_peer() -> MacosLocalPeerConnectInfo {
    MacosLocalPeerConnectInfo::from_peer(MacosLocalPeer::from_audit_token_words([
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    ]))
}

type OwnerWebauthnRecoveryRouterFixture = (
    TempDir,
    Router,
    Arc<OwnerEventLog>,
    OwnerEventsBroadcaster,
    P256Keypair,
    Arc<household_rs::LoadedIdentity>,
    Arc<PairMachineWindow>,
    Arc<dyn keystore_rs::KeystoreBackend>,
    Arc<dyn keystore_rs::KeystoreBackend>,
    WebauthnAuthenticator<SoftPasskey>,
);

type OwnerWebauthnRecoveryRouterFixtureWithState = (
    TempDir,
    Router,
    Arc<OwnerEventLog>,
    OwnerEventsBroadcaster,
    P256Keypair,
    Arc<household_rs::LoadedIdentity>,
    Arc<PairMachineWindow>,
    Arc<dyn keystore_rs::KeystoreBackend>,
    Arc<dyn keystore_rs::KeystoreBackend>,
    WebauthnAuthenticator<SoftPasskey>,
    OwnerEventsRouterState,
);

#[derive(Default)]
struct SpyTransport {
    captured: StdMutex<Vec<Vec<u8>>>,
}

impl SpyTransport {
    fn clear(&self) {
        self.captured.lock().unwrap().clear();
    }

    fn captured(&self) -> Vec<Vec<u8>> {
        self.captured.lock().unwrap().clone()
    }
}

impl ApnsTransport for SpyTransport {
    fn topic(&self) -> &'static str {
        "test.theyos.apns"
    }

    fn send<'a>(
        &'a self,
        _push_token: &'a [u8],
        body: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), ApnsError>> + Send + 'a>> {
        let captured = body.to_vec();
        Box::pin(async move {
            self.captured.lock().unwrap().push(captured);
            Ok(())
        })
    }
}

struct FailingSetKeystore {
    inner: FileKeystore,
    fail_set: AtomicBool,
}

impl FailingSetKeystore {
    fn new(state_dir: &std::path::Path) -> Self {
        Self {
            inner: FileKeystore::new(state_dir, keystore_rs::SERVICE),
            fail_set: AtomicBool::new(false),
        }
    }

    fn fail_writes(&self, fail: bool) {
        self.fail_set.store(fail, Ordering::SeqCst);
    }
}

impl KeystoreBackend for FailingSetKeystore {
    fn get(&self, account: &str) -> Result<Vec<u8>, KeystoreError> {
        self.inner.get(account)
    }

    fn set(&self, account: &str, value: &[u8]) -> Result<(), KeystoreError> {
        if self.fail_set.load(Ordering::SeqCst) {
            return Err(KeystoreError::Unavailable {
                hint: "test anchor write failure".into(),
            });
        }
        self.inner.set(account, value)
    }

    fn delete(&self, account: &str) -> Result<(), KeystoreError> {
        self.inner.delete(account)
    }
}

struct BlockingSetKeystore {
    inner: FileKeystore,
    block_next_set: AtomicBool,
    entered: AtomicUsize,
    release: StdMutex<bool>,
    release_cvar: Condvar,
}

impl BlockingSetKeystore {
    fn new(state_dir: &std::path::Path) -> Self {
        Self {
            inner: FileKeystore::new(state_dir, keystore_rs::SERVICE),
            block_next_set: AtomicBool::new(false),
            entered: AtomicUsize::new(0),
            release: StdMutex::new(false),
            release_cvar: Condvar::new(),
        }
    }

    fn block_next_write(&self) {
        self.entered.store(0, Ordering::SeqCst);
        *self.release.lock().unwrap() = false;
        self.block_next_set.store(true, Ordering::SeqCst);
    }

    async fn wait_for_blocked_write(&self) {
        while self.entered.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn release_blocked_write(&self) {
        *self.release.lock().unwrap() = true;
        self.release_cvar.notify_all();
    }
}

impl KeystoreBackend for BlockingSetKeystore {
    fn get(&self, account: &str) -> Result<Vec<u8>, KeystoreError> {
        self.inner.get(account)
    }

    fn set(&self, account: &str, value: &[u8]) -> Result<(), KeystoreError> {
        if self.block_next_set.swap(false, Ordering::SeqCst) {
            self.entered.fetch_add(1, Ordering::SeqCst);
            let mut released = self.release.lock().unwrap();
            while !*released {
                released = self.release_cvar.wait(released).unwrap();
            }
        }
        self.inner.set(account, value)
    }

    fn delete(&self, account: &str) -> Result<(), KeystoreError> {
        self.inner.delete(account)
    }
}

static SPY_TRANSPORT: OnceLock<Arc<SpyTransport>> = OnceLock::new();

fn install_spy_transport() -> Arc<SpyTransport> {
    Arc::clone(SPY_TRANSPORT.get_or_init(|| {
        let spy = Arc::new(SpyTransport::default());
        let transport: Arc<dyn ApnsTransport> = spy.clone();
        let _ = install_transport(transport);
        spy
    }))
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
struct OwnerEventsResponse {
    #[serde(rename = "v")]
    version: u8,
    events: Vec<OwnerEvent>,
    next_cursor: u64,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
struct GenericUnauth {
    #[serde(rename = "v")]
    version: u8,
    error: String,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
struct OwnerDeclineAck {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
struct OwnerApprovalAck {
    #[serde(rename = "v")]
    version: u8,
    machine_cert_hash: ByteBuf,
}

#[derive(serde::Serialize)]
struct OwnerApprovalV2StartRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Deserialize)]
struct OwnerApprovalV2StartResponse {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    context: OwnerApprovalContextV2,
    options: RequestChallengeResponse,
}

#[derive(serde::Serialize)]
struct OwnerWebauthnRevokeCredentialStartRequest {
    #[serde(rename = "v")]
    version: u8,
    target_credential_id: ByteBuf,
}

#[derive(serde::Serialize)]
struct OwnerApprovalV2FinishBody {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    approval: OwnerApprovalV2,
}

#[derive(serde::Serialize)]
struct OwnerWebauthnRegistrationStartRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Deserialize)]
struct OwnerWebauthnRegistrationStartResponse {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    options: CreationChallengeResponse,
}

#[derive(serde::Serialize)]
struct OwnerWebauthnRegistrationFinishRequest {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
struct OwnerWebauthnRegistrationFinishResponse {
    #[serde(rename = "v")]
    version: u8,
    credential_id: ByteBuf,
    active_credential_count: u64,
}

#[derive(Deserialize)]
struct OwnerWebauthnRevokeCredentialFinishResponse {
    #[serde(rename = "v")]
    version: u8,
    active_credential_count: u64,
}

#[derive(serde::Serialize)]
struct OwnerWebauthnRecoveryStartRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(serde::Serialize)]
struct OwnerWebauthnRecoveryConsumeStartRequest {
    #[serde(rename = "v")]
    version: u8,
    recovery_code: String,
}

#[derive(Deserialize)]
struct OwnerWebauthnRecoveryConsumeStartResponse {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    context: OwnerApprovalContextV2,
    options: CreationChallengeResponse,
}

#[derive(serde::Serialize)]
struct OwnerWebauthnAddCredentialStartRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Deserialize)]
struct OwnerWebauthnAddCredentialStartResponse {
    #[serde(rename = "v")]
    version: u8,
    registration: OwnerWebauthnRegistrationStartResponse,
    approval: OwnerApprovalV2StartResponse,
    context: OwnerApprovalContextV2,
}

#[derive(serde::Serialize)]
struct OwnerWebauthnAddCredentialFinishRequest {
    #[serde(rename = "v")]
    version: u8,
    context: OwnerApprovalContextV2,
    registration: OwnerWebauthnRegistrationFinishRequest,
    approval: OwnerApprovalV2FinishBody,
}

#[derive(Deserialize)]
struct OwnerWebauthnAddCredentialFinishResponse {
    #[serde(rename = "v")]
    version: u8,
    credential_id: ByteBuf,
    active_credential_count: u64,
}

#[derive(serde::Serialize)]
struct OwnerWebauthnRecoveryConsumeFinishRequest {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    context: OwnerApprovalContextV2,
    credential: RegisterPublicKeyCredential,
    recovery_code: String,
}

#[derive(Deserialize)]
struct OwnerWebauthnRecoveryConsumeFinishResponse {
    #[serde(rename = "v")]
    version: u8,
    credential_id: ByteBuf,
    active_credential_count: u64,
    recovery_ready: bool,
}

#[derive(serde::Serialize)]
struct OwnerWebauthnRecoveryStatusRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Deserialize)]
struct OwnerWebauthnRecoveryStatusResponse {
    #[serde(rename = "v")]
    version: u8,
    ready: bool,
}

#[derive(Deserialize)]
struct OwnerWebauthnRecoveryFinishResponse {
    #[serde(rename = "v")]
    version: u8,
    recovery_code: String,
    recovery_ready: bool,
}

#[derive(serde::Serialize)]
struct OwnerWebauthnRegistrationStatusRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Deserialize)]
struct OwnerWebauthnRegistrationStatusResponse {
    #[serde(rename = "v")]
    version: u8,
    enrolled: bool,
}

#[derive(serde::Serialize)]
struct TestInitialEnrollmentAnchorMarker {
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

#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
struct TestAddCredentialRegistrationBindingContext {
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

fn assert_generic_unauth(status: StatusCode, resp_bytes: &[u8]) {
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(resp_bytes).unwrap();
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.error, "unauthenticated");
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn bootstrap(state_dir: &std::path::Path) -> household_rs::LoadedIdentity {
    household_rs::bootstrap_or_load(
        state_dir,
        BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some("studio-test".into()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .unwrap()
}

fn owner_auth_for(identity: &household_rs::LoadedIdentity) -> (HouseholdAuthState, P256Keypair) {
    let person = P256Keypair::generate();
    let cert = PersonCert::sign_owner_with_verified_provenance(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv present in single-machine household"),
        SignOwnerOptions {
            hh_id: identity.record.hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: identity.record.created_at,
        },
        VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .unwrap();
    (HouseholdAuthState::new(&identity.record, cert), person)
}

fn legacy_owner_auth_for(
    identity: &household_rs::LoadedIdentity,
) -> (HouseholdAuthState, P256Keypair) {
    let person = P256Keypair::generate();
    let cert = PersonCert::sign_owner(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv present in single-machine household"),
        SignOwnerOptions {
            hh_id: identity.record.hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: identity.record.created_at,
        },
    )
    .unwrap();
    (HouseholdAuthState::new(&identity.record, cert), person)
}

fn router_from_owner_auth(
    td: TempDir,
    identity: Arc<household_rs::LoadedIdentity>,
    owner_auth: HouseholdAuthState,
    person: P256Keypair,
    timeout: Duration,
    configure: impl FnOnce(OwnerEventsRouterState) -> OwnerEventsRouterState,
) -> (
    TempDir,
    Router,
    Arc<OwnerEventLog>,
    OwnerEventsBroadcaster,
    P256Keypair,
    Arc<household_rs::LoadedIdentity>,
    Arc<PairMachineWindow>,
) {
    let (td, router, event_log, broadcaster, person, identity, window, _state) =
        router_from_owner_auth_with_router_state(
            td, identity, owner_auth, person, timeout, configure,
        );
    (td, router, event_log, broadcaster, person, identity, window)
}

fn router_from_owner_auth_with_router_state(
    td: TempDir,
    identity: Arc<household_rs::LoadedIdentity>,
    owner_auth: HouseholdAuthState,
    person: P256Keypair,
    timeout: Duration,
    configure: impl FnOnce(OwnerEventsRouterState) -> OwnerEventsRouterState,
) -> OwnerEventsRouterFixtureWithState {
    let household =
        HouseholdState::loaded_with_owner_auth(Arc::clone(&identity), Some(Arc::new(owner_auth)));
    let broadcaster = OwnerEventsBroadcaster::new();
    let event_log =
        OwnerEventLog::open_with_broadcaster(td.path().to_path_buf(), broadcaster.clone()).unwrap();
    let window = Arc::new(PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap());
    let state = OwnerEventsRouterState::with_timeout(
        household,
        Arc::clone(&window),
        Arc::clone(&event_log),
        broadcaster.clone(),
        td.path().to_path_buf(),
        household_rs::KeyBackingPolicy::ForceSoftware,
        timeout,
    );
    let state = configure(state);
    let state_for_assertion = state.clone();
    let router = Router::new()
        .route(
            OWNER_EVENTS_PATH,
            get(handlers_owner_events::owner_events_long_poll),
        )
        .route(
            "/api/v1/household/owner-webauthn/registration/start",
            post(handlers_owner_events::owner_webauthn_registration_start_handler),
        )
        .route(
            "/api/v1/household/owner-webauthn/registration/finish",
            post(handlers_owner_events::owner_webauthn_registration_finish_handler),
        )
        .route(
            "/api/v1/household/owner-webauthn/registration/status",
            post(handlers_owner_events::owner_webauthn_registration_status_handler),
        )
        .route(
            handlers_owner_events::SECURE_UPGRADE_APP_ATTEST_START_PATH,
            post(handlers_owner_events::secure_upgrade_app_attest_start_handler),
        )
        .route(
            handlers_owner_events::SECURE_UPGRADE_APP_ATTEST_FINISH_PATH,
            post(handlers_owner_events::secure_upgrade_app_attest_finish_handler),
        )
        .route(
            "/api/v1/household/owner-webauthn/revoke/start",
            post(handlers_owner_events::owner_webauthn_revoke_credential_start_handler),
        )
        .route(
            "/api/v1/household/owner-webauthn/revoke/finish",
            post(handlers_owner_events::owner_webauthn_revoke_credential_finish_handler),
        )
        .route(
            "/api/v1/household/owner-webauthn/add-credential/start",
            post(handlers_owner_events::owner_webauthn_add_credential_start_handler),
        )
        .route(
            "/api/v1/household/owner-webauthn/add-credential/finish",
            post(handlers_owner_events::owner_webauthn_add_credential_finish_handler),
        )
        .route(
            "/api/v1/household/owner-webauthn/recovery/status",
            post(handlers_owner_events::owner_webauthn_recovery_status_handler),
        )
        .route(
            "/api/v1/household/owner-webauthn/recovery/start",
            post(handlers_owner_events::owner_webauthn_recovery_start_handler),
        )
        .route(
            "/api/v1/household/owner-webauthn/recovery/finish",
            post(handlers_owner_events::owner_webauthn_recovery_finish_handler),
        )
        .route(
            "/api/v1/household/owner-webauthn/recovery/consume/start",
            post(handlers_owner_events::owner_webauthn_recovery_consume_start_handler),
        )
        .route(
            "/api/v1/household/owner-webauthn/recovery/consume/finish",
            post(handlers_owner_events::owner_webauthn_recovery_consume_finish_handler),
        )
        .route(
            "/api/v1/household/owner-events/{cursor}/approval-v2/start",
            post(handlers_owner_events::owner_approval_v2_start_handler),
        )
        .route(
            "/api/v1/household/owner-events/{cursor}/approve",
            post(handlers_owner_events::owner_approve_handler),
        )
        .route(
            "/api/v1/household/owner-events/{cursor}/decline",
            post(handlers_owner_events::owner_decline_handler),
        )
        .with_state(state);
    (
        td,
        router,
        event_log,
        broadcaster,
        person,
        identity,
        window,
        state_for_assertion,
    )
}

fn router_with_state(
    timeout: Duration,
) -> (
    TempDir,
    Router,
    Arc<OwnerEventLog>,
    OwnerEventsBroadcaster,
    P256Keypair,
    Arc<household_rs::LoadedIdentity>,
    Arc<PairMachineWindow>,
) {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person) = legacy_owner_auth_for(&identity);
    router_from_owner_auth(td, identity, owner_auth, person, timeout, |state| state)
}

fn owner_webauthn_rp() -> OwnerWebauthnRp {
    let config = OwnerWebauthnConfig::new(
        "alpha.example.test",
        Url::parse("https://alpha.example.test").unwrap(),
        "Soyeht Alpha",
    )
    .unwrap()
    .with_challenge_ttl(Duration::from_secs(60));
    OwnerWebauthnRp::new(config).unwrap()
}

#[tokio::test]
async fn secure_upgrade_start_is_default_off() {
    let (_td, router, _log, _broadcaster, person, _identity, _window) =
        router_with_state(Duration::from_millis(100));
    let body = household_rs::cbor::to_canonical_vec(&SecureUpgradeStartTestRequest {
        version: 1,
        proof_key_id: "app-attest-proof-key-alpha".to_string(),
        platform: SecureUpgradePlatform::Ios,
    })
    .unwrap();

    let (status, _headers, _bytes) = post_cbor(
        router,
        handlers_owner_events::SECURE_UPGRADE_APP_ATTEST_START_PATH,
        body,
        Some(&person),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn secure_upgrade_start_issues_server_authoritative_transcript_when_enabled() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person) = legacy_owner_auth_for(&identity);
    let (_td, router, _log, _broadcaster, person, _identity, _window, state) =
        router_from_owner_auth_with_router_state(
            td,
            identity.clone(),
            owner_auth,
            person,
            Duration::from_millis(100),
            |state| {
                state
                    .with_owner_approval_policy(
                        OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout()
                            .with_secure_upgrade(SecureUpgradeEnforcement::StrongMintingEnabled),
                    )
                    .with_secure_upgrade_runtime(SecureUpgradeRuntimeConfig {
                        app_team_id: "TEAMID1234".to_string(),
                        app_bundle_id: "com.example.soyeht.dev".to_string(),
                        proof_environment: SecureUpgradeProofEnvironment::Development,
                        challenge_ttl: Duration::from_secs(300),
                    })
            },
        );
    let body = household_rs::cbor::to_canonical_vec(&SecureUpgradeStartTestRequest {
        version: 1,
        proof_key_id: "app-attest-proof-key-alpha".to_string(),
        platform: SecureUpgradePlatform::Ios,
    })
    .unwrap();

    let (status, _headers, bytes) = post_cbor(
        router,
        handlers_owner_events::SECURE_UPGRADE_APP_ATTEST_START_PATH,
        body,
        Some(&person),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: SecureUpgradeStartTestResponse =
        household_rs::cbor::from_canonical_slice(&bytes).unwrap();
    assert_eq!(response.version, 1);
    assert!(response.challenge_id.starts_with("su-"));
    assert!(response.expires_at > unix_now());

    let transcript =
        SecureUpgradeTranscript::from_canonical_bytes(response.canonical_transcript_cbor.as_ref())
            .unwrap();
    assert_eq!(transcript.hh_id, identity.record.hh_id);
    assert_eq!(
        transcript.owner_p_id,
        household_rs::derive_person_id(&person.public())
    );
    assert_eq!(
        transcript.owner_key_id,
        household_rs::derive_person_id(&person.public()).0
    );
    assert_eq!(transcript.challenge_id, response.challenge_id);
    assert_eq!(transcript.app_team_id, "TEAMID1234");
    assert_eq!(transcript.app_bundle_id, "com.example.soyeht.dev");
    assert_eq!(transcript.proof_key_id, "app-attest-proof-key-alpha");
    assert_eq!(
        transcript.proof_environment,
        SecureUpgradeProofEnvironment::Development
    );
    assert_eq!(transcript.platform, SecureUpgradePlatform::Ios);
    let digest = SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
        response.canonical_transcript_cbor.as_ref(),
    );
    assert_eq!(response.challenge_sha256.as_ref(), digest.as_slice());
    assert!(
        !state
            .secure_upgrade_runtime
            .as_ref()
            .unwrap()
            .challenge_store
            .is_empty()
    );
}

#[tokio::test]
async fn secure_upgrade_finish_fails_closed_without_real_app_attest() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person) = legacy_owner_auth_for(&identity);
    let (_td, router, _log, _broadcaster, person, _identity, _window, state) =
        router_from_owner_auth_with_router_state(
            td,
            identity,
            owner_auth,
            person,
            Duration::from_millis(100),
            |state| {
                state
                    .with_owner_approval_policy(
                        OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout()
                            .with_secure_upgrade(SecureUpgradeEnforcement::StrongMintingEnabled),
                    )
                    .with_secure_upgrade_runtime(SecureUpgradeRuntimeConfig {
                        app_team_id: "TEAMID1234".to_string(),
                        app_bundle_id: "com.example.soyeht.dev".to_string(),
                        proof_environment: SecureUpgradeProofEnvironment::Development,
                        challenge_ttl: Duration::from_secs(300),
                    })
            },
        );
    let start_body = household_rs::cbor::to_canonical_vec(&SecureUpgradeStartTestRequest {
        version: 1,
        proof_key_id: "app-attest-proof-key-alpha".to_string(),
        platform: SecureUpgradePlatform::Ios,
    })
    .unwrap();
    let (status, _headers, start_bytes) = post_cbor(
        router.clone(),
        handlers_owner_events::SECURE_UPGRADE_APP_ATTEST_START_PATH,
        start_body,
        Some(&person),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let start: SecureUpgradeStartTestResponse =
        household_rs::cbor::from_canonical_slice(&start_bytes).unwrap();
    let digest = SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
        start.canonical_transcript_cbor.as_ref(),
    );
    let owner_signature = person.sign(&digest).unwrap();
    let finish_body = household_rs::cbor::to_canonical_vec(&SecureUpgradeFinishTestRequest {
        version: 1,
        challenge_id: start.challenge_id,
        canonical_transcript_cbor: start.canonical_transcript_cbor,
        attestation_object_cbor: ByteBuf::from(vec![0xa0]),
        owner_signature: ByteBuf::from(owner_signature.as_bytes().to_vec()),
    })
    .unwrap();

    let (status, _headers, resp_bytes) = post_cbor(
        router,
        handlers_owner_events::SECURE_UPGRADE_APP_ATTEST_FINISH_PATH,
        finish_body,
        Some(&person),
    )
    .await;

    assert_generic_unauth(status, &resp_bytes);
    let current_owner_auth = state
        .household
        .current_owner_auth()
        .await
        .expect("owner auth remains loaded");
    assert!(
        !current_owner_auth
            .owner_person_cert
            .has_strong_owner_provenance()
    );
    let replay_dir = state
        .secure_upgrade_runtime
        .as_ref()
        .expect("secure upgrade runtime exists")
        .replay_store
        .dir();
    assert!(
        !replay_dir.exists() || fs::read_dir(replay_dir).unwrap().next().is_none(),
        "failed finish must not record durable App Attest replay state"
    );
}

fn register_owner_softpasskey(
    rp: &mut OwnerWebauthnRp,
) -> (OwnerWebauthnCredential, WebauthnAuthenticator<SoftPasskey>) {
    let mut rng = StdRng::seed_from_u64(7);
    let (challenge_id, challenge) = rp
        .start_registration(
            &mut rng,
            unix_now(),
            Uuid::new_v4(),
            "owner-alpha",
            "Owner Alpha",
            &[],
        )
        .unwrap();
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let response = authenticator
        .do_registration(Url::parse("https://alpha.example.test").unwrap(), challenge)
        .unwrap();
    let credential = rp
        .finish_registration(unix_now(), &challenge_id, &response)
        .unwrap();
    (credential, authenticator)
}

fn approval_v2_from_assertion(
    context: OwnerApprovalContextV2,
    assertion: &PublicKeyCredential,
) -> OwnerApprovalV2 {
    OwnerApprovalV2 {
        version: 2,
        context,
        credential_id: ByteBuf::from(assertion.raw_id.as_slice().to_vec()),
        authenticator_data: ByteBuf::from(
            assertion.response.authenticator_data.as_slice().to_vec(),
        ),
        client_data_json: ByteBuf::from(assertion.response.client_data_json.as_slice().to_vec()),
        signature: ByteBuf::from(assertion.response.signature.as_slice().to_vec()),
        user_handle: assertion
            .response
            .user_handle
            .as_ref()
            .map(|user_handle| ByteBuf::from(user_handle.as_slice().to_vec())),
    }
}

async fn start_approval_v2(
    router: Router,
    person: &P256Keypair,
    cursor: u64,
) -> OwnerApprovalV2StartResponse {
    let (status, start_bytes) = post_approval_v2_start(router, person, cursor).await;
    assert_eq!(status, StatusCode::OK);
    let start: OwnerApprovalV2StartResponse =
        household_rs::cbor::from_canonical_slice(&start_bytes).unwrap();
    assert_eq!(start.version, 1);
    start
}

async fn post_approval_v2_start(
    router: Router,
    person: &P256Keypair,
    cursor: u64,
) -> (StatusCode, Vec<u8>) {
    let start_uri = format!("/api/v1/household/owner-events/{cursor}/approval-v2/start");
    let start_body =
        household_rs::cbor::to_canonical_vec(&OwnerApprovalV2StartRequest { version: 1 }).unwrap();
    let start_auth = pop_header_for(person, "POST", &start_uri, unix_now(), &start_body);
    let start_resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(start_uri)
                .header(header::AUTHORIZATION, start_auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(start_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = start_resp.status();
    let start_bytes = to_bytes(start_resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, start_bytes)
}

fn approval_v2_finish_body(
    context: OwnerApprovalContextV2,
    challenge_id: String,
    assertion: &PublicKeyCredential,
) -> Vec<u8> {
    let approval = approval_v2_from_assertion(context, assertion);
    household_rs::cbor::to_canonical_vec(&OwnerApprovalV2FinishBody {
        version: 1,
        challenge_id,
        approval,
    })
    .unwrap()
}

async fn post_approve_body(
    router: Router,
    person: &P256Keypair,
    cursor: u64,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let approve_uri = format!("/api/v1/household/owner-events/{cursor}/approve");
    let finish_auth = pop_header_for(person, "POST", &approve_uri, unix_now(), &body);
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(approve_uri)
                .header(header::AUTHORIZATION, finish_auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

fn owner_auth_with_webauthn_credential(
    identity: &household_rs::LoadedIdentity,
) -> (
    household_rs::HouseholdAuthState,
    P256Keypair,
    OwnerWebauthnRp,
    WebauthnAuthenticator<SoftPasskey>,
) {
    let (owner_auth, person) = owner_auth_for(identity);
    owner_auth_with_webauthn_credential_from(identity, owner_auth, person)
}

fn legacy_owner_auth_with_webauthn_credential(
    identity: &household_rs::LoadedIdentity,
) -> (
    household_rs::HouseholdAuthState,
    P256Keypair,
    OwnerWebauthnRp,
    WebauthnAuthenticator<SoftPasskey>,
) {
    let (owner_auth, person) = legacy_owner_auth_for(identity);
    owner_auth_with_webauthn_credential_from(identity, owner_auth, person)
}

fn owner_auth_with_webauthn_credential_from(
    identity: &household_rs::LoadedIdentity,
    mut owner_auth: HouseholdAuthState,
    person: P256Keypair,
) -> (
    household_rs::HouseholdAuthState,
    P256Keypair,
    OwnerWebauthnRp,
    WebauthnAuthenticator<SoftPasskey>,
) {
    let mut rp = owner_webauthn_rp();
    let (credential, authenticator) = register_owner_softpasskey(&mut rp);
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv present in single-machine household"),
        &identity.record,
        &owner_auth.owner_person_cert,
        credential,
        unix_now(),
    )
    .unwrap();
    owner_auth.owner_webauthn.push_signed(genesis);
    owner_auth.updated_at = unix_now();
    (owner_auth, person, rp, authenticator)
}

fn owner_auth_with_revoked_webauthn_credential(
    identity: &household_rs::LoadedIdentity,
) -> (
    household_rs::HouseholdAuthState,
    P256Keypair,
    OwnerWebauthnRp,
) {
    let (mut owner_auth, person, rp, _authenticator) =
        owner_auth_with_webauthn_credential(identity);
    let credential_id = owner_auth
        .owner_webauthn
        .reconstruct(&identity.record, &owner_auth.owner_person_cert)
        .unwrap()
        .credentials()
        .first()
        .expect("genesis credential exists")
        .credential_id_bytes()
        .to_vec();
    let previous = owner_auth
        .owner_webauthn
        .entries()
        .last()
        .expect("genesis event exists")
        .clone();
    let revoke = OwnerWebauthnAuthority::sign_append(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv present in single-machine household"),
        &identity.record,
        &owner_auth.owner_person_cert,
        &previous,
        &credential_id,
        OwnerWebauthnCredentialEventAction::Revoke {
            credential_id: ByteBuf::from(credential_id.clone()),
        },
        unix_now(),
    )
    .unwrap();
    owner_auth.owner_webauthn.push_signed(revoke);
    owner_auth.updated_at = unix_now();
    assert_eq!(
        owner_auth
            .owner_webauthn_credentials(&identity.record)
            .unwrap()
            .active_count(),
        0
    );
    (owner_auth, person, rp)
}

fn owner_auth_with_two_webauthn_credentials(
    identity: &household_rs::LoadedIdentity,
) -> (
    household_rs::HouseholdAuthState,
    P256Keypair,
    OwnerWebauthnRp,
    WebauthnAuthenticator<SoftPasskey>,
) {
    let (mut owner_auth, person, mut rp, authenticator) =
        owner_auth_with_webauthn_credential(identity);
    let actor_credential_id = owner_auth
        .owner_webauthn
        .reconstruct(&identity.record, &owner_auth.owner_person_cert)
        .unwrap()
        .credentials()
        .first()
        .expect("genesis credential exists")
        .credential_id_bytes()
        .to_vec();
    let previous = owner_auth
        .owner_webauthn
        .entries()
        .last()
        .expect("genesis event exists")
        .clone();
    let (credential, _second_authenticator) = register_owner_softpasskey(&mut rp);
    let add = OwnerWebauthnAuthority::sign_append(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv present in single-machine household"),
        &identity.record,
        &owner_auth.owner_person_cert,
        &previous,
        &actor_credential_id,
        OwnerWebauthnCredentialEventAction::Add {
            credential: Box::new(credential),
        },
        unix_now(),
    )
    .unwrap();
    owner_auth.owner_webauthn.push_signed(add);
    owner_auth.updated_at = unix_now();
    assert_eq!(
        owner_auth
            .owner_webauthn_credentials(&identity.record)
            .unwrap()
            .active_count(),
        2
    );
    (owner_auth, person, rp, authenticator)
}

fn owner_auth_with_three_webauthn_credentials(
    identity: &household_rs::LoadedIdentity,
) -> (
    household_rs::HouseholdAuthState,
    P256Keypair,
    OwnerWebauthnRp,
    WebauthnAuthenticator<SoftPasskey>,
) {
    let (mut owner_auth, person, mut rp, authenticator) =
        owner_auth_with_two_webauthn_credentials(identity);
    let actor_credential_id = owner_auth
        .owner_webauthn
        .reconstruct(&identity.record, &owner_auth.owner_person_cert)
        .unwrap()
        .active_credentials()
        .first()
        .expect("active actor credential exists")
        .credential_id_bytes()
        .to_vec();
    let previous = owner_auth
        .owner_webauthn
        .entries()
        .last()
        .expect("second add event exists")
        .clone();
    let (credential, _third_authenticator) = register_owner_softpasskey(&mut rp);
    let add = OwnerWebauthnAuthority::sign_append(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv present in single-machine household"),
        &identity.record,
        &owner_auth.owner_person_cert,
        &previous,
        &actor_credential_id,
        OwnerWebauthnCredentialEventAction::Add {
            credential: Box::new(credential),
        },
        unix_now(),
    )
    .unwrap();
    owner_auth.owner_webauthn.push_signed(add);
    owner_auth.updated_at = unix_now();
    assert_eq!(
        owner_auth
            .owner_webauthn_credentials(&identity.record)
            .unwrap()
            .active_count(),
        3
    );
    (owner_auth, person, rp, authenticator)
}

fn router_with_v2_owner(timeout: Duration) -> V2OwnerRouterFixture {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, authenticator) = owner_auth_with_webauthn_credential(&identity);

    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    verify_or_update_owner_webauthn_authority_anchor(
        anchor_store.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::MigrationDefaultOff,
    )
    .unwrap();
    let policy = OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout();
    let (td, router, log, broadcaster, person, identity, window) =
        router_from_owner_auth(td, identity, owner_auth, person, timeout, move |state| {
            state
                .with_owner_approval_policy(policy)
                .with_owner_webauthn_rp(rp)
                .with_owner_webauthn_anchor(anchor_store)
        });
    (
        td,
        router,
        log,
        broadcaster,
        person,
        identity,
        window,
        authenticator,
    )
}

fn router_with_v2_owner_without_hh_priv(timeout: Duration) -> V2OwnerRouterFixture {
    let td = tempfile::tempdir().unwrap();
    let identity = bootstrap(td.path());
    let (owner_auth, person, rp, authenticator) = owner_auth_with_webauthn_credential(&identity);
    let identity = Arc::new(loaded_identity_without_hh_priv(&identity));

    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    verify_or_update_owner_webauthn_authority_anchor(
        anchor_store.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::MigrationDefaultOff,
    )
    .unwrap();
    let policy = OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout();
    let (td, router, log, broadcaster, person, identity, window) =
        router_from_owner_auth(td, identity, owner_auth, person, timeout, move |state| {
            state
                .with_owner_approval_policy(policy)
                .with_owner_webauthn_rp(rp)
                .with_owner_webauthn_anchor(anchor_store)
        });
    (
        td,
        router,
        log,
        broadcaster,
        person,
        identity,
        window,
        authenticator,
    )
}

fn router_with_v2_policy_without_passkey(timeout: Duration) -> OwnerEventsRouterFixture {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person) = owner_auth_for(&identity);
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    let policy = OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout();
    router_from_owner_auth(td, identity, owner_auth, person, timeout, move |state| {
        state
            .with_owner_approval_policy(policy)
            .with_owner_webauthn_anchor(anchor_store)
    })
}

fn router_with_owner_webauthn_registration(
    timeout: Duration,
) -> OwnerWebauthnRegistrationRouterFixture {
    let td = tempfile::tempdir().unwrap();
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    router_with_owner_webauthn_registration_anchor(timeout, td, anchor_store)
}

fn router_with_owner_webauthn_registration_anchor(
    timeout: Duration,
    td: TempDir,
    anchor_store: Arc<dyn keystore_rs::KeystoreBackend>,
) -> OwnerWebauthnRegistrationRouterFixture {
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person) = owner_auth_for(&identity);
    let rp = owner_webauthn_rp();
    let anchor_for_state = Arc::clone(&anchor_store);
    let (td, router, log, broadcaster, person, identity, window) =
        router_from_owner_auth(td, identity, owner_auth, person, timeout, move |state| {
            state
                .with_owner_webauthn_rp(rp)
                .with_owner_webauthn_anchor(anchor_for_state)
        });
    (
        td,
        router,
        log,
        broadcaster,
        person,
        identity,
        window,
        anchor_store,
    )
}

fn local_router_with_owner_webauthn_registration(
    timeout: Duration,
    caller_auth: Option<Arc<dyn MacosLocalCallerAuth>>,
) -> OwnerWebauthnRegistrationRouterFixture {
    let td = tempfile::tempdir().unwrap();
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person) = owner_auth_for(&identity);
    let rp = owner_webauthn_rp();
    let anchor_for_state = Arc::clone(&anchor_store);
    let auth_for_state = caller_auth;
    let (td, _network_router, log, broadcaster, person, identity, window, state) =
        router_from_owner_auth_with_router_state(
            td,
            identity,
            owner_auth,
            person,
            timeout,
            move |state| {
                let state = state
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_for_state);
                if let Some(auth) = auth_for_state {
                    state.with_macos_local_caller_auth(auth)
                } else {
                    state
                }
            },
        );
    let local_router = handlers_owner_events::owner_webauthn_macos_local_registration_router(state);
    (
        td,
        local_router,
        log,
        broadcaster,
        person,
        identity,
        window,
        anchor_store,
    )
}

fn dual_router_with_owner_webauthn_registration(
    timeout: Duration,
    caller_auth: Option<Arc<dyn MacosLocalCallerAuth>>,
) -> OwnerWebauthnDualRegistrationRouterFixture {
    let td = tempfile::tempdir().unwrap();
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person) = owner_auth_for(&identity);
    let rp = owner_webauthn_rp();
    let anchor_for_state = Arc::clone(&anchor_store);
    let auth_for_state = caller_auth;
    let (td, network_router, log, broadcaster, person, identity, window, state) =
        router_from_owner_auth_with_router_state(
            td,
            identity,
            owner_auth,
            person,
            timeout,
            move |state| {
                let state = state
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_for_state);
                if let Some(auth) = auth_for_state {
                    state.with_macos_local_caller_auth(auth)
                } else {
                    state
                }
            },
        );
    let local_router = handlers_owner_events::owner_webauthn_macos_local_registration_router(state);
    (
        td,
        network_router,
        local_router,
        log,
        broadcaster,
        person,
        identity,
        window,
        anchor_store,
    )
}

fn router_with_owner_webauthn_add_credential(
    timeout: Duration,
    add_policy_enabled: bool,
) -> V2OwnerRouterFixtureWithState {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, authenticator) = owner_auth_with_webauthn_credential(&identity);
    let webauthn_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    anchor_owner_webauthn_authority(webauthn_anchor_store.as_ref(), &identity, &owner_auth);
    let policy = if add_policy_enabled {
        OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout()
    } else {
        OwnerApprovalEnforcementPolicy::default()
    };
    let (td, router, log, broadcaster, person, identity, window, state) =
        router_from_owner_auth_with_router_state(
            td,
            identity,
            owner_auth,
            person,
            timeout,
            move |state| {
                state
                    .with_owner_approval_policy(policy)
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(webauthn_anchor_store)
            },
        );
    (
        td,
        router,
        log,
        broadcaster,
        person,
        identity,
        window,
        authenticator,
        state,
    )
}

fn router_with_owner_webauthn_recovery(
    timeout: Duration,
    recovery_policy_enabled: bool,
) -> OwnerWebauthnRecoveryRouterFixture {
    router_with_owner_webauthn_recovery_with_limiter(timeout, recovery_policy_enabled, Some(100))
}

fn router_with_owner_webauthn_recovery_with_limiter(
    timeout: Duration,
    recovery_policy_enabled: bool,
    recovery_consume_limiter_limit: Option<i64>,
) -> OwnerWebauthnRecoveryRouterFixture {
    let policy = if recovery_policy_enabled {
        OwnerApprovalEnforcementPolicy::default()
            .with_recovery_code(RecoveryCodeEnforcement::BreakGlassEnabled)
    } else {
        OwnerApprovalEnforcementPolicy::default()
    };
    let (
        td,
        router,
        log,
        broadcaster,
        person,
        identity,
        window,
        webauthn_anchor,
        recovery_anchor,
        authenticator,
        _state,
    ) = router_with_owner_webauthn_recovery_with_state(
        timeout,
        policy,
        recovery_consume_limiter_limit,
    );
    (
        td,
        router,
        log,
        broadcaster,
        person,
        identity,
        window,
        webauthn_anchor,
        recovery_anchor,
        authenticator,
    )
}

fn router_with_owner_webauthn_recovery_with_state(
    timeout: Duration,
    policy: OwnerApprovalEnforcementPolicy,
    recovery_consume_limiter_limit: Option<i64>,
) -> OwnerWebauthnRecoveryRouterFixtureWithState {
    let td = tempfile::tempdir().unwrap();
    let recovery_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    router_with_owner_webauthn_recovery_anchor_with_state(
        timeout,
        policy,
        td,
        recovery_anchor_store,
        recovery_consume_limiter_limit,
    )
}

fn router_with_owner_webauthn_recovery_anchor(
    timeout: Duration,
    recovery_policy_enabled: bool,
    td: TempDir,
    recovery_anchor_store: Arc<dyn keystore_rs::KeystoreBackend>,
) -> OwnerWebauthnRecoveryRouterFixture {
    router_with_owner_webauthn_recovery_anchor_with_limiter(
        timeout,
        recovery_policy_enabled,
        td,
        recovery_anchor_store,
        Some(100),
    )
}

fn router_with_owner_webauthn_recovery_anchor_with_limiter(
    timeout: Duration,
    recovery_policy_enabled: bool,
    td: TempDir,
    recovery_anchor_store: Arc<dyn keystore_rs::KeystoreBackend>,
    recovery_consume_limiter_limit: Option<i64>,
) -> OwnerWebauthnRecoveryRouterFixture {
    let policy = if recovery_policy_enabled {
        OwnerApprovalEnforcementPolicy::default()
            .with_recovery_code(RecoveryCodeEnforcement::BreakGlassEnabled)
    } else {
        OwnerApprovalEnforcementPolicy::default()
    };
    let (
        td,
        router,
        log,
        broadcaster,
        person,
        identity,
        window,
        webauthn_anchor,
        recovery_anchor,
        authenticator,
        _state,
    ) = router_with_owner_webauthn_recovery_anchor_with_state(
        timeout,
        policy,
        td,
        recovery_anchor_store,
        recovery_consume_limiter_limit,
    );
    (
        td,
        router,
        log,
        broadcaster,
        person,
        identity,
        window,
        webauthn_anchor,
        recovery_anchor,
        authenticator,
    )
}

fn router_with_owner_webauthn_recovery_anchor_with_state(
    timeout: Duration,
    policy: OwnerApprovalEnforcementPolicy,
    td: TempDir,
    recovery_anchor_store: Arc<dyn keystore_rs::KeystoreBackend>,
    recovery_consume_limiter_limit: Option<i64>,
) -> OwnerWebauthnRecoveryRouterFixtureWithState {
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, authenticator) = owner_auth_with_webauthn_credential(&identity);
    let webauthn_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    anchor_owner_webauthn_authority(webauthn_anchor_store.as_ref(), &identity, &owner_auth);
    let recovery_consume_limiter = recovery_consume_limiter_limit.map(|limit| {
        Arc::new(
            server_rs::ratelimit::Limiter::new(
                td.path()
                    .join("recovery-consume-rate-limit.db")
                    .to_str()
                    .unwrap(),
                limit,
            )
            .unwrap(),
        )
    });
    let (td, router, log, broadcaster, person, identity, window, state) =
        router_from_owner_auth_with_router_state(td, identity, owner_auth, person, timeout, {
            let webauthn_anchor_store = Arc::clone(&webauthn_anchor_store);
            let recovery_anchor_store = Arc::clone(&recovery_anchor_store);
            move |state| {
                let state = state
                    .with_owner_approval_policy(policy)
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(webauthn_anchor_store)
                    .with_owner_webauthn_recovery_anchor(recovery_anchor_store);
                if let Some(limiter) = recovery_consume_limiter {
                    state.with_recovery_consume_rate_limiter(limiter)
                } else {
                    state
                }
            }
        });
    (
        td,
        router,
        log,
        broadcaster,
        person,
        identity,
        window,
        webauthn_anchor_store,
        recovery_anchor_store,
        authenticator,
        state,
    )
}

fn loaded_identity_without_hh_priv(
    identity: &household_rs::LoadedIdentity,
) -> household_rs::LoadedIdentity {
    household_rs::LoadedIdentity {
        record: identity.record.clone(),
        cert: identity.cert.clone(),
        hh_priv: None,
        m_priv: Box::new(
            P256Keypair::from_secret_scalar(identity.m_priv.as_software_secret().unwrap()).unwrap(),
        ),
        backing: identity.backing,
    }
}

fn router_with_owner_webauthn_registration_without_hh_priv(
    timeout: Duration,
) -> (
    TempDir,
    Router,
    Arc<OwnerEventLog>,
    OwnerEventsBroadcaster,
    P256Keypair,
    Arc<household_rs::LoadedIdentity>,
    Arc<PairMachineWindow>,
) {
    let td = tempfile::tempdir().unwrap();
    let identity = bootstrap(td.path());
    let (owner_auth, person) = owner_auth_for(&identity);
    let identity = Arc::new(loaded_identity_without_hh_priv(&identity));
    let rp = owner_webauthn_rp();
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    router_from_owner_auth(td, identity, owner_auth, person, timeout, move |state| {
        state
            .with_owner_webauthn_rp(rp)
            .with_owner_webauthn_anchor(anchor_store)
    })
}

fn cursor_param(cursor: u64) -> String {
    let bytes = household_rs::cbor::to_canonical_vec(&cursor).unwrap();
    B64URL.encode(bytes)
}

fn owner_events_uri(since: u64) -> String {
    format!("{OWNER_EVENTS_PATH}?since={}", cursor_param(since))
}

fn pop_header_for(
    person: &P256Keypair,
    method: &str,
    uri: &str,
    timestamp: u64,
    body: &[u8],
) -> String {
    let ctx = RequestSigningContext::new(method, uri, timestamp, body);
    let sig = person.sign(&ctx.canonical_bytes().unwrap()).unwrap();
    format!(
        "Soyeht-PoP v1:{}:{}:{}",
        household_rs::derive_person_id(&person.public()).0,
        timestamp,
        B64URL.encode(sig.as_bytes())
    )
}

fn pop_header(person: &P256Keypair, uri: &str, timestamp: u64) -> String {
    pop_header_for(person, "GET", uri, timestamp, b"")
}

async fn get_cbor(
    router: Router,
    uri: &str,
    person: Option<&P256Keypair>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(person) = person {
        builder = builder.header(header::AUTHORIZATION, pop_header(person, uri, unix_now()));
    }
    let resp = router
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, bytes)
}

async fn post_cbor(
    router: Router,
    uri: &str,
    body: Vec<u8>,
    person: Option<&P256Keypair>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/cbor");
    if let Some(person) = person {
        builder = builder.header(
            header::AUTHORIZATION,
            pop_header_for(person, "POST", uri, unix_now(), &body),
        );
    }
    let resp = router
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, bytes)
}

#[derive(Serialize)]
struct SecureUpgradeStartTestRequest {
    #[serde(rename = "v")]
    version: u8,
    proof_key_id: String,
    platform: SecureUpgradePlatform,
}

#[derive(Deserialize)]
struct SecureUpgradeStartTestResponse {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    canonical_transcript_cbor: ByteBuf,
    challenge_sha256: ByteBuf,
    expires_at: u64,
}

#[derive(Serialize)]
struct SecureUpgradeFinishTestRequest {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    canonical_transcript_cbor: ByteBuf,
    attestation_object_cbor: ByteBuf,
    owner_signature: ByteBuf,
}

async fn post_cbor_with_macos_local_peer(
    router: Router,
    uri: &str,
    body: Vec<u8>,
    peer: MacosLocalPeerConnectInfo,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    let resp = router.oneshot(request).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, bytes)
}

fn append_join_event(log: &OwnerEventLog, identity: &household_rs::LoadedIdentity) -> OwnerEvent {
    log.append(
        &identity.cert.m_id.to_string(),
        identity.m_priv.as_ref(),
        OwnerEventType::JoinRequest,
        OwnerEventPayload::JoinRequest(JoinRequestPayload {
            join_request_cbor: ByteBuf::from(vec![0xa1, 0x02, 0x03]),
            fingerprint: "mass museum swamp various model gift".to_string(),
            expiry: unix_now() + 300,
        }),
    )
    .unwrap()
}

async fn stage_join_window(
    window: &PairMachineWindow,
    log: &OwnerEventLog,
    identity: &household_rs::LoadedIdentity,
) -> OwnerEvent {
    window
        .enter_staging(
            [0x02; 33],
            [0x42; 32],
            JoinTransport::Tailscale,
            "127.0.0.1:8091".into(),
            "mass museum swamp various model gift".into(),
            vec![0xa1, 0x02, 0x03],
            300,
            None,
        )
        .await
        .unwrap();
    let event = append_join_event(log, identity);
    window.enter_awaiting_owner(event.cursor).await.unwrap();
    event
}

struct CandidateHarness {
    td: TempDir,
    prepared: household_rs::pair_machine::PreparedCandidate,
    window: Arc<PairMachineWindow>,
    addr: String,
}

#[derive(Default)]
struct BlockingFinalizeGate {
    calls: AtomicUsize,
    entered: Notify,
    release: Notify,
}

impl BlockingFinalizeGate {
    async fn wait_for_calls(&self, expected: usize) {
        loop {
            if self.calls.load(Ordering::SeqCst) >= expected {
                return;
            }
            self.entered.notified().await;
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn release_all(&self) {
        self.release.notify_waiters();
    }
}

#[derive(Clone)]
struct BlockingFinalizeState {
    inner: PreHouseholdRouterState,
    gate: Arc<BlockingFinalizeGate>,
}

#[derive(Clone, Copy)]
enum CandidateFinalizeMode {
    Normal,
    CommitThenBadAck,
    RejectFinalize,
}

async fn start_candidate_harness() -> CandidateHarness {
    start_candidate_harness_with_mode(CandidateFinalizeMode::Normal).await
}

async fn start_candidate_harness_with_mode(mode: CandidateFinalizeMode) -> CandidateHarness {
    start_candidate_harness_with_router(|state| match mode {
        CandidateFinalizeMode::Normal => pre_household_router(state),
        CandidateFinalizeMode::CommitThenBadAck => Router::new()
            .route(
                "/pair-machine/local/finalize",
                post(commit_then_bad_finalize_ack),
            )
            .with_state(state),
        CandidateFinalizeMode::RejectFinalize => Router::new()
            .route("/pair-machine/local/finalize", post(reject_finalize))
            .with_state(state),
    })
    .await
}

async fn start_blocking_candidate_harness() -> (CandidateHarness, Arc<BlockingFinalizeGate>) {
    let gate = Arc::new(BlockingFinalizeGate::default());
    let gate_for_router = Arc::clone(&gate);
    let candidate = start_candidate_harness_with_router(move |state| {
        Router::new()
            .route(
                "/pair-machine/local/finalize",
                post(blocking_finalize_handler),
            )
            .with_state(BlockingFinalizeState {
                inner: state,
                gate: Arc::clone(&gate_for_router),
            })
    })
    .await;
    (candidate, gate)
}

async fn start_candidate_harness_with_router(
    router_for_state: impl FnOnce(PreHouseholdRouterState) -> Router,
) -> CandidateHarness {
    let td = tempfile::tempdir().unwrap();
    let window = Arc::new(PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let prepared = prepare_candidate(
        &window,
        PrepareCandidateOpts {
            state_dir: td.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: addr.clone(),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: Duration::from_secs(300),
            now_unix: unix_now(),
        },
    )
    .await
    .unwrap();
    let state = PreHouseholdRouterState {
        window: Arc::clone(&window),
        state_dir: td.path().to_path_buf(),
        key_policy: KeyBackingPolicy::ForceSoftware,
        bootstrap: None,
    };
    let router = router_for_state(state);
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    CandidateHarness {
        td,
        prepared,
        window,
        addr,
    }
}

async fn blocking_finalize_handler(
    State(state): State<BlockingFinalizeState>,
    body: Bytes,
) -> Response {
    state.gate.calls.fetch_add(1, Ordering::SeqCst);
    state.gate.entered.notify_waiters();
    state.gate.release.notified().await;
    server_rs::handlers_pair_machine::local_finalize_handler(State(state.inner), body).await
}

async fn commit_then_bad_finalize_ack(
    State(state): State<PreHouseholdRouterState>,
    body: Bytes,
) -> Response {
    let committed =
        server_rs::handlers_pair_machine::local_finalize_handler(State(state), body).await;
    if committed.status() != StatusCode::OK {
        return committed;
    }
    (StatusCode::OK, b"not-cbor".to_vec()).into_response()
}

async fn reject_finalize() -> Response {
    StatusCode::UNAUTHORIZED.into_response()
}

async fn stage_prepared_join_window(
    window: &PairMachineWindow,
    log: &OwnerEventLog,
    identity: &household_rs::LoadedIdentity,
    candidate: &CandidateHarness,
) -> OwnerEvent {
    let nonce: [u8; 32] = candidate
        .prepared
        .join_request
        .nonce
        .as_ref()
        .try_into()
        .unwrap();
    window
        .enter_staging(
            candidate.prepared.m_pub_sec1,
            nonce,
            JoinTransport::Tailscale,
            candidate.addr.clone(),
            candidate.prepared.fingerprint.clone(),
            candidate.prepared.join_request_cbor.clone(),
            300,
            None,
        )
        .await
        .unwrap();
    let expiry = window.snapshot().await.expiry.unwrap();
    let event = log
        .append(
            &identity.cert.m_id.to_string(),
            identity.m_priv.as_ref(),
            OwnerEventType::JoinRequest,
            OwnerEventPayload::JoinRequest(JoinRequestPayload {
                join_request_cbor: ByteBuf::from(candidate.prepared.join_request_cbor.clone()),
                fingerprint: candidate.prepared.fingerprint.clone(),
                expiry,
            }),
        )
        .unwrap();
    window.enter_awaiting_owner(event.cursor).await.unwrap();
    event
}

fn approval_body(
    identity: &household_rs::LoadedIdentity,
    person: &P256Keypair,
    cursor: u64,
    challenge_sig: ByteBuf,
    timestamp: u64,
) -> Vec<u8> {
    let ctx = OwnerApprovalContext::build(
        identity.record.hh_id.clone(),
        household_rs::derive_person_id(&person.public()),
        cursor,
        challenge_sig,
        timestamp,
    );
    let sig = person.sign(&ctx.to_canonical_bytes().unwrap()).unwrap();
    household_rs::cbor::to_canonical_vec(&OwnerApproval {
        version: 1,
        cursor,
        approval_sig: sig,
    })
    .unwrap()
}

async fn wait_for_subscriber(broadcaster: &OwnerEventsBroadcaster) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while broadcaster.active_subscribers() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("long-poll request did not subscribe");
}

async fn wait_for_captured_tickle(spy: &SpyTransport, expected_len: usize) -> Vec<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let captured = spy.captured();
            if captured.len() >= expected_len {
                return captured;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("APNS tickle was not dispatched")
}

#[tokio::test]
async fn catch_up_returns_immediately() {
    let (_td, router, log, _broadcaster, person, identity, _window) =
        router_with_state(Duration::from_secs(45));
    let event = append_join_event(&log, &identity);

    let uri = owner_events_uri(0);
    let (status, headers, resp_bytes) = get_cbor(router, &uri, Some(&person)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/cbor"
    );
    let parsed: OwnerEventsResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.events.len(), 1);
    assert_eq!(parsed.events[0].cursor, event.cursor);
    assert_eq!(parsed.next_cursor, event.cursor);
}

#[tokio::test]
async fn idle_holds_open_until_event() {
    let (_td, router, log, _broadcaster, person, identity, _window) =
        router_with_state(Duration::from_secs(1));
    let uri = owner_events_uri(0);
    let auth = pop_header(&person, &uri, unix_now());
    let handle = tokio::spawn({
        let router = router.clone();
        let uri = uri.clone();
        async move {
            let resp = router
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(uri)
                        .header(header::AUTHORIZATION, auth)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let bytes = to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec();
            (status, bytes)
        }
    });

    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !handle.is_finished(),
        "idle long-poll returned before event"
    );
    let event = append_join_event(&log, &identity);

    let (status, resp_bytes) = tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    let parsed: OwnerEventsResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.events.len(), 1);
    assert_eq!(parsed.next_cursor, event.cursor);
}

#[tokio::test]
async fn idle_returns_204_on_timeout() {
    let (_td, router, _log, _broadcaster, person, _identity, _window) =
        router_with_state(Duration::from_millis(20));
    let uri = owner_events_uri(0);

    let (status, _headers, resp_bytes) = get_cbor(router, &uri, Some(&person)).await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(resp_bytes.is_empty());
}

#[tokio::test]
async fn cancellation_drops_subscription_without_response() {
    let (_td, router, _log, broadcaster, person, _identity, _window) =
        router_with_state(Duration::from_secs(5));
    let uri = owner_events_uri(0);
    let auth = pop_header(&person, &uri, unix_now());
    let handle = tokio::spawn(async move {
        router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header(header::AUTHORIZATION, auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
    });

    wait_for_subscriber(&broadcaster).await;
    handle.abort();
    let err = handle.await.unwrap_err();
    assert!(err.is_cancelled());
    assert_eq!(broadcaster.active_subscribers(), 0);
}

#[tokio::test]
async fn bad_pop_returns_generic_401() {
    let (_td, router, _log, _broadcaster, _person, _identity, _window) =
        router_with_state(Duration::from_secs(45));
    let uri = owner_events_uri(0);

    let (status, _headers, resp_bytes) = get_cbor(router, &uri, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.error, "unauthenticated");
}

#[tokio::test]
async fn owner_webauthn_registration_start_fails_closed_without_rp_or_anchor() {
    let (_td, router, _log, _broadcaster, person, _identity, _window) =
        router_with_state(Duration::from_secs(45));
    let uri = "/api/v1/household/owner-webauthn/registration/start";
    let body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();

    let (status, _headers, resp_bytes) = post_cbor(router, uri, body, Some(&person)).await;

    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_status_fails_closed_without_anchor_verifier() {
    let (_td, router, _log, _broadcaster, person, _identity, _window) =
        router_with_state(Duration::from_secs(45));

    let (status, _headers, resp_bytes) = post_registration_status(router, &person).await;

    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_tcp_start_still_requires_pop() {
    let (_td, router, _log, _broadcaster, _person, _identity, _window, _anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));
    let body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();

    let (status, _headers, resp_bytes) = post_cbor(
        router,
        "/api/v1/household/owner-webauthn/registration/start",
        body,
        None,
    )
    .await;

    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_local_absent_verifier_fails_closed_before_decode() {
    let (_td, router, _log, _broadcaster, _person, _identity, _window, _anchor_store) =
        local_router_with_owner_webauthn_registration(Duration::from_secs(45), None);

    let (status, _headers, resp_bytes) = post_cbor_with_macos_local_peer(
        router,
        handlers_owner_events::OWNER_WEBAUTHN_REGISTRATION_LOCAL_START_PATH,
        vec![0xff],
        test_macos_local_peer(),
    )
    .await;

    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_local_missing_peer_fails_closed_before_decode() {
    let (_td, router, _log, _broadcaster, _person, _identity, _window, _anchor_store) =
        local_router_with_owner_webauthn_registration(
            Duration::from_secs(45),
            Some(TestMacosLocalCallerAuth::allow()),
        );

    let (status, _headers, resp_bytes) = post_cbor(
        router,
        handlers_owner_events::OWNER_WEBAUTHN_REGISTRATION_LOCAL_START_PATH,
        vec![0xff],
        None,
    )
    .await;

    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_local_denied_rejects_opaque_without_challenge() {
    let (_td, router, _log, _broadcaster, _person, _identity, _window, _anchor_store) =
        local_router_with_owner_webauthn_registration(
            Duration::from_secs(45),
            Some(TestMacosLocalCallerAuth::deny()),
        );
    let body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();

    let (status, _headers, resp_bytes) = post_cbor_with_macos_local_peer(
        router,
        handlers_owner_events::OWNER_WEBAUTHN_REGISTRATION_LOCAL_START_PATH,
        body,
        test_macos_local_peer(),
    )
    .await;

    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_local_fake_auth_allows_start_and_status_only() {
    let (_td, router, _log, _broadcaster, _person, _identity, _window, _anchor_store) =
        local_router_with_owner_webauthn_registration(
            Duration::from_secs(45),
            Some(TestMacosLocalCallerAuth::allow()),
        );
    let start_body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();

    let (status, _headers, resp_bytes) = post_cbor_with_macos_local_peer(
        router.clone(),
        handlers_owner_events::OWNER_WEBAUTHN_REGISTRATION_LOCAL_START_PATH,
        start_body,
        test_macos_local_peer(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let start: OwnerWebauthnRegistrationStartResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(start.version, 1);
    assert!(!start.challenge_id.is_empty());
    let selection = start
        .options
        .public_key
        .authenticator_selection
        .as_ref()
        .expect("local start requests platform authenticator selection");
    assert_eq!(
        selection.authenticator_attachment,
        Some(AuthenticatorAttachment::Platform)
    );
    assert_eq!(
        selection.user_verification,
        UserVerificationPolicy::Required
    );
    assert!(selection.require_resident_key);
    assert!(matches!(
        start.options.public_key.attestation.as_ref(),
        Some(AttestationConveyancePreference::Direct)
    ));
    assert_eq!(
        start
            .options
            .public_key
            .attestation_formats
            .as_ref()
            .map(Vec::as_slice),
        Some([AttestationFormat::AppleAnonymous].as_slice())
    );

    let status_body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStatusRequest {
            version: 1,
        })
        .unwrap();
    let (status, _headers, resp_bytes) = post_cbor_with_macos_local_peer(
        router.clone(),
        handlers_owner_events::OWNER_WEBAUTHN_REGISTRATION_LOCAL_STATUS_PATH,
        status_body,
        test_macos_local_peer(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let status_body: OwnerWebauthnRegistrationStatusResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(status_body.version, 1);
    assert!(!status_body.enrolled);

    let (status, _headers, resp_bytes) = post_cbor_with_macos_local_peer(
        router,
        handlers_owner_events::OWNER_WEBAUTHN_REGISTRATION_LOCAL_FINISH_PATH,
        vec![0xff],
        test_macos_local_peer(),
    )
    .await;
    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_local_attested_challenge_not_consumed_by_tcp_finish() {
    let (
        _td,
        network_router,
        local_router,
        log,
        _broadcaster,
        person,
        identity,
        _window,
        anchor_store,
    ) = dual_router_with_owner_webauthn_registration(
        Duration::from_secs(45),
        Some(TestMacosLocalCallerAuth::allow()),
    );
    let start_body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();
    let (status, _headers, resp_bytes) = post_cbor_with_macos_local_peer(
        local_router,
        handlers_owner_events::OWNER_WEBAUTHN_REGISTRATION_LOCAL_START_PATH,
        start_body,
        test_macos_local_peer(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let start: OwnerWebauthnRegistrationStartResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();

    let credential = standalone_registration_credential();
    let finish_body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationFinishRequest {
            version: 1,
            challenge_id: start.challenge_id,
            credential,
        })
        .unwrap();
    let (status, _headers, resp_bytes) = post_cbor(
        network_router,
        "/api/v1/household/owner-webauthn/registration/finish",
        finish_body,
        Some(&person),
    )
    .await;

    assert_generic_unauth(status, &resp_bytes);
    assert!(
        log.read_since(0).unwrap().is_empty(),
        "normal finish must not mutate authority log for a local attested challenge"
    );
    assert!(
        read_owner_webauthn_authority_anchor(anchor_store.as_ref(), &identity.record.hh_id)
            .unwrap()
            .is_none(),
        "normal finish must not write WebAuthn anchor for a local attested challenge"
    );
}

#[test]
fn owner_webauthn_registration_local_profiles_are_mutually_exclusive() {
    let prod = MacosLocalAppProfile::Production.designated_requirement();
    assert!(prod.contains(&format!(r#"identifier "{}""#, SOYEHT_MACOS_PROD_BUNDLE_ID)));
    assert!(!prod.contains(&format!(r#"identifier "{}""#, SOYEHT_MACOS_DEV_BUNDLE_ID)));

    let dev = MacosLocalAppProfile::Development.designated_requirement();
    assert!(dev.contains(&format!(r#"identifier "{}""#, SOYEHT_MACOS_DEV_BUNDLE_ID)));
    assert!(!dev.contains(&format!(r#"identifier "{}""#, SOYEHT_MACOS_PROD_BUNDLE_ID)));
}

#[tokio::test]
async fn owner_webauthn_registration_rejects_wrong_person_pop() {
    let (_td, router, _log, _broadcaster, person, identity, _window, _anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));
    let wrong_person = P256Keypair::generate();
    let wrong_cert = PersonCert::sign_owner(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv present in single-machine household"),
        SignOwnerOptions {
            hh_id: identity.record.hh_id.clone(),
            p_pub: wrong_person.public(),
            display_name: "Member Alpha".into(),
            issued_at: identity.record.created_at,
        },
    )
    .unwrap();
    wrong_cert
        .verify(&identity.record.hh_id, &identity.record.hh_pub, unix_now())
        .expect("wrong person cert is signed by the household root");
    assert_ne!(
        household_rs::derive_person_id(&wrong_person.public()),
        household_rs::derive_person_id(&person.public())
    );
    let start_uri = "/api/v1/household/owner-webauthn/registration/start";
    let start_body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();

    let (status, _headers, resp_bytes) =
        post_cbor(router.clone(), start_uri, start_body, Some(&wrong_person)).await;
    assert_generic_unauth(status, &resp_bytes);

    let finish_uri = "/api/v1/household/owner-webauthn/registration/finish";
    let finish_body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationFinishRequest {
            version: 1,
            challenge_id: "00000000000000000000000000000000".into(),
            credential: standalone_registration_credential(),
        })
        .unwrap();
    let (status, _headers, resp_bytes) =
        post_cbor(router, finish_uri, finish_body, Some(&wrong_person)).await;
    assert_generic_unauth(status, &resp_bytes);

    let (_td, router, _log, _broadcaster, _person, _identity, _window, _anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));
    let (status, _headers, resp_bytes) = post_registration_status(router, &wrong_person).await;
    assert_generic_unauth(status, &resp_bytes);
}

fn make_version_value_noncanonical(mut body: Vec<u8>) -> Vec<u8> {
    let needle = [0x61, b'v', 0x01];
    let offset = body
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("body contains canonical v=1 field");
    body.splice((offset + 2)..(offset + 3), [0x18, 0x01]);
    body
}

fn standalone_registration_credential() -> RegisterPublicKeyCredential {
    let mut rp = owner_webauthn_rp();
    let mut rng = StdRng::seed_from_u64(19);
    let (_challenge_id, challenge) = rp
        .start_registration(
            &mut rng,
            unix_now(),
            Uuid::new_v4(),
            "owner-alpha",
            "Owner Alpha",
            &[],
        )
        .unwrap();
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    authenticator
        .do_registration(Url::parse("https://alpha.example.test").unwrap(), challenge)
        .unwrap()
}

async fn owner_webauthn_registration_finish_body(router: Router, person: &P256Keypair) -> Vec<u8> {
    let start_uri = "/api/v1/household/owner-webauthn/registration/start";
    let start_body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();
    let (status, headers, resp_bytes) =
        post_cbor(router.clone(), start_uri, start_body, Some(person)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/cbor"
    );
    let start: OwnerWebauthnRegistrationStartResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(start.version, 1);
    assert_eq!(start.challenge_id.len(), 32);

    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = authenticator
        .do_registration(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationFinishRequest {
        version: 1,
        challenge_id: start.challenge_id,
        credential,
    })
    .unwrap()
}

async fn enroll_first_owner_passkey(
    router: Router,
    person: &P256Keypair,
) -> OwnerWebauthnRegistrationFinishResponse {
    let finish_uri = "/api/v1/household/owner-webauthn/registration/finish";
    let finish_body = owner_webauthn_registration_finish_body(router.clone(), person).await;
    let (status, headers, resp_bytes) =
        post_cbor(router, finish_uri, finish_body, Some(person)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/cbor"
    );
    household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap()
}

fn registration_status_marker_path(state_dir: &std::path::Path) -> std::path::PathBuf {
    household_rs::storage::household_dir(state_dir)
        .join("owner_webauthn_initial_enrollment_anchor_pending.cbor")
}

fn registration_status_body() -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStatusRequest { version: 1 })
        .unwrap()
}

async fn post_registration_status(
    router: Router,
    person: &P256Keypair,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let uri = "/api/v1/household/owner-webauthn/registration/status";
    post_cbor(router, uri, registration_status_body(), Some(person)).await
}

async fn registration_status(
    router: Router,
    person: &P256Keypair,
) -> OwnerWebauthnRegistrationStatusResponse {
    let (status, headers, bytes) = post_registration_status(router, person).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/cbor"
    );
    let response: OwnerWebauthnRegistrationStatusResponse =
        household_rs::cbor::from_canonical_slice(&bytes).unwrap();
    assert_eq!(response.version, 1);
    response
}

fn revoke_start_body(target_credential_id: Vec<u8>) -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&OwnerWebauthnRevokeCredentialStartRequest {
        version: 1,
        target_credential_id: ByteBuf::from(target_credential_id),
    })
    .unwrap()
}

async fn post_revoke_start(
    router: Router,
    person: &P256Keypair,
    target_credential_id: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    post_cbor(
        router,
        "/api/v1/household/owner-webauthn/revoke/start",
        revoke_start_body(target_credential_id),
        Some(person),
    )
    .await
}

async fn start_revoke(
    router: Router,
    person: &P256Keypair,
    target_credential_id: Vec<u8>,
) -> OwnerApprovalV2StartResponse {
    let (status, headers, resp_bytes) =
        post_revoke_start(router, person, target_credential_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/cbor"
    );
    let response: OwnerApprovalV2StartResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(response.version, 1);
    assert_eq!(response.context.op, OwnerOperation::RevokeCredential);
    response
}

fn revoke_finish_body(
    context: OwnerApprovalContextV2,
    challenge_id: String,
    assertion: &PublicKeyCredential,
) -> Vec<u8> {
    approval_v2_finish_body(context, challenge_id, assertion)
}

fn add_credential_registration_binding_from_context(
    context: &OwnerApprovalContextV2,
) -> OwnerWebauthnRegistrationBinding {
    let binding_context = TestAddCredentialRegistrationBindingContext {
        version: 1,
        purpose: "owner-webauthn-add-credential-registration-v1".to_string(),
        op: "add-credential".to_string(),
        hh_id: context.hh_id.clone(),
        owner_p_id: context.owner_p_id.clone(),
        authority_head_sequence: context.authority_head_sequence.unwrap(),
        authority_head_hash: context.authority_head_hash.clone().unwrap(),
        pre_active_credential_count: context.pre_active_credential_count.unwrap(),
        capabilities: context.capabilities.clone(),
        issued_at: context.issued_at,
        expires_at: context.expires_at,
        replay_nonce: context.replay_nonce.clone(),
    };
    let canonical = household_rs::cbor::to_canonical_vec(&binding_context).unwrap();
    let binding = OwnerWebauthnRegistrationBinding::from_canonical_binding(
        "owner-webauthn-add-credential-registration-v1",
        canonical,
    )
    .unwrap();
    let digest = binding.binding_digest();
    assert_eq!(
        context
            .new_credential_binding_hash
            .as_ref()
            .map(ByteBuf::as_ref),
        Some(digest.as_slice()),
        "context binding hash must be the digest used for the registration challenge"
    );
    binding
}

async fn post_revoke_finish(
    router: Router,
    person: &P256Keypair,
    body: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    post_cbor(
        router,
        "/api/v1/household/owner-webauthn/revoke/finish",
        body,
        Some(person),
    )
    .await
}

async fn revoke_finish(
    router: Router,
    person: &P256Keypair,
    body: Vec<u8>,
) -> OwnerWebauthnRevokeCredentialFinishResponse {
    let (status, headers, resp_bytes) = post_revoke_finish(router, person, body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/cbor"
    );
    let response: OwnerWebauthnRevokeCredentialFinishResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(response.version, 1);
    response
}

fn add_credential_start_body() -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&OwnerWebauthnAddCredentialStartRequest { version: 1 })
        .unwrap()
}

async fn post_add_credential_start(
    router: Router,
    person: Option<&P256Keypair>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    post_cbor(
        router,
        "/api/v1/household/owner-webauthn/add-credential/start",
        add_credential_start_body(),
        person,
    )
    .await
}

async fn start_add_credential(
    router: Router,
    person: &P256Keypair,
) -> OwnerWebauthnAddCredentialStartResponse {
    let (status, headers, resp_bytes) = post_add_credential_start(router, Some(person)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/cbor"
    );
    let response: OwnerWebauthnAddCredentialStartResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(response.version, 1);
    assert_eq!(response.registration.version, 1);
    assert_eq!(response.approval.version, 1);
    assert_eq!(response.context.op, OwnerOperation::AddCredential);
    assert_eq!(response.approval.context, response.context);
    response
}

fn add_credential_finish_body(
    context: OwnerApprovalContextV2,
    registration_challenge_id: String,
    approval_challenge_id: String,
    credential: RegisterPublicKeyCredential,
    assertion: &PublicKeyCredential,
) -> Vec<u8> {
    let approval = approval_v2_from_assertion(context.clone(), assertion);
    household_rs::cbor::to_canonical_vec(&OwnerWebauthnAddCredentialFinishRequest {
        version: 1,
        context,
        registration: OwnerWebauthnRegistrationFinishRequest {
            version: 1,
            challenge_id: registration_challenge_id,
            credential,
        },
        approval: OwnerApprovalV2FinishBody {
            version: 1,
            challenge_id: approval_challenge_id,
            approval,
        },
    })
    .unwrap()
}

async fn post_add_credential_finish(
    router: Router,
    person: &P256Keypair,
    body: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    post_cbor(
        router,
        "/api/v1/household/owner-webauthn/add-credential/finish",
        body,
        Some(person),
    )
    .await
}

async fn add_credential_finish(
    router: Router,
    person: &P256Keypair,
    body: Vec<u8>,
) -> OwnerWebauthnAddCredentialFinishResponse {
    let (status, headers, resp_bytes) = post_add_credential_finish(router, person, body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/cbor"
    );
    let response: OwnerWebauthnAddCredentialFinishResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(response.version, 1);
    response
}

fn recovery_start_body() -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&OwnerWebauthnRecoveryStartRequest { version: 1 }).unwrap()
}

async fn post_recovery_start(
    router: Router,
    person: &P256Keypair,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    post_cbor(
        router,
        "/api/v1/household/owner-webauthn/recovery/start",
        recovery_start_body(),
        Some(person),
    )
    .await
}

async fn start_recovery(router: Router, person: &P256Keypair) -> OwnerApprovalV2StartResponse {
    let (status, headers, resp_bytes) = post_recovery_start(router, person).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/cbor"
    );
    let response: OwnerApprovalV2StartResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(response.version, 1);
    assert_eq!(response.context.op, OwnerOperation::ProvisionRecoveryCode);
    response
}

fn recovery_finish_body(
    context: OwnerApprovalContextV2,
    challenge_id: String,
    assertion: &PublicKeyCredential,
) -> Vec<u8> {
    approval_v2_finish_body(context, challenge_id, assertion)
}

async fn post_recovery_finish(
    router: Router,
    person: &P256Keypair,
    body: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    post_cbor(
        router,
        "/api/v1/household/owner-webauthn/recovery/finish",
        body,
        Some(person),
    )
    .await
}

async fn recovery_finish(
    router: Router,
    person: &P256Keypair,
    body: Vec<u8>,
) -> OwnerWebauthnRecoveryFinishResponse {
    let (status, headers, resp_bytes) = post_recovery_finish(router, person, body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/cbor"
    );
    let response: OwnerWebauthnRecoveryFinishResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(response.version, 1);
    response
}

async fn provision_recovery_code(
    router: Router,
    person: &P256Keypair,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
) -> String {
    let provision_start = start_recovery(router.clone(), person).await;
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            provision_start.options,
        )
        .unwrap();
    recovery_finish(
        router,
        person,
        recovery_finish_body(
            provision_start.context,
            provision_start.challenge_id,
            &assertion,
        ),
    )
    .await
    .recovery_code
}

fn recovery_consume_start_body(recovery_code: &str) -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&OwnerWebauthnRecoveryConsumeStartRequest {
        version: 1,
        recovery_code: recovery_code.to_string(),
    })
    .unwrap()
}

async fn post_recovery_consume_start(
    router: Router,
    person: &P256Keypair,
    recovery_code: &str,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    post_cbor(
        router,
        "/api/v1/household/owner-webauthn/recovery/consume/start",
        recovery_consume_start_body(recovery_code),
        Some(person),
    )
    .await
}

async fn start_recovery_consume(
    router: Router,
    person: &P256Keypair,
    recovery_code: &str,
) -> OwnerWebauthnRecoveryConsumeStartResponse {
    let (status, headers, resp_bytes) =
        post_recovery_consume_start(router, person, recovery_code).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/cbor"
    );
    let response: OwnerWebauthnRecoveryConsumeStartResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(response.version, 1);
    assert_eq!(response.context.op, OwnerOperation::RecoverCredential);
    response
}

fn recovery_consume_finish_body(
    context: OwnerApprovalContextV2,
    challenge_id: String,
    credential: RegisterPublicKeyCredential,
    recovery_code: &str,
) -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&OwnerWebauthnRecoveryConsumeFinishRequest {
        version: 1,
        challenge_id,
        context,
        credential,
        recovery_code: recovery_code.to_string(),
    })
    .unwrap()
}

async fn post_recovery_consume_finish(
    router: Router,
    person: &P256Keypair,
    body: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    post_cbor(
        router,
        "/api/v1/household/owner-webauthn/recovery/consume/finish",
        body,
        Some(person),
    )
    .await
}

async fn recovery_consume_finish(
    router: Router,
    person: &P256Keypair,
    body: Vec<u8>,
) -> OwnerWebauthnRecoveryConsumeFinishResponse {
    let (status, headers, resp_bytes) = post_recovery_consume_finish(router, person, body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/cbor"
    );
    let response: OwnerWebauthnRecoveryConsumeFinishResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(response.version, 1);
    response
}

fn recovery_status_body() -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&OwnerWebauthnRecoveryStatusRequest { version: 1 })
        .unwrap()
}

async fn post_recovery_status(
    router: Router,
    person: &P256Keypair,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    post_cbor(
        router,
        "/api/v1/household/owner-webauthn/recovery/status",
        recovery_status_body(),
        Some(person),
    )
    .await
}

async fn recovery_status(
    router: Router,
    person: &P256Keypair,
) -> OwnerWebauthnRecoveryStatusResponse {
    let (status, headers, resp_bytes) = post_recovery_status(router, person).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/cbor"
    );
    let response: OwnerWebauthnRecoveryStatusResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(response.version, 1);
    response
}

fn active_credential_ids(
    owner_auth: &HouseholdAuthState,
    identity: &household_rs::LoadedIdentity,
) -> Vec<Vec<u8>> {
    owner_auth
        .owner_webauthn_credentials(&identity.record)
        .unwrap()
        .active_credentials()
        .iter()
        .map(|credential| credential.credential_id_bytes().to_vec())
        .collect()
}

fn anchor_owner_webauthn_authority(
    anchor_store: &dyn keystore_rs::KeystoreBackend,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &HouseholdAuthState,
) -> OwnerWebauthnAuthorityHead {
    verify_or_update_owner_webauthn_authority_anchor(
        anchor_store,
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::MigrationDefaultOff,
    )
    .unwrap();
    verified_owner_webauthn_authority_head(
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
    )
    .unwrap()
    .expect("non-empty authority has a head")
}

fn load_owner_auth(td: &TempDir, identity: &household_rs::LoadedIdentity) -> HouseholdAuthState {
    HouseholdAuthState::load_optional(td.path(), &identity.record, unix_now())
        .unwrap()
        .expect("owner auth state persisted")
}

fn revoke_events_for_target(
    owner_auth: &HouseholdAuthState,
    target_credential_id: &[u8],
) -> Vec<Vec<u8>> {
    owner_auth
        .owner_webauthn
        .entries()
        .iter()
        .filter_map(|entry| {
            let OwnerWebauthnCredentialEventAction::Revoke { credential_id } = &entry.event.action
            else {
                return None;
            };
            if credential_id.as_ref() != target_credential_id {
                return None;
            }
            match &entry.event.actor {
                OwnerWebauthnEventActor::OwnerCredential { credential_id } => {
                    Some(credential_id.to_vec())
                }
                OwnerWebauthnEventActor::GenesisTofu
                | OwnerWebauthnEventActor::RecoveryProof { .. } => None,
            }
        })
        .collect()
}

fn recovery_event_verifier_bytes(owner_auth: &HouseholdAuthState, index: usize) -> Vec<u8> {
    let event = &owner_auth
        .owner_webauthn_recovery
        .entries()
        .get(index)
        .expect("recovery event exists")
        .event;
    match &event.action {
        OwnerWebauthnRecoveryEventAction::Provision { verifier }
        | OwnerWebauthnRecoveryEventAction::Rotate { verifier } => {
            household_rs::cbor::to_canonical_vec(verifier).unwrap()
        }
        OwnerWebauthnRecoveryEventAction::Consume => {
            panic!("consume event does not carry a verifier")
        }
    }
}

fn assert_recovery_event_is_provision(owner_auth: &HouseholdAuthState, index: usize) {
    assert!(matches!(
        &owner_auth.owner_webauthn_recovery.entries()[index]
            .event
            .action,
        OwnerWebauthnRecoveryEventAction::Provision { .. }
    ));
}

fn assert_recovery_event_is_rotate(owner_auth: &HouseholdAuthState, index: usize) {
    assert!(matches!(
        &owner_auth.owner_webauthn_recovery.entries()[index]
            .event
            .action,
        OwnerWebauthnRecoveryEventAction::Rotate { .. }
    ));
}

fn append_revoke_event(
    identity: &household_rs::LoadedIdentity,
    owner_auth: &mut HouseholdAuthState,
    actor_credential_id: &[u8],
    target_credential_id: &[u8],
) {
    let previous = owner_auth
        .owner_webauthn
        .entries()
        .last()
        .expect("authority head exists")
        .clone();
    let revoke = OwnerWebauthnAuthority::sign_append(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv present in single-machine household"),
        &identity.record,
        &owner_auth.owner_person_cert,
        &previous,
        actor_credential_id,
        OwnerWebauthnCredentialEventAction::Revoke {
            credential_id: ByteBuf::from(target_credential_id.to_vec()),
        },
        unix_now(),
    )
    .unwrap();
    owner_auth.owner_webauthn.push_signed(revoke);
    owner_auth.updated_at = unix_now();
}

fn owner_auth_without_last_webauthn_event(owner_auth: &HouseholdAuthState) -> HouseholdAuthState {
    let mut truncated = owner_auth.clone();
    truncated.owner_webauthn = OwnerWebauthnAuthority::new();
    for entry in owner_auth
        .owner_webauthn
        .entries()
        .iter()
        .take(owner_auth.owner_webauthn.entries().len().saturating_sub(1))
    {
        truncated.owner_webauthn.push_signed(entry.clone());
    }
    truncated
}

fn write_test_initial_enrollment_marker(
    state_dir: &std::path::Path,
    marker: &TestInitialEnrollmentAnchorMarker,
) {
    household_rs::storage::atomic_write_cbor(&registration_status_marker_path(state_dir), marker)
        .unwrap();
}

fn source_segment<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start_index = source.find(start).expect("source start marker present");
    let rest = &source[start_index..];
    let end_index = rest.find(end).expect("source end marker present");
    &rest[..end_index]
}

fn path_has_component(path: &Path, component: &str) -> bool {
    path.components()
        .any(|entry| entry.as_os_str() == std::ffi::OsStr::new(component))
}

fn collect_runtime_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry
            .unwrap_or_else(|e| panic!("read entry under {}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            if path_has_component(&path, "target")
                || path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with('.'))
            {
                continue;
            }
            collect_runtime_rust_sources(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs")
            && path_has_component(&path, "src")
        {
            out.push(path);
        }
    }
}

fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry
            .unwrap_or_else(|e| panic!("read entry under {}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            if path_has_component(&path, "target")
                || path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with('.'))
            {
                continue;
            }
            collect_rust_sources(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn assert_passkey_conversion_only_in_local_attested_helper() {
    let admin_rust_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("server-rs parent is admin/rust")
        .to_path_buf();
    let mut sources = Vec::new();
    collect_runtime_rust_sources(&admin_rust_dir, &mut sources);

    let allowed_path = admin_rust_dir
        .join("household-rs")
        .join("src")
        .join("owner_webauthn.rs");
    let allowed_line = "let passkey: Passkey = verified.credential.into();";
    let dangerous_patterns = [
        "Passkey::from(",
        "Into::<Passkey>",
        ": Passkey =",
        "credential.into()",
    ];
    let mut violations = Vec::new();

    for path in sources {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read runtime source {}: {e}", path.display()));
        for (index, line) in source.lines().enumerate() {
            if !dangerous_patterns
                .iter()
                .any(|pattern| line.contains(pattern))
            {
                continue;
            }
            if path == allowed_path && line.contains(allowed_line) {
                continue;
            }
            violations.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
        }
    }

    assert!(
        violations.is_empty(),
        "Credential -> Passkey conversion must stay allowlisted in the local attested proof-object helper:\n{}",
        violations.join("\n")
    );
}

fn assert_strong_owner_minter_not_called_from_runtime() {
    let admin_rust_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("server-rs parent is admin/rust")
        .to_path_buf();
    let mut sources = Vec::new();
    collect_runtime_rust_sources(&admin_rust_dir, &mut sources);

    let person_cert_path = admin_rust_dir
        .join("household-rs")
        .join("src")
        .join("person_cert.rs");
    let secure_upgrade_path = admin_rust_dir
        .join("household-rs")
        .join("src")
        .join("secure_upgrade.rs");
    let household_lib_path = admin_rust_dir
        .join("household-rs")
        .join("src")
        .join("lib.rs");
    let owner_events_path = admin_rust_dir
        .join("server-rs")
        .join("src")
        .join("handlers_owner_events.rs");
    let household_auth_path = admin_rust_dir
        .join("server-rs")
        .join("src")
        .join("household_auth.rs");
    let household_bootstrap_path = admin_rust_dir
        .join("server-rs")
        .join("src")
        .join("household_bootstrap.rs");
    assert!(
        !sources.is_empty(),
        "secure-upgrade strong-tier source guard must scan real runtime files"
    );
    assert!(
        sources.iter().any(|path| path == &person_cert_path),
        "secure-upgrade strong-tier source guard must include household-rs/src/person_cert.rs"
    );
    assert!(
        sources.iter().any(|path| path == &secure_upgrade_path),
        "secure-upgrade strong-tier source guard must include household-rs/src/secure_upgrade.rs"
    );
    assert!(
        sources.iter().any(|path| path == &owner_events_path),
        "secure-upgrade strong-tier source guard must include server-rs/src/handlers_owner_events.rs"
    );
    assert!(
        sources.iter().any(|path| path == &household_auth_path),
        "secure-upgrade strong-tier source guard must include server-rs/src/household_auth.rs"
    );
    assert!(
        sources.iter().any(|path| path == &household_bootstrap_path),
        "secure-upgrade strong-tier source guard must include server-rs/src/household_bootstrap.rs"
    );
    let mut violations = Vec::new();

    for path in sources {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read runtime source {}: {e}", path.display()));
        for (index, line) in source.lines().enumerate() {
            let contains_direct_minter = line.contains("sign_owner_with_verified_provenance");
            if contains_direct_minter {
                let allowed_person_cert_definition = path == person_cert_path
                    && line.contains("pub fn sign_owner_with_verified_provenance(");
                let allowed_secure_upgrade_wrapper = path == secure_upgrade_path
                    && line.contains("PersonCert::sign_owner_with_verified_provenance(");
                if !allowed_person_cert_definition && !allowed_secure_upgrade_wrapper {
                    violations.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
                    continue;
                }
            }

            let contains_secure_upgrade = line.contains("SecureUpgrade")
                || line.contains("secure_upgrade")
                || line.contains("secure-upgrade")
                || line.contains("secure/upgrade");
            if !contains_secure_upgrade {
                continue;
            }
            let allowed_path = path == secure_upgrade_path
                || path == person_cert_path
                || path == household_lib_path
                || path == owner_events_path
                || path == household_auth_path
                || path == household_bootstrap_path;
            if !allowed_path {
                violations.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Secure/Upgrade strong owner minting must stay confined to the reviewed crypto module, explicit runtime handler, and bootstrap wiring; direct minter calls are only allowed through the crypto wrapper:\n{}",
        violations.join("\n")
    );

    let owner_events_source = fs::read_to_string(&owner_events_path).unwrap();
    assert!(owner_events_source.contains("reviewed-core-v2-secure-upgrade"));
    assert!(owner_events_source.contains("secure_upgrade_strong_minting_enabled"));
    assert!(owner_events_source.contains("secure_upgrade_runtime_or_reject"));
    assert!(owner_events_source.contains("sign_owner_cert_with_secure_upgrade_verification"));
    assert!(!owner_events_source.contains("PersonCert::sign_owner_with_verified_provenance("));

    let bootstrap_source = fs::read_to_string(&household_bootstrap_path).unwrap();
    assert!(bootstrap_source.contains("secure_upgrade_runtime_config_from_env()"));
    assert!(bootstrap_source.contains("with_secure_upgrade_runtime(config)"));
    assert!(bootstrap_source.contains("secure_upgrade_app_attest_start_handler"));
    assert!(bootstrap_source.contains("secure_upgrade_app_attest_finish_handler"));
}

#[test]
fn owner_strong_tier_minting_source_guard_requires_stop_resolution() {
    assert_strong_owner_minter_not_called_from_runtime();
}

#[test]
fn approved_online_signal_source_guard_remains_stop_gated() {
    let server_src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    collect_runtime_rust_sources(&server_src_dir, &mut sources);
    assert!(
        !sources.is_empty(),
        "approved/online source guard must scan real server runtime files"
    );
    assert!(
        sources.iter().any(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "handlers_owner_events.rs")
        }),
        "approved/online source guard must include owner-events runtime source"
    );
    assert!(
        sources.iter().any(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "household_bootstrap.rs")
        }),
        "approved/online source guard must include household bootstrap runtime source"
    );

    let forbidden = [
        "presence_approved",
        "approval_denied",
        "approved_online",
        "PresenceApproved",
        "ApprovalDenied",
        "ApprovedOnline",
    ];
    let mut violations = Vec::new();
    for path in sources {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read server runtime source {}: {e}", path.display()));
        for (index, line) in source.lines().enumerate() {
            for token in forbidden {
                if line.contains(token) {
                    violations.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "approved/online signal remains a STOP; do not wire it in server runtime before the reviewed signal contract lands:\n{}",
        violations.join("\n")
    );
}

#[test]
fn device_pairing_fan_out_gate_source_guard_remains_stop_gated() {
    let device_pairing = include_str!("../src/handlers_device_pairing.rs");
    let approve_handler = source_segment(
        device_pairing,
        "pub async fn device_pairing_approve_handler(",
        "fn validate_request_version(",
    );
    assert!(approve_handler.contains("household_auth::authorize_request"));
    assert!(approve_handler.contains("Operation::HouseholdAddMachine"));
    assert!(approve_handler.contains(".device_pairing_store"));
    assert!(approve_handler.contains(".approve(&request.request_id"));

    for forbidden in [
        "owner_can_fan_out",
        "owner_auth_allows_fan_out",
        "OwnerApprovalEnforcementPolicy",
        "reviewed-core-v2",
        "sign_owner_with_verified_provenance",
    ] {
        assert!(
            !device_pairing.contains(forbidden),
            "device-pairing approve remains a future/default-safe fan-out gate; \
             do not wire {forbidden:?} here until strong-tier minting and a separate \
             rollout policy are reviewed"
        );
    }
}

#[test]
fn household_remote_attach_source_guard_remains_stop_gated() {
    let household_claws = include_str!("../src/handlers_household_claws.rs");
    let public_mint_attach_token = source_segment(
        household_claws,
        "pub async fn handle_household_mint_attach_token(",
        "/// Upgrades a household terminal WebSocket using a single-use attach token.",
    );
    assert!(public_mint_attach_token.contains("is_terminal_attach_peer_allowed"));
    assert!(public_mint_attach_token.contains("Operation::ClawsUse"));
    assert!(public_mint_attach_token.contains("\"mint_attach_token\""));
    assert!(public_mint_attach_token.contains("household_mint_attach_token("));

    let private_mint_attach_token = source_segment(
        household_claws,
        "async fn household_mint_attach_token(",
        "async fn household_terminal_pty(",
    );
    assert!(private_mint_attach_token.contains("require_household_container"));
    assert!(private_mint_attach_token.contains("verify_session_owner"));
    assert!(private_mint_attach_token.contains(".attach_tokens"));
    assert!(private_mint_attach_token.contains(".mint(HouseholdAttachScope"));

    let public_terminal_pty = source_segment(
        household_claws,
        "pub async fn handle_household_terminal_pty(",
        "/// `PoP`-gates stopping a household-scoped instance.",
    );
    assert!(public_terminal_pty.contains("is_terminal_attach_peer_allowed"));
    assert!(public_terminal_pty.contains("household_terminal_pty(&state"));

    let private_terminal_pty = source_segment(
        household_claws,
        "async fn household_terminal_pty(",
        "fn attach_token_from_headers(",
    );
    assert!(private_terminal_pty.contains(".attach_tokens"));
    assert!(private_terminal_pty.contains(".consume(token)"));
    assert!(private_terminal_pty.contains("verify_session_owner"));
    assert!(private_terminal_pty.contains("serve_authorized_terminal_pty"));

    for forbidden in [
        "owner_can_fan_out",
        "owner_auth_allows_fan_out",
        "OwnerApprovalEnforcementPolicy",
        "reviewed-core-v2",
        "sign_owner_with_verified_provenance",
    ] {
        let segments = [
            ("public_mint_attach_token", public_mint_attach_token),
            ("private_mint_attach_token", private_mint_attach_token),
            ("public_terminal_pty", public_terminal_pty),
            ("private_terminal_pty", private_terminal_pty),
        ];
        let offenders = segments
            .iter()
            .filter_map(|(name, segment)| segment.contains(forbidden).then_some(*name))
            .collect::<Vec<_>>();
        assert!(
            offenders.is_empty(),
            "household remote attach remains a future/default-safe fan-out gate; \
             do not wire {forbidden:?} in {offenders:?} until strong-tier minting \
             and a separate rollout policy are reviewed"
        );
    }
}

#[test]
fn product_a_transport_source_guard_does_not_become_owner_tier_authority() {
    let server_src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    collect_runtime_rust_sources(&server_src_dir, &mut sources);
    let product_a_sources = sources
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name == "handlers_claw_share.rs"
                        || name.starts_with("claw_share_relay")
                        || name.starts_with("claw_share_rendezvous")
                        || name.starts_with("relay_stream_")
                })
        })
        .collect::<Vec<_>>();
    assert!(
        !product_a_sources.is_empty(),
        "Product A / relay_stream source guard must scan real runtime files"
    );
    assert!(
        product_a_sources.iter().any(|path| path
            .file_name()
            .is_some_and(|name| name == "handlers_claw_share.rs")),
        "Product A source guard must include handlers_claw_share.rs"
    );
    assert!(
        product_a_sources.iter().any(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("claw_share_relay"))
        }),
        "Product A source guard must include claw_share_relay* runtime sources"
    );
    assert!(
        product_a_sources.iter().any(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("claw_share_rendezvous"))
        }),
        "Product A source guard must include claw_share_rendezvous* runtime sources"
    );
    assert!(
        product_a_sources.iter().any(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("relay_stream_"))
        }),
        "Product A source guard must include relay_stream_* bin entrypoints"
    );

    let forbidden = [
        "owner_can_fan_out",
        "owner_auth_allows_fan_out",
        "sign_owner_with_verified_provenance",
        "OwnerApprovalEnforcementPolicy",
        "THEYOS_OWNER_AUTH_V2_ROLLOUT",
        "reviewed-core-v2",
    ];
    let mut violations = Vec::new();
    for path in product_a_sources {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read Product A runtime source {}: {e}", path.display()));
        for (index, line) in source.lines().enumerate() {
            for token in forbidden {
                if line.contains(token) {
                    violations.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Product A / nvpn / relay_stream must stay post-trust connectivity, not owner-tier authority:\n{}",
        violations.join("\n")
    );
}

#[test]
fn product_a_per_claw_vpn_dev_config_remains_default_off_and_unwired() {
    let server_crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let admin_rust_dir = server_crate_dir
        .parent()
        .expect("server-rs parent is admin/rust")
        .to_path_buf();
    let server_src_dir = server_crate_dir.join("src");
    let mut sources = Vec::new();
    collect_runtime_rust_sources(&server_src_dir, &mut sources);
    assert!(
        !sources.is_empty(),
        "per-Claw VPN source guard must scan real server runtime files"
    );

    let config_path = server_src_dir.join("claw_vpn_dev_config.rs");
    let interface_route_plan_path = server_src_dir.join("claw_vpn_interface_route_plan.rs");
    let packet_pump_path = server_src_dir.join("claw_vpn_packet_pump.rs");
    let pollable_pump_path = server_src_dir.join("claw_vpn_pollable_pump.rs");
    let relay_stream_path = server_src_dir.join("claw_vpn_relay_stream.rs");
    let t1_caller_path = server_src_dir.join("claw_vpn_t1_caller.rs");
    let t1_relay_stream_router_path = server_src_dir.join("claw_vpn_t1_relay_stream_router.rs");
    let target_session_relay_path = server_src_dir.join("claw_vpn_target_session_relay.rs");
    let target_session_router_path = server_src_dir.join("claw_vpn_target_session_router.rs");
    let target_session_runtime_path = server_src_dir.join("claw_vpn_target_session_runtime.rs");
    let relay_stream_responder_reverse_connect_path =
        server_src_dir.join("claw_share_relay_stream_responder_reverse_connect.rs");
    let relay_stream_reverse_connect_binding_path =
        server_src_dir.join("claw_share_relay_stream_reverse_connect_binding.rs");
    let relay_stream_reverse_connect_pool_path =
        server_src_dir.join("claw_share_relay_stream_reverse_connect_pool.rs");
    let relay_stream_runtime_path = server_src_dir.join("claw_share_relay_stream_runtime.rs");
    let relay_stream_mount_path = server_src_dir.join("claw_share_relay_stream_mount.rs");
    let relay_stream_target_router_path =
        server_src_dir.join("claw_share_relay_stream_target_router.rs");
    let t1_phase0_dev_bin_path = server_src_dir.join("bin").join("t1_iptunnel_claw_dev.rs");
    let runtime_path = server_src_dir.join("claw_vpn_runtime.rs");
    let wiring_path = server_src_dir.join("claw_vpn_wiring.rs");
    let startup_wiring_path = server_src_dir.join("startup_wiring.rs");
    let linux_tun_path = server_src_dir.join("claw_vpn_linux_tun.rs");
    let macos_utun_path = server_src_dir.join("claw_vpn_macos_utun.rs");
    let lib_path = server_src_dir.join("lib.rs");
    let e2e_crate_dir = admin_rust_dir.join("e2e-rs");
    let e2e_dev_dep_manifest = e2e_crate_dir.join("Cargo.toml");
    let e2e_runner_src_path = e2e_crate_dir.join("src").join("main.rs");
    let e2e_failure_injection_test_path = e2e_crate_dir
        .join("tests")
        .join("phase3_support")
        .join("failure_injector.rs");
    let e2e_bench_path = e2e_crate_dir.join("benches").join("phase1_identity.rs");
    let mut e2e_sources = Vec::new();
    collect_rust_sources(&e2e_crate_dir, &mut e2e_sources);
    assert!(
        sources.iter().any(|path| path == &config_path),
        "per-Claw VPN source guard must include server-rs/src/claw_vpn_dev_config.rs"
    );
    assert!(
        sources
            .iter()
            .any(|path| path == &interface_route_plan_path),
        "per-Claw VPN source guard must include server-rs/src/claw_vpn_interface_route_plan.rs"
    );
    assert!(
        sources.iter().any(|path| path == &packet_pump_path),
        "per-Claw VPN source guard must include server-rs/src/claw_vpn_packet_pump.rs"
    );
    assert!(
        sources.iter().any(|path| path == &pollable_pump_path),
        "per-Claw VPN source guard must include server-rs/src/claw_vpn_pollable_pump.rs"
    );
    assert!(
        sources.iter().any(|path| path == &relay_stream_path),
        "per-Claw VPN source guard must include server-rs/src/claw_vpn_relay_stream.rs"
    );
    assert!(
        sources.iter().any(|path| path == &t1_caller_path),
        "per-Claw VPN source guard must include server-rs/src/claw_vpn_t1_caller.rs"
    );
    assert!(
        sources
            .iter()
            .any(|path| path == &t1_relay_stream_router_path),
        "per-Claw VPN source guard must include server-rs/src/claw_vpn_t1_relay_stream_router.rs"
    );
    assert!(
        sources
            .iter()
            .any(|path| path == &target_session_relay_path),
        "per-Claw VPN source guard must include server-rs/src/claw_vpn_target_session_relay.rs"
    );
    assert!(
        sources
            .iter()
            .any(|path| path == &target_session_router_path),
        "per-Claw VPN source guard must include server-rs/src/claw_vpn_target_session_router.rs"
    );
    assert!(
        sources
            .iter()
            .any(|path| path == &target_session_runtime_path),
        "per-Claw VPN source guard must include server-rs/src/claw_vpn_target_session_runtime.rs"
    );
    assert!(
        sources
            .iter()
            .any(|path| path == &relay_stream_responder_reverse_connect_path),
        "per-Claw VPN source guard must include server-rs/src/claw_share_relay_stream_responder_reverse_connect.rs"
    );
    assert!(
        sources
            .iter()
            .any(|path| path == &relay_stream_reverse_connect_binding_path),
        "per-Claw VPN source guard must include server-rs/src/claw_share_relay_stream_reverse_connect_binding.rs"
    );
    assert!(
        sources
            .iter()
            .any(|path| path == &relay_stream_reverse_connect_pool_path),
        "per-Claw VPN source guard must include server-rs/src/claw_share_relay_stream_reverse_connect_pool.rs"
    );
    assert!(
        sources
            .iter()
            .any(|path| path == &relay_stream_runtime_path),
        "per-Claw VPN source guard must include server-rs/src/claw_share_relay_stream_runtime.rs"
    );
    assert!(
        sources.iter().any(|path| path == &relay_stream_mount_path),
        "per-Claw VPN source guard must include server-rs/src/claw_share_relay_stream_mount.rs"
    );
    assert!(
        sources
            .iter()
            .any(|path| path == &relay_stream_target_router_path),
        "per-Claw VPN source guard must include server-rs/src/claw_share_relay_stream_target_router.rs"
    );
    assert!(
        sources.iter().any(|path| path == &runtime_path),
        "per-Claw VPN source guard must include server-rs/src/claw_vpn_runtime.rs"
    );
    assert!(
        sources.iter().any(|path| path == &wiring_path),
        "per-Claw VPN source guard must include server-rs/src/claw_vpn_wiring.rs"
    );
    assert!(
        sources.iter().any(|path| path == &startup_wiring_path),
        "per-Claw VPN source guard must include server-rs/src/startup_wiring.rs for the default-off startup gate"
    );
    assert!(
        sources.iter().any(|path| path == &linux_tun_path),
        "per-Claw VPN source guard must include server-rs/src/claw_vpn_linux_tun.rs"
    );
    assert!(
        sources.iter().any(|path| path == &macos_utun_path),
        "per-Claw VPN source guard must include server-rs/src/claw_vpn_macos_utun.rs"
    );
    assert!(
        sources.iter().any(|path| path == &lib_path),
        "per-Claw VPN source guard must include server-rs/src/lib.rs"
    );
    assert!(
        e2e_dev_dep_manifest.exists(),
        "per-Claw VPN source guard must anchor e2e-rs because it has a server-rs dev-dependency"
    );
    let e2e_manifest_source = fs::read_to_string(&e2e_dev_dep_manifest).unwrap_or_else(|e| {
        panic!(
            "read per-Claw VPN e2e manifest {}: {e}",
            e2e_dev_dep_manifest.display()
        )
    });
    let mut in_e2e_dev_dependencies = false;
    let e2e_manifest_has_server_rs_dev_dep = e2e_manifest_source.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_e2e_dev_dependencies = trimmed == "[dev-dependencies]";
            return false;
        }
        if !in_e2e_dev_dependencies {
            return false;
        }
        let code = trimmed.split('#').next().unwrap_or("").trim();
        code.strip_prefix("server-rs")
            .is_some_and(|rest| rest.trim_start().starts_with('='))
    });
    assert!(
        e2e_manifest_has_server_rs_dev_dep,
        "per-Claw VPN e2e guard must stay anchored while e2e-rs can reach server-rs as a dev-dependency"
    );
    assert!(
        e2e_sources.iter().any(|path| path == &e2e_runner_src_path),
        "per-Claw VPN source guard must scan e2e-rs/src"
    );
    assert!(
        e2e_sources
            .iter()
            .any(|path| path == &e2e_failure_injection_test_path),
        "per-Claw VPN source guard must scan e2e-rs tests that can reach server-rs via dev-dependency"
    );
    assert!(
        e2e_sources.iter().any(|path| path == &e2e_bench_path),
        "per-Claw VPN source guard must scan e2e-rs benches"
    );
    let lib_source = fs::read_to_string(&lib_path).unwrap_or_else(|e| {
        panic!(
            "read per-Claw VPN runtime source {}: {e}",
            lib_path.display()
        )
    });
    let lib_lines = lib_source.lines().map(str::trim).collect::<Vec<_>>();
    let dev_only_cfg = "#[cfg(any(test, feature = \"dev_t1_datapath\"))]";
    for module in [
        "pub mod claw_vpn_interface_route_plan;",
        "pub mod claw_vpn_packet_pump;",
        "pub mod claw_vpn_relay_stream;",
        "pub mod claw_vpn_t1_caller;",
        "pub mod claw_vpn_t1_relay_stream_router;",
        "pub mod claw_vpn_target_session_relay;",
        "pub mod claw_vpn_target_session_router;",
        "pub mod claw_vpn_target_session_runtime;",
        "pub mod claw_vpn_runtime;",
        "pub mod claw_vpn_wiring;",
    ] {
        let matches = lib_lines
            .iter()
            .enumerate()
            .filter(|(_, line)| **line == module)
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "{module} must have exactly one export");
        let (index, _) = matches[0];
        assert!(
            index > 0 && lib_lines[index - 1] == dev_only_cfg,
            "{module} must compile only for tests or the explicit DEV datapath feature"
        );
    }
    for (module, required_cfg) in [
        (
            "pub mod claw_vpn_linux_tun;",
            "#[cfg(all(any(test, feature = \"dev_t1_datapath\"), target_os = \"linux\"))]",
        ),
        (
            "pub mod claw_vpn_macos_utun;",
            "#[cfg(all(any(test, feature = \"dev_t1_datapath\"), target_os = \"macos\"))]",
        ),
    ] {
        let matches = lib_lines
            .iter()
            .enumerate()
            .filter(|(_, line)| **line == module)
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "{module} must have exactly one export");
        let (index, _) = matches[0];
        assert!(
            index > 0 && lib_lines[index - 1] == required_cfg,
            "{module} must be both DEV/test-only and target-specific"
        );
    }

    fn rust_guard_lexer_unsupported_reason(lines: &[&str]) -> Option<String> {
        for (line_index, line) in lines.iter().enumerate() {
            let mut chars = line.char_indices().peekable();
            let mut in_string = false;
            let mut escaped = false;
            while let Some((_, ch)) = chars.next() {
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if ch == '\\' {
                        escaped = true;
                    } else if ch == '"' {
                        in_string = false;
                    }
                    continue;
                }
                if ch == '/' && chars.peek().is_some_and(|(_, next)| *next == '/') {
                    break;
                }
                if ch == '/' && chars.peek().is_some_and(|(_, next)| *next == '*') {
                    return Some("block comments".to_string());
                }
                if ch == '*' && chars.peek().is_some_and(|(_, next)| *next == '/') {
                    return Some("block comments".to_string());
                }
                if ch == 'r' {
                    let mut raw_candidate = chars.clone();
                    while raw_candidate
                        .peek()
                        .is_some_and(|(_, candidate)| *candidate == '#')
                    {
                        raw_candidate.next();
                    }
                    if raw_candidate
                        .peek()
                        .is_some_and(|(_, candidate)| *candidate == '"')
                    {
                        return Some("raw strings".to_string());
                    }
                }
                if ch == '\'' {
                    let mut char_candidate = chars.clone();
                    let mut escaped_char = false;
                    let mut contains_brace = false;
                    let mut contains_double_quote = false;
                    while let Some((_, candidate)) = char_candidate.next() {
                        if escaped_char {
                            contains_double_quote |= candidate == '"';
                            escaped_char = false;
                            continue;
                        }
                        if candidate == '\\' {
                            escaped_char = true;
                            continue;
                        }
                        if candidate == '\'' {
                            if contains_brace {
                                return Some("brace char literals".to_string());
                            }
                            if contains_double_quote {
                                return Some("double-quote char literals".to_string());
                            }
                            break;
                        }
                        contains_double_quote |= candidate == '"';
                        contains_brace |= candidate == '{' || candidate == '}';
                    }
                }
                if ch == '"' {
                    in_string = true;
                }
            }
            if in_string {
                return Some(format!(
                    "multiline strings starting on line {}",
                    line_index + 1
                ));
            }
        }
        None
    }

    fn assert_rust_guard_lexer_supported(module_label: &str, lines: &[&str]) {
        if let Some(reason) = rust_guard_lexer_unsupported_reason(lines) {
            panic!("per-Claw VPN {module_label} guard lexer does not support {reason}");
        }
    }

    fn rust_brace_delta_outside_strings(line: &str) -> isize {
        let mut delta = 0;
        let mut chars = line.chars().peekable();
        let mut in_string = false;
        let mut escaped = false;
        while let Some(ch) = chars.next() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }
            if ch == '/' && chars.peek() == Some(&'/') {
                break;
            }
            if ch == '"' {
                in_string = true;
            } else if ch == '{' {
                delta += 1;
            } else if ch == '}' {
                delta -= 1;
            }
        }
        delta
    }

    fn rust_test_module_span(module_label: &str, lines: &[&str]) -> (usize, usize) {
        assert_rust_guard_lexer_supported(module_label, lines);
        let test_markers = lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| (line.trim() == "#[cfg(test)]").then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(
            test_markers.len(),
            1,
            "per-Claw VPN {module_label} guard expects one explicit cfg(test) boundary"
        );
        let test_start = test_markers[0];
        assert_eq!(
            lines.get(test_start + 1).map(|line| line.trim()),
            Some("mod tests {"),
            "per-Claw VPN {module_label} cfg(test) boundary must immediately guard the test module"
        );
        let mut brace_depth = 0isize;
        let mut test_end = None;
        for (line_index, line) in lines.iter().enumerate().skip(test_start + 1) {
            brace_depth += rust_brace_delta_outside_strings(line);
            assert!(
                brace_depth >= 0,
                "per-Claw VPN {module_label} test module has unbalanced braces"
            );
            if brace_depth == 0 {
                test_end = Some(line_index);
                break;
            }
        }
        let test_end = test_end.expect("per-Claw VPN test module must close before EOF");
        let trailing_runtime_items = lines
            .iter()
            .skip(test_end + 1)
            .any(|line| !line.trim().is_empty() && !line.trim().starts_with("//"));
        assert!(
            !trailing_runtime_items,
            "per-Claw VPN {module_label} test module must remain the final item"
        );
        (test_start, test_end)
    }

    fn assert_rust_guard_lexer_rejects(_module_label: &str, lines: &[&str]) {
        assert!(
            rust_guard_lexer_unsupported_reason(lines).is_some(),
            "per-Claw VPN guard lexer fixture should reject unsupported syntax"
        );
    }

    assert_rust_guard_lexer_supported(
        "fixture",
        &[
            r#"fn ok<'a>() { let debug = format!("{value:?}"); }"#,
            "// raw-looking r\" text in comments is ignored",
        ],
    );
    assert_rust_guard_lexer_rejects("fixture", &["let _ = /* unsupported */ 1;"]);
    assert_rust_guard_lexer_rejects("fixture", &[r#"let _ = r"{ unsupported }";"#]);
    assert_rust_guard_lexer_rejects("fixture", &["let _ = '{';"]);
    assert_rust_guard_lexer_rejects("fixture", &[r#"let _ = { let _ = '"'; }; let _ = '"';"#]);
    assert_rust_guard_lexer_rejects("fixture", &[r#"let _ = { let _ = '\"'; }; let _ = '\"';"#]);
    assert_rust_guard_lexer_rejects("fixture", &[r#"let _ = { let _ = b'"'; }; let _ = b'"';"#]);
    assert_rust_guard_lexer_rejects("fixture", &["let _ = \"unterminated;"]);

    let relay_stream_mount_source =
        fs::read_to_string(&relay_stream_mount_path).unwrap_or_else(|e| {
            panic!(
                "read per-Claw VPN relay-stream mount source {}: {e}",
                relay_stream_mount_path.display()
            )
        });
    let relay_stream_mount_lines = relay_stream_mount_source.lines().collect::<Vec<_>>();
    let relay_stream_mount_test_span =
        rust_test_module_span("relay-stream mount", &relay_stream_mount_lines);
    let relay_stream_mount_non_test_source = relay_stream_mount_lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            (index < relay_stream_mount_test_span.0 || index > relay_stream_mount_test_span.1)
                .then_some(*line)
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        relay_stream_mount_source
            .matches("PerClawVpnT1PreflightEvidence::missing")
            .count(),
        1,
        "per-Claw VPN relay-stream mount must keep exactly one fail-closed missing-preflight fallback"
    );
    assert_eq!(
        relay_stream_mount_source
            .matches("load_per_claw_vpn_t1_preflight_evidence_record_for_current_build(")
            .count(),
        1,
        "per-Claw VPN relay-stream mount must bind evidence through the reviewed current-build SHA loader"
    );
    for forbidden_preflight_token in [
        "PerClawVpnT1PreflightEvidence::new",
        "PreflightEvidencePresent",
        "per_claw_vpn_startup_gate_with_preflight",
        "load_per_claw_vpn_t1_preflight_evidence_record(",
        "load_per_claw_vpn_t1_preflight_evidence_record_for_build_sha",
        "parse_per_claw_vpn_t1_preflight_evidence_record",
        "PerClawVpnT1PreflightEvidenceLoadError",
        "PER_CLAW_VPN_T1_PREFLIGHT_EVIDENCE_SCHEMA",
        "per_claw_vpn_t1_preflight_evidence_v1",
    ] {
        assert!(
            !relay_stream_mount_non_test_source.contains(forbidden_preflight_token),
            "per-Claw VPN relay-stream mount must not use unreviewed T1 preflight evidence symbols: {forbidden_preflight_token}"
        );
    }
    for forbidden_audit_export_token in [
        "claw_vpn_t1_keyed_audit_export_jsonl",
        "ClawVpnT1AuditExportHmacKey",
        "CLAW_VPN_T1_AUDIT_EXPORT_HMAC_KEY_BYTES",
        "member_id_keyed_hash",
        "device_pub_keyed_hash",
        "claw_id_keyed_hash",
    ] {
        assert!(
            !relay_stream_mount_source.contains(forbidden_audit_export_token),
            "per-Claw VPN relay-stream mount must not wire T1 off-host audit export symbols: {forbidden_audit_export_token}"
        );
    }

    let mut violations = Vec::new();
    for path in sources {
        if path == t1_phase0_dev_bin_path {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read per-Claw VPN runtime source {}: {e}", path.display()));
        let lines = source.lines().collect::<Vec<_>>();
        let packet_pump_test_span = if path == packet_pump_path {
            Some(rust_test_module_span("packet pump", &lines))
        } else {
            None
        };
        let pollable_pump_test_span = if path == pollable_pump_path {
            Some(rust_test_module_span("pollable pump", &lines))
        } else {
            None
        };
        let runtime_test_span = if path == runtime_path {
            Some(rust_test_module_span("runtime coordinator", &lines))
        } else {
            None
        };
        let wiring_test_span = if path == wiring_path {
            Some(rust_test_module_span("runtime wiring assembly", &lines))
        } else {
            None
        };
        let target_session_router_test_span = if path == target_session_router_path {
            Some(rust_test_module_span(
                "target-session router adapter",
                &lines,
            ))
        } else {
            None
        };
        let target_session_runtime_test_span = if path == target_session_runtime_path {
            Some(rust_test_module_span(
                "target-session runtime bridge",
                &lines,
            ))
        } else {
            None
        };
        let t1_relay_stream_router_test_span = if path == t1_relay_stream_router_path {
            Some(rust_test_module_span("T1 relay-stream router", &lines))
        } else {
            None
        };
        for (index, line) in lines.iter().enumerate() {
            let module_export = path == lib_path && line.trim() == "pub mod claw_vpn_dev_config;";
            let interface_route_plan_module_export =
                path == lib_path && line.trim() == "pub mod claw_vpn_interface_route_plan;";
            let packet_pump_module_export =
                path == lib_path && line.trim() == "pub mod claw_vpn_packet_pump;";
            let pollable_pump_module_export =
                path == lib_path && line.trim() == "pub mod claw_vpn_pollable_pump;";
            let relay_stream_module_export =
                path == lib_path && line.trim() == "pub mod claw_vpn_relay_stream;";
            let target_session_relay_module_export =
                path == lib_path && line.trim() == "pub mod claw_vpn_target_session_relay;";
            let target_session_router_module_export =
                path == lib_path && line.trim() == "pub mod claw_vpn_target_session_router;";
            let t1_caller_module_export =
                path == lib_path && line.trim() == "pub mod claw_vpn_t1_caller;";
            let t1_relay_stream_router_module_export =
                path == lib_path && line.trim() == "pub mod claw_vpn_t1_relay_stream_router;";
            let target_session_runtime_module_export =
                path == lib_path && line.trim() == "pub mod claw_vpn_target_session_runtime;";
            let runtime_module_export =
                path == lib_path && line.trim() == "pub mod claw_vpn_runtime;";
            let wiring_module_export =
                path == lib_path && line.trim() == "pub mod claw_vpn_wiring;";
            let linux_tun_module_export =
                path == lib_path && line.trim() == "pub mod claw_vpn_linux_tun;";
            let macos_utun_module_export =
                path == lib_path && line.trim() == "pub mod claw_vpn_macos_utun;";
            let in_config_module = path == config_path;
            let in_interface_route_plan_module = path == interface_route_plan_path;
            let in_packet_pump_module = path == packet_pump_path;
            let in_pollable_pump_module = path == pollable_pump_path;
            let in_relay_stream_module = path == relay_stream_path;
            let in_t1_caller_module = path == t1_caller_path;
            let in_t1_relay_stream_router_module = path == t1_relay_stream_router_path;
            let in_target_session_relay_module = path == target_session_relay_path;
            let in_target_session_router_module = path == target_session_router_path;
            let in_target_session_runtime_module = path == target_session_runtime_path;
            let in_relay_stream_responder_reverse_connect_module =
                path == relay_stream_responder_reverse_connect_path;
            let in_relay_stream_reverse_connect_binding_module =
                path == relay_stream_reverse_connect_binding_path;
            let in_relay_stream_reverse_connect_pool_module =
                path == relay_stream_reverse_connect_pool_path;
            let in_relay_stream_runtime_module = path == relay_stream_runtime_path;
            let in_relay_stream_mount_module = path == relay_stream_mount_path;
            let in_relay_stream_target_router_module = path == relay_stream_target_router_path;
            let in_runtime_module = path == runtime_path;
            let in_wiring_module = path == wiring_path;
            let in_startup_wiring_module = path == startup_wiring_path;
            let in_linux_tun_module = path == linux_tun_path;
            let in_macos_utun_module = path == macos_utun_path;
            let in_packet_pump_tests = in_packet_pump_module
                && matches!(packet_pump_test_span, Some((start, end)) if index >= start && index <= end);
            let in_pollable_pump_tests = in_pollable_pump_module
                && matches!(pollable_pump_test_span, Some((start, end)) if index >= start && index <= end);
            let in_runtime_tests = in_runtime_module
                && matches!(runtime_test_span, Some((start, end)) if index >= start && index <= end);
            let in_wiring_tests = in_wiring_module
                && matches!(wiring_test_span, Some((start, end)) if index >= start && index <= end);
            let in_target_session_router_tests = in_target_session_router_module
                && matches!(target_session_router_test_span, Some((start, end)) if index >= start && index <= end);
            let in_target_session_runtime_tests = in_target_session_runtime_module
                && matches!(target_session_runtime_test_span, Some((start, end)) if index >= start && index <= end);
            let in_t1_relay_stream_router_tests = in_t1_relay_stream_router_module
                && matches!(t1_relay_stream_router_test_span, Some((start, end)) if index >= start && index <= end);
            let in_relay_stream_mount_tests = in_relay_stream_mount_module
                && index >= relay_stream_mount_test_span.0
                && index <= relay_stream_mount_test_span.1;
            let line_without_allowed_relay_stream_mount_audit_root_env =
                if in_relay_stream_mount_module {
                    line.replace("CLAW_VPN_T1_PREFLIGHT_EVIDENCE_RECORD_ENV", "")
                        .replace("THEYOS_CLAW_VPN_T1_PREFLIGHT_EVIDENCE_RECORD", "")
                } else {
                    (*line).to_owned()
                };
            let references_dev_config = line_without_allowed_relay_stream_mount_audit_root_env
                .contains("ClawVpnDevConfig")
                || line_without_allowed_relay_stream_mount_audit_root_env
                    .contains("claw_vpn_dev_config");
            let references_dev_flag =
                line_without_allowed_relay_stream_mount_audit_root_env.contains("THEYOS_CLAW_VPN_");
            let references_interface_route_plan = line.contains("ClawVpnInterfaceRoute")
                || line.contains("ClawVpnInterfaceName")
                || line.contains("claw_vpn_interface_route_plan");
            let references_packet_pump = line.contains("ClawVpnPacketPump")
                || line.contains("ClawVpnPacketInterface")
                || line.contains("ClawVpnPacketRelay")
                || line.contains("claw_vpn_packet_pump")
                || line.contains("ClawVpnPollablePump")
                || line.contains("claw_vpn_pollable_pump");
            let references_relay_stream_adapter =
                line.contains("ClawVpnRelayStream") || line.contains("claw_vpn_relay_stream");
            let references_target_session_relay_adapter = line
                .contains("ClawVpnTargetSessionRelay")
                || line.contains("claw_vpn_target_session_relay");
            let references_target_session_router_adapter = line
                .contains("ClawVpnTargetSessionRouter")
                || line.contains("claw_vpn_target_session_router");
            let references_t1_caller_gate = line.contains("ClawVpnT1CallerStatus")
                || line.contains("ClawVpnT1Ready")
                || line.contains("ClawVpnT1CallerReadySeal")
                || line.contains("ClawVpnT1TargetSessionRouter")
                || line.contains("ClawVpnT1RelayStream")
                || line.contains("assemble_claw_vpn_t1_caller")
                || line.contains("assemble_claw_vpn_t1_target_session_router")
                || line.contains("assemble_claw_vpn_t1_target_session_router_factory")
                || line.contains("assemble_claw_vpn_t1_relay_stream_router")
                || line.contains("claw_vpn_t1_relay_stream_router")
                || line.contains("claw_vpn_t1_caller");
            let references_t1_relay_stream_audit_sink = line
                .contains("claw_vpn_t1_spooled_jsonl_audit_sink")
                || line.contains("claw_vpn_t1_canonical_audit_log_path")
                || line.contains("claw_vpn_t1_keyed_audit_export_jsonl")
                || line.contains("ClawVpnT1AuditExportHmacKey")
                || line.contains("ClawVpnT1AuditSinkError")
                || line.contains("CLAW_VPN_T1_AUDIT_SINK_QUEUE_CAPACITY")
                || line.contains("CLAW_VPN_T1_AUDIT_LOG_ROTATE_BYTES")
                || line.contains("CLAW_VPN_T1_AUDIT_LOG_RETAINED_FILES")
                || line.contains("CLAW_VPN_T1_AUDIT_EXPORT_HMAC_KEY_BYTES")
                || line.contains("CLAW_VPN_T1_AUDIT_LOG_DIRECTORY_NAME")
                || line.contains("CLAW_VPN_T1_AUDIT_LOG_FILE_NAME");
            let references_t1_relay_stream_mount_audit_sink = line
                .contains("claw_vpn_t1_spooled_jsonl_audit_sink")
                || line.contains("claw_vpn_t1_canonical_audit_log_path")
                || line.contains("ClawVpnT1AuditSinkError")
                || line.contains("CLAW_VPN_T1_AUDIT_LOG_DIRECTORY_NAME")
                || line.contains("CLAW_VPN_T1_AUDIT_LOG_FILE_NAME");
            let references_target_session_runtime_bridge = line
                .contains("ClawVpnTargetSessionRuntime")
                || line.contains("claw_vpn_target_session_runtime");
            let references_ip_tunnel_target_backend = line.contains("new_with_ip_tunnel_router")
                || line.contains("ip_tunnel_router")
                || line.contains("RelayStreamIpTunnelRouter")
                || line.contains("RelayStreamIpTunnelTarget")
                || line.contains("RelayStreamIpTunnelUnavailableRouter")
                || line.contains("bind_relay_stream_reverse_connect_with_ip_tunnel_router")
                || line.contains("assemble_relay_stream_live_with_ip_tunnel_router");
            let references_t1_preflight_gate = line.contains("PerClawVpnT1PreflightEvidence")
                || line.contains("per_claw_vpn_startup_gate_with_preflight")
                || line.contains("PreflightEvidencePresent");
            let references_t1_preflight_evidence_record = line
                .contains("load_per_claw_vpn_t1_preflight_evidence_record")
                || line.contains("parse_per_claw_vpn_t1_preflight_evidence_record")
                || line.contains("PerClawVpnT1PreflightEvidenceBundle")
                || line.contains("PerClawVpnT1PreflightEvidenceLoadError")
                || line.contains("PER_CLAW_VPN_T1_PREFLIGHT_EVIDENCE_SCHEMA")
                || line.contains("per_claw_vpn_t1_preflight_evidence_v1");
            let allowed_tun_packet_interface_adapter = (in_linux_tun_module
                || in_macos_utun_module)
                && (line.contains("ClawVpnPacketInterface")
                    || line.contains("ClawVpnPollablePacketInterface"))
                && !line.contains("ClawVpnPacketPump")
                && !line.contains("ClawVpnPollablePump")
                && !line.contains("ClawVpnPacketRelay")
                && !line.contains("ClawVpnPacketPumpLoop");
            let allowed_relay_stream_packet_relay_adapter = in_relay_stream_module
                && line.contains("ClawVpnPacketRelay")
                && !line.contains("ClawVpnPacketPump")
                && !line.contains("ClawVpnPacketInterface")
                && !line.contains("ClawVpnPacketPumpLoop");
            let allowed_target_session_relay_packet_relay_adapter = in_target_session_relay_module
                && (line.contains("ClawVpnPacketRelay")
                    || line.contains("ClawVpnPollablePacketRelay"))
                && !line.contains("ClawVpnPacketPump")
                && !line.contains("ClawVpnPollablePump")
                && !line.contains("ClawVpnPacketInterface")
                && !line.contains("ClawVpnPacketPumpLoop");
            let allowed_target_session_relay_stream_adapter =
                in_target_session_relay_module && references_relay_stream_adapter;
            let allowed_target_session_router_packet_interface = in_target_session_router_module
                && (((line.contains("ClawVpnPacketInterface")
                    || line.contains("ClawVpnPollablePacketInterface"))
                    && !line.contains("ClawVpnPacketPump")
                    && !line.contains("ClawVpnPollablePump")
                    && !line.contains("ClawVpnPacketRelay")
                    && !line.contains("ClawVpnPacketPumpLoop"))
                    || in_target_session_router_tests);
            let allowed_target_session_router_relay_stream_adapter =
                in_target_session_router_module && references_relay_stream_adapter;
            let allowed_target_session_router_runtime_bridge =
                in_target_session_router_module && references_target_session_runtime_bridge;
            let allowed_target_session_runtime_packet_interface = in_target_session_runtime_module
                && (((line.contains("ClawVpnPacketInterface")
                    || line.contains("ClawVpnPollablePacketInterface"))
                    && !line.contains("ClawVpnPacketPump")
                    && !line.contains("ClawVpnPollablePump")
                    && !line.contains("ClawVpnPacketRelay")
                    && !line.contains("ClawVpnPacketPumpLoop"))
                    || in_target_session_runtime_tests);
            let allowed_target_session_runtime_relay_stream_adapter =
                in_target_session_runtime_module && references_relay_stream_adapter;
            let allowed_target_session_runtime_relay_pair =
                in_target_session_runtime_module && references_target_session_relay_adapter;
            let allowed_target_session_router_relay_pair =
                in_target_session_router_module && references_target_session_relay_adapter;
            let allowed_t1_relay_stream_router_relay_pair =
                in_t1_relay_stream_router_module && references_target_session_relay_adapter;
            let allowed_t1_relay_stream_router_packet_interface = in_t1_relay_stream_router_module
                && (((line.contains("ClawVpnPacketInterface")
                    || line.contains("ClawVpnPollablePacketInterface"))
                    && !line.contains("ClawVpnPacketPump")
                    && !line.contains("ClawVpnPollablePump")
                    && !line.contains("ClawVpnPacketRelay")
                    && !line.contains("ClawVpnPacketPumpLoop"))
                    || in_t1_relay_stream_router_tests);
            let allowed_relay_stream_mount_packet_interface = in_relay_stream_mount_module
                && line.contains("ClawVpnPacketInterface")
                && !line.contains("ClawVpnPacketPump")
                && !line.contains("ClawVpnPacketRelay")
                && !line.contains("ClawVpnPacketPumpLoop");
            let allowed_t1_relay_stream_router_relay_stream_adapter =
                in_t1_relay_stream_router_module && references_relay_stream_adapter;
            let allowed_t1_relay_stream_router_target_session_router =
                in_t1_relay_stream_router_module && references_target_session_router_adapter;
            let allowed_relay_stream_mount_target_session_router =
                in_relay_stream_mount_module && references_target_session_router_adapter;
            let allowed_t1_relay_stream_router_target_session_runtime =
                in_t1_relay_stream_router_module && references_target_session_runtime_bridge;
            let line_without_target_session_runtime_wiring = if in_target_session_runtime_module
                || in_target_session_router_module
                || in_t1_relay_stream_router_module
                || in_relay_stream_mount_module
            {
                line.replace("ClawVpnRuntimeWiring", "")
                    .replace("try_assemble_claw_vpn_runtime_wiring_deferred", "")
                    .replace("claw_vpn_wiring", "")
            } else {
                (*line).to_owned()
            };
            let references_runtime = line_without_target_session_runtime_wiring
                .contains("ClawVpnRuntime")
                || line_without_target_session_runtime_wiring.contains("claw_vpn_runtime")
                || line_without_target_session_runtime_wiring.contains("CLAW_VPN_RUNTIME");
            let references_wiring =
                line.contains("ClawVpnRuntimeWiring") || line.contains("claw_vpn_wiring");
            let allowed_t1_relay_stream_router_wiring =
                in_t1_relay_stream_router_module && references_wiring;
            let allowed_relay_stream_mount_wiring =
                in_relay_stream_mount_module && references_wiring;
            let references_linux_tun = line.contains("ClawVpnLinuxTun")
                || line.contains("claw_vpn_linux_tun")
                || line.contains("/dev/net/tun")
                || line.contains("TUNSETIFF")
                || line.contains("IFF_TUN")
                || line.contains("IFF_TUN_EXCL")
                || line.contains("IFF_NO_PI");
            let references_macos_utun = line.contains("ClawVpnMacosUtun")
                || line.contains("claw_vpn_macos_utun")
                || line.contains("utun_control")
                || line.contains("CTLIOCGINFO")
                || line.contains("UTUN_OPT_IFNAME")
                || line.contains("sockaddr_ctl")
                || line.contains("PF_SYSTEM")
                || line.contains("AF_SYSTEM")
                || line.contains("AF_SYS_CONTROL")
                || line.contains("SYSPROTO_CONTROL");
            let references_datapath_runtime = line.contains("ClawVpnDatapath")
                || line.contains("ClawVpnAgentCore")
                || line.contains("ClawVpnAgentSessionCore")
                || line.contains("ClawVpnSessionRegistry")
                || line.contains("ClawVpnSessionId")
                || line.contains("ClawVpnAuditEvent");
            let line_without_allowed_datapath_side = line.replace("ClawVpnDatapathSide", "");
            let line_without_wiring_allowed_datapath = line
                .replace("ClawVpnAgentSessionCore", "")
                .replace("ClawVpnDatapathSide", "");
            let line_without_target_session_runtime_allowed_datapath = line
                .replace("ClawVpnAgentSessionCore", "")
                .replace("ClawVpnDatapathSide", "");
            let references_disallowed_packet_pump_datapath_runtime = line
                .contains("ClawVpnAgentCore")
                || line_without_allowed_datapath_side.contains("ClawVpnDatapath")
                || line.contains("ClawVpnSessionRegistry")
                || line.contains("ClawVpnSessionId");
            let allowed_packet_pump_datapath_runtime = in_packet_pump_tests
                || (in_packet_pump_module
                    && !references_disallowed_packet_pump_datapath_runtime
                    && (line.contains("ClawVpnAgentSessionCore")
                        || line.contains("ClawVpnAuditEvent")
                        || line.contains("ClawVpnDatapathSide")));
            let allowed_pollable_pump_datapath_runtime = in_pollable_pump_tests
                || (in_pollable_pump_module
                    && !references_disallowed_packet_pump_datapath_runtime
                    && (line.contains("ClawVpnAgentSessionCore")
                        || line.contains("ClawVpnAuditEvent")
                        || line.contains("ClawVpnDatapathSide")));
            let allowed_runtime_datapath_runtime = in_runtime_tests;
            let allowed_wiring_datapath_runtime = in_wiring_tests
                || (in_wiring_module
                    && !line_without_wiring_allowed_datapath.contains("ClawVpnDatapath")
                    && !line.contains("ClawVpnAgentCore")
                    && !line.contains("ClawVpnSessionRegistry")
                    && !line.contains("ClawVpnSessionId")
                    && !line.contains("ClawVpnAuditEvent")
                    && (line.contains("ClawVpnAgentSessionCore")
                        || line.contains("ClawVpnDatapathSide")));
            let allowed_target_session_runtime_datapath = in_target_session_runtime_tests
                || (in_target_session_runtime_module
                    && !line_without_target_session_runtime_allowed_datapath
                        .contains("ClawVpnDatapath")
                    && !line.contains("ClawVpnAgentCore")
                    && !line.contains("ClawVpnSessionRegistry")
                    && !line.contains("ClawVpnSessionId")
                    && !line.contains("ClawVpnAuditEvent")
                    && (line.contains("ClawVpnAgentSessionCore")
                        || line.contains("ClawVpnDatapathSide")));
            let allowed_target_session_router_datapath = in_target_session_router_tests;
            let allowed_t1_relay_stream_router_datapath =
                in_t1_relay_stream_router_module && references_datapath_runtime;
            let allowed_startup_wiring_dev_config_gate =
                in_startup_wiring_module && references_dev_config && !references_dev_flag;
            let allowed_t1_caller_dev_config_gate =
                in_t1_caller_module && references_dev_config && !references_dev_flag;
            let allowed_t1_relay_stream_router_dev_config_gate =
                in_t1_relay_stream_router_module && references_dev_config && !references_dev_flag;
            let allowed_relay_stream_mount_dev_config_gate =
                in_relay_stream_mount_module && references_dev_config && !references_dev_flag;
            let allowed_t1_caller_preflight_gate =
                in_t1_caller_module && references_t1_preflight_gate;
            let allowed_t1_relay_stream_router_preflight_gate =
                in_t1_relay_stream_router_module && references_t1_preflight_gate;
            let allowed_relay_stream_mount_preflight_gate =
                in_relay_stream_mount_module && references_t1_preflight_gate;
            let allowed_startup_wiring_preflight_evidence_record =
                in_startup_wiring_module && references_t1_preflight_evidence_record;
            let allowed_relay_stream_mount_preflight_evidence_record = in_relay_stream_mount_module
                && (line
                    .contains("load_per_claw_vpn_t1_preflight_evidence_record_for_current_build")
                    || line.contains("PerClawVpnT1PreflightEvidenceBundle"));
            let allowed_t1_caller_target_session_router =
                in_t1_caller_module && references_target_session_router_adapter;
            let allowed_t1_relay_stream_router_t1_caller_gate =
                in_t1_relay_stream_router_module && references_t1_caller_gate;
            let allowed_t1_relay_stream_router_audit_sink =
                in_t1_relay_stream_router_module && references_t1_relay_stream_audit_sink;
            let allowed_relay_stream_mount_audit_sink =
                in_relay_stream_mount_module && references_t1_relay_stream_mount_audit_sink;
            let allowed_relay_stream_mount_t1_caller_gate =
                in_relay_stream_mount_module && references_t1_caller_gate;
            let allowed_relay_stream_mount_interface_route_plan =
                in_relay_stream_mount_module && references_interface_route_plan;
            let allowed_relay_stream_mount_ip_tunnel_target_backend =
                in_relay_stream_mount_module && references_ip_tunnel_target_backend;
            let allowed_relay_stream_mount_linux_tun =
                in_relay_stream_mount_module && references_linux_tun;
            let allowed_relay_stream_mount_macos_utun =
                in_relay_stream_mount_module && references_macos_utun;
            if (!allowed_packet_pump_datapath_runtime
                && !allowed_pollable_pump_datapath_runtime
                && !allowed_runtime_datapath_runtime
                && !allowed_wiring_datapath_runtime
                && !allowed_target_session_runtime_datapath
                && !allowed_target_session_router_datapath
                && !allowed_t1_relay_stream_router_datapath
                && references_datapath_runtime)
                || (!in_config_module
                    && !module_export
                    && !allowed_startup_wiring_dev_config_gate
                    && !allowed_t1_caller_dev_config_gate
                    && !allowed_t1_relay_stream_router_dev_config_gate
                    && !allowed_relay_stream_mount_dev_config_gate
                    && (references_dev_config || references_dev_flag))
                || (!in_interface_route_plan_module
                    && !in_runtime_module
                    && !in_wiring_module
                    && !(in_target_session_router_module && in_target_session_router_tests)
                    && !(in_target_session_runtime_module && in_target_session_runtime_tests)
                    && !in_t1_relay_stream_router_tests
                    && !allowed_relay_stream_mount_interface_route_plan
                    && !interface_route_plan_module_export
                    && references_interface_route_plan)
                || (!in_packet_pump_module
                    && !in_pollable_pump_module
                    && !in_runtime_module
                    && !in_wiring_module
                    && !packet_pump_module_export
                    && !pollable_pump_module_export
                    && !allowed_tun_packet_interface_adapter
                    && !allowed_relay_stream_packet_relay_adapter
                    && !allowed_target_session_relay_packet_relay_adapter
                    && !allowed_target_session_router_packet_interface
                    && !allowed_target_session_runtime_packet_interface
                    && !allowed_t1_relay_stream_router_packet_interface
                    && !allowed_relay_stream_mount_packet_interface
                    && references_packet_pump)
                || (!in_relay_stream_module
                    && !relay_stream_module_export
                    && !allowed_target_session_relay_stream_adapter
                    && !allowed_target_session_router_relay_stream_adapter
                    && !allowed_target_session_runtime_relay_stream_adapter
                    && !allowed_t1_relay_stream_router_relay_stream_adapter
                    && references_relay_stream_adapter)
                || (!in_target_session_relay_module
                    && !target_session_relay_module_export
                    && !allowed_target_session_runtime_relay_pair
                    && !allowed_target_session_router_relay_pair
                    && !allowed_t1_relay_stream_router_relay_pair
                    && references_target_session_relay_adapter)
                || (!in_target_session_router_module
                    && !allowed_t1_caller_target_session_router
                    && !allowed_t1_relay_stream_router_target_session_router
                    && !allowed_relay_stream_mount_target_session_router
                    && !target_session_router_module_export
                    && references_target_session_router_adapter)
                || (!in_t1_caller_module
                    && !allowed_t1_relay_stream_router_t1_caller_gate
                    && !allowed_relay_stream_mount_t1_caller_gate
                    && !t1_caller_module_export
                    && !t1_relay_stream_router_module_export
                    && references_t1_caller_gate)
                || (!allowed_t1_relay_stream_router_audit_sink
                    && !allowed_relay_stream_mount_audit_sink
                    && references_t1_relay_stream_audit_sink)
                || (!in_target_session_runtime_module
                    && !allowed_target_session_router_runtime_bridge
                    && !allowed_t1_relay_stream_router_target_session_runtime
                    && !target_session_runtime_module_export
                    && references_target_session_runtime_bridge)
                || (!in_relay_stream_target_router_module
                    && !in_t1_relay_stream_router_module
                    && !in_relay_stream_responder_reverse_connect_module
                    && !in_relay_stream_reverse_connect_binding_module
                    && !in_relay_stream_reverse_connect_pool_module
                    && !in_relay_stream_runtime_module
                    && !allowed_relay_stream_mount_ip_tunnel_target_backend
                    && references_ip_tunnel_target_backend)
                || (!in_startup_wiring_module
                    && !allowed_t1_caller_preflight_gate
                    && !allowed_t1_relay_stream_router_preflight_gate
                    && !allowed_relay_stream_mount_preflight_gate
                    && references_t1_preflight_gate)
                || (!allowed_startup_wiring_preflight_evidence_record
                    && !allowed_relay_stream_mount_preflight_evidence_record
                    && !in_relay_stream_mount_tests
                    && references_t1_preflight_evidence_record)
                || (!in_runtime_module
                    && !in_wiring_module
                    && !(in_target_session_router_module && in_target_session_router_tests)
                    && !(in_target_session_runtime_module && in_target_session_runtime_tests)
                    && !runtime_module_export
                    && references_runtime)
                || (!in_wiring_module
                    && !in_target_session_router_module
                    && !in_target_session_runtime_module
                    && !allowed_t1_relay_stream_router_wiring
                    && !allowed_relay_stream_mount_wiring
                    && !wiring_module_export
                    && references_wiring)
                || (!in_linux_tun_module
                    && !linux_tun_module_export
                    && !allowed_relay_stream_mount_linux_tun
                    && references_linux_tun)
                || (!in_macos_utun_module
                    && !macos_utun_module_export
                    && !allowed_relay_stream_mount_macos_utun
                    && references_macos_utun)
            {
                violations.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "per-Claw VPN dev config/interface-route-plan-executor/packet-pump/runtime/TUN/utun/datapath must stay default-off/unwired outside reviewed modules:\n{}",
        violations.join("\n")
    );

    let mut e2e_violations = Vec::new();
    for path in e2e_sources {
        let source = fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("read per-Claw VPN e2e guard source {}: {e}", path.display())
        });
        for (index, line) in source.lines().enumerate() {
            let references_per_claw_vpn_symbol =
                line.contains("ClawVpn") || line.contains("claw_vpn") || line.contains("CLAW_VPN");
            let references_linux_tun = line.contains("ClawVpnLinuxTun")
                || line.contains("claw_vpn_linux_tun")
                || line.contains("/dev/net/tun")
                || line.contains("TUNSETIFF")
                || line.contains("IFF_TUN")
                || line.contains("IFF_TUN_EXCL")
                || line.contains("IFF_NO_PI");
            let references_macos_utun = line.contains("ClawVpnMacosUtun")
                || line.contains("claw_vpn_macos_utun")
                || line.contains("utun_control")
                || line.contains("CTLIOCGINFO")
                || line.contains("UTUN_OPT_IFNAME")
                || line.contains("sockaddr_ctl")
                || line.contains("PF_SYSTEM")
                || line.contains("AF_SYSTEM")
                || line.contains("AF_SYS_CONTROL")
                || line.contains("SYSPROTO_CONTROL");
            if references_per_claw_vpn_symbol || references_linux_tun || references_macos_utun {
                e2e_violations.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
            }
        }
    }

    assert!(
        e2e_violations.is_empty(),
        "per-Claw VPN symbols/TUN/utun wiring must stay out of e2e-rs despite its server-rs dev-dependency:\n{}",
        e2e_violations.join("\n")
    );
}

#[test]
fn t1_phase0_dev_datapath_bypass_is_feature_gated_and_not_mounted() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cargo_toml_path = manifest_dir.join("Cargo.toml");
    let cargo_toml = fs::read_to_string(&cargo_toml_path)
        .unwrap_or_else(|e| panic!("read server Cargo.toml {}: {e}", cargo_toml_path.display()));
    let bin_target = r#"[[bin]]
name = "t1_iptunnel_claw_dev"
path = "src/bin/t1_iptunnel_claw_dev.rs"
required-features = ["dev_t1_datapath"]"#;
    assert!(
        cargo_toml.contains(bin_target),
        "T1 Phase 0 claw dev bypass must be absent from default/product builds"
    );
    assert!(
        cargo_toml.contains(r#"dev_t1_datapath = ["dev_claw_share_mint"]"#),
        "T1 Phase 0 dev datapath feature must be explicit and opt-in"
    );

    let bin_path = manifest_dir.join("src/bin/t1_iptunnel_claw_dev.rs");
    let bin_source = fs::read_to_string(&bin_path)
        .unwrap_or_else(|e| panic!("read T1 Phase 0 dev bin {}: {e}", bin_path.display()));
    for required_token in [
        "PerClawVpnT1PreflightEvidence::new(true, true, true)",
        "THEYOS_T1_DEV_DATAPATH",
        "THEYOS_FORCE_SOFTWARE_KEYS",
        "dev-host T1-T4 only; no production activation",
        "dev-host public relay dial allowed; no production activation",
        "runner_tun_opened=false",
        "runner_route_installed=false",
        "runner_packet_pump_started=false",
    ] {
        assert!(
            bin_source.contains(required_token),
            "T1 Phase 0 dev bin must retain hard dev-only guard token: {required_token}"
        );
    }
    assert!(
        !bin_source.contains("/Applications/Soyeht.app")
            && !bin_source.contains("com.soyeht.mac")
            && !bin_source.contains(":8091"),
        "T1 Phase 0 dev bin must not reference production app/state endpoints"
    );

    let rust_workspace_dir = manifest_dir
        .parent()
        .expect("server-rs manifest has a Rust workspace parent");
    let runner_cargo_toml_path = rust_workspace_dir
        .join("t1-iptunnel-dev-runner-rs")
        .join("Cargo.toml");
    let runner_cargo_toml = fs::read_to_string(&runner_cargo_toml_path).unwrap_or_else(|e| {
        panic!(
            "read runner Cargo.toml {}: {e}",
            runner_cargo_toml_path.display()
        )
    });
    assert!(
        runner_cargo_toml.contains(r#"dev_t1_datapath = ["dep:server-rs"]"#),
        "T1 Phase 0 device-side dev datapath must be an explicit opt-in runner feature"
    );

    let runner_source_path = rust_workspace_dir
        .join("t1-iptunnel-dev-runner-rs")
        .join("src/main.rs");
    let runner_source = fs::read_to_string(&runner_source_path)
        .unwrap_or_else(|e| panic!("read runner source {}: {e}", runner_source_path.display()));
    for required_token in [
        "#[cfg(feature = \"dev_t1_datapath\")]\n    RunDeviceDatapath",
        "#[cfg(feature = \"dev_t1_datapath\")]\nmod dev_datapath",
        "#[cfg(feature = \"dev_t1_datapath\")]\n        Command::RunDeviceDatapath",
        "THEYOS_T1_DEV_DATAPATH",
        "THEYOS_FORCE_SOFTWARE_KEYS",
        "dev-host T1-T4 only; no production activation",
        "dev-host public relay dial allowed; no production activation",
    ] {
        assert!(
            runner_source.contains(required_token),
            "T1 Phase 0 runner must retain hard dev-only guard token: {required_token}"
        );
    }
    assert!(
        !runner_source.contains("/Applications/Soyeht.app")
            && !runner_source.contains("com.soyeht.mac")
            && !runner_source.contains(":8091"),
        "T1 Phase 0 runner must not reference production app/state endpoints"
    );

    let mount_path = manifest_dir.join("src/claw_share_relay_stream_mount.rs");
    let mount_source = fs::read_to_string(&mount_path)
        .unwrap_or_else(|e| panic!("read relay-stream mount {}: {e}", mount_path.display()));
    assert_eq!(
        mount_source
            .matches("PerClawVpnT1PreflightEvidence::missing")
            .count(),
        1,
        "production mount must keep exactly one fail-closed T1 fallback after the reviewed #286 current-build gate is wired"
    );
    assert_eq!(
        mount_source
            .matches("load_per_claw_vpn_t1_preflight_evidence_record_for_current_build(")
            .count(),
        1,
        "production mount must load #286 evidence only through the reviewed current-build SHA gate"
    );
    for required_token in [
        "#[cfg(not(any(test, feature = \"dev_t1_datapath\")))]",
        "assemble_relay_stream_live(inputs, config)",
        "#[cfg(any(test, feature = \"dev_t1_datapath\"))]",
        "assemble_relay_stream_live_with_ip_tunnel_router(",
        "IP_TUNNEL_RESOURCE_COMPILED",
    ] {
        assert!(
            mount_source.contains(required_token),
            "production mount must retain the Phase 0 compile-out branch: {required_token}"
        );
    }
    for forbidden_token in [
        "PerClawVpnT1PreflightEvidence::new",
        "THEYOS_T1_DEV_DATAPATH",
        "THEYOS_FORCE_SOFTWARE_KEYS",
    ] {
        assert!(
            !mount_source.contains(forbidden_token),
            "Phase 0 mount must not contain a runtime DEV bypass token: {forbidden_token}"
        );
    }
}

#[test]
fn owner_webauthn_registration_status_source_guards_read_only_contract() {
    let source = include_str!("../src/handlers_owner_events.rs");
    let status_classifier = source_segment(
        source,
        "fn owner_webauthn_registration_status(",
        "fn reject_owner_webauthn_registration",
    );
    assert!(status_classifier.contains("classify_owner_webauthn_authority_anchor_read_only"));
    assert!(!status_classifier.contains("verify_or_update_owner_webauthn_authority_anchor"));
    assert!(!status_classifier.contains("OwnerWebauthnAnchorMode::MigrationDefaultOff"));

    let status_handler = source_segment(
        source,
        "pub async fn owner_webauthn_registration_status_handler(",
        "/// `POST /api/v1/household/owner-webauthn/registration/start`",
    );
    assert!(status_handler.contains("authorize_owner_webauthn_registration_status_request"));
    assert!(!status_handler.contains("authorize_owner_auth_enroll_initial_request"));
    assert!(!status_handler.contains("HouseholdAddMachine"));

    let pair_machine_policy = source_segment(
        source,
        "fn pair_machine_owner_webauthn_policy_snapshot(",
        "struct OwnerWebauthnRevokeCredentialStartSnapshot",
    );
    assert!(!pair_machine_policy.contains("marker_backed_initial_enrollment_committed"));
}

#[test]
fn owner_webauthn_registration_local_source_guards_fail_closed_boundary() {
    let source = include_str!("../src/handlers_owner_events.rs");
    let rp_source = include_str!("../../household-rs/src/owner_webauthn.rs");
    let rp_runtime_source = rp_source
        .split("#[cfg(test)]")
        .next()
        .expect("runtime source segment exists");
    assert!(source.contains(
        "OWNER_WEBAUTHN_REGISTRATION_LOCAL_START_PATH: &str =\n    \"/api/v1/household/owner-webauthn/registration/local/start\""
    ));
    assert!(rp_runtime_source.contains("mod macos_local_attested_registration"));
    assert!(rp_runtime_source.contains("LocalAttestedRegistration"));
    assert!(rp_runtime_source.contains("AttestationFormat::AppleAnonymous"));
    assert!(rp_runtime_source.contains("AttestationConveyancePreference::Direct"));
    assert!(rp_runtime_source.contains("reject_synchronised_authenticators(true)"));
    assert!(rp_runtime_source.contains("does not expose Apple Anonymous"));
    assert!(rp_runtime_source.contains("APPLE_WEBAUTHN_ROOT_CA_PEM"));
    assert!(rp_runtime_source.contains("APPLE_WEBAUTHN_ROOT_CA_SHA256_FINGERPRINT"));
    assert!(rp_runtime_source.contains("VerifiedLocalAppleAttestedCredential"));
    assert!(rp_runtime_source.contains("fn local_attested_passkey_from_verified_credential"));
    assert_eq!(
        rp_runtime_source
            .matches("let passkey: Passkey = verified.credential.into();")
            .count(),
        1
    );
    assert_passkey_conversion_only_in_local_attested_helper();
    assert!(!rp_runtime_source.contains("AttestationCaList::default()"));
    assert!(!rp_runtime_source.contains("finish_attested_passkey_registration"));
    assert!(!rp_runtime_source.contains("Passkey::from("));
    assert!(!rp_runtime_source.contains("Into::<Passkey>"));
    assert!(source.contains(
        "OWNER_WEBAUTHN_REGISTRATION_LOCAL_FINISH_PATH: &str =\n    \"/api/v1/household/owner-webauthn/registration/local/finish\""
    ));
    assert!(source.contains(
        "OWNER_WEBAUTHN_REGISTRATION_LOCAL_STATUS_PATH: &str =\n    \"/api/v1/household/owner-webauthn/registration/local/status\""
    ));
    let local_router = source_segment(
        source,
        "pub fn owner_webauthn_macos_local_registration_router(",
        "#[derive(Clone, Debug, PartialEq, Eq)]",
    );
    assert!(local_router.contains("OWNER_WEBAUTHN_REGISTRATION_LOCAL_START_PATH"));
    assert!(local_router.contains("OWNER_WEBAUTHN_REGISTRATION_LOCAL_FINISH_PATH"));
    assert!(local_router.contains("OWNER_WEBAUTHN_REGISTRATION_LOCAL_STATUS_PATH"));

    let local_start = source_segment(
        source,
        "pub async fn owner_webauthn_registration_local_start_handler(",
        "/// `POST /api/v1/household/owner-webauthn/registration/local/finish`",
    );
    assert!(local_start.contains("Option<Extension<ConnectInfo<MacosLocalPeerConnectInfo>>>"));
    assert!(local_start.contains("authorize_macos_local_caller"));
    assert!(local_start.contains("BOOTSTRAP_MUTATION_LOCK"));
    assert!(local_start.contains("owner_webauthn_initial_enrollment_policy_snapshot_read_only"));
    assert!(!local_start.contains("owner_webauthn_initial_enrollment_policy_snapshot("));
    assert!(local_start.contains("start_macos_local_attested_registration_from"));
    assert!(!local_start.contains("authorize_owner_auth_enroll_initial_request"));
    assert!(!local_start.contains("authorize_owner_webauthn_registration_status_request"));
    assert!(!local_start.contains("finish_registration"));
    assert!(!local_start.contains("OwnerWebauthnAuthority::sign_genesis"));
    assert!(!local_start.contains(".save("));
    assert!(!local_start.contains("set_owner_auth"));
    assert!(!local_start.contains("verify_or_update_owner_webauthn_authority_anchor"));
    assert!(!local_start.contains("OwnerWebauthnPolicySnapshot"));
    assert!(!local_start.contains("OwnerWebauthnCredentialEventAction::Revoke"));
    assert!(!local_start.contains("OwnerWebauthnRecoveryAuthority"));
    assert!(!local_start.contains("HouseholdAddMachine"));
    assert!(!local_start.contains("AttestationCaList"));
    assert!(!local_start.contains("finish_attested"));
    assert!(
        local_start.find("authorize_macos_local_caller").unwrap()
            < local_start.find("decode_canonical_cbor").unwrap()
    );

    let local_policy_snapshot = source_segment(
        source,
        "fn owner_webauthn_initial_enrollment_policy_snapshot_read_only(",
        "fn require_owner_webauthn_never_enrolled_for_initial_enrollment",
    );
    assert!(local_policy_snapshot.contains("classify_owner_webauthn_authority_anchor_read_only"));
    assert!(!local_policy_snapshot.contains("verify_or_update_owner_webauthn_authority_anchor"));
    assert!(!local_policy_snapshot.contains("OwnerWebauthnAnchorMode::Enforcement"));
    assert!(!local_policy_snapshot.contains("OwnerWebauthnAnchorMode::MigrationDefaultOff"));

    let local_finish = source_segment(
        source,
        "pub async fn owner_webauthn_registration_local_finish_handler(",
        "/// `POST /api/v1/household/owner-webauthn/registration/finish`",
    );
    assert!(local_finish.contains("Option<Extension<ConnectInfo<MacosLocalPeerConnectInfo>>>"));
    assert!(local_finish.contains("authorize_macos_local_caller"));
    assert!(local_finish.contains("local_attestation_constraints_unavailable"));
    assert!(!local_finish.contains("decode_canonical_cbor"));
    assert!(!local_finish.contains("finish_registration"));
    assert!(!local_finish.contains("OwnerWebauthnAuthority::sign_genesis"));
    assert!(!local_finish.contains(".save("));
    assert!(!local_finish.contains("set_owner_auth"));
    assert!(!local_finish.contains("verify_or_update_owner_webauthn_authority_anchor"));
    assert!(!local_finish.contains("AttestationCaList"));
    assert!(!local_finish.contains("finish_attested"));
    assert!(!local_finish.contains("finish_passkey_registration"));
    assert!(!local_finish.contains("finish_macos_local_attested_registration"));

    let local_status = source_segment(
        source,
        "pub async fn owner_webauthn_registration_local_status_handler(",
        "/// `POST /api/v1/household/owner-webauthn/revoke/start`",
    );
    assert!(local_status.contains("Option<Extension<ConnectInfo<MacosLocalPeerConnectInfo>>>"));
    assert!(local_status.contains("authorize_macos_local_caller"));
    assert!(local_status.contains("BOOTSTRAP_MUTATION_LOCK"));
    assert!(local_status.contains("owner_webauthn_registration_status"));
    assert!(!local_status.contains("authorize_owner_auth_enroll_initial_request"));
    assert!(!local_status.contains("authorize_owner_webauthn_registration_status_request"));
    assert!(!local_status.contains("verify_or_update_owner_webauthn_authority_anchor"));
    assert!(!local_status.contains(".save("));
    assert!(
        local_status.find("authorize_macos_local_caller").unwrap()
            < local_status.find("decode_canonical_cbor").unwrap()
    );

    let tcp_start = source_segment(
        source,
        "pub async fn owner_webauthn_registration_start_handler(",
        "/// `POST /api/v1/household/owner-webauthn/registration/local/start`",
    );
    assert!(tcp_start.contains("authorize_owner_auth_enroll_initial_request"));
    assert!(tcp_start.contains("start_registration"));
    assert!(!tcp_start.contains("start_platform_registration"));
    assert!(!tcp_start.contains("start_macos_local_attested_registration_from"));
    assert!(!tcp_start.contains("authorize_macos_local_caller"));

    let tcp_finish = source_segment(
        source,
        "pub async fn owner_webauthn_registration_finish_handler(",
        "let request: OwnerWebauthnRegistrationFinishRequest",
    );
    assert!(tcp_finish.contains("authorize_owner_auth_enroll_initial_request"));
    assert!(!tcp_finish.contains("authorize_macos_local_caller"));

    let router_source = include_str!("../src/household_bootstrap.rs");
    assert!(!router_source.contains("/registration/local/"));
    assert!(!router_source.contains(".merge(owner_webauthn_macos_local_registration_router"));
    assert!(router_source.contains("spawn_macos_local_registration_listener"));
    assert!(router_source.contains("DesignatedRequirementMacosLocalCallerAuth::new"));
    assert!(router_source.contains("macos_local_app_profile_for_state_dir(&state_dir)"));
    assert!(router_source.contains("macos_local_owner_webauthn_registration_state("));
    assert!(
        router_source.contains(".with_owner_webauthn_rp(owner_webauthn_local_registration_rp()?")
    );
    assert!(router_source.contains(
        ".with_owner_webauthn_anchor(owner_webauthn_local_registration_anchor_store(state_dir))"
    ));
    assert!(router_source.contains(".with_macos_local_caller_auth(verifier)"));
    assert!(router_source.contains("fn macos_local_app_profile_for_state_dir"));
    assert!(router_source.contains("MacosLocalAppProfile::Production"));
    assert!(router_source.contains("MacosLocalAppProfile::Development"));
    assert!(router_source.contains("\"SoyehtDev\""));
    assert!(router_source.contains("/api/v1/household/owner-webauthn/registration/start"));
    assert!(router_source.contains("/api/v1/household/owner-webauthn/registration/finish"));
    assert!(router_source.contains("/api/v1/household/owner-webauthn/registration/status"));

    let auth_source = include_str!("../src/macos_local_caller_auth.rs");
    assert!(auth_source.contains("pub peer: &'a MacosLocalPeer"));
    assert!(!auth_source.contains("HeaderMap"));
    assert!(!auth_source.contains("pub headers"));
    assert!(!auth_source.contains("pub body"));
    assert!(auth_source.contains("MacosLocalAppProfile::Production"));
    assert!(auth_source.contains("MacosLocalAppProfile::Development"));
    assert!(auth_source.contains("SOYEHT_MACOS_PROD_BUNDLE_ID"));
    assert!(auth_source.contains("SOYEHT_MACOS_DEV_BUNDLE_ID"));
    assert!(auth_source.contains("SecCodeCopyGuestWithAttributes"));
    assert!(auth_source.contains("SecCodeCheckValidity"));
    assert!(auth_source.contains("SecRequirementCreateWithString"));
    assert!(auth_source.contains("FailClosedMacosLocalCallerAuth"));
    assert!(auth_source.contains("Err(MacosLocalCallerAuthError::Unavailable)"));
    assert!(!auth_source.contains("DEV_ALLOW"));
    assert!(!auth_source.contains("LOCAL_NO_AUTH"));
    assert!(!auth_source.contains("std::env"));
    assert!(!auth_source.contains("localhost"));
    assert!(!auth_source.contains("kSecGuestAttributePid"));

    let listener_source = include_str!("../src/macos_local_registration_listener.rs");
    assert!(listener_source.contains("UnixListener"));
    assert!(listener_source.contains("LOCAL_PEERTOKEN"));
    assert!(listener_source.contains("MacosLocalPeerConnectInfo"));
    assert!(listener_source.contains("phase0_axum_serve!"));
    assert!(listener_source.contains("connect_info = MacosLocalPeerConnectInfo"));
    assert!(listener_source.contains("Permissions::from_mode(0o700)"));
    assert!(!listener_source.contains("TcpListener"));
    assert!(!auth_source.contains("localhost"));
    assert!(!auth_source.contains("Authorization"));

    let state_default = source_segment(
        source,
        "pub fn with_timeout(",
        "pub fn with_owner_approval_policy(",
    );
    assert!(state_default.contains("macos_local_caller_auth: None"));
}

#[test]
fn owner_approval_rollout_source_guard_requires_explicit_default_off_wiring() {
    let source = include_str!("../src/handlers_owner_events.rs");
    assert!(source.contains("THEYOS_OWNER_AUTH_V2_ROLLOUT"));
    assert!(source.contains("reviewed-core-v2"));
    assert!(source.contains("reviewed-core-v2-secure-upgrade"));
    assert!(source.contains("unknown owner-auth v2 rollout value; keeping LegacyOnly policy"));

    let reviewed_rollout = source_segment(
        source,
        "pub fn reviewed_core_v2_rollout() -> Self {",
        "pub fn with_pair_machine_approve(",
    );
    assert!(reviewed_rollout.contains("with_pair_machine_approve"));
    assert!(reviewed_rollout.contains("with_revoke_credential"));
    assert!(reviewed_rollout.contains("with_recovery_code"));
    assert!(reviewed_rollout.contains("RecoveryCodeEnforcement::BreakGlassEnabled"));
    assert!(
        !reviewed_rollout.contains(
            "with_recovery_code(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential)"
        )
    );
    assert!(reviewed_rollout.contains("with_add_credential"));
    assert!(!reviewed_rollout.contains("bootstrap_initialize"));
    assert!(!reviewed_rollout.contains("bootstrap_teardown"));
    assert!(!reviewed_rollout.contains("pair_device_confirm"));
    assert!(!reviewed_rollout.contains("device_pairing"));
    assert!(!reviewed_rollout.contains("device-pairing"));
    assert!(!reviewed_rollout.contains("attach_token"));
    assert!(!reviewed_rollout.contains("terminal_pty"));
    assert!(!reviewed_rollout.contains("household_claws"));
    assert!(!reviewed_rollout.contains("secure_upgrade"));
    assert!(!reviewed_rollout.contains("SecureUpgrade"));
    assert!(!reviewed_rollout.contains("sign_owner_with_verified_provenance"));

    let parser = source_segment(
        source,
        "pub fn owner_approval_policy_from_rollout_value(",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
    );
    assert!(parser.contains("None | Some(\"off\" | \"legacy\" | \"legacy-only\")"));
    assert!(parser.contains("OWNER_AUTH_V2_REVIEWED_CORE_ROLLOUT"));
    assert!(parser.contains("OWNER_AUTH_V2_SECURE_UPGRADE_ROLLOUT"));
    assert!(parser.contains("with_secure_upgrade(SecureUpgradeEnforcement::StrongMintingEnabled)"));
    assert!(parser.contains("OwnerApprovalEnforcementPolicy::default()"));

    let router_source = include_str!("../src/household_bootstrap.rs");
    assert!(router_source.contains(
        "let owner_approval_policy = handlers_owner_events::owner_approval_policy_from_env();"
    ));
    assert!(router_source.contains(".with_owner_approval_policy(owner_approval_policy.clone())"));
    assert!(router_source.contains("secure_upgrade_runtime_config_from_env()"));
    assert!(router_source.contains("with_secure_upgrade_runtime(config)"));
}

#[test]
fn pair_machine_fan_out_source_guard_requires_strong_owner_tier() {
    let source = include_str!("../src/handlers_owner_events.rs");
    assert!(source.contains("fn owner_auth_allows_fan_out("));
    assert!(source.contains("owner_auth.owner_can_fan_out()"));
    assert!(source.contains("owner_auth_tier_not_strong"));

    let start_handler = source_segment(
        source,
        "pub async fn owner_approval_v2_start_handler(",
        "let Some(credentials) = policy_snapshot.credentials",
    );
    assert!(start_handler.contains("PairMachineApprovalBodyMode::RequireV2"));
    assert!(start_handler.contains("owner_auth_allows_fan_out"));

    let approve_handler = source_segment(
        source,
        "pub async fn owner_approve_handler(",
        "let approval_wire = match parse_pair_machine_approval_body",
    );
    assert!(approve_handler.contains("let body_mode = state"));
    assert!(approve_handler.contains("body_mode == PairMachineApprovalBodyMode::RequireV2"));
    assert!(approve_handler.contains("owner_auth_allows_fan_out"));
}

#[test]
fn owner_webauthn_revoke_start_source_guards_read_only_contract() {
    let source = include_str!("../src/handlers_owner_events.rs");
    let snapshot = source_segment(
        source,
        "fn owner_webauthn_revoke_credential_start_snapshot(",
        "fn parse_pair_machine_approval_body(",
    );
    assert!(snapshot.contains("classify_owner_webauthn_authority_anchor_read_only"));
    assert!(!snapshot.contains("verify_or_update_owner_webauthn_authority_anchor"));
    assert!(!snapshot.contains("OwnerWebauthnAnchorMode::MigrationDefaultOff"));
    assert!(!snapshot.contains("PairMachineApprovalBodyMode::LegacyV1"));

    let handler = source_segment(
        source,
        "pub async fn owner_webauthn_revoke_credential_start_handler(",
        "/// `POST /api/v1/household/owner-webauthn/revoke/finish`",
    );
    assert!(handler.contains("authorize_owner_webauthn_revoke_credential_start_request"));
    assert!(handler.contains("BOOTSTRAP_MUTATION_LOCK"));
    assert!(!handler.contains("verify_or_update"));
    assert!(!handler.contains("verify_or_update_owner_webauthn_authority_anchor"));
    assert!(!handler.contains("write_owner_webauthn_authority_anchor"));
    assert!(!handler.contains("OwnerWebauthnAnchorMode"));
    assert!(!handler.contains("MigrationDefaultOff"));
    assert!(!handler.contains("authorize_owner_auth_enroll_initial_request"));
    assert!(!handler.contains("owner_webauthn_initial_enrollment_policy_snapshot"));
    assert!(!handler.contains("HouseholdAddMachine"));
    assert!(!handler.contains("LegacyV1"));
    assert!(!handler.contains("sign_append"));
    assert!(!handler.contains(".save("));
    assert!(!handler.contains("set_owner_auth"));
    assert!(!handler.contains("initial_enrollment_marker"));

    let auth_source = include_str!("../src/household_auth.rs");
    let auth_helper = source_segment(
        auth_source,
        "pub async fn authorize_owner_webauthn_revoke_credential_start_request(",
        "async fn authorize_owner_only_pop_request(",
    );
    assert!(auth_helper.contains("authorize_owner_only_pop_request"));
    assert!(!auth_helper.contains("caveats::permits"));
    assert!(!auth_helper.contains("HouseholdAddMachine"));
    assert!(!auth_helper.contains("OwnerAuthEnrollInitial"));

    let router_source = include_str!("../src/household_bootstrap.rs");
    assert!(router_source.contains("/api/v1/household/owner-webauthn/revoke/start"));
}

#[test]
fn owner_webauthn_add_credential_start_source_guards_challenge_only_contract() {
    let source = include_str!("../src/handlers_owner_events.rs");
    let plan = source_segment(
        source,
        "fn owner_webauthn_add_credential_start_plan(",
        "fn owner_webauthn_add_credential_finish_plan(",
    );
    assert!(plan.contains("add_credential_start_enabled"));
    assert!(plan.contains("classify_owner_webauthn_authority_anchor_read_only"));
    assert!(plan.contains("OwnerWebauthnAnchorStatus::Verified"));
    assert!(plan.contains("OwnerWebauthnAnchorStatus::Advanced"));
    assert!(plan.contains("active_count == 0"));
    assert!(!plan.contains("OwnerWebauthnPolicySnapshot"));
    assert!(!plan.contains("owner_webauthn_recovery"));
    assert!(!plan.contains("verify_or_update_owner_webauthn_authority_anchor"));
    assert!(!plan.contains("OwnerWebauthnAnchorMode::MigrationDefaultOff"));
    assert!(!plan.contains("OwnerAuthEnrollInitial"));
    assert!(!plan.contains("HouseholdAddMachine"));

    let handler = source_segment(
        source,
        "pub async fn owner_webauthn_add_credential_start_handler(",
        "/// `POST /api/v1/household/owner-webauthn/revoke/finish`",
    );
    assert!(handler.contains("authorize_owner_webauthn_add_credential_start_request"));
    assert!(handler.contains("BOOTSTRAP_MUTATION_LOCK"));
    assert!(handler.contains("owner_webauthn_add_credential_start_plan"));
    assert!(handler.contains("OwnerApprovalContextV2::add_credential"));
    assert!(handler.contains("start_registration_from"));
    assert!(handler.contains("start_owner_approval_assertion"));
    assert!(handler.contains("challenge is an orphan until TTL"));
    assert!(handler.contains("OwnerWebauthnAddCredentialStartResponse"));
    assert!(!handler.contains("finish_registration"));
    assert!(!handler.contains("finish_owner_approval_assertion"));
    assert!(!handler.contains("OwnerWebauthnAuthority::sign_append"));
    assert!(!handler.contains("OwnerWebauthnAuthority::sign_recovery_add"));
    assert!(!handler.contains("OwnerWebauthnRecoveryAuthority::sign_consume"));
    assert!(!handler.contains(".save("));
    assert!(!handler.contains("set_owner_auth"));
    assert!(!handler.contains("verify_or_update_owner_webauthn_authority_anchor"));
    assert!(!handler.contains("write_owner_webauthn_authority_anchor"));
    assert!(!handler.contains("OwnerWebauthnPolicySnapshot"));
    assert!(!handler.contains("OwnerWebauthnCredentialEventAction::Revoke"));
    assert!(!handler.contains("MigrationDefaultOff"));
    assert!(!handler.contains("OwnerAuthEnrollInitial"));
    assert!(!handler.contains("HouseholdAddMachine"));
    let registration_start = handler.find("start_registration_from").unwrap();
    let approval_start = handler.find("start_owner_approval_assertion").unwrap();
    let response = handler
        .find("OwnerWebauthnAddCredentialStartResponse")
        .unwrap();
    assert!(registration_start < approval_start);
    assert!(approval_start < response);

    let auth_source = include_str!("../src/household_auth.rs");
    let auth_helper = source_segment(
        auth_source,
        "pub async fn authorize_owner_webauthn_add_credential_start_request(",
        "/// Authorize the owner recovery-code readiness surface.",
    );
    assert!(auth_helper.contains("authorize_owner_only_pop_request"));
    assert!(auth_helper.contains("OwnerWebauthnAddCredentialStart"));
    assert!(!auth_helper.contains("authorize_owner_approval"));
    assert!(!auth_helper.contains("caveats::permits"));
    assert!(!auth_helper.contains("HouseholdAddMachine"));
    assert!(!auth_helper.contains("OwnerAuthEnrollInitial"));

    let router_source = include_str!("../src/household_bootstrap.rs");
    assert!(router_source.contains("/api/v1/household/owner-webauthn/add-credential/start"));
    assert!(router_source.contains("/api/v1/household/owner-webauthn/add-credential/finish"));
}

#[test]
fn owner_webauthn_add_credential_finish_source_guards_mutation_contract() {
    let source = include_str!("../src/handlers_owner_events.rs");
    let plan = source_segment(
        source,
        "fn owner_webauthn_add_credential_finish_plan(",
        "fn owner_webauthn_recovery_consume_registration_binding(",
    );
    assert!(plan.contains("add_credential_start_enabled"));
    assert!(plan.contains("owner_webauthn_add_credential_registration_binding_from_context"));
    assert!(plan.contains("owner_webauthn_active_snapshot_read_only"));
    assert!(plan.contains("add_credential_actor_not_active"));
    assert!(plan.contains("add_credential_head_mismatch"));
    assert!(plan.contains("add_credential_count_mismatch"));
    assert!(plan.contains("OwnerApprovalContextV2::add_credential"));
    assert!(!plan.contains("OwnerWebauthnPolicySnapshot"));
    assert!(!plan.contains("owner_webauthn_recovery"));
    assert!(!plan.contains("verify_or_update_owner_webauthn_authority_anchor"));
    assert!(!plan.contains("OwnerWebauthnAnchorMode::MigrationDefaultOff"));
    assert!(!plan.contains("OwnerAuthEnrollInitial"));
    assert!(!plan.contains("HouseholdAddMachine"));

    let handler = source_segment(
        source,
        "pub async fn owner_webauthn_add_credential_finish_handler(",
        "/// `POST /api/v1/household/owner-webauthn/recovery/status`",
    );
    assert!(handler.contains("authorize_owner_webauthn_add_credential_finish_request"));
    assert!(handler.contains("BOOTSTRAP_MUTATION_LOCK"));
    assert!(handler.contains("owner_webauthn_add_credential_finish_plan"));
    assert!(handler.contains("require_expected_context"));
    assert!(handler.contains("require_registration_challenge_binding"));
    assert!(handler.contains("require_owner_approval_challenge_context"));
    assert!(handler.contains("finish_registration_with_binding"));
    assert!(handler.contains("finish_owner_approval_assertion"));
    assert!(handler.contains("OwnerWebauthnAuthority::sign_append"));
    assert!(handler.contains("OwnerWebauthnCredentialEventAction::Add"));
    assert!(handler.contains(".save("));
    assert!(handler.contains("set_owner_auth"));
    assert!(handler.contains("verify_or_update_owner_webauthn_authority_anchor"));
    assert!(!handler.contains("OwnerWebauthnAuthority::sign_recovery_add"));
    assert!(!handler.contains("OwnerWebauthnRecoveryAuthority::sign_consume"));
    assert!(!handler.contains("OwnerWebauthnCredentialEventAction::Revoke"));
    assert!(!handler.contains("OwnerWebauthnPolicySnapshot"));
    assert!(!handler.contains("MigrationDefaultOff"));
    assert!(!handler.contains("OwnerAuthEnrollInitial"));
    assert!(!handler.contains("HouseholdAddMachine"));
    let context_check = handler.find("require_expected_context").unwrap();
    let registration_context = handler
        .find("require_registration_challenge_binding")
        .unwrap();
    let approval_context = handler
        .find("require_owner_approval_challenge_context")
        .unwrap();
    let registration_finish = handler.find("finish_registration_with_binding").unwrap();
    let approval_finish = handler.find("finish_owner_approval_assertion").unwrap();
    let append = handler.find("OwnerWebauthnAuthority::sign_append").unwrap();
    let save = handler.find(".save(").unwrap();
    let memory = handler.find("set_owner_auth").unwrap();
    let anchor = handler
        .find("verify_or_update_owner_webauthn_authority_anchor")
        .unwrap();
    assert!(context_check < registration_context);
    assert!(context_check < approval_context);
    assert!(registration_context < registration_finish);
    assert!(approval_context < registration_finish);
    assert!(registration_finish < approval_finish);
    assert!(approval_finish < append);
    assert!(append < save);
    assert!(save < memory);
    assert!(memory < anchor);

    let auth_source = include_str!("../src/household_auth.rs");
    let auth_helper = source_segment(
        auth_source,
        "pub async fn authorize_owner_webauthn_add_credential_finish_request(",
        "/// Authorize the owner recovery-code readiness surface.",
    );
    assert!(auth_helper.contains("authorize_owner_only_pop_request"));
    assert!(auth_helper.contains("OwnerWebauthnAddCredentialFinish"));
    assert!(!auth_helper.contains("authorize_owner_approval"));
    assert!(!auth_helper.contains("caveats::permits"));
    assert!(!auth_helper.contains("HouseholdAddMachine"));
    assert!(!auth_helper.contains("OwnerAuthEnrollInitial"));

    let router_source = include_str!("../src/household_bootstrap.rs");
    assert!(router_source.contains("/api/v1/household/owner-webauthn/add-credential/finish"));
}

#[test]
fn owner_webauthn_revoke_finish_source_guards_mutation_contract() {
    let source = include_str!("../src/handlers_owner_events.rs");
    let plan = source_segment(
        source,
        "fn owner_webauthn_revoke_credential_finish_plan(",
        "fn parse_pair_machine_approval_body(",
    );
    assert!(plan.contains("classify_owner_webauthn_authority_anchor_read_only"));
    assert!(!plan.contains("verify_or_update_owner_webauthn_authority_anchor"));
    assert!(!plan.contains("OwnerWebauthnAnchorMode::MigrationDefaultOff"));
    let target_check = plan.find("revoke_credential_target_not_active").unwrap();
    let actor_check = plan.find("revoke_credential_actor_not_active").unwrap();
    let head_check = plan.find("revoke_credential_head_mismatch").unwrap();
    let count_check = plan.find("revoke_credential_count_mismatch").unwrap();
    assert!(target_check < head_check);
    assert!(actor_check < head_check);
    assert!(head_check < count_check);

    let handler = source_segment(
        source,
        "pub async fn owner_webauthn_revoke_credential_finish_handler(",
        "/// `POST /api/v1/household/owner-webauthn/recovery/status`",
    );
    assert!(handler.contains("authorize_owner_webauthn_revoke_credential_finish_request"));
    assert!(handler.contains("BOOTSTRAP_MUTATION_LOCK"));
    assert!(handler.contains("require_expected_context"));
    assert!(handler.contains("require_owner_approval_challenge_context"));
    assert!(handler.contains("finish_owner_approval_assertion"));
    assert!(handler.contains("OwnerWebauthnAuthority::sign_append"));
    assert!(handler.contains("OwnerWebauthnCredentialEventAction::Revoke"));
    assert!(handler.contains("set_owner_auth"));
    assert!(handler.contains("OwnerWebauthnAnchorMode::Enforcement"));
    assert!(!handler.contains("MigrationDefaultOff"));
    assert!(!handler.contains("OwnerAuthEnrollInitial"));
    assert!(!handler.contains("HouseholdAddMachine"));
    assert!(!handler.contains("LegacyV1"));
    assert!(!handler.contains("initial_enrollment_marker"));
    assert!(!handler.contains("registration_status"));
    let lock = handler.find("BOOTSTRAP_MUTATION_LOCK").unwrap();
    let context_check = handler.find("require_expected_context").unwrap();
    let challenge_check = handler
        .find("require_owner_approval_challenge_context")
        .unwrap();
    let challenge_finish = handler.find("finish_owner_approval_assertion").unwrap();
    let append = handler.find("OwnerWebauthnAuthority::sign_append").unwrap();
    let save = handler.find(".save(").unwrap();
    let memory = handler.find("set_owner_auth").unwrap();
    let anchor = handler
        .find("verify_or_update_owner_webauthn_authority_anchor")
        .unwrap();
    assert!(lock < context_check);
    assert!(context_check < challenge_check);
    assert!(challenge_check < challenge_finish);
    assert!(challenge_finish < append);
    assert!(append < save);
    assert!(save < memory);
    assert!(memory < anchor);

    let auth_source = include_str!("../src/household_auth.rs");
    let auth_helper = source_segment(
        auth_source,
        "pub async fn authorize_owner_webauthn_revoke_credential_finish_request(",
        "async fn authorize_owner_only_pop_request(",
    );
    assert!(auth_helper.contains("authorize_owner_only_pop_request"));
    assert!(!auth_helper.contains("caveats::permits"));
    assert!(!auth_helper.contains("HouseholdAddMachine"));
    assert!(!auth_helper.contains("OwnerAuthEnrollInitial"));

    let router_source = include_str!("../src/household_bootstrap.rs");
    assert!(router_source.contains("/api/v1/household/owner-webauthn/revoke/finish"));
}

#[test]
fn owner_webauthn_recovery_source_guards_provision_readiness_contract() {
    let source = include_str!("../src/handlers_owner_events.rs");
    let start_snapshot = source_segment(
        source,
        "fn owner_webauthn_recovery_start_snapshot(",
        "fn owner_webauthn_recovery_finish_plan(",
    );
    assert!(start_snapshot.contains("owner_webauthn_active_snapshot_read_only"));
    assert!(start_snapshot.contains("owner_webauthn_recovery_head_read_only"));
    assert!(!start_snapshot.contains("verify_or_update"));
    assert!(!start_snapshot.contains("MigrationDefaultOff"));

    let status = source_segment(
        source,
        "fn owner_webauthn_recovery_ready_status(",
        "fn owner_webauthn_recovery_consume_start_plan(",
    );
    assert!(status.contains("classify_owner_webauthn_recovery_anchor_read_only"));
    assert!(status.contains("owner_webauthn_recovery.recovery_ready()"));
    assert!(!status.contains("advance_owner_webauthn_recovery_anchor_after_commit"));
    assert!(!status.contains("verify_or_update"));
    assert!(!status.contains("MigrationDefaultOff"));

    let status_handler = source_segment(
        source,
        "pub async fn owner_webauthn_recovery_status_handler(",
        "/// `POST /api/v1/household/owner-webauthn/recovery/start`",
    );
    assert!(status_handler.contains("authorize_owner_webauthn_recovery_status_request"));
    assert!(status_handler.contains("BOOTSTRAP_MUTATION_LOCK"));
    assert!(!status_handler.contains("advance_owner_webauthn_recovery_anchor_after_commit"));
    assert!(!status_handler.contains(".save("));
    assert!(!status_handler.contains("set_owner_auth"));
    assert!(!status_handler.contains("MigrationDefaultOff"));
    assert!(!status_handler.contains("OwnerAuthEnrollInitial"));
    assert!(!status_handler.contains("HouseholdAddMachine"));

    let start_handler = source_segment(
        source,
        "pub async fn owner_webauthn_recovery_start_handler(",
        "/// `POST /api/v1/household/owner-webauthn/recovery/consume/start`",
    );
    assert!(start_handler.contains("authorize_owner_webauthn_recovery_start_request"));
    assert!(start_handler.contains("BOOTSTRAP_MUTATION_LOCK"));
    assert!(start_handler.contains("start_owner_approval_assertion"));
    assert!(!start_handler.contains("advance_owner_webauthn_recovery_anchor_after_commit"));
    assert!(!start_handler.contains(".save("));
    assert!(!start_handler.contains("set_owner_auth"));
    assert!(!start_handler.contains("MigrationDefaultOff"));
    assert!(!start_handler.contains("OwnerAuthEnrollInitial"));
    assert!(!start_handler.contains("HouseholdAddMachine"));

    let finish_handler = source_segment(
        source,
        "pub async fn owner_webauthn_recovery_finish_handler(",
        "/// `POST /api/v1/household/owner-webauthn/registration/start`",
    );
    assert!(finish_handler.contains("authorize_owner_webauthn_recovery_finish_request"));
    assert!(finish_handler.contains("BOOTSTRAP_MUTATION_LOCK"));
    assert!(finish_handler.contains("require_expected_context"));
    assert!(finish_handler.contains("require_owner_approval_challenge_context"));
    assert!(finish_handler.contains("finish_owner_approval_assertion"));
    assert!(finish_handler.contains("OwnerWebauthnRecoveryAuthority::sign_next"));
    assert!(finish_handler.contains(".save("));
    assert!(finish_handler.contains("set_owner_auth"));
    assert!(finish_handler.contains("advance_owner_webauthn_recovery_anchor_after_commit"));
    assert!(!finish_handler.contains("MigrationDefaultOff"));
    assert!(!finish_handler.contains("OwnerAuthEnrollInitial"));
    assert!(!finish_handler.contains("HouseholdAddMachine"));
    let lock = finish_handler.find("BOOTSTRAP_MUTATION_LOCK").unwrap();
    let context_check = finish_handler.find("require_expected_context").unwrap();
    let challenge_check = finish_handler
        .find("require_owner_approval_challenge_context")
        .unwrap();
    let challenge_finish = finish_handler
        .find("finish_owner_approval_assertion")
        .unwrap();
    let append = finish_handler
        .find("OwnerWebauthnRecoveryAuthority::sign_next")
        .unwrap();
    let save = finish_handler.find(".save(").unwrap();
    let memory = finish_handler.find("set_owner_auth").unwrap();
    let anchor = finish_handler
        .find("advance_owner_webauthn_recovery_anchor_after_commit")
        .unwrap();
    assert!(lock < context_check);
    assert!(context_check < challenge_check);
    assert!(challenge_check < challenge_finish);
    assert!(challenge_finish < append);
    assert!(append < save);
    assert!(save < memory);
    assert!(memory < anchor);

    let consume_plan = source_segment(
        source,
        "fn owner_webauthn_recovery_consume_start_plan(",
        "fn owner_webauthn_recovery_consume_finish_plan(",
    );
    assert!(consume_plan.contains("check_recovery_consume_attempt"));
    assert!(consume_plan.contains("classify_owner_webauthn_authority_anchor_read_only"));
    assert!(consume_plan.contains("classify_owner_webauthn_recovery_anchor_read_only"));
    assert!(consume_plan.contains("classify_owner_webauthn_recovery_consume_readiness"));
    assert!(consume_plan.contains("matches_code_bytes"));
    assert!(!consume_plan.contains("owner_webauthn_active_snapshot_read_only"));
    assert!(!consume_plan.contains("OwnerWebauthnPolicySnapshot"));
    assert!(!consume_plan.contains("OwnerOperation::AddCredential"));
    assert!(!consume_plan.contains("start_owner_approval_assertion"));
    assert!(!consume_plan.contains("finish_owner_approval_assertion"));
    assert!(!consume_plan.contains("MigrationDefaultOff"));
    assert!(!consume_plan.contains("OwnerAuthEnrollInitial"));
    assert!(!consume_plan.contains("HouseholdAddMachine"));
    let limiter = consume_plan.find("check_recovery_consume_attempt").unwrap();
    let code_compare = consume_plan.find("matches_code_bytes").unwrap();
    assert!(limiter < code_compare);

    let consume_handler = source_segment(
        source,
        "pub async fn owner_webauthn_recovery_consume_start_handler(",
        "/// `POST /api/v1/household/owner-webauthn/recovery/consume/finish`",
    );
    assert!(consume_handler.contains("authorize_owner_webauthn_recovery_consume_start_request"));
    assert!(consume_handler.contains("BOOTSTRAP_MUTATION_LOCK"));
    assert!(consume_handler.contains("OwnerApprovalContextV2::recover_credential"));
    assert!(consume_handler.contains("start_registration_from"));
    assert!(!consume_handler.contains("finish_registration"));
    assert!(!consume_handler.contains("OwnerWebauthnAuthority::sign_recovery_add"));
    assert!(!consume_handler.contains("OwnerWebauthnRecoveryAuthority::sign_consume"));
    assert!(!consume_handler.contains(".save("));
    assert!(!consume_handler.contains("set_owner_auth"));
    assert!(!consume_handler.contains("advance_owner_webauthn_recovery_anchor_after_commit"));
    assert!(!consume_handler.contains("verify_or_update_owner_webauthn_authority_anchor"));
    assert!(!consume_handler.contains("MigrationDefaultOff"));
    assert!(!consume_handler.contains("OwnerAuthEnrollInitial"));
    assert!(!consume_handler.contains("HouseholdAddMachine"));

    let consume_finish_plan = source_segment(
        source,
        "fn owner_webauthn_recovery_consume_finish_plan(",
        "fn owner_webauthn_recovery_consume_registration_binding(",
    );
    assert!(consume_finish_plan.contains("check_recovery_consume_attempt"));
    assert!(consume_finish_plan.contains("classify_owner_webauthn_authority_anchor_read_only"));
    assert!(consume_finish_plan.contains("classify_owner_webauthn_recovery_anchor_read_only"));
    assert!(consume_finish_plan.contains("classify_owner_webauthn_recovery_consume_readiness"));
    assert!(consume_finish_plan.contains("OwnerApprovalContextV2::recover_credential"));
    assert!(consume_finish_plan.contains("matches_code_bytes"));
    assert!(!consume_finish_plan.contains("OwnerWebauthnPolicySnapshot"));
    assert!(!consume_finish_plan.contains("OwnerOperation::AddCredential"));
    assert!(!consume_finish_plan.contains("finish_owner_approval_assertion"));
    assert!(!consume_finish_plan.contains("MigrationDefaultOff"));
    assert!(!consume_finish_plan.contains("OwnerAuthEnrollInitial"));
    assert!(!consume_finish_plan.contains("HouseholdAddMachine"));
    let limiter = consume_finish_plan
        .find("check_recovery_consume_attempt")
        .unwrap();
    let code_compare = consume_finish_plan.find("matches_code_bytes").unwrap();
    assert!(limiter < code_compare);

    let consume_finish_handler = source_segment(
        source,
        "pub async fn owner_webauthn_recovery_consume_finish_handler(",
        "/// `POST /api/v1/household/owner-webauthn/recovery/finish`",
    );
    assert!(
        consume_finish_handler.contains("authorize_owner_webauthn_recovery_consume_finish_request")
    );
    assert!(consume_finish_handler.contains("BOOTSTRAP_MUTATION_LOCK"));
    assert!(consume_finish_handler.contains("repair_recovery_consume_finish_if_committed"));
    assert!(consume_finish_handler.contains("owner_webauthn_recovery_consume_finish_plan"));
    assert!(consume_finish_handler.contains("finish_registration_with_binding"));
    assert!(consume_finish_handler.contains("OwnerWebauthnAuthority::sign_recovery_add"));
    assert!(consume_finish_handler.contains("OwnerWebauthnRecoveryAuthority::sign_consume"));
    assert!(consume_finish_handler.contains(".save("));
    assert!(consume_finish_handler.contains("set_owner_auth"));
    assert!(consume_finish_handler.contains("verify_or_update_owner_webauthn_authority_anchor"));
    assert!(consume_finish_handler.contains("advance_owner_webauthn_recovery_anchor_after_commit"));
    assert!(!consume_finish_handler.contains("finish_owner_approval_assertion"));
    assert!(!consume_finish_handler.contains("OwnerOperation::AddCredential"));
    assert!(!consume_finish_handler.contains("OwnerWebauthnPolicySnapshot"));
    assert!(!consume_finish_handler.contains("MigrationDefaultOff"));
    assert!(!consume_finish_handler.contains("OwnerAuthEnrollInitial"));
    assert!(!consume_finish_handler.contains("HouseholdAddMachine"));
    let repair = consume_finish_handler
        .find("repair_recovery_consume_finish_if_committed")
        .unwrap();
    let context_expiry = consume_finish_handler.find("validate_at").unwrap();
    let plan = consume_finish_handler
        .find("owner_webauthn_recovery_consume_finish_plan")
        .unwrap();
    let challenge_finish = consume_finish_handler
        .find("finish_registration_with_binding")
        .unwrap();
    let add = consume_finish_handler
        .find("OwnerWebauthnAuthority::sign_recovery_add")
        .unwrap();
    let consume = consume_finish_handler
        .find("OwnerWebauthnRecoveryAuthority::sign_consume")
        .unwrap();
    let save = consume_finish_handler.find(".save(").unwrap();
    let memory = consume_finish_handler.find("set_owner_auth").unwrap();
    let webauthn_anchor = consume_finish_handler
        .find("verify_or_update_owner_webauthn_authority_anchor")
        .unwrap();
    let recovery_anchor = consume_finish_handler
        .find("advance_owner_webauthn_recovery_anchor_after_commit")
        .unwrap();
    assert!(repair < context_expiry);
    assert!(context_expiry < plan);
    assert!(plan < challenge_finish);
    assert!(challenge_finish < add);
    assert!(add < consume);
    assert!(consume < save);
    assert!(save < memory);
    assert!(memory < webauthn_anchor);
    assert!(webauthn_anchor < recovery_anchor);

    let pair_machine_policy = source_segment(
        source,
        "fn pair_machine_owner_webauthn_policy_snapshot(",
        "struct OwnerWebauthnRevokeCredentialStartSnapshot",
    );
    assert!(!pair_machine_policy.contains("owner_webauthn_recovery"));
    assert!(!pair_machine_policy.contains("recovery_code"));
    let revoke_start = source_segment(
        source,
        "pub async fn owner_webauthn_revoke_credential_start_handler(",
        "/// `POST /api/v1/household/owner-webauthn/revoke/finish`",
    );
    assert!(!revoke_start.contains("recovery"));
    let revoke_finish = source_segment(
        source,
        "pub async fn owner_webauthn_revoke_credential_finish_handler(",
        "/// `POST /api/v1/household/owner-webauthn/recovery/status`",
    );
    assert!(!revoke_finish.contains("recovery"));

    let auth_source = include_str!("../src/household_auth.rs");
    for helper in [
        "pub async fn authorize_owner_webauthn_recovery_status_request(",
        "pub async fn authorize_owner_webauthn_recovery_start_request(",
        "pub async fn authorize_owner_webauthn_recovery_finish_request(",
        "pub async fn authorize_owner_webauthn_recovery_consume_start_request(",
        "pub async fn authorize_owner_webauthn_recovery_consume_finish_request(",
    ] {
        let auth_helper = source_segment(
            auth_source,
            helper,
            "async fn authorize_owner_only_pop_request(",
        );
        assert!(auth_helper.contains("authorize_owner_only_pop_request"));
        assert!(!auth_helper.contains("caveats::permits"));
        assert!(!auth_helper.contains("HouseholdAddMachine"));
        assert!(!auth_helper.contains("OwnerAuthEnrollInitial"));
    }

    let router_source = include_str!("../src/household_bootstrap.rs");
    assert!(router_source.contains("/api/v1/household/owner-webauthn/recovery/status"));
    assert!(router_source.contains("/api/v1/household/owner-webauthn/recovery/start"));
    assert!(router_source.contains("/api/v1/household/owner-webauthn/recovery/finish"));
    assert!(router_source.contains("/api/v1/household/owner-webauthn/recovery/consume/start"));
    assert!(router_source.contains("/api/v1/household/owner-webauthn/recovery/consume/finish"));
}

#[tokio::test]
async fn owner_webauthn_revoke_start_reviewed_rollout_binds_context_read_only_advanced() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, _authenticator) =
        owner_auth_with_two_webauthn_credentials(&identity);
    let active_ids = active_credential_ids(&owner_auth, &identity);
    assert_eq!(active_ids.len(), 2);
    let target = active_ids[1].clone();
    let live_head = verified_owner_webauthn_authority_head(
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
    )
    .unwrap()
    .expect("two-credential authority has a head");
    let first_entry = owner_auth
        .owner_webauthn
        .entries()
        .first()
        .expect("genesis event exists");
    let first_hash = first_entry.entry_hash().unwrap();
    let first_anchor = OwnerWebauthnAuthorityAnchor::new(
        &identity.record,
        &owner_auth.owner_person_cert,
        0,
        first_hash,
    );
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    write_owner_webauthn_authority_anchor(anchor_store.as_ref(), &first_anchor).unwrap();
    let policy = OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout();
    let (_td, router, _log, _broadcaster, person, identity, _window) =
        router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
            let anchor_store = Arc::clone(&anchor_store);
            move |state| {
                state
                    .with_owner_approval_policy(policy)
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_store)
            }
        });

    let (status, headers, resp_bytes) = post_revoke_start(router, &person, target.clone()).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/cbor"
    );
    let response: OwnerApprovalV2StartResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(response.version, 1);
    assert!(!response.challenge_id.is_empty());
    assert_eq!(response.context.op, OwnerOperation::RevokeCredential);
    response.context.validate_shape().unwrap();
    assert_eq!(
        response
            .context
            .target_credential_id
            .as_ref()
            .map(ByteBuf::as_ref),
        Some(target.as_slice())
    );
    assert_eq!(
        response.context.authority_head_sequence,
        Some(live_head.sequence)
    );
    assert_eq!(
        response
            .context
            .authority_head_hash
            .as_ref()
            .map(ByteBuf::as_ref),
        Some(live_head.head_hash.as_slice())
    );
    assert_eq!(response.context.pre_active_credential_count, Some(2));
    assert_eq!(
        response.context.capabilities,
        vec!["owner-auth-revoke".to_string()]
    );
    let anchor =
        read_owner_webauthn_authority_anchor(anchor_store.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("anchor remains present");
    assert_eq!(
        anchor.sequence(),
        0,
        "revoke start must not advance a lagging but valid anchor"
    );
    assert_eq!(anchor.head_hash(), first_hash);
}

#[tokio::test]
async fn owner_webauthn_revoke_start_policy_default_off_is_opaque() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, _authenticator) =
        owner_auth_with_two_webauthn_credentials(&identity);
    let target = active_credential_ids(&owner_auth, &identity)[0].clone();
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    anchor_owner_webauthn_authority(anchor_store.as_ref(), &identity, &owner_auth);
    let (_td, router, _log, _broadcaster, person, _identity, _window) =
        router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
            let anchor_store = Arc::clone(&anchor_store);
            move |state| {
                state
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_store)
            }
        });

    let (status, _headers, resp_bytes) = post_revoke_start(router, &person, target).await;

    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_revoke_start_rejects_missing_anchor_without_migration() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, _authenticator) =
        owner_auth_with_two_webauthn_credentials(&identity);
    let target = active_credential_ids(&owner_auth, &identity)[0].clone();
    let owner_auth_for_assert = owner_auth.clone();
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_revoke_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
    let (_td, router, _log, _broadcaster, person, identity, _window) =
        router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
            let anchor_store = Arc::clone(&anchor_store);
            move |state| {
                state
                    .with_owner_approval_policy(policy)
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_store)
            }
        });

    let (status, _headers, resp_bytes) = post_revoke_start(router, &person, target).await;

    assert_generic_unauth(status, &resp_bytes);
    assert!(
        read_owner_webauthn_authority_anchor(anchor_store.as_ref(), &identity.record.hh_id)
            .unwrap()
            .is_none(),
        "revoke start must not migrate or write a missing anchor"
    );
    assert!(
        verify_or_update_owner_webauthn_authority_anchor(
            anchor_store.as_ref(),
            &owner_auth_for_assert.owner_webauthn,
            &identity.record,
            &owner_auth_for_assert.owner_person_cert,
            OwnerWebauthnAnchorMode::Enforcement,
        )
        .is_err()
    );
}

#[tokio::test]
async fn owner_webauthn_revoke_start_rejects_unsafe_targets_and_trust_states() {
    {
        let td = tempfile::tempdir().unwrap();
        let identity = Arc::new(bootstrap(td.path()));
        let (owner_auth, person, rp, _authenticator) =
            owner_auth_with_webauthn_credential(&identity);
        let target = active_credential_ids(&owner_auth, &identity)[0].clone();
        let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
            Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
        anchor_owner_webauthn_authority(anchor_store.as_ref(), &identity, &owner_auth);
        let policy = OwnerApprovalEnforcementPolicy::default()
            .with_revoke_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
        let (_td, router, _log, _broadcaster, person, _identity, _window) =
            router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
                let anchor_store = Arc::clone(&anchor_store);
                move |state| {
                    state
                        .with_owner_approval_policy(policy)
                        .with_owner_webauthn_rp(rp)
                        .with_owner_webauthn_anchor(anchor_store)
                }
            });

        let (status, _headers, resp_bytes) = post_revoke_start(router, &person, target).await;
        assert_generic_unauth(status, &resp_bytes);
    }

    {
        let td = tempfile::tempdir().unwrap();
        let identity = Arc::new(bootstrap(td.path()));
        let (owner_auth, person, rp, _authenticator) =
            owner_auth_with_two_webauthn_credentials(&identity);
        let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
            Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
        anchor_owner_webauthn_authority(anchor_store.as_ref(), &identity, &owner_auth);
        let policy = OwnerApprovalEnforcementPolicy::default()
            .with_revoke_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
        let (_td, router, _log, _broadcaster, person, _identity, _window) =
            router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
                let anchor_store = Arc::clone(&anchor_store);
                move |state| {
                    state
                        .with_owner_approval_policy(policy)
                        .with_owner_webauthn_rp(rp)
                        .with_owner_webauthn_anchor(anchor_store)
                }
            });

        let (status, _headers, resp_bytes) =
            post_revoke_start(router, &person, vec![0xca, 0xfe]).await;
        assert_generic_unauth(status, &resp_bytes);
    }

    {
        let td = tempfile::tempdir().unwrap();
        let identity = Arc::new(bootstrap(td.path()));
        let (owner_auth, person, rp) = owner_auth_with_revoked_webauthn_credential(&identity);
        let revoked_target = owner_auth
            .owner_webauthn_credentials(&identity.record)
            .unwrap()
            .credentials()
            .first()
            .expect("credential exists")
            .credential_id_bytes()
            .to_vec();
        let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
            Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
        anchor_owner_webauthn_authority(anchor_store.as_ref(), &identity, &owner_auth);
        let policy = OwnerApprovalEnforcementPolicy::default()
            .with_revoke_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
        let (_td, router, _log, _broadcaster, person, _identity, _window) =
            router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
                let anchor_store = Arc::clone(&anchor_store);
                move |state| {
                    state
                        .with_owner_approval_policy(policy)
                        .with_owner_webauthn_rp(rp)
                        .with_owner_webauthn_anchor(anchor_store)
                }
            });

        let (status, _headers, resp_bytes) =
            post_revoke_start(router, &person, revoked_target).await;
        assert_generic_unauth(status, &resp_bytes);
    }
}

#[tokio::test]
async fn owner_webauthn_revoke_start_rejects_bad_pop_and_cbor() {
    #[derive(serde::Serialize)]
    struct RevokeStartWithExtraField {
        #[serde(rename = "v")]
        version: u8,
        target_credential_id: ByteBuf,
        unexpected: u8,
    }

    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, _authenticator) =
        owner_auth_with_two_webauthn_credentials(&identity);
    let target = active_credential_ids(&owner_auth, &identity)[0].clone();
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    anchor_owner_webauthn_authority(anchor_store.as_ref(), &identity, &owner_auth);
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_revoke_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
    let (_td, router, _log, _broadcaster, person, _identity, _window) =
        router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
            let anchor_store = Arc::clone(&anchor_store);
            move |state| {
                state
                    .with_owner_approval_policy(policy)
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_store)
            }
        });
    let uri = "/api/v1/household/owner-webauthn/revoke/start";
    let body = revoke_start_body(target.clone());
    let path_mismatch_auth = pop_header_for(
        &person,
        "POST",
        "/api/v1/household/owner-webauthn/registration/start",
        unix_now(),
        &body,
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, path_mismatch_auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    assert_generic_unauth(status, &resp_bytes);

    let body = household_rs::cbor::to_canonical_vec(&RevokeStartWithExtraField {
        version: 1,
        target_credential_id: ByteBuf::from(target.clone()),
        unexpected: 1,
    })
    .unwrap();
    let (status, _headers, resp_bytes) = post_cbor(router.clone(), uri, body, Some(&person)).await;
    assert_generic_unauth(status, &resp_bytes);

    let body = make_version_value_noncanonical(revoke_start_body(target));
    let (status, _headers, resp_bytes) = post_cbor(router, uri, body, Some(&person)).await;
    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_revoke_finish_reviewed_rollout_commits_revoke_and_advances_anchor() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, mut authenticator) =
        owner_auth_with_two_webauthn_credentials(&identity);
    let active_ids = active_credential_ids(&owner_auth, &identity);
    let actor = active_ids[0].clone();
    let target = active_ids[1].clone();
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    anchor_owner_webauthn_authority(anchor_store.as_ref(), &identity, &owner_auth);
    let policy = OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout();
    let (td, router, _log, _broadcaster, person, identity, _window) =
        router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
            let anchor_store = Arc::clone(&anchor_store);
            move |state| {
                state
                    .with_owner_approval_policy(policy)
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_store)
            }
        });

    let start = start_revoke(router.clone(), &person, target.clone()).await;
    let context = start.context;
    let challenge_id = start.challenge_id;
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    let body = revoke_finish_body(context, challenge_id, &assertion);
    let finish = revoke_finish(router, &person, body).await;

    assert_eq!(finish.active_credential_count, 1);
    let loaded = load_owner_auth(&td, &identity);
    let loaded_active = active_credential_ids(&loaded, &identity);
    assert_eq!(loaded_active, vec![actor.clone()]);
    assert_eq!(revoke_events_for_target(&loaded, &target), vec![actor]);
    let final_head = verified_owner_webauthn_authority_head(
        &loaded.owner_webauthn,
        &identity.record,
        &loaded.owner_person_cert,
    )
    .unwrap()
    .expect("revoked authority has a head");
    let anchor =
        read_owner_webauthn_authority_anchor(anchor_store.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("finish advances anchor");
    assert_eq!(anchor.sequence(), final_head.sequence);
    assert_eq!(anchor.head_hash(), final_head.head_hash);
}

#[tokio::test]
async fn owner_webauthn_revoke_finish_context_mismatch_does_not_consume_challenge() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, mut authenticator) =
        owner_auth_with_three_webauthn_credentials(&identity);
    let active_ids = active_credential_ids(&owner_auth, &identity);
    let target = active_ids[1].clone();
    let other_target = active_ids[2].clone();
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    anchor_owner_webauthn_authority(anchor_store.as_ref(), &identity, &owner_auth);
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_revoke_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
    let (td, router, _log, _broadcaster, person, identity, _window) =
        router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
            let anchor_store = Arc::clone(&anchor_store);
            move |state| {
                state
                    .with_owner_approval_policy(policy)
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_store)
            }
        });

    let start = start_revoke(router.clone(), &person, target.clone()).await;
    let original_context = start.context;
    let challenge_id = start.challenge_id;
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    let mut tampered_context = original_context.clone();
    tampered_context.target_credential_id = Some(ByteBuf::from(other_target));
    let tampered_body = revoke_finish_body(tampered_context, challenge_id.clone(), &assertion);
    let (status, _headers, resp_bytes) =
        post_revoke_finish(router.clone(), &person, tampered_body).await;
    assert_generic_unauth(status, &resp_bytes);

    let body = revoke_finish_body(original_context, challenge_id, &assertion);
    let finish = revoke_finish(router, &person, body).await;

    assert_eq!(finish.active_credential_count, 2);
    let loaded = load_owner_auth(&td, &identity);
    assert_eq!(revoke_events_for_target(&loaded, &target).len(), 1);
}

#[tokio::test]
async fn owner_webauthn_revoke_finish_rejects_stale_head_and_inactive_actor_or_target() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, mut authenticator) =
        owner_auth_with_three_webauthn_credentials(&identity);
    let active_ids = active_credential_ids(&owner_auth, &identity);
    let actor = active_ids[0].clone();
    let target = active_ids[1].clone();
    let third = active_ids[2].clone();
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    anchor_owner_webauthn_authority(anchor_store.as_ref(), &identity, &owner_auth);
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_revoke_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
    let (_td, router, _log, _broadcaster, person, identity, _window, router_state) =
        router_from_owner_auth_with_router_state(
            td,
            identity,
            owner_auth.clone(),
            person,
            Duration::from_secs(45),
            {
                let anchor_store = Arc::clone(&anchor_store);
                move |state| {
                    state
                        .with_owner_approval_policy(policy)
                        .with_owner_webauthn_rp(rp)
                        .with_owner_webauthn_anchor(anchor_store)
                }
            },
        );

    let start = start_revoke(router.clone(), &person, target.clone()).await;
    let context = start.context;
    let challenge_id = start.challenge_id;
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    let body = revoke_finish_body(context, challenge_id, &assertion);

    let mut live_auth = owner_auth.clone();
    append_revoke_event(&identity, &mut live_auth, &actor, &third);
    router_state
        .household
        .set_owner_auth(Arc::new(live_auth))
        .await;
    let (status, _headers, resp_bytes) =
        post_revoke_finish(router.clone(), &person, body.clone()).await;
    assert_generic_unauth(status, &resp_bytes);

    let mut target_inactive = owner_auth.clone();
    append_revoke_event(&identity, &mut target_inactive, &actor, &target);
    router_state
        .household
        .set_owner_auth(Arc::new(target_inactive))
        .await;
    let (status, _headers, resp_bytes) =
        post_revoke_finish(router.clone(), &person, body.clone()).await;
    assert_generic_unauth(status, &resp_bytes);

    let mut actor_inactive = owner_auth;
    append_revoke_event(&identity, &mut actor_inactive, &target, &actor);
    router_state
        .household
        .set_owner_auth(Arc::new(actor_inactive))
        .await;
    let (status, _headers, resp_bytes) = post_revoke_finish(router, &person, body).await;
    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_revoke_finish_rejects_policy_off_bad_pop_and_noncanonical_cbor() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, mut authenticator) =
        owner_auth_with_two_webauthn_credentials(&identity);
    let active_ids = active_credential_ids(&owner_auth, &identity);
    let target = active_ids[1].clone();
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    anchor_owner_webauthn_authority(anchor_store.as_ref(), &identity, &owner_auth);
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_revoke_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
    let (_td, router, _log, _broadcaster, person, _identity, _window, router_state) =
        router_from_owner_auth_with_router_state(
            td,
            identity,
            owner_auth,
            person,
            Duration::from_secs(45),
            {
                let anchor_store = Arc::clone(&anchor_store);
                move |state| {
                    state
                        .with_owner_approval_policy(policy)
                        .with_owner_webauthn_rp(rp)
                        .with_owner_webauthn_anchor(anchor_store)
                }
            },
        );
    let start = start_revoke(router.clone(), &person, target).await;
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    let body = revoke_finish_body(start.context, start.challenge_id, &assertion);

    let mut policy_off_state = router_state.clone();
    policy_off_state.owner_approval_policy = OwnerApprovalEnforcementPolicy::default();
    let policy_off_router = Router::new()
        .route(
            "/api/v1/household/owner-webauthn/revoke/finish",
            post(handlers_owner_events::owner_webauthn_revoke_credential_finish_handler),
        )
        .with_state(policy_off_state);
    let (status, _headers, resp_bytes) =
        post_revoke_finish(policy_off_router, &person, body.clone()).await;
    assert_generic_unauth(status, &resp_bytes);

    let uri = "/api/v1/household/owner-webauthn/revoke/finish";
    let bad_pop = pop_header_for(
        &person,
        "POST",
        "/api/v1/household/owner-webauthn/revoke/start",
        unix_now(),
        &body,
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, bad_pop)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    assert_generic_unauth(status, &resp_bytes);

    let noncanonical_body = make_version_value_noncanonical(body);
    let (status, _headers, resp_bytes) =
        post_revoke_finish(router, &person, noncanonical_body).await;
    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_webauthn_revoke_finish_concurrent_duplicate_revoke_only_appends_once() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, mut authenticator) =
        owner_auth_with_three_webauthn_credentials(&identity);
    let active_ids = active_credential_ids(&owner_auth, &identity);
    let actor = active_ids[0].clone();
    let target = active_ids[1].clone();
    let anchor_store = Arc::new(BlockingSetKeystore::new(td.path()));
    anchor_owner_webauthn_authority(anchor_store.as_ref(), &identity, &owner_auth);
    let anchor_for_state: Arc<dyn keystore_rs::KeystoreBackend> = anchor_store.clone();
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_revoke_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
    let (td, router, _log, _broadcaster, person, identity, _window) =
        router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
            move |state| {
                state
                    .with_owner_approval_policy(policy)
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_for_state)
            }
        });

    let first_start = start_revoke(router.clone(), &person, target.clone()).await;
    let second_start = start_revoke(router.clone(), &person, target.clone()).await;
    let first_assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            first_start.options,
        )
        .unwrap();
    let second_assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            second_start.options,
        )
        .unwrap();
    let first_body = revoke_finish_body(
        first_start.context,
        first_start.challenge_id,
        &first_assertion,
    );
    let second_body = revoke_finish_body(
        second_start.context,
        second_start.challenge_id,
        &second_assertion,
    );
    anchor_store.block_next_write();

    let first_uri = "/api/v1/household/owner-webauthn/revoke/finish";
    let first_auth = pop_header_for(&person, "POST", first_uri, unix_now(), &first_body);
    let first_request = Request::builder()
        .method("POST")
        .uri(first_uri)
        .header(header::AUTHORIZATION, first_auth)
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(Body::from(first_body))
        .unwrap();
    let first_router = router.clone();
    let first_task = tokio::spawn(async move {
        let resp = first_router.oneshot(first_request).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, bytes)
    });
    anchor_store.wait_for_blocked_write().await;

    let second_uri = "/api/v1/household/owner-webauthn/revoke/finish";
    let second_auth = pop_header_for(&person, "POST", second_uri, unix_now(), &second_body);
    let second_request = Request::builder()
        .method("POST")
        .uri(second_uri)
        .header(header::AUTHORIZATION, second_auth)
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(Body::from(second_body))
        .unwrap();
    let second_router = router.clone();
    let second_task = tokio::spawn(async move {
        let resp = second_router.oneshot(second_request).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, bytes)
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    anchor_store.release_blocked_write();

    let (first_status, first_bytes) = first_task.await.unwrap();
    let (second_status, second_bytes) = second_task.await.unwrap();
    assert_eq!(first_status, StatusCode::OK);
    let finish: OwnerWebauthnRevokeCredentialFinishResponse =
        household_rs::cbor::from_canonical_slice(&first_bytes).unwrap();
    assert_eq!(finish.active_credential_count, 2);
    assert_generic_unauth(second_status, &second_bytes);
    let loaded = load_owner_auth(&td, &identity);
    assert_eq!(revoke_events_for_target(&loaded, &target), vec![actor]);
    assert_eq!(
        loaded
            .owner_webauthn_credentials(&identity.record)
            .unwrap()
            .active_count(),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_webauthn_revoke_finish_concurrent_different_targets_preserves_last_active() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, mut authenticator) =
        owner_auth_with_two_webauthn_credentials(&identity);
    let active_ids = active_credential_ids(&owner_auth, &identity);
    let actor_and_second_target = active_ids[0].clone();
    let first_target = active_ids[1].clone();
    let anchor_store = Arc::new(BlockingSetKeystore::new(td.path()));
    anchor_owner_webauthn_authority(anchor_store.as_ref(), &identity, &owner_auth);
    let anchor_for_state: Arc<dyn keystore_rs::KeystoreBackend> = anchor_store.clone();
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_revoke_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
    let (td, router, _log, _broadcaster, person, identity, _window) =
        router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
            move |state| {
                state
                    .with_owner_approval_policy(policy)
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_for_state)
            }
        });

    let first_start = start_revoke(router.clone(), &person, first_target.clone()).await;
    let second_start = start_revoke(router.clone(), &person, actor_and_second_target.clone()).await;
    let first_assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            first_start.options,
        )
        .unwrap();
    let second_assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            second_start.options,
        )
        .unwrap();
    let first_body = revoke_finish_body(
        first_start.context,
        first_start.challenge_id,
        &first_assertion,
    );
    let second_body = revoke_finish_body(
        second_start.context,
        second_start.challenge_id,
        &second_assertion,
    );
    anchor_store.block_next_write();

    let first_uri = "/api/v1/household/owner-webauthn/revoke/finish";
    let first_auth = pop_header_for(&person, "POST", first_uri, unix_now(), &first_body);
    let first_request = Request::builder()
        .method("POST")
        .uri(first_uri)
        .header(header::AUTHORIZATION, first_auth)
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(Body::from(first_body))
        .unwrap();
    let first_router = router.clone();
    let first_task = tokio::spawn(async move {
        let resp = first_router.oneshot(first_request).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, bytes)
    });
    anchor_store.wait_for_blocked_write().await;

    let second_uri = "/api/v1/household/owner-webauthn/revoke/finish";
    let second_auth = pop_header_for(&person, "POST", second_uri, unix_now(), &second_body);
    let second_request = Request::builder()
        .method("POST")
        .uri(second_uri)
        .header(header::AUTHORIZATION, second_auth)
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(Body::from(second_body))
        .unwrap();
    let second_router = router.clone();
    let second_task = tokio::spawn(async move {
        let resp = second_router.oneshot(second_request).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, bytes)
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    anchor_store.release_blocked_write();

    let (first_status, first_bytes) = first_task.await.unwrap();
    let (second_status, second_bytes) = second_task.await.unwrap();
    assert_eq!(first_status, StatusCode::OK);
    let finish: OwnerWebauthnRevokeCredentialFinishResponse =
        household_rs::cbor::from_canonical_slice(&first_bytes).unwrap();
    assert_eq!(finish.active_credential_count, 1);
    assert_generic_unauth(second_status, &second_bytes);
    let loaded = load_owner_auth(&td, &identity);
    assert_eq!(
        revoke_events_for_target(&loaded, &first_target),
        vec![actor_and_second_target.clone()]
    );
    assert!(
        revoke_events_for_target(&loaded, &actor_and_second_target).is_empty(),
        "last-active guard must reject the still-active second target without appending"
    );
    assert_eq!(
        loaded
            .owner_webauthn_credentials(&identity.record)
            .unwrap()
            .active_count(),
        1
    );
    assert_eq!(
        active_credential_ids(&loaded, &identity),
        vec![actor_and_second_target]
    );
}

#[tokio::test]
async fn owner_webauthn_revoke_finish_anchor_failure_recovers_without_duplicate_revoke() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, mut authenticator) =
        owner_auth_with_three_webauthn_credentials(&identity);
    let active_ids = active_credential_ids(&owner_auth, &identity);
    let actor = active_ids[0].clone();
    let target = active_ids[1].clone();
    let anchor_store = Arc::new(FailingSetKeystore::new(td.path()));
    anchor_owner_webauthn_authority(anchor_store.as_ref(), &identity, &owner_auth);
    let anchor_for_state: Arc<dyn keystore_rs::KeystoreBackend> = anchor_store.clone();
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_revoke_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
    let (td, router, _log, _broadcaster, person, identity, _window) =
        router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
            move |state| {
                state
                    .with_owner_approval_policy(policy)
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_for_state)
            }
        });

    let start = start_revoke(router.clone(), &person, target.clone()).await;
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    let body = revoke_finish_body(start.context, start.challenge_id, &assertion);
    anchor_store.fail_writes(true);
    let (status, _headers, resp_bytes) =
        post_revoke_finish(router.clone(), &person, body.clone()).await;
    assert_generic_unauth(status, &resp_bytes);
    let loaded_after_fail = load_owner_auth(&td, &identity);
    assert_eq!(
        revoke_events_for_target(&loaded_after_fail, &target),
        vec![actor.clone()]
    );

    let (status, _headers, resp_bytes) = post_revoke_finish(router, &person, body).await;
    assert_generic_unauth(status, &resp_bytes);
    let loaded_after_retry = load_owner_auth(&td, &identity);
    assert_eq!(
        revoke_events_for_target(&loaded_after_retry, &target),
        vec![actor]
    );

    anchor_store.fail_writes(false);
    verify_or_update_owner_webauthn_authority_anchor(
        anchor_store.as_ref(),
        &loaded_after_retry.owner_webauthn,
        &identity.record,
        &loaded_after_retry.owner_person_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    )
    .expect("later enforcement advances anchor over persisted revoke");
    let loaded_after_recovery = load_owner_auth(&td, &identity);
    assert_eq!(
        revoke_events_for_target(&loaded_after_recovery, &target).len(),
        1
    );
}

#[tokio::test]
async fn owner_webauthn_revoke_finish_anchor_blocks_rollback_unrevoke() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, mut authenticator) =
        owner_auth_with_two_webauthn_credentials(&identity);
    let active_ids = active_credential_ids(&owner_auth, &identity);
    let target = active_ids[1].clone();
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    anchor_owner_webauthn_authority(anchor_store.as_ref(), &identity, &owner_auth);
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_revoke_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
    let (td, router, _log, _broadcaster, person, identity, _window) =
        router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
            let anchor_store = Arc::clone(&anchor_store);
            move |state| {
                state
                    .with_owner_approval_policy(policy)
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_store)
            }
        });

    let start = start_revoke(router.clone(), &person, target).await;
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    let body = revoke_finish_body(start.context, start.challenge_id, &assertion);
    let finish = revoke_finish(router, &person, body).await;
    assert_eq!(finish.active_credential_count, 1);
    let committed = load_owner_auth(&td, &identity);
    let truncated = owner_auth_without_last_webauthn_event(&committed);
    assert!(
        verify_or_update_owner_webauthn_authority_anchor(
            anchor_store.as_ref(),
            &truncated.owner_webauthn,
            &identity.record,
            &truncated.owner_person_cert,
            OwnerWebauthnAnchorMode::Enforcement,
        )
        .is_err(),
        "anchor must reject rollback that would un-revoke the credential"
    );
}

#[tokio::test]
async fn owner_webauthn_recovery_status_reports_not_ready_when_empty() {
    let (
        _td,
        router,
        _log,
        _broadcaster,
        person,
        identity,
        _window,
        _webauthn_anchor,
        recovery_anchor,
        _authenticator,
    ) = router_with_owner_webauthn_recovery(Duration::from_secs(45), true);

    let status = recovery_status(router, &person).await;

    assert!(!status.ready);
    assert!(
        read_owner_webauthn_recovery_anchor(recovery_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .is_none(),
        "status read path must not create a recovery anchor"
    );
}

#[tokio::test]
async fn owner_webauthn_recovery_start_policy_default_off_is_opaque() {
    let (
        _td,
        router,
        _log,
        _broadcaster,
        person,
        identity,
        _window,
        _webauthn_anchor,
        recovery_anchor,
        _authenticator,
    ) = router_with_owner_webauthn_recovery(Duration::from_secs(45), false);

    let (status, _headers, resp_bytes) = post_recovery_start(router, &person).await;

    assert_generic_unauth(status, &resp_bytes);
    assert!(
        read_owner_webauthn_recovery_anchor(recovery_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .is_none(),
        "policy-off recovery start must not write recovery anchor state"
    );
}

#[tokio::test]
async fn owner_webauthn_recovery_provision_reviewed_rollout_uses_recovery_code_switch() {
    let (
        td,
        router,
        _log,
        _broadcaster,
        person,
        identity,
        _window,
        _webauthn_anchor,
        recovery_anchor,
        mut authenticator,
        _state,
    ) = router_with_owner_webauthn_recovery_with_state(
        Duration::from_secs(45),
        OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout(),
        Some(100),
    );

    let start = start_recovery(router.clone(), &person).await;
    assert_eq!(start.context.op, OwnerOperation::ProvisionRecoveryCode);
    assert_eq!(start.context.pre_active_credential_count, Some(1));
    assert_eq!(
        start.context.capabilities,
        vec!["owner-auth-recovery-provision".to_string()],
        "reviewed-core-v2 must enable recovery through the dedicated recovery-code policy"
    );
    assert!(
        read_owner_webauthn_recovery_anchor(recovery_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .is_none(),
        "recovery provision start must stay challenge-only under the reviewed rollout"
    );

    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    let finish = recovery_finish(
        router,
        &person,
        recovery_finish_body(start.context, start.challenge_id, &assertion),
    )
    .await;

    assert!(finish.recovery_ready);
    assert!(!finish.recovery_code.is_empty());
    let loaded = load_owner_auth(&td, &identity);
    assert_eq!(loaded.owner_webauthn_recovery.entries().len(), 1);
    assert!(matches!(
        loaded.owner_webauthn_recovery.entries()[0].event.action,
        OwnerWebauthnRecoveryEventAction::Provision { .. }
    ));
    let head = verified_owner_webauthn_recovery_head(
        &loaded.owner_webauthn_recovery,
        &identity.record,
        &loaded.owner_person_cert,
    )
    .unwrap()
    .expect("reviewed rollout recovery provision has a head");
    let anchor =
        read_owner_webauthn_recovery_anchor(recovery_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("reviewed rollout recovery provision advances the recovery anchor");
    assert_eq!(anchor.sequence(), head.sequence);
    assert_eq!(anchor.head_hash(), head.head_hash);
}

#[tokio::test]
async fn owner_webauthn_recovery_provision_persists_verifier_and_anchor_without_plaintext() {
    let (
        td,
        router,
        _log,
        _broadcaster,
        person,
        identity,
        _window,
        _webauthn_anchor,
        recovery_anchor,
        mut authenticator,
    ) = router_with_owner_webauthn_recovery(Duration::from_secs(45), true);

    let initial = recovery_status(router.clone(), &person).await;
    assert!(!initial.ready);
    let start = start_recovery(router.clone(), &person).await;
    assert_eq!(start.context.recovery_head_sequence, None);
    assert_eq!(start.context.recovery_head_hash, None);
    assert_eq!(start.context.pre_active_credential_count, Some(1));
    assert_eq!(
        start.context.capabilities,
        vec!["owner-auth-recovery-provision".to_string()]
    );
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    let body = recovery_finish_body(start.context, start.challenge_id, &assertion);
    let finish = recovery_finish(router.clone(), &person, body).await;

    assert!(finish.recovery_ready);
    assert!(!finish.recovery_code.is_empty());
    let loaded = load_owner_auth(&td, &identity);
    assert_eq!(loaded.owner_webauthn_recovery.entries().len(), 1);
    let event = &loaded.owner_webauthn_recovery.entries()[0].event;
    assert_eq!(event.sequence, 0);
    match &event.action {
        OwnerWebauthnRecoveryEventAction::Provision { verifier } => {
            let verifier_bytes = household_rs::cbor::to_canonical_vec(verifier).unwrap();
            assert!(
                !verifier_bytes
                    .windows(finish.recovery_code.len())
                    .any(|window| window == finish.recovery_code.as_bytes()),
                "stored verifier must not contain plaintext recovery code"
            );
        }
        OwnerWebauthnRecoveryEventAction::Rotate { .. }
        | OwnerWebauthnRecoveryEventAction::Consume => {
            panic!("first recovery event must provision")
        }
    }
    let auth_bytes = fs::read(household_rs::storage::household_auth_state_path(td.path())).unwrap();
    assert!(
        !auth_bytes
            .windows(finish.recovery_code.len())
            .any(|window| window == finish.recovery_code.as_bytes()),
        "household_auth_state.cbor must not persist plaintext recovery code"
    );
    let head = verified_owner_webauthn_recovery_head(
        &loaded.owner_webauthn_recovery,
        &identity.record,
        &loaded.owner_person_cert,
    )
    .unwrap()
    .expect("recovery authority has a head");
    let anchor =
        read_owner_webauthn_recovery_anchor(recovery_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("finish advances recovery anchor");
    assert_eq!(anchor.sequence(), head.sequence);
    assert_eq!(anchor.head_hash(), head.head_hash);
    assert!(
        classify_owner_webauthn_recovery_anchor_read_only(
            recovery_anchor.as_ref(),
            &loaded.owner_webauthn_recovery,
            &identity.record,
            &loaded.owner_person_cert,
        )
        .is_ok()
    );
    assert_eq!(
        loaded
            .owner_webauthn_credentials(&identity.record)
            .unwrap()
            .active_count(),
        1,
        "recovery readiness must not alter WebAuthn active credential count"
    );
    let status = recovery_status(router, &person).await;
    assert!(status.ready);
}

#[tokio::test]
async fn owner_webauthn_add_credential_start_reviewed_rollout_returns_dual_challenges_without_mutation()
 {
    let (_td, router, _log, _broadcaster, person, identity, _window, mut authenticator, state) =
        router_with_owner_webauthn_add_credential(Duration::from_secs(45), true);

    let before = state
        .household
        .current_owner_auth()
        .await
        .expect("owner auth is present before AddCredential start");
    let before_webauthn_entries = before.owner_webauthn.entries().len();
    let before_head = verified_owner_webauthn_authority_head(
        &before.owner_webauthn,
        &identity.record,
        &before.owner_person_cert,
    )
    .unwrap()
    .expect("existing passkey has an anchored head");

    let start = start_add_credential(router.clone(), &person).await;

    assert!(!start.registration.challenge_id.is_empty());
    assert!(!start.approval.challenge_id.is_empty());
    assert_ne!(
        start.registration.challenge_id, start.approval.challenge_id,
        "registration and approval ceremonies must use distinct challenge ids"
    );
    assert_eq!(start.approval.context, start.context);
    assert_eq!(
        start.context.capabilities,
        vec!["owner-auth-add-credential".to_string()]
    );
    assert_eq!(
        start.context.authority_head_sequence,
        Some(before_head.sequence)
    );
    assert_eq!(
        start
            .context
            .authority_head_hash
            .as_ref()
            .map(ByteBuf::as_ref),
        Some(before_head.head_hash.as_slice())
    );
    assert_eq!(start.context.pre_active_credential_count, Some(1));
    assert_eq!(
        start
            .context
            .new_credential_binding_hash
            .as_ref()
            .map(|hash| hash.as_ref().len()),
        Some(32),
        "AddCredential must bind the future registration ceremony"
    );

    let binding = add_credential_registration_binding_from_context(&start.context);
    let registration_challenge_id = household_rs::owner_webauthn::OwnerWebauthnChallengeId::parse(
        start.registration.challenge_id.clone(),
    )
    .unwrap();
    let approval_challenge_id = household_rs::owner_webauthn::OwnerWebauthnChallengeId::parse(
        start.approval.challenge_id.clone(),
    )
    .unwrap();
    let mut rp = state
        .owner_webauthn_rp
        .as_ref()
        .expect("rp configured")
        .lock()
        .await;
    rp.require_registration_challenge_binding(unix_now(), &registration_challenge_id, &binding)
        .expect("registration challenge must be bound to the digest in the context");
    rp.require_owner_approval_challenge_context(unix_now(), &approval_challenge_id, &start.context)
        .expect("approval challenge must be bound to the same AddCredential context");
    drop(rp);

    let mut fresh_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    drop(
        fresh_authenticator
            .do_registration(
                Url::parse("https://alpha.example.test").unwrap(),
                start.registration.options,
            )
            .unwrap(),
    );
    drop(
        authenticator
            .do_authentication(
                Url::parse("https://alpha.example.test").unwrap(),
                start.approval.options,
            )
            .unwrap(),
    );

    let after = state
        .household
        .current_owner_auth()
        .await
        .expect("owner auth remains present after AddCredential start");
    assert_eq!(
        after.owner_webauthn.entries().len(),
        before_webauthn_entries,
        "add-credential start must not append WebAuthn Add"
    );
    let anchor_after = read_owner_webauthn_authority_anchor(
        state
            .owner_webauthn_anchor
            .as_ref()
            .unwrap()
            .keystore
            .as_ref(),
        &identity.record.hh_id,
    )
    .unwrap()
    .expect("anchor remains present");
    assert_eq!(anchor_after.sequence(), before_head.sequence);
    assert_eq!(anchor_after.head_hash(), before_head.head_hash);
}

#[tokio::test]
async fn owner_webauthn_add_credential_finish_reviewed_rollout_adds_credential_and_advances_anchor()
{
    let (_td, router, _log, _broadcaster, person, identity, _window, mut authenticator, state) =
        router_with_owner_webauthn_add_credential(Duration::from_secs(45), true);
    let before = state
        .household
        .current_owner_auth()
        .await
        .expect("owner auth is present before AddCredential finish");
    let before_entries = before.owner_webauthn.entries().len();
    let before_head = verified_owner_webauthn_authority_head(
        &before.owner_webauthn,
        &identity.record,
        &before.owner_person_cert,
    )
    .unwrap()
    .expect("existing passkey has an anchored head");

    let start = start_add_credential(router.clone(), &person).await;
    let mut fresh_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = fresh_authenticator
        .do_registration(
            Url::parse("https://alpha.example.test").unwrap(),
            start.registration.options,
        )
        .unwrap();
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.approval.options,
        )
        .unwrap();
    let approval_credential_id = ByteBuf::from(assertion.raw_id.as_slice().to_vec());

    let finish = add_credential_finish(
        router.clone(),
        &person,
        add_credential_finish_body(
            start.context,
            start.registration.challenge_id,
            start.approval.challenge_id,
            credential,
            &assertion,
        ),
    )
    .await;

    assert_eq!(finish.active_credential_count, 2);
    let after = state
        .household
        .current_owner_auth()
        .await
        .expect("owner auth remains present after AddCredential finish");
    assert_eq!(after.owner_webauthn.entries().len(), before_entries + 1);
    let add_entry = after
        .owner_webauthn
        .entries()
        .last()
        .expect("AddCredential finish appends one event");
    match &add_entry.event.actor {
        OwnerWebauthnEventActor::OwnerCredential { credential_id } => {
            assert_eq!(credential_id, &approval_credential_id);
        }
        other => panic!("unexpected AddCredential actor: {other:?}"),
    }
    match &add_entry.event.action {
        OwnerWebauthnCredentialEventAction::Add { credential } => {
            assert_eq!(
                credential.credential_id_bytes(),
                finish.credential_id.as_ref()
            );
        }
        other => panic!("unexpected AddCredential action: {other:?}"),
    }
    let credentials = after.owner_webauthn_credentials(&identity.record).unwrap();
    assert_eq!(credentials.active_count(), 2);
    let after_head = verified_owner_webauthn_authority_head(
        &after.owner_webauthn,
        &identity.record,
        &after.owner_person_cert,
    )
    .unwrap()
    .expect("AddCredential finish has a new head");
    assert_eq!(after_head.sequence, before_head.sequence + 1);
    let anchor_after = read_owner_webauthn_authority_anchor(
        state
            .owner_webauthn_anchor
            .as_ref()
            .unwrap()
            .keystore
            .as_ref(),
        &identity.record.hh_id,
    )
    .unwrap()
    .expect("anchor remains present");
    assert_eq!(anchor_after.sequence(), after_head.sequence);
    assert_eq!(anchor_after.head_hash(), after_head.head_hash);
}

#[tokio::test]
async fn owner_webauthn_add_credential_finish_context_mismatch_does_not_consume_challenges() {
    let (_td, router, _log, _broadcaster, person, _identity, _window, mut authenticator, _state) =
        router_with_owner_webauthn_add_credential(Duration::from_secs(45), true);
    let start = start_add_credential(router.clone(), &person).await;
    let mut fresh_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = fresh_authenticator
        .do_registration(
            Url::parse("https://alpha.example.test").unwrap(),
            start.registration.options.clone(),
        )
        .unwrap();
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.approval.options,
        )
        .unwrap();

    let mut mismatched_context = start.context.clone();
    mismatched_context.replay_nonce = ByteBuf::from([0x44; 32].to_vec());
    let (status, _headers, bytes) = post_add_credential_finish(
        router.clone(),
        &person,
        add_credential_finish_body(
            mismatched_context,
            start.registration.challenge_id.clone(),
            start.approval.challenge_id.clone(),
            credential.clone(),
            &assertion,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_generic_unauth(status, &bytes);

    let finish = add_credential_finish(
        router,
        &person,
        add_credential_finish_body(
            start.context,
            start.registration.challenge_id,
            start.approval.challenge_id,
            credential,
            &assertion,
        ),
    )
    .await;
    assert_eq!(finish.active_credential_count, 2);
}

#[tokio::test]
async fn owner_webauthn_add_credential_finish_nested_version_mismatch_does_not_consume_challenges()
{
    let (_td, router, _log, _broadcaster, person, _identity, _window, mut authenticator, _state) =
        router_with_owner_webauthn_add_credential(Duration::from_secs(45), true);
    let start = start_add_credential(router.clone(), &person).await;
    let mut fresh_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = fresh_authenticator
        .do_registration(
            Url::parse("https://alpha.example.test").unwrap(),
            start.registration.options.clone(),
        )
        .unwrap();
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.approval.options,
        )
        .unwrap();
    let approval = approval_v2_from_assertion(start.context.clone(), &assertion);
    let body = household_rs::cbor::to_canonical_vec(&OwnerWebauthnAddCredentialFinishRequest {
        version: 1,
        context: start.context.clone(),
        registration: OwnerWebauthnRegistrationFinishRequest {
            version: 2,
            challenge_id: start.registration.challenge_id.clone(),
            credential: credential.clone(),
        },
        approval: OwnerApprovalV2FinishBody {
            version: 1,
            challenge_id: start.approval.challenge_id.clone(),
            approval,
        },
    })
    .unwrap();

    let (status, _headers, bytes) = post_add_credential_finish(router.clone(), &person, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_generic_unauth(status, &bytes);

    let finish = add_credential_finish(
        router,
        &person,
        add_credential_finish_body(
            start.context,
            start.registration.challenge_id,
            start.approval.challenge_id,
            credential,
            &assertion,
        ),
    )
    .await;
    assert_eq!(finish.active_credential_count, 2);
}

#[tokio::test]
async fn owner_webauthn_add_credential_finish_bad_approval_does_not_append_or_anchor() {
    let (_td, router, _log, _broadcaster, person, identity, _window, mut authenticator, state) =
        router_with_owner_webauthn_add_credential(Duration::from_secs(45), true);
    let before = state
        .household
        .current_owner_auth()
        .await
        .expect("owner auth is present before bad AddCredential finish");
    let before_entries = before.owner_webauthn.entries().len();
    let before_head = verified_owner_webauthn_authority_head(
        &before.owner_webauthn,
        &identity.record,
        &before.owner_person_cert,
    )
    .unwrap()
    .expect("existing passkey has an anchored head");

    let start = start_add_credential(router.clone(), &person).await;
    let mut fresh_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = fresh_authenticator
        .do_registration(
            Url::parse("https://alpha.example.test").unwrap(),
            start.registration.options,
        )
        .unwrap();
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.approval.options,
        )
        .unwrap();
    let mut approval = approval_v2_from_assertion(start.context.clone(), &assertion);
    approval.signature = ByteBuf::from([0x42; 64].to_vec());
    let body = household_rs::cbor::to_canonical_vec(&OwnerWebauthnAddCredentialFinishRequest {
        version: 1,
        context: start.context,
        registration: OwnerWebauthnRegistrationFinishRequest {
            version: 1,
            challenge_id: start.registration.challenge_id,
            credential,
        },
        approval: OwnerApprovalV2FinishBody {
            version: 1,
            challenge_id: start.approval.challenge_id,
            approval,
        },
    })
    .unwrap();

    let (status, _headers, bytes) = post_add_credential_finish(router.clone(), &person, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_generic_unauth(status, &bytes);

    let after = state
        .household
        .current_owner_auth()
        .await
        .expect("owner auth remains present after rejected AddCredential finish");
    assert_eq!(
        after.owner_webauthn.entries().len(),
        before_entries,
        "bad approval assertion must not append WebAuthn Add"
    );
    let anchor_after = read_owner_webauthn_authority_anchor(
        state
            .owner_webauthn_anchor
            .as_ref()
            .unwrap()
            .keystore
            .as_ref(),
        &identity.record.hh_id,
    )
    .unwrap()
    .expect("anchor remains present");
    assert_eq!(anchor_after.sequence(), before_head.sequence);
    assert_eq!(anchor_after.head_hash(), before_head.head_hash);
}

#[tokio::test]
async fn owner_webauthn_add_credential_finish_replay_after_success_does_not_duplicate_add() {
    let (_td, router, _log, _broadcaster, person, identity, _window, mut authenticator, state) =
        router_with_owner_webauthn_add_credential(Duration::from_secs(45), true);
    let before = state
        .household
        .current_owner_auth()
        .await
        .expect("owner auth is present before AddCredential finish replay");
    let before_entries = before.owner_webauthn.entries().len();

    let start = start_add_credential(router.clone(), &person).await;
    let mut fresh_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = fresh_authenticator
        .do_registration(
            Url::parse("https://alpha.example.test").unwrap(),
            start.registration.options,
        )
        .unwrap();
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.approval.options,
        )
        .unwrap();
    let body = add_credential_finish_body(
        start.context,
        start.registration.challenge_id,
        start.approval.challenge_id,
        credential,
        &assertion,
    );

    let finish = add_credential_finish(router.clone(), &person, body.clone()).await;
    assert_eq!(finish.active_credential_count, 2);

    let (status, _headers, bytes) = post_add_credential_finish(router.clone(), &person, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_generic_unauth(status, &bytes);

    let after = state
        .household
        .current_owner_auth()
        .await
        .expect("owner auth remains present after replayed AddCredential finish");
    assert_eq!(
        after.owner_webauthn.entries().len(),
        before_entries + 1,
        "replaying a consumed AddCredential finish must not append a second Add"
    );
    let credentials = after.owner_webauthn_credentials(&identity.record).unwrap();
    assert_eq!(credentials.active_count(), 2);
    let adds_for_new_credential = after
        .owner_webauthn
        .entries()
        .iter()
        .filter(|entry| {
            matches!(
                &entry.event.action,
                OwnerWebauthnCredentialEventAction::Add { credential }
                    if credential.credential_id_bytes() == finish.credential_id.as_ref()
            )
        })
        .count();
    assert_eq!(
        adds_for_new_credential, 1,
        "replayed AddCredential finish must not duplicate the new credential"
    );
}

#[tokio::test]
async fn owner_webauthn_add_credential_finish_anchor_failure_does_not_duplicate_add() {
    let td = tempfile::tempdir().unwrap();
    let failing_anchor = Arc::new(FailingSetKeystore::new(td.path()));
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> = failing_anchor.clone();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, mut authenticator) =
        owner_auth_with_webauthn_credential(&identity);
    let before_entries = owner_auth.owner_webauthn.entries().len();
    let before_head =
        anchor_owner_webauthn_authority(failing_anchor.as_ref(), &identity, &owner_auth);
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_add_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
    let (td, router, _log, _broadcaster, person, identity, _window) =
        router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
            move |state| {
                state
                    .with_owner_approval_policy(policy)
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_store)
            }
        });

    let start = start_add_credential(router.clone(), &person).await;
    let mut fresh_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = fresh_authenticator
        .do_registration(
            Url::parse("https://alpha.example.test").unwrap(),
            start.registration.options,
        )
        .unwrap();
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.approval.options,
        )
        .unwrap();
    let body = add_credential_finish_body(
        start.context,
        start.registration.challenge_id,
        start.approval.challenge_id,
        credential,
        &assertion,
    );

    failing_anchor.fail_writes(true);
    let (status, _headers, bytes) =
        post_add_credential_finish(router.clone(), &person, body.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_generic_unauth(status, &bytes);

    let loaded_after_fail = load_owner_auth(&td, &identity);
    assert_eq!(
        loaded_after_fail.owner_webauthn.entries().len(),
        before_entries + 1,
        "failed anchor advance still saves exactly one AddCredential Add"
    );
    assert_eq!(
        loaded_after_fail
            .owner_webauthn_credentials(&identity.record)
            .unwrap()
            .active_count(),
        2
    );
    let anchor_after_fail =
        read_owner_webauthn_authority_anchor(failing_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("previous WebAuthn anchor remains present");
    assert_eq!(anchor_after_fail.sequence(), before_head.sequence);
    assert_eq!(anchor_after_fail.head_hash(), before_head.head_hash);

    let (status, _headers, bytes) = post_add_credential_finish(router, &person, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_generic_unauth(status, &bytes);
    let loaded_after_retry = load_owner_auth(&td, &identity);
    assert_eq!(
        loaded_after_retry.owner_webauthn.entries().len(),
        before_entries + 1,
        "retry after anchor failure must not sign a duplicate AddCredential Add"
    );

    failing_anchor.fail_writes(false);
    verify_or_update_owner_webauthn_authority_anchor(
        failing_anchor.as_ref(),
        &loaded_after_retry.owner_webauthn,
        &identity.record,
        &loaded_after_retry.owner_person_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    )
    .expect("later enforcement advances anchor over persisted AddCredential Add");
    let repaired_head = verified_owner_webauthn_authority_head(
        &loaded_after_retry.owner_webauthn,
        &identity.record,
        &loaded_after_retry.owner_person_cert,
    )
    .unwrap()
    .expect("persisted AddCredential Add has a head");
    let repaired_anchor =
        read_owner_webauthn_authority_anchor(failing_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("later enforcement writes repaired WebAuthn anchor");
    assert_eq!(repaired_anchor.sequence(), repaired_head.sequence);
    assert_eq!(repaired_anchor.head_hash(), repaired_head.head_hash);
}

#[tokio::test]
async fn owner_webauthn_add_credential_start_policy_off_rejects_opaque() {
    let (_td, router, _log, _broadcaster, person, _identity, _window, _authenticator, _state) =
        router_with_owner_webauthn_add_credential(Duration::from_secs(45), false);

    let (status, _headers, bytes) = post_add_credential_start(router, Some(&person)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_generic_unauth(status, &bytes);
}

#[tokio::test]
async fn owner_webauthn_add_credential_start_never_enrolled_rejects_opaque() {
    let (_td, router, _log, _broadcaster, person, _identity, _window) =
        router_with_v2_policy_without_passkey(Duration::from_secs(45));

    let (status, _headers, bytes) = post_add_credential_start(router, Some(&person)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_generic_unauth(status, &bytes);
}

#[tokio::test]
async fn owner_webauthn_add_credential_start_missing_anchor_rejects_opaque() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, _authenticator) = owner_auth_with_webauthn_credential(&identity);
    let webauthn_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_add_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
    let (_td, router, _log, _broadcaster, person, _identity, _window) = router_from_owner_auth(
        td,
        identity,
        owner_auth,
        person,
        Duration::from_secs(45),
        move |state| {
            state
                .with_owner_approval_policy(policy)
                .with_owner_webauthn_rp(rp)
                .with_owner_webauthn_anchor(webauthn_anchor_store)
        },
    );

    let (status, _headers, bytes) = post_add_credential_start(router, Some(&person)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_generic_unauth(status, &bytes);
}

#[tokio::test]
async fn owner_webauthn_add_credential_start_invalid_anchor_rejects_opaque() {
    for anchor in ["truncated", "divergent"] {
        let td = tempfile::tempdir().unwrap();
        let identity = Arc::new(bootstrap(td.path()));
        let (owner_auth, person, rp, _authenticator) =
            owner_auth_with_webauthn_credential(&identity);
        let webauthn_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
            Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
        let stale_anchor = match anchor {
            "truncated" => OwnerWebauthnAuthorityAnchor::new(
                &identity.record,
                &owner_auth.owner_person_cert,
                1,
                [0x42; 32],
            ),
            "divergent" => OwnerWebauthnAuthorityAnchor::new(
                &identity.record,
                &owner_auth.owner_person_cert,
                0,
                [0x43; 32],
            ),
            _ => unreachable!(),
        };
        write_owner_webauthn_authority_anchor(webauthn_anchor_store.as_ref(), &stale_anchor)
            .unwrap();
        let policy = OwnerApprovalEnforcementPolicy::default()
            .with_add_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
        let (_td, router, _log, _broadcaster, person, identity, _window) =
            router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
                let webauthn_anchor_store = Arc::clone(&webauthn_anchor_store);
                move |state| {
                    state
                        .with_owner_approval_policy(policy)
                        .with_owner_webauthn_rp(rp)
                        .with_owner_webauthn_anchor(webauthn_anchor_store)
                }
            });

        let (status, _headers, bytes) = post_add_credential_start(router, Some(&person)).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_generic_unauth(status, &bytes);
        let persisted = read_owner_webauthn_authority_anchor(
            webauthn_anchor_store.as_ref(),
            &identity.record.hh_id,
        )
        .unwrap()
        .expect("AddCredential start leaves invalid anchor untouched");
        assert_eq!(persisted.sequence(), stale_anchor.sequence());
        assert_eq!(persisted.head_hash(), stale_anchor.head_hash());
    }
}

#[tokio::test]
async fn owner_webauthn_add_credential_start_all_revoked_rejects_opaque() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp) = owner_auth_with_revoked_webauthn_credential(&identity);
    let webauthn_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    anchor_owner_webauthn_authority(webauthn_anchor_store.as_ref(), &identity, &owner_auth);
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_add_credential(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
    let (_td, router, _log, _broadcaster, person, _identity, _window) = router_from_owner_auth(
        td,
        identity,
        owner_auth,
        person,
        Duration::from_secs(45),
        move |state| {
            state
                .with_owner_approval_policy(policy)
                .with_owner_webauthn_rp(rp)
                .with_owner_webauthn_anchor(webauthn_anchor_store)
        },
    );

    let (status, _headers, bytes) = post_add_credential_start(router, Some(&person)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_generic_unauth(status, &bytes);
}

#[tokio::test]
async fn owner_webauthn_add_credential_start_missing_pop_rejects_opaque() {
    let (_td, router, _log, _broadcaster, _person, _identity, _window, _authenticator, _state) =
        router_with_owner_webauthn_add_credential(Duration::from_secs(45), true);

    let (status, _headers, bytes) = post_add_credential_start(router, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_generic_unauth(status, &bytes);
}

#[tokio::test]
async fn owner_webauthn_add_credential_start_wrong_pop_rejects_opaque() {
    let (_td, router, _log, _broadcaster, _person, _identity, _window, _authenticator, _state) =
        router_with_owner_webauthn_add_credential(Duration::from_secs(45), true);
    let wrong_person = P256Keypair::generate();

    let (status, _headers, bytes) = post_add_credential_start(router, Some(&wrong_person)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_generic_unauth(status, &bytes);
}

#[tokio::test]
async fn owner_webauthn_recovery_consume_start_binds_fresh_registration_without_mutation() {
    let (
        td,
        router,
        _log,
        _broadcaster,
        person,
        identity,
        _window,
        _webauthn_anchor,
        recovery_anchor,
        mut authenticator,
    ) = router_with_owner_webauthn_recovery(Duration::from_secs(45), true);

    let provision_start = start_recovery(router.clone(), &person).await;
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            provision_start.options,
        )
        .unwrap();
    let provision_finish = recovery_finish(
        router.clone(),
        &person,
        recovery_finish_body(
            provision_start.context,
            provision_start.challenge_id,
            &assertion,
        ),
    )
    .await;
    let before_start = load_owner_auth(&td, &identity);
    let before_recovery_entries = before_start.owner_webauthn_recovery.entries().len();
    let before_webauthn_entries = before_start.owner_webauthn.entries().len();
    let recovery_head = verified_owner_webauthn_recovery_head(
        &before_start.owner_webauthn_recovery,
        &identity.record,
        &before_start.owner_person_cert,
    )
    .unwrap()
    .expect("recovery provision has a head");
    let recovery_anchor_before =
        read_owner_webauthn_recovery_anchor(recovery_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("provision finish advanced recovery anchor");

    let start =
        start_recovery_consume(router.clone(), &person, &provision_finish.recovery_code).await;

    assert!(!start.challenge_id.is_empty());
    assert_eq!(
        start.context.capabilities,
        vec!["owner-auth-recovery-consume".to_string()]
    );
    assert_eq!(start.context.pre_active_credential_count, Some(1));
    assert_eq!(
        start.context.recovery_head_sequence,
        Some(recovery_head.sequence)
    );
    assert_eq!(
        start
            .context
            .recovery_head_hash
            .as_ref()
            .map(ByteBuf::as_ref),
        Some(recovery_head.head_hash.as_slice())
    );
    assert_eq!(
        start
            .context
            .new_credential_binding_hash
            .as_ref()
            .map(|hash| hash.as_ref().len()),
        Some(32),
        "RecoverCredential must bind the future registration ceremony"
    );
    let mut fresh_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    drop(
        fresh_authenticator
            .do_registration(
                Url::parse("https://alpha.example.test").unwrap(),
                start.options,
            )
            .unwrap(),
    );
    let after_start = load_owner_auth(&td, &identity);
    assert_eq!(
        after_start.owner_webauthn_recovery.entries().len(),
        before_recovery_entries,
        "consume start must not append recovery Consume"
    );
    assert_eq!(
        after_start.owner_webauthn.entries().len(),
        before_webauthn_entries,
        "consume start must not append WebAuthn Add"
    );
    let recovery_anchor_after =
        read_owner_webauthn_recovery_anchor(recovery_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("recovery anchor remains present");
    assert_eq!(
        recovery_anchor_after.sequence(),
        recovery_anchor_before.sequence()
    );
    assert_eq!(
        recovery_anchor_after.head_hash(),
        recovery_anchor_before.head_hash()
    );
}

#[tokio::test]
async fn owner_webauthn_recovery_consume_start_reviewed_rollout_allows_zero_active_break_glass() {
    let (
        td,
        router,
        _log,
        _broadcaster,
        person,
        identity,
        _window,
        webauthn_anchor,
        _recovery_anchor,
        mut authenticator,
        state,
    ) = router_with_owner_webauthn_recovery_with_state(
        Duration::from_secs(45),
        OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout(),
        Some(100),
    );

    let recovery_code = provision_recovery_code(router.clone(), &person, &mut authenticator).await;
    let mut owner_auth = load_owner_auth(&td, &identity);
    let credential_id = owner_auth
        .owner_webauthn_credentials(&identity.record)
        .unwrap()
        .active_credentials()
        .first()
        .expect("provision starts from one active passkey")
        .credential_id_bytes()
        .to_vec();
    let previous = owner_auth
        .owner_webauthn
        .entries()
        .last()
        .expect("webauthn head exists")
        .clone();
    let revoke = OwnerWebauthnAuthority::sign_append(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv present in single-machine household"),
        &identity.record,
        &owner_auth.owner_person_cert,
        &previous,
        &credential_id,
        OwnerWebauthnCredentialEventAction::Revoke {
            credential_id: ByteBuf::from(credential_id.clone()),
        },
        unix_now(),
    )
    .unwrap();
    owner_auth.owner_webauthn.push_signed(revoke);
    owner_auth.updated_at = unix_now();
    owner_auth.verify(&identity.record, unix_now()).unwrap();
    assert_eq!(
        owner_auth
            .owner_webauthn_credentials(&identity.record)
            .unwrap()
            .active_count(),
        0,
        "test setup must exercise the break-glass case"
    );
    owner_auth.save(td.path()).unwrap();
    state
        .household
        .set_owner_auth(Arc::new(owner_auth.clone()))
        .await;
    anchor_owner_webauthn_authority(webauthn_anchor.as_ref(), &identity, &owner_auth);

    let start = start_recovery_consume(router, &person, &recovery_code).await;

    assert_eq!(
        start.context.pre_active_credential_count,
        Some(0),
        "reviewed-core-v2 recovery consume must preserve break-glass semantics"
    );
    assert_eq!(start.context.op, OwnerOperation::RecoverCredential);
}

#[tokio::test]
async fn owner_webauthn_recovery_consume_start_wrong_code_is_opaque_and_does_not_burn_recovery() {
    let (
        _td,
        router,
        _log,
        _broadcaster,
        person,
        _identity,
        _window,
        _webauthn_anchor,
        _recovery_anchor,
        mut authenticator,
    ) = router_with_owner_webauthn_recovery(Duration::from_secs(45), true);

    let provision_start = start_recovery(router.clone(), &person).await;
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            provision_start.options,
        )
        .unwrap();
    let provision_finish = recovery_finish(
        router.clone(),
        &person,
        recovery_finish_body(
            provision_start.context,
            provision_start.challenge_id,
            &assertion,
        ),
    )
    .await;

    let (status, _headers, resp_bytes) =
        post_recovery_consume_start(router.clone(), &person, "wrong-recovery-code").await;
    assert_generic_unauth(status, &resp_bytes);

    let retry =
        start_recovery_consume(router.clone(), &person, &provision_finish.recovery_code).await;
    assert_eq!(retry.context.op, OwnerOperation::RecoverCredential);
}

#[tokio::test]
async fn owner_webauthn_recovery_consume_start_rate_limit_rejects_opaque_without_challenge() {
    let (
        _td,
        router,
        _log,
        _broadcaster,
        person,
        _identity,
        _window,
        _webauthn_anchor,
        _recovery_anchor,
        mut authenticator,
    ) = router_with_owner_webauthn_recovery_with_limiter(Duration::from_secs(45), true, Some(1));
    let recovery_code = provision_recovery_code(router.clone(), &person, &mut authenticator).await;

    let first = start_recovery_consume(router.clone(), &person, &recovery_code).await;
    assert_eq!(first.context.op, OwnerOperation::RecoverCredential);

    let (status, _headers, resp_bytes) =
        post_recovery_consume_start(router.clone(), &person, &recovery_code).await;
    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_recovery_consume_start_missing_limiter_fails_closed() {
    let (
        _td,
        router,
        _log,
        _broadcaster,
        person,
        _identity,
        _window,
        _webauthn_anchor,
        _recovery_anchor,
        mut authenticator,
    ) = router_with_owner_webauthn_recovery_with_limiter(Duration::from_secs(45), true, None);
    let recovery_code = provision_recovery_code(router.clone(), &person, &mut authenticator).await;

    let (status, _headers, resp_bytes) =
        post_recovery_consume_start(router.clone(), &person, &recovery_code).await;
    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_recovery_consume_finish_adds_credential_and_consumes_code() {
    let (
        td,
        router,
        _log,
        _broadcaster,
        person,
        identity,
        _window,
        webauthn_anchor,
        recovery_anchor,
        mut authenticator,
    ) = router_with_owner_webauthn_recovery(Duration::from_secs(45), true);
    let recovery_code = provision_recovery_code(router.clone(), &person, &mut authenticator).await;
    let start = start_recovery_consume(router.clone(), &person, &recovery_code).await;
    let recovery_head_sequence = start.context.recovery_head_sequence.unwrap();
    let recovery_head_hash = start.context.recovery_head_hash.clone().unwrap();
    let mut fresh_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = fresh_authenticator
        .do_registration(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();

    let finish = recovery_consume_finish(
        router.clone(),
        &person,
        recovery_consume_finish_body(
            start.context,
            start.challenge_id,
            credential,
            &recovery_code,
        ),
    )
    .await;

    assert_eq!(finish.active_credential_count, 2);
    assert!(!finish.recovery_ready);
    assert!(!finish.credential_id.is_empty());
    let loaded = load_owner_auth(&td, &identity);
    let credentials = loaded.owner_webauthn_credentials(&identity.record).unwrap();
    assert_eq!(credentials.active_count(), 2);
    assert!(
        credentials
            .active_credentials()
            .iter()
            .any(|credential| credential.credential_id_bytes() == finish.credential_id.as_ref())
    );
    let recovery_adds = loaded
        .owner_webauthn
        .entries()
        .iter()
        .filter(|entry| {
            matches!(
                &entry.event.actor,
                OwnerWebauthnEventActor::RecoveryProof {
                    recovery_head_sequence: sequence,
                    recovery_head_hash: hash,
                } if *sequence == recovery_head_sequence
                    && hash.as_ref() == recovery_head_hash.as_ref()
            ) && matches!(
                &entry.event.action,
                OwnerWebauthnCredentialEventAction::Add { .. }
            )
        })
        .count();
    assert_eq!(recovery_adds, 1, "finish must record one RecoveryProof Add");
    let consumes = loaded
        .owner_webauthn_recovery
        .entries()
        .iter()
        .filter(|entry| {
            matches!(
                entry.event.action,
                OwnerWebauthnRecoveryEventAction::Consume
            )
        })
        .count();
    assert_eq!(consumes, 1, "finish must record one recovery Consume");
    assert!(!loaded.owner_webauthn_recovery.recovery_ready());
    let webauthn_head = verified_owner_webauthn_authority_head(
        &loaded.owner_webauthn,
        &identity.record,
        &loaded.owner_person_cert,
    )
    .unwrap()
    .expect("webauthn authority has a head after recovery add");
    let webauthn_anchor =
        read_owner_webauthn_authority_anchor(webauthn_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("finish advances WebAuthn anchor");
    assert_eq!(webauthn_anchor.sequence(), webauthn_head.sequence);
    assert_eq!(webauthn_anchor.head_hash(), webauthn_head.head_hash);
    let recovery_head = verified_owner_webauthn_recovery_head(
        &loaded.owner_webauthn_recovery,
        &identity.record,
        &loaded.owner_person_cert,
    )
    .unwrap()
    .expect("recovery authority has a head after consume");
    let recovery_anchor =
        read_owner_webauthn_recovery_anchor(recovery_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("finish advances recovery anchor");
    assert_eq!(recovery_anchor.sequence(), recovery_head.sequence);
    assert_eq!(recovery_anchor.head_hash(), recovery_head.head_hash);
}

#[tokio::test]
async fn owner_webauthn_recovery_consume_finish_wrong_code_does_not_consume_challenge() {
    let (
        _td,
        router,
        _log,
        _broadcaster,
        person,
        _identity,
        _window,
        _webauthn_anchor,
        _recovery_anchor,
        mut authenticator,
    ) = router_with_owner_webauthn_recovery(Duration::from_secs(45), true);
    let recovery_code = provision_recovery_code(router.clone(), &person, &mut authenticator).await;
    let start = start_recovery_consume(router.clone(), &person, &recovery_code).await;
    let mut fresh_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = fresh_authenticator
        .do_registration(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options.clone(),
        )
        .unwrap();

    let (status, _headers, resp_bytes) = post_recovery_consume_finish(
        router.clone(),
        &person,
        recovery_consume_finish_body(
            start.context.clone(),
            start.challenge_id.clone(),
            credential.clone(),
            "wrong-recovery-code",
        ),
    )
    .await;
    assert_generic_unauth(status, &resp_bytes);

    let finish = recovery_consume_finish(
        router.clone(),
        &person,
        recovery_consume_finish_body(
            start.context,
            start.challenge_id,
            credential,
            &recovery_code,
        ),
    )
    .await;
    assert_eq!(finish.active_credential_count, 2);
}

#[tokio::test]
async fn owner_webauthn_recovery_consume_finish_context_mismatch_does_not_consume_challenge() {
    let (
        _td,
        router,
        _log,
        _broadcaster,
        person,
        _identity,
        _window,
        _webauthn_anchor,
        _recovery_anchor,
        mut authenticator,
    ) = router_with_owner_webauthn_recovery(Duration::from_secs(45), true);
    let recovery_code = provision_recovery_code(router.clone(), &person, &mut authenticator).await;
    let start = start_recovery_consume(router.clone(), &person, &recovery_code).await;
    let mut fresh_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = fresh_authenticator
        .do_registration(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options.clone(),
        )
        .unwrap();
    let mut mismatched_context = start.context.clone();
    mismatched_context.pre_active_credential_count = mismatched_context
        .pre_active_credential_count
        .map(|count| count + 1);

    let (status, _headers, resp_bytes) = post_recovery_consume_finish(
        router.clone(),
        &person,
        recovery_consume_finish_body(
            mismatched_context,
            start.challenge_id.clone(),
            credential.clone(),
            &recovery_code,
        ),
    )
    .await;
    assert_generic_unauth(status, &resp_bytes);

    let finish = recovery_consume_finish(
        router.clone(),
        &person,
        recovery_consume_finish_body(
            start.context,
            start.challenge_id,
            credential,
            &recovery_code,
        ),
    )
    .await;
    assert_eq!(finish.active_credential_count, 2);
}

#[tokio::test]
async fn owner_webauthn_recovery_consume_finish_wrong_code_counts_rate_limit() {
    let (
        td,
        router,
        _log,
        _broadcaster,
        person,
        identity,
        _window,
        _webauthn_anchor,
        _recovery_anchor,
        mut authenticator,
    ) = router_with_owner_webauthn_recovery_with_limiter(Duration::from_secs(45), true, Some(2));
    let recovery_code = provision_recovery_code(router.clone(), &person, &mut authenticator).await;
    let start = start_recovery_consume(router.clone(), &person, &recovery_code).await;
    let mut fresh_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = fresh_authenticator
        .do_registration(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();

    let (status, _headers, resp_bytes) = post_recovery_consume_finish(
        router.clone(),
        &person,
        recovery_consume_finish_body(
            start.context.clone(),
            start.challenge_id.clone(),
            credential.clone(),
            "wrong-recovery-code",
        ),
    )
    .await;
    assert_generic_unauth(status, &resp_bytes);
    let (status, _headers, resp_bytes) = post_recovery_consume_finish(
        router.clone(),
        &person,
        recovery_consume_finish_body(
            start.context,
            start.challenge_id,
            credential,
            &recovery_code,
        ),
    )
    .await;
    assert_generic_unauth(status, &resp_bytes);
    let loaded = load_owner_auth(&td, &identity);
    assert_eq!(
        loaded
            .owner_webauthn
            .entries()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.event.actor,
                    OwnerWebauthnEventActor::RecoveryProof { .. }
                ) && matches!(
                    entry.event.action,
                    OwnerWebauthnCredentialEventAction::Add { .. }
                )
            })
            .count(),
        0,
        "over-limit retry must not add the credential"
    );
    assert_eq!(
        loaded
            .owner_webauthn_recovery
            .entries()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.event.action,
                    OwnerWebauthnRecoveryEventAction::Consume
                )
            })
            .count(),
        0,
        "over-limit retry must not consume recovery"
    );
}

#[tokio::test]
async fn owner_webauthn_recovery_consume_finish_missing_limiter_fails_closed() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, mut authenticator) =
        owner_auth_with_webauthn_credential(&identity);
    let webauthn_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    anchor_owner_webauthn_authority(webauthn_anchor_store.as_ref(), &identity, &owner_auth);
    let recovery_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    let recovery_consume_limiter = Arc::new(
        server_rs::ratelimit::Limiter::new(
            td.path()
                .join("recovery-consume-rate-limit.db")
                .to_str()
                .unwrap(),
            100,
        )
        .unwrap(),
    );
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_recovery_code(RecoveryCodeEnforcement::BreakGlassEnabled);
    let (_td, router, _log, _broadcaster, person, _identity, _window, mut state_without_limiter) =
        router_from_owner_auth_with_router_state(
            td,
            Arc::clone(&identity),
            owner_auth,
            person,
            Duration::from_secs(45),
            {
                let webauthn_anchor_store = Arc::clone(&webauthn_anchor_store);
                let recovery_anchor_store = Arc::clone(&recovery_anchor_store);
                move |state| {
                    state
                        .with_owner_approval_policy(policy)
                        .with_owner_webauthn_rp(rp)
                        .with_owner_webauthn_anchor(webauthn_anchor_store)
                        .with_owner_webauthn_recovery_anchor(recovery_anchor_store)
                        .with_recovery_consume_rate_limiter(recovery_consume_limiter)
                }
            },
        );
    let recovery_code = provision_recovery_code(router.clone(), &person, &mut authenticator).await;
    let start = start_recovery_consume(router.clone(), &person, &recovery_code).await;
    state_without_limiter.recovery_consume_rate_limiter = None;
    let router_without_limiter = Router::new()
        .route(
            "/api/v1/household/owner-webauthn/recovery/consume/finish",
            post(handlers_owner_events::owner_webauthn_recovery_consume_finish_handler),
        )
        .with_state(state_without_limiter);
    let mut fresh_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = fresh_authenticator
        .do_registration(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();

    let (status, _headers, resp_bytes) = post_recovery_consume_finish(
        router_without_limiter,
        &person,
        recovery_consume_finish_body(
            start.context,
            start.challenge_id,
            credential,
            &recovery_code,
        ),
    )
    .await;
    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_recovery_consume_finish_retries_repair_after_recovery_anchor_failure() {
    let td = tempfile::tempdir().unwrap();
    let failing_anchor = Arc::new(FailingSetKeystore::new(td.path()));
    let recovery_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> = failing_anchor.clone();
    let (
        td,
        router,
        _log,
        _broadcaster,
        person,
        identity,
        _window,
        webauthn_anchor,
        _recovery_anchor,
        mut authenticator,
    ) = router_with_owner_webauthn_recovery_anchor(
        Duration::from_secs(45),
        true,
        td,
        recovery_anchor_store,
    );
    let recovery_code = provision_recovery_code(router.clone(), &person, &mut authenticator).await;
    let start = start_recovery_consume(router.clone(), &person, &recovery_code).await;
    let mut fresh_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = fresh_authenticator
        .do_registration(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    let finish_body = recovery_consume_finish_body(
        start.context,
        start.challenge_id,
        credential,
        &recovery_code,
    );

    failing_anchor.fail_writes(true);
    let (status, _headers, resp_bytes) =
        post_recovery_consume_finish(router.clone(), &person, finish_body.clone()).await;
    assert_generic_unauth(status, &resp_bytes);
    let after_failed_finish = load_owner_auth(&td, &identity);
    assert_eq!(
        after_failed_finish
            .owner_webauthn
            .entries()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.event.actor,
                    OwnerWebauthnEventActor::RecoveryProof { .. }
                ) && matches!(
                    entry.event.action,
                    OwnerWebauthnCredentialEventAction::Add { .. }
                )
            })
            .count(),
        1,
        "failed recovery-anchor advance still saved exactly one WebAuthn Add"
    );
    assert_eq!(
        after_failed_finish
            .owner_webauthn_recovery
            .entries()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.event.action,
                    OwnerWebauthnRecoveryEventAction::Consume
                )
            })
            .count(),
        1,
        "failed recovery-anchor advance still saved exactly one recovery Consume"
    );
    let webauthn_head = verified_owner_webauthn_authority_head(
        &after_failed_finish.owner_webauthn,
        &identity.record,
        &after_failed_finish.owner_person_cert,
    )
    .unwrap()
    .expect("webauthn authority has committed Add");
    let webauthn_anchor =
        read_owner_webauthn_authority_anchor(webauthn_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("WebAuthn anchor advanced before recovery anchor");
    assert_eq!(webauthn_anchor.sequence(), webauthn_head.sequence);
    assert_eq!(webauthn_anchor.head_hash(), webauthn_head.head_hash);

    failing_anchor.fail_writes(false);
    let repaired = recovery_consume_finish(router.clone(), &person, finish_body).await;
    assert_eq!(repaired.active_credential_count, 2);
    assert!(!repaired.recovery_ready);
    let after_repair = load_owner_auth(&td, &identity);
    assert_eq!(
        after_repair
            .owner_webauthn
            .entries()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.event.actor,
                    OwnerWebauthnEventActor::RecoveryProof { .. }
                ) && matches!(
                    entry.event.action,
                    OwnerWebauthnCredentialEventAction::Add { .. }
                )
            })
            .count(),
        1,
        "repair must not sign a duplicate WebAuthn Add"
    );
    assert_eq!(
        after_repair
            .owner_webauthn_recovery
            .entries()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.event.action,
                    OwnerWebauthnRecoveryEventAction::Consume
                )
            })
            .count(),
        1,
        "repair must not sign a duplicate recovery Consume"
    );
    let recovery_head = verified_owner_webauthn_recovery_head(
        &after_repair.owner_webauthn_recovery,
        &identity.record,
        &after_repair.owner_person_cert,
    )
    .unwrap()
    .expect("recovery authority has committed Consume");
    let recovery_anchor =
        read_owner_webauthn_recovery_anchor(failing_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("retry repairs recovery anchor");
    assert_eq!(recovery_anchor.sequence(), recovery_head.sequence);
    assert_eq!(recovery_anchor.head_hash(), recovery_head.head_hash);
}

#[tokio::test]
async fn owner_webauthn_recovery_consume_finish_retries_repair_after_webauthn_anchor_failure() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, mut authenticator) =
        owner_auth_with_webauthn_credential(&identity);
    let failing_webauthn_anchor = Arc::new(FailingSetKeystore::new(td.path()));
    let webauthn_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        failing_webauthn_anchor.clone();
    anchor_owner_webauthn_authority(webauthn_anchor_store.as_ref(), &identity, &owner_auth);
    let recovery_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    let recovery_consume_limiter = Arc::new(
        server_rs::ratelimit::Limiter::new(
            td.path()
                .join("recovery-consume-rate-limit.db")
                .to_str()
                .unwrap(),
            100,
        )
        .unwrap(),
    );
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_recovery_code(RecoveryCodeEnforcement::BreakGlassEnabled);
    let (td, router, _log, _broadcaster, person, identity, _window, _state) =
        router_from_owner_auth_with_router_state(
            td,
            Arc::clone(&identity),
            owner_auth,
            person,
            Duration::from_secs(45),
            {
                let webauthn_anchor_store = Arc::clone(&webauthn_anchor_store);
                let recovery_anchor_store = Arc::clone(&recovery_anchor_store);
                move |state| {
                    state
                        .with_owner_approval_policy(policy)
                        .with_owner_webauthn_rp(rp)
                        .with_owner_webauthn_anchor(webauthn_anchor_store)
                        .with_owner_webauthn_recovery_anchor(recovery_anchor_store)
                        .with_recovery_consume_rate_limiter(recovery_consume_limiter)
                }
            },
        );
    let recovery_code = provision_recovery_code(router.clone(), &person, &mut authenticator).await;
    let start = start_recovery_consume(router.clone(), &person, &recovery_code).await;
    let mut fresh_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = fresh_authenticator
        .do_registration(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    let finish_body = recovery_consume_finish_body(
        start.context,
        start.challenge_id,
        credential,
        &recovery_code,
    );

    failing_webauthn_anchor.fail_writes(true);
    let (status, _headers, resp_bytes) =
        post_recovery_consume_finish(router.clone(), &person, finish_body.clone()).await;
    assert_generic_unauth(status, &resp_bytes);
    let after_failed_finish = load_owner_auth(&td, &identity);
    assert_eq!(
        after_failed_finish
            .owner_webauthn
            .entries()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.event.actor,
                    OwnerWebauthnEventActor::RecoveryProof { .. }
                ) && matches!(
                    entry.event.action,
                    OwnerWebauthnCredentialEventAction::Add { .. }
                )
            })
            .count(),
        1,
        "failed WebAuthn-anchor advance still saved exactly one WebAuthn Add"
    );
    assert_eq!(
        after_failed_finish
            .owner_webauthn_recovery
            .entries()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.event.action,
                    OwnerWebauthnRecoveryEventAction::Consume
                )
            })
            .count(),
        1,
        "failed WebAuthn-anchor advance still saved exactly one recovery Consume"
    );
    let recovery_anchor =
        read_owner_webauthn_recovery_anchor(recovery_anchor_store.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("recovery provision anchor remains present");
    assert_eq!(
        recovery_anchor.sequence(),
        0,
        "recovery anchor must not advance when WebAuthn anchor failed first"
    );

    failing_webauthn_anchor.fail_writes(false);
    let repaired = recovery_consume_finish(router.clone(), &person, finish_body).await;
    assert_eq!(repaired.active_credential_count, 2);
    assert!(!repaired.recovery_ready);
    let after_repair = load_owner_auth(&td, &identity);
    assert_eq!(
        after_repair
            .owner_webauthn
            .entries()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.event.actor,
                    OwnerWebauthnEventActor::RecoveryProof { .. }
                ) && matches!(
                    entry.event.action,
                    OwnerWebauthnCredentialEventAction::Add { .. }
                )
            })
            .count(),
        1,
        "repair must not sign a duplicate WebAuthn Add"
    );
    assert_eq!(
        after_repair
            .owner_webauthn_recovery
            .entries()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.event.action,
                    OwnerWebauthnRecoveryEventAction::Consume
                )
            })
            .count(),
        1,
        "repair must not sign a duplicate recovery Consume"
    );
    let webauthn_head = verified_owner_webauthn_authority_head(
        &after_repair.owner_webauthn,
        &identity.record,
        &after_repair.owner_person_cert,
    )
    .unwrap()
    .expect("webauthn authority has committed Add");
    let webauthn_anchor = read_owner_webauthn_authority_anchor(
        webauthn_anchor_store.as_ref(),
        &identity.record.hh_id,
    )
    .unwrap()
    .expect("retry repairs WebAuthn anchor");
    assert_eq!(webauthn_anchor.sequence(), webauthn_head.sequence);
    assert_eq!(webauthn_anchor.head_hash(), webauthn_head.head_hash);
    let recovery_head = verified_owner_webauthn_recovery_head(
        &after_repair.owner_webauthn_recovery,
        &identity.record,
        &after_repair.owner_person_cert,
    )
    .unwrap()
    .expect("recovery authority has committed Consume");
    let recovery_anchor =
        read_owner_webauthn_recovery_anchor(recovery_anchor_store.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("retry repairs recovery anchor");
    assert_eq!(recovery_anchor.sequence(), recovery_head.sequence);
    assert_eq!(recovery_anchor.head_hash(), recovery_head.head_hash);
}

#[tokio::test]
async fn owner_webauthn_recovery_anchor_failure_replaces_initial_provision_on_retry() {
    let td = tempfile::tempdir().unwrap();
    let failing_anchor = Arc::new(FailingSetKeystore::new(td.path()));
    let recovery_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> = failing_anchor.clone();
    let (
        td,
        router,
        _log,
        _broadcaster,
        person,
        identity,
        _window,
        _webauthn_anchor,
        _recovery_anchor,
        mut authenticator,
    ) = router_with_owner_webauthn_recovery_anchor(
        Duration::from_secs(45),
        true,
        td,
        recovery_anchor_store,
    );

    let start = start_recovery(router.clone(), &person).await;
    assert_eq!(start.context.recovery_head_sequence, None);
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    let failed_body = recovery_finish_body(start.context, start.challenge_id, &assertion);

    failing_anchor.fail_writes(true);
    let (status, _headers, resp_bytes) =
        post_recovery_finish(router.clone(), &person, failed_body.clone()).await;
    assert_generic_unauth(status, &resp_bytes);
    let failed = load_owner_auth(&td, &identity);
    assert_eq!(failed.owner_webauthn_recovery.entries().len(), 1);
    assert_recovery_event_is_provision(&failed, 0);
    let lost_provision_verifier = recovery_event_verifier_bytes(&failed, 0);
    assert!(
        read_owner_webauthn_recovery_anchor(failing_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .is_none(),
        "failed anchor write must leave no authoritative recovery anchor"
    );
    let status = recovery_status(router.clone(), &person).await;
    assert!(
        !status.ready,
        "unanchored shown-once verifier is not recovery-ready"
    );
    let (status, _headers, resp_bytes) =
        post_recovery_finish(router.clone(), &person, failed_body).await;
    assert_generic_unauth(status, &resp_bytes);
    let after_replay = load_owner_auth(&td, &identity);
    assert_eq!(
        after_replay.owner_webauthn_recovery.entries().len(),
        1,
        "replaying a consumed failed finish must not append another provision"
    );

    let retry_start = start_recovery(router.clone(), &person).await;
    assert_eq!(
        retry_start.context.recovery_head_sequence, None,
        "retry replaces the unanchored genesis event instead of building on it"
    );
    let retry_assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            retry_start.options,
        )
        .unwrap();
    let retry_body = recovery_finish_body(
        retry_start.context,
        retry_start.challenge_id,
        &retry_assertion,
    );

    failing_anchor.fail_writes(false);
    let finish = recovery_finish(router.clone(), &person, retry_body).await;

    assert!(finish.recovery_ready);
    assert!(!finish.recovery_code.is_empty());
    let loaded = load_owner_auth(&td, &identity);
    assert_eq!(loaded.owner_webauthn_recovery.entries().len(), 1);
    assert_recovery_event_is_provision(&loaded, 0);
    assert_ne!(
        recovery_event_verifier_bytes(&loaded, 0),
        lost_provision_verifier,
        "lost provision verifier must be replaced before readiness"
    );
    let head = verified_owner_webauthn_recovery_head(
        &loaded.owner_webauthn_recovery,
        &identity.record,
        &loaded.owner_person_cert,
    )
    .unwrap()
    .expect("retry provision has head");
    let anchor =
        read_owner_webauthn_recovery_anchor(failing_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("retry anchors delivered recovery code");
    assert_eq!(anchor.sequence(), head.sequence);
    assert_eq!(anchor.head_hash(), head.head_hash);
    let status = recovery_status(router, &person).await;
    assert!(status.ready);
}

#[tokio::test]
async fn owner_webauthn_recovery_anchor_failure_replaces_rotate_on_retry() {
    let td = tempfile::tempdir().unwrap();
    let failing_anchor = Arc::new(FailingSetKeystore::new(td.path()));
    let recovery_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> = failing_anchor.clone();
    let (
        td,
        router,
        _log,
        _broadcaster,
        person,
        identity,
        _window,
        _webauthn_anchor,
        _recovery_anchor,
        mut authenticator,
    ) = router_with_owner_webauthn_recovery_anchor(
        Duration::from_secs(45),
        true,
        td,
        recovery_anchor_store,
    );

    let first_start = start_recovery(router.clone(), &person).await;
    let first_assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            first_start.options,
        )
        .unwrap();
    let first_body = recovery_finish_body(
        first_start.context,
        first_start.challenge_id,
        &first_assertion,
    );
    let first_finish = recovery_finish(router.clone(), &person, first_body).await;
    assert!(first_finish.recovery_ready);
    let first_loaded = load_owner_auth(&td, &identity);
    assert_eq!(first_loaded.owner_webauthn_recovery.entries().len(), 1);
    let first_anchor =
        read_owner_webauthn_recovery_anchor(failing_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("first provision anchors");
    assert_eq!(first_anchor.sequence(), 0);

    let rotate_start = start_recovery(router.clone(), &person).await;
    assert_eq!(rotate_start.context.recovery_head_sequence, Some(0));
    let rotate_assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            rotate_start.options,
        )
        .unwrap();
    let failed_rotate_body = recovery_finish_body(
        rotate_start.context,
        rotate_start.challenge_id,
        &rotate_assertion,
    );

    failing_anchor.fail_writes(true);
    let (status, _headers, resp_bytes) =
        post_recovery_finish(router.clone(), &person, failed_rotate_body.clone()).await;
    assert_generic_unauth(status, &resp_bytes);
    let failed = load_owner_auth(&td, &identity);
    assert_eq!(failed.owner_webauthn_recovery.entries().len(), 2);
    assert_recovery_event_is_provision(&failed, 0);
    assert_recovery_event_is_rotate(&failed, 1);
    let lost_rotate_verifier = recovery_event_verifier_bytes(&failed, 1);
    let anchor_after_failure =
        read_owner_webauthn_recovery_anchor(failing_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("failed rotate leaves previous anchor intact");
    assert_eq!(anchor_after_failure.sequence(), 0);
    let status = recovery_status(router.clone(), &person).await;
    assert!(
        !status.ready,
        "lagging rotate verifier is not recovery-ready until replaced and anchored"
    );
    let (status, _headers, resp_bytes) =
        post_recovery_finish(router.clone(), &person, failed_rotate_body).await;
    assert_generic_unauth(status, &resp_bytes);
    let after_replay = load_owner_auth(&td, &identity);
    assert_eq!(
        after_replay.owner_webauthn_recovery.entries().len(),
        2,
        "replaying a consumed failed rotate must not append a third event"
    );

    let retry_start = start_recovery(router.clone(), &person).await;
    assert_eq!(
        retry_start.context.recovery_head_sequence,
        Some(0),
        "retry builds from the last anchored recovery head"
    );
    let retry_assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            retry_start.options,
        )
        .unwrap();
    let retry_body = recovery_finish_body(
        retry_start.context,
        retry_start.challenge_id,
        &retry_assertion,
    );

    failing_anchor.fail_writes(false);
    let retry_finish = recovery_finish(router.clone(), &person, retry_body).await;

    assert!(retry_finish.recovery_ready);
    assert_ne!(
        retry_finish.recovery_code, first_finish.recovery_code,
        "rotate retry must deliver a fresh recovery code"
    );
    let loaded = load_owner_auth(&td, &identity);
    assert_eq!(
        loaded.owner_webauthn_recovery.entries().len(),
        2,
        "retry replaces the unanchored rotate instead of stacking duplicate events"
    );
    assert_recovery_event_is_provision(&loaded, 0);
    assert_recovery_event_is_rotate(&loaded, 1);
    assert_ne!(
        recovery_event_verifier_bytes(&loaded, 1),
        lost_rotate_verifier,
        "lost rotate verifier must not become authoritative"
    );
    let head = verified_owner_webauthn_recovery_head(
        &loaded.owner_webauthn_recovery,
        &identity.record,
        &loaded.owner_person_cert,
    )
    .unwrap()
    .expect("retry rotate has head");
    let anchor =
        read_owner_webauthn_recovery_anchor(failing_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("retry rotate advances anchor");
    assert_eq!(anchor.sequence(), head.sequence);
    assert_eq!(anchor.head_hash(), head.head_hash);
    assert_eq!(anchor.sequence(), 1);
    let status = recovery_status(router, &person).await;
    assert!(status.ready);
}

#[tokio::test]
async fn owner_webauthn_recovery_finish_context_mismatch_does_not_consume_challenge() {
    let (
        td,
        router,
        _log,
        _broadcaster,
        person,
        identity,
        _window,
        _webauthn_anchor,
        _recovery_anchor,
        mut authenticator,
    ) = router_with_owner_webauthn_recovery(Duration::from_secs(45), true);

    let start = start_recovery(router.clone(), &person).await;
    let original_context = start.context;
    let challenge_id = start.challenge_id;
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    let mut tampered_context = original_context.clone();
    tampered_context.pre_active_credential_count = Some(2);
    let tampered_body = recovery_finish_body(tampered_context, challenge_id.clone(), &assertion);
    let (status, _headers, resp_bytes) =
        post_recovery_finish(router.clone(), &person, tampered_body).await;
    assert_generic_unauth(status, &resp_bytes);

    let body = recovery_finish_body(original_context, challenge_id, &assertion);
    let finish = recovery_finish(router, &person, body).await;

    assert!(finish.recovery_ready);
    let loaded = load_owner_auth(&td, &identity);
    assert_eq!(loaded.owner_webauthn_recovery.entries().len(), 1);
}

#[tokio::test]
async fn owner_webauthn_recovery_rejects_unsafe_trust_states_and_bad_pop() {
    {
        let td = tempfile::tempdir().unwrap();
        let identity = Arc::new(bootstrap(td.path()));
        let (owner_auth, person, rp, _authenticator) =
            owner_auth_with_webauthn_credential(&identity);
        let webauthn_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
            Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
        let recovery_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
            Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
        let policy = OwnerApprovalEnforcementPolicy::default()
            .with_recovery_code(RecoveryCodeEnforcement::BreakGlassEnabled);
        let (_td, router, _log, _broadcaster, person, identity, _window) = router_from_owner_auth(
            td,
            identity,
            owner_auth.clone(),
            person,
            Duration::from_secs(45),
            {
                let webauthn_anchor_store = Arc::clone(&webauthn_anchor_store);
                let recovery_anchor_store = Arc::clone(&recovery_anchor_store);
                move |state| {
                    state
                        .with_owner_approval_policy(policy)
                        .with_owner_webauthn_rp(rp)
                        .with_owner_webauthn_anchor(webauthn_anchor_store)
                        .with_owner_webauthn_recovery_anchor(recovery_anchor_store)
                }
            },
        );
        let (status, _headers, resp_bytes) = post_recovery_start(router, &person).await;
        assert_generic_unauth(status, &resp_bytes);
        assert!(
            read_owner_webauthn_authority_anchor(
                webauthn_anchor_store.as_ref(),
                &identity.record.hh_id,
            )
            .unwrap()
            .is_none(),
            "recovery start must not migrate a missing WebAuthn authority anchor"
        );
        assert!(
            verify_or_update_owner_webauthn_authority_anchor(
                webauthn_anchor_store.as_ref(),
                &owner_auth.owner_webauthn,
                &identity.record,
                &owner_auth.owner_person_cert,
                OwnerWebauthnAnchorMode::Enforcement,
            )
            .is_err()
        );
    }

    {
        let td = tempfile::tempdir().unwrap();
        let identity = Arc::new(bootstrap(td.path()));
        let (owner_auth, person, rp) = owner_auth_with_revoked_webauthn_credential(&identity);
        let webauthn_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
            Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
        anchor_owner_webauthn_authority(webauthn_anchor_store.as_ref(), &identity, &owner_auth);
        let recovery_anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
            Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
        let policy = OwnerApprovalEnforcementPolicy::default()
            .with_recovery_code(RecoveryCodeEnforcement::BreakGlassEnabled);
        let (_td, router, _log, _broadcaster, person, _identity, _window) =
            router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
                let webauthn_anchor_store = Arc::clone(&webauthn_anchor_store);
                let recovery_anchor_store = Arc::clone(&recovery_anchor_store);
                move |state| {
                    state
                        .with_owner_approval_policy(policy)
                        .with_owner_webauthn_rp(rp)
                        .with_owner_webauthn_anchor(webauthn_anchor_store)
                        .with_owner_webauthn_recovery_anchor(recovery_anchor_store)
                }
            });
        let (status, _headers, resp_bytes) = post_recovery_start(router, &person).await;
        assert_generic_unauth(status, &resp_bytes);
    }

    {
        let (
            _td,
            router,
            _log,
            _broadcaster,
            person,
            _identity,
            _window,
            _webauthn_anchor,
            _recovery_anchor,
            _authenticator,
        ) = router_with_owner_webauthn_recovery(Duration::from_secs(45), true);
        let uri = "/api/v1/household/owner-webauthn/recovery/status";
        let body = recovery_status_body();
        let bad_auth = pop_header_for(
            &person,
            "POST",
            "/api/v1/household/owner-webauthn/recovery/start",
            unix_now(),
            &body,
        );
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::AUTHORIZATION, bad_auth)
                    .header(header::CONTENT_TYPE, "application/cbor")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        assert_generic_unauth(status, &resp_bytes);
    }
}

#[tokio::test]
async fn owner_webauthn_registration_status_reports_never_enrolled() {
    let (_td, router, _log, _broadcaster, person, _identity, _window, _anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));

    let status = registration_status(router, &person).await;

    assert!(!status.enrolled);
}

#[tokio::test]
async fn owner_webauthn_registration_status_reports_read_only_advanced_without_anchor_write() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, _authenticator) =
        owner_auth_with_two_webauthn_credentials(&identity);
    let first_entry = owner_auth
        .owner_webauthn
        .entries()
        .first()
        .expect("genesis event exists");
    let first_hash = first_entry.entry_hash().unwrap();
    let first_anchor = OwnerWebauthnAuthorityAnchor::new(
        &identity.record,
        &owner_auth.owner_person_cert,
        0,
        first_hash,
    );
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    write_owner_webauthn_authority_anchor(anchor_store.as_ref(), &first_anchor).unwrap();
    let (_td, router, _log, _broadcaster, person, identity, _window) =
        router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
            let anchor_store = Arc::clone(&anchor_store);
            move |state| {
                state
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_store)
            }
        });

    let status = registration_status(router, &person).await;

    assert!(status.enrolled);
    let anchor =
        read_owner_webauthn_authority_anchor(anchor_store.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("anchor remains present");
    assert_eq!(
        anchor.sequence(),
        0,
        "status must classify anchor lag without advancing the durable anchor"
    );
    assert_eq!(anchor.head_hash(), first_hash);
}

#[tokio::test]
async fn owner_webauthn_registration_round_trip_persists_genesis_and_anchor() {
    let (td, router, _log, _broadcaster, person, identity, _window, anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));

    let finish = enroll_first_owner_passkey(router.clone(), &person).await;

    assert_eq!(finish.version, 1);
    assert_eq!(finish.active_credential_count, 1);
    assert!(!finish.credential_id.is_empty());
    let loaded = HouseholdAuthState::load_optional(td.path(), &identity.record, unix_now())
        .unwrap()
        .expect("owner auth state persisted");
    assert_eq!(loaded.owner_webauthn.entries().len(), 1);
    assert!(
        !permits(
            &loaded.owner_person_cert.caveats,
            &Operation::OwnerAuthEnrollInitial
        ),
        "initial enrollment accepts legacy owner certs without the new operation caveat"
    );
    assert!(
        loaded
            .owner_has_active_webauthn_credential(&identity.record)
            .unwrap()
    );
    verify_or_update_owner_webauthn_authority_anchor(
        anchor_store.as_ref(),
        &loaded.owner_webauthn,
        &identity.record,
        &loaded.owner_person_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    )
    .expect("anchor accepts persisted genesis");
    let status = registration_status(router, &person).await;
    assert!(status.enrolled);
    assert!(
        !registration_status_marker_path(td.path()).exists(),
        "successful anchor update clears the transient status marker"
    );
}

#[tokio::test]
async fn owner_webauthn_registration_status_verified_authority_ignores_stale_marker() {
    let (td, router, _log, _broadcaster, person, identity, _window, anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));
    let finish = enroll_first_owner_passkey(router.clone(), &person).await;
    let stale_marker = TestInitialEnrollmentAnchorMarker {
        version: 1,
        purpose: "wrong-purpose".into(),
        hh_id: identity.record.hh_id.clone(),
        owner_p_id: household_rs::derive_person_id(&P256Keypair::generate().public()),
        credential_id: ByteBuf::from(vec![0xde, 0xad, 0xbe, 0xef]),
        authority_head_sequence: 0,
        authority_head_hash: ByteBuf::from(vec![0x55; 32]),
        active_credential_count: 1,
    };
    write_test_initial_enrollment_marker(td.path(), &stale_marker);
    let before =
        read_owner_webauthn_authority_anchor(anchor_store.as_ref(), &identity.record.hh_id)
            .unwrap()
            .expect("successful enrollment wrote anchor");

    let status = registration_status(router, &person).await;

    assert!(status.enrolled);
    let after = read_owner_webauthn_authority_anchor(anchor_store.as_ref(), &identity.record.hh_id)
        .unwrap()
        .expect("status leaves anchor present");
    assert_eq!(after.sequence(), before.sequence());
    assert_eq!(after.head_hash(), before.head_hash());
    assert!(
        registration_status_marker_path(td.path()).exists(),
        "status read path does not clean stale markers"
    );
    assert!(!finish.credential_id.is_empty());
}

#[tokio::test]
async fn owner_webauthn_registration_rejects_second_start_after_success() {
    let (_td, router, _log, _broadcaster, person, _identity, _window, _anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));

    let finish = enroll_first_owner_passkey(router.clone(), &person).await;
    assert_eq!(finish.active_credential_count, 1);

    let start_uri = "/api/v1/household/owner-webauthn/registration/start";
    let start_body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();
    let (status, _headers, resp_bytes) =
        post_cbor(router, start_uri, start_body, Some(&person)).await;

    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_rejects_replayed_finish_after_success() {
    let (_td, router, _log, _broadcaster, person, _identity, _window, _anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));
    let finish_uri = "/api/v1/household/owner-webauthn/registration/finish";
    let finish_body = owner_webauthn_registration_finish_body(router.clone(), &person).await;

    let (status, _headers, _resp_bytes) = post_cbor(
        router.clone(),
        finish_uri,
        finish_body.clone(),
        Some(&person),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _headers, resp_bytes) =
        post_cbor(router.clone(), finish_uri, finish_body, Some(&person)).await;
    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_rejects_noncanonical_start_body() {
    let (_td, router, _log, _broadcaster, person, _identity, _window, _anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));
    let uri = "/api/v1/household/owner-webauthn/registration/start";
    let body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();
    let body = make_version_value_noncanonical(body);

    let (status, _headers, resp_bytes) = post_cbor(router, uri, body, Some(&person)).await;

    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_rejects_noncanonical_finish_body() {
    let (_td, router, _log, _broadcaster, person, _identity, _window, _anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));
    let uri = "/api/v1/household/owner-webauthn/registration/finish";
    let body = owner_webauthn_registration_finish_body(router.clone(), &person).await;
    let body = make_version_value_noncanonical(body);

    let (status, _headers, resp_bytes) = post_cbor(router, uri, body, Some(&person)).await;

    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_finish_fails_closed_without_rp_or_anchor() {
    let (_td, router, _log, _broadcaster, person, _identity, _window) =
        router_with_state(Duration::from_secs(45));
    let uri = "/api/v1/household/owner-webauthn/registration/finish";
    let body = household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationFinishRequest {
        version: 1,
        challenge_id: "00000000000000000000000000000000".into(),
        credential: standalone_registration_credential(),
    })
    .unwrap();

    let (status, _headers, resp_bytes) = post_cbor(router, uri, body, Some(&person)).await;

    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_finish_fails_closed_without_household_root() {
    let (_td, router, _log, _broadcaster, person, _identity, _window) =
        router_with_owner_webauthn_registration_without_hh_priv(Duration::from_secs(45));
    let finish_uri = "/api/v1/household/owner-webauthn/registration/finish";
    let finish_body = owner_webauthn_registration_finish_body(router.clone(), &person).await;

    let (status, _headers, resp_bytes) =
        post_cbor(router.clone(), finish_uri, finish_body, Some(&person)).await;

    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_rejects_stale_pop_timestamp() {
    let (_td, router, _log, _broadcaster, person, _identity, _window, _anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));
    let uri = "/api/v1/household/owner-webauthn/registration/start";
    let body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();
    let stale_timestamp = unix_now().saturating_sub(120);
    let auth = pop_header_for(&person, "POST", uri, stale_timestamp, &body);

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_rejects_body_hash_mismatch() {
    let (_td, router, _log, _broadcaster, person, _identity, _window, _anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));
    let uri = "/api/v1/household/owner-webauthn/registration/start";
    let body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();
    let auth = pop_header_for(&person, "POST", uri, unix_now(), b"not-the-request-body");

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_rejects_path_mismatch() {
    let (_td, router, _log, _broadcaster, person, _identity, _window, _anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));
    let start_uri = "/api/v1/household/owner-webauthn/registration/start";
    let finish_uri = "/api/v1/household/owner-webauthn/registration/finish";
    let body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();
    let auth = pop_header_for(&person, "POST", finish_uri, unix_now(), &body);

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(start_uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_status_rejects_bad_pop() {
    let (_td, router, _log, _broadcaster, person, _identity, _window, _anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));
    let uri = "/api/v1/household/owner-webauthn/registration/status";
    let body = registration_status_body();

    let stale_timestamp = unix_now().saturating_sub(120);
    let stale_auth = pop_header_for(&person, "POST", uri, stale_timestamp, &body);
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, stale_auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    assert_generic_unauth(status, &resp_bytes);

    let path_mismatch_auth = pop_header_for(
        &person,
        "POST",
        "/api/v1/household/owner-webauthn/registration/start",
        unix_now(),
        &body,
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, path_mismatch_auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    assert_generic_unauth(status, &resp_bytes);

    let body_mismatch_auth = pop_header_for(&person, "POST", uri, unix_now(), b"wrong-body");
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, body_mismatch_auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_rejects_non_empty_authority_without_anchor() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, _authenticator) = owner_auth_with_webauthn_credential(&identity);
    let owner_auth_for_assert = owner_auth.clone();
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    let (_td, router, _log, _broadcaster, person, identity, _window) =
        router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
            let anchor_store = Arc::clone(&anchor_store);
            move |state| {
                state
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_store)
            }
        });

    let start_uri = "/api/v1/household/owner-webauthn/registration/start";
    let start_body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();
    let (status, _headers, resp_bytes) =
        post_cbor(router.clone(), start_uri, start_body, Some(&person)).await;
    assert_generic_unauth(status, &resp_bytes);

    let finish_uri = "/api/v1/household/owner-webauthn/registration/finish";
    let finish_body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationFinishRequest {
            version: 1,
            challenge_id: "00000000000000000000000000000000".into(),
            credential: standalone_registration_credential(),
        })
        .unwrap();
    let (status, _headers, resp_bytes) =
        post_cbor(router, finish_uri, finish_body, Some(&person)).await;
    assert_generic_unauth(status, &resp_bytes);

    let (_td, router, _log, _broadcaster, person, identity, _window) = router_from_owner_auth(
        tempfile::tempdir().unwrap(),
        Arc::clone(&identity),
        owner_auth_for_assert.clone(),
        person,
        Duration::from_secs(45),
        {
            let anchor_store = Arc::clone(&anchor_store);
            move |state| state.with_owner_webauthn_anchor(anchor_store)
        },
    );
    let (status, _headers, resp_bytes) = post_registration_status(router, &person).await;
    assert_generic_unauth(status, &resp_bytes);
    assert!(
        read_owner_webauthn_authority_anchor(anchor_store.as_ref(), &identity.record.hh_id)
            .unwrap()
            .is_none(),
        "registration request path must not migrate a missing anchor for an existing authority log"
    );
    assert!(
        verify_or_update_owner_webauthn_authority_anchor(
            anchor_store.as_ref(),
            &owner_auth_for_assert.owner_webauthn,
            &identity.record,
            &owner_auth_for_assert.owner_person_cert,
            OwnerWebauthnAnchorMode::Enforcement,
        )
        .is_err()
    );
}

#[tokio::test]
async fn owner_webauthn_registration_status_rejects_marker_mismatches() {
    #[derive(Clone, Copy)]
    enum MarkerMismatch {
        Purpose,
        Household,
        Owner,
        Credential,
        HeadSequence,
        HeadHash,
        ActiveCount,
    }

    for mismatch in [
        MarkerMismatch::Purpose,
        MarkerMismatch::Household,
        MarkerMismatch::Owner,
        MarkerMismatch::Credential,
        MarkerMismatch::HeadSequence,
        MarkerMismatch::HeadHash,
        MarkerMismatch::ActiveCount,
    ] {
        let td = tempfile::tempdir().unwrap();
        let identity = Arc::new(bootstrap(td.path()));
        let (owner_auth, person, rp, _authenticator) =
            owner_auth_with_webauthn_credential(&identity);
        let head = verified_owner_webauthn_authority_head(
            &owner_auth.owner_webauthn,
            &identity.record,
            &owner_auth.owner_person_cert,
        )
        .unwrap()
        .expect("non-empty authority has a head");
        let credential_id = owner_auth
            .owner_webauthn_credentials(&identity.record)
            .unwrap()
            .active_credentials()
            .first()
            .expect("first enrollment has an active credential")
            .credential_id_bytes()
            .to_vec();
        let mut marker = TestInitialEnrollmentAnchorMarker {
            version: 1,
            purpose: "owner-webauthn-initial-enrollment-anchor-pending".into(),
            hh_id: identity.record.hh_id.clone(),
            owner_p_id: owner_auth.owner_person_cert.p_id.clone(),
            credential_id: ByteBuf::from(credential_id),
            authority_head_sequence: head.sequence,
            authority_head_hash: ByteBuf::from(head.head_hash.to_vec()),
            active_credential_count: 1,
        };
        match mismatch {
            MarkerMismatch::Purpose => {
                marker.purpose = "wrong-purpose".into();
            }
            MarkerMismatch::Household => {
                let other = bootstrap(tempfile::tempdir().unwrap().path());
                marker.hh_id = other.record.hh_id;
            }
            MarkerMismatch::Owner => {
                marker.owner_p_id =
                    household_rs::derive_person_id(&P256Keypair::generate().public());
            }
            MarkerMismatch::Credential => {
                marker.credential_id = ByteBuf::from(vec![0xde, 0xad, 0xbe, 0xef]);
            }
            MarkerMismatch::HeadSequence => {
                marker.authority_head_sequence = marker.authority_head_sequence.saturating_add(1);
            }
            MarkerMismatch::HeadHash => {
                marker.authority_head_hash = ByteBuf::from(vec![0x44; 32]);
            }
            MarkerMismatch::ActiveCount => {
                marker.active_credential_count = 2;
            }
        }
        write_test_initial_enrollment_marker(td.path(), &marker);
        let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
            Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
        let (_td, router, _log, _broadcaster, person, identity, _window) =
            router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
                let anchor_store = Arc::clone(&anchor_store);
                move |state| {
                    state
                        .with_owner_webauthn_rp(rp)
                        .with_owner_webauthn_anchor(anchor_store)
                }
            });

        let (status, _headers, resp_bytes) = post_registration_status(router, &person).await;

        assert_generic_unauth(status, &resp_bytes);
        assert!(
            read_owner_webauthn_authority_anchor(anchor_store.as_ref(), &identity.record.hh_id)
                .unwrap()
                .is_none(),
            "marker mismatch must not repair or write an anchor"
        );
    }
}

#[tokio::test]
async fn owner_webauthn_registration_rejects_all_revoked_authority() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp) = owner_auth_with_revoked_webauthn_credential(&identity);
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    verify_or_update_owner_webauthn_authority_anchor(
        anchor_store.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::MigrationDefaultOff,
    )
    .unwrap();
    let (_td, router, _log, _broadcaster, person, _identity, _window) = router_from_owner_auth(
        td,
        identity,
        owner_auth,
        person,
        Duration::from_secs(45),
        move |state| {
            state
                .with_owner_webauthn_rp(rp)
                .with_owner_webauthn_anchor(anchor_store)
        },
    );

    let start_uri = "/api/v1/household/owner-webauthn/registration/start";
    let start_body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();
    let (status, _headers, resp_bytes) =
        post_cbor(router.clone(), start_uri, start_body, Some(&person)).await;
    assert_generic_unauth(status, &resp_bytes);

    let finish_uri = "/api/v1/household/owner-webauthn/registration/finish";
    let finish_body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationFinishRequest {
            version: 1,
            challenge_id: "00000000000000000000000000000000".into(),
            credential: standalone_registration_credential(),
        })
        .unwrap();
    let (status, _headers, resp_bytes) =
        post_cbor(router.clone(), finish_uri, finish_body, Some(&person)).await;
    assert_generic_unauth(status, &resp_bytes);

    let status = registration_status(router, &person).await;
    assert!(
        status.enrolled,
        "status reports ever-enrolled when a valid anchored authority has only revoked credentials"
    );
}

#[tokio::test]
async fn owner_webauthn_registration_rejects_empty_authority_with_anchor() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person) = owner_auth_for(&identity);
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    let stale_anchor = OwnerWebauthnAuthorityAnchor::new(
        &identity.record,
        &owner_auth.owner_person_cert,
        0,
        [0x24; 32],
    );
    write_owner_webauthn_authority_anchor(anchor_store.as_ref(), &stale_anchor).unwrap();
    let rp = owner_webauthn_rp();
    let (_td, router, _log, _broadcaster, person, _identity, _window) = router_from_owner_auth(
        td,
        identity,
        owner_auth,
        person,
        Duration::from_secs(45),
        move |state| {
            state
                .with_owner_webauthn_rp(rp)
                .with_owner_webauthn_anchor(anchor_store)
        },
    );

    let uri = "/api/v1/household/owner-webauthn/registration/start";
    let body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();
    let (status, _headers, resp_bytes) = post_cbor(router.clone(), uri, body, Some(&person)).await;

    assert_generic_unauth(status, &resp_bytes);

    let (status, _headers, resp_bytes) = post_registration_status(router, &person).await;
    assert_generic_unauth(status, &resp_bytes);
}

#[tokio::test]
async fn owner_webauthn_registration_status_rejects_rollback_or_divergent_anchor() {
    for anchor in ["truncated", "divergent"] {
        let td = tempfile::tempdir().unwrap();
        let identity = Arc::new(bootstrap(td.path()));
        let (owner_auth, person, rp, _authenticator) =
            owner_auth_with_webauthn_credential(&identity);
        let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
            Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
        let stale_anchor = match anchor {
            "truncated" => OwnerWebauthnAuthorityAnchor::new(
                &identity.record,
                &owner_auth.owner_person_cert,
                1,
                [0x42; 32],
            ),
            "divergent" => OwnerWebauthnAuthorityAnchor::new(
                &identity.record,
                &owner_auth.owner_person_cert,
                0,
                [0x43; 32],
            ),
            _ => unreachable!(),
        };
        write_owner_webauthn_authority_anchor(anchor_store.as_ref(), &stale_anchor).unwrap();
        let (_td, router, _log, _broadcaster, person, identity, _window) =
            router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
                let anchor_store = Arc::clone(&anchor_store);
                move |state| {
                    state
                        .with_owner_webauthn_rp(rp)
                        .with_owner_webauthn_anchor(anchor_store)
                }
            });

        let (status, _headers, resp_bytes) = post_registration_status(router, &person).await;

        assert_generic_unauth(status, &resp_bytes);
        let persisted =
            read_owner_webauthn_authority_anchor(anchor_store.as_ref(), &identity.record.hh_id)
                .unwrap()
                .expect("status leaves invalid anchor untouched");
        assert_eq!(persisted.sequence(), stale_anchor.sequence());
        assert_eq!(persisted.head_hash(), stale_anchor.head_hash());
    }
}

#[tokio::test]
async fn owner_webauthn_registration_anchor_write_failure_keeps_memory_committed() {
    let td = tempfile::tempdir().unwrap();
    let failing_anchor = Arc::new(FailingSetKeystore::new(td.path()));
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> = failing_anchor.clone();
    let (td, router, _log, _broadcaster, person, identity, _window, _anchor_store) =
        router_with_owner_webauthn_registration_anchor(Duration::from_secs(45), td, anchor_store);
    let finish_uri = "/api/v1/household/owner-webauthn/registration/finish";
    let finish_body = owner_webauthn_registration_finish_body(router.clone(), &person).await;

    failing_anchor.fail_writes(true);
    let (status, _headers, resp_bytes) =
        post_cbor(router.clone(), finish_uri, finish_body, Some(&person)).await;
    assert_generic_unauth(status, &resp_bytes);

    let loaded = HouseholdAuthState::load_optional(td.path(), &identity.record, unix_now())
        .unwrap()
        .expect("owner auth state persisted before anchor failure");
    assert_eq!(loaded.owner_webauthn.entries().len(), 1);

    let start_uri = "/api/v1/household/owner-webauthn/registration/start";
    let start_body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartRequest { version: 1 })
            .unwrap();
    let (status, _headers, resp_bytes) =
        post_cbor(router.clone(), start_uri, start_body, Some(&person)).await;
    assert_generic_unauth(status, &resp_bytes);

    let status = registration_status(router.clone(), &person).await;
    assert!(status.enrolled);
    assert!(
        read_owner_webauthn_authority_anchor(failing_anchor.as_ref(), &identity.record.hh_id)
            .unwrap()
            .is_none(),
        "status marker fallback must not write or migrate the anchor"
    );

    failing_anchor.fail_writes(false);
    verify_or_update_owner_webauthn_authority_anchor(
        failing_anchor.as_ref(),
        &loaded.owner_webauthn,
        &identity.record,
        &loaded.owner_person_cert,
        OwnerWebauthnAnchorMode::MigrationDefaultOff,
    )
    .expect("reload migration advances anchor after a saved log extension");
}

#[tokio::test]
async fn owner_webauthn_registration_does_not_flip_pair_machine_policy() {
    let (td, router, log, _broadcaster, person, identity, window, _anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));
    let finish = enroll_first_owner_passkey(router.clone(), &person).await;
    assert_eq!(finish.active_credential_count, 1);

    fs::write(household_root_sole_path(td.path()), b"fake-sole-shard").unwrap();
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    candidate
        .window
        .pin_household_anchor(
            identity.record.hh_id.as_str().to_string(),
            *identity.record.hh_pub.as_bytes(),
        )
        .await
        .unwrap();
    let uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let timestamp = unix_now();
    let body = approval_body(
        &identity,
        &person,
        event.cursor,
        ByteBuf::from(
            candidate
                .prepared
                .join_request
                .challenge_sig
                .as_ref()
                .to_vec(),
        ),
        timestamp,
    );

    let auth = pop_header_for(&person, "POST", &uri, timestamp, &body);
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::OK);
    let ack: OwnerApprovalAck = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(ack.version, 1);
    assert_eq!(window.snapshot().await.state, PairMachineState::Committed);
}

#[tokio::test]
async fn decline_transitions_and_records_cancel_event() {
    let (_td, router, log, _broadcaster, person, identity, window) =
        router_with_state(Duration::from_secs(45));
    let event = stage_join_window(&window, &log, &identity).await;
    let uri = format!("/api/v1/household/owner-events/{}/decline", event.cursor);
    let auth = pop_header_for(&person, "POST", &uri, unix_now(), b"");

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::OK);
    let ack: OwnerDeclineAck = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(ack.version, 1);
    assert_eq!(window.snapshot().await.state, PairMachineState::Aborted);
    let events = log.read_since(event.cursor).unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        OwnerEventType::JoinCancelled
    ));
    let OwnerEventPayload::JoinCancelled(payload) = &events[0].payload else {
        panic!("expected JoinCancelled payload");
    };
    assert_eq!(payload.reason, "declined");
}

#[tokio::test]
async fn approve_happy_path_drives_commit() {
    let (td, router, log, _broadcaster, person, identity, window) =
        router_with_state(Duration::from_secs(45));
    fs::write(household_root_sole_path(td.path()), b"fake-sole-shard").unwrap();
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    // Simulate the iPhone-side `POST /pair-machine/local/anchor` per
    // `contracts/local-anchor.md` (B7): without this, M2's
    // `local/finalize` correctly refuses with 401 trust_anchor_missing.
    candidate
        .window
        .pin_household_anchor(
            identity.record.hh_id.as_str().to_string(),
            *identity.record.hh_pub.as_bytes(),
        )
        .await
        .unwrap();
    let uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let timestamp = unix_now();
    let body = approval_body(
        &identity,
        &person,
        event.cursor,
        candidate.prepared.join_request.challenge_sig.clone(),
        timestamp,
    );
    let auth = pop_header_for(&person, "POST", &uri, timestamp, &body);

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::OK);
    let ack: OwnerApprovalAck = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(ack.version, 1);
    let m2_id = candidate.window.snapshot().await.m_pub.unwrap();
    let m2_id = household_rs::derive_machine_id(
        &household_rs::keys::P256PublicKey::from_bytes(m2_id.as_ref()).unwrap(),
    )
    .to_string();
    let cert_path = machine_cert_for(td.path(), &m2_id);
    assert!(cert_path.exists());
    let cert: household_rs::MachineCert =
        household_rs::cbor::from_canonical_slice(&fs::read(cert_path).unwrap()).unwrap();
    assert_eq!(
        ack.machine_cert_hash.as_ref(),
        machine_cert_hash(&cert).unwrap().as_slice()
    );
    assert!(machine_cert_for(candidate.td.path(), &identity.cert.m_id.to_string()).exists());
    assert!(machine_cert_for(candidate.td.path(), &m2_id).exists());
    assert_eq!(window.snapshot().await.state, PairMachineState::Committed);
    assert!(window.snapshot().await.cached_response.is_some());
    assert_eq!(
        candidate.window.snapshot().await.state,
        PairMachineState::Committed
    );
    assert!(!household_root_sole_path(td.path()).exists());
    let events = log.read_since(event.cursor).unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        OwnerEventType::MachineJoined
    ));
}

#[tokio::test]
async fn approve_legacy_policy_allows_tierless_owner_before_strong_minting() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person) = legacy_owner_auth_for(&identity);
    assert!(!owner_auth.owner_can_fan_out());
    let (td, router, log, _broadcaster, person, identity, window) = router_from_owner_auth(
        td,
        identity,
        owner_auth,
        person,
        Duration::from_secs(45),
        |state| state,
    );

    fs::write(household_root_sole_path(td.path()), b"fake-sole-shard").unwrap();
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    candidate
        .window
        .pin_household_anchor(
            identity.record.hh_id.as_str().to_string(),
            *identity.record.hh_pub.as_bytes(),
        )
        .await
        .unwrap();
    let uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let timestamp = unix_now();
    let body = approval_body(
        &identity,
        &person,
        event.cursor,
        candidate.prepared.join_request.challenge_sig.clone(),
        timestamp,
    );
    let auth = pop_header_for(&person, "POST", &uri, timestamp, &body);

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::OK);
    let ack: OwnerApprovalAck = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(ack.version, 1);
    assert_eq!(window.snapshot().await.state, PairMachineState::Committed);
    assert_eq!(
        candidate.window.snapshot().await.state,
        PairMachineState::Committed
    );
    let events = log.read_since(event.cursor).unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        OwnerEventType::MachineJoined
    ));
}

#[tokio::test]
async fn approve_reviewed_rollout_trust_state_never_enrolled_keeps_legacy_path() {
    let (td, router, log, _broadcaster, person, identity, window) =
        router_with_v2_policy_without_passkey(Duration::from_secs(45));
    fs::write(household_root_sole_path(td.path()), b"fake-sole-shard").unwrap();
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    candidate
        .window
        .pin_household_anchor(
            identity.record.hh_id.as_str().to_string(),
            *identity.record.hh_pub.as_bytes(),
        )
        .await
        .unwrap();
    let uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let timestamp = unix_now();
    let body = approval_body(
        &identity,
        &person,
        event.cursor,
        candidate.prepared.join_request.challenge_sig.clone(),
        timestamp,
    );
    let auth = pop_header_for(&person, "POST", &uri, timestamp, &body);

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::OK);
    let ack: OwnerApprovalAck = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(ack.version, 1);
    assert_eq!(window.snapshot().await.state, PairMachineState::Committed);
}

#[tokio::test]
async fn approve_reviewed_rollout_trust_state_missing_anchor_fails_closed() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, _authenticator) = owner_auth_with_webauthn_credential(&identity);
    let policy = OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout();
    let (_td, router, log, _broadcaster, person, identity, window) = router_from_owner_auth(
        td,
        identity,
        owner_auth,
        person,
        Duration::from_secs(45),
        |state| {
            state
                .with_owner_approval_policy(policy)
                .with_owner_webauthn_rp(rp)
        },
    );
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    let uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let timestamp = unix_now();
    let body = approval_body(
        &identity,
        &person,
        event.cursor,
        candidate.prepared.join_request.challenge_sig.clone(),
        timestamp,
    );
    let auth = pop_header_for(&person, "POST", &uri, timestamp, &body);

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
    assert_eq!(
        window.snapshot().await.state,
        PairMachineState::AwaitingOwner
    );
    assert!(log.read_since(event.cursor).unwrap().is_empty());
}

#[tokio::test]
async fn approval_v2_start_does_not_migrate_missing_anchor_on_request_path() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, _authenticator) = owner_auth_with_webauthn_credential(&identity);
    let owner_auth_for_assert = owner_auth.clone();
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_pair_machine_approve(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
    let (_td, router, log, _broadcaster, person, identity, window) =
        router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
            let anchor_store = Arc::clone(&anchor_store);
            move |state| {
                state
                    .with_owner_approval_policy(policy)
                    .with_owner_webauthn_rp(rp)
                    .with_owner_webauthn_anchor(anchor_store)
            }
        });
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    let start_uri = format!(
        "/api/v1/household/owner-events/{}/approval-v2/start",
        event.cursor
    );
    let start_body =
        household_rs::cbor::to_canonical_vec(&OwnerApprovalV2StartRequest { version: 1 }).unwrap();
    let start_auth = pop_header_for(&person, "POST", &start_uri, unix_now(), &start_body);

    let start_resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(start_uri)
                .header(header::AUTHORIZATION, start_auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(start_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = start_resp.status();
    let resp_bytes = to_bytes(start_resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
    assert_eq!(
        window.snapshot().await.state,
        PairMachineState::AwaitingOwner
    );
    assert!(log.read_since(event.cursor).unwrap().is_empty());
    assert!(
        verify_or_update_owner_webauthn_authority_anchor(
            anchor_store.as_ref(),
            &owner_auth_for_assert.owner_webauthn,
            &identity.record,
            &owner_auth_for_assert.owner_person_cert,
            OwnerWebauthnAnchorMode::Enforcement,
        )
        .is_err()
    );
}

#[tokio::test]
async fn approval_v2_start_rejects_tierless_owner_even_with_active_passkey() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, _authenticator) =
        legacy_owner_auth_with_webauthn_credential(&identity);
    assert!(!owner_auth.owner_can_fan_out());
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    verify_or_update_owner_webauthn_authority_anchor(
        anchor_store.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::MigrationDefaultOff,
    )
    .unwrap();
    let policy = OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout();
    let (_td, router, log, _broadcaster, person, identity, window) = router_from_owner_auth(
        td,
        identity,
        owner_auth,
        person,
        Duration::from_secs(45),
        move |state| {
            state
                .with_owner_approval_policy(policy)
                .with_owner_webauthn_rp(rp)
                .with_owner_webauthn_anchor(anchor_store)
        },
    );
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    let (status, resp_bytes) = post_approval_v2_start(router, &person, event.cursor).await;

    assert_generic_unauth(status, &resp_bytes);
    assert_eq!(
        window.snapshot().await.state,
        PairMachineState::AwaitingOwner
    );
    assert!(log.read_since(event.cursor).unwrap().is_empty());
}

#[tokio::test]
async fn approve_v2_reviewed_rollout_rejects_tierless_owner_before_fan_out() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, _authenticator) =
        legacy_owner_auth_with_webauthn_credential(&identity);
    assert!(!owner_auth.owner_can_fan_out());
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    verify_or_update_owner_webauthn_authority_anchor(
        anchor_store.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::MigrationDefaultOff,
    )
    .unwrap();
    let policy = OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout();
    let (_td, router, log, _broadcaster, person, identity, window) = router_from_owner_auth(
        td,
        identity,
        owner_auth,
        person,
        Duration::from_secs(45),
        move |state| {
            state
                .with_owner_approval_policy(policy)
                .with_owner_webauthn_rp(rp)
                .with_owner_webauthn_anchor(anchor_store)
        },
    );

    fs::write(household_root_sole_path(_td.path()), b"fake-sole-shard").unwrap();
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    candidate
        .window
        .pin_household_anchor(
            identity.record.hh_id.as_str().to_string(),
            *identity.record.hh_pub.as_bytes(),
        )
        .await
        .unwrap();
    let uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let body =
        household_rs::cbor::to_canonical_vec(&OwnerApprovalV2StartRequest { version: 1 }).unwrap();
    let auth = pop_header_for(&person, "POST", &uri, unix_now(), &body);

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_generic_unauth(status, &resp_bytes);
    assert_eq!(
        window.snapshot().await.state,
        PairMachineState::AwaitingOwner
    );
    assert!(log.read_since(event.cursor).unwrap().is_empty());
    assert_ne!(
        candidate.window.snapshot().await.state,
        PairMachineState::Committed
    );
}

#[tokio::test]
async fn approve_reviewed_rollout_trust_state_recovery_required_rejects_legacy_path() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp) = owner_auth_with_revoked_webauthn_credential(&identity);
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    verify_or_update_owner_webauthn_authority_anchor(
        anchor_store.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::MigrationDefaultOff,
    )
    .unwrap();
    let policy = OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout();
    let (_td, router, log, _broadcaster, person, identity, window) = router_from_owner_auth(
        td,
        identity,
        owner_auth,
        person,
        Duration::from_secs(45),
        move |state| {
            state
                .with_owner_approval_policy(policy)
                .with_owner_webauthn_rp(rp)
                .with_owner_webauthn_anchor(anchor_store)
        },
    );
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    let uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let timestamp = unix_now();
    let body = approval_body(
        &identity,
        &person,
        event.cursor,
        candidate.prepared.join_request.challenge_sig.clone(),
        timestamp,
    );
    let auth = pop_header_for(&person, "POST", &uri, timestamp, &body);

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
    assert_eq!(
        window.snapshot().await.state,
        PairMachineState::AwaitingOwner
    );
    assert!(log.read_since(event.cursor).unwrap().is_empty());
}

#[tokio::test]
async fn approval_v2_start_reviewed_rollout_trust_state_recovery_required_fails_closed() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp) = owner_auth_with_revoked_webauthn_credential(&identity);
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    verify_or_update_owner_webauthn_authority_anchor(
        anchor_store.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::MigrationDefaultOff,
    )
    .unwrap();
    let policy = OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout();
    let (_td, router, log, _broadcaster, person, identity, window) = router_from_owner_auth(
        td,
        identity,
        owner_auth,
        person,
        Duration::from_secs(45),
        move |state| {
            state
                .with_owner_approval_policy(policy)
                .with_owner_webauthn_rp(rp)
                .with_owner_webauthn_anchor(anchor_store)
        },
    );
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    let start_uri = format!(
        "/api/v1/household/owner-events/{}/approval-v2/start",
        event.cursor
    );
    let start_body =
        household_rs::cbor::to_canonical_vec(&OwnerApprovalV2StartRequest { version: 1 }).unwrap();
    let start_auth = pop_header_for(&person, "POST", &start_uri, unix_now(), &start_body);

    let start_resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(start_uri)
                .header(header::AUTHORIZATION, start_auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(start_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = start_resp.status();
    let resp_bytes = to_bytes(start_resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
    assert_eq!(
        window.snapshot().await.state,
        PairMachineState::AwaitingOwner
    );
    assert!(log.read_since(event.cursor).unwrap().is_empty());
}

#[tokio::test]
async fn approve_reviewed_rollout_trust_state_empty_authority_with_anchor_fails_closed() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person) = owner_auth_for(&identity);
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    let stale_anchor = OwnerWebauthnAuthorityAnchor::new(
        &identity.record,
        &owner_auth.owner_person_cert,
        0,
        [0x42; 32],
    );
    write_owner_webauthn_authority_anchor(anchor_store.as_ref(), &stale_anchor).unwrap();
    let policy = OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout();
    let (_td, router, log, _broadcaster, person, identity, window) = router_from_owner_auth(
        td,
        identity,
        owner_auth,
        person,
        Duration::from_secs(45),
        move |state| {
            state
                .with_owner_approval_policy(policy)
                .with_owner_webauthn_anchor(anchor_store)
        },
    );
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    let uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let timestamp = unix_now();
    let body = approval_body(
        &identity,
        &person,
        event.cursor,
        candidate.prepared.join_request.challenge_sig.clone(),
        timestamp,
    );
    let auth = pop_header_for(&person, "POST", &uri, timestamp, &body);

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
    assert_eq!(
        window.snapshot().await.state,
        PairMachineState::AwaitingOwner
    );
    assert!(log.read_since(event.cursor).unwrap().is_empty());
}

#[tokio::test]
async fn approve_reviewed_rollout_trust_state_rollback_or_divergent_anchor_fails_closed() {
    for anchor in ["rollback", "divergent"] {
        let td = tempfile::tempdir().unwrap();
        let identity = Arc::new(bootstrap(td.path()));
        let (owner_auth, person, rp, _authenticator) =
            owner_auth_with_webauthn_credential(&identity);
        let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
            Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
        let stale_anchor = match anchor {
            "rollback" => OwnerWebauthnAuthorityAnchor::new(
                &identity.record,
                &owner_auth.owner_person_cert,
                1,
                [0x42; 32],
            ),
            "divergent" => OwnerWebauthnAuthorityAnchor::new(
                &identity.record,
                &owner_auth.owner_person_cert,
                0,
                [0x43; 32],
            ),
            _ => unreachable!(),
        };
        write_owner_webauthn_authority_anchor(anchor_store.as_ref(), &stale_anchor).unwrap();
        let policy = OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout();
        let (_td, router, log, _broadcaster, person, identity, window) =
            router_from_owner_auth(td, identity, owner_auth, person, Duration::from_secs(45), {
                let anchor_store = Arc::clone(&anchor_store);
                move |state| {
                    state
                        .with_owner_approval_policy(policy)
                        .with_owner_webauthn_rp(rp)
                        .with_owner_webauthn_anchor(anchor_store)
                }
            });
        let candidate = start_candidate_harness().await;
        let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
        let uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
        let timestamp = unix_now();
        let body = approval_body(
            &identity,
            &person,
            event.cursor,
            candidate.prepared.join_request.challenge_sig.clone(),
            timestamp,
        );
        let auth = pop_header_for(&person, "POST", &uri, timestamp, &body);

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::AUTHORIZATION, auth)
                    .header(header::CONTENT_TYPE, "application/cbor")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
        assert_eq!(parsed.error, "unauthenticated");
        assert_eq!(
            window.snapshot().await.state,
            PairMachineState::AwaitingOwner
        );
        assert!(log.read_since(event.cursor).unwrap().is_empty());
        let persisted =
            read_owner_webauthn_authority_anchor(anchor_store.as_ref(), &identity.record.hh_id)
                .unwrap()
                .expect("fail-closed path leaves invalid anchor untouched");
        assert_eq!(persisted.sequence(), stale_anchor.sequence());
        assert_eq!(persisted.head_hash(), stale_anchor.head_hash());
    }
}

#[tokio::test]
async fn approve_require_v2_rejects_legacy_body_without_mutation() {
    let (_td, router, log, _broadcaster, person, identity, window, _authenticator) =
        router_with_v2_owner(Duration::from_secs(45));
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    let uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let timestamp = unix_now();
    let body = approval_body(
        &identity,
        &person,
        event.cursor,
        candidate.prepared.join_request.challenge_sig.clone(),
        timestamp,
    );
    let auth = pop_header_for(&person, "POST", &uri, timestamp, &body);

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
    assert_eq!(
        window.snapshot().await.state,
        PairMachineState::AwaitingOwner
    );
    assert!(log.read_since(event.cursor).unwrap().is_empty());
}

#[tokio::test]
async fn approve_v2_reviewed_rollout_happy_path_drives_commit() {
    let (td, router, log, _broadcaster, person, identity, window, mut authenticator) =
        router_with_v2_owner(Duration::from_secs(45));
    fs::write(household_root_sole_path(td.path()), b"fake-sole-shard").unwrap();
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    candidate
        .window
        .pin_household_anchor(
            identity.record.hh_id.as_str().to_string(),
            *identity.record.hh_pub.as_bytes(),
        )
        .await
        .unwrap();

    let start_uri = format!(
        "/api/v1/household/owner-events/{}/approval-v2/start",
        event.cursor
    );
    let start_body =
        household_rs::cbor::to_canonical_vec(&OwnerApprovalV2StartRequest { version: 1 }).unwrap();
    let start_auth = pop_header_for(&person, "POST", &start_uri, unix_now(), &start_body);
    let start_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(start_uri)
                .header(header::AUTHORIZATION, start_auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(start_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start_resp.status(), StatusCode::OK);
    let start_bytes = to_bytes(start_resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    let start: OwnerApprovalV2StartResponse =
        household_rs::cbor::from_canonical_slice(&start_bytes).unwrap();
    assert_eq!(start.version, 1);

    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    let approval = approval_v2_from_assertion(start.context, &assertion);
    let finish_body = household_rs::cbor::to_canonical_vec(&OwnerApprovalV2FinishBody {
        version: 1,
        challenge_id: start.challenge_id,
        approval,
    })
    .unwrap();
    let approve_uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let finish_auth = pop_header_for(&person, "POST", &approve_uri, unix_now(), &finish_body);
    let finish_resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(approve_uri)
                .header(header::AUTHORIZATION, finish_auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(finish_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = finish_resp.status();
    let finish_bytes = to_bytes(finish_resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::OK);
    let ack: OwnerApprovalAck = household_rs::cbor::from_canonical_slice(&finish_bytes).unwrap();
    assert_eq!(ack.version, 1);
    assert_eq!(window.snapshot().await.state, PairMachineState::Committed);
    let events = log.read_since(event.cursor).unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        OwnerEventType::MachineJoined
    ));
}

#[tokio::test]
async fn approve_v2_double_prepare_claim_rejects_second_valid_approval() {
    let (td, router, log, _broadcaster, person, identity, window, mut authenticator) =
        router_with_v2_owner(Duration::from_secs(45));
    fs::write(household_root_sole_path(td.path()), b"fake-sole-shard").unwrap();
    let (candidate, finalize_gate) = start_blocking_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    candidate
        .window
        .pin_household_anchor(
            identity.record.hh_id.as_str().to_string(),
            *identity.record.hh_pub.as_bytes(),
        )
        .await
        .unwrap();

    let first_start = start_approval_v2(router.clone(), &person, event.cursor).await;
    let second_start = start_approval_v2(router.clone(), &person, event.cursor).await;
    let first_context = first_start.context;
    let first_challenge_id = first_start.challenge_id;
    let first_assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            first_start.options,
        )
        .unwrap();
    let second_context = second_start.context;
    let second_challenge_id = second_start.challenge_id;
    let second_assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            second_start.options,
        )
        .unwrap();
    let first_body = approval_v2_finish_body(first_context, first_challenge_id, &first_assertion);
    let second_body =
        approval_v2_finish_body(second_context, second_challenge_id, &second_assertion);

    let first_router = router.clone();
    let first_cursor = event.cursor;
    let first_uri = format!("/api/v1/household/owner-events/{first_cursor}/approve");
    let first_auth = pop_header_for(&person, "POST", &first_uri, unix_now(), &first_body);
    let first_request = Request::builder()
        .method("POST")
        .uri(first_uri)
        .header(header::AUTHORIZATION, first_auth)
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(Body::from(first_body))
        .unwrap();
    let first_task = tokio::spawn(async move {
        let resp = first_router.oneshot(first_request).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, bytes)
    });
    finalize_gate.wait_for_calls(1).await;
    assert_eq!(finalize_gate.calls(), 1);

    let (claimed_start_status, claimed_start_bytes) =
        post_approval_v2_start(router.clone(), &person, event.cursor).await;
    assert_generic_unauth(claimed_start_status, &claimed_start_bytes);

    let (second_status, second_bytes) = tokio::time::timeout(
        Duration::from_secs(5),
        post_approve_body(router.clone(), &person, event.cursor, second_body),
    )
    .await
    .expect("claimed second approval must reject before finalize");
    assert_generic_unauth(second_status, &second_bytes);
    assert_eq!(
        finalize_gate.calls(),
        1,
        "second valid approval must not reach prepare/finalize"
    );

    finalize_gate.release_all();
    let (first_status, first_bytes) = first_task.await.unwrap();
    assert_eq!(first_status, StatusCode::OK);
    let ack: OwnerApprovalAck = household_rs::cbor::from_canonical_slice(&first_bytes).unwrap();
    assert_eq!(ack.version, 1);
    assert_eq!(window.snapshot().await.state, PairMachineState::Committed);
    assert!(window.snapshot().await.approval_claim.is_none());
    assert_eq!(
        candidate.window.snapshot().await.state,
        PairMachineState::Committed
    );
    let events = log.read_since(event.cursor).unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        OwnerEventType::MachineJoined
    ));
}

#[tokio::test]
async fn approve_v2_post_claim_abort_clears_claim_for_next_window() {
    let (_td, router, log, _broadcaster, person, identity, window, mut authenticator) =
        router_with_v2_owner_without_hh_priv(Duration::from_secs(45));
    let first_candidate = start_candidate_harness().await;
    let first_event = stage_prepared_join_window(&window, &log, &identity, &first_candidate).await;
    first_candidate
        .window
        .pin_household_anchor(
            identity.record.hh_id.as_str().to_string(),
            *identity.record.hh_pub.as_bytes(),
        )
        .await
        .unwrap();

    let first_start = start_approval_v2(router.clone(), &person, first_event.cursor).await;
    let first_assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            first_start.options,
        )
        .unwrap();
    let first_body = approval_v2_finish_body(
        first_start.context,
        first_start.challenge_id,
        &first_assertion,
    );
    let (first_status, first_bytes) =
        post_approve_body(router.clone(), &person, first_event.cursor, first_body).await;
    assert_generic_unauth(first_status, &first_bytes);
    let first_snapshot = window.snapshot().await;
    assert_eq!(first_snapshot.state, PairMachineState::Aborted);
    assert!(first_snapshot.approval_claim.is_none());

    let second_candidate = start_candidate_harness().await;
    let second_event =
        stage_prepared_join_window(&window, &log, &identity, &second_candidate).await;
    assert_ne!(first_event.cursor, second_event.cursor);
    second_candidate
        .window
        .pin_household_anchor(
            identity.record.hh_id.as_str().to_string(),
            *identity.record.hh_pub.as_bytes(),
        )
        .await
        .unwrap();
    let second_start = start_approval_v2(router, &person, second_event.cursor).await;
    assert_eq!(second_start.version, 1);
    assert_eq!(
        window.snapshot().await.state,
        PairMachineState::AwaitingOwner
    );
    assert!(window.snapshot().await.approval_claim.is_none());
}

#[tokio::test]
async fn approve_v2_definite_finalize_failure_aborts_and_clears_claim() {
    let (td, router, log, _broadcaster, person, identity, window, mut authenticator) =
        router_with_v2_owner(Duration::from_secs(45));
    fs::write(household_root_sole_path(td.path()), b"fake-sole-shard").unwrap();
    let candidate = start_candidate_harness_with_mode(CandidateFinalizeMode::RejectFinalize).await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    candidate
        .window
        .pin_household_anchor(
            identity.record.hh_id.as_str().to_string(),
            *identity.record.hh_pub.as_bytes(),
        )
        .await
        .unwrap();

    let start = start_approval_v2(router.clone(), &person, event.cursor).await;
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    let body = approval_v2_finish_body(start.context, start.challenge_id, &assertion);
    let (status, bytes) = post_approve_body(router, &person, event.cursor, body).await;

    assert_generic_unauth(status, &bytes);
    let snapshot = window.snapshot().await;
    assert_eq!(snapshot.state, PairMachineState::Aborted);
    assert!(snapshot.approval_claim.is_none());
    let events = log.read_since(event.cursor).unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        OwnerEventType::JoinCancelled
    ));
    let OwnerEventPayload::JoinCancelled(payload) = &events[0].payload else {
        panic!("expected JoinCancelled payload");
    };
    assert_eq!(payload.reason, "candidate_unreachable");
}

#[tokio::test]
async fn approve_v2_context_mismatch_returns_401_without_mutation() {
    let (_td, router, log, _broadcaster, person, identity, window, mut authenticator) =
        router_with_v2_owner(Duration::from_secs(45));
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;

    let start_uri = format!(
        "/api/v1/household/owner-events/{}/approval-v2/start",
        event.cursor
    );
    let start_body =
        household_rs::cbor::to_canonical_vec(&OwnerApprovalV2StartRequest { version: 1 }).unwrap();
    let start_auth = pop_header_for(&person, "POST", &start_uri, unix_now(), &start_body);
    let start_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(start_uri)
                .header(header::AUTHORIZATION, start_auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(start_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start_resp.status(), StatusCode::OK);
    let start_bytes = to_bytes(start_resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    let start: OwnerApprovalV2StartResponse =
        household_rs::cbor::from_canonical_slice(&start_bytes).unwrap();
    let assertion = authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            start.options,
        )
        .unwrap();
    let mut tampered_context = start.context;
    tampered_context.addr = Some("198.51.100.10:8091".to_string());
    let approval = approval_v2_from_assertion(tampered_context, &assertion);
    let finish_body = household_rs::cbor::to_canonical_vec(&OwnerApprovalV2FinishBody {
        version: 1,
        challenge_id: start.challenge_id,
        approval,
    })
    .unwrap();
    let approve_uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let finish_auth = pop_header_for(&person, "POST", &approve_uri, unix_now(), &finish_body);
    let finish_resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(approve_uri)
                .header(header::AUTHORIZATION, finish_auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(finish_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = finish_resp.status();
    let finish_bytes = to_bytes(finish_resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&finish_bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
    assert_eq!(
        window.snapshot().await.state,
        PairMachineState::AwaitingOwner
    );
    assert!(log.read_since(event.cursor).unwrap().is_empty());
}

#[tokio::test]
async fn approve_preserves_m1_evidence_when_m2_commits_but_ack_is_bad() {
    let (td, router, log, _broadcaster, person, identity, window) =
        router_with_state(Duration::from_secs(45));
    fs::write(household_root_sole_path(td.path()), b"fake-sole-shard").unwrap();
    let candidate =
        start_candidate_harness_with_mode(CandidateFinalizeMode::CommitThenBadAck).await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    candidate
        .window
        .pin_household_anchor(
            identity.record.hh_id.as_str().to_string(),
            *identity.record.hh_pub.as_bytes(),
        )
        .await
        .unwrap();
    let uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let timestamp = unix_now();
    let body = approval_body(
        &identity,
        &person,
        event.cursor,
        candidate.prepared.join_request.challenge_sig.clone(),
        timestamp,
    );
    let auth = pop_header_for(&person, "POST", &uri, timestamp, &body);

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.error, "internal");
    assert_eq!(
        candidate.window.snapshot().await.state,
        PairMachineState::Committed
    );
    assert_eq!(
        window.snapshot().await.state,
        PairMachineState::AwaitingOwner
    );
    assert!(phase3_finalize_ack_marker_exists(td.path()));
    assert!(staged_path_for(&household_record_path(td.path())).exists());
    assert!(staged_path_for(&shamir_self_shard_path(td.path())).exists());
    let m2_id = household_rs::derive_machine_id(
        &household_rs::keys::P256PublicKey::from_bytes(
            candidate.window.snapshot().await.m_pub.unwrap().as_ref(),
        )
        .unwrap(),
    )
    .to_string();
    let m1_candidate_cert = machine_cert_for(td.path(), &m2_id);
    assert!(!m1_candidate_cert.exists());
    assert!(staged_path_for(&m1_candidate_cert).exists());
    assert!(machine_cert_for(candidate.td.path(), &m2_id).exists());
    assert!(household_root_sole_path(td.path()).exists());
    assert!(log.read_since(event.cursor).unwrap().is_empty());
}

#[tokio::test]
async fn approve_with_different_challenge_sig_returns_401_and_cancel_event() {
    let (_td, router, log, _broadcaster, person, identity, window) =
        router_with_state(Duration::from_secs(45));
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    let uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let timestamp = unix_now();
    let mut wrong_challenge = candidate.prepared.join_request.challenge_sig.to_vec();
    wrong_challenge[0] ^= 0x01;
    let body = approval_body(
        &identity,
        &person,
        event.cursor,
        ByteBuf::from(wrong_challenge),
        timestamp,
    );
    let auth = pop_header_for(&person, "POST", &uri, timestamp, &body);

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
    assert_eq!(window.snapshot().await.state, PairMachineState::Aborted);
    let events = log.read_since(event.cursor).unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        OwnerEventType::JoinCancelled
    ));
}

#[tokio::test]
async fn approve_with_mismatched_cursor_returns_401() {
    let (_td, router, log, _broadcaster, person, identity, window) =
        router_with_state(Duration::from_secs(45));
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    let uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let timestamp = unix_now();
    let body = approval_body(
        &identity,
        &person,
        event.cursor + 1,
        candidate.prepared.join_request.challenge_sig.clone(),
        timestamp,
    );
    let auth = pop_header_for(&person, "POST", &uri, timestamp, &body);

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn approve_with_timestamp_outside_window_returns_401() {
    let (_td, router, log, _broadcaster, person, identity, window) =
        router_with_state(Duration::from_secs(45));
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    let uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let timestamp = unix_now() - 120;
    let body = approval_body(
        &identity,
        &person,
        event.cursor,
        candidate.prepared.join_request.challenge_sig.clone(),
        timestamp,
    );
    let auth = pop_header_for(&person, "POST", &uri, timestamp, &body);

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn approve_with_bad_pop_returns_401() {
    let (_td, router, log, _broadcaster, person, identity, window) =
        router_with_state(Duration::from_secs(45));
    let candidate = start_candidate_harness().await;
    let event = stage_prepared_join_window(&window, &log, &identity, &candidate).await;
    let uri = format!("/api/v1/household/owner-events/{}/approve", event.cursor);
    let timestamp = unix_now();
    let body = approval_body(
        &identity,
        &person,
        event.cursor,
        candidate.prepared.join_request.challenge_sig.clone(),
        timestamp,
    );

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn decline_malformed_cursor_returns_generic_401() {
    let (_td, router, _log, _broadcaster, person, _identity, _window) =
        router_with_state(Duration::from_secs(45));
    let uri = "/api/v1/household/owner-events/not-a-u64/decline";
    let auth = pop_header_for(&person, "POST", uri, unix_now(), b"");

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let resp_bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.error, "unauthenticated");
}

#[tokio::test]
async fn test_apns_dispatched_when_no_poll() {
    let spy = install_spy_transport();
    spy.clear();
    let (td, _router, log, broadcaster, _person, identity, _window) =
        router_with_state(Duration::from_secs(45));
    household_rs::owner_events::put_owner_push_token(
        td.path(),
        &household_rs::owner_events::OwnerDevicePushToken {
            version: 1,
            p_id: "p_test_owner".into(),
            platform: "ios".into(),
            push_token: ByteBuf::from(vec![9u8; 32]),
            updated_at: unix_now(),
        },
    )
    .unwrap();

    append_join_event(&log, &identity);
    handlers_owner_events::dispatch_owner_event_tickle_if_idle(
        td.path().to_path_buf(),
        &broadcaster,
    );
    let captured = wait_for_captured_tickle(&spy, 1).await;
    assert_eq!(captured[0].as_slice(), APNS_TICKLE_BODY);

    spy.clear();
    let _sub = broadcaster.subscribe();
    append_join_event(&log, &identity);
    handlers_owner_events::dispatch_owner_event_tickle_if_idle(
        td.path().to_path_buf(),
        &broadcaster,
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(spy.captured().is_empty());
}
