//! T049 integration coverage for
//! `GET /api/v1/household/owner-events?since=<cursor>`.

use std::fs;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex as StdMutex, OnceLock};
use std::time::Duration;

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{
    Router,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::machine_cert::Platform;
use household_rs::owner_approval_v2::{OwnerApprovalContextV2, OwnerApprovalV2};
use household_rs::owner_events::{
    JoinRequestPayload, OwnerEvent, OwnerEventLog, OwnerEventPayload, OwnerEventType,
    OwnerEventsBroadcaster,
};
use household_rs::owner_webauthn::{OwnerWebauthnConfig, OwnerWebauthnCredential, OwnerWebauthnRp};
use household_rs::owner_webauthn_anchor::{
    OwnerWebauthnAnchorMode, verify_or_update_owner_webauthn_authority_anchor,
};
use household_rs::owner_webauthn_authority::OwnerWebauthnAuthority;
use household_rs::pair_machine::{
    JoinTransport, OwnerApproval, OwnerApprovalContext, PairMachineState, PairMachineWindow,
    PrepareCandidateOpts, household_root_sole_path, machine_cert_hash, prepare_candidate,
    shamir_self_shard_path,
};
use household_rs::person_cert::{PersonCert, SignOwnerOptions};
use household_rs::pop::RequestSigningContext;
use household_rs::storage::{
    household_record_path, machine_cert_for, phase3_finalize_ack_marker_exists, staged_path_for,
};
use household_rs::{BootstrapOpts, HouseholdAuthState, KeyBackingPolicy};
use keystore_rs::{FileKeystore, KeystoreBackend, KeystoreError};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use server_rs::apns_dispatcher::{APNS_TICKLE_BODY, ApnsError, ApnsTransport, install_transport};
use server_rs::handlers_owner_events::{
    self, OwnerApprovalEnforcementPolicy, OwnerEventsRouterState, OwnerOperationEnforcement,
};
use server_rs::handlers_pair_machine::{PreHouseholdRouterState, pre_household_router};
use server_rs::household_state::HouseholdState;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tower::ServiceExt;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Uuid,
};

const OWNER_EVENTS_PATH: &str = "/api/v1/household/owner-events";

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
    (td, router, event_log, broadcaster, person, identity, window)
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
    let (owner_auth, person) = owner_auth_for(&identity);
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

fn owner_auth_with_webauthn_credential(
    identity: &household_rs::LoadedIdentity,
) -> (
    household_rs::HouseholdAuthState,
    P256Keypair,
    OwnerWebauthnRp,
    WebauthnAuthenticator<SoftPasskey>,
) {
    let (mut owner_auth, person) = owner_auth_for(identity);
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

fn router_with_v2_owner(
    timeout: Duration,
) -> (
    TempDir,
    Router,
    Arc<OwnerEventLog>,
    OwnerEventsBroadcaster,
    P256Keypair,
    Arc<household_rs::LoadedIdentity>,
    Arc<PairMachineWindow>,
    WebauthnAuthenticator<SoftPasskey>,
) {
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
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_pair_machine_approve(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
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

fn router_with_v2_policy_without_passkey(
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
    let (owner_auth, person) = owner_auth_for(&identity);
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_pair_machine_approve(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
    router_from_owner_auth(td, identity, owner_auth, person, timeout, move |state| {
        state
            .with_owner_approval_policy(policy)
            .with_owner_webauthn_anchor(anchor_store)
    })
}

fn router_with_owner_webauthn_registration(
    timeout: Duration,
) -> (
    TempDir,
    Router,
    Arc<OwnerEventLog>,
    OwnerEventsBroadcaster,
    P256Keypair,
    Arc<household_rs::LoadedIdentity>,
    Arc<PairMachineWindow>,
    Arc<dyn keystore_rs::KeystoreBackend>,
) {
    let td = tempfile::tempdir().unwrap();
    let anchor_store: Arc<dyn keystore_rs::KeystoreBackend> =
        Arc::new(FileKeystore::new(td.path(), keystore_rs::SERVICE));
    router_with_owner_webauthn_registration_anchor(timeout, td, anchor_store)
}

fn router_with_owner_webauthn_registration_anchor(
    timeout: Duration,
    td: TempDir,
    anchor_store: Arc<dyn keystore_rs::KeystoreBackend>,
) -> (
    TempDir,
    Router,
    Arc<OwnerEventLog>,
    OwnerEventsBroadcaster,
    P256Keypair,
    Arc<household_rs::LoadedIdentity>,
    Arc<PairMachineWindow>,
    Arc<dyn keystore_rs::KeystoreBackend>,
) {
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

#[derive(Clone, Copy)]
enum CandidateFinalizeMode {
    Normal,
    CommitThenBadAck,
}

async fn start_candidate_harness() -> CandidateHarness {
    start_candidate_harness_with_mode(CandidateFinalizeMode::Normal).await
}

async fn start_candidate_harness_with_mode(mode: CandidateFinalizeMode) -> CandidateHarness {
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
    let router = match mode {
        CandidateFinalizeMode::Normal => pre_household_router(state),
        CandidateFinalizeMode::CommitThenBadAck => Router::new()
            .route(
                "/pair-machine/local/finalize",
                post(commit_then_bad_finalize_ack),
            )
            .with_state(state),
    };
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
async fn owner_webauthn_registration_rejects_wrong_person_pop() {
    let (_td, router, _log, _broadcaster, _person, _identity, _window, _anchor_store) =
        router_with_owner_webauthn_registration(Duration::from_secs(45));
    let wrong_person = P256Keypair::generate();
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
    let finish_body =
        household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationFinishRequest {
            version: 1,
            challenge_id: start.challenge_id,
            credential,
        })
        .unwrap();
    finish_body
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
        post_cbor(router, finish_uri, finish_body, Some(&person)).await;
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
        post_cbor(router, finish_uri, finish_body, Some(&person)).await;

    assert_generic_unauth(status, &resp_bytes);
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
        post_cbor(router, start_uri, start_body, Some(&person)).await;
    assert_generic_unauth(status, &resp_bytes);

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

    let (status, _headers, resp_bytes) = post_cbor(router, &uri, body, Some(&person)).await;

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
async fn approve_policy_on_without_passkey_keeps_legacy_path() {
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
async fn approve_policy_on_with_passkey_without_anchor_fails_closed() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person, rp, _authenticator) = owner_auth_with_webauthn_credential(&identity);
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_pair_machine_approve(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);
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
async fn approve_v2_happy_path_drives_commit() {
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
