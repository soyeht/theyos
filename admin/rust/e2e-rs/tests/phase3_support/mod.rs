#![allow(clippy::missing_panics_doc)]
#![allow(dead_code)]

pub mod failure_injector;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::{Router, routing};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey, verify_signature};
use household_rs::machine_cert::Platform;
use household_rs::owner_events::{
    OwnerEvent, OwnerEventLog, OwnerEventPayload, OwnerEventType, OwnerEventsBroadcaster,
};
use household_rs::pair_machine::{
    JoinRequest, JoinTransport, OwnerApproval, OwnerApprovalContext, PairMachineWindow,
    PrepareCandidateOpts, household_root_sole_path, prepare_candidate, shamir_self_shard_path,
};
use household_rs::person_cert::{PersonCert, SignOwnerOptions};
use household_rs::pop::RequestSigningContext;
use household_rs::storage::{household_record_path, legacy_machine_cert_path, machine_cert_for};
use household_rs::{BootstrapOpts, HouseholdAuthState, KeyBackingPolicy};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use server_rs::handlers_owner_events::{self, OwnerEventsRouterState};
use server_rs::handlers_pair_machine::{
    PairMachineRouterState, PreHouseholdRouterState, founder_join_request_handler,
    pre_household_router,
};
use server_rs::household_state::HouseholdState;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tower::ServiceExt;

pub const JOIN_REQUEST_PATH: &str = "/api/v1/household/join-request";
pub const OWNER_EVENTS_PATH: &str = "/api/v1/household/owner-events";

#[derive(Deserialize)]
pub struct JoinRequestAccepted {
    #[serde(rename = "v")]
    pub version: u8,
    pub owner_event_cursor: u64,
    pub expiry: u64,
}

#[derive(Deserialize)]
pub struct OwnerEventsResponse {
    #[serde(rename = "v")]
    pub version: u8,
    pub events: Vec<OwnerEvent>,
    pub next_cursor: u64,
}

#[derive(Deserialize)]
pub struct OwnerApprovalAck {
    #[serde(rename = "v")]
    pub version: u8,
    pub machine_cert_hash: ByteBuf,
}

#[derive(serde::Serialize)]
struct LocalAnchorWire<'a> {
    #[serde(rename = "v")]
    version: u8,
    anchor_secret: ByteBuf,
    hh_id: &'a str,
    hh_pub: ByteBuf,
}

pub struct OwnerHarness {
    pub auth: Arc<HouseholdAuthState>,
    pub key: P256Keypair,
}

pub struct FounderHarness {
    pub dir: TempDir,
    pub identity: Arc<household_rs::LoadedIdentity>,
    pub owner: OwnerHarness,
    pub window: Arc<PairMachineWindow>,
    pub event_log: Arc<OwnerEventLog>,
    pub router: Router,
    /// Cloned `PairMachineRouterState` so Story 2's Bonjour browser can
    /// stage `JoinRequest`s against the same in-process founder window
    /// the HTTP router writes into.
    pub pair_state: PairMachineRouterState,
}

pub struct CandidateHarness {
    pub dir: TempDir,
    pub window: Arc<PairMachineWindow>,
    pub prepared: household_rs::pair_machine::PreparedCandidate,
    pub router: Router,
    server: Option<tokio::task::JoinHandle<()>>,
}

impl CandidateHarness {
    /// Constructor used by `tests/phase3_atomic_rollback.rs` so it can
    /// build a candidate harness with a custom TTL without re-
    /// implementing the entire `candidate_harness()` body. The orphan
    /// rule prevents external test files from adding inherent impls,
    /// hence this `__new_for_test` escape hatch lives in the support
    /// module.
    #[doc(hidden)]
    #[must_use]
    pub fn __new_for_test(
        dir: TempDir,
        window: Arc<PairMachineWindow>,
        prepared: household_rs::pair_machine::PreparedCandidate,
        router: Router,
        server: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self {
            dir,
            window,
            prepared,
            router,
            server: Some(server),
        }
    }

    /// Abort the candidate's pre-household HTTP server. Used by the
    /// rollback tests (T067, T069) to simulate "M2 becomes unreachable
    /// during M1's finalize POST". After this returns, future POSTs
    /// to `candidate.prepared.addr` get connection-refused; the
    /// candidate's on-disk state at `candidate.dir` is preserved.
    pub fn stop_server(&mut self) {
        if let Some(handle) = self.server.take() {
            handle.abort();
        }
    }
}

pub struct CompletedCeremony {
    pub founder: FounderHarness,
    pub candidate: CandidateHarness,
    pub accepted: JoinRequestAccepted,
    pub approval_ack: OwnerApprovalAck,
    pub join_request_from_qr: JoinRequest,
    pub anchor_secret: [u8; 32],
    pub elapsed: Duration,
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_secs()
}

fn bootstrap(state_dir: &std::path::Path, hostname: &str) -> household_rs::LoadedIdentity {
    household_rs::bootstrap_or_load(
        state_dir,
        BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some(hostname.into()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .expect("bootstrap household identity")
}

fn owner_auth_for(identity: &household_rs::LoadedIdentity) -> OwnerHarness {
    let key = P256Keypair::generate();
    let cert = PersonCert::sign_owner(
        identity
            .hh_priv
            .as_deref()
            .expect("single-machine household has hh_priv"),
        SignOwnerOptions {
            hh_id: identity.record.hh_id.clone(),
            p_pub: key.public(),
            display_name: "Owner".into(),
            issued_at: identity.record.created_at,
        },
    )
    .expect("sign owner cert");
    OwnerHarness {
        auth: Arc::new(HouseholdAuthState::new(&identity.record, cert)),
        key,
    }
}

pub fn founder_harness() -> FounderHarness {
    let dir = tempfile::tempdir().expect("m1 tempdir");
    let identity = Arc::new(bootstrap(dir.path(), "studio-m1"));
    let owner = owner_auth_for(&identity);
    let household = HouseholdState::loaded_with_owner_auth(
        Arc::clone(&identity),
        Some(Arc::clone(&owner.auth)),
    );
    let window =
        Arc::new(PairMachineWindow::with_persistence(dir.path().to_path_buf()).expect("m1 window"));
    let broadcaster = OwnerEventsBroadcaster::new();
    let event_log =
        OwnerEventLog::open_with_broadcaster(dir.path().to_path_buf(), broadcaster.clone())
            .expect("owner event log");

    let pair_state = PairMachineRouterState {
        window: Arc::clone(&window),
        household: household.clone(),
        event_log: Arc::clone(&event_log),
        event_broadcaster: broadcaster.clone(),
        state_dir: dir.path().to_path_buf(),
    };
    let owner_state = OwnerEventsRouterState::with_timeout(
        household,
        Arc::clone(&window),
        Arc::clone(&event_log),
        broadcaster,
        dir.path().to_path_buf(),
        KeyBackingPolicy::ForceSoftware,
        Duration::from_millis(50),
    );
    let router = Router::new()
        .route(
            JOIN_REQUEST_PATH,
            routing::post(founder_join_request_handler),
        )
        .with_state(pair_state.clone())
        .merge(
            Router::new()
                .route(
                    OWNER_EVENTS_PATH,
                    routing::get(handlers_owner_events::owner_events_long_poll),
                )
                .route(
                    "/api/v1/household/owner-events/{cursor}/approve",
                    routing::post(handlers_owner_events::owner_approve_handler),
                )
                .route(
                    "/api/v1/household/owner-events/{cursor}/decline",
                    routing::post(handlers_owner_events::owner_decline_handler),
                )
                .with_state(owner_state),
        );

    FounderHarness {
        dir,
        identity,
        owner,
        window,
        event_log,
        router,
        pair_state,
    }
}

pub fn rebuild_founder_router_from_disk(
    founder: &FounderHarness,
) -> (Router, Arc<PairMachineWindow>, Arc<OwnerEventLog>) {
    let identity = Arc::new(
        household_rs::try_load_existing(founder.dir.path(), KeyBackingPolicy::ForceSoftware)
            .expect("reload founder identity")
            .expect("founder identity exists"),
    );
    let household =
        HouseholdState::loaded_with_owner_auth(identity, Some(Arc::clone(&founder.owner.auth)));
    let window = Arc::new(
        PairMachineWindow::with_persistence(founder.dir.path().to_path_buf())
            .expect("reload pair-machine window"),
    );
    let broadcaster = OwnerEventsBroadcaster::new();
    let event_log =
        OwnerEventLog::open_with_broadcaster(founder.dir.path().to_path_buf(), broadcaster.clone())
            .expect("reload owner event log");
    let pair_state = PairMachineRouterState {
        window: Arc::clone(&window),
        household: household.clone(),
        event_log: Arc::clone(&event_log),
        event_broadcaster: broadcaster.clone(),
        state_dir: founder.dir.path().to_path_buf(),
    };
    let owner_state = OwnerEventsRouterState::with_timeout(
        household,
        Arc::clone(&window),
        Arc::clone(&event_log),
        broadcaster,
        founder.dir.path().to_path_buf(),
        KeyBackingPolicy::ForceSoftware,
        Duration::from_millis(50),
    );
    let router = Router::new()
        .route(
            JOIN_REQUEST_PATH,
            routing::post(founder_join_request_handler),
        )
        .with_state(pair_state)
        .merge(
            Router::new()
                .route(
                    OWNER_EVENTS_PATH,
                    routing::get(handlers_owner_events::owner_events_long_poll),
                )
                .route(
                    "/api/v1/household/owner-events/{cursor}/approve",
                    routing::post(handlers_owner_events::owner_approve_handler),
                )
                .with_state(owner_state),
        );
    (router, window, event_log)
}

pub async fn candidate_harness() -> CandidateHarness {
    let dir = tempfile::tempdir().expect("m2 tempdir");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind candidate listener");
    let addr = listener.local_addr().expect("candidate local addr");
    let window =
        Arc::new(PairMachineWindow::with_persistence(dir.path().to_path_buf()).expect("m2 window"));
    let prepared = prepare_candidate(
        &window,
        PrepareCandidateOpts {
            state_dir: dir.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: addr.to_string(),
            hostname: "studio-m2".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: Duration::from_secs(300),
            now_unix: unix_now(),
        },
    )
    .await
    .expect("prepare candidate");
    let router = pre_household_router(PreHouseholdRouterState {
        window: Arc::clone(&window),
        state_dir: dir.path().to_path_buf(),
        key_policy: KeyBackingPolicy::ForceSoftware,
        finalize_lock: Arc::new(tokio::sync::Mutex::new(())),
    });
    let served_router = router.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, served_router).await;
    });

    CandidateHarness {
        dir,
        window,
        prepared,
        router,
        server: Some(server),
    }
}

pub fn pop_header(
    owner: &OwnerHarness,
    method: &str,
    path_and_query: &str,
    timestamp: u64,
    body: &[u8],
) -> String {
    let ctx = RequestSigningContext::new(method, path_and_query, timestamp, body);
    let sig = owner
        .key
        .sign(&ctx.canonical_bytes().expect("canonical PoP context"))
        .expect("sign PoP context");
    format!(
        "Soyeht-PoP v1:{}:{}:{}",
        owner.auth.owner_person_cert.p_id.0,
        timestamp,
        B64URL.encode(sig.as_bytes())
    )
}

pub async fn post_cbor(
    router: Router,
    path: &str,
    body: Vec<u8>,
    owner: Option<&OwnerHarness>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/cbor");
    if let Some(owner) = owner {
        builder = builder.header(
            header::AUTHORIZATION,
            pop_header(owner, "POST", path, unix_now(), &body),
        );
    }
    let resp = router
        .oneshot(builder.body(Body::from(body)).expect("request body"))
        .await
        .expect("router response");
    response_parts(resp).await
}

pub async fn get_cbor(
    router: Router,
    path: &str,
    owner: &OwnerHarness,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let builder = Request::builder().method(Method::GET).uri(path).header(
        header::AUTHORIZATION,
        pop_header(owner, "GET", path, unix_now(), b""),
    );
    let resp = router
        .oneshot(builder.body(Body::empty()).expect("request body"))
        .await
        .expect("router response");
    response_parts(resp).await
}

async fn response_parts(resp: axum::response::Response) -> (StatusCode, HeaderMap, Vec<u8>) {
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read response")
        .to_vec();
    (status, headers, body)
}

pub fn cursor_param(cursor: u64) -> String {
    let bytes = household_rs::cbor::to_canonical_vec(&cursor).expect("cursor cbor");
    B64URL.encode(bytes)
}

fn parse_pair_machine_query(uri: &str) -> BTreeMap<String, String> {
    let (_, query) = uri.split_once('?').expect("pair-machine uri has query");
    query
        .split('&')
        .map(|kv| {
            let (k, v) = kv.split_once('=').expect("query item has key/value");
            (k.to_string(), v.to_string())
        })
        .collect()
}

pub fn parse_join_request_from_qr(uri: &str) -> (JoinRequest, [u8; 32]) {
    assert!(uri.starts_with("soyeht://household/pair-machine?"));
    let q = parse_pair_machine_query(uri);
    assert_eq!(q.get("v").map(String::as_str), Some("1"));
    let m_pub = B64URL
        .decode(q.get("m_pub").expect("m_pub param"))
        .expect("decode m_pub");
    let nonce = B64URL
        .decode(q.get("nonce").expect("nonce param"))
        .expect("decode nonce");
    let challenge_sig = B64URL
        .decode(q.get("challenge_sig").expect("challenge_sig param"))
        .expect("decode challenge_sig");
    let anchor_secret_vec = B64URL
        .decode(q.get("anchor_secret").expect("anchor_secret param"))
        .expect("decode anchor_secret");
    let anchor_secret: [u8; 32] = anchor_secret_vec
        .try_into()
        .expect("anchor_secret is 32 bytes");
    let platform = match q.get("platform").map(String::as_str) {
        Some("macos") => Platform::Macos,
        Some("linux-nix") => Platform::LinuxNix,
        Some("linux-other") => Platform::LinuxOther,
        other => panic!("unexpected platform param: {other:?}"),
    };
    let transport = match q.get("transport").map(String::as_str) {
        Some("tailscale") => JoinTransport::Tailscale,
        Some("lan") => JoinTransport::Lan,
        other => panic!("unexpected transport param: {other:?}"),
    };
    (
        JoinRequest {
            version: 1,
            m_pub: ByteBuf::from(m_pub),
            hostname: q.get("hostname").expect("hostname param").clone(),
            platform,
            nonce: ByteBuf::from(nonce),
            addr: q.get("addr").expect("addr param").clone(),
            transport,
            challenge_sig: ByteBuf::from(challenge_sig),
        },
        anchor_secret,
    )
}

pub fn verify_owner_side_challenge(join_request: &JoinRequest) {
    household_rs::pair_machine::verify_join_request(join_request)
        .expect("owner-side QR verification accepts signed JoinRequest");
    let challenge = join_request.challenge().expect("challenge from request");
    let challenge_bytes = challenge
        .to_canonical_bytes()
        .expect("canonical JoinChallenge bytes");
    let m_pub =
        P256PublicKey::from_bytes(join_request.m_pub.as_ref()).expect("QR m_pub decodes as P-256");
    let sig = household_rs::P256Signature::from_bytes(join_request.challenge_sig.as_ref())
        .expect("challenge sig length");
    verify_signature(&m_pub, &challenge_bytes, &sig).expect("challenge signature verifies");
}

pub fn owner_approval_body(
    founder: &FounderHarness,
    join_request: &JoinRequest,
    cursor: u64,
    timestamp: u64,
) -> Vec<u8> {
    let ctx = OwnerApprovalContext::build(
        founder.identity.record.hh_id.clone(),
        founder.owner.auth.owner_person_cert.p_id.clone(),
        cursor,
        join_request.challenge_sig.clone(),
        timestamp,
    );
    let sig = founder
        .owner
        .key
        .sign(&ctx.to_canonical_bytes().expect("approval context cbor"))
        .expect("sign approval context");
    let approval = OwnerApproval {
        version: 1,
        cursor,
        approval_sig: sig,
    };
    approval.to_canonical_bytes().expect("approval cbor")
}

pub async fn post_local_anchor(
    candidate: &CandidateHarness,
    founder: &FounderHarness,
    anchor_secret: &[u8; 32],
) {
    let body = household_rs::cbor::to_canonical_vec(&LocalAnchorWire {
        version: 1,
        anchor_secret: ByteBuf::from(anchor_secret.to_vec()),
        hh_id: founder.identity.record.hh_id.as_str(),
        hh_pub: ByteBuf::from(founder.identity.record.hh_pub.as_bytes().to_vec()),
    })
    .expect("local anchor cbor");
    let (status, _, _) = post_cbor(
        candidate.router.clone(),
        "/pair-machine/local/anchor",
        body,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

pub async fn run_remote_ceremony() -> CompletedCeremony {
    let founder = founder_harness();
    let candidate = candidate_harness().await;
    let qr_uri = candidate
        .prepared
        .join_request
        .to_pair_machine_uri_with_anchor(
            candidate.prepared.ttl_unix,
            &candidate.prepared.anchor_secret,
        );
    let (join_request_from_qr, anchor_secret) = parse_join_request_from_qr(&qr_uri);
    verify_owner_side_challenge(&join_request_from_qr);
    assert_eq!(
        join_request_from_qr
            .to_canonical_bytes()
            .expect("qr join request cbor"),
        candidate.prepared.join_request_cbor
    );

    let start = Instant::now();
    let (status, headers, body) = post_cbor(
        founder.router.clone(),
        JOIN_REQUEST_PATH,
        candidate.prepared.join_request_cbor.clone(),
        Some(&founder.owner),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/cbor")
    );
    let accepted: JoinRequestAccepted =
        household_rs::cbor::from_canonical_slice(&body).expect("decode accepted");
    assert_eq!(accepted.version, 1);
    assert_eq!(accepted.owner_event_cursor, 1);
    assert!(accepted.expiry > unix_now());

    let owner_events_uri = format!("{OWNER_EVENTS_PATH}?since={}", cursor_param(0));
    let (status, _, body) =
        get_cbor(founder.router.clone(), &owner_events_uri, &founder.owner).await;
    assert_eq!(status, StatusCode::OK);
    let events: OwnerEventsResponse =
        household_rs::cbor::from_canonical_slice(&body).expect("decode events");
    assert_eq!(events.version, 1);
    assert_eq!(events.next_cursor, 1);
    assert_eq!(events.events.len(), 1);
    assert_eq!(events.events[0].cursor, accepted.owner_event_cursor);
    assert_eq!(events.events[0].event_type, OwnerEventType::JoinRequest);
    let OwnerEventPayload::JoinRequest(payload) = &events.events[0].payload else {
        panic!("first owner event should be join-request");
    };
    assert_eq!(
        payload.join_request_cbor.as_ref(),
        candidate.prepared.join_request_cbor.as_slice()
    );
    assert_eq!(payload.fingerprint, candidate.prepared.fingerprint);

    post_local_anchor(&candidate, &founder, &anchor_secret).await;

    let approve_path = format!(
        "/api/v1/household/owner-events/{}/approve",
        accepted.owner_event_cursor
    );
    let approval_body = owner_approval_body(
        &founder,
        &candidate.prepared.join_request,
        accepted.owner_event_cursor,
        unix_now(),
    );
    let (status, _, body) = post_cbor(
        founder.router.clone(),
        &approve_path,
        approval_body,
        Some(&founder.owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let approval_ack: OwnerApprovalAck =
        household_rs::cbor::from_canonical_slice(&body).expect("decode approval ack");
    assert_eq!(approval_ack.version, 1);
    assert_eq!(approval_ack.machine_cert_hash.len(), 32);

    CompletedCeremony {
        founder,
        candidate,
        accepted,
        approval_ack,
        join_request_from_qr,
        anchor_secret,
        elapsed: start.elapsed(),
    }
}

pub fn assert_machine_cert_layout(dir: &std::path::Path, m1_id: &str, m2_id: &str) {
    assert!(
        machine_cert_for(dir, m1_id).exists(),
        "missing m1 cert in {}",
        dir.display()
    );
    assert!(
        machine_cert_for(dir, m2_id).exists(),
        "missing m2 cert in {}",
        dir.display()
    );
    assert!(
        !legacy_machine_cert_path(dir).exists(),
        "legacy machine_cert.cbor should not exist in {}",
        dir.display()
    );
}

pub fn assert_record_is_two_member(dir: &std::path::Path, m1_id: &str, m2_id: &str) {
    let record: household_rs::HouseholdRecord =
        household_rs::storage::read_optional_cbor(&household_record_path(dir))
            .expect("read household record")
            .expect("household record exists");
    assert_eq!(record.shamir_k, 2);
    assert_eq!(record.shamir_n, 2);
    // The Phase 3 contract treats members as a two-entry set; do not couple
    // this e2e assertion to the storage insertion order.
    let mut members: Vec<String> = record.members.iter().map(ToString::to_string).collect();
    members.sort();
    let mut expected = vec![m1_id.to_string(), m2_id.to_string()];
    expected.sort();
    assert_eq!(members, expected);
}

pub fn assert_successful_remote_ceremony(c: &CompletedCeremony) {
    assert!(
        c.elapsed < Duration::from_secs(30),
        "remote ceremony exceeded SC-001 budget: {:?}",
        c.elapsed
    );
    let m1_id = c.founder.identity.cert.m_id.to_string();
    let m2_id = c.candidate.prepared.m_id.to_string();
    assert_machine_cert_layout(c.founder.dir.path(), &m1_id, &m2_id);
    assert_machine_cert_layout(c.candidate.dir.path(), &m1_id, &m2_id);
    assert_record_is_two_member(c.founder.dir.path(), &m1_id, &m2_id);
    assert_record_is_two_member(c.candidate.dir.path(), &m1_id, &m2_id);
    assert!(!household_root_sole_path(c.founder.dir.path()).exists());
    assert!(shamir_self_shard_path(c.founder.dir.path()).exists());
    assert!(shamir_self_shard_path(c.candidate.dir.path()).exists());
}
