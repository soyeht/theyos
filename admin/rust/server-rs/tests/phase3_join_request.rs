//! T046 founder-side `POST /api/v1/household/join-request` integration
//! tests. Exercises the happy path (201), the deterministic-CBOR 401
//! generic-failure surface, and the idempotent-restage path.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use axum::{Router, routing::post};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
use household_rs::owner_events::{OwnerEventLog, OwnerEventsBroadcaster};
use household_rs::pair_machine::{
    JoinRequest, JoinTransport, PairMachineState, PairMachineWindow, PairMachineWindowSnapshot,
    PrepareCandidateOpts, pair_machine_window_path, prepare_candidate,
};
use household_rs::person_cert::{PersonCert, SignOwnerOptions};
use household_rs::pop::RequestSigningContext;
use household_rs::{BootstrapOpts, HouseholdAuthState, KeyBackingPolicy, LoadedIdentity};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use server_rs::handlers_pair_machine::{self, PairMachineRouterState};
use server_rs::household_state::HouseholdState;
use tower::ServiceExt;

#[derive(Deserialize, Debug, PartialEq, Eq)]
struct JoinRequestAccepted {
    #[serde(rename = "v")]
    version: u8,
    owner_event_cursor: u64,
    expiry: u64,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
struct GenericUnauth {
    #[serde(rename = "v")]
    version: u8,
    error: String,
}

const JOIN_REQUEST_PATH: &str = "/api/v1/household/join-request";

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

fn router_with_state(state_dir: &std::path::Path) -> (Router, Arc<PairMachineWindow>, P256Keypair) {
    let identity = Arc::new(bootstrap(state_dir));
    let (owner_auth, person) = owner_auth_for(&identity);
    let (router, window) = router_with_loaded_identity(state_dir, &identity, owner_auth);
    (router, window, person)
}

fn router_with_loaded_identity(
    state_dir: &std::path::Path,
    identity: &Arc<LoadedIdentity>,
    owner_auth: HouseholdAuthState,
) -> (Router, Arc<PairMachineWindow>) {
    let owner_auth = Arc::new(owner_auth);
    let household = HouseholdState::loaded_with_owner_auth(Arc::clone(identity), Some(owner_auth));
    let window = Arc::new(PairMachineWindow::with_persistence(state_dir.to_path_buf()).unwrap());
    let broadcaster = OwnerEventsBroadcaster::new();
    let event_log =
        OwnerEventLog::open_with_broadcaster(state_dir.to_path_buf(), broadcaster.clone()).unwrap();

    let state = PairMachineRouterState {
        window: Arc::clone(&window),
        household,
        event_log,
        event_broadcaster: broadcaster,
        state_dir: state_dir.to_path_buf(),
    };

    let router = Router::new()
        .route(
            JOIN_REQUEST_PATH,
            post(handlers_pair_machine::founder_join_request_handler),
        )
        .with_state(state);
    (router, window)
}

async fn build_signed_request_bytes(state_dir: &std::path::Path) -> Vec<u8> {
    let candidate_dir = tempfile::tempdir().unwrap();
    let win = PairMachineWindow::with_persistence(candidate_dir.path().to_path_buf()).unwrap();
    let prepared = prepare_candidate(
        &win,
        PrepareCandidateOpts {
            state_dir: candidate_dir.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: "100.1.2.3:8091".into(),
            hostname: "studio-linux".into(),
            platform: household_rs::machine_cert::Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: std::time::Duration::from_secs(300),
            now_unix: 1_700_000_000,
        },
    )
    .await
    .unwrap();
    // The candidate's state dir is independent of M1's state dir.
    // Hand back the canonical CBOR bytes only.
    let _ = state_dir;
    prepared.join_request_cbor
}

fn write_committed_snapshot(
    state_dir: &std::path::Path,
    join_request_cbor: &[u8],
    cached_response: Vec<u8>,
    expiry: u64,
) {
    let request: JoinRequest = household_rs::cbor::from_canonical_slice(join_request_cbor).unwrap();
    let m_pub_arr: [u8; 33] = request.m_pub.as_ref().try_into().unwrap();
    let snap = PairMachineWindowSnapshot {
        version: 1,
        state: PairMachineState::Committed,
        m_pub: Some(request.m_pub.clone()),
        nonce: Some(request.nonce.clone()),
        expiry: Some(expiry),
        transport: Some(request.transport),
        addr_hint: Some(request.addr),
        fingerprint: Some(household_rs::fingerprint::fingerprint(&m_pub_arr)),
        owner_event_cursor: Some(1),
        cached_join_request: Some(ByteBuf::from(join_request_cbor.to_vec())),
        cached_response: Some(ByteBuf::from(cached_response)),
        anchor_secret: None,
        pinned_hh_pub: None,
        pinned_hh_id: None,
        approval_claim: None,
    };
    household_rs::storage::atomic_write_cbor(&pair_machine_window_path(state_dir), &snap).unwrap();
}

fn candidate_machine_id(join_request_cbor: &[u8]) -> household_rs::MachineId {
    let request: JoinRequest = household_rs::cbor::from_canonical_slice(join_request_cbor).unwrap();
    let candidate_m_pub = P256PublicKey::from_bytes(request.m_pub.as_ref()).unwrap();
    household_rs::derive_machine_id(&candidate_m_pub)
}

fn pop_header(person: &P256Keypair, timestamp: u64, body: &[u8]) -> String {
    let ctx = RequestSigningContext::new("POST", JOIN_REQUEST_PATH, timestamp, body);
    let sig = person.sign(&ctx.canonical_bytes().unwrap()).unwrap();
    format!(
        "Soyeht-PoP v1:{}:{}:{}",
        household_rs::derive_person_id(&person.public()).0,
        timestamp,
        B64URL.encode(sig.as_bytes())
    )
}

async fn post_cbor(
    router: Router,
    body: Vec<u8>,
    person: Option<&P256Keypair>,
) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(JOIN_REQUEST_PATH)
        .header("content-type", "application/cbor");
    if let Some(person) = person {
        builder = builder.header(header::AUTHORIZATION, pop_header(person, unix_now(), &body));
    }
    let resp = router
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

#[tokio::test]
async fn replay_within_grace_returns_cached_response_bytes() {
    let td = tempfile::tempdir().unwrap();
    let body = build_signed_request_bytes(td.path()).await;
    let cached_response = vec![0xa1, 0x61, b'v', 0x01];
    write_committed_snapshot(
        td.path(),
        &body,
        cached_response.clone(),
        unix_now().saturating_add(300),
    );
    let (router, _window, person) = router_with_state(td.path());

    let (status, resp_bytes) = post_cbor(router, body, Some(&person)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp_bytes, cached_response);
}

#[tokio::test]
async fn replay_within_grace_precedes_post_shamir_membership_gates() {
    let td = tempfile::tempdir().unwrap();
    let body = build_signed_request_bytes(td.path()).await;
    let cached_response = vec![0xa1, 0x61, b'v', 0x01];
    write_committed_snapshot(
        td.path(),
        &body,
        cached_response.clone(),
        unix_now().saturating_add(300),
    );

    let mut identity = bootstrap(td.path());
    let (owner_auth, person) = owner_auth_for(&identity);
    identity.record.shamir_k = 2;
    identity.record.shamir_n = 2;
    identity.record.members.push(candidate_machine_id(&body));
    identity.record.validate().unwrap();
    let identity = Arc::new(identity);
    let (router, _window) = router_with_loaded_identity(td.path(), &identity, owner_auth);

    let (status, resp_bytes) = post_cbor(router, body, Some(&person)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp_bytes, cached_response);
}

#[tokio::test]
async fn replay_after_grace_returns_generic_401() {
    let td = tempfile::tempdir().unwrap();
    let body = build_signed_request_bytes(td.path()).await;
    let cached_response = vec![0xa1, 0x61, b'v', 0x01];
    write_committed_snapshot(
        td.path(),
        &body,
        cached_response,
        unix_now().saturating_sub(61),
    );
    let (router, _window, person) = router_with_state(td.path());

    let (status, resp_bytes) = post_cbor(router, body, Some(&person)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
}

#[tokio::test]
async fn happy_path_returns_201_with_cursor() {
    let td = tempfile::tempdir().unwrap();
    let (router, _window, person) = router_with_state(td.path());
    let body = build_signed_request_bytes(td.path()).await;
    let (status, resp_bytes) = post_cbor(router, body, Some(&person)).await;
    assert_eq!(status, StatusCode::CREATED);
    let parsed: JoinRequestAccepted =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.version, 1);
    assert!(parsed.owner_event_cursor >= 1);
    assert!(parsed.expiry > 0);
}

#[tokio::test]
async fn malformed_cbor_returns_generic_401() {
    let td = tempfile::tempdir().unwrap();
    let (router, _, person) = router_with_state(td.path());
    let (status, resp_bytes) = post_cbor(router, b"not cbor".to_vec(), Some(&person)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.error, "unauthenticated");
}

#[tokio::test]
async fn tampered_signature_returns_generic_401() {
    let td = tempfile::tempdir().unwrap();
    let (router, _, person) = router_with_state(td.path());
    let mut body = build_signed_request_bytes(td.path()).await;
    // Flip a byte in the middle of the CBOR — most likely lands inside
    // the signature or a length-prefixed field, breaking either the
    // shape decode or the signature verify.
    let mid = body.len() / 2;
    body[mid] ^= 0x80;
    let (status, resp_bytes) = post_cbor(router, body, Some(&person)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
}

#[tokio::test]
async fn idempotent_restage_returns_same_cursor() {
    let td = tempfile::tempdir().unwrap();
    let (router, _, person) = router_with_state(td.path());
    let body = build_signed_request_bytes(td.path()).await;

    let (s1, b1) = post_cbor(router.clone(), body.clone(), Some(&person)).await;
    assert_eq!(s1, StatusCode::CREATED);
    let p1: JoinRequestAccepted = household_rs::cbor::from_canonical_slice(&b1).unwrap();

    let (s2, b2) = post_cbor(router, body, Some(&person)).await;
    assert_eq!(s2, StatusCode::CREATED);
    let p2: JoinRequestAccepted = household_rs::cbor::from_canonical_slice(&b2).unwrap();

    assert_eq!(p1.owner_event_cursor, p2.owner_event_cursor);
    assert_eq!(p1.expiry, p2.expiry);
}

#[tokio::test]
async fn second_concurrent_ceremony_returns_generic_401() {
    let td = tempfile::tempdir().unwrap();
    let (router, _, person) = router_with_state(td.path());
    let body1 = build_signed_request_bytes(td.path()).await;
    let body2 = build_signed_request_bytes(td.path()).await; // different candidate

    let (s1, _) = post_cbor(router.clone(), body1, Some(&person)).await;
    assert_eq!(s1, StatusCode::CREATED);

    let (s2, b2) = post_cbor(router, body2, Some(&person)).await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&b2).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
}

#[tokio::test]
async fn missing_pop_returns_generic_401() {
    let td = tempfile::tempdir().unwrap();
    let (router, _, _person) = router_with_state(td.path());
    let body = build_signed_request_bytes(td.path()).await;
    let (status, resp_bytes) = post_cbor(router, body, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
}

#[tokio::test]
async fn missing_owner_auth_returns_generic_401() {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    // No owner_auth → request must be rejected.
    let household = HouseholdState::loaded(Arc::clone(&identity));
    let window = Arc::new(PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap());
    let broadcaster = OwnerEventsBroadcaster::new();
    let event_log =
        OwnerEventLog::open_with_broadcaster(td.path().to_path_buf(), broadcaster.clone()).unwrap();
    let state = PairMachineRouterState {
        window,
        household,
        event_log,
        event_broadcaster: broadcaster,
        state_dir: td.path().to_path_buf(),
    };
    let router = Router::new()
        .route(
            JOIN_REQUEST_PATH,
            post(handlers_pair_machine::founder_join_request_handler),
        )
        .with_state(state);

    let body = build_signed_request_bytes(td.path()).await;
    let person = P256Keypair::generate();
    let (status, resp_bytes) = post_cbor(router, body, Some(&person)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
}
