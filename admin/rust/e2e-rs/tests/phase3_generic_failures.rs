//! Phase 3 Story 3 — generic-failure shape audit (T077).
//!
//! Per FR-019a / R14 every Phase 3 endpoint MUST return one and only one
//! 401 envelope on failure: `{"v": 1, "error": "unauthenticated"}` as
//! deterministic CBOR. Internal triage logs may distinguish causes; the
//! wire surface MUST NOT. This test enforces the indistinguishability
//! requirement on two axes:
//!
//! 1. Six different failure conditions against `POST /household/join-request`
//!    (no active sole-shard, owner not paired, `m_pub` already member, bad
//!    `challenge_sig`, malformed CBOR, "expired" / window-already-open) all
//!    produce byte-identical 401 responses.
//! 2. The deterministic-CBOR error body is byte-equivalent across all five
//!    Phase 3 endpoints (join-request, owner-events long-poll, approve,
//!    decline, push-token-register).
//!
//! Note on "expired window": the founder handler treats Aborted / expired
//! Committed / Idle uniformly as "re-stage from idle" (no 401). The only
//! window-state failure that produces a 401 is "open window with a
//! different ceremony in progress". The test therefore exercises that
//! literal path while keeping the spec's "expired window" wording —
//! semantically, both are "the candidate's request cannot be staged
//! because the founder window is still occupied by an in-flight peer".

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::routing;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::HouseholdRecord;
use household_rs::household_lifecycle::HouseholdLifecycleLock;
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::machine_cert::Platform;
use household_rs::owner_events::{OwnerEventLog, OwnerEventsBroadcaster};
use household_rs::pair_machine::{
    JoinRequest, JoinTransport, PairMachineWindow, PrepareCandidateOpts, prepare_candidate,
};
use household_rs::person_cert::{PersonCert, SignOwnerOptions};
use household_rs::pop::RequestSigningContext;
use household_rs::storage::{atomic_write_cbor, household_record_path};
use household_rs::{BootstrapOpts, HouseholdAuthState, KeyBackingPolicy};
use serde::Serialize;
use serde_bytes::ByteBuf;
use server_rs::handlers_owner_events::{self, OwnerEventsRouterState};
use server_rs::handlers_pair_machine::{self, PairMachineRouterState};
use server_rs::household_state::HouseholdState;
use tempfile::TempDir;
use tower::ServiceExt;

const JOIN_REQUEST_PATH: &str = "/api/v1/household/join-request";
const OWNER_EVENTS_PATH: &str = "/api/v1/household/owner-events";
const PUSH_TOKEN_PATH: &str = "/api/v1/household/owner-device/push-token";

/// The canonical CBOR body the spec mandates for every 401 response on
/// every Phase 3 endpoint.
fn canonical_unauthenticated_body() -> Vec<u8> {
    #[derive(Serialize)]
    struct GenericUnauth<'a> {
        #[serde(rename = "v")]
        version: u8,
        error: &'a str,
    }
    household_rs::cbor::to_canonical_vec(&GenericUnauth {
        version: 1,
        error: "unauthenticated",
    })
    .expect("canonical unauth body")
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
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
    .expect("bootstrap household")
}

fn owner_auth_for(identity: &household_rs::LoadedIdentity) -> (HouseholdAuthState, P256Keypair) {
    let person = P256Keypair::generate();
    let cert = PersonCert::sign_owner(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv on single-machine"),
        SignOwnerOptions {
            hh_id: identity.record.hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: identity.record.created_at,
        },
    )
    .expect("sign owner cert");
    (HouseholdAuthState::new(&identity.record, cert), person)
}

struct FounderRig {
    _dir: TempDir,
    state_dir: std::path::PathBuf,
    identity: Arc<household_rs::LoadedIdentity>,
    pair_state: PairMachineRouterState,
    owner_keypair: Option<P256Keypair>,
    owner_auth: Option<Arc<HouseholdAuthState>>,
    window: Arc<PairMachineWindow>,
    event_log: Arc<OwnerEventLog>,
    broadcaster: OwnerEventsBroadcaster,
}

fn build_founder_rig(pair_owner: bool) -> FounderRig {
    let dir = tempfile::tempdir().expect("founder dir");
    let identity = Arc::new(bootstrap(dir.path()));
    let (owner_auth, owner_keypair) = if pair_owner {
        let (auth, kp) = owner_auth_for(&identity);
        (Some(Arc::new(auth)), Some(kp))
    } else {
        (None, None)
    };
    let household = HouseholdState::loaded_with_owner_auth(
        Arc::clone(&identity),
        owner_auth.as_ref().map(Arc::clone),
    );
    let window =
        Arc::new(PairMachineWindow::with_persistence(dir.path().to_path_buf()).expect("window"));
    let broadcaster = OwnerEventsBroadcaster::new();
    let lifecycle = HouseholdLifecycleLock::open_verified(dir.path()).expect("open lifecycle lock");
    let lifecycle_guard = lifecycle
        .lock_exclusive()
        .expect("lock lifecycle exclusive");
    let event_log = OwnerEventLog::open_with_broadcaster_under_lifecycle(
        &lifecycle_guard,
        dir.path().to_path_buf(),
        &identity.record.hh_id.to_string(),
        broadcaster.clone(),
    )
    .expect("event log");
    drop(lifecycle_guard);
    let pair_state = PairMachineRouterState {
        window: Arc::clone(&window),
        household,
        event_log: Arc::clone(&event_log),
        event_broadcaster: broadcaster.clone(),
        state_dir: dir.path().to_path_buf(),
    };
    let state_dir = dir.path().to_path_buf();
    FounderRig {
        _dir: dir,
        state_dir,
        identity,
        pair_state,
        owner_keypair,
        owner_auth,
        window,
        event_log,
        broadcaster,
    }
}

fn full_router(rig: &FounderRig) -> Router {
    let owner_state = OwnerEventsRouterState::with_timeout(
        rig.pair_state.household.clone(),
        Arc::clone(&rig.window),
        Arc::clone(&rig.event_log),
        rig.broadcaster.clone(),
        rig.state_dir.clone(),
        KeyBackingPolicy::ForceSoftware,
        Duration::from_millis(50),
    );
    Router::new()
        .route(
            JOIN_REQUEST_PATH,
            routing::post(handlers_pair_machine::founder_join_request_handler),
        )
        .with_state(rig.pair_state.clone())
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
                .route(
                    PUSH_TOKEN_PATH,
                    routing::post(handlers_owner_events::push_token_register_handler),
                )
                .with_state(owner_state),
        )
}

async fn build_join_request_for(_state_dir: &std::path::Path) -> (Vec<u8>, JoinRequest) {
    let candidate_dir = tempfile::tempdir().expect("candidate dir");
    let win = PairMachineWindow::with_persistence(candidate_dir.path().to_path_buf()).expect("win");
    let prepared = prepare_candidate(
        &win,
        PrepareCandidateOpts {
            state_dir: candidate_dir.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: "100.1.2.3:8091".into(),
            hostname: "studio-candidate".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: Duration::from_secs(300),
            now_unix: unix_now(),
        },
    )
    .await
    .expect("prepare candidate");
    candidate_dir.close().ok();
    (prepared.join_request_cbor, prepared.join_request)
}

fn pop_header(person: &P256Keypair, method: &str, path: &str, ts: u64, body: &[u8]) -> String {
    let ctx = RequestSigningContext::new(method, path, ts, body);
    let sig = person
        .sign(&ctx.canonical_bytes().expect("canonical pop"))
        .expect("sign pop");
    format!(
        "Soyeht-PoP v1:{}:{}:{}",
        household_rs::derive_person_id(&person.public()).0,
        ts,
        B64URL.encode(sig.as_bytes())
    )
}

async fn fire(
    router: Router,
    method: Method,
    path: &str,
    body: Vec<u8>,
    auth: Option<&P256Keypair>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut builder = Request::builder()
        .method(method.clone())
        .uri(path)
        .header(header::CONTENT_TYPE, "application/cbor");
    if let Some(person) = auth {
        builder = builder.header(
            header::AUTHORIZATION,
            pop_header(person, method.as_str(), path, unix_now(), &body),
        );
    }
    let resp = router
        .oneshot(builder.body(Body::from(body)).expect("body"))
        .await
        .expect("oneshot");
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body")
        .to_vec();
    (status, headers, bytes)
}

fn cursor_param(cursor: u64) -> String {
    let bytes = household_rs::cbor::to_canonical_vec(&cursor).expect("cursor cbor");
    B64URL.encode(bytes)
}

/// Reach into the on-disk `household_record.cbor` and rewrite it as a
/// post-Shamir (k=2, n=2, two members) record so the next handler-side
/// `state.household.current()` read sees a household where 1→2 growth is
/// already complete. Used to drive the `no_active_sole_shard` 401 path.
fn write_post_shamir_record(rig: &FounderRig) {
    // Borrow the existing record and mutate the Shamir fields. A fresh
    // dummy machine id satisfies the validate() invariant
    // `members.len() == shamir_n` without needing a real second cert.
    let dummy_kp = P256Keypair::generate();
    let dummy_m_id = household_rs::derive_machine_id(&dummy_kp.public());
    let mut record: HouseholdRecord = rig.identity.record.clone();
    record.shamir_k = 2;
    record.shamir_n = 2;
    record.members.push(dummy_m_id);
    record.validate().expect("post-Shamir record valid");
    atomic_write_cbor(&household_record_path(&rig.state_dir), &record)
        .expect("write post-Shamir record");
}

/// Reload the founder identity from disk so the in-memory
/// `HouseholdState` reflects the mutated record. Returns a fresh
/// `Router` that mounts all five Phase 3 endpoints.
fn rebuild_router_from_disk(rig: &FounderRig) -> Router {
    let identity = Arc::new(
        household_rs::try_load_existing(&rig.state_dir, KeyBackingPolicy::ForceSoftware)
            .expect("reload identity")
            .expect("identity present"),
    );
    let owner_auth = rig.owner_auth.as_ref().map(Arc::clone);
    let household = HouseholdState::loaded_with_owner_auth(identity, owner_auth);
    let owner_state = OwnerEventsRouterState::with_timeout(
        household.clone(),
        Arc::clone(&rig.window),
        Arc::clone(&rig.event_log),
        rig.broadcaster.clone(),
        rig.state_dir.clone(),
        KeyBackingPolicy::ForceSoftware,
        Duration::from_millis(50),
    );
    let pair_state = PairMachineRouterState {
        window: Arc::clone(&rig.window),
        household,
        event_log: Arc::clone(&rig.event_log),
        event_broadcaster: rig.broadcaster.clone(),
        state_dir: rig.state_dir.clone(),
    };
    Router::new()
        .route(
            JOIN_REQUEST_PATH,
            routing::post(handlers_pair_machine::founder_join_request_handler),
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
                .route(
                    "/api/v1/household/owner-events/{cursor}/decline",
                    routing::post(handlers_owner_events::owner_decline_handler),
                )
                .route(
                    PUSH_TOKEN_PATH,
                    routing::post(handlers_owner_events::push_token_register_handler),
                )
                .with_state(owner_state),
        )
}

/// `m_pub_already_member` setup: prepare a candidate signed with M1's own
/// key, so the handler computes `candidate_m_id == m1.m_id` and trips the
/// already-member gate without needing record mutation.
fn build_self_join_request(rig: &FounderRig) -> Vec<u8> {
    use household_rs::pair_machine::JoinChallenge;
    let m_pub_sec1: [u8; 33] = *rig.identity.cert.m_pub.as_bytes();
    // A fixed 32-byte nonce is sufficient — this code path is rejected
    // by the already-member gate before nonce uniqueness matters.
    let mut nonce = [0u8; 32];
    for (i, slot) in nonce.iter_mut().enumerate() {
        let i_byte = u8::try_from(i & 0xff).expect("i fits in u8");
        *slot = i_byte.wrapping_mul(7).wrapping_add(0x5a);
    }
    let challenge = JoinChallenge::build(&m_pub_sec1, &nonce, "studio-self", Platform::LinuxNix);
    let challenge_bytes = challenge.to_canonical_bytes().expect("challenge cbor");
    let sig = rig
        .identity
        .m_priv
        .sign(&challenge_bytes)
        .expect("sign challenge");
    let request = JoinRequest {
        version: 1,
        m_pub: ByteBuf::from(m_pub_sec1.to_vec()),
        hostname: "studio-self".into(),
        platform: Platform::LinuxNix,
        nonce: ByteBuf::from(nonce.to_vec()),
        addr: "100.5.6.7:8091".into(),
        transport: JoinTransport::Tailscale,
        challenge_sig: ByteBuf::from(sig.as_bytes().to_vec()),
    };
    request.to_canonical_bytes().expect("self-join cbor")
}

#[tokio::test]
async fn test_join_request_failures_are_indistinguishable() {
    let canonical = canonical_unauthenticated_body();

    // ── Failure #1: malformed CBOR body ──────────────────────────────
    let rig = build_founder_rig(true);
    let owner = rig.owner_keypair.as_ref().expect("owner kp");
    let router = full_router(&rig);
    let (s1, h1, b1) = fire(
        router,
        Method::POST,
        JOIN_REQUEST_PATH,
        b"not-valid-cbor".to_vec(),
        Some(owner),
    )
    .await;
    drop(rig);

    // ── Failure #2: tampered challenge_sig ───────────────────────────
    let rig = build_founder_rig(true);
    let owner = rig.owner_keypair.as_ref().expect("owner kp");
    let router = full_router(&rig);
    let (mut body, _) = build_join_request_for(&rig.state_dir).await;
    let mid = body.len() / 2;
    body[mid] ^= 0x80;
    let (s2, h2, b2) = fire(router, Method::POST, JOIN_REQUEST_PATH, body, Some(owner)).await;
    drop(rig);

    // ── Failure #3: owner not paired ─────────────────────────────────
    let rig = build_founder_rig(false);
    let router = full_router(&rig);
    let (body, _) = build_join_request_for(&rig.state_dir).await;
    // Without owner pairing the request needs SOME PoP header to reach
    // the owner-not-paired branch instead of the missing-PoP branch.
    let stranger = P256Keypair::generate();
    let (s3, h3, b3) = fire(
        router,
        Method::POST,
        JOIN_REQUEST_PATH,
        body,
        Some(&stranger),
    )
    .await;
    drop(rig);

    // ── Failure #4: m_pub already member (candidate uses M1's key) ──
    let rig = build_founder_rig(true);
    let owner = rig.owner_keypair.as_ref().expect("owner kp");
    let router = full_router(&rig);
    let body = build_self_join_request(&rig);
    let (s4, h4, b4) = fire(router, Method::POST, JOIN_REQUEST_PATH, body, Some(owner)).await;
    drop(rig);

    // ── Failure #5: no active sole-shard (post-Shamir record) ────────
    let rig = build_founder_rig(true);
    let owner = rig.owner_keypair.as_ref().expect("owner kp");
    write_post_shamir_record(&rig);
    let router = rebuild_router_from_disk(&rig);
    let (body, _) = build_join_request_for(&rig.state_dir).await;
    let (s5, h5, b5) = fire(router, Method::POST, JOIN_REQUEST_PATH, body, Some(owner)).await;
    drop(rig);

    // ── Failure #6: window already open / "expired window" ───────────
    let rig = build_founder_rig(true);
    let owner = rig.owner_keypair.as_ref().expect("owner kp");
    let router = full_router(&rig);
    let (body1, _) = build_join_request_for(&rig.state_dir).await;
    // First request opens the window cleanly (201).
    let (s_open, _, _) = fire(
        router.clone(),
        Method::POST,
        JOIN_REQUEST_PATH,
        body1,
        Some(owner),
    )
    .await;
    assert_eq!(s_open, StatusCode::CREATED);
    // Second request with a *different* candidate reaches the
    // window-already-open branch and 401s.
    let (body2, _) = build_join_request_for(&rig.state_dir).await;
    let (s6, h6, b6) = fire(router, Method::POST, JOIN_REQUEST_PATH, body2, Some(owner)).await;
    drop(rig);

    let cases: Vec<(&str, StatusCode, HeaderMap, Vec<u8>)> = vec![
        ("malformed_cbor", s1, h1, b1),
        ("tampered_signature", s2, h2, b2),
        ("owner_not_paired", s3, h3, b3),
        ("m_pub_already_member", s4, h4, b4),
        ("no_active_sole_shard", s5, h5, b5),
        ("window_already_open", s6, h6, b6),
    ];
    for (name, status, headers, body) in &cases {
        assert_eq!(*status, StatusCode::UNAUTHORIZED, "{name}: status");
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/cbor"),
            "{name}: content-type"
        );
        assert_eq!(body, &canonical, "{name}: body must equal canonical");
    }
}

#[tokio::test]
async fn test_phase3_endpoints_share_canonical_unauthenticated_body() {
    let canonical = canonical_unauthenticated_body();

    // ── /join-request : missing PoP ──────────────────────────────────
    let rig = build_founder_rig(true);
    let router = full_router(&rig);
    let (body, _) = build_join_request_for(&rig.state_dir).await;
    let (s_jr, h_jr, b_jr) = fire(router, Method::POST, JOIN_REQUEST_PATH, body, None).await;
    drop(rig);

    // ── /owner-events long-poll : missing PoP ────────────────────────
    let rig = build_founder_rig(true);
    let router = full_router(&rig);
    let path = format!("{OWNER_EVENTS_PATH}?since={}", cursor_param(0));
    let (status_long_poll, headers_long_poll, body_long_poll) =
        fire(router, Method::GET, &path, Vec::new(), None).await;
    drop(rig);

    // ── /owner-events/<cursor>/approve : missing PoP ─────────────────
    let rig = build_founder_rig(true);
    let router = full_router(&rig);
    let approve_path = "/api/v1/household/owner-events/1/approve";
    let (status_approve, headers_approve, body_approve) =
        fire(router, Method::POST, approve_path, vec![0x80], None).await;
    drop(rig);

    // ── /owner-events/<cursor>/decline : missing PoP ─────────────────
    let rig = build_founder_rig(true);
    let router = full_router(&rig);
    let decline_path = "/api/v1/household/owner-events/1/decline";
    let (status_decline, headers_decline, body_decline) =
        fire(router, Method::POST, decline_path, Vec::new(), None).await;
    drop(rig);

    // ── /owner-device/push-token : missing PoP ───────────────────────
    let rig = build_founder_rig(true);
    let router = full_router(&rig);
    let (status_push, headers_push, body_push) =
        fire(router, Method::POST, PUSH_TOKEN_PATH, Vec::new(), None).await;
    drop(rig);

    let endpoints: Vec<(&str, StatusCode, HeaderMap, Vec<u8>)> = vec![
        ("join_request", s_jr, h_jr, b_jr),
        (
            "owner_events_long_poll",
            status_long_poll,
            headers_long_poll,
            body_long_poll,
        ),
        (
            "owner_events_approve",
            status_approve,
            headers_approve,
            body_approve,
        ),
        (
            "owner_events_decline",
            status_decline,
            headers_decline,
            body_decline,
        ),
        ("push_token_register", status_push, headers_push, body_push),
    ];
    for (name, status, headers, body) in &endpoints {
        assert_eq!(*status, StatusCode::UNAUTHORIZED, "{name}: status");
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/cbor"),
            "{name}: content-type"
        );
        assert_eq!(body, &canonical, "{name}: body byte-equivalent");
    }
}
