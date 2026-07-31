//! B0a contract tests for `GET /api/v1/household/roster/currency/{m_id}`.
//!
//! Two layers, deliberately:
//!
//! 1. A **wire table** over all nine `PublicCurrencyOutcome` variants. Every
//!    outcome is asserted for its literal, its exact response key set and its
//!    canonical encoding. This is the layer that would catch a vocabulary drift
//!    or a stray key, and it covers `active`/`revoked`/`not_listed` plus every
//!    `unavailable_*` without needing owner-signed checkpoints.
//! 2. **HTTP handler** tests over a real bootstrapped household with a real
//!    owner `PoP`, covering the auth gate, request-shape rejections, the
//!    not-initialized store, and one genuine end-to-end store outcome
//!    (`unavailable_no_genesis` after `provision_no_genesis`).
//!
//! Reaching `active`/`revoked` through the full stack needs owner-signed
//! checkpoints admitted into the store; the rig for that is `#[cfg(test)]`
//! inside `household-rs` and is not reachable from an integration test. Those
//! two outcomes are therefore covered at the encoding layer here, and their
//! end-to-end admission path belongs with the store's own rig.
//!
//! Key-set assertions are structural rather than string comparisons: each
//! response is decoded into an echo struct that is `deny_unknown_fields` with
//! every field required, so an extra key fails to decode and a missing key
//! fails to decode. Re-encoding the echo and byte-comparing against the served
//! body then proves the response was canonical CBOR — the same fixed point the
//! iOS client requires before it will accept a response.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use axum::{
    Router,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::ids::{HouseholdId, MachineId, derive_machine_id};
use household_rs::keys::{IdentityKey, P256Keypair, P256Signature};
use household_rs::machine_roster_authority::{
    MachineRosterMemberV1, MachineRosterRevocationV1, RevocationCascade, RevocationReason,
};
use household_rs::machine_roster_evidence::{
    RosterEvidenceOutcome, RosterEvidenceSnapshot, build_signed_evidence, signing_preimage,
};
use household_rs::machine_roster_store::{MachineRosterCoordinator, PublicCurrencyOutcome};
use household_rs::person_cert::{SignOwnerOptions, VerifiedOwnerProvenance, derive_person_id};
use household_rs::pop::RequestSigningContext;
use household_rs::{BootstrapOpts, HouseholdAuthState, KeyBackingPolicy, PersonCert};
use serde::{Deserialize, Serialize};
use server_rs::handlers_household_roster::{
    self, CONTENT_TYPE, CURRENCY_PATH, EVIDENCE_PATH, RosterRouterState, encode_currency_body,
    encode_evidence_body,
};
use server_rs::household_state::HouseholdState;
use tower::ServiceExt;

// ─── echo structs (exact key sets by construction) ──────────────────────────

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveEcho {
    v: u8,
    outcome: String,
    member: MachineRosterMemberV1,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokedEcho {
    v: u8,
    outcome: String,
    tombstone: MachineRosterRevocationV1,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlainEcho {
    v: u8,
    outcome: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorEcho {
    v: u8,
    error: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EvidenceRequestEcho {
    client_nonce: serde_bytes::ByteBuf,
    v: u8,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SnapshotBodyEcho {
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_checkpoint: Option<serde_bytes::ByteBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conflicting_checkpoint: Option<serde_bytes::ByteBuf>,
    floor_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    genesis_checkpoint: Option<serde_bytes::ByteBuf>,
    hh_id: HouseholdId,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_checkpoint: Option<serde_bytes::ByteBuf>,
    state_kind: u8,
    v: u8,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceAvailableEcho {
    client_nonce: serde_bytes::ByteBuf,
    full_snapshot_digest: serde_bytes::ByteBuf,
    outcome: String,
    signature: serde_bytes::ByteBuf,
    signer_m_id: String,
    signer_machine_cert: serde_bytes::ByteBuf,
    signer_machine_cert_fingerprint: serde_bytes::ByteBuf,
    snapshot_body: SnapshotBodyEcho,
    state_evidence_digest: serde_bytes::ByteBuf,
    v: u8,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceUnavailableEcho {
    client_nonce: serde_bytes::ByteBuf,
    outcome: String,
    signature: serde_bytes::ByteBuf,
    signer_m_id: String,
    signer_machine_cert: serde_bytes::ByteBuf,
    signer_machine_cert_fingerprint: serde_bytes::ByteBuf,
    v: u8,
}

/// Decode `bytes` into `T`, re-encode canonically and require the exact same
/// bytes back. Fails if the body carries an unexpected key, is missing one, or
/// was not canonically encoded.
fn assert_exact_and_canonical<T>(bytes: &[u8]) -> T
where
    T: Serialize + serde::de::DeserializeOwned,
{
    let decoded: T = household_rs::cbor::from_canonical_slice(bytes)
        .unwrap_or_else(|e| panic!("body does not match the expected closed key set: {e}"));
    let re_encoded = household_rs::cbor::to_canonical_vec(&decoded).expect("re-encode");
    assert_eq!(
        re_encoded, bytes,
        "response body is not canonical CBOR (decode → re-encode changed bytes)"
    );
    decoded
}

// ─── helpers ────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sample_hh_id() -> HouseholdId {
    HouseholdId::parse("hh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .expect("well-formed household id")
}

fn sample_member() -> MachineRosterMemberV1 {
    let m_pub = P256Keypair::generate().public();
    MachineRosterMemberV1 {
        m_id: derive_machine_id(&m_pub),
        m_pub,
        machine_cert: vec![0xA1, 0xA2, 0xA3],
        machine_cert_fingerprint: [0x11; 32],
    }
}

fn sample_tombstone() -> MachineRosterRevocationV1 {
    let m_pub = P256Keypair::generate().public();
    let owner_pub = P256Keypair::generate().public();
    MachineRosterRevocationV1 {
        v: 1,
        kind: "household-machine-roster-revocation/v1".to_string(),
        hh_id: sample_hh_id(),
        epoch: [0x22; 32],
        sequence: 1,
        prev_event_hash: [0; 32],
        m_id: derive_machine_id(&m_pub),
        m_pub,
        machine_cert_fingerprint: [0x33; 32],
        revoked_at: 1_700_000_000,
        reason: RevocationReason::Retired,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: derive_person_id(&owner_pub),
        owner_cert_fingerprint: [0x44; 32],
        owner_person_cert: vec![0xB1, 0xB2],
        signature: P256Signature::from_bytes(&[0x55; 64]).expect("64-byte signature"),
    }
}

struct Fixture {
    app: Router,
    owner: P256Keypair,
    state_dir: tempfile::TempDir,
    identity: household_rs::LoadedIdentity,
    auth: Arc<HouseholdAuthState>,
}

fn fixture() -> Fixture {
    let state_dir = tempfile::tempdir().expect("household state");
    let identity = household_rs::bootstrap_or_load(
        state_dir.path(),
        BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some("mac-alpha".into()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .expect("bootstrap");
    let owner = P256Keypair::generate();
    // Strong tier with verified provenance, not a bare `sign_owner`: the roster
    // coordinator derives its owner binding through the roster authority, which
    // accepts only a strong-tier owner cert carrying one of the four verified
    // provenances. A basic-tier owner is rejected as
    // `invalid_current_owner_authority` before the store is ever read.
    let cert = PersonCert::sign_owner_with_verified_provenance(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv present in single-machine household"),
        SignOwnerOptions {
            hh_id: identity.record.hh_id.clone(),
            p_pub: owner.public(),
            display_name: "Owner".into(),
            issued_at: identity.record.created_at,
        },
        VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .expect("owner cert");
    let auth = Arc::new(HouseholdAuthState::new(&identity.record, cert));

    let household = HouseholdState::loaded_with_owner_auth(
        Arc::new(clone_identity(&identity)),
        Some(Arc::clone(&auth)),
    );
    let app = Router::new()
        .route(CURRENCY_PATH, get(handlers_household_roster::currency))
        .route(EVIDENCE_PATH, post(handlers_household_roster::evidence))
        .with_state(RosterRouterState {
            household,
            state_dir: state_dir.path().to_path_buf(),
        });

    Fixture {
        app,
        owner,
        state_dir,
        identity,
        auth,
    }
}

/// `LoadedIdentity` is not `Clone` (it owns key material), so rebuild it from
/// the software secrets the same way the existing household tests do.
fn clone_identity(identity: &household_rs::LoadedIdentity) -> household_rs::LoadedIdentity {
    household_rs::LoadedIdentity {
        record: identity.record.clone(),
        cert: identity.cert.clone(),
        hh_priv: Some(Box::new(
            P256Keypair::from_secret_scalar(
                identity
                    .hh_priv
                    .as_ref()
                    .and_then(|k| k.as_software_secret())
                    .expect("software hh_priv"),
            )
            .unwrap(),
        )),
        m_priv: Box::new(
            P256Keypair::from_secret_scalar(identity.m_priv.as_software_secret().unwrap()).unwrap(),
        ),
        backing: identity.backing,
    }
}

fn pop_header(owner: &P256Keypair, path: &str, body: &[u8]) -> String {
    pop_header_for_method(owner, "GET", path, body)
}

fn pop_header_for_method(owner: &P256Keypair, method: &str, path: &str, body: &[u8]) -> String {
    let ts = unix_now();
    let ctx = RequestSigningContext::new(method, path, ts, body);
    let sig = owner.sign(&ctx.canonical_bytes().unwrap()).unwrap();
    format!(
        "Soyeht-PoP v1:{}:{}:{}",
        derive_person_id(&owner.public()).0,
        ts,
        B64URL.encode(sig.as_bytes())
    )
}

fn evidence_request(nonce: [u8; 32]) -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&EvidenceRequestEcho {
        client_nonce: serde_bytes::ByteBuf::from(nonce.to_vec()),
        v: 1,
    })
    .expect("canonical evidence request")
}

/// The general POST. `content_type: None` omits the header entirely, which is a
/// distinct case from sending a wrong one — both must be 415.
async fn evidence_post(
    app: &Router,
    pop: &str,
    content_type: Option<&str>,
    body: Vec<u8>,
    device_id: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(EVIDENCE_PATH)
        .header(header::AUTHORIZATION, pop);
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(device_id) = device_id {
        builder = builder.header("soyeht-device-id", device_id);
    }
    app.clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

/// Owner-signed POST with the exact media type — the happy shape.
async fn evidence_call(
    app: &Router,
    signer: &P256Keypair,
    body: Vec<u8>,
    device_id: Option<&str>,
) -> axum::response::Response {
    let pop = pop_header_for_method(signer, "POST", EVIDENCE_PATH, &body);
    evidence_post(app, &pop, Some(CONTENT_TYPE), body, device_id).await
}

fn currency_path(m_id: &str) -> String {
    format!("/api/v1/household/roster/currency/{m_id}")
}

/// A well-formed machine id that is not a member of the household.
fn stranger_m_id() -> MachineId {
    derive_machine_id(&P256Keypair::generate().public())
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body")
        .to_vec()
}

fn assert_cbor_no_store(resp: &axum::response::Response) {
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE),
        Some(&HeaderValue::from_static(CONTENT_TYPE))
    );
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
}

// ─── 1. wire table over all nine outcomes ───────────────────────────────────

#[test]
fn every_outcome_has_a_unique_literal() {
    let cases: Vec<(PublicCurrencyOutcome, &str)> = vec![
        (
            PublicCurrencyOutcome::Active {
                member: Box::new(sample_member()),
            },
            "active",
        ),
        (
            PublicCurrencyOutcome::Revoked {
                tombstone: Box::new(sample_tombstone()),
            },
            "revoked",
        ),
        (PublicCurrencyOutcome::NotListed, "not_listed"),
        (
            PublicCurrencyOutcome::UnavailableNoGenesis,
            "unavailable_no_genesis",
        ),
        (
            PublicCurrencyOutcome::UnavailableCheckpointStale,
            "unavailable_checkpoint_stale",
        ),
        (
            PublicCurrencyOutcome::UnavailableCheckpointForkConflict,
            "unavailable_checkpoint_fork_conflict",
        ),
        (
            PublicCurrencyOutcome::UnavailableEventForkConflict,
            "unavailable_event_fork_conflict",
        ),
        (
            PublicCurrencyOutcome::UnavailableClockState,
            "unavailable_clock_state",
        ),
        (
            PublicCurrencyOutcome::UnavailableOwnerAuthority,
            "unavailable_owner_authority",
        ),
    ];

    // Nine variants, nine rows: a new variant without a row fails here.
    assert_eq!(cases.len(), 9, "one row per PublicCurrencyOutcome variant");

    let mut seen = std::collections::BTreeSet::new();
    for (outcome, expected) in &cases {
        assert_eq!(outcome.wire_str(), *expected, "literal for {outcome:?}");
        assert!(seen.insert(*expected), "literal {expected} is not unique");
    }
}

/// Every outcome that is neither `active` nor `revoked` serves exactly
/// `{v, outcome}` — no member, no tombstone, nothing to mistake for a fact
/// about a machine.
#[test]
fn plain_outcomes_serve_only_v_and_outcome() {
    let plain = [
        (PublicCurrencyOutcome::NotListed, "not_listed"),
        (
            PublicCurrencyOutcome::UnavailableNoGenesis,
            "unavailable_no_genesis",
        ),
        (
            PublicCurrencyOutcome::UnavailableCheckpointStale,
            "unavailable_checkpoint_stale",
        ),
        (
            PublicCurrencyOutcome::UnavailableCheckpointForkConflict,
            "unavailable_checkpoint_fork_conflict",
        ),
        (
            PublicCurrencyOutcome::UnavailableEventForkConflict,
            "unavailable_event_fork_conflict",
        ),
        (
            PublicCurrencyOutcome::UnavailableClockState,
            "unavailable_clock_state",
        ),
        (
            PublicCurrencyOutcome::UnavailableOwnerAuthority,
            "unavailable_owner_authority",
        ),
    ];
    // `not_listed` plus all six `unavailable_*` the endpoint can serve.
    assert_eq!(plain.len(), 7);

    for (outcome, expected) in &plain {
        let body = encode_currency_body(outcome).expect("encode");
        let echo: PlainEcho = assert_exact_and_canonical(&body);
        assert_eq!(echo.v, 1);
        assert_eq!(echo.outcome, *expected);
    }
}

#[test]
fn active_serves_the_member_unchanged() {
    let member = sample_member();
    let outcome = PublicCurrencyOutcome::Active {
        member: Box::new(member.clone()),
    };
    let body = encode_currency_body(&outcome).expect("encode");
    let echo: ActiveEcho = assert_exact_and_canonical(&body);
    assert_eq!(echo.v, 1);
    assert_eq!(echo.outcome, "active");
    // Round-trips to exactly the member the authority produced: the client
    // re-derives the machine id from `m_pub` and checks the cert fingerprint,
    // so no field may be dropped or rewritten in transit.
    assert_eq!(echo.member, member);
}

#[test]
fn revoked_serves_the_full_tombstone_unchanged() {
    let tombstone = sample_tombstone();
    let outcome = PublicCurrencyOutcome::Revoked {
        tombstone: Box::new(tombstone.clone()),
    };
    let body = encode_currency_body(&outcome).expect("encode");
    let echo: RevokedEcho = assert_exact_and_canonical(&body);
    assert_eq!(echo.v, 1);
    assert_eq!(echo.outcome, "revoked");
    // The client verifies the tombstone offline against the household root, so
    // `owner_person_cert` and `signature` must survive intact — a trimmed
    // tombstone is unverifiable and would have to be rejected on device.
    assert_eq!(echo.tombstone, tombstone);
    assert!(!echo.tombstone.owner_person_cert.is_empty());
}

// ─── 2. HTTP handler ────────────────────────────────────────────────────────

#[tokio::test]
async fn rejects_missing_authorization_with_unauthenticated_envelope() {
    let fx = fixture();
    let path = currency_path(stranger_m_id().0.as_str());
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_cbor_no_store(&resp);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.v, 1);
    assert_eq!(echo.error, "unauthenticated");
}

#[tokio::test]
async fn rejects_malformed_pop_with_unauthenticated_envelope() {
    let fx = fixture();
    let path = currency_path(stranger_m_id().0.as_str());
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&path)
                .header(header::AUTHORIZATION, "Soyeht-PoP garbage")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_cbor_no_store(&resp);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "unauthenticated");
}

/// A structurally valid `PoP` from a person who is not the household owner must
/// not pass the gate — the roster is owner-authed, not merely signed.
#[tokio::test]
async fn rejects_valid_pop_from_non_owner() {
    let fx = fixture();
    let stranger = P256Keypair::generate();
    let path = currency_path(stranger_m_id().0.as_str());
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&path)
                .header(header::AUTHORIZATION, pop_header(&stranger, &path, b""))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_cbor_no_store(&resp);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "unauthenticated");
}

#[tokio::test]
async fn rejects_malformed_machine_id() {
    let fx = fixture();
    // Right prefix, wrong length/alphabet → must never reach the store.
    let path = currency_path("m_not_a_valid_base32_machine_id");
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&path)
                .header(header::AUTHORIZATION, pop_header(&fx.owner, &path, b""))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_cbor_no_store(&resp);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "invalid_machine_id");
}

#[tokio::test]
async fn rejects_body_on_get_even_when_signed() {
    let fx = fixture();
    let path = currency_path(stranger_m_id().0.as_str());
    let payload = b"{}";
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&path)
                // Signed over the same body, so this is an authentic request
                // that is still refused on shape.
                .header(header::AUTHORIZATION, pop_header(&fx.owner, &path, payload))
                .body(Body::from(payload.as_slice()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_cbor_no_store(&resp);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "body_not_allowed");
}

/// Household is bootstrapped and the owner is authorized, but the roster store
/// was never provisioned: the endpoint must say so rather than inventing
/// `not_listed`, which the client would read as proven non-membership.
#[tokio::test]
async fn reports_not_initialized_before_provisioning() {
    let fx = fixture();
    let path = currency_path(stranger_m_id().0.as_str());
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&path)
                .header(header::AUTHORIZATION, pop_header(&fx.owner, &path, b""))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_cbor_no_store(&resp);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "not_initialized");
}

/// End-to-end through the real store: a provisioned but genesis-less roster
/// answers `unavailable_no_genesis` with a 200, because "no genesis yet" is a
/// legitimate roster state, not a transport failure.
#[tokio::test]
async fn serves_unavailable_no_genesis_from_a_provisioned_store() {
    let fx = fixture();
    let coordinator = MachineRosterCoordinator::from_validated_household(
        fx.state_dir.path(),
        &fx.identity.record,
        &fx.auth,
    )
    .expect("coordinator");
    coordinator.provision_no_genesis().expect("provision");

    let path = currency_path(stranger_m_id().0.as_str());
    let resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&path)
                .header(header::AUTHORIZATION, pop_header(&fx.owner, &path, b""))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_cbor_no_store(&resp);
    let echo: PlainEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.v, 1);
    assert_eq!(echo.outcome, "unavailable_no_genesis");
}

/// The focused handler fixture mounts the route directly. Pin the production
/// bootstrap merge separately so deleting the real mount cannot leave this
/// integration target green while the endpoint disappears from the server.
#[test]
fn production_bootstrap_mounts_the_roster_router() {
    let bootstrap = include_str!("../src/household_bootstrap.rs");
    assert_eq!(
        bootstrap.matches(".merge(roster_router)").count(),
        1,
        "the production household router must mount the roster router exactly once"
    );
}

/// Drop `//` line comments so a route named only in prose cannot satisfy a
/// source guard. Double-quoted strings are tracked, so a `//` inside a literal
/// is not mistaken for a comment. Block comments and raw strings are not
/// handled — `household_bootstrap.rs` contains neither, and the teeth below
/// come from the pinned `(path, method, handler)` triple rather than from this
/// normalization.
fn strip_line_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for line in source.lines() {
        let bytes = line.as_bytes();
        let mut in_string = false;
        let mut escaped = false;
        let mut cut = line.len();
        for (i, &c) in bytes.iter().enumerate() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if c == b'\\' {
                    escaped = true;
                } else if c == b'"' {
                    in_string = false;
                }
            } else if c == b'"' {
                in_string = true;
            } else if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
                cut = i;
                break;
            }
        }
        out.push_str(&line[..cut]);
        out.push('\n');
    }
    out
}

/// Remove every whitespace byte, so a needle matches regardless of how rustfmt
/// wraps the call across lines or indents it.
fn strip_whitespace(source: &str) -> String {
    source.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The evidence route must be mounted exactly once **and as POST**.
///
/// Counting a bare mention of `EVIDENCE_PATH` cannot see the method: flipping
/// `axum::routing::post` to `get` leaves that count at 1 while the endpoint
/// stops answering the only verb the contract defines. So the pinned needle is
/// the whole `(path, method, handler)` triple, over comment-stripped and
/// whitespace-stripped source. The trailing comma is deliberately outside the
/// needle so a one-line reflow still matches.
#[test]
fn production_bootstrap_mounts_the_evidence_route() {
    let bootstrap = strip_whitespace(&strip_line_comments(include_str!(
        "../src/household_bootstrap.rs"
    )));

    let evidence_post_route = strip_whitespace(
        ".route(handlers_household_roster::EVIDENCE_PATH,
         axum::routing::post(handlers_household_roster::evidence)",
    );
    let evidence_get_route = strip_whitespace(
        ".route(handlers_household_roster::EVIDENCE_PATH,
         axum::routing::get(handlers_household_roster::evidence)",
    );
    let currency_get_route = strip_whitespace(
        ".route(handlers_household_roster::CURRENCY_PATH,
         axum::routing::get(handlers_household_roster::currency)",
    );

    // CONTROL — the same needle shape, built the same way, finds the currency
    // route. Without it a zero count below would be indistinguishable between
    // "the route is gone" and "this needle never matches anything", and a
    // guard that cannot find what is there proves nothing about what is not.
    assert_eq!(
        bootstrap.matches(&currency_get_route).count(),
        1,
        "control needle failed to find the currency GET route — the needle shape is wrong, \
         so the assertions below prove nothing"
    );

    assert_eq!(
        bootstrap.matches(&evidence_post_route).count(),
        1,
        "POST /api/v1/household/roster/evidence is absent from the production router"
    );
    // NEGATIVE — the mutation this test exists to catch.
    assert_eq!(
        bootstrap.matches(&evidence_get_route).count(),
        0,
        "the evidence route must not be mounted as GET"
    );
    // And exactly one registration total, so a second mount under another verb
    // cannot hide behind the passing POST assertion above.
    assert_eq!(
        bootstrap
            .matches("handlers_household_roster::EVIDENCE_PATH")
            .count(),
        1,
        "EVIDENCE_PATH must be referenced by exactly one route registration"
    );

    // MUTATION PROOF — the whole reason this guard was strengthened. Apply the
    // post→get flip to the real source text and confirm the guard's answer
    // actually changes. Without this, "the assertions pass" would be evidence
    // only that the source is unmutated, never that a mutation would be seen.
    // Entirely in memory: no file is written and nothing on disk is touched.
    let mutated = bootstrap.replace(&evidence_post_route, &evidence_get_route);
    assert_ne!(
        mutated, bootstrap,
        "the simulated post→get flip must actually change the source text"
    );
    assert_eq!(
        mutated.matches(&evidence_post_route).count(),
        0,
        "a post→get flip must break the POST assertion above"
    );
    assert_eq!(
        mutated.matches(&evidence_get_route).count(),
        1,
        "a post→get flip must trip the GET negative above"
    );
}

// ─── 3. D2c-1b: delegated device dispatch, end to end ───────────────────────
//
// The four cases below discriminate the delegated wiring from the owner-only
// handler. Against an owner-only Currency they are exactly inverted: R1 wants
// 200 and gets 401, R2 and R4 want 401 and get 200, R3 wants 503 and gets 401.
// Nothing is stubbed — a real strong owner, a real `DeviceCert`, and a real
// admission into the durable authority.

struct DeviceFixture {
    app: Router,
    owner: P256Keypair,
    device: P256Keypair,
    cert: household_rs::device_cert::DeviceCert,
    state_dir: tempfile::TempDir,
    identity: household_rs::LoadedIdentity,
    auth: Arc<HouseholdAuthState>,
}

/// Like [`fixture`], but the owner cert additionally carries the explicit
/// `household.add_device` grant (re-signed under the household root, keeping
/// its strong provenance) so a `DeviceCert` can narrow from it. `admit`
/// controls whether the device reaches the durable authority.
fn device_fixture(
    admit: bool,
    device_caveats: Option<Vec<household_rs::caveats::Caveat>>,
) -> DeviceFixture {
    use household_rs::caveats::{Caveat, Operation};
    use household_rs::device_admission::{
        HouseholdDeviceAdmissionAuthorityV1, add_pop_challenge, owner_person_cert_digest,
    };
    use household_rs::device_cert::{DeviceCert, SignOptions};

    let state_dir = tempfile::tempdir().expect("household state");
    let identity = household_rs::bootstrap_or_load(
        state_dir.path(),
        BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some("mac-alpha".into()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .expect("bootstrap");
    let owner = P256Keypair::generate();
    let hh_priv = identity
        .hh_priv
        .as_deref()
        .expect("hh_priv present in single-machine household");
    let mut owner_cert = PersonCert::sign_owner_with_verified_provenance(
        hh_priv,
        SignOwnerOptions {
            hh_id: identity.record.hh_id.clone(),
            p_pub: owner.public(),
            display_name: "Owner".into(),
            issued_at: identity.record.created_at,
        },
        VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .expect("owner cert");
    owner_cert
        .caveats
        .push(Caveat::new(Operation::HouseholdAddDevice, None));
    let signing = owner_cert.signing_bytes().expect("owner signing bytes");
    owner_cert.signature = hh_priv.sign(&signing).expect("re-sign owner cert");

    let device = P256Keypair::generate();
    let cert = DeviceCert::sign(
        &owner,
        SignOptions {
            p_pub: owner.public(),
            d_pub: device.public(),
            device_name: "iPhone 15".into(),
            platform: "ios".into(),
            added_at: identity.record.created_at,
            caveats: device_caveats,
        },
    )
    .expect("device cert");

    if admit {
        let authority = HouseholdDeviceAdmissionAuthorityV1::new(
            state_dir.path(),
            identity.record.hh_id.clone(),
            identity.record.hh_pub.clone(),
        );
        authority.provision().expect("provision authority");
        let generation = authority.live_snapshot().expect("snapshot").generation();
        let nonce = [0x5a; 32];
        let challenge = add_pop_challenge(
            &identity.record.hh_id,
            generation,
            &cert,
            &cert.digest().expect("cert digest"),
            &owner_person_cert_digest(&owner_cert).expect("owner digest"),
            &nonce,
        )
        .expect("add challenge");
        let pop = owner.sign(&challenge).expect("owner add pop");
        authority
            .admit_device(&owner_cert, &cert, &pop, &nonce, unix_now())
            .expect("admit device");
    }

    let auth = Arc::new(HouseholdAuthState::new(&identity.record, owner_cert));
    let household = HouseholdState::loaded_with_owner_auth(
        Arc::new(clone_identity(&identity)),
        Some(Arc::clone(&auth)),
    );
    let app = Router::new()
        .route(CURRENCY_PATH, get(handlers_household_roster::currency))
        .route(EVIDENCE_PATH, post(handlers_household_roster::evidence))
        .with_state(RosterRouterState {
            household,
            state_dir: state_dir.path().to_path_buf(),
        });

    DeviceFixture {
        app,
        owner,
        device,
        cert,
        state_dir,
        identity,
        auth,
    }
}

/// A `PoP` signed by `signer` but naming `p_id` in the person slot — the
/// delegated shape: parent person named, device key signing.
fn delegated_pop_header(signer: &P256Keypair, p_id: &str, path: &str, ts: u64) -> String {
    delegated_pop_header_for_request(signer, p_id, "GET", path, ts, b"")
}

fn delegated_pop_header_for_request(
    signer: &P256Keypair,
    p_id: &str,
    method: &str,
    path: &str,
    ts: u64,
    body: &[u8],
) -> String {
    let ctx = RequestSigningContext::new(method, path, ts, body);
    let sig = signer.sign(&ctx.canonical_bytes().unwrap()).unwrap();
    format!(
        "Soyeht-PoP v1:{p_id}:{ts}:{}",
        B64URL.encode(sig.as_bytes())
    )
}

async fn currency_call(
    app: &Router,
    path: &str,
    pop: &str,
    device_id: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::AUTHORIZATION, pop);
    if let Some(device_id) = device_id {
        builder = builder.header("soyeht-device-id", device_id);
    }
    app.clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// R1 — an admitted device signing under its own `d_pub` is served the *whole*
/// contract, not merely let past the gate: same 200, same no-store CBOR
/// headers, same `unavailable_no_genesis` envelope the owner receives from
/// `serves_unavailable_no_genesis_from_a_provisioned_store`.
///
/// The store is provisioned here so the delegated path reaches the envelope.
/// That does not weaken this case's RED: against the owner-only handler the
/// `d_pub` signature was refused with 401 *before* the store was ever read, so
/// provisioning could not have changed that "before". The recorded RED
/// (401 → 200) stands on the un-mutated run already captured.
#[tokio::test]
async fn delegated_device_is_served_like_the_owner() {
    let fx = device_fixture(true, None);
    let coordinator = MachineRosterCoordinator::from_validated_household(
        fx.state_dir.path(),
        &fx.identity.record,
        &fx.auth,
    )
    .expect("coordinator");
    coordinator.provision_no_genesis().expect("provision");

    let path = currency_path(stranger_m_id().0.as_str());
    let p_id = derive_person_id(&fx.owner.public()).0;
    let pop = delegated_pop_header(&fx.device, &p_id, &path, unix_now());
    let resp = currency_call(&fx.app, &path, &pop, Some(&fx.cert.d_id.0)).await;

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "an admitted device must reach the store exactly as the owner does"
    );
    assert_cbor_no_store(&resp);
    let echo: PlainEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.v, 1);
    assert_eq!(
        echo.outcome, "unavailable_no_genesis",
        "the delegated path must serve the identical outcome vocabulary"
    );
}

/// R2 — the header is an explicit, terminal selector. A valid *owner* signature
/// presented alongside it must NOT fall back to the owner path.
#[tokio::test]
async fn device_header_with_owner_signature_never_falls_back() {
    let fx = device_fixture(true, None);
    let path = currency_path(stranger_m_id().0.as_str());
    let pop = pop_header(&fx.owner, &path, b"");
    let resp = currency_call(&fx.app, &path, &pop, Some(&fx.cert.d_id.0)).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "an owner signature must not satisfy a device-selected request"
    );
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "unauthenticated");
}

/// R3 — a device request with no durable authority is a service state, not a
/// credential failure, so it must be 503 rather than a collapsed 401.
#[tokio::test]
async fn delegated_device_without_authority_is_not_initialized() {
    let fx = device_fixture(false, None);
    let path = currency_path(stranger_m_id().0.as_str());
    let p_id = derive_person_id(&fx.owner.public()).0;
    let pop = delegated_pop_header(&fx.device, &p_id, &path, unix_now());
    let resp = currency_call(&fx.app, &path, &pop, Some(&fx.cert.d_id.0)).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "not_initialized");
}

/// R4 — a malformed device id is still an explicit device selection, so the
/// owner signature must not rescue it.
#[tokio::test]
async fn malformed_device_header_with_owner_signature_is_refused() {
    let fx = device_fixture(true, None);
    let path = currency_path(stranger_m_id().0.as_str());
    let pop = pop_header(&fx.owner, &path, b"");
    let resp = currency_call(&fx.app, &path, &pop, Some("d_not-a-real-device-id")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "unauthenticated");
}

/// The replay window applies to the delegated path exactly as it does to the
/// owner: a correctly-signed device proof outside the skew tolerance is still
/// refused, and refused into the same collapsed class.
#[tokio::test]
async fn stale_device_pop_is_refused() {
    let fx = device_fixture(true, None);
    let path = currency_path(stranger_m_id().0.as_str());
    let p_id = derive_person_id(&fx.owner.public()).0;
    // Well outside the 60s tolerance, signed correctly for that timestamp.
    let stale = unix_now() - 3_600;
    let pop = delegated_pop_header(&fx.device, &p_id, &path, stale);
    let resp = currency_call(&fx.app, &path, &pop, Some(&fx.cert.d_id.0)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_cbor_no_store(&resp);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "unauthenticated");
}

/// A device-selected request whose proof does not parse must not be treated
/// differently from any other device refusal — same collapsed class, no hint
/// that the device id itself was or was not recognised.
#[tokio::test]
async fn malformed_device_pop_is_refused() {
    let fx = device_fixture(true, None);
    let path = currency_path(stranger_m_id().0.as_str());
    let resp = currency_call(&fx.app, &path, "Soyeht-PoP garbage", Some(&fx.cert.d_id.0)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_cbor_no_store(&resp);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "unauthenticated");
}

// ─── 4. B0b: POST /api/v1/household/roster/evidence ─────────────────────────
//
// Two layers, for the same reason as the currency surface. The encoding layer
// reaches all four outcomes and all four `state_kind` shapes; the HTTP layer
// cannot, because driving the store to an accepted chain or a fork needs
// owner-signed checkpoints admitted through the `#[cfg(test)]` rig inside
// `household-rs`. End to end a provisioned roster is `state_kind` 0, and that
// is the state the HTTP cases below assert.

/// A real `MachineCert` under a real household key — never a stub, because the
/// cert is serialized into the signed map and its fingerprint is a wire field.
fn evidence_signer() -> (P256Keypair, household_rs::MachineCert, HouseholdId) {
    let hh = P256Keypair::generate();
    let machine = P256Keypair::generate();
    let hh_id = household_rs::derive_household_id(&hh.public());
    let cert = household_rs::MachineCert::sign(
        &hh,
        &machine.public(),
        &household_rs::machine_cert::SignOptions {
            hh_id: hh_id.clone(),
            hostname: "studio-mac".into(),
            platform: household_rs::Platform::Macos,
            joined_at: 1_714_972_800,
        },
    )
    .expect("machine cert");
    (machine, cert, hh_id)
}

/// The per-`state_kind` body shape the contract requires: no checkpoints at
/// kind 0, a predecessor only on the accepted state, a conflicting checkpoint
/// only on the two fork states.
fn evidence_snapshot(hh_id: &HouseholdId, state_kind: u8) -> RosterEvidenceSnapshot {
    RosterEvidenceSnapshot {
        hh_id: hh_id.clone(),
        state_kind,
        floor_secs: 1_714_972_800,
        genesis_checkpoint: (state_kind != 0).then(|| vec![0xA1, 0x01]),
        accepted_checkpoint: (state_kind != 0).then(|| vec![0xA1, 0x02]),
        predecessor_checkpoint: (state_kind == 1).then(|| vec![0xA1, 0x04]),
        conflicting_checkpoint: (state_kind >= 2).then(|| vec![0xA1, 0x03]),
    }
}

fn provision_roster(
    state_dir: &std::path::Path,
    fx_record: &household_rs::HouseholdRecord,
    auth: &Arc<HouseholdAuthState>,
) {
    MachineRosterCoordinator::from_validated_household(state_dir, fx_record, auth)
        .expect("coordinator")
        .provision_no_genesis()
        .expect("provision");
}

/// `{client_nonce: h'…', v: 1}` — decodable, but **non-canonical**.
///
/// This encoder sorts map keys by their *encoded bytes*, not alphabetically:
/// `"v"` encodes as `0x61 0x76` and `"client_nonce"` as `0x6C 0x63 …`, so
/// `0x61 < 0x6C` puts `v` first. The canonical order is therefore the reverse
/// of the alphabetical one, and the alphabetical order written here is the
/// wrong encoding the byte-compare exists to catch. Hand-encoded, because the
/// canonical encoder cannot emit this by construction.
fn non_canonical_evidence_request(nonce: [u8; 32]) -> Vec<u8> {
    let mut out = vec![0xA2, 0x6C];
    out.extend_from_slice(b"client_nonce");
    out.extend_from_slice(&[0x58, 0x20]);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&[0x61, b'v', 0x01]);
    out
}

/// An indefinite-length map (`0xBF … 0xFF`). Canonical CBOR is definite-length
/// only, so this is refused whether it fails at decode or at the byte-compare.
fn indefinite_length_evidence_request(nonce: [u8; 32]) -> Vec<u8> {
    let mut out = vec![0xBF, 0x61, b'v', 0x01, 0x6C];
    out.extend_from_slice(b"client_nonce");
    out.extend_from_slice(&[0x58, 0x20]);
    out.extend_from_slice(&nonce);
    out.push(0xFF);
    out
}

fn evidence_request_with_nonce_len(len: usize) -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&EvidenceRequestEcho {
        client_nonce: serde_bytes::ByteBuf::from(vec![0x42; len]),
        v: 1,
    })
    .expect("canonical evidence request")
}

// ── encoding layer ──────────────────────────────────────────────────────────

/// `snapshot_body` must be a nested CBOR **map**. `SnapshotBodyEcho` is a
/// struct, so this only decodes if that is true — a byte string carrying CBOR
/// (the shape iOS rejects) fails to decode here.
#[test]
fn evidence_available_wire_is_exactly_ten_keys_with_a_nested_map_body() {
    let (key, cert, hh_id) = evidence_signer();
    let snapshot = evidence_snapshot(&hh_id, 1);
    let evidence = build_signed_evidence(
        RosterEvidenceOutcome::Available,
        [0x5A; 32],
        &cert,
        &key,
        Some(&snapshot),
    )
    .expect("signed evidence");
    let echo: EvidenceAvailableEcho =
        assert_exact_and_canonical(&encode_evidence_body(&evidence).expect("encode"));
    assert_eq!(echo.v, 1);
    assert_eq!(echo.outcome, "available");
    assert_eq!(echo.client_nonce.as_ref(), &[0x5A; 32]);
    assert_eq!(echo.state_evidence_digest.len(), 32);
    assert_eq!(echo.full_snapshot_digest.len(), 32);
    assert_eq!(echo.signer_machine_cert_fingerprint.len(), 32);
    assert_eq!(echo.signer_m_id, cert.m_id.to_string());
    assert!(!echo.signer_machine_cert.is_empty());
    assert_eq!(echo.snapshot_body.state_kind, 1);
    assert_eq!(echo.snapshot_body.floor_secs, snapshot.floor_secs);
    assert_eq!(echo.snapshot_body.hh_id, hh_id);
}

/// Every `unavailable_*` is seven keys. The three optional members are absent,
/// not null — asserted by requiring the available-shaped decode to fail.
#[test]
fn evidence_unavailable_wire_is_exactly_seven_keys_for_every_literal() {
    for (outcome, literal) in [
        (
            RosterEvidenceOutcome::UnavailableClockState,
            "unavailable_clock_state",
        ),
        (
            RosterEvidenceOutcome::UnavailableOwnerAuthority,
            "unavailable_owner_authority",
        ),
        (
            RosterEvidenceOutcome::UnavailableCheckpointStale,
            "unavailable_checkpoint_stale",
        ),
    ] {
        let (key, cert, _hh_id) = evidence_signer();
        let evidence =
            build_signed_evidence(outcome, [0x11; 32], &cert, &key, None).expect("signed evidence");
        let encoded = encode_evidence_body(&evidence).expect("encode");
        let echo: EvidenceUnavailableEcho = assert_exact_and_canonical(&encoded);
        assert_eq!(echo.outcome, literal);
        assert_eq!(echo.v, 1);
        assert_eq!(echo.client_nonce.as_ref(), &[0x11; 32]);
        assert!(
            household_rs::cbor::from_canonical_slice::<EvidenceAvailableEcho>(&encoded).is_err(),
            "{literal} must carry no body and no digests"
        );
    }
}

/// The four outcome literals are exactly the four this surface may serve.
#[test]
fn evidence_serves_exactly_four_outcome_literals() {
    let served: Vec<&str> = [
        RosterEvidenceOutcome::Available,
        RosterEvidenceOutcome::UnavailableClockState,
        RosterEvidenceOutcome::UnavailableOwnerAuthority,
        RosterEvidenceOutcome::UnavailableCheckpointStale,
    ]
    .iter()
    .map(|o| o.wire_str())
    .collect();
    assert_eq!(
        served,
        vec![
            "available",
            "unavailable_clock_state",
            "unavailable_owner_authority",
            "unavailable_checkpoint_stale"
        ]
    );
    let distinct: std::collections::BTreeSet<&str> = served.iter().copied().collect();
    assert_eq!(distinct.len(), 4, "the four literals must be distinct");
    // The currency vocabulary is a different partition and must not leak in.
    assert!(!served.contains(&"not_listed"));
    assert!(!served.contains(&"unavailable_no_genesis"));
}

#[test]
fn evidence_snapshot_body_shape_follows_state_kind() {
    let (key, cert, hh_id) = evidence_signer();
    for kind in [0u8, 1, 2, 3] {
        let snapshot = evidence_snapshot(&hh_id, kind);
        let evidence = build_signed_evidence(
            RosterEvidenceOutcome::Available,
            [kind; 32],
            &cert,
            &key,
            Some(&snapshot),
        )
        .expect("signed evidence");
        let echo: EvidenceAvailableEcho =
            assert_exact_and_canonical(&encode_evidence_body(&evidence).expect("encode"));
        let body = echo.snapshot_body;
        assert_eq!(body.state_kind, kind);
        assert_eq!(body.genesis_checkpoint.is_some(), kind != 0);
        assert_eq!(body.accepted_checkpoint.is_some(), kind != 0);
        assert_eq!(
            body.predecessor_checkpoint.is_some(),
            kind == 1,
            "state_kind {kind}: predecessor belongs only to the accepted state"
        );
        assert_eq!(
            body.conflicting_checkpoint.is_some(),
            kind >= 2,
            "state_kind {kind}: only the fork states carry a conflicting checkpoint"
        );
    }
}

#[test]
fn evidence_signature_verifies_over_the_frozen_preimage() {
    let (key, cert, hh_id) = evidence_signer();
    let snapshot = evidence_snapshot(&hh_id, 2);
    let evidence = build_signed_evidence(
        RosterEvidenceOutcome::Available,
        [0x77; 32],
        &cert,
        &key,
        Some(&snapshot),
    )
    .expect("signed evidence");
    let preimage = signing_preimage(&evidence).expect("preimage");
    household_rs::keys::verify_signature(&cert.m_pub, &preimage, &evidence.signature)
        .expect("the genuine signature must verify");
    // NEGATIVE CONTROL — exercises the verifier, so the assertion above cannot
    // be passing because verification is broken outright.
    let forged = P256Keypair::generate().sign(&preimage).expect("forge");
    assert!(household_rs::keys::verify_signature(&cert.m_pub, &preimage, &forged).is_err());
}

// ── HTTP layer: owner ───────────────────────────────────────────────────────

#[tokio::test]
async fn evidence_owner_is_served_available_and_echoes_the_nonce() {
    let fx = fixture();
    provision_roster(fx.state_dir.path(), &fx.identity.record, &fx.auth);
    let nonce = [0x3C; 32];
    let resp = evidence_call(&fx.app, &fx.owner, evidence_request(nonce), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_cbor_no_store(&resp);
    let echo: EvidenceAvailableEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(
        echo.outcome, "available",
        "a provisioned genesis-less roster is an available state_kind 0, not an unavailable"
    );
    assert_eq!(
        echo.client_nonce.as_ref(),
        &nonce,
        "the client nonce must be echoed verbatim"
    );
    assert_eq!(echo.snapshot_body.state_kind, 0);
    assert!(echo.snapshot_body.genesis_checkpoint.is_none());
    assert!(echo.snapshot_body.accepted_checkpoint.is_none());
    assert!(echo.snapshot_body.predecessor_checkpoint.is_none());
    assert!(echo.snapshot_body.conflicting_checkpoint.is_none());
    assert_eq!(
        echo.signer_m_id,
        fx.identity.cert.m_id.to_string(),
        "the signer must be the boot-loaded machine identity, never a fresh key"
    );
}

/// The served signature must cover the frozen preimage under the boot-loaded
/// machine key. Rebuilding the statement locally and verifying the *served*
/// signature against the rebuilt preimage avoids depending on ECDSA nonce
/// determinism, which a byte-comparison of two responses would.
#[tokio::test]
async fn evidence_is_signed_by_the_boot_loaded_identity_over_the_frozen_preimage() {
    let fx = fixture();
    provision_roster(fx.state_dir.path(), &fx.identity.record, &fx.auth);
    let nonce = [0x91; 32];
    let resp = evidence_call(&fx.app, &fx.owner, evidence_request(nonce), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let echo: EvidenceAvailableEcho = assert_exact_and_canonical(&body_bytes(resp).await);

    let snapshot = RosterEvidenceSnapshot {
        hh_id: echo.snapshot_body.hh_id.clone(),
        state_kind: echo.snapshot_body.state_kind,
        floor_secs: echo.snapshot_body.floor_secs,
        genesis_checkpoint: echo
            .snapshot_body
            .genesis_checkpoint
            .clone()
            .map(serde_bytes::ByteBuf::into_vec),
        accepted_checkpoint: echo
            .snapshot_body
            .accepted_checkpoint
            .clone()
            .map(serde_bytes::ByteBuf::into_vec),
        predecessor_checkpoint: echo
            .snapshot_body
            .predecessor_checkpoint
            .clone()
            .map(serde_bytes::ByteBuf::into_vec),
        conflicting_checkpoint: echo
            .snapshot_body
            .conflicting_checkpoint
            .clone()
            .map(serde_bytes::ByteBuf::into_vec),
    };
    let rebuilt = build_signed_evidence(
        RosterEvidenceOutcome::Available,
        nonce,
        &fx.identity.cert,
        fx.identity.m_priv.as_ref(),
        Some(&snapshot),
    )
    .expect("rebuild");
    let preimage = signing_preimage(&rebuilt).expect("preimage");
    let served = P256Signature::from_bytes(&echo.signature).expect("64-byte signature");
    household_rs::keys::verify_signature(&fx.identity.cert.m_pub, &preimage, &served)
        .expect("the served signature must cover the frozen preimage");
}

#[tokio::test]
async fn evidence_rejects_unauthenticated_requests() {
    let fx = fixture();
    let body = evidence_request([0x01; 32]);
    let resp = evidence_post(
        &fx.app,
        "Soyeht-PoP garbage",
        Some(CONTENT_TYPE),
        body,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_cbor_no_store(&resp);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "unauthenticated");
}

#[tokio::test]
async fn evidence_reports_not_initialized_before_provisioning() {
    let fx = fixture();
    let resp = evidence_call(&fx.app, &fx.owner, evidence_request([0x02; 32]), None).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_cbor_no_store(&resp);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "not_initialized");
}

/// Every malformed request shape collapses to one 400 literal.
#[tokio::test]
async fn evidence_rejects_every_malformed_request_shape() {
    #[derive(Serialize)]
    struct UnknownKey {
        client_nonce: serde_bytes::ByteBuf,
        extra: u8,
        v: u8,
    }
    #[derive(Serialize)]
    struct MissingNonce {
        v: u8,
    }

    let unknown_key = household_rs::cbor::to_canonical_vec(&UnknownKey {
        client_nonce: serde_bytes::ByteBuf::from(vec![0x42; 32]),
        extra: 9,
        v: 1,
    })
    .expect("canonical");
    let missing_nonce =
        household_rs::cbor::to_canonical_vec(&MissingNonce { v: 1 }).expect("canonical");
    let wrong_version = household_rs::cbor::to_canonical_vec(&EvidenceRequestEcho {
        client_nonce: serde_bytes::ByteBuf::from(vec![0x42; 32]),
        v: 2,
    })
    .expect("canonical");

    // CONTROL — the "non-canonical" fixture must actually differ from the
    // canonical encoding. Key order here is by encoded bytes, not alphabetical,
    // so an alphabetically-ordered fixture can silently *be* canonical and turn
    // this case into a 200 that looks like a handler bug.
    assert_ne!(
        non_canonical_evidence_request([0x42; 32]),
        evidence_request([0x42; 32]),
        "the non-canonical fixture must not coincide with the canonical encoding"
    );

    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "non-canonical key order",
            non_canonical_evidence_request([0x42; 32]),
        ),
        (
            "indefinite-length map",
            indefinite_length_evidence_request([0x42; 32]),
        ),
        ("unknown key", unknown_key),
        ("missing client_nonce", missing_nonce),
        ("wrong version", wrong_version),
        ("nonce too short", evidence_request_with_nonce_len(31)),
        ("nonce too long", evidence_request_with_nonce_len(33)),
        ("empty body", Vec::new()),
        ("not a map", vec![0x01]),
    ];

    for (label, body) in cases {
        let fx = fixture();
        provision_roster(fx.state_dir.path(), &fx.identity.record, &fx.auth);
        let resp = evidence_call(&fx.app, &fx.owner, body, None).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{label} must be refused as invalid_request"
        );
        assert_cbor_no_store(&resp);
        let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
        assert_eq!(echo.error, "invalid_request", "{label}");
    }
}

/// The media type must be exactly `application/cbor`; absent is as fatal as
/// wrong, and neither is leniently parsed.
#[tokio::test]
async fn evidence_requires_the_exact_content_type() {
    for content_type in [None, Some("application/json"), Some("text/plain")] {
        let fx = fixture();
        provision_roster(fx.state_dir.path(), &fx.identity.record, &fx.auth);
        let body = evidence_request([0x04; 32]);
        let pop = pop_header_for_method(&fx.owner, "POST", EVIDENCE_PATH, &body);
        let resp = evidence_post(&fx.app, &pop, content_type, body, None).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content type {content_type:?} must be refused"
        );
        assert_cbor_no_store(&resp);
        let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
        assert_eq!(echo.error, "unsupported_media_type");
    }
}

/// An oversized body is refused on size even though the `PoP` covers it and the
/// media type is correct.
///
/// This pins the size gate itself and nothing more. It says nothing about gate
/// *order*: a server that checked size before authorizing would answer `413`
/// here too, so this case is equally green under either order. The order is
/// pinned by `evidence_oversized_body_with_invalid_pop_is_unauthenticated`.
#[tokio::test]
async fn evidence_rejects_an_oversized_body() {
    let fx = fixture();
    provision_roster(fx.state_dir.path(), &fx.identity.record, &fx.auth);
    let resp = evidence_call(&fx.app, &fx.owner, vec![0x00; 2048], None).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_cbor_no_store(&resp);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "payload_too_large");
}

/// DISCRIMINATOR for the gate order — authorization precedes the size check.
///
/// Same oversized body as above, but the `PoP` is invalid. The two tests differ
/// in exactly one input and must differ in the answer: `401 unauthenticated`
/// here, `413 payload_too_large` there. Only this pair separates the two gate
/// orders. If size ran first, an unauthenticated caller would be told `413` —
/// learning that the server accepted, measured and rejected their payload
/// before they ever proved who they are, and gaining a probe for the limit that
/// costs no credential.
#[tokio::test]
async fn evidence_oversized_body_with_invalid_pop_is_unauthenticated() {
    let fx = fixture();
    provision_roster(fx.state_dir.path(), &fx.identity.record, &fx.auth);
    let resp = evidence_post(
        &fx.app,
        "Soyeht-PoP garbage",
        Some(CONTENT_TYPE),
        vec![0x00; 2048],
        None,
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "an oversized body must not be refused on size before the caller is authenticated"
    );
    assert_cbor_no_store(&resp);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "unauthenticated");
}

// ── HTTP layer: delegated device ────────────────────────────────────────────

#[tokio::test]
async fn evidence_delegated_device_is_served_like_the_owner() {
    let fx = device_fixture(true, None);
    provision_roster(fx.state_dir.path(), &fx.identity.record, &fx.auth);
    let nonce = [0x2B; 32];
    let body = evidence_request(nonce);
    let p_id = derive_person_id(&fx.owner.public()).0;
    let pop = delegated_pop_header_for_request(
        &fx.device,
        &p_id,
        "POST",
        EVIDENCE_PATH,
        unix_now(),
        &body,
    );
    let resp = evidence_post(
        &fx.app,
        &pop,
        Some(CONTENT_TYPE),
        body,
        Some(&fx.cert.d_id.0),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "an admitted device must reach the signer exactly as the owner does"
    );
    assert_cbor_no_store(&resp);
    let echo: EvidenceAvailableEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.client_nonce.as_ref(), &nonce);
    assert_eq!(echo.outcome, "available");
    assert_eq!(
        echo.signer_m_id,
        fx.identity.cert.m_id.to_string(),
        "the delegated path must not change who signs"
    );
}

/// The device header is terminal on this route too: a valid owner signature
/// beside it must not rescue the request.
#[tokio::test]
async fn evidence_device_header_with_owner_signature_never_falls_back() {
    let fx = device_fixture(true, None);
    let body = evidence_request([0x2C; 32]);
    let pop = pop_header_for_method(&fx.owner, "POST", EVIDENCE_PATH, &body);
    let resp = evidence_post(
        &fx.app,
        &pop,
        Some(CONTENT_TYPE),
        body,
        Some(&fx.cert.d_id.0),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_cbor_no_store(&resp);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "unauthenticated");
}

/// Unknown, malformed and stale device proofs all collapse into the same 401,
/// so the status cannot be used to enumerate which devices exist.
#[tokio::test]
async fn evidence_refuses_unknown_malformed_and_stale_devices() {
    let p_id_of = |fx: &DeviceFixture| derive_person_id(&fx.owner.public()).0;

    // Unknown device id, otherwise well-formed delegated proof.
    let fx = device_fixture(true, None);
    let body = evidence_request([0x2D; 32]);
    let pop = delegated_pop_header_for_request(
        &fx.device,
        &p_id_of(&fx),
        "POST",
        EVIDENCE_PATH,
        unix_now(),
        &body,
    );
    let resp = evidence_post(
        &fx.app,
        &pop,
        Some(CONTENT_TYPE),
        body,
        Some("d_not-a-real-device-id"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "unknown device id");
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "unauthenticated");

    // Malformed proof under a real admitted device id.
    let fx = device_fixture(true, None);
    let resp = evidence_post(
        &fx.app,
        "Soyeht-PoP garbage",
        Some(CONTENT_TYPE),
        evidence_request([0x2E; 32]),
        Some(&fx.cert.d_id.0),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "malformed device proof"
    );
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "unauthenticated");

    // Correctly signed, but well outside the replay window.
    let fx = device_fixture(true, None);
    let body = evidence_request([0x2F; 32]);
    let pop = delegated_pop_header_for_request(
        &fx.device,
        &p_id_of(&fx),
        "POST",
        EVIDENCE_PATH,
        unix_now() - 3_600,
        &body,
    );
    let resp = evidence_post(
        &fx.app,
        &pop,
        Some(CONTENT_TYPE),
        body,
        Some(&fx.cert.d_id.0),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "stale device proof"
    );
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "unauthenticated");
}

/// A device request with no durable admission authority is a service state, not
/// a credential failure.
#[tokio::test]
async fn evidence_delegated_device_without_authority_is_not_initialized() {
    let fx = device_fixture(false, None);
    let body = evidence_request([0x30; 32]);
    let p_id = derive_person_id(&fx.owner.public()).0;
    let pop = delegated_pop_header_for_request(
        &fx.device,
        &p_id,
        "POST",
        EVIDENCE_PATH,
        unix_now(),
        &body,
    );
    let resp = evidence_post(
        &fx.app,
        &pop,
        Some(CONTENT_TYPE),
        body,
        Some(&fx.cert.d_id.0),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let echo: ErrorEcho = assert_exact_and_canonical(&body_bytes(resp).await);
    assert_eq!(echo.error, "not_initialized");
}
