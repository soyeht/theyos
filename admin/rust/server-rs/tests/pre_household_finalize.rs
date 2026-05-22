//! T037-T041 coverage for M2's pre-household
//! `/pair-machine/local/seed` and `/pair-machine/local/finalize` endpoints.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use household_rs::machine_cert::Platform;
use household_rs::pair_machine::{
    CeremonyInputs, CeremonyTxn, FinalizeAck, JoinResponse, JoinResponseUnsigned, JoinTransport,
    PairMachineState, PairMachineWindow, PeerEntry, PrepareCandidateOpts, join_request_hash,
    prepare_candidate,
};
use household_rs::storage::{household_record_path, machine_cert_for, read_self_m_id};
use household_rs::{BootstrapOpts, KeyBackingPolicy};
use serde_bytes::ByteBuf;
use server_rs::handlers_pair_machine::{PreHouseholdRouterState, pre_household_router};
use tempfile::TempDir;
use tower::ServiceExt;
use zeroize::Zeroizing;

const FINALIZE_PATH: &str = "/pair-machine/local/finalize";

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

struct Fixture {
    _m1_dir: TempDir,
    m2_dir: TempDir,
    router: Router,
    window: Arc<PairMachineWindow>,
    prepared: household_rs::pair_machine::PreparedCandidate,
    join_response: JoinResponse,
    join_response_bytes: Vec<u8>,
}

async fn fixture() -> Fixture {
    let m1_dir = tempfile::tempdir().unwrap();
    let m2_dir = tempfile::tempdir().unwrap();
    let m1 = bootstrap(m1_dir.path());
    let window =
        Arc::new(PairMachineWindow::with_persistence(m2_dir.path().to_path_buf()).unwrap());
    let prepared = prepare_candidate(
        &window,
        PrepareCandidateOpts {
            state_dir: m2_dir.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: "127.0.0.1:8091".into(),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: Duration::from_secs(300),
            now_unix: unix_now(),
        },
    )
    .await
    .unwrap();
    let join_response = build_join_response(m1_dir.path(), &m1, &prepared);
    let join_response_bytes = join_response.to_canonical_bytes().unwrap();
    // Simulate the iPhone having delivered POST /pair-machine/local/anchor
    // for the happy-path tests. The anchor-gate-rejects-when-missing case
    // is covered by `local_finalize_rejects_without_pinned_anchor` below.
    window
        .pin_household_anchor(m1.record.hh_id.to_string(), *m1.record.hh_pub.as_bytes())
        .await
        .unwrap();
    let router = pre_household_router(PreHouseholdRouterState {
        window: Arc::clone(&window),
        state_dir: m2_dir.path().to_path_buf(),
        key_policy: KeyBackingPolicy::ForceSoftware,
        finalize_lock: Arc::new(tokio::sync::Mutex::new(())),
    });
    Fixture {
        _m1_dir: m1_dir,
        m2_dir,
        router,
        window,
        prepared,
        join_response,
        join_response_bytes,
    }
}

fn build_join_response(
    m1_state_dir: &std::path::Path,
    m1: &household_rs::LoadedIdentity,
    prepared: &household_rs::pair_machine::PreparedCandidate,
) -> JoinResponse {
    let txn = CeremonyTxn::prepare(CeremonyInputs {
        hh_priv: Zeroizing::new(
            *m1.hh_priv
                .as_ref()
                .and_then(|k| k.as_software_secret())
                .expect("software hh_priv pre-Shamir"),
        ),
        hh_id: m1.record.hh_id.clone(),
        hh_pub_sec1: *m1.record.hh_pub.as_bytes(),
        m1_priv_scalar: Zeroizing::new(*m1.m_priv.as_software_secret().unwrap()),
        m1_pub_sec1: *m1.cert.m_pub.as_bytes(),
        m1_id: m1.cert.m_id.to_string(),
        candidate_m_pub_sec1: prepared.m_pub_sec1,
        candidate_hostname: prepared.join_request.hostname.clone(),
        candidate_platform: prepared.join_request.platform.clone(),
        joined_at: unix_now(),
        state_dir: m1_state_dir.to_path_buf(),
        existing_record: m1.record.clone(),
        policy: household_rs::KeyBackingPolicy::ForceSoftware,
    })
    .unwrap();
    JoinResponseUnsigned {
        version: 1,
        join_request_hash: ByteBuf::from(join_request_hash(&prepared.join_request_cbor).to_vec()),
        machine_cert: txn.candidate_cert().clone(),
        encrypted_shard: txn.peer_encrypted_shard().clone(),
        household_record: txn.new_household_record().clone(),
        peer_list: vec![PeerEntry {
            m_id: m1.cert.m_id.to_string(),
            m_pub: ByteBuf::from(m1.cert.m_pub.as_bytes().to_vec()),
            hostname: m1.cert.hostname.clone(),
            tailscale_addr: None,
            machine_cert: Some(m1.cert.clone()),
        }],
        push_token_seed: None,
    }
    .sign(m1.m_priv.as_ref())
    .unwrap()
}

async fn post_finalize(router: Router, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(FINALIZE_PATH)
                .header("content-type", "application/cbor")
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

async fn get_seed(router: Router, nonce_short: &str) -> (StatusCode, Vec<u8>) {
    let uri = format!("/pair-machine/local/seed?nonce={nonce_short}");
    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
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

#[tokio::test]
async fn local_seed_returns_cached_join_request_for_short_nonce() {
    let f = fixture().await;
    let nonce = f.prepared.join_request.nonce.as_ref();
    let nonce_short = household_rs::ids::base32_lower_nopad_encode(&nonce[..8]);

    let (status, bytes) = get_seed(f.router, &nonce_short).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, f.prepared.join_request_cbor);
}

#[tokio::test]
async fn local_finalize_commits_candidate_state() {
    let f = fixture().await;
    let m1_id = f.join_response.peer_list[0].m_id.clone();
    let m2_id = f.join_response.machine_cert.m_id.to_string();

    let (status, bytes) = post_finalize(f.router, f.join_response_bytes).await;

    assert_eq!(status, StatusCode::OK);
    let ack: FinalizeAck = household_rs::cbor::from_canonical_slice(&bytes).unwrap();
    assert_eq!(ack.version, 1);
    assert_eq!(ack.m_id, m2_id);
    assert_eq!(
        ack.machine_cert_hash.as_ref(),
        household_rs::pair_machine::machine_cert_hash(&f.join_response.machine_cert)
            .unwrap()
            .as_slice()
    );
    assert!(machine_cert_for(f.m2_dir.path(), &m1_id).exists());
    assert!(machine_cert_for(f.m2_dir.path(), &m2_id).exists());
    assert_eq!(
        read_self_m_id(f.m2_dir.path()).unwrap().as_deref(),
        Some(m2_id.as_str())
    );
    let self_cert = household_rs::machine_cert::load_self_cert(f.m2_dir.path())
        .unwrap()
        .expect("self cert should load through self_m_id marker");
    assert_eq!(self_cert.m_id.to_string(), m2_id);
    assert!(household_record_path(f.m2_dir.path()).exists());
    assert!(household_rs::pair_machine::shamir_self_shard_path(f.m2_dir.path()).exists());
    assert_eq!(
        household_rs::bootstrap_state::load(f.m2_dir.path()).unwrap(),
        household_rs::bootstrap_state::BootstrapState::Ready
    );
    assert_eq!(f.window.snapshot().await.state, PairMachineState::Committed);
    assert!(!household_rs::storage::legacy_machine_cert_path(f.m2_dir.path()).exists());
}

#[tokio::test]
async fn local_finalize_is_idempotent_for_concurrent_same_response() {
    let f = fixture().await;

    let (first, second) = tokio::join!(
        post_finalize(f.router.clone(), f.join_response_bytes.clone()),
        post_finalize(f.router, f.join_response_bytes)
    );
    let (status1, bytes1) = first;
    let (status2, bytes2) = second;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(bytes1, bytes2);
}

#[tokio::test]
async fn local_finalize_rejects_response_for_superseded_join_request() {
    let f = fixture().await;
    let old_response = f.join_response_bytes.clone();

    let _new_prepared = prepare_candidate(
        &f.window,
        PrepareCandidateOpts {
            state_dir: f.m2_dir.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: "127.0.0.1:8091".into(),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: Duration::from_secs(300),
            now_unix: unix_now(),
        },
    )
    .await
    .unwrap();

    let (status, bytes) = post_finalize(f.router, old_response).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: serde_cbor_like::GenericUnauth =
        household_rs::cbor::from_canonical_slice(&bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
}

#[tokio::test]
async fn local_finalize_rejects_rehashed_stale_response_without_resign() {
    let f = fixture().await;
    let old_response = f.join_response_bytes.clone();

    let new_prepared = prepare_candidate(
        &f.window,
        PrepareCandidateOpts {
            state_dir: f.m2_dir.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: "127.0.0.1:8091".into(),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: Duration::from_secs(300),
            now_unix: unix_now(),
        },
    )
    .await
    .unwrap();

    let mut stale: JoinResponse = household_rs::cbor::from_canonical_slice(&old_response).unwrap();
    stale.join_request_hash =
        ByteBuf::from(join_request_hash(&new_prepared.join_request_cbor).to_vec());
    let rehashed_body = stale.to_canonical_bytes().unwrap();
    let (status, bytes) = post_finalize(f.router, rehashed_body).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: serde_cbor_like::GenericUnauth =
        household_rs::cbor::from_canonical_slice(&bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
}

#[tokio::test]
async fn local_finalize_rejects_unsigned_push_token_seed_mutation() {
    let f = fixture().await;
    let mut mutated = f.join_response.clone();
    mutated.push_token_seed = Some(household_rs::owner_events::OwnerDevicePushToken {
        version: 1,
        p_id: "p_test_owner".into(),
        platform: "ios".into(),
        push_token: ByteBuf::from(vec![9u8; 32]),
        updated_at: unix_now(),
    });

    let (status, bytes) = post_finalize(f.router, mutated.to_canonical_bytes().unwrap()).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: serde_cbor_like::GenericUnauth =
        household_rs::cbor::from_canonical_slice(&bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
}

#[tokio::test]
async fn local_finalize_rejects_mutated_response_after_commit() {
    let f = fixture().await;
    let (status, _) = post_finalize(f.router.clone(), f.join_response_bytes.clone()).await;
    assert_eq!(status, StatusCode::OK);

    let mut mutated = f.join_response_bytes;
    let last = mutated.len() - 1;
    mutated[last] ^= 0x01;
    let (status, bytes) = post_finalize(f.router, mutated).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: serde_cbor_like::GenericUnauth =
        household_rs::cbor::from_canonical_slice(&bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
}

#[tokio::test]
async fn local_seed_missing_nonce_returns_generic_401() {
    let f = fixture().await;

    let resp = f
        .router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/pair-machine/local/seed")
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

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: serde_cbor_like::GenericUnauth =
        household_rs::cbor::from_canonical_slice(&bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
}

#[tokio::test]
async fn local_seed_wrong_nonce_returns_generic_401() {
    let f = fixture().await;

    let (status, bytes) = get_seed(f.router, "wrongnonce").await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: serde_cbor_like::GenericUnauth =
        household_rs::cbor::from_canonical_slice(&bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
}

mod serde_cbor_like {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct GenericUnauth {
        #[serde(rename = "v")]
        pub _version: u8,
        pub error: String,
    }
}

// ── B7: external trust anchor (`POST /pair-machine/local/anchor`) ────

const ANCHOR_PATH: &str = "/pair-machine/local/anchor";

async fn post_anchor(router: Router, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(ANCHOR_PATH)
                .header("content-type", "application/cbor")
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

#[derive(serde::Serialize)]
struct LocalAnchorWire<'a> {
    #[serde(rename = "v")]
    version: u8,
    anchor_secret: serde_bytes::ByteBuf,
    hh_id: &'a str,
    hh_pub: serde_bytes::ByteBuf,
}

fn build_anchor_for(
    _m1: &household_rs::LoadedIdentity,
    anchor_secret: &[u8; 32],
    hh_pub: &[u8; 33],
    hh_id: &str,
) -> Vec<u8> {
    let body = LocalAnchorWire {
        version: 1,
        anchor_secret: serde_bytes::ByteBuf::from(anchor_secret.to_vec()),
        hh_id,
        hh_pub: serde_bytes::ByteBuf::from(hh_pub.to_vec()),
    };
    household_rs::cbor::to_canonical_vec(&body).unwrap()
}

/// Build a fresh fixture without the auto-pinned anchor so the
/// finalize-without-anchor test can verify the gate fires.
async fn fixture_without_anchor() -> (Fixture, household_rs::LoadedIdentity, [u8; 32]) {
    let m1_dir = tempfile::tempdir().unwrap();
    let m2_dir = tempfile::tempdir().unwrap();
    let m1 = bootstrap(m1_dir.path());
    let window =
        Arc::new(PairMachineWindow::with_persistence(m2_dir.path().to_path_buf()).unwrap());
    let prepared = prepare_candidate(
        &window,
        PrepareCandidateOpts {
            state_dir: m2_dir.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: "127.0.0.1:8091".into(),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: Duration::from_secs(300),
            now_unix: unix_now(),
        },
    )
    .await
    .unwrap();
    let join_response = build_join_response(m1_dir.path(), &m1, &prepared);
    let join_response_bytes = join_response.to_canonical_bytes().unwrap();
    let anchor_secret = prepared.anchor_secret;
    let router = pre_household_router(PreHouseholdRouterState {
        window: Arc::clone(&window),
        state_dir: m2_dir.path().to_path_buf(),
        key_policy: KeyBackingPolicy::ForceSoftware,
        finalize_lock: Arc::new(tokio::sync::Mutex::new(())),
    });
    (
        Fixture {
            _m1_dir: m1_dir,
            m2_dir,
            router,
            window,
            prepared,
            join_response,
            join_response_bytes,
        },
        m1,
        anchor_secret,
    )
}

#[tokio::test]
async fn local_finalize_rejects_when_anchor_not_pinned() {
    // The `fixture()` helper pre-pins the anchor for the happy-path
    // tests. This test uses `fixture_without_anchor` to verify the
    // finalize gate fires when the iPhone has not delivered the
    // anchor yet.
    let (f, _m1, _anchor) = fixture_without_anchor().await;
    let (status, body) = post_finalize(f.router, f.join_response_bytes).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: serde_cbor_like::GenericUnauth =
        household_rs::cbor::from_canonical_slice(&body).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
}

#[tokio::test]
async fn local_anchor_pins_household_for_finalize() {
    let (f, m1, anchor_secret) = fixture_without_anchor().await;
    let body = build_anchor_for(
        &m1,
        &anchor_secret,
        m1.record.hh_pub.as_bytes(),
        m1.record.hh_id.as_str(),
    );
    let (status, _) = post_anchor(f.router.clone(), body).await;
    assert_eq!(status, StatusCode::OK);
    let snap = f.window.snapshot().await;
    assert_eq!(
        snap.pinned_hh_pub.as_ref().map(|b| b.as_slice()),
        Some(m1.record.hh_pub.as_bytes().as_slice())
    );
    assert_eq!(snap.pinned_hh_id.as_deref(), Some(m1.record.hh_id.as_str()));

    // Now finalize must succeed because the anchor is pinned to M1.
    let (status, _) = post_finalize(f.router, f.join_response_bytes).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn local_anchor_rejects_wrong_secret() {
    let (f, m1, _real_secret) = fixture_without_anchor().await;
    let body = build_anchor_for(
        &m1,
        &[0xAA; 32], // wrong anchor_secret
        m1.record.hh_pub.as_bytes(),
        m1.record.hh_id.as_str(),
    );
    let (status, _) = post_anchor(f.router, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let snap = f.window.snapshot().await;
    assert!(
        snap.pinned_hh_pub.is_none(),
        "wrong-secret anchor must not pin"
    );
}

#[tokio::test]
async fn local_anchor_rejects_attacker_household_substitution() {
    // Confirms the attack the contract is designed to prevent. An
    // attacker who knows the candidate's `m_pub` and `nonce` (both
    // exposed via `local/seed`) cannot bypass the anchor gate by
    // POSTing a `JoinResponse` from their own household, because
    // they cannot also produce a valid `LocalAnchor` — the
    // `anchor_secret` only lives in the QR.
    let (f, _m1, _real_secret) = fixture_without_anchor().await;

    // Mint a separate "attacker" household whose response would
    // otherwise self-verify.
    let attacker_dir = tempfile::tempdir().unwrap();
    let attacker = bootstrap(attacker_dir.path());
    let attacker_response = build_join_response(attacker_dir.path(), &attacker, &f.prepared);
    let attacker_bytes = attacker_response.to_canonical_bytes().unwrap();

    // The attacker tries to pin their own household with a fabricated
    // anchor_secret. Refused.
    let body = build_anchor_for(
        &attacker,
        &[0x00; 32],
        attacker.record.hh_pub.as_bytes(),
        attacker.record.hh_id.as_str(),
    );
    let (status, _) = post_anchor(f.router.clone(), body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Without a pinned anchor, finalize is also refused.
    let (status, _) = post_finalize(f.router, attacker_bytes).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn local_anchor_is_idempotent_on_identical_repin() {
    let (f, m1, anchor_secret) = fixture_without_anchor().await;
    let body = build_anchor_for(
        &m1,
        &anchor_secret,
        m1.record.hh_pub.as_bytes(),
        m1.record.hh_id.as_str(),
    );
    let (s1, _) = post_anchor(f.router.clone(), body.clone()).await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, _) = post_anchor(f.router, body).await;
    assert_eq!(s2, StatusCode::OK);
}

#[tokio::test]
async fn local_anchor_rejects_divergent_repin() {
    let (f, m1, anchor_secret) = fixture_without_anchor().await;
    let body1 = build_anchor_for(
        &m1,
        &anchor_secret,
        m1.record.hh_pub.as_bytes(),
        m1.record.hh_id.as_str(),
    );
    let (s1, _) = post_anchor(f.router.clone(), body1).await;
    assert_eq!(s1, StatusCode::OK);

    // Same anchor_secret but different (hh_id, hh_pub). Refused: the
    // first pin wins.
    let other_dir = tempfile::tempdir().unwrap();
    let other = bootstrap(other_dir.path());
    let body2 = build_anchor_for(
        &m1, // re-use m1's hh_priv to sign the cert (cheap fixture)
        &anchor_secret,
        other.record.hh_pub.as_bytes(),
        other.record.hh_id.as_str(),
    );
    let (s2, _) = post_anchor(f.router, body2).await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED);
    let snap = f.window.snapshot().await;
    assert_eq!(
        snap.pinned_hh_pub.as_ref().map(|b| b.as_slice()),
        Some(m1.record.hh_pub.as_bytes().as_slice()),
        "first pin wins"
    );
}
