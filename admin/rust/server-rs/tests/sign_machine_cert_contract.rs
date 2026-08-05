//! Contract tests for `POST /api/v1/household/sign-machine-cert`.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::household_lifecycle::HouseholdLifecycleLock;
use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey, P256Signature};
use household_rs::machine_cert::{MachineCert, Platform};
use household_rs::owner_events::{
    OwnerEventLog, OwnerEventPayload, OwnerEventType, OwnerEventsBroadcaster,
};
use household_rs::person_cert::{PersonCert, SignOwnerOptions};
use household_rs::pop::RequestSigningContext;
use household_rs::{
    BootstrapOpts, HouseholdAuthState, KeyBackingPolicy, LoadedIdentity, MachineId,
    derive_machine_id,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use server_rs::handlers_sign_machine_cert::{SignMachineCertRouterState, sign_machine_cert_router};
use server_rs::household_state::HouseholdState;
use tower::ServiceExt;

const PATH: &str = "/api/v1/household/sign-machine-cert";

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn bootstrap(state_dir: &std::path::Path) -> LoadedIdentity {
    household_rs::bootstrap_or_load(
        state_dir,
        BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some("linux-founder".into()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .unwrap()
}

fn owner_auth_for(identity: &LoadedIdentity) -> (HouseholdAuthState, P256Keypair) {
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

fn router_with_identity(
    state_dir: &std::path::Path,
    identity: LoadedIdentity,
    owner_auth: Option<HouseholdAuthState>,
) -> axum::Router {
    let expected_hh_id = identity.record.hh_id.to_string();
    let owner_auth = owner_auth.map(Arc::new);
    let household = HouseholdState::loaded_with_owner_auth(Arc::new(identity), owner_auth);
    let lifecycle = HouseholdLifecycleLock::open_verified(state_dir).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    let event_log = OwnerEventLog::open_with_broadcaster_under_lifecycle(
        &write,
        state_dir.to_path_buf(),
        &expected_hh_id,
        OwnerEventsBroadcaster::new(),
    )
    .unwrap();
    drop(write);
    sign_machine_cert_router(SignMachineCertRouterState {
        household,
        event_log,
        state_dir: state_dir.to_path_buf(),
    })
}

fn router_with_state(state_dir: &std::path::Path) -> (axum::Router, LoadedIdentity, P256Keypair) {
    let identity = bootstrap(state_dir);
    let (owner_auth, person) = owner_auth_for(&identity);
    let router = router_with_identity(
        state_dir,
        clone_loaded_for_test(&identity),
        Some(owner_auth),
    );
    (router, identity, person)
}

fn clone_loaded_for_test(identity: &LoadedIdentity) -> LoadedIdentity {
    let m_secret = identity.m_priv.as_software_secret().unwrap();
    let m_priv = P256Keypair::from_secret_scalar(m_secret).unwrap();
    let hh_priv = identity.hh_priv.as_ref().map(|key| {
        let secret = key.as_software_secret().unwrap();
        Box::new(P256Keypair::from_secret_scalar(secret).unwrap()) as Box<dyn IdentityKey>
    });
    LoadedIdentity {
        record: identity.record.clone(),
        cert: identity.cert.clone(),
        hh_priv,
        m_priv: Box::new(m_priv),
        backing: identity.backing,
    }
}

#[derive(Clone)]
struct SubjectFixture {
    m_id: MachineId,
    m_pub: P256PublicKey,
}

fn subject_fixture() -> SubjectFixture {
    let machine = P256Keypair::generate();
    let m_pub = machine.public();
    let m_id = derive_machine_id(&m_pub);
    SubjectFixture { m_id, m_pub }
}

#[derive(Serialize)]
struct SignReq<'a> {
    #[serde(rename = "v")]
    version: u8,
    kind: &'a str,
    subject: SubjectReq<'a>,
    challenge: &'a serde_bytes::Bytes,
}

#[derive(Serialize)]
struct SubjectReq<'a> {
    m_id: &'a str,
    m_pub: &'a serde_bytes::Bytes,
    hostname: &'a str,
    platform: &'a str,
}

fn cbor_req(subject: &SubjectFixture, challenge: &[u8]) -> Vec<u8> {
    cbor_req_with(
        subject.m_id.as_str(),
        subject.m_pub.as_bytes(),
        "new-mac",
        "macos",
        "machine",
        challenge,
    )
}

fn cbor_req_with(
    m_id: &str,
    m_pub: &[u8],
    hostname: &str,
    platform: &str,
    kind: &str,
    challenge: &[u8],
) -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&SignReq {
        version: 1,
        kind,
        subject: SubjectReq {
            m_id,
            m_pub: serde_bytes::Bytes::new(m_pub),
            hostname,
            platform,
        },
        challenge: serde_bytes::Bytes::new(challenge),
    })
    .unwrap()
}

fn cbor_req_with_extra(subject: &SubjectFixture, challenge: &[u8]) -> Vec<u8> {
    #[derive(Serialize)]
    struct Req<'a> {
        #[serde(rename = "v")]
        version: u8,
        kind: &'a str,
        subject: SubjectReq<'a>,
        challenge: &'a serde_bytes::Bytes,
        extra: u8,
    }
    household_rs::cbor::to_canonical_vec(&Req {
        version: 1,
        kind: "machine",
        subject: SubjectReq {
            m_id: subject.m_id.as_str(),
            m_pub: serde_bytes::Bytes::new(subject.m_pub.as_bytes()),
            hostname: "new-mac",
            platform: "macos",
        },
        challenge: serde_bytes::Bytes::new(challenge),
        extra: 1,
    })
    .unwrap()
}

fn pop_header(person: &P256Keypair, timestamp: u64, body: &[u8]) -> String {
    let ctx = RequestSigningContext::new("POST", PATH, timestamp, body);
    let sig = person.sign(&ctx.canonical_bytes().unwrap()).unwrap();
    format!(
        "Soyeht-PoP v1:{}:{}:{}",
        household_rs::derive_person_id(&person.public()).0,
        timestamp,
        B64URL.encode(sig.as_bytes())
    )
}

async fn post_cbor(
    router: axum::Router,
    body: Vec<u8>,
    person: Option<&P256Keypair>,
) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(PATH)
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

#[derive(Deserialize)]
struct OkBody {
    #[serde(rename = "v")]
    version: u8,
    machine_cert: ByteBuf,
    challenge_signature: ByteBuf,
    m_id: String,
    joined_at: u64,
}

#[derive(Deserialize)]
struct ErrBody {
    #[serde(rename = "v")]
    version: u8,
    error: String,
}

fn decode_ok(bytes: &[u8]) -> OkBody {
    household_rs::cbor::from_canonical_slice(bytes).unwrap()
}

fn decode_err(bytes: &[u8]) -> ErrBody {
    household_rs::cbor::from_canonical_slice(bytes).unwrap()
}

#[tokio::test]
async fn sign_machine_cert_happy_path_returns_verifiable_cert_and_audit_event() {
    let td = tempfile::tempdir().unwrap();
    let (router, identity, person) = router_with_state(td.path());
    let subject = subject_fixture();
    let challenge = b"canonical join challenge bytes";
    let body = cbor_req(&subject, challenge);

    let (status, resp) = post_cbor(router, body, Some(&person)).await;

    assert_eq!(status, StatusCode::OK, "body: {resp:?}");
    let ok = decode_ok(&resp);
    assert_eq!(ok.version, 1);
    assert_eq!(ok.m_id, subject.m_id.to_string());
    assert!(ok.joined_at >= identity.record.created_at);

    let cert: MachineCert = household_rs::cbor::from_canonical_slice(&ok.machine_cert).unwrap();
    assert_eq!(cert.hh_id, identity.record.hh_id);
    assert_eq!(cert.m_id, subject.m_id);
    assert_eq!(cert.m_pub, subject.m_pub);
    assert_eq!(cert.hostname, "new-mac");
    assert_eq!(cert.platform, Platform::Macos);
    assert_eq!(cert.joined_at, ok.joined_at);
    cert.verify(&identity.record.hh_pub).unwrap();
    household_rs::keys::verify_signature(
        &identity.record.hh_pub,
        &cert.signing_bytes().unwrap(),
        &cert.signature,
    )
    .unwrap();

    let challenge_sig = P256Signature::from_bytes(&ok.challenge_signature).unwrap();
    household_rs::keys::verify_signature(&identity.record.hh_pub, challenge, &challenge_sig)
        .unwrap();

    let lifecycle = HouseholdLifecycleLock::open_verified(td.path()).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    let log = OwnerEventLog::open_under_lifecycle(
        &write,
        td.path().to_path_buf(),
        &identity.record.hh_id.to_string(),
    )
    .unwrap();
    drop(write);
    let read = lifecycle.lock_shared().unwrap();
    let events = log.read_since(&read, 0).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].event_type,
        OwnerEventType::SignMachineCertForProxy
    );
    match &events[0].payload {
        OwnerEventPayload::SignMachineCertForProxy(payload) => {
            assert_eq!(
                payload.actor_person_id,
                household_rs::derive_person_id(&person.public()).0
            );
            assert_eq!(payload.target_m_id, ok.m_id);
            assert_eq!(payload.hostname, "new-mac");
            assert_eq!(payload.platform, "macos");
            assert_eq!(payload.joined_at, ok.joined_at);
        }
        other => panic!("unexpected payload: {other:?}"),
    }
}

#[tokio::test]
async fn sign_machine_cert_400_on_malformed_or_unknown_key_cbor() {
    let td = tempfile::tempdir().unwrap();
    let (router, _identity, person) = router_with_state(td.path());
    let (status, body) = post_cbor(router, b"not cbor".to_vec(), Some(&person)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let err = decode_err(&body);
    assert_eq!(err.version, 1);
    assert_eq!(err.error, "invalid_cbor");

    let td = tempfile::tempdir().unwrap();
    let (router, _identity, person) = router_with_state(td.path());
    let subject = subject_fixture();
    let body = cbor_req_with_extra(&subject, b"challenge");
    let (status, body) = post_cbor(router, body, Some(&person)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(decode_err(&body).error, "invalid_cbor");
}

#[tokio::test]
async fn sign_machine_cert_400_on_invalid_subject_variants() {
    let subject = subject_fixture();
    let other = subject_fixture();
    let cases = [
        cbor_req_with(
            subject.m_id.as_str(),
            &[0x02; 32],
            "new-mac",
            "macos",
            "machine",
            b"challenge",
        ),
        cbor_req_with(
            other.m_id.as_str(),
            subject.m_pub.as_bytes(),
            "new-mac",
            "macos",
            "machine",
            b"challenge",
        ),
        cbor_req_with(
            subject.m_id.as_str(),
            subject.m_pub.as_bytes(),
            "",
            "macos",
            "machine",
            b"challenge",
        ),
        cbor_req_with(
            subject.m_id.as_str(),
            subject.m_pub.as_bytes(),
            "new-mac",
            "ios",
            "machine",
            b"challenge",
        ),
        cbor_req_with(
            subject.m_id.as_str(),
            subject.m_pub.as_bytes(),
            "new-mac",
            "macos",
            "person",
            b"challenge",
        ),
    ];

    for body in cases {
        let td = tempfile::tempdir().unwrap();
        let (router, _identity, person) = router_with_state(td.path());
        let (status, body) = post_cbor(router, body, Some(&person)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(decode_err(&body).error, "invalid_subject");
    }
}

#[tokio::test]
async fn sign_machine_cert_401_on_invalid_pop() {
    let td = tempfile::tempdir().unwrap();
    let (router, _identity, _person) = router_with_state(td.path());
    let body = cbor_req(&subject_fixture(), b"challenge");

    let (status, resp) = post_cbor(router, body, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(decode_err(&resp).error, "invalid_pop");
}

#[tokio::test]
async fn sign_machine_cert_403_when_pop_signer_is_not_member() {
    let td = tempfile::tempdir().unwrap();
    let (router, _identity, _person) = router_with_state(td.path());
    let outsider = P256Keypair::generate();
    let body = cbor_req(&subject_fixture(), b"challenge");

    let (status, resp) = post_cbor(router, body, Some(&outsider)).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(decode_err(&resp).error, "not_a_member");
}

#[tokio::test]
async fn sign_machine_cert_409_without_local_household_private_key_or_follower() {
    let td = tempfile::tempdir().unwrap();
    let identity = bootstrap(td.path());
    let (owner_auth, person) = owner_auth_for(&identity);
    let mut follower = clone_loaded_for_test(&identity);
    follower.record.is_follower = true;
    follower.record.shamir_k = 0;
    follower.record.shamir_n = 0;
    follower.hh_priv = None;
    let router = router_with_identity(td.path(), follower, Some(owner_auth));
    let body = cbor_req(&subject_fixture(), b"challenge");

    let (status, resp) = post_cbor(router, body, Some(&person)).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(decode_err(&resp).error, "household_not_initialized");
}

#[tokio::test]
async fn sign_machine_cert_500_when_audit_append_fails() {
    let td = tempfile::tempdir().unwrap();
    let (router, _identity, person) = router_with_state(td.path());
    let owner_events_path = household_rs::storage::household_dir(td.path()).join("owner_events");
    std::fs::write(&owner_events_path, b"not a directory").unwrap();
    let body = cbor_req(&subject_fixture(), b"challenge");

    let (status, resp) = post_cbor(router, body, Some(&person)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(decode_err(&resp).error, "internal_error");
}
