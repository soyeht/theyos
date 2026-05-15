//! T055 integration coverage for
//! `POST /api/v1/household/owner-device/push-token`.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use axum::{Router, routing::post};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::owner_events::{OwnerEventLog, OwnerEventsBroadcaster, get_owner_push_token};
use household_rs::pair_machine::PairMachineWindow;
use household_rs::person_cert::{PersonCert, SignOwnerOptions};
use household_rs::pop::RequestSigningContext;
use household_rs::{BootstrapOpts, HouseholdAuthState, KeyBackingPolicy};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use server_rs::handlers_owner_events::{self, OwnerEventsRouterState};
use server_rs::household_state::HouseholdState;
use tempfile::TempDir;
use tower::ServiceExt;

const PUSH_TOKEN_PATH: &str = "/api/v1/household/owner-device/push-token";

#[derive(Serialize)]
struct PushTokenRegisterRequest {
    #[serde(rename = "v")]
    version: u8,
    platform: String,
    push_token: ByteBuf,
}

#[derive(Serialize)]
struct MissingPlatformRequest {
    #[serde(rename = "v")]
    version: u8,
    push_token: ByteBuf,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
struct PushTokenRegisterResponse {
    #[serde(rename = "v")]
    version: u8,
    updated_at: u64,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
struct GenericUnauth {
    #[serde(rename = "v")]
    version: u8,
    error: String,
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

fn router_with_state() -> (TempDir, Router, P256Keypair) {
    let td = tempfile::tempdir().unwrap();
    let identity = Arc::new(bootstrap(td.path()));
    let (owner_auth, person) = owner_auth_for(&identity);
    let household =
        HouseholdState::loaded_with_owner_auth(Arc::clone(&identity), Some(Arc::new(owner_auth)));
    let broadcaster = OwnerEventsBroadcaster::new();
    let event_log =
        OwnerEventLog::open_with_broadcaster(td.path().to_path_buf(), broadcaster.clone()).unwrap();
    let window = Arc::new(PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap());
    let state = OwnerEventsRouterState::with_timeout(
        household,
        window,
        event_log,
        broadcaster,
        td.path().to_path_buf(),
        household_rs::KeyBackingPolicy::ForceSoftware,
        Duration::from_secs(45),
    );
    let router = Router::new()
        .route(
            PUSH_TOKEN_PATH,
            post(handlers_owner_events::push_token_register_handler),
        )
        .with_state(state);
    (td, router, person)
}

fn pop_header(person: &P256Keypair, timestamp: u64, body: &[u8]) -> String {
    let ctx = RequestSigningContext::new("POST", PUSH_TOKEN_PATH, timestamp, body);
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
        .uri(PUSH_TOKEN_PATH)
        .header(header::CONTENT_TYPE, "application/cbor");
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

fn register_body(token: Vec<u8>) -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&PushTokenRegisterRequest {
        version: 1,
        platform: "ios".into(),
        push_token: ByteBuf::from(token),
    })
    .unwrap()
}

#[tokio::test]
async fn register_happy_path_persists_token() {
    let (td, router, person) = router_with_state();
    let body = register_body(vec![7u8; 32]);

    let (status, resp_bytes) = post_cbor(router, body, Some(&person)).await;

    assert_eq!(status, StatusCode::OK);
    let parsed: PushTokenRegisterResponse =
        household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.version, 1);
    assert!(parsed.updated_at > 0);
    let token = get_owner_push_token(td.path()).unwrap().unwrap();
    assert_eq!(token.platform, "ios");
    assert_eq!(token.push_token.as_ref(), &[7u8; 32]);
}

#[tokio::test]
async fn rotation_overwrites_previous_token() {
    let (td, router, person) = router_with_state();

    let (status, _) = post_cbor(router.clone(), register_body(vec![1u8; 32]), Some(&person)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = post_cbor(router, register_body(vec![2u8; 32]), Some(&person)).await;
    assert_eq!(status, StatusCode::OK);

    let token = get_owner_push_token(td.path()).unwrap().unwrap();
    assert_eq!(token.push_token.as_ref(), &[2u8; 32]);
}

#[tokio::test]
async fn non_owner_pop_returns_generic_401() {
    let (_td, router, _person) = router_with_state();
    let non_owner = P256Keypair::generate();
    let body = register_body(vec![3u8; 32]);

    let (status, resp_bytes) = post_cbor(router, body, Some(&non_owner)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.error, "unauthenticated");
}

#[tokio::test]
async fn missing_platform_returns_generic_401() {
    let (_td, router, person) = router_with_state();
    let body = household_rs::cbor::to_canonical_vec(&MissingPlatformRequest {
        version: 1,
        push_token: ByteBuf::from(vec![4u8; 32]),
    })
    .unwrap();

    let (status, resp_bytes) = post_cbor(router, body, Some(&person)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth = household_rs::cbor::from_canonical_slice(&resp_bytes).unwrap();
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.error, "unauthenticated");
}
