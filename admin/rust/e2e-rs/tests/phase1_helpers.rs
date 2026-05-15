#![allow(dead_code)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]

use std::path::Path;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::{
    Router,
    routing::{get as route_get, post},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL},
};
use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
use household_rs::pair_device::PairDeviceWindow;
use household_rs::{BootstrapOpts, KeyBackingPolicy, LoadedIdentity, derive_household_id};
use serde::Deserialize;
use serde_json::Value;
use server_rs::handlers_household;
use server_rs::handlers_pair_device::{self, PairDeviceState};
use server_rs::household_state::HouseholdState;
use tower::ServiceExt;

#[derive(Debug)]
pub struct TestResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct IdentityBody {
    pub version: u8,
    pub hh_id: String,
    pub hh_pub_b64: String,
    pub name: String,
    pub created_at: u64,
}

#[derive(Debug, Deserialize)]
pub struct InitiateBody {
    pub uri: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmBody {
    #[serde(default)]
    pub v: u8,
    #[serde(default)]
    pub consumed: bool,
    #[serde(default)]
    pub hh_id: String,
    #[serde(default)]
    pub p_id: String,
    #[serde(default)]
    pub person_cert_cbor: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

pub fn bootstrap_identity(
    state_dir: &Path,
    household_name: &str,
    hostname_label: &str,
) -> LoadedIdentity {
    household_rs::bootstrap_or_load(
        state_dir,
        BootstrapOpts {
            household_name: household_name.to_string(),
            hostname_label: Some(hostname_label.to_string()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .expect("bootstrap household identity with software keys")
}

pub fn load_existing_identity(state_dir: &Path) -> LoadedIdentity {
    household_rs::try_load_existing(state_dir, KeyBackingPolicy::ForceSoftware)
        .expect("load existing identity")
        .expect("identity should exist")
}

pub fn identity_router(identity: Option<Arc<LoadedIdentity>>) -> Router {
    let state = match identity {
        Some(identity) => HouseholdState::loaded(identity),
        None => HouseholdState::empty(),
    };
    Router::new()
        .route(
            "/api/v1/household/identity",
            route_get(handlers_household::get_identity),
        )
        .route(
            "/api/v1/household/snapshot",
            route_get(handlers_household::snapshot).post(handlers_household::snapshot),
        )
        .with_state(state)
}

pub fn pair_router(
    window: Arc<PairDeviceWindow>,
    identity: Option<Arc<LoadedIdentity>>,
    state_dir: &Path,
) -> Router {
    let household = match identity {
        Some(identity) => HouseholdState::loaded(identity),
        None => HouseholdState::empty(),
    };
    Router::new()
        .route(
            "/api/v1/household/pair-device/initiate",
            post(handlers_pair_device::initiate),
        )
        .route(
            "/api/v1/household/pair-device/confirm",
            post(handlers_pair_device::confirm),
        )
        .with_state(PairDeviceState {
            window,
            household,
            state_dir: state_dir.to_path_buf(),
        })
}

pub fn household_router(
    identity: Arc<LoadedIdentity>,
    window: Arc<PairDeviceWindow>,
    state_dir: &Path,
) -> Router {
    let household = HouseholdState::loaded(identity);
    let identity_routes = Router::new()
        .route(
            "/api/v1/household/identity",
            route_get(handlers_household::get_identity),
        )
        .route(
            "/api/v1/household/snapshot",
            route_get(handlers_household::snapshot).post(handlers_household::snapshot),
        )
        .with_state(household.clone());
    let pair_routes = Router::new()
        .route(
            "/api/v1/household/pair-device/initiate",
            post(handlers_pair_device::initiate),
        )
        .route(
            "/api/v1/household/pair-device/confirm",
            post(handlers_pair_device::confirm),
        )
        .with_state(PairDeviceState {
            window,
            household,
            state_dir: state_dir.to_path_buf(),
        });
    identity_routes.merge(pair_routes)
}

pub async fn get(app: &Router, path: &str) -> TestResponse {
    request(app, Method::GET, path, Body::empty()).await
}

pub async fn get_with_auth(app: &Router, path: &str, authorization: &str) -> TestResponse {
    request_with_auth(app, Method::GET, path, Body::empty(), authorization).await
}

pub async fn post_body_with_auth(
    app: &Router,
    path: &str,
    body: impl Into<Vec<u8>>,
    authorization: &str,
) -> TestResponse {
    request_with_auth(
        app,
        Method::POST,
        path,
        Body::from(body.into()),
        authorization,
    )
    .await
}

pub async fn post_json(app: &Router, path: &str, value: Value) -> TestResponse {
    let body = Body::from(serde_json::to_vec(&value).expect("serialize json body"));
    request(app, Method::POST, path, body).await
}

pub async fn request(app: &Router, method: Method, path: &str, body: Body) -> TestResponse {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("router response");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read response body")
        .to_vec();
    TestResponse {
        status,
        headers,
        body,
    }
}

pub async fn request_with_auth(
    app: &Router,
    method: Method,
    path: &str,
    body: Body,
    authorization: &str,
) -> TestResponse {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, authorization)
        .body(body)
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("router response");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read response body")
        .to_vec();
    TestResponse {
        status,
        headers,
        body,
    }
}

pub fn parse_identity(resp: &TestResponse) -> IdentityBody {
    serde_json::from_slice(&resp.body).expect("identity json")
}

pub fn parse_initiate(resp: &TestResponse) -> InitiateBody {
    serde_json::from_slice(&resp.body).expect("initiate json")
}

pub fn parse_confirm(resp: &TestResponse) -> ConfirmBody {
    serde_json::from_slice(&resp.body).expect("confirm json")
}

pub fn assert_identity_contract(body: &IdentityBody, expected_name: &str) -> P256PublicKey {
    assert_eq!(body.version, 1);
    assert_eq!(body.name, expected_name);
    assert_ne!(body.created_at, 0);
    let hh_pub = B64.decode(&body.hh_pub_b64).expect("base64 hh_pub");
    assert_eq!(hh_pub.len(), P256PublicKey::LEN);
    let hh_pub = P256PublicKey::from_bytes(&hh_pub).expect("valid SEC1 hh_pub");
    assert_eq!(body.hh_id, derive_household_id(&hh_pub).to_string());
    hh_pub
}

pub fn uri_param(uri: &str, key: &str) -> Option<String> {
    let query = uri.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| v.to_string())
    })
}

pub fn fake_device_pub_b64() -> String {
    B64URL.encode(P256Keypair::generate().public().as_bytes())
}
