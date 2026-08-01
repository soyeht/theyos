use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::{Router, routing::get};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::person_cert::SignOwnerOptions;
use household_rs::pop::RequestSigningContext;
use household_rs::{BootstrapOpts, HouseholdAuthState, KeyBackingPolicy, PersonCert};
use server_rs::handlers_household;
use server_rs::handlers_household::MachinesRouterState;
use server_rs::household_auth::SoyehtPoP;
use server_rs::household_state::HouseholdState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tower::ServiceExt;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn fixture() -> (Router, P256Keypair, household_rs::LoadedIdentity) {
    let td = tempfile::tempdir().unwrap();
    let identity = household_rs::bootstrap_or_load(
        td.path(),
        BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some("studio-test".into()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .unwrap();
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
    let auth = HouseholdAuthState::new(&identity.record, cert);
    let state = HouseholdState::loaded_with_owner_auth(
        Arc::new(identity_for_state(&identity)),
        Some(Arc::new(auth)),
    );
    let app = Router::new()
        .route(
            "/api/v1/household/snapshot",
            get(handlers_household::snapshot),
        )
        .with_state(state);
    (app, person, identity)
}

fn identity_for_state(identity: &household_rs::LoadedIdentity) -> household_rs::LoadedIdentity {
    household_rs::LoadedIdentity {
        record: identity.record.clone(),
        cert: identity.cert.clone(),
        hh_priv: Some(Box::new(
            P256Keypair::from_secret_scalar(
                identity
                    .hh_priv
                    .as_ref()
                    .and_then(|k| k.as_software_secret())
                    .expect("software hh_priv in single-machine household"),
            )
            .unwrap(),
        )),
        m_priv: Box::new(
            P256Keypair::from_secret_scalar(identity.m_priv.as_software_secret().unwrap()).unwrap(),
        ),
        backing: identity.backing,
    }
}

fn pop_header(person: &P256Keypair, path: &str, timestamp: u64, body: &[u8]) -> String {
    let ctx = RequestSigningContext::new("GET", path, timestamp, body);
    let sig = person.sign(&ctx.canonical_bytes().unwrap()).unwrap();
    format!(
        "Soyeht-PoP v1:{}:{}:{}",
        household_rs::derive_person_id(&person.public()).0,
        timestamp,
        B64URL.encode(sig.as_bytes())
    )
}

#[test]
fn parser_rejects_bearer_and_accepts_soyeht_pop_shape() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
    assert!(SoyehtPoP::parse(&headers).is_err());

    headers.insert(
        header::AUTHORIZATION,
        "Soyeht-PoP v1:not-a-person:1714972800:abc".parse().unwrap(),
    );
    assert!(SoyehtPoP::parse(&headers).is_err());

    let person = P256Keypair::generate();
    let header = pop_header(&person, "/api/v1/household/snapshot", unix_now(), b"");
    headers.insert(header::AUTHORIZATION, header.parse().unwrap());
    let parsed = SoyehtPoP::parse(&headers).unwrap();
    assert_eq!(
        parsed.p_id,
        household_rs::derive_person_id(&person.public()).0
    );
}

#[tokio::test]
async fn snapshot_accepts_valid_pop_and_rejects_wrong_path() {
    let (app, person, _identity) = fixture();
    let now = unix_now();
    let valid = pop_header(&person, "/api/v1/household/snapshot", now, b"");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/household/snapshot")
                .header(header::AUTHORIZATION, valid)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let wrong = pop_header(&person, "/api/v1/household/other", now, b"");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/household/snapshot")
                .header(header::AUTHORIZATION, wrong)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn shared_listener_router_still_requires_owner_pop_for_snapshot() {
    let (app, _person, _identity) = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(
            b"GET /api/v1/household/snapshot HTTP/1.1\r\nHost: mesh-test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    server.abort();

    assert!(response.starts_with(b"HTTP/1.1 401 "));
}

/// Build a router serving `/api/v1/household/machines` plus the persisted
/// household state on disk (the `TempDir` is returned so its lifetime spans the
/// test — the handler reads `machine_certs/<m_id>.cbor` from it).
fn machines_fixture() -> (
    Router,
    P256Keypair,
    tempfile::TempDir,
    household_rs::LoadedIdentity,
) {
    let td = tempfile::tempdir().unwrap();
    let identity = household_rs::bootstrap_or_load(
        td.path(),
        BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some("Mac Studio".into()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .unwrap();
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
    let auth = HouseholdAuthState::new(&identity.record, cert);
    let household = HouseholdState::loaded_with_owner_auth(
        Arc::new(identity_for_state(&identity)),
        Some(Arc::new(auth)),
    );
    let app = Router::new()
        .route(
            "/api/v1/household/machines",
            get(handlers_household::machines),
        )
        .with_state(MachinesRouterState {
            household,
            state_dir: td.path().to_path_buf(),
        });
    (app, person, td, identity)
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn machines_owner_auth_ok_returns_self_machine() {
    let (app, person, td, identity) = machines_fixture();
    let now = unix_now();
    let valid = pop_header(&person, "/api/v1/household/machines", now, b"");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/household/machines")
                .header(header::AUTHORIZATION, valid)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let raw = body_string(resp).await;
    let json: serde_json::Value = serde_json::from_str(&raw).unwrap();

    assert_eq!(json["v"], 1);
    assert_eq!(json["hh_id"], identity.record.hh_id.to_string());

    let expected_self = household_rs::storage::read_self_m_id(td.path())
        .unwrap()
        .unwrap();
    assert_eq!(expected_self, identity.cert.m_id.to_string());
    assert_eq!(json["self_m_id"], expected_self);

    let machines = json["machines"].as_array().unwrap();
    let self_entry = machines
        .iter()
        .find(|m| m["is_self"] == true)
        .expect("self machine entry present");
    assert_eq!(self_entry["machine_id"], expected_self);
    assert_eq!(
        self_entry["machine_pub"],
        hex::encode(identity.cert.m_pub.as_bytes())
    );
    assert_eq!(self_entry["host_label"], "Mac Studio");
    let expected_platform = serde_json::to_value(&identity.cert.platform).unwrap();
    assert_eq!(self_entry["platform"], expected_platform);
    assert_eq!(self_entry["joined_at"], identity.cert.joined_at);
    assert_eq!(
        self_entry["capabilities"],
        serde_json::json!(["engine", "pty", "clawsite"])
    );
}

#[tokio::test]
async fn machines_no_auth_denied() {
    let (app, _person, _td, _identity) = machines_fixture();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/household/machines")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn machines_non_owner_pop_denied() {
    let (app, _owner, _td, _identity) = machines_fixture();
    let now = unix_now();
    // PoP signed by a key that is NOT the household owner.
    let stranger = P256Keypair::generate();
    let forged = pop_header(&stranger, "/api/v1/household/machines", now, b"");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/household/machines")
                .header(header::AUTHORIZATION, forged)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn machines_wrong_path_pop_denied() {
    let (app, person, _td, _identity) = machines_fixture();
    let now = unix_now();
    // PoP bound to a different path → signature won't verify for /machines.
    let wrong_path = pop_header(&person, "/api/v1/household/other", now, b"");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/household/machines")
                .header(header::AUTHORIZATION, wrong_path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn machines_response_has_no_secret_fields() {
    let (app, person, _td, _identity) = machines_fixture();
    let now = unix_now();
    let valid = pop_header(&person, "/api/v1/household/machines", now, b"");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/household/machines")
                .header(header::AUTHORIZATION, valid)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let raw = body_string(resp).await;
    for forbidden in [
        "signature",
        "priv",
        "secret",
        "shard",
        "token",
        "addr",
        "port",
        "endpoint",
        "hh_priv",
        "m_priv",
    ] {
        assert!(
            !raw.contains(forbidden),
            "machines response leaked forbidden token `{forbidden}`: {raw}"
        );
    }
}
