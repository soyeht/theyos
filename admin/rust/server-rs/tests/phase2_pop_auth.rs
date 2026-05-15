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
use server_rs::household_auth::SoyehtPoP;
use server_rs::household_state::HouseholdState;
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
