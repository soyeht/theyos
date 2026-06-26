use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRegistrationStartResponse {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    options: CreationChallengeResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRegistrationFinishRequest {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    contract: String,
    version: u8,
    start_responses: Vec<VectorCase>,
    finish_requests: Vec<VectorCase>,
}

#[derive(Debug, Deserialize)]
struct VectorCase {
    id: String,
    input: Value,
    canonical_cbor_hex: String,
}

#[test]
fn owner_webauthn_registration_start_response_vectors_are_canonical() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.contract,
        "soyeht-owner-webauthn-registration-cbor-cross-language"
    );
    assert_eq!(fixture.version, 1);
    assert_eq!(fixture.start_responses.len(), 3);

    for vector in &fixture.start_responses {
        let typed: OwnerWebauthnRegistrationStartResponse =
            serde_json::from_value(vector.input.clone()).unwrap();
        assert_canonical_round_trip(vector, &typed);
    }

    let minimal = case_by_id(&fixture.start_responses, "start-minimal");
    assert_eq!(
        json_path(minimal, &["options", "publicKey", "challenge"]),
        "ICEiIyQlJic"
    );
    assert_eq!(
        json_path(minimal, &["options", "publicKey", "user", "id"]),
        "EBESExQVFhc"
    );

    let realistic = case_by_id(&fixture.start_responses, "start-realistic-passkey");
    assert_eq!(
        json_path(
            realistic,
            &[
                "options",
                "publicKey",
                "authenticatorSelection",
                "userVerification",
            ],
        ),
        "required"
    );
    assert!(
        realistic
            .input
            .pointer("/options/publicKey/excludeCredentials")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty),
        "realistic start vector must pin empty excludeCredentials as []",
    );
}

#[test]
fn owner_webauthn_registration_finish_request_vectors_are_canonical() {
    let fixture = load_fixture();
    assert_eq!(fixture.finish_requests.len(), 3);

    for vector in &fixture.finish_requests {
        let typed: OwnerWebauthnRegistrationFinishRequest =
            serde_json::from_value(vector.input.clone()).unwrap();
        assert_canonical_round_trip(vector, &typed);

        let raw_id = typed.credential.raw_id.as_ref();
        assert_eq!(
            typed.credential.id,
            B64URL.encode(raw_id),
            "{} must use base64url(rawId) in credential.id",
            vector.id,
        );
    }

    let minimal = case_by_id(
        &fixture.finish_requests,
        "finish-minimal-null-transports-empty-extensions",
    );
    assert!(
        minimal
            .input
            .pointer("/credential/response/transports")
            .is_some_and(Value::is_null),
        "minimal finish vector must pin transports:null",
    );
    assert!(
        minimal
            .input
            .pointer("/credential/extensions")
            .and_then(Value::as_object)
            .is_some_and(serde_json::Map::is_empty),
        "minimal finish vector must pin extensions:{{}}",
    );

    let transports = case_by_id(&fixture.finish_requests, "finish-with-transports");
    assert_eq!(
        transports
            .input
            .pointer("/credential/response/transports/0")
            .and_then(Value::as_str),
        Some("internal"),
    );
    assert_eq!(
        transports
            .input
            .pointer("/credential/response/transports/1")
            .and_then(Value::as_str),
        Some("hybrid"),
    );
}

fn assert_canonical_round_trip<T>(vector: &VectorCase, typed: &T)
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    let expected = hex::decode(&vector.canonical_cbor_hex).unwrap();
    let encoded = household_rs::cbor::to_canonical_vec(typed).unwrap();
    assert_eq!(
        hex::encode(&encoded),
        vector.canonical_cbor_hex,
        "{} fixture input must encode to the pinned canonical CBOR bytes",
        vector.id,
    );

    let decoded: T = household_rs::cbor::from_canonical_slice(&expected).unwrap();
    let reencoded = household_rs::cbor::to_canonical_vec(&decoded).unwrap();
    assert_eq!(
        reencoded, expected,
        "{} pinned bytes must be a canonical decode/re-encode fixed point",
        vector.id,
    );
}

fn load_fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "data/owner_webauthn_registration_vectors.json"
    ))
    .unwrap()
}

fn case_by_id<'a>(cases: &'a [VectorCase], id: &str) -> &'a VectorCase {
    cases
        .iter()
        .find(|case| case.id == id)
        .unwrap_or_else(|| panic!("missing vector case {id}"))
}

fn json_path<'a>(vector: &'a VectorCase, path: &[&str]) -> &'a str {
    let mut value = &vector.input;
    for segment in path {
        value = value
            .get(*segment)
            .unwrap_or_else(|| panic!("missing path segment {segment} in {}", vector.id));
    }
    value
        .as_str()
        .unwrap_or_else(|| panic!("path {path:?} in {} is not a string", vector.id))
}
