use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::Value;
use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRegistrationStartRequest {
    #[serde(rename = "v")]
    version: u8,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRegistrationFinishResponse {
    #[serde(rename = "v")]
    version: u8,
    credential_id: ByteBuf,
    active_credential_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRegistrationStatusRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRegistrationStatusResponse {
    #[serde(rename = "v")]
    version: u8,
    enrolled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenericError {
    #[serde(rename = "v")]
    version: u8,
    error: String,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    contract: String,
    version: u8,
    start_requests: Vec<VectorCase>,
    start_responses: Vec<VectorCase>,
    finish_requests: Vec<VectorCase>,
    finish_responses: Vec<FinishResponseVector>,
    status_requests: Vec<VectorCase>,
    status_responses: Vec<VectorCase>,
    registration_rejects: Vec<RejectVector>,
}

#[derive(Debug, Deserialize)]
struct VectorCase {
    id: String,
    input: Value,
    canonical_cbor_hex: String,
}

#[derive(Debug, Deserialize)]
struct FinishResponseVector {
    id: String,
    credential_id_hex: String,
    active_credential_count: u64,
    canonical_cbor_hex: String,
}

#[derive(Debug, Deserialize)]
struct RejectVector {
    id: String,
    status: u16,
    content_type: String,
    input: Value,
    canonical_cbor_hex: String,
}

#[test]
fn owner_webauthn_registration_start_request_vectors_are_canonical() {
    let fixture = load_fixture();
    assert_eq!(fixture.start_requests.len(), 1);

    for vector in &fixture.start_requests {
        let typed: OwnerWebauthnRegistrationStartRequest =
            serde_json::from_value(vector.input.clone()).unwrap();
        assert_canonical_round_trip(vector, &typed);
    }

    let start = case_by_id(&fixture.start_requests, "start-request-v1");
    assert_eq!(start.input.get("v").and_then(Value::as_u64), Some(1));
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

#[test]
fn owner_webauthn_registration_finish_response_vectors_are_canonical() {
    let fixture = load_fixture();
    assert_eq!(fixture.finish_responses.len(), 1);

    for vector in &fixture.finish_responses {
        let credential_id = hex::decode(&vector.credential_id_hex).unwrap();
        let typed = OwnerWebauthnRegistrationFinishResponse {
            version: 1,
            credential_id: ByteBuf::from(credential_id.clone()),
            active_credential_count: vector.active_credential_count,
        };
        let expected = hex::decode(&vector.canonical_cbor_hex).unwrap();
        let encoded = household_rs::cbor::to_canonical_vec(&typed).unwrap();
        assert_eq!(
            encoded, expected,
            "{} fixture input must encode to the pinned canonical CBOR bytes",
            vector.id,
        );

        let decoded: OwnerWebauthnRegistrationFinishResponse =
            household_rs::cbor::from_canonical_slice(&expected).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.credential_id.as_ref(), credential_id.as_slice());
        assert_eq!(
            decoded.active_credential_count,
            vector.active_credential_count
        );
        assert_eq!(
            household_rs::cbor::to_canonical_vec(&decoded).unwrap(),
            expected,
            "{} pinned bytes must be a canonical decode/re-encode fixed point",
            vector.id,
        );

        assert!(
            credential_id.len() <= 23,
            "fixture assertion only covers single-byte CBOR byte-string lengths"
        );
        let credential_id_byte_string_hex = format!(
            "6d63726564656e7469616c5f6964{:02x}{}",
            0x40 + credential_id.len(),
            vector.credential_id_hex
        );
        assert!(
            vector
                .canonical_cbor_hex
                .contains(&credential_id_byte_string_hex),
            "{} should pin credential_id as a CBOR byte string, not base64url text",
            vector.id,
        );
    }
}

#[test]
fn owner_webauthn_registration_status_vectors_are_canonical() {
    let fixture = load_fixture();
    assert_eq!(fixture.status_requests.len(), 1);
    assert_eq!(fixture.status_responses.len(), 2);

    for vector in &fixture.status_requests {
        let typed: OwnerWebauthnRegistrationStatusRequest =
            serde_json::from_value(vector.input.clone()).unwrap();
        assert_canonical_round_trip(vector, &typed);
    }

    for vector in &fixture.status_responses {
        let typed: OwnerWebauthnRegistrationStatusResponse =
            serde_json::from_value(vector.input.clone()).unwrap();
        assert_canonical_round_trip(vector, &typed);
    }

    let never_enrolled = case_by_id(&fixture.status_responses, "status-response-never-enrolled");
    assert_eq!(
        never_enrolled
            .input
            .get("enrolled")
            .and_then(Value::as_bool),
        Some(false),
    );
    let enrolled = case_by_id(&fixture.status_responses, "status-response-enrolled");
    assert_eq!(
        enrolled.input.get("enrolled").and_then(Value::as_bool),
        Some(true),
    );
}

#[test]
fn owner_webauthn_registration_reject_vectors_are_canonical() {
    let fixture = load_fixture();
    assert_eq!(fixture.registration_rejects.len(), 1);

    let reject = &fixture.registration_rejects[0];
    assert_eq!(reject.id, "registration-reject-unauthenticated");
    assert_eq!(reject.status, 401);
    assert_eq!(reject.content_type, "application/cbor");
    let typed: GenericError = serde_json::from_value(reject.input.clone()).unwrap();
    assert_eq!(typed.version, 1);
    assert_eq!(typed.error, "unauthenticated");

    let expected = hex::decode(&reject.canonical_cbor_hex).unwrap();
    let encoded = household_rs::cbor::to_canonical_vec(&typed).unwrap();
    assert_eq!(encoded, expected);
    let decoded: GenericError = household_rs::cbor::from_canonical_slice(&expected).unwrap();
    assert_eq!(decoded.error, "unauthenticated");
    assert_eq!(
        household_rs::cbor::to_canonical_vec(&decoded).unwrap(),
        expected
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
