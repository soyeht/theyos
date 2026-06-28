//! AddCredential dual-ceremony wire CBOR cross-language golden vectors.
//!
//! This pins the composite wrappers around already-vectorized sub-shapes:
//! registration start/finish, owner approval-v2 start/finish, and the
//! AddCredential owner-approval context.

use household_rs::ids::HouseholdId;
use household_rs::machine_cert::PersonId;
use household_rs::owner_approval_v2::{
    AddCredentialContextInput, OwnerApprovalContextV2, OwnerApprovalV2,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_bytes::ByteBuf;
use serde_json::Value;
use webauthn_rs::prelude::{
    CreationChallengeResponse, RegisterPublicKeyCredential, RequestChallengeResponse,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    contract: String,
    version: u8,
    add_credential_start_responses: Vec<StartResponseVector>,
    add_credential_finish_requests: Vec<FinishRequestVector>,
}

#[derive(Debug, Deserialize)]
struct StartResponseVector {
    id: String,
    input: StartResponseInput,
    canonical_cbor_hex: String,
}

#[derive(Debug, Deserialize)]
struct FinishRequestVector {
    id: String,
    input: FinishRequestInput,
    canonical_cbor_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartResponseInput {
    #[serde(rename = "v")]
    version: u8,
    registration: RegistrationStartResponseInput,
    approval: ApprovalStartResponseInput,
    context: AddCredentialContextInputJson,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishRequestInput {
    #[serde(rename = "v")]
    version: u8,
    context: AddCredentialContextInputJson,
    registration: RegistrationFinishRequestInput,
    approval: ApprovalFinishInput,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationStartResponseInput {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    options: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalStartResponseInput {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    context: AddCredentialContextInputJson,
    options: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationFinishRequestInput {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    credential: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalFinishInput {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    approval: ApprovalInput,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalInput {
    #[serde(rename = "v")]
    version: u8,
    context: AddCredentialContextInputJson,
    credential_id_hex: String,
    authenticator_data_hex: String,
    client_data_json_hex: String,
    signature_hex: String,
    user_handle_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AddCredentialContextInputJson {
    #[serde(rename = "v")]
    version: u8,
    purpose: String,
    op: String,
    hh_id: String,
    owner_p_id: String,
    new_credential_binding_hash_hex: String,
    authority_head_sequence: u64,
    authority_head_hash_hex: String,
    pre_active_credential_count: u64,
    capabilities: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    replay_nonce_hex: String,
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
struct OwnerApprovalV2StartResponse {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    context: OwnerApprovalContextV2,
    options: RequestChallengeResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerApprovalV2Finish {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    approval: OwnerApprovalV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnAddCredentialStartResponse {
    #[serde(rename = "v")]
    version: u8,
    registration: OwnerWebauthnRegistrationStartResponse,
    approval: OwnerApprovalV2StartResponse,
    context: OwnerApprovalContextV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnAddCredentialFinishRequest {
    #[serde(rename = "v")]
    version: u8,
    context: OwnerApprovalContextV2,
    registration: OwnerWebauthnRegistrationFinishRequest,
    approval: OwnerApprovalV2Finish,
}

#[test]
fn add_credential_start_response_vector_is_canonical() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.contract,
        "soyeht-owner-webauthn-add-credential-wire-cbor-cross-language"
    );
    assert_eq!(fixture.version, 1);
    assert_eq!(fixture.add_credential_start_responses.len(), 1);

    let vector = &fixture.add_credential_start_responses[0];
    let start = start_response_from_input(&vector.input);
    assert_eq!(vector.input.approval.context, vector.input.context);
    assert_eq!(start.approval.context, start.context);
    start.context.validate_shape().unwrap();

    let encoded =
        assert_canonical_round_trip(vector.id.as_str(), &vector.canonical_cbor_hex, &start);
    let encoded_hex = hex::encode(encoded);

    assert!(
        encoded_hex.contains(&cbor_text_hex("registration")),
        "{} must include the nested registration block",
        vector.id
    );
    assert!(
        encoded_hex.contains(&cbor_text_hex("approval")),
        "{} must include the nested approval block",
        vector.id
    );
    assert!(
        encoded_hex.contains(&cbor_text_hex("QEFCQ0RFRkdISUpLTE1OTw")),
        "{} must preserve registration challenge as base64url text",
        vector.id
    );
    assert!(
        encoded_hex.contains(&cbor_text_hex("AQIDBAUGBwg")),
        "{} must preserve approval challenge as base64url text inside options",
        vector.id
    );
    assert_byte_field(
        vector.id.as_str(),
        &hex::decode(encoded_hex).unwrap(),
        "new_credential_binding_hash",
        &vector.input.context.new_credential_binding_hash_hex,
    );
}

#[test]
fn add_credential_finish_request_vector_is_canonical() {
    let fixture = load_fixture();
    assert_eq!(fixture.add_credential_finish_requests.len(), 1);

    let vector = &fixture.add_credential_finish_requests[0];
    let finish = finish_request_from_input(&vector.input);
    assert_eq!(vector.input.approval.approval.context, vector.input.context);
    assert_eq!(finish.approval.approval.context, finish.context);
    finish.context.validate_shape().unwrap();
    finish.approval.approval.validate_shape().unwrap();

    let encoded =
        assert_canonical_round_trip(vector.id.as_str(), &vector.canonical_cbor_hex, &finish);
    let encoded_hex = hex::encode(&encoded);

    assert!(
        encoded_hex.contains(&cbor_text_hex("EBESExQVFhc")),
        "{} must preserve registration credential id/rawId as base64url text",
        vector.id
    );
    assert_byte_field(
        vector.id.as_str(),
        &encoded,
        "credential_id",
        &vector.input.approval.approval.credential_id_hex,
    );
    assert_byte_field(
        vector.id.as_str(),
        &encoded,
        "authenticator_data",
        &vector.input.approval.approval.authenticator_data_hex,
    );
    assert_byte_field(
        vector.id.as_str(),
        &encoded,
        "client_data_json",
        &vector.input.approval.approval.client_data_json_hex,
    );
    assert!(
        !encoded_hex.contains(&cbor_text_hex("00010280ff7f")),
        "{} must not encode approval credential_id as text",
        vector.id
    );
}

fn start_response_from_input(
    input: &StartResponseInput,
) -> OwnerWebauthnAddCredentialStartResponse {
    assert_eq!(input.version, 1);
    OwnerWebauthnAddCredentialStartResponse {
        version: input.version,
        registration: registration_start_response_from_input(&input.registration),
        approval: approval_start_response_from_input(&input.approval),
        context: add_credential_context_from_input(&input.context),
    }
}

fn finish_request_from_input(
    input: &FinishRequestInput,
) -> OwnerWebauthnAddCredentialFinishRequest {
    assert_eq!(input.version, 1);
    OwnerWebauthnAddCredentialFinishRequest {
        version: input.version,
        context: add_credential_context_from_input(&input.context),
        registration: registration_finish_request_from_input(&input.registration),
        approval: approval_finish_from_input(&input.approval),
    }
}

fn registration_start_response_from_input(
    input: &RegistrationStartResponseInput,
) -> OwnerWebauthnRegistrationStartResponse {
    assert_eq!(input.version, 1);
    OwnerWebauthnRegistrationStartResponse {
        version: input.version,
        challenge_id: input.challenge_id.clone(),
        options: serde_json::from_value(input.options.clone()).unwrap(),
    }
}

fn approval_start_response_from_input(
    input: &ApprovalStartResponseInput,
) -> OwnerApprovalV2StartResponse {
    assert_eq!(input.version, 1);
    OwnerApprovalV2StartResponse {
        version: input.version,
        challenge_id: input.challenge_id.clone(),
        context: add_credential_context_from_input(&input.context),
        options: serde_json::from_value(input.options.clone()).unwrap(),
    }
}

fn registration_finish_request_from_input(
    input: &RegistrationFinishRequestInput,
) -> OwnerWebauthnRegistrationFinishRequest {
    assert_eq!(input.version, 1);
    OwnerWebauthnRegistrationFinishRequest {
        version: input.version,
        challenge_id: input.challenge_id.clone(),
        credential: serde_json::from_value(input.credential.clone()).unwrap(),
    }
}

fn approval_finish_from_input(input: &ApprovalFinishInput) -> OwnerApprovalV2Finish {
    assert_eq!(input.version, 1);
    OwnerApprovalV2Finish {
        version: input.version,
        challenge_id: input.challenge_id.clone(),
        approval: approval_from_input(&input.approval),
    }
}

fn approval_from_input(input: &ApprovalInput) -> OwnerApprovalV2 {
    assert_eq!(input.version, 2);
    OwnerApprovalV2 {
        version: input.version,
        context: add_credential_context_from_input(&input.context),
        credential_id: ByteBuf::from(unhex(&input.credential_id_hex)),
        authenticator_data: ByteBuf::from(unhex(&input.authenticator_data_hex)),
        client_data_json: ByteBuf::from(unhex(&input.client_data_json_hex)),
        signature: ByteBuf::from(unhex(&input.signature_hex)),
        user_handle: input
            .user_handle_hex
            .as_deref()
            .map(unhex)
            .map(ByteBuf::from),
    }
}

fn add_credential_context_from_input(
    input: &AddCredentialContextInputJson,
) -> OwnerApprovalContextV2 {
    assert_eq!(input.version, 2);
    assert_eq!(input.purpose, "owner-approval-v2");
    assert_eq!(input.op, "add-credential");
    OwnerApprovalContextV2::add_credential(AddCredentialContextInput {
        hh_id: HouseholdId::parse(input.hh_id.clone()).unwrap(),
        owner_p_id: PersonId(input.owner_p_id.clone()),
        new_credential_binding_hash: unhex_array_32(
            "new_credential_binding_hash",
            &input.new_credential_binding_hash_hex,
        ),
        authority_head_sequence: input.authority_head_sequence,
        authority_head_hash: unhex_array_32("authority_head_hash", &input.authority_head_hash_hex),
        pre_active_credential_count: input.pre_active_credential_count,
        capabilities: input.capabilities.clone(),
        issued_at: input.issued_at,
        expires_at: input.expires_at,
        replay_nonce: unhex_array_32("replay_nonce", &input.replay_nonce_hex),
    })
}

fn assert_canonical_round_trip<T>(id: &str, canonical_cbor_hex: &str, typed: &T) -> Vec<u8>
where
    T: Serialize + DeserializeOwned,
{
    let encoded = household_rs::cbor::to_canonical_vec(typed).unwrap();
    let encoded_hex = hex::encode(&encoded);
    if canonical_cbor_hex == "__GENERATE__" {
        panic!("{id} generated canonical_cbor_hex: {encoded_hex}");
    }
    assert_eq!(
        encoded_hex, canonical_cbor_hex,
        "{id} fixture input must encode to the pinned canonical CBOR bytes",
    );

    let expected = hex::decode(canonical_cbor_hex).unwrap();
    let decoded: T = household_rs::cbor::from_canonical_slice(&expected).unwrap();
    let reencoded = household_rs::cbor::to_canonical_vec(&decoded).unwrap();
    assert_eq!(
        reencoded, expected,
        "{id} pinned bytes must be a canonical decode/re-encode fixed point",
    );
    encoded
}

fn assert_byte_field(id: &str, encoded: &[u8], field: &str, bytes_hex: &str) {
    let expected = format!(
        "{}{}",
        cbor_text_hex(field),
        cbor_byte_string_hex(bytes_hex)
    );
    assert!(
        hex::encode(encoded).contains(&expected),
        "{id} must encode {field} as a CBOR byte string",
    );
}

fn cbor_text_hex(text: &str) -> String {
    let bytes = text.as_bytes();
    match bytes.len() {
        len if len < 24 => format!("{:02x}{}", 0x60 + len, hex::encode(bytes)),
        len if u8::try_from(len).is_ok() => format!("78{len:02x}{}", hex::encode(bytes)),
        len => panic!("test helper does not support text length {len}"),
    }
}

fn cbor_byte_string_hex(bytes_hex: &str) -> String {
    let bytes = hex::decode(bytes_hex).unwrap();
    match bytes.len() {
        len if len < 24 => format!("{:02x}{bytes_hex}", 0x40 + len),
        len if u8::try_from(len).is_ok() => format!("58{len:02x}{bytes_hex}"),
        len => panic!("test helper does not support byte string length {len}"),
    }
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn unhex_array_32(label: &str, value: &str) -> [u8; 32] {
    let bytes = unhex(value);
    assert_eq!(bytes.len(), 32, "{label} must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn load_fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "data/owner_webauthn_add_credential_wire_vectors.json"
    ))
    .unwrap()
}
