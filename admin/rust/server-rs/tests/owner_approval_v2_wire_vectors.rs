//! Owner approval v2 `WebAuthn` wire CBOR cross-language golden vectors.
//!
//! This fixture is consumed by the Swift owner-approval adapter work. It pins
//! the server-rs wrappers around the household ownerApprovalContextV2 contract:
//! the assertion envelope, finish request wrapper, and start response options.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::ids::{HouseholdId, MachineId};
use household_rs::machine_cert::PersonId;
use household_rs::owner_approval_v2::{
    OwnerApprovalContextV2, OwnerApprovalV2, OwnerApprovalV2Error, PairMachineApprovalContextInput,
    RevokeCredentialContextInput,
};
use household_rs::pair_machine::JoinTransport;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_bytes::ByteBuf;
use serde_json::Value;
use webauthn_rs::prelude::RequestChallengeResponse;

#[derive(Debug, Deserialize)]
struct Fixture {
    contract: String,
    version: u8,
    owner_approvals: Vec<ApprovalVector>,
    owner_approval_finishes: Vec<FinishVector>,
    owner_approval_start_responses: Vec<StartResponseVector>,
    revoke_credential_contexts: Vec<RevokeCredentialContextVector>,
}

#[derive(Debug, Deserialize)]
struct ApprovalVector {
    id: String,
    input: ApprovalInput,
    canonical_cbor_hex: String,
}

#[derive(Debug, Deserialize)]
struct FinishVector {
    id: String,
    input: FinishInput,
    canonical_cbor_hex: String,
}

#[derive(Debug, Deserialize)]
struct StartResponseVector {
    id: String,
    input: StartResponseInput,
    canonical_cbor_hex: String,
}

#[derive(Debug, Deserialize)]
struct RevokeCredentialContextVector {
    id: String,
    input: RevokeCredentialContextInputJson,
    canonical_cbor_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalInput {
    #[serde(rename = "v")]
    version: u8,
    context: ContextInput,
    credential_id_hex: String,
    authenticator_data_hex: String,
    client_data_json_hex: String,
    signature_hex: String,
    user_handle_hex: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishInput {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    approval: ApprovalInput,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartResponseInput {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    context: ContextInput,
    options: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextInput {
    #[serde(rename = "v")]
    version: u8,
    purpose: String,
    op: String,
    hh_id: String,
    owner_p_id: String,
    cursor: u64,
    m_id: String,
    addr: String,
    transport: String,
    ttl_unix: u64,
    nonce_hex: String,
    join_request_hash_hex: String,
    capabilities: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    replay_nonce_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeCredentialContextInputJson {
    #[serde(rename = "v")]
    version: u8,
    purpose: String,
    op: String,
    hh_id: String,
    owner_p_id: String,
    target_credential_id_hex: String,
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
struct OwnerApprovalV2Finish {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    approval: OwnerApprovalV2,
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

#[test]
fn owner_approval_v2_assertion_envelope_vectors_are_canonical() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.contract,
        "soyeht-owner-approval-v2-wire-cbor-cross-language"
    );
    assert_eq!(fixture.version, 1);
    assert_eq!(fixture.owner_approvals.len(), 2);

    for vector in &fixture.owner_approvals {
        let approval = approval_from_input(&vector.input);
        approval.validate_shape().unwrap();
        let encoded =
            assert_canonical_round_trip(vector.id.as_str(), &vector.canonical_cbor_hex, &approval);

        assert_byte_field(
            vector.id.as_str(),
            &encoded,
            "credential_id",
            &vector.input.credential_id_hex,
        );
        assert_byte_field(
            vector.id.as_str(),
            &encoded,
            "authenticator_data",
            &vector.input.authenticator_data_hex,
        );
        assert_byte_field(
            vector.id.as_str(),
            &encoded,
            "client_data_json",
            &vector.input.client_data_json_hex,
        );
        assert_byte_field(
            vector.id.as_str(),
            &encoded,
            "signature",
            &vector.input.signature_hex,
        );

        if let Some(user_handle_hex) = &vector.input.user_handle_hex {
            assert_byte_field(vector.id.as_str(), &encoded, "user_handle", user_handle_hex);
        } else {
            assert!(
                !hex::encode(&encoded).contains(&cbor_text_hex("user_handle")),
                "{} must omit user_handle instead of encoding null",
                vector.id
            );
        }
    }
}

#[test]
fn owner_approval_v2_finish_vectors_are_canonical() {
    let fixture = load_fixture();
    assert_eq!(fixture.owner_approval_finishes.len(), 2);

    for vector in &fixture.owner_approval_finishes {
        let finish = finish_from_input(&vector.input);
        finish.approval.validate_shape().unwrap();
        assert_canonical_round_trip(vector.id.as_str(), &vector.canonical_cbor_hex, &finish);
    }
}

#[test]
fn owner_approval_v2_start_response_vector_is_canonical() {
    let fixture = load_fixture();
    assert_eq!(fixture.owner_approval_start_responses.len(), 1);

    let vector = &fixture.owner_approval_start_responses[0];
    let start = start_response_from_input(&vector.input);
    let encoded =
        assert_canonical_round_trip(vector.id.as_str(), &vector.canonical_cbor_hex, &start);

    assert_eq!(start.options.public_key.rp_id, "alpha.example.test");
    assert_eq!(start.options.public_key.allow_credentials.len(), 1);
    assert_eq!(
        start.options.public_key.challenge.as_slice(),
        B64URL.decode("AQIDBAUGBwg").unwrap().as_slice(),
    );
    assert_eq!(
        start.options.public_key.allow_credentials[0].id.as_slice(),
        B64URL.decode("AAECgP9_").unwrap().as_slice(),
    );

    let encoded_hex = hex::encode(&encoded);
    assert!(
        encoded_hex.contains(&cbor_text_hex("AQIDBAUGBwg")),
        "{} must encode RequestChallengeResponse challenge as base64url text",
        vector.id,
    );
    assert!(
        encoded_hex.contains(&cbor_text_hex("AAECgP9_")),
        "{} must encode allowCredentials[].id as base64url text",
        vector.id,
    );
    assert!(
        !encoded_hex.contains("480102030405060708"),
        "{} must not encode RequestChallengeResponse challenge as CBOR bytes",
        vector.id,
    );
}

#[test]
fn owner_approval_v2_revoke_credential_context_vectors_are_canonical() {
    let fixture = load_fixture();
    assert_eq!(fixture.revoke_credential_contexts.len(), 2);

    for vector in &fixture.revoke_credential_contexts {
        let context = revoke_context_from_input(&vector.input);
        context.validate_shape().unwrap();
        let encoded =
            assert_canonical_round_trip(vector.id.as_str(), &vector.canonical_cbor_hex, &context);
        let encoded_hex = hex::encode(&encoded);

        assert_byte_field(
            vector.id.as_str(),
            &encoded,
            "target_credential_id",
            &vector.input.target_credential_id_hex,
        );
        assert_byte_field(
            vector.id.as_str(),
            &encoded,
            "authority_head_hash",
            &vector.input.authority_head_hash_hex,
        );
        assert!(
            !encoded_hex.contains(&cbor_text_hex("AAECgP9_")),
            "{} must not encode a base64url-looking target credential as CBOR text",
            vector.id,
        );
    }
}

#[test]
fn revoke_credential_context_rejects_missing_and_unknown_fields() {
    let fixture = load_fixture();
    let input = &fixture.revoke_credential_contexts[0].input;
    for missing in [
        "target_credential_id_hex",
        "authority_head_sequence",
        "authority_head_hash_hex",
        "pre_active_credential_count",
    ] {
        let mut value = serde_json::to_value(input).unwrap();
        value.as_object_mut().unwrap().remove(missing);
        assert!(
            serde_json::from_value::<RevokeCredentialContextInputJson>(value).is_err(),
            "missing {missing} must reject",
        );
    }

    let mut value = serde_json::to_value(input).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("cursor".to_string(), serde_json::json!(7));
    assert!(
        serde_json::from_value::<RevokeCredentialContextInputJson>(value).is_err(),
        "unknown pair-machine field must reject",
    );
}

#[test]
fn revoke_credential_context_rejects_invalid_hash_len_and_count() {
    let fixture = load_fixture();
    let mut invalid_hash = revoke_context_from_input(&fixture.revoke_credential_contexts[0].input);
    invalid_hash.authority_head_hash = Some(ByteBuf::from(vec![0x44; 31]));
    assert!(matches!(
        invalid_hash.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"))
    ));

    let mut invalid_count = revoke_context_from_input(&fixture.revoke_credential_contexts[0].input);
    invalid_count.pre_active_credential_count = Some(0);
    assert!(matches!(
        invalid_count.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField(
            "pre_active_credential_count"
        ))
    ));
}

#[test]
fn revoke_credential_context_sequence_and_count_are_canonical_unsigned_ints() {
    let fixture = load_fixture();
    let vector = &fixture.revoke_credential_contexts[0];
    let context = revoke_context_from_input(&vector.input);
    let encoded = context.to_canonical_bytes().unwrap();
    let encoded_hex = hex::encode(encoded);

    assert!(
        encoded_hex.contains(&format!("{}1818", cbor_text_hex("authority_head_sequence"))),
        "{} must encode authority_head_sequence=24 as canonical uint8",
        vector.id,
    );
    assert!(
        encoded_hex.contains(&format!(
            "{}02",
            cbor_text_hex("pre_active_credential_count")
        )),
        "{} must encode pre_active_credential_count=2 as canonical small uint",
        vector.id,
    );
}

fn approval_from_input(input: &ApprovalInput) -> OwnerApprovalV2 {
    assert_eq!(input.version, 2);
    OwnerApprovalV2 {
        version: input.version,
        context: context_from_input(&input.context),
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

fn finish_from_input(input: &FinishInput) -> OwnerApprovalV2Finish {
    assert_eq!(input.version, 1);
    OwnerApprovalV2Finish {
        version: input.version,
        challenge_id: input.challenge_id.clone(),
        approval: approval_from_input(&input.approval),
    }
}

fn start_response_from_input(input: &StartResponseInput) -> OwnerApprovalV2StartResponse {
    assert_eq!(input.version, 1);
    OwnerApprovalV2StartResponse {
        version: input.version,
        challenge_id: input.challenge_id.clone(),
        context: context_from_input(&input.context),
        options: serde_json::from_value(input.options.clone()).unwrap(),
    }
}

fn context_from_input(input: &ContextInput) -> OwnerApprovalContextV2 {
    assert_eq!(input.version, 2);
    assert_eq!(input.purpose, "owner-approval-v2");
    assert_eq!(input.op, "pair-machine-approve");
    OwnerApprovalContextV2::pair_machine_approve(PairMachineApprovalContextInput {
        hh_id: HouseholdId::parse(input.hh_id.clone()).unwrap(),
        owner_p_id: PersonId(input.owner_p_id.clone()),
        cursor: input.cursor,
        m_id: MachineId::parse(input.m_id.clone()).unwrap(),
        addr: input.addr.clone(),
        transport: match input.transport.as_str() {
            "lan" => JoinTransport::Lan,
            "tailscale" => JoinTransport::Tailscale,
            other => panic!("unexpected transport {other}"),
        },
        ttl_unix: input.ttl_unix,
        nonce: unhex_array_32("nonce", &input.nonce_hex),
        join_request_hash: unhex_array_32("join_request_hash", &input.join_request_hash_hex),
        capabilities: input.capabilities.clone(),
        issued_at: input.issued_at,
        expires_at: input.expires_at,
        replay_nonce: unhex_array_32("replay_nonce", &input.replay_nonce_hex),
    })
}

fn revoke_context_from_input(input: &RevokeCredentialContextInputJson) -> OwnerApprovalContextV2 {
    assert_eq!(input.version, 2);
    assert_eq!(input.purpose, "owner-approval-v2");
    assert_eq!(input.op, "revoke-credential");
    OwnerApprovalContextV2::revoke_credential(RevokeCredentialContextInput {
        hh_id: HouseholdId::parse(input.hh_id.clone()).unwrap(),
        owner_p_id: PersonId(input.owner_p_id.clone()),
        target_credential_id: unhex(&input.target_credential_id_hex),
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
    assert_eq!(
        hex::encode(&encoded),
        canonical_cbor_hex,
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
    serde_json::from_str(include_str!("data/owner_approval_v2_wire_vectors.json")).unwrap()
}
