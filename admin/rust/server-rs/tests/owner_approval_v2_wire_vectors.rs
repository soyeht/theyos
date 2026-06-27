//! Owner approval v2 `WebAuthn` wire CBOR cross-language golden vectors.
//!
//! This fixture is consumed by the Swift owner-approval adapter work. It pins
//! the server-rs wrappers around the household ownerApprovalContextV2 contract:
//! the assertion envelope, finish request wrapper, and start response options.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::ids::{HouseholdId, MachineId};
use household_rs::machine_cert::PersonId;
use household_rs::owner_approval_v2::{
    AddCredentialContextInput, OwnerApprovalContextV2, OwnerApprovalV2, OwnerApprovalV2Error,
    PairMachineApprovalContextInput, ProvisionRecoveryCodeContextInput,
    RecoverCredentialContextInput, RecoveryAuthorityHeadInput, RevokeCredentialContextInput,
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
    provision_recovery_code_contexts: Vec<ProvisionRecoveryCodeContextVector>,
    add_credential_contexts: Vec<AddCredentialContextVector>,
    recover_credential_contexts: Vec<RecoverCredentialContextVector>,
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

#[derive(Debug, Deserialize)]
struct ProvisionRecoveryCodeContextVector {
    id: String,
    input: ProvisionRecoveryCodeContextInputJson,
    canonical_cbor_hex: String,
}

#[derive(Debug, Deserialize)]
struct AddCredentialContextVector {
    id: String,
    input: AddCredentialContextInputJson,
    canonical_cbor_hex: String,
}

#[derive(Debug, Deserialize)]
struct RecoverCredentialContextVector {
    id: String,
    input: RecoverCredentialContextInputJson,
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
struct ProvisionRecoveryCodeContextInputJson {
    #[serde(rename = "v")]
    version: u8,
    purpose: String,
    op: String,
    hh_id: String,
    owner_p_id: String,
    authority_head_sequence: u64,
    authority_head_hash_hex: String,
    pre_active_credential_count: u64,
    recovery_head_sequence: Option<u64>,
    recovery_head_hash_hex: Option<String>,
    capabilities: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    replay_nonce_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
struct RecoverCredentialContextInputJson {
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
    recovery_head_sequence: u64,
    recovery_head_hash_hex: String,
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

#[test]
fn owner_approval_v2_provision_recovery_code_context_vectors_are_canonical() {
    let fixture = load_fixture();
    assert_eq!(fixture.provision_recovery_code_contexts.len(), 2);

    for vector in &fixture.provision_recovery_code_contexts {
        let context = provision_recovery_context_from_input(&vector.input);
        context.validate_shape().unwrap();
        let encoded =
            assert_canonical_round_trip(vector.id.as_str(), &vector.canonical_cbor_hex, &context);
        let encoded_hex = hex::encode(&encoded);

        assert_byte_field(
            vector.id.as_str(),
            &encoded,
            "authority_head_hash",
            &vector.input.authority_head_hash_hex,
        );
        if let Some(recovery_head_hash_hex) = &vector.input.recovery_head_hash_hex {
            assert_byte_field(
                vector.id.as_str(),
                &encoded,
                "recovery_head_hash",
                recovery_head_hash_hex,
            );
        } else {
            assert!(
                !encoded_hex.contains(&cbor_text_hex("recovery_head_hash")),
                "{} must omit recovery_head_hash when no recovery head is bound",
                vector.id,
            );
            assert!(
                !encoded_hex.contains(&cbor_text_hex("recovery_head_sequence")),
                "{} must omit recovery_head_sequence when no recovery head is bound",
                vector.id,
            );
        }
    }
}

#[test]
fn provision_recovery_code_context_rejects_missing_and_unknown_fields() {
    let fixture = load_fixture();
    let input = &fixture.provision_recovery_code_contexts[0].input;
    for missing in [
        "authority_head_sequence",
        "authority_head_hash_hex",
        "pre_active_credential_count",
    ] {
        let mut value = serde_json::to_value(input).unwrap();
        value.as_object_mut().unwrap().remove(missing);
        assert!(
            serde_json::from_value::<ProvisionRecoveryCodeContextInputJson>(value).is_err(),
            "missing {missing} must reject",
        );
    }

    let mut value = serde_json::to_value(input).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("cursor".to_string(), serde_json::json!(7));
    assert!(
        serde_json::from_value::<ProvisionRecoveryCodeContextInputJson>(value).is_err(),
        "unknown pair-machine field must reject",
    );
}

#[test]
fn provision_recovery_code_context_rejects_invalid_values_and_half_present_head() {
    let fixture = load_fixture();
    let mut invalid_hash =
        provision_recovery_context_from_input(&fixture.provision_recovery_code_contexts[0].input);
    invalid_hash.authority_head_hash = Some(ByteBuf::from(vec![0x44; 31]));
    assert!(matches!(
        invalid_hash.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"))
    ));

    let mut invalid_count =
        provision_recovery_context_from_input(&fixture.provision_recovery_code_contexts[0].input);
    invalid_count.pre_active_credential_count = Some(0);
    assert!(matches!(
        invalid_count.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField(
            "pre_active_credential_count"
        ))
    ));

    let mut recovery_hash_short =
        provision_recovery_context_from_input(&fixture.provision_recovery_code_contexts[1].input);
    recovery_hash_short.recovery_head_hash = Some(ByteBuf::from(vec![0x77; 31]));
    assert!(matches!(
        recovery_hash_short.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField("recovery_head_hash"))
    ));

    let mut missing_recovery_hash =
        provision_recovery_context_from_input(&fixture.provision_recovery_code_contexts[1].input);
    missing_recovery_hash.recovery_head_hash = None;
    assert!(matches!(
        missing_recovery_hash.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField("recovery_head_hash"))
    ));

    let mut missing_recovery_sequence =
        provision_recovery_context_from_input(&fixture.provision_recovery_code_contexts[1].input);
    missing_recovery_sequence.recovery_head_sequence = None;
    assert!(matches!(
        missing_recovery_sequence.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField("recovery_head_sequence"))
    ));
}

#[test]
fn provision_recovery_code_context_sequence_and_count_are_canonical_unsigned_ints() {
    let fixture = load_fixture();
    let vector = &fixture.provision_recovery_code_contexts[0];
    let context = provision_recovery_context_from_input(&vector.input);
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

#[test]
fn owner_approval_v2_add_credential_context_vectors_are_canonical() {
    let fixture = load_fixture();
    assert_eq!(fixture.add_credential_contexts.len(), 1);

    for vector in &fixture.add_credential_contexts {
        let context = add_credential_context_from_input(&vector.input);
        context.validate_shape().unwrap();
        let encoded =
            assert_canonical_round_trip(vector.id.as_str(), &vector.canonical_cbor_hex, &context);
        let encoded_hex = hex::encode(&encoded);

        assert_byte_field(
            vector.id.as_str(),
            &encoded,
            "new_credential_binding_hash",
            &vector.input.new_credential_binding_hash_hex,
        );
        assert_byte_field(
            vector.id.as_str(),
            &encoded,
            "authority_head_hash",
            &vector.input.authority_head_hash_hex,
        );
        assert!(
            !encoded_hex.contains(&cbor_text_hex("AAECgP9_AAECgP9_AAECgP9_AAECgP9_")),
            "{} must not encode a base64url-looking binding hash as CBOR text",
            vector.id,
        );
    }
}

#[test]
fn add_credential_context_rejects_missing_and_unknown_fields() {
    let fixture = load_fixture();
    let input = &fixture.add_credential_contexts[0].input;
    for missing in [
        "new_credential_binding_hash_hex",
        "authority_head_sequence",
        "authority_head_hash_hex",
        "pre_active_credential_count",
    ] {
        let mut value = serde_json::to_value(input).unwrap();
        value.as_object_mut().unwrap().remove(missing);
        assert!(
            serde_json::from_value::<AddCredentialContextInputJson>(value).is_err(),
            "missing {missing} must reject",
        );
    }

    let mut value = serde_json::to_value(input).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("cursor".to_string(), serde_json::json!(7));
    assert!(
        serde_json::from_value::<AddCredentialContextInputJson>(value).is_err(),
        "unknown pair-machine field must reject",
    );
}

#[test]
fn add_credential_context_rejects_invalid_hash_len_and_count() {
    let fixture = load_fixture();
    let mut invalid_binding =
        add_credential_context_from_input(&fixture.add_credential_contexts[0].input);
    invalid_binding.new_credential_binding_hash = Some(ByteBuf::from(vec![0x41; 31]));
    assert!(matches!(
        invalid_binding.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField(
            "new_credential_binding_hash"
        ))
    ));

    let mut invalid_hash =
        add_credential_context_from_input(&fixture.add_credential_contexts[0].input);
    invalid_hash.authority_head_hash = Some(ByteBuf::from(vec![0x44; 31]));
    assert!(matches!(
        invalid_hash.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"))
    ));

    let mut invalid_count =
        add_credential_context_from_input(&fixture.add_credential_contexts[0].input);
    invalid_count.pre_active_credential_count = Some(0);
    assert!(matches!(
        invalid_count.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField(
            "pre_active_credential_count"
        ))
    ));
}

#[test]
fn add_credential_context_sequence_and_count_are_canonical_unsigned_ints() {
    let fixture = load_fixture();
    let vector = &fixture.add_credential_contexts[0];
    let context = add_credential_context_from_input(&vector.input);
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

#[test]
fn owner_approval_v2_recover_credential_context_vectors_are_canonical() {
    let fixture = load_fixture();
    assert_eq!(fixture.recover_credential_contexts.len(), 1);

    for vector in &fixture.recover_credential_contexts {
        let context = recover_credential_context_from_input(&vector.input);
        context.validate_shape().unwrap();
        let encoded =
            assert_canonical_round_trip(vector.id.as_str(), &vector.canonical_cbor_hex, &context);
        let encoded_hex = hex::encode(&encoded);

        assert_byte_field(
            vector.id.as_str(),
            &encoded,
            "new_credential_binding_hash",
            &vector.input.new_credential_binding_hash_hex,
        );
        assert_byte_field(
            vector.id.as_str(),
            &encoded,
            "authority_head_hash",
            &vector.input.authority_head_hash_hex,
        );
        assert_byte_field(
            vector.id.as_str(),
            &encoded,
            "recovery_head_hash",
            &vector.input.recovery_head_hash_hex,
        );
        assert!(
            encoded_hex.contains(&format!(
                "{}00",
                cbor_text_hex("pre_active_credential_count")
            )),
            "{} must allow and encode pre_active_credential_count=0 as telemetry",
            vector.id,
        );
    }
}

#[test]
fn recover_credential_context_rejects_missing_and_unknown_fields() {
    let fixture = load_fixture();
    let input = &fixture.recover_credential_contexts[0].input;
    for missing in [
        "new_credential_binding_hash_hex",
        "authority_head_sequence",
        "authority_head_hash_hex",
        "pre_active_credential_count",
        "recovery_head_sequence",
        "recovery_head_hash_hex",
    ] {
        let mut value = serde_json::to_value(input).unwrap();
        value.as_object_mut().unwrap().remove(missing);
        assert!(
            serde_json::from_value::<RecoverCredentialContextInputJson>(value).is_err(),
            "missing {missing} must reject",
        );
    }

    let mut value = serde_json::to_value(input).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("cursor".to_string(), serde_json::json!(7));
    assert!(
        serde_json::from_value::<RecoverCredentialContextInputJson>(value).is_err(),
        "unknown pair-machine field must reject",
    );
}

#[test]
fn recover_credential_context_rejects_invalid_hash_lengths_but_allows_zero_count() {
    let fixture = load_fixture();
    let mut invalid_binding =
        recover_credential_context_from_input(&fixture.recover_credential_contexts[0].input);
    invalid_binding.new_credential_binding_hash = Some(ByteBuf::from(vec![0x41; 31]));
    assert!(matches!(
        invalid_binding.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField(
            "new_credential_binding_hash"
        ))
    ));

    let mut invalid_authority_hash =
        recover_credential_context_from_input(&fixture.recover_credential_contexts[0].input);
    invalid_authority_hash.authority_head_hash = Some(ByteBuf::from(vec![0x66; 31]));
    assert!(matches!(
        invalid_authority_hash.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"))
    ));

    let mut invalid_recovery_hash =
        recover_credential_context_from_input(&fixture.recover_credential_contexts[0].input);
    invalid_recovery_hash.recovery_head_hash = Some(ByteBuf::from(vec![0x77; 31]));
    assert!(matches!(
        invalid_recovery_hash.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField("recovery_head_hash"))
    ));

    let mut zero_count =
        recover_credential_context_from_input(&fixture.recover_credential_contexts[0].input);
    zero_count.pre_active_credential_count = Some(0);
    zero_count.validate_shape().unwrap();
}

#[test]
fn owner_approval_context_cross_rejects_fields_from_other_operations() {
    let fixture = load_fixture();
    let mut pair_machine = context_from_input(&fixture.owner_approvals[0].input.context);
    pair_machine.recovery_head_sequence = Some(0);
    assert!(matches!(
        pair_machine.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField(
            "recovery_head_sequence"
        ))
    ));

    let mut revoke = revoke_context_from_input(&fixture.revoke_credential_contexts[0].input);
    revoke.recovery_head_hash = Some(ByteBuf::from(vec![0x77; 32]));
    assert!(matches!(
        revoke.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField("recovery_head_hash"))
    ));

    let mut provision =
        provision_recovery_context_from_input(&fixture.provision_recovery_code_contexts[0].input);
    provision.target_credential_id = Some(ByteBuf::from(vec![0x41]));
    assert!(matches!(
        provision.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField(
            "target_credential_id"
        ))
    ));

    let mut provision_with_pair_field =
        provision_recovery_context_from_input(&fixture.provision_recovery_code_contexts[0].input);
    provision_with_pair_field.cursor = Some(7);
    assert!(matches!(
        provision_with_pair_field.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField("cursor"))
    ));

    let mut add = add_credential_context_from_input(&fixture.add_credential_contexts[0].input);
    add.target_credential_id = Some(ByteBuf::from(vec![0x41]));
    assert!(matches!(
        add.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField(
            "target_credential_id"
        ))
    ));

    let mut add_with_recovery =
        add_credential_context_from_input(&fixture.add_credential_contexts[0].input);
    add_with_recovery.recovery_head_hash = Some(ByteBuf::from(vec![0x77; 32]));
    assert!(matches!(
        add_with_recovery.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField("recovery_head_hash"))
    ));

    let mut revoke_with_add =
        revoke_context_from_input(&fixture.revoke_credential_contexts[0].input);
    revoke_with_add.new_credential_binding_hash = Some(ByteBuf::from(vec![0x41; 32]));
    assert!(matches!(
        revoke_with_add.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField(
            "new_credential_binding_hash"
        ))
    ));

    let mut provision_with_add =
        provision_recovery_context_from_input(&fixture.provision_recovery_code_contexts[0].input);
    provision_with_add.new_credential_binding_hash = Some(ByteBuf::from(vec![0x41; 32]));
    assert!(matches!(
        provision_with_add.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField(
            "new_credential_binding_hash"
        ))
    ));

    let mut recover =
        recover_credential_context_from_input(&fixture.recover_credential_contexts[0].input);
    recover.target_credential_id = Some(ByteBuf::from(vec![0x41]));
    assert!(matches!(
        recover.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField(
            "target_credential_id"
        ))
    ));

    let mut recover_with_pair =
        recover_credential_context_from_input(&fixture.recover_credential_contexts[0].input);
    recover_with_pair.cursor = Some(7);
    assert!(matches!(
        recover_with_pair.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField("cursor"))
    ));
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

fn provision_recovery_context_from_input(
    input: &ProvisionRecoveryCodeContextInputJson,
) -> OwnerApprovalContextV2 {
    assert_eq!(input.version, 2);
    assert_eq!(input.purpose, "owner-approval-v2");
    assert_eq!(input.op, "provision-recovery-code");
    let recovery_head = match (
        input.recovery_head_sequence,
        input.recovery_head_hash_hex.as_ref(),
    ) {
        (None, None) => None,
        (Some(sequence), Some(head_hash_hex)) => Some(RecoveryAuthorityHeadInput {
            sequence,
            head_hash: unhex_array_32("recovery_head_hash", head_hash_hex),
        }),
        (Some(_), None) => panic!("recovery_head_hash_hex missing"),
        (None, Some(_)) => panic!("recovery_head_sequence missing"),
    };
    OwnerApprovalContextV2::provision_recovery_code(ProvisionRecoveryCodeContextInput {
        hh_id: HouseholdId::parse(input.hh_id.clone()).unwrap(),
        owner_p_id: PersonId(input.owner_p_id.clone()),
        authority_head_sequence: input.authority_head_sequence,
        authority_head_hash: unhex_array_32("authority_head_hash", &input.authority_head_hash_hex),
        pre_active_credential_count: input.pre_active_credential_count,
        recovery_head,
        capabilities: input.capabilities.clone(),
        issued_at: input.issued_at,
        expires_at: input.expires_at,
        replay_nonce: unhex_array_32("replay_nonce", &input.replay_nonce_hex),
    })
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

fn recover_credential_context_from_input(
    input: &RecoverCredentialContextInputJson,
) -> OwnerApprovalContextV2 {
    assert_eq!(input.version, 2);
    assert_eq!(input.purpose, "owner-approval-v2");
    assert_eq!(input.op, "recover-credential");
    OwnerApprovalContextV2::recover_credential(RecoverCredentialContextInput {
        hh_id: HouseholdId::parse(input.hh_id.clone()).unwrap(),
        owner_p_id: PersonId(input.owner_p_id.clone()),
        new_credential_binding_hash: unhex_array_32(
            "new_credential_binding_hash",
            &input.new_credential_binding_hash_hex,
        ),
        authority_head_sequence: input.authority_head_sequence,
        authority_head_hash: unhex_array_32("authority_head_hash", &input.authority_head_hash_hex),
        pre_active_credential_count: input.pre_active_credential_count,
        recovery_head: RecoveryAuthorityHeadInput {
            sequence: input.recovery_head_sequence,
            head_hash: unhex_array_32("recovery_head_hash", &input.recovery_head_hash_hex),
        },
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
