//! Owner approval Protocol-v2 CBOR cross-language golden vectors.
//!
//! This pins the Rust encoder against the neutral public fixture shared with
//! the Swift side. If these bytes change, the wire contract changed and both
//! sides must intentionally re-mint the vectors.

use household_rs::ids::{HouseholdId, MachineId};
use household_rs::machine_cert::PersonId;
use household_rs::owner_approval_v2::{
    AddCredentialContextInput, OwnerApprovalContextV2, OwnerOperation,
    PairMachineApprovalContextInput, ProvisionRecoveryCodeContextInput, RecoveryAuthorityHeadInput,
};
use household_rs::pair_machine::JoinTransport;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use std::fmt::Write as _;

#[derive(Deserialize)]
struct Vectors {
    owner_approval_context_v2: Vec<OwnerApprovalCase>,
}

#[derive(Deserialize)]
struct OwnerApprovalCase {
    id: String,
    input: OwnerApprovalInput,
    canonical_cbor_hex: String,
    challenge_sha256_hex: String,
    #[serde(default)]
    omitted_fields: Vec<String>,
}

#[derive(Deserialize)]
struct OwnerApprovalInput {
    purpose: String,
    op: String,
    hh_id: String,
    owner_p_id: String,
    cursor: Option<u64>,
    m_id: Option<String>,
    addr: Option<String>,
    transport: Option<String>,
    ttl_unix: Option<u64>,
    nonce_hex: Option<String>,
    join_request_hash_hex: Option<String>,
    authority_head_sequence: Option<u64>,
    authority_head_hash_hex: Option<String>,
    pre_active_credential_count: Option<u64>,
    recovery_head_sequence: Option<u64>,
    recovery_head_hash_hex: Option<String>,
    new_credential_binding_hash_hex: Option<String>,
    capabilities: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    replay_nonce_hex: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("data/owner_approval_v2_vectors.json"))
        .expect("owner_approval_v2_vectors.json must be valid JSON")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn unhex_array_32(label: &str, value: &str) -> [u8; 32] {
    let bytes = unhex(value);
    assert_eq!(bytes.len(), 32, "{label} must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn operation(value: &str) -> OwnerOperation {
    match value {
        "pair-machine-approve" => OwnerOperation::PairMachineApprove,
        "bootstrap-initialize" => OwnerOperation::BootstrapInitialize,
        "bootstrap-teardown" => OwnerOperation::BootstrapTeardown,
        "pair-device-confirm" => OwnerOperation::PairDeviceConfirm,
        "revoke-credential" => OwnerOperation::RevokeCredential,
        "provision-recovery-code" => OwnerOperation::ProvisionRecoveryCode,
        "add-credential" => OwnerOperation::AddCredential,
        other => panic!("unknown operation in fixture: {other}"),
    }
}

fn transport(value: &str) -> JoinTransport {
    match value {
        "lan" => JoinTransport::Lan,
        "tailscale" => JoinTransport::Tailscale,
        other => panic!("unknown transport in fixture: {other}"),
    }
}

fn context_for(case: &OwnerApprovalCase) -> OwnerApprovalContextV2 {
    let input = &case.input;
    assert_eq!(
        input.purpose, "owner-approval-v2",
        "{}: purpose drifted",
        case.id
    );
    let hh_id = HouseholdId::parse(input.hh_id.clone()).expect("fixture hh_id must parse");
    let owner_p_id = PersonId(input.owner_p_id.clone());
    let replay_nonce = ByteBuf::from(unhex(&input.replay_nonce_hex));

    if input.op == "pair-machine-approve" {
        return OwnerApprovalContextV2::pair_machine_approve(PairMachineApprovalContextInput {
            hh_id,
            owner_p_id,
            cursor: input.cursor.expect("pair-machine cursor"),
            m_id: MachineId::parse(input.m_id.clone().expect("pair-machine m_id"))
                .expect("fixture m_id must parse"),
            addr: input.addr.clone().expect("pair-machine addr"),
            transport: transport(input.transport.as_deref().expect("pair-machine transport")),
            ttl_unix: input.ttl_unix.expect("pair-machine ttl_unix"),
            nonce: unhex_array_32(
                "nonce",
                input.nonce_hex.as_deref().expect("pair-machine nonce"),
            ),
            join_request_hash: unhex_array_32(
                "join_request_hash",
                input
                    .join_request_hash_hex
                    .as_deref()
                    .expect("pair-machine join_request_hash"),
            ),
            capabilities: input.capabilities.clone(),
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            replay_nonce: unhex_array_32("replay_nonce", &input.replay_nonce_hex),
        });
    }

    if input.op == "provision-recovery-code" {
        let recovery_head = match (
            input.recovery_head_sequence,
            input.recovery_head_hash_hex.as_deref(),
        ) {
            (None, None) => None,
            (Some(sequence), Some(head_hash)) => Some(RecoveryAuthorityHeadInput {
                sequence,
                head_hash: unhex_array_32("recovery_head_hash", head_hash),
            }),
            _ => panic!(
                "{}: recovery head must be fully present or omitted",
                case.id
            ),
        };
        return OwnerApprovalContextV2::provision_recovery_code(
            ProvisionRecoveryCodeContextInput {
                hh_id,
                owner_p_id,
                authority_head_sequence: input
                    .authority_head_sequence
                    .expect("provision recovery authority_head_sequence"),
                authority_head_hash: unhex_array_32(
                    "authority_head_hash",
                    input
                        .authority_head_hash_hex
                        .as_deref()
                        .expect("provision recovery authority_head_hash"),
                ),
                pre_active_credential_count: input
                    .pre_active_credential_count
                    .expect("provision recovery pre_active_credential_count"),
                recovery_head,
                capabilities: input.capabilities.clone(),
                issued_at: input.issued_at,
                expires_at: input.expires_at,
                replay_nonce: unhex_array_32("replay_nonce", &input.replay_nonce_hex),
            },
        );
    }

    if input.op == "add-credential" {
        return OwnerApprovalContextV2::add_credential(AddCredentialContextInput {
            hh_id,
            owner_p_id,
            new_credential_binding_hash: unhex_array_32(
                "new_credential_binding_hash",
                input
                    .new_credential_binding_hash_hex
                    .as_deref()
                    .expect("add credential new_credential_binding_hash"),
            ),
            authority_head_sequence: input
                .authority_head_sequence
                .expect("add credential authority_head_sequence"),
            authority_head_hash: unhex_array_32(
                "authority_head_hash",
                input
                    .authority_head_hash_hex
                    .as_deref()
                    .expect("add credential authority_head_hash"),
            ),
            pre_active_credential_count: input
                .pre_active_credential_count
                .expect("add credential pre_active_credential_count"),
            capabilities: input.capabilities.clone(),
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            replay_nonce: unhex_array_32("replay_nonce", &input.replay_nonce_hex),
        });
    }

    OwnerApprovalContextV2 {
        version: 2,
        purpose: input.purpose.clone(),
        op: operation(&input.op),
        hh_id,
        owner_p_id,
        cursor: input.cursor,
        m_id: input
            .m_id
            .clone()
            .map(MachineId::parse)
            .transpose()
            .expect("fixture m_id must parse"),
        addr: input.addr.clone(),
        transport: input.transport.as_deref().map(transport),
        ttl_unix: input.ttl_unix,
        nonce: input
            .nonce_hex
            .as_ref()
            .map(|value| ByteBuf::from(unhex(value))),
        join_request_hash: input
            .join_request_hash_hex
            .as_ref()
            .map(|value| ByteBuf::from(unhex(value))),
        target_credential_id: None,
        authority_head_sequence: None,
        authority_head_hash: None,
        pre_active_credential_count: None,
        recovery_head_sequence: None,
        recovery_head_hash: None,
        new_credential_binding_hash: None,
        capabilities: input.capabilities.clone(),
        issued_at: input.issued_at,
        expires_at: input.expires_at,
        replay_nonce,
    }
}

#[test]
fn owner_approval_v2_canonical_bytes_and_challenge_match_fixture() {
    for case in vectors().owner_approval_context_v2 {
        let ctx = context_for(&case);
        assert_eq!(
            hex(&ctx.to_canonical_bytes().expect("canonical bytes")),
            case.canonical_cbor_hex,
            "{}: canonical CBOR drifted; re-mint vectors on both sides if intentional",
            case.id
        );
        assert_eq!(
            hex(&ctx.challenge_digest().expect("challenge digest")),
            case.challenge_sha256_hex,
            "{}: challenge digest drifted",
            case.id
        );
    }
}

#[test]
fn owner_approval_v2_optional_fields_are_omitted_not_null() {
    for case in vectors().owner_approval_context_v2 {
        if case.omitted_fields.is_empty() {
            continue;
        }
        let canonical = context_for(&case)
            .to_canonical_bytes()
            .expect("canonical bytes");
        let value: ciborium::value::Value =
            ciborium::de::from_reader(canonical.as_slice()).expect("decode fixture cbor");
        let ciborium::value::Value::Map(entries) = value else {
            panic!("{}: context encodes as map", case.id);
        };
        let keys: Vec<String> = entries
            .into_iter()
            .map(|(key, _)| match key {
                ciborium::value::Value::Text(text) => text,
                other => panic!("{}: unexpected key: {other:?}", case.id),
            })
            .collect();
        for omitted in &case.omitted_fields {
            assert!(
                !keys.iter().any(|key| key == omitted),
                "{}: optional field {omitted} was encoded",
                case.id
            );
        }
    }
}
