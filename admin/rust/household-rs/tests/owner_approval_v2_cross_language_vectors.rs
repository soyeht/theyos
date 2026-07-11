//! Owner approval Protocol-v2 CBOR cross-language golden vectors.
//!
//! This pins the Rust encoder against the neutral public fixture shared with
//! the Swift side. If these bytes change, the wire contract changed and both
//! sides must intentionally re-mint the vectors.

use household_rs::ids::{HouseholdId, MachineId};
use household_rs::machine_cert::PersonId;
use household_rs::owner_approval_v2::{
    AddCredentialContextInput, MobileClawVpnDevE2eApprovalContextInput,
    MobileClawVpnDevE2eExecutionTupleInput, MobileClawVpnDevE2eExecutionTupleV1,
    OwnerApprovalContextV2, OwnerOperation, PairMachineApprovalContextInput,
    ProvisionRecoveryCodeContextInput, RecoverCredentialContextInput, RecoveryAuthorityHeadInput,
};
use household_rs::pair_machine::JoinTransport;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

const MOBILE_OWNER_APPROVAL_V1_FIXTURE: &str =
    include_str!("../../../contracts/mobile-claw-vpn/v1/owner_approval_v2_execution_vectors.json");
const MOBILE_OWNER_APPROVAL_V1_FIXTURE_SHA256: &str =
    "c47ebb5d9f9a1309e45647dedcdcb20fd7abd47a46e6f31f5541d8f2711c316c";

#[derive(Deserialize)]
struct Vectors {
    owner_approval_context_v2: Vec<OwnerApprovalCase>,
}

#[derive(Deserialize)]
struct MobileVectors {
    mobile_claw_vpn_dev_e2e_execution_tuple_v1: Vec<MobileExecutionCase>,
    owner_approval_context_v2: Vec<OwnerApprovalCase>,
}

#[derive(Deserialize)]
struct MobileExecutionCase {
    id: String,
    input: MobileExecutionInput,
    canonical_cbor_hex: String,
    execution_sha256_hex: String,
}

#[derive(Deserialize)]
struct MobileExecutionInput {
    v: u8,
    purpose: String,
    op: String,
    hh_id: String,
    engine_audience_hex: String,
    member_id: String,
    attempt_id: String,
    readiness_run_id: String,
    source_artifact_git_sha1_hex: String,
    execution_manifest_sha256_hex: String,
    device_binding_hex: String,
    execution_run_id: String,
    execution_claim_sha256_hex: String,
    bundle_id: String,
    device_id: String,
    claw_id: String,
    device_alias: String,
    claw_alias: String,
    issued_at: u64,
    expires_at: u64,
    server_nonce_hex: String,
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
    v: u8,
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
    mobile_claw_vpn_execution_tuple_id: Option<String>,
    capabilities: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    replay_nonce_hex: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("data/owner_approval_v2_vectors.json"))
        .expect("owner_approval_v2_vectors.json must be valid JSON")
}

fn mobile_vectors() -> MobileVectors {
    serde_json::from_str(MOBILE_OWNER_APPROVAL_V1_FIXTURE)
        .expect("authoritative mobile owner approval fixture must be valid JSON")
}

fn owner_approval_cases() -> Vec<OwnerApprovalCase> {
    let mut cases = vectors().owner_approval_context_v2;
    cases.extend(mobile_vectors().owner_approval_context_v2);
    cases
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
        "recover-credential" => OwnerOperation::RecoverCredential,
        "mobile-claw-vpn-dev-e2e-execute" => OwnerOperation::MobileClawVpnDevE2eExecute,
        other => panic!("unknown operation in fixture: {other}"),
    }
}

fn execution_for(case: &MobileExecutionCase) -> MobileClawVpnDevE2eExecutionTupleV1 {
    let input = &case.input;
    assert_eq!(input.v, 1, "{}: tuple version drifted", case.id);
    assert_eq!(
        input.purpose, "mobile-claw-vpn-dev-e2e-execution",
        "{}: tuple purpose drifted",
        case.id
    );
    assert_eq!(
        input.op, "mobile-claw-vpn-dev-e2e-execute",
        "{}: tuple operation drifted",
        case.id
    );
    assert_eq!(
        input.bundle_id, "com.soyeht.app.dev",
        "{}: tuple bundle drifted",
        case.id
    );
    MobileClawVpnDevE2eExecutionTupleV1::new(MobileClawVpnDevE2eExecutionTupleInput {
        hh_id: HouseholdId::parse(input.hh_id.clone()).expect("fixture hh_id must parse"),
        engine_audience: unhex_array_32("engine_audience", &input.engine_audience_hex),
        member_id: input.member_id.clone(),
        attempt_id: input.attempt_id.clone(),
        readiness_run_id: input.readiness_run_id.clone(),
        source_artifact_git_sha1: {
            let bytes = unhex(&input.source_artifact_git_sha1_hex);
            assert_eq!(bytes.len(), 20, "source_artifact_git_sha1 must be 20 bytes");
            let mut output = [0u8; 20];
            output.copy_from_slice(&bytes);
            output
        },
        execution_manifest_sha256: unhex_array_32(
            "execution_manifest_sha256",
            &input.execution_manifest_sha256_hex,
        ),
        device_binding: unhex_array_32("device_binding", &input.device_binding_hex),
        execution_run_id: input.execution_run_id.clone(),
        execution_claim_sha256: unhex_array_32(
            "execution_claim_sha256",
            &input.execution_claim_sha256_hex,
        ),
        device_id: input.device_id.clone(),
        claw_id: input.claw_id.clone(),
        device_alias: input.device_alias.clone(),
        claw_alias: input.claw_alias.clone(),
        issued_at: input.issued_at,
        expires_at: input.expires_at,
        server_nonce: unhex_array_32("server_nonce", &input.server_nonce_hex),
    })
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

    if input.op == "mobile-claw-vpn-dev-e2e-execute" {
        let tuple_id = input
            .mobile_claw_vpn_execution_tuple_id
            .as_deref()
            .expect("mobile execution tuple id");
        let fixture = mobile_vectors();
        let tuple_case = fixture
            .mobile_claw_vpn_dev_e2e_execution_tuple_v1
            .iter()
            .find(|tuple| tuple.id == tuple_id)
            .expect("referenced mobile execution tuple");
        let execution = execution_for(tuple_case);
        assert_eq!(input.v, 2, "{}: context version drifted", case.id);
        assert_eq!(
            input.hh_id,
            execution.hh_id.as_str(),
            "{}: household drifted",
            case.id
        );
        assert_eq!(
            input.capabilities,
            ["mobile-claw-vpn-dev-e2e-execute"],
            "{}: capability drifted",
            case.id
        );
        assert_eq!(
            input.issued_at, execution.issued_at,
            "{}: issued_at drifted",
            case.id
        );
        assert_eq!(
            input.expires_at, execution.expires_at,
            "{}: expires_at drifted",
            case.id
        );
        assert!(input.cursor.is_none(), "{}: cursor must be absent", case.id);
        assert!(input.m_id.is_none(), "{}: m_id must be absent", case.id);
        assert!(input.addr.is_none(), "{}: addr must be absent", case.id);
        assert!(
            input.transport.is_none(),
            "{}: transport must be absent",
            case.id
        );
        assert!(
            input.ttl_unix.is_none(),
            "{}: ttl_unix must be absent",
            case.id
        );
        assert!(
            input.nonce_hex.is_none(),
            "{}: nonce must be absent",
            case.id
        );
        assert!(
            input.join_request_hash_hex.is_none(),
            "{}: join_request_hash must be absent",
            case.id
        );
        assert!(
            input.authority_head_sequence.is_none(),
            "{}: authority_head_sequence must be absent",
            case.id
        );
        assert!(
            input.authority_head_hash_hex.is_none(),
            "{}: authority_head_hash must be absent",
            case.id
        );
        assert!(
            input.pre_active_credential_count.is_none(),
            "{}: pre_active_credential_count must be absent",
            case.id
        );
        assert!(
            input.recovery_head_sequence.is_none(),
            "{}: recovery_head_sequence must be absent",
            case.id
        );
        assert!(
            input.recovery_head_hash_hex.is_none(),
            "{}: recovery_head_hash must be absent",
            case.id
        );
        assert!(
            input.new_credential_binding_hash_hex.is_none(),
            "{}: new_credential_binding_hash must be absent",
            case.id
        );
        return OwnerApprovalContextV2::mobile_claw_vpn_dev_e2e_execute(
            MobileClawVpnDevE2eApprovalContextInput {
                owner_p_id,
                execution: &execution,
                replay_nonce: unhex_array_32("replay_nonce", &input.replay_nonce_hex),
            },
        )
        .expect("mobile execution context");
    }

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

    if input.op == "recover-credential" {
        let recovery_head = match (
            input.recovery_head_sequence,
            input.recovery_head_hash_hex.as_deref(),
        ) {
            (Some(sequence), Some(head_hash)) => RecoveryAuthorityHeadInput {
                sequence,
                head_hash: unhex_array_32("recovery_head_hash", head_hash),
            },
            _ => panic!("{}: recovery head must be fully present", case.id),
        };
        return OwnerApprovalContextV2::recover_credential(RecoverCredentialContextInput {
            hh_id,
            owner_p_id,
            new_credential_binding_hash: unhex_array_32(
                "new_credential_binding_hash",
                input
                    .new_credential_binding_hash_hex
                    .as_deref()
                    .expect("recover credential new_credential_binding_hash"),
            ),
            authority_head_sequence: input
                .authority_head_sequence
                .expect("recover credential authority_head_sequence"),
            authority_head_hash: unhex_array_32(
                "authority_head_hash",
                input
                    .authority_head_hash_hex
                    .as_deref()
                    .expect("recover credential authority_head_hash"),
            ),
            pre_active_credential_count: input
                .pre_active_credential_count
                .expect("recover credential pre_active_credential_count"),
            recovery_head,
            capabilities: input.capabilities.clone(),
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            replay_nonce: unhex_array_32("replay_nonce", &input.replay_nonce_hex),
        });
    }

    OwnerApprovalContextV2 {
        version: input.v,
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
        mobile_claw_vpn_execution_hash: None,
        capabilities: input.capabilities.clone(),
        issued_at: input.issued_at,
        expires_at: input.expires_at,
        replay_nonce,
    }
}

#[test]
fn mobile_claw_vpn_owner_approval_v1_fixture_sha256_is_immutable() {
    assert_eq!(
        hex(&Sha256::digest(MOBILE_OWNER_APPROVAL_V1_FIXTURE.as_bytes())),
        MOBILE_OWNER_APPROVAL_V1_FIXTURE_SHA256,
        "V1 fixture is immutable; add a new versioned fixture instead"
    );
}

#[test]
fn mobile_claw_vpn_execution_tuple_canonical_bytes_and_hash_match_fixture() {
    for case in mobile_vectors().mobile_claw_vpn_dev_e2e_execution_tuple_v1 {
        let execution = execution_for(&case);
        assert_eq!(
            hex(&execution
                .to_canonical_bytes()
                .expect("canonical tuple bytes")),
            case.canonical_cbor_hex,
            "{}: canonical execution tuple CBOR drifted",
            case.id
        );
        assert_eq!(
            hex(&execution.execution_hash().expect("execution hash")),
            case.execution_sha256_hex,
            "{}: execution tuple hash drifted",
            case.id
        );
    }
}

#[test]
fn owner_approval_v2_canonical_bytes_and_challenge_match_fixture() {
    for case in owner_approval_cases() {
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
    for case in owner_approval_cases() {
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
        if case.input.op != "mobile-claw-vpn-dev-e2e-execute" {
            assert!(
                !keys
                    .iter()
                    .any(|key| key == "mobile_claw_vpn_execution_hash"),
                "{}: legacy context encoded mobile execution hash",
                case.id
            );
        }
    }
}
