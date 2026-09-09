#![cfg(test)]

use super::*;
use crate::keys::{IdentityKey, P256Keypair};
use crate::machine_cert::Platform;
use crate::owner_webauthn::{OwnerWebauthnConfig, OwnerWebauthnRp};
use crate::pair_machine::{JoinChallenge, PAIR_MACHINE_VERSION};
use rand::SeedableRng;
use rand::rngs::StdRng;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{Url, Uuid};

const NOW: u64 = 1_800_000_000;

fn household_id() -> HouseholdId {
    HouseholdId::parse(format!("hh_{}", "a".repeat(52))).unwrap()
}

fn machine_id() -> MachineId {
    MachineId::parse(format!("m_{}", "b".repeat(52))).unwrap()
}

fn person_id() -> PersonId {
    PersonId("p_owner-alpha".to_string())
}

fn sample_context() -> OwnerApprovalContextV2 {
    OwnerApprovalContextV2::pair_machine_approve(PairMachineApprovalContextInput {
        hh_id: household_id(),
        owner_p_id: person_id(),
        cursor: 7,
        m_id: machine_id(),
        addr: "192.0.2.10:8091".to_string(),
        transport: JoinTransport::Lan,
        ttl_unix: 1_800,
        nonce: [0x11; 32],
        join_request_hash: [0x22; 32],
        capabilities: vec!["machine-cert".to_string(), "shamir-2pc".to_string()],
        issued_at: 1_000,
        expires_at: 1_600,
        replay_nonce: [0x33; 32],
    })
}

fn sample_revoke_context() -> OwnerApprovalContextV2 {
    OwnerApprovalContextV2::revoke_credential(RevokeCredentialContextInput {
        hh_id: household_id(),
        owner_p_id: person_id(),
        target_credential_id: b"AAECgP9_".to_vec(),
        authority_head_sequence: 24,
        authority_head_hash: [0x44; 32],
        pre_active_credential_count: 2,
        capabilities: vec!["owner-auth-revoke".to_string()],
        issued_at: 1_000,
        expires_at: 1_600,
        replay_nonce: [0x55; 32],
    })
}

fn sample_provision_recovery_context() -> OwnerApprovalContextV2 {
    OwnerApprovalContextV2::provision_recovery_code(ProvisionRecoveryCodeContextInput {
        hh_id: household_id(),
        owner_p_id: person_id(),
        authority_head_sequence: 24,
        authority_head_hash: [0x44; 32],
        pre_active_credential_count: 2,
        recovery_head: Some(RecoveryAuthorityHeadInput {
            sequence: 0,
            head_hash: [0x77; 32],
        }),
        capabilities: vec!["owner-auth-recovery-provision".to_string()],
        issued_at: 1_000,
        expires_at: 1_600,
        replay_nonce: [0x55; 32],
    })
}

fn sample_add_credential_context() -> OwnerApprovalContextV2 {
    OwnerApprovalContextV2::add_credential(AddCredentialContextInput {
        hh_id: household_id(),
        owner_p_id: person_id(),
        new_credential_binding_hash: *b"AAECgP9_AAECgP9_AAECgP9_AAECgP9_",
        authority_head_sequence: 24,
        authority_head_hash: [0x44; 32],
        pre_active_credential_count: 2,
        capabilities: vec!["owner-auth-add-credential".to_string()],
        issued_at: 1_000,
        expires_at: 1_600,
        replay_nonce: [0x55; 32],
    })
}

fn sample_recover_credential_context() -> OwnerApprovalContextV2 {
    OwnerApprovalContextV2::recover_credential(RecoverCredentialContextInput {
        hh_id: household_id(),
        owner_p_id: person_id(),
        new_credential_binding_hash: *b"RECgP9_RECgP9_RECgP9_RECgP9_RECg",
        authority_head_sequence: 42,
        authority_head_hash: [0x66; 32],
        pre_active_credential_count: 0,
        recovery_head: RecoveryAuthorityHeadInput {
            sequence: 7,
            head_hash: [0x77; 32],
        },
        capabilities: vec!["owner-auth-recovery-consume".to_string()],
        issued_at: 2_000,
        expires_at: 2_600,
        replay_nonce: [0x88; 32],
    })
}

fn sample_mobile_claw_vpn_execution() -> MobileClawVpnDevE2eExecutionTupleV1 {
    MobileClawVpnDevE2eExecutionTupleV1::new(MobileClawVpnDevE2eExecutionTupleInput {
        hh_id: household_id(),
        engine_audience: [0x90; 32],
        member_id: "member-alpha".to_string(),
        attempt_id: "11111111-1111-4111-8111-111111111111".to_string(),
        readiness_run_id: "22222222-2222-4222-8222-222222222222".to_string(),
        source_artifact_git_sha1: [0xaa; 20],
        execution_manifest_sha256: [0xbb; 32],
        device_binding: [0xcc; 32],
        execution_run_id: "33333333-3333-4333-8333-333333333333".to_string(),
        execution_claim_sha256: [0xdd; 32],
        device_id: "device-alpha".to_string(),
        claw_id: "claw-alpha".to_string(),
        device_alias: "Device-D".to_string(),
        claw_alias: "Claw-M".to_string(),
        issued_at: 1_000,
        expires_at: 1_060,
        server_nonce: [0xee; 32],
    })
}

fn sample_mobile_claw_vpn_context() -> OwnerApprovalContextV2 {
    let execution = sample_mobile_claw_vpn_execution();
    OwnerApprovalContextV2::mobile_claw_vpn_dev_e2e_execute(
        MobileClawVpnDevE2eApprovalContextInput {
            owner_p_id: person_id(),
            execution: &execution,
            replay_nonce: [0xf0; 32],
        },
    )
    .unwrap()
}

fn sample_approval(context: OwnerApprovalContextV2) -> OwnerApprovalV2 {
    OwnerApprovalV2 {
        version: OWNER_APPROVAL_V2_VERSION,
        context,
        credential_id: ByteBuf::from(vec![0xA1; 16]),
        authenticator_data: ByteBuf::from(vec![0xA2; 37]),
        client_data_json: ByteBuf::from(br#"{"type":"webauthn.get"}"#.to_vec()),
        signature: ByteBuf::from(vec![0xA3; 64]),
        user_handle: None,
    }
}

fn owner_webauthn_rp() -> OwnerWebauthnRp {
    let config = OwnerWebauthnConfig::new(
        "alpha.example.test",
        Url::parse("https://alpha.example.test").unwrap(),
        "Soyeht Alpha",
    )
    .unwrap();
    OwnerWebauthnRp::new(config).unwrap()
}

fn register_softpasskey(
    rp: &mut OwnerWebauthnRp,
    rng: &mut StdRng,
) -> (
    crate::owner_webauthn::OwnerWebauthnCredential,
    WebauthnAuthenticator<SoftPasskey>,
) {
    let (challenge_id, challenge) = rp
        .start_registration(rng, NOW, Uuid::new_v4(), "owner-alpha", "Owner Alpha", &[])
        .unwrap();
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let response = authenticator
        .do_registration(Url::parse("https://alpha.example.test").unwrap(), challenge)
        .unwrap();
    let credential = rp
        .finish_registration(NOW, &challenge_id, &response)
        .unwrap();
    (credential, authenticator)
}

fn approval_from_assertion(
    context: OwnerApprovalContextV2,
    assertion: &PublicKeyCredential,
) -> OwnerApprovalV2 {
    OwnerApprovalV2 {
        version: OWNER_APPROVAL_V2_VERSION,
        context,
        credential_id: ByteBuf::from(assertion.raw_id.as_slice().to_vec()),
        authenticator_data: ByteBuf::from(
            assertion.response.authenticator_data.as_slice().to_vec(),
        ),
        client_data_json: ByteBuf::from(assertion.response.client_data_json.as_slice().to_vec()),
        signature: ByteBuf::from(assertion.response.signature.as_slice().to_vec()),
        user_handle: assertion
            .response
            .user_handle
            .as_ref()
            .map(|user_handle| ByteBuf::from(user_handle.as_slice().to_vec())),
    }
}

fn signed_join_request() -> (P256Keypair, JoinRequest, Vec<u8>) {
    let kp = P256Keypair::generate();
    let m_pub = *kp.public().as_bytes();
    let nonce = [0x44; 32];
    let challenge = JoinChallenge::build(&m_pub, &nonce, "linux-alpha", Platform::LinuxNix);
    let canonical = challenge.to_canonical_bytes().unwrap();
    let sig = kp.sign(&canonical).unwrap();
    let request = JoinRequest {
        version: PAIR_MACHINE_VERSION,
        m_pub: ByteBuf::from(m_pub.to_vec()),
        hostname: "linux-alpha".into(),
        platform: Platform::LinuxNix,
        nonce: ByteBuf::from(nonce.to_vec()),
        addr: "192.0.2.10:8091".into(),
        transport: JoinTransport::Lan,
        challenge_sig: ByteBuf::from(sig.0.to_vec()),
    };
    let bytes = request.to_canonical_bytes().unwrap();
    (kp, request, bytes)
}

fn awaiting_owner_snapshot(
    request: &JoinRequest,
    request_bytes: &[u8],
) -> PairMachineWindowSnapshot {
    PairMachineWindowSnapshot {
        version: PAIR_MACHINE_VERSION,
        state: PairMachineState::AwaitingOwner,
        m_pub: Some(request.m_pub.clone()),
        nonce: Some(request.nonce.clone()),
        expiry: Some(1_600),
        transport: Some(request.transport),
        addr_hint: Some(request.addr.clone()),
        fingerprint: Some("fp-neutral".into()),
        owner_event_cursor: Some(7),
        cached_join_request: Some(ByteBuf::from(request_bytes.to_vec())),
        cached_response: None,
        anchor_secret: None,
        pinned_hh_pub: None,
        pinned_hh_id: None,
        approval_claim: None,
        lifecycle_generation: None,
    }
}

#[test]
fn pair_machine_context_canonical_bytes_are_stable() {
    let ctx = sample_context();
    let bytes = ctx.to_canonical_bytes().unwrap();
    let decoded = OwnerApprovalContextV2::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(decoded, ctx);
    assert_eq!(
        hex::encode(bytes),
        concat!(
            "b0617602626f7074706169722d6d616368696e652d617070726f766564616464726f3139",
            "322e302e322e31303a38303931646d5f696478366d5f6262626262626262626262626262",
            "626262626262626262626262626262626262626262626262626262626262626262626262",
            "62626568685f6964783768685f6161616161616161616161616161616161616161616161",
            "6161616161616161616161616161616161616161616161616161616161656e6f6e636558",
            "201111111111111111111111111111111111111111111111111111111111111111666375",
            "72736f720767707572706f7365716f776e65722d617070726f76616c2d76326874746c5f",
            "756e6978190708696973737565645f61741903e8697472616e73706f7274636c616e6a65",
            "7870697265735f61741906406a6f776e65725f705f69646d705f6f776e65722d616c7068",
            "616c6361706162696c6974696573826c6d616368696e652d636572746a7368616d69722d",
            "3270636c7265706c61795f6e6f6e63655820333333333333333333333333333333333333",
            "3333333333333333333333333333716a6f696e5f726571756573745f6861736858202222",
            "222222222222222222222222222222222222222222222222222222222222"
        )
    );
}

#[test]
fn challenge_digest_changes_when_bound_fields_change() {
    let baseline = sample_context().challenge_digest().unwrap();

    let mut changed_op = sample_context();
    changed_op.op = OwnerOperation::BootstrapTeardown;
    changed_op.cursor = None;
    changed_op.m_id = None;
    changed_op.addr = None;
    changed_op.transport = None;
    changed_op.ttl_unix = None;
    changed_op.nonce = None;
    changed_op.join_request_hash = None;
    assert_ne!(changed_op.challenge_digest().unwrap(), baseline);

    let mut changed_addr = sample_context();
    changed_addr.addr = Some("198.51.100.10:8091".to_string());
    assert_ne!(changed_addr.challenge_digest().unwrap(), baseline);

    let mut changed_transport = sample_context();
    changed_transport.transport = Some(JoinTransport::Tailscale);
    assert_ne!(changed_transport.challenge_digest().unwrap(), baseline);

    let mut changed_ttl = sample_context();
    changed_ttl.ttl_unix = Some(1_801);
    assert_ne!(changed_ttl.challenge_digest().unwrap(), baseline);

    let mut changed_nonce = sample_context();
    changed_nonce.nonce = Some(ByteBuf::from(vec![0x44; 32]));
    assert_ne!(changed_nonce.challenge_digest().unwrap(), baseline);

    let mut changed_machine = sample_context();
    changed_machine.m_id = Some(MachineId::parse(format!("m_{}", "c".repeat(52))).unwrap());
    assert_ne!(changed_machine.challenge_digest().unwrap(), baseline);

    let mut changed_join_hash = sample_context();
    changed_join_hash.join_request_hash = Some(ByteBuf::from(vec![0x55; 32]));
    assert_ne!(changed_join_hash.challenge_digest().unwrap(), baseline);

    let mut changed_capabilities = sample_context();
    changed_capabilities.capabilities = vec!["machine-cert".to_string(), "push-token".to_string()];
    assert_ne!(changed_capabilities.challenge_digest().unwrap(), baseline);
}

#[test]
fn mobile_claw_vpn_execution_tuple_round_trips_and_hashes_canonical_cbor() {
    let execution = sample_mobile_claw_vpn_execution();
    let canonical = execution.to_canonical_bytes().unwrap();
    let decoded = MobileClawVpnDevE2eExecutionTupleV1::from_canonical_bytes(&canonical).unwrap();
    assert_eq!(decoded, execution);
    assert_eq!(execution.execution_hash().unwrap().len(), 32);
}

#[test]
fn mobile_claw_vpn_execution_hash_changes_for_every_mutable_tuple_field() {
    let baseline = sample_mobile_claw_vpn_execution();
    let baseline_bytes = baseline.to_canonical_bytes().unwrap();
    let baseline_hash = baseline.execution_hash().unwrap();
    let baseline_context = OwnerApprovalContextV2::mobile_claw_vpn_dev_e2e_execute(
        MobileClawVpnDevE2eApprovalContextInput {
            owner_p_id: person_id(),
            execution: &baseline,
            replay_nonce: [0xf0; 32],
        },
    )
    .unwrap();
    let baseline_challenge = baseline_context.challenge_digest().unwrap();
    let mut mutations = Vec::new();

    let mut value = baseline.clone();
    value.hh_id = HouseholdId::parse(format!("hh_{}", "c".repeat(52))).unwrap();
    mutations.push(("hh_id", value));
    let mut value = baseline.clone();
    value.engine_audience = ByteBuf::from(vec![0x91; 32]);
    mutations.push(("engine_audience", value));
    let mut value = baseline.clone();
    value.member_id = "member-beta".to_string();
    mutations.push(("member_id", value));
    let mut value = baseline.clone();
    value.attempt_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string();
    mutations.push(("attempt_id", value));
    let mut value = baseline.clone();
    value.readiness_run_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_string();
    mutations.push(("readiness_run_id", value));
    let mut value = baseline.clone();
    value.source_artifact_git_sha1 = ByteBuf::from(vec![0xa1; 20]);
    mutations.push(("source_artifact_git_sha1", value));
    let mut value = baseline.clone();
    value.execution_manifest_sha256 = ByteBuf::from(vec![0xb1; 32]);
    mutations.push(("execution_manifest_sha256", value));
    let mut value = baseline.clone();
    value.device_binding = ByteBuf::from(vec![0xc1; 32]);
    mutations.push(("device_binding", value));
    let mut value = baseline.clone();
    value.execution_run_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_string();
    mutations.push(("execution_run_id", value));
    let mut value = baseline.clone();
    value.execution_claim_sha256 = ByteBuf::from(vec![0xd1; 32]);
    mutations.push(("execution_claim_sha256", value));
    let mut value = baseline.clone();
    value.device_id = "device-beta".to_string();
    mutations.push(("device_id", value));
    let mut value = baseline.clone();
    value.claw_id = "claw-beta".to_string();
    mutations.push(("claw_id", value));
    let mut value = baseline.clone();
    value.claw_alias = "Claw-L".to_string();
    mutations.push(("claw_alias", value));
    let mut value = baseline.clone();
    value.issued_at = 1_001;
    mutations.push(("issued_at", value));
    let mut value = baseline.clone();
    value.expires_at = 1_061;
    mutations.push(("expires_at", value));
    let mut value = baseline.clone();
    value.server_nonce = ByteBuf::from(vec![0xe1; 32]);
    mutations.push(("server_nonce", value));

    for (field, mutation) in mutations {
        assert_ne!(
            mutation.to_canonical_bytes().unwrap(),
            baseline_bytes,
            "{field}: canonical tuple bytes did not change"
        );
        assert_ne!(
            mutation.execution_hash().unwrap(),
            baseline_hash,
            "{field}: execution hash did not change"
        );
        let mutated_context = OwnerApprovalContextV2::mobile_claw_vpn_dev_e2e_execute(
            MobileClawVpnDevE2eApprovalContextInput {
                owner_p_id: person_id(),
                execution: &mutation,
                replay_nonce: [0xf0; 32],
            },
        )
        .unwrap();
        assert_ne!(
            mutated_context.challenge_digest().unwrap(),
            baseline_challenge,
            "{field}: owner approval challenge did not change"
        );
    }
}

#[test]
fn mobile_claw_vpn_execution_hash_is_domain_separated_and_length_delimited() {
    let baseline = sample_mobile_claw_vpn_execution();
    let canonical = baseline.to_canonical_bytes().unwrap();
    let undomained: [u8; 32] = Sha256::digest(&canonical).into();
    assert_ne!(baseline.execution_hash().unwrap(), undomained);

    let mut left = baseline.clone();
    left.member_id = "a".to_string();
    left.device_id = "bc".to_string();
    let mut right = baseline;
    right.member_id = "ab".to_string();
    right.device_id = "c".to_string();
    assert_ne!(
        left.to_canonical_bytes().unwrap(),
        right.to_canonical_bytes().unwrap()
    );
    assert_ne!(
        left.execution_hash().unwrap(),
        right.execution_hash().unwrap()
    );
}

#[test]
fn mobile_claw_vpn_execution_tuple_rejects_fixed_field_and_length_drift() {
    let baseline = sample_mobile_claw_vpn_execution();

    let mut invalid = baseline.clone();
    invalid.version = 2;
    assert!(matches!(
        invalid.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField(
            "mobile_claw_vpn_execution.v"
        ))
    ));
    let mut invalid = baseline.clone();
    invalid.purpose = "other".to_string();
    assert!(matches!(
        invalid.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField(
            "mobile_claw_vpn_execution.purpose"
        ))
    ));
    let mut invalid = baseline.clone();
    invalid.op = OwnerOperation::PairMachineApprove;
    assert!(matches!(
        invalid.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField(
            "mobile_claw_vpn_execution.op"
        ))
    ));
    let mut invalid = baseline.clone();
    invalid.bundle_id = "com.soyeht.app".to_string();
    assert!(matches!(
        invalid.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField("bundle_id"))
    ));
    let mut invalid = baseline.clone();
    invalid.hh_id = HouseholdId("hh_test".to_string());
    assert!(matches!(
        invalid.to_canonical_bytes(),
        Err(OwnerApprovalV2Error::InvalidField(
            "mobile_claw_vpn_execution.hh_id"
        ))
    ));
    let mut invalid = baseline.clone();
    invalid.device_alias = "Device-X".to_string();
    assert!(matches!(
        invalid.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField("device_alias"))
    ));
    let mut invalid = baseline.clone();
    invalid.source_artifact_git_sha1 = ByteBuf::from(vec![0xaa; 19]);
    assert!(matches!(
        invalid.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField(
            "source_artifact_git_sha1"
        ))
    ));
    let mut invalid = baseline;
    invalid.server_nonce = ByteBuf::from(vec![0xee; 33]);
    assert!(matches!(
        invalid.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField("server_nonce"))
    ));
}

#[test]
fn mobile_claw_vpn_context_requires_exact_operation_specific_hash() {
    let context = sample_mobile_claw_vpn_context();
    let expected_hash = sample_mobile_claw_vpn_execution().execution_hash().unwrap();
    assert_eq!(
        context
            .mobile_claw_vpn_execution_hash
            .as_ref()
            .unwrap()
            .as_ref(),
        expected_hash.as_slice()
    );
    assert_eq!(context.capabilities, [MOBILE_CLAW_VPN_DEV_E2E_CAPABILITY]);

    let baseline_challenge = context.challenge_digest().unwrap();
    let mut changed_hash = context.clone();
    changed_hash.mobile_claw_vpn_execution_hash = Some(ByteBuf::from(vec![0x45; 32]));
    assert_ne!(changed_hash.challenge_digest().unwrap(), baseline_challenge);

    let mut context_mutations = Vec::new();
    let mut mutation = context.clone();
    mutation.hh_id = HouseholdId::parse(format!("hh_{}", "c".repeat(52))).unwrap();
    context_mutations.push(("hh_id", mutation));
    let mut mutation = context.clone();
    mutation.owner_p_id = PersonId("p_owner-beta".to_string());
    context_mutations.push(("owner_p_id", mutation));
    let mut mutation = context.clone();
    mutation.issued_at = 1_001;
    context_mutations.push(("issued_at", mutation));
    let mut mutation = context.clone();
    mutation.expires_at = 1_059;
    context_mutations.push(("expires_at", mutation));
    let mut mutation = context.clone();
    mutation.replay_nonce = ByteBuf::from(vec![0xf1; 32]);
    context_mutations.push(("replay_nonce", mutation));
    for (field, mutation) in context_mutations {
        assert_ne!(
            mutation.challenge_digest().unwrap(),
            baseline_challenge,
            "{field}: owner approval challenge did not change"
        );
    }

    let mut wrong_operation = context.clone();
    wrong_operation.op = OwnerOperation::PairMachineApprove;
    assert!(wrong_operation.to_canonical_bytes().is_err());
    assert!(wrong_operation.challenge_digest().is_err());
    let wrong_operation_bytes = crate::cbor::to_canonical_vec(&wrong_operation).unwrap();
    assert!(
        OwnerApprovalContextV2::from_canonical_bytes(&wrong_operation_bytes).is_err(),
        "cross-op execution hash must fail during canonical decode"
    );

    let mut missing = context.clone();
    missing.mobile_claw_vpn_execution_hash = None;
    assert!(matches!(
        missing.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField(
            "mobile_claw_vpn_execution_hash"
        ))
    ));
    assert!(missing.to_canonical_bytes().is_err());
    let missing_bytes = crate::cbor::to_canonical_vec(&missing).unwrap();
    assert!(
        OwnerApprovalContextV2::from_canonical_bytes(&missing_bytes).is_err(),
        "execute without tuple hash must fail during canonical decode"
    );

    for length in [31, 33] {
        let mut invalid = context.clone();
        invalid.mobile_claw_vpn_execution_hash = Some(ByteBuf::from(vec![0x44; length]));
        assert!(matches!(
            invalid.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField(
                "mobile_claw_vpn_execution_hash"
            ))
        ));
        assert!(invalid.to_canonical_bytes().is_err());
        let invalid_bytes = crate::cbor::to_canonical_vec(&invalid).unwrap();
        assert!(
            OwnerApprovalContextV2::from_canonical_bytes(&invalid_bytes).is_err(),
            "{length}-byte execution hash must fail during canonical decode"
        );
    }

    let mut zero_ttl = context.clone();
    zero_ttl.expires_at = zero_ttl.issued_at;
    assert!(matches!(
        zero_ttl.challenge_digest(),
        Err(OwnerApprovalV2Error::InvalidTimeWindow)
    ));
    let mut excessive_ttl = context.clone();
    excessive_ttl.expires_at = excessive_ttl.issued_at + 121;
    assert!(matches!(
        excessive_ttl.challenge_digest(),
        Err(OwnerApprovalV2Error::InvalidTimeWindow)
    ));

    let mut invalid_household = context.clone();
    invalid_household.hh_id = HouseholdId("hh_test".to_string());
    assert!(matches!(
        invalid_household.challenge_digest(),
        Err(OwnerApprovalV2Error::InvalidField("hh_id"))
    ));
    let mut invalid_owner = context.clone();
    invalid_owner.owner_p_id = PersonId("owner-alpha".to_string());
    assert!(matches!(
        invalid_owner.challenge_digest(),
        Err(OwnerApprovalV2Error::InvalidField("owner_p_id"))
    ));

    let mut injected = sample_context();
    injected.mobile_claw_vpn_execution_hash = Some(ByteBuf::from(vec![0x44; 32]));
    assert!(matches!(
        injected.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField(
            "mobile_claw_vpn_execution_hash"
        ))
    ));
}

#[test]
fn pair_machine_required_fields_are_enforced() {
    let mut missing = sample_context();
    missing.join_request_hash = None;
    assert!(matches!(
        missing.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField("join_request_hash"))
    ));
}

#[test]
fn pair_machine_rejects_revoke_fields() {
    let mut invalid = sample_context();
    invalid.target_credential_id = Some(ByteBuf::from(vec![0x41]));
    assert!(matches!(
        invalid.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField(
            "target_credential_id"
        ))
    ));
}

#[test]
fn revoke_credential_context_round_trips_as_canonical_cbor() {
    let ctx = sample_revoke_context();
    let bytes = ctx.to_canonical_bytes().unwrap();
    let decoded = OwnerApprovalContextV2::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(decoded, ctx);

    let hex = hex::encode(&bytes);
    assert!(hex.contains("717265766f6b652d63726564656e7469616c"));
    assert!(hex.contains("747461726765745f63726564656e7469616c5f696448414145436750395f"));
    assert!(
        !hex.contains("6461646472"),
        "revoke context must not carry pair-machine addr",
    );
    assert!(
        !hex.contains("716a6f696e5f726571756573745f68617368"),
        "revoke context must not carry pair-machine join_request_hash",
    );
}

#[test]
fn revoke_credential_required_fields_are_enforced() {
    let mut missing_target = sample_revoke_context();
    missing_target.target_credential_id = None;
    assert!(matches!(
        missing_target.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField("target_credential_id"))
    ));

    let mut missing_sequence = sample_revoke_context();
    missing_sequence.authority_head_sequence = None;
    assert!(matches!(
        missing_sequence.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField(
            "authority_head_sequence"
        ))
    ));

    let mut missing_hash = sample_revoke_context();
    missing_hash.authority_head_hash = None;
    assert!(matches!(
        missing_hash.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField("authority_head_hash"))
    ));

    let mut missing_count = sample_revoke_context();
    missing_count.pre_active_credential_count = None;
    assert!(matches!(
        missing_count.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField(
            "pre_active_credential_count"
        ))
    ));
}

#[test]
fn revoke_credential_rejects_invalid_field_values() {
    let mut empty_target = sample_revoke_context();
    empty_target.target_credential_id = Some(ByteBuf::from(vec![]));
    assert!(matches!(
        empty_target.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField("target_credential_id"))
    ));

    let mut short_hash = sample_revoke_context();
    short_hash.authority_head_hash = Some(ByteBuf::from(vec![0x44; 31]));
    assert!(matches!(
        short_hash.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"))
    ));

    let mut zero_count = sample_revoke_context();
    zero_count.pre_active_credential_count = Some(0);
    assert!(matches!(
        zero_count.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField(
            "pre_active_credential_count"
        ))
    ));
}

#[test]
fn revoke_credential_rejects_pair_machine_fields() {
    let mut invalid = sample_revoke_context();
    invalid.cursor = Some(7);
    assert!(matches!(
        invalid.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField("cursor"))
    ));
}

#[test]
fn provision_recovery_code_context_round_trips_as_canonical_cbor() {
    let ctx = sample_provision_recovery_context();
    let bytes = ctx.to_canonical_bytes().unwrap();
    let decoded = OwnerApprovalContextV2::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(decoded, ctx);

    let hex = hex::encode(&bytes);
    assert!(hex.contains("7770726f766973696f6e2d7265636f766572792d636f6465"));
    assert!(hex.contains("727265636f766572795f686561645f686173685820"));
    assert!(
        !hex.contains("747461726765745f63726564656e7469616c5f6964"),
        "provision recovery context must not carry revoke target",
    );
    assert!(
        !hex.contains("716a6f696e5f726571756573745f68617368"),
        "provision recovery context must not carry pair-machine join_request_hash",
    );
}

#[test]
fn provision_recovery_code_required_fields_are_enforced() {
    let mut missing_sequence = sample_provision_recovery_context();
    missing_sequence.authority_head_sequence = None;
    assert!(matches!(
        missing_sequence.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField(
            "authority_head_sequence"
        ))
    ));

    let mut missing_hash = sample_provision_recovery_context();
    missing_hash.authority_head_hash = None;
    assert!(matches!(
        missing_hash.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField("authority_head_hash"))
    ));

    let mut missing_count = sample_provision_recovery_context();
    missing_count.pre_active_credential_count = None;
    assert!(matches!(
        missing_count.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField(
            "pre_active_credential_count"
        ))
    ));
}

#[test]
fn provision_recovery_code_rejects_invalid_values_and_foreign_fields() {
    let mut short_hash = sample_provision_recovery_context();
    short_hash.authority_head_hash = Some(ByteBuf::from(vec![0x44; 31]));
    assert!(matches!(
        short_hash.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"))
    ));

    let mut zero_count = sample_provision_recovery_context();
    zero_count.pre_active_credential_count = Some(0);
    assert!(matches!(
        zero_count.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField(
            "pre_active_credential_count"
        ))
    ));

    let mut half_head = sample_provision_recovery_context();
    half_head.recovery_head_hash = None;
    assert!(matches!(
        half_head.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField("recovery_head_hash"))
    ));

    let mut with_revoke_field = sample_provision_recovery_context();
    with_revoke_field.target_credential_id = Some(ByteBuf::from(vec![0x41]));
    assert!(matches!(
        with_revoke_field.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField(
            "target_credential_id"
        ))
    ));

    let mut with_pair_field = sample_provision_recovery_context();
    with_pair_field.cursor = Some(7);
    assert!(matches!(
        with_pair_field.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField("cursor"))
    ));
}

#[test]
fn non_recovery_contexts_reject_recovery_fields() {
    let mut pair_machine = sample_context();
    pair_machine.recovery_head_sequence = Some(0);
    assert!(matches!(
        pair_machine.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField(
            "recovery_head_sequence"
        ))
    ));

    let mut revoke = sample_revoke_context();
    revoke.recovery_head_hash = Some(ByteBuf::from(vec![0x77; 32]));
    assert!(matches!(
        revoke.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField("recovery_head_hash"))
    ));
}

#[test]
fn add_credential_context_round_trips_as_canonical_cbor() {
    let ctx = sample_add_credential_context();
    let bytes = ctx.to_canonical_bytes().unwrap();
    let decoded = OwnerApprovalContextV2::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(decoded, ctx);

    let hex = hex::encode(&bytes);
    assert!(hex.contains("6e6164642d63726564656e7469616c"));
    assert!(hex.contains("781b6e65775f63726564656e7469616c5f62696e64696e675f686173685820"));
    assert!(
        !hex.contains("747461726765745f63726564656e7469616c5f6964"),
        "add credential context must not carry revoke target",
    );
    assert!(
        !hex.contains("727265636f766572795f686561645f68617368"),
        "add credential context must not carry recovery head",
    );
}

#[test]
fn add_credential_required_fields_are_enforced() {
    let mut missing_binding = sample_add_credential_context();
    missing_binding.new_credential_binding_hash = None;
    assert!(matches!(
        missing_binding.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField(
            "new_credential_binding_hash"
        ))
    ));

    let mut missing_sequence = sample_add_credential_context();
    missing_sequence.authority_head_sequence = None;
    assert!(matches!(
        missing_sequence.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField(
            "authority_head_sequence"
        ))
    ));

    let mut missing_hash = sample_add_credential_context();
    missing_hash.authority_head_hash = None;
    assert!(matches!(
        missing_hash.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField("authority_head_hash"))
    ));

    let mut missing_count = sample_add_credential_context();
    missing_count.pre_active_credential_count = None;
    assert!(matches!(
        missing_count.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField(
            "pre_active_credential_count"
        ))
    ));
}

#[test]
fn add_credential_rejects_invalid_values_and_foreign_fields() {
    let mut short_binding = sample_add_credential_context();
    short_binding.new_credential_binding_hash = Some(ByteBuf::from(vec![0x41; 31]));
    assert!(matches!(
        short_binding.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField(
            "new_credential_binding_hash"
        ))
    ));

    let mut short_hash = sample_add_credential_context();
    short_hash.authority_head_hash = Some(ByteBuf::from(vec![0x44; 31]));
    assert!(matches!(
        short_hash.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"))
    ));

    let mut zero_count = sample_add_credential_context();
    zero_count.pre_active_credential_count = Some(0);
    assert!(matches!(
        zero_count.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField(
            "pre_active_credential_count"
        ))
    ));

    let mut with_revoke_field = sample_add_credential_context();
    with_revoke_field.target_credential_id = Some(ByteBuf::from(vec![0x41]));
    assert!(matches!(
        with_revoke_field.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField(
            "target_credential_id"
        ))
    ));

    let mut with_recovery_field = sample_add_credential_context();
    with_recovery_field.recovery_head_hash = Some(ByteBuf::from(vec![0x77; 32]));
    assert!(matches!(
        with_recovery_field.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField("recovery_head_hash"))
    ));

    let mut with_pair_field = sample_add_credential_context();
    with_pair_field.cursor = Some(7);
    assert!(matches!(
        with_pair_field.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField("cursor"))
    ));
}

#[test]
fn non_add_contexts_reject_add_credential_fields() {
    let mut pair_machine = sample_context();
    pair_machine.new_credential_binding_hash = Some(ByteBuf::from(vec![0x41; 32]));
    assert!(matches!(
        pair_machine.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField(
            "new_credential_binding_hash"
        ))
    ));

    let mut revoke = sample_revoke_context();
    revoke.new_credential_binding_hash = Some(ByteBuf::from(vec![0x41; 32]));
    assert!(matches!(
        revoke.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField(
            "new_credential_binding_hash"
        ))
    ));

    let mut recovery = sample_provision_recovery_context();
    recovery.new_credential_binding_hash = Some(ByteBuf::from(vec![0x41; 32]));
    assert!(matches!(
        recovery.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField(
            "new_credential_binding_hash"
        ))
    ));
}

#[test]
fn recover_credential_context_round_trips_as_canonical_cbor() {
    let ctx = sample_recover_credential_context();
    let bytes = ctx.to_canonical_bytes().unwrap();
    let decoded = OwnerApprovalContextV2::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(decoded, ctx);

    let hex = hex::encode(&bytes);
    assert!(hex.contains("727265636f7665722d63726564656e7469616c"));
    assert!(hex.contains("727265636f766572795f686561645f686173685820"));
    assert!(hex.contains("781b6e65775f63726564656e7469616c5f62696e64696e675f686173685820"));
    assert!(
        !hex.contains("747461726765745f63726564656e7469616c5f6964"),
        "recover credential context must not carry revoke target",
    );
    assert!(
        !hex.contains("716a6f696e5f726571756573745f68617368"),
        "recover credential context must not carry pair-machine join_request_hash",
    );
}

#[test]
fn recover_credential_required_fields_are_enforced() {
    let mut missing_binding = sample_recover_credential_context();
    missing_binding.new_credential_binding_hash = None;
    assert!(matches!(
        missing_binding.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField(
            "new_credential_binding_hash"
        ))
    ));

    let mut missing_sequence = sample_recover_credential_context();
    missing_sequence.authority_head_sequence = None;
    assert!(matches!(
        missing_sequence.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField(
            "authority_head_sequence"
        ))
    ));

    let mut missing_hash = sample_recover_credential_context();
    missing_hash.authority_head_hash = None;
    assert!(matches!(
        missing_hash.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField("authority_head_hash"))
    ));

    let mut missing_count = sample_recover_credential_context();
    missing_count.pre_active_credential_count = None;
    assert!(matches!(
        missing_count.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField(
            "pre_active_credential_count"
        ))
    ));

    let mut missing_recovery_sequence = sample_recover_credential_context();
    missing_recovery_sequence.recovery_head_sequence = None;
    assert!(matches!(
        missing_recovery_sequence.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField("recovery_head_sequence"))
    ));

    let mut missing_recovery_hash = sample_recover_credential_context();
    missing_recovery_hash.recovery_head_hash = None;
    assert!(matches!(
        missing_recovery_hash.validate_shape(),
        Err(OwnerApprovalV2Error::MissingField("recovery_head_hash"))
    ));
}

#[test]
fn recover_credential_allows_zero_active_count_as_telemetry() {
    let mut context = sample_recover_credential_context();
    context.pre_active_credential_count = Some(0);
    context.validate_shape().unwrap();
}

#[test]
fn recover_credential_rejects_invalid_values_and_foreign_fields() {
    let mut short_binding = sample_recover_credential_context();
    short_binding.new_credential_binding_hash = Some(ByteBuf::from(vec![0x41; 31]));
    assert!(matches!(
        short_binding.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField(
            "new_credential_binding_hash"
        ))
    ));

    let mut short_authority_hash = sample_recover_credential_context();
    short_authority_hash.authority_head_hash = Some(ByteBuf::from(vec![0x66; 31]));
    assert!(matches!(
        short_authority_hash.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"))
    ));

    let mut short_recovery_hash = sample_recover_credential_context();
    short_recovery_hash.recovery_head_hash = Some(ByteBuf::from(vec![0x77; 31]));
    assert!(matches!(
        short_recovery_hash.validate_shape(),
        Err(OwnerApprovalV2Error::InvalidField("recovery_head_hash"))
    ));

    let mut with_revoke_field = sample_recover_credential_context();
    with_revoke_field.target_credential_id = Some(ByteBuf::from(vec![0x41]));
    assert!(matches!(
        with_revoke_field.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField(
            "target_credential_id"
        ))
    ));

    let mut with_pair_field = sample_recover_credential_context();
    with_pair_field.cursor = Some(7);
    assert!(matches!(
        with_pair_field.validate_shape(),
        Err(OwnerApprovalV2Error::UnexpectedField("cursor"))
    ));
}

#[test]
fn expired_context_is_rejected() {
    let ctx = sample_context();
    assert!(matches!(
        ctx.validate_at(1_601),
        Err(OwnerApprovalV2Error::Expired {
            now: 1_601,
            expires_at: 1_600
        })
    ));
}

#[test]
fn capabilities_must_be_sorted_and_unique() {
    let mut unsorted = sample_context();
    unsorted.capabilities = vec!["shamir-2pc".to_string(), "machine-cert".to_string()];
    assert!(matches!(
        unsorted.validate_shape(),
        Err(OwnerApprovalV2Error::CapabilitiesNotSorted)
    ));

    let mut duplicate = sample_context();
    duplicate.capabilities = vec!["machine-cert".to_string(), "machine-cert".to_string()];
    assert!(matches!(
        duplicate.validate_shape(),
        Err(OwnerApprovalV2Error::DuplicateCapability(cap))
            if cap == "machine-cert"
    ));
}

#[test]
fn none_fields_are_omitted_for_non_pair_machine_operations() {
    let ctx = OwnerApprovalContextV2 {
        version: OWNER_APPROVAL_V2_VERSION,
        purpose: OWNER_APPROVAL_V2_PURPOSE.to_string(),
        op: OwnerOperation::BootstrapTeardown,
        hh_id: household_id(),
        owner_p_id: person_id(),
        cursor: None,
        m_id: None,
        addr: None,
        transport: None,
        ttl_unix: None,
        nonce: None,
        join_request_hash: None,
        target_credential_id: None,
        authority_head_sequence: None,
        authority_head_hash: None,
        pre_active_credential_count: None,
        recovery_head_sequence: None,
        recovery_head_hash: None,
        new_credential_binding_hash: None,
        mobile_claw_vpn_execution_hash: None,
        capabilities: vec![],
        issued_at: 1_000,
        expires_at: 1_100,
        replay_nonce: ByteBuf::from(vec![0x77; 32]),
    };

    let bytes = ctx.to_canonical_bytes().unwrap();
    let value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    let ciborium::value::Value::Map(entries) = value else {
        panic!("context encodes as map");
    };
    let keys: Vec<String> = entries
        .into_iter()
        .map(|(key, _)| match key {
            ciborium::value::Value::Text(text) => text,
            other => panic!("unexpected key: {other:?}"),
        })
        .collect();

    for omitted in [
        "cursor",
        "m_id",
        "addr",
        "transport",
        "ttl_unix",
        "nonce",
        "join_request_hash",
        "target_credential_id",
        "authority_head_sequence",
        "authority_head_hash",
        "pre_active_credential_count",
    ] {
        assert!(!keys.iter().any(|key| key == omitted), "{omitted} encoded");
    }
}

#[test]
fn owner_approval_body_requires_expected_context_byte_equality() {
    let expected = sample_context();
    let approval = sample_approval(expected.clone());
    assert_eq!(
        approval.require_expected_context(&expected).unwrap(),
        expected.challenge_digest().unwrap()
    );

    let mut tampered = expected.clone();
    tampered.addr = Some("198.51.100.10:8091".to_string());
    let err = approval.require_expected_context(&tampered).unwrap_err();
    assert!(matches!(err, OwnerApprovalV2Error::ContextMismatch));
}

#[test]
fn owner_approval_body_rejects_empty_assertion_fields() {
    let mut approval = sample_approval(sample_context());
    approval.signature = ByteBuf::from(vec![]);
    assert!(matches!(
        approval.validate_shape(),
        Err(OwnerApprovalV2Error::AssertionField("signature"))
    ));
}

#[test]
fn owner_approval_body_converts_to_webauthn_public_key_credential() {
    let mut rp = owner_webauthn_rp();
    let mut rng = StdRng::seed_from_u64(61);
    let (mut credential, mut authenticator) = register_softpasskey(&mut rp, &mut rng);
    let expected_context = sample_context();

    let (challenge_id, challenge) = rp
        .start_owner_approval_assertion(&mut rng, NOW + 1, &[credential.clone()], &expected_context)
        .unwrap();
    let assertion = authenticator
        .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
        .unwrap();
    let approval = approval_from_assertion(expected_context.clone(), &assertion);

    let converted = approval.to_public_key_credential().unwrap();
    assert_eq!(
        converted.id,
        data_encoding::BASE64URL_NOPAD.encode(approval.credential_id.as_ref())
    );
    assert_eq!(converted.type_, "public-key");
    assert_eq!(converted.raw_id.as_slice(), assertion.raw_id.as_slice());
    assert_eq!(
        converted.response.authenticator_data.as_slice(),
        assertion.response.authenticator_data.as_slice()
    );
    assert_eq!(
        converted.response.client_data_json.as_slice(),
        assertion.response.client_data_json.as_slice()
    );
    assert_eq!(
        converted.response.signature.as_slice(),
        assertion.response.signature.as_slice()
    );
    assert_eq!(
        converted
            .response
            .user_handle
            .as_ref()
            .map(|user_handle| user_handle.as_slice()),
        assertion
            .response
            .user_handle
            .as_ref()
            .map(|user_handle| user_handle.as_slice())
    );

    rp.finish_owner_approval_assertion(
        NOW + 1,
        &challenge_id,
        &converted,
        &mut credential,
        &expected_context,
    )
    .unwrap();
}

#[test]
fn owner_approval_body_omits_absent_user_handle() {
    let approval = sample_approval(sample_context());
    let bytes = approval.to_canonical_bytes().unwrap();
    let decoded = OwnerApprovalV2::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(decoded, approval);

    let value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    let ciborium::value::Value::Map(entries) = value else {
        panic!("approval body encodes as map");
    };
    let keys: Vec<String> = entries
        .into_iter()
        .map(|(key, _)| match key {
            ciborium::value::Value::Text(text) => text,
            other => panic!("unexpected key: {other:?}"),
        })
        .collect();
    assert!(
        !keys.iter().any(|key| key == "user_handle"),
        "user_handle encoded"
    );
}

#[test]
fn pair_machine_context_uses_trusted_snapshot_and_cached_join_request() {
    let (_kp, request, request_bytes) = signed_join_request();
    let snapshot = awaiting_owner_snapshot(&request, &request_bytes);
    let ctx = OwnerApprovalContextV2::pair_machine_approve_from_trusted_state(
        PairMachineTrustedContextInput {
            hh_id: household_id(),
            owner_p_id: person_id(),
            snapshot: &snapshot,
            capabilities: vec!["machine-cert".into(), "shamir-2pc".into()],
            issued_at: 1_000,
            challenge_ttl_secs: 120,
            replay_nonce: [0x55; 32],
        },
    )
    .unwrap();

    assert_eq!(ctx.cursor, Some(7));
    assert_eq!(ctx.addr.as_deref(), Some("192.0.2.10:8091"));
    assert_eq!(ctx.transport, Some(JoinTransport::Lan));
    assert_eq!(ctx.ttl_unix, Some(1_600));
    assert_eq!(ctx.expires_at, 1_120);
    assert_eq!(
        ctx.join_request_hash.as_ref().map(ByteBuf::as_ref),
        Some(join_request_hash(&request_bytes).as_slice())
    );
    assert_eq!(
        ctx.nonce.as_ref().map(ByteBuf::as_ref),
        Some(request.nonce.as_ref())
    );
}

#[test]
fn pair_machine_context_rejects_snapshot_request_mismatch() {
    let (_kp, request, request_bytes) = signed_join_request();
    let mut snapshot = awaiting_owner_snapshot(&request, &request_bytes);
    snapshot.addr_hint = Some("198.51.100.10:8091".into());

    let err = OwnerApprovalContextV2::pair_machine_approve_from_trusted_state(
        PairMachineTrustedContextInput {
            hh_id: household_id(),
            owner_p_id: person_id(),
            snapshot: &snapshot,
            capabilities: vec!["machine-cert".into()],
            issued_at: 1_000,
            challenge_ttl_secs: 120,
            replay_nonce: [0x55; 32],
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        OwnerApprovalV2Error::TrustedState("addr mismatch")
    ));
}

#[test]
fn pair_machine_context_requires_awaiting_owner_window() {
    let (_kp, request, request_bytes) = signed_join_request();
    let mut snapshot = awaiting_owner_snapshot(&request, &request_bytes);
    snapshot.state = PairMachineState::Staging;

    let err = OwnerApprovalContextV2::pair_machine_approve_from_trusted_state(
        PairMachineTrustedContextInput {
            hh_id: household_id(),
            owner_p_id: person_id(),
            snapshot: &snapshot,
            capabilities: vec!["machine-cert".into()],
            issued_at: 1_000,
            challenge_ttl_secs: 120,
            replay_nonce: [0x55; 32],
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        OwnerApprovalV2Error::TrustedState("window not awaiting owner")
    ));
}
