#![cfg(test)]

use std::time::Duration;

use crate::ids::{HouseholdId, MachineId};
use crate::machine_cert::PersonId;
use crate::owner_approval_v2::{OwnerApprovalContextV2, PairMachineApprovalContextInput};
use crate::pair_machine::{JoinTransport, join_request_hash};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::Deserialize;
use serde_json::json;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{AttestationFormat, AuthenticatorAttachment, Url};
use webauthn_rs_core::proto::{AttestationConveyancePreference, UserVerificationPolicy};

use super::*;

const NOW: u64 = 1_800_000_000;

fn config() -> OwnerWebauthnConfig {
    OwnerWebauthnConfig::new(
        "alpha.example.test",
        Url::parse("https://alpha.example.test").unwrap(),
        "Soyeht Alpha",
    )
    .unwrap()
    .with_challenge_ttl(Duration::from_secs(60))
}

fn rp() -> OwnerWebauthnRp {
    OwnerWebauthnRp::new(config()).unwrap()
}

fn spectral_apple_fixture_rp() -> OwnerWebauthnRp {
    let config = OwnerWebauthnConfig::new(
        "spectral.local",
        Url::parse("https://spectral.local:8443").unwrap(),
        "Soyeht Spectral",
    )
    .unwrap()
    .with_challenge_ttl(Duration::from_secs(60));
    OwnerWebauthnRp::new(config).unwrap()
}

fn synthetic_passkey(id: &[u8]) -> Passkey {
    let encoded_id = data_encoding::BASE64URL_NOPAD.encode(id);
    serde_json::from_value(json!({
        "cred": {
            "cred_id": encoded_id,
            "cred": {
                "type_": "ES256",
                "key": {
                    "EC_EC2": {
                        "curve": "SECP256R1",
                        "x": data_encoding::BASE64URL_NOPAD.encode(&[1_u8; 32]),
                        "y": data_encoding::BASE64URL_NOPAD.encode(&[2_u8; 32])
                    }
                }
            },
            "counter": 0,
            "transports": null,
            "user_verified": true,
            "backup_eligible": true,
            "backup_state": true,
            "registration_policy": "required",
            "extensions": {},
            "attestation": {
                "data": "None",
                "metadata": "None"
            },
            "attestation_format": "none"
        }
    }))
    .unwrap()
}

fn synthetic_credential(id: &[u8]) -> OwnerWebauthnCredential {
    OwnerWebauthnCredential::new(synthetic_passkey(id))
}

fn synthetic_core_credential(
    id: &[u8],
    attestation_format: &str,
    attestation_data: serde_json::Value,
    user_verified: bool,
    backup_eligible: bool,
    backup_state: bool,
) -> Credential {
    let encoded_id = data_encoding::BASE64URL_NOPAD.encode(id);
    serde_json::from_value(json!({
        "cred_id": encoded_id,
        "cred": {
            "type_": "ES256",
            "key": {
                "EC_EC2": {
                    "curve": "SECP256R1",
                    "x": data_encoding::BASE64URL_NOPAD.encode(&[1_u8; 32]),
                    "y": data_encoding::BASE64URL_NOPAD.encode(&[2_u8; 32])
                }
            }
        },
        "counter": 0,
        "transports": null,
        "user_verified": user_verified,
        "backup_eligible": backup_eligible,
        "backup_state": backup_state,
        "registration_policy": "required",
        "extensions": {},
        "attestation": {
            "data": attestation_data,
            "metadata": "None"
        },
        "attestation_format": attestation_format
    }))
    .unwrap()
}

fn household_id() -> HouseholdId {
    HouseholdId::parse(format!("hh_{}", "a".repeat(52))).unwrap()
}

fn machine_id() -> MachineId {
    MachineId::parse(format!("m_{}", "b".repeat(52))).unwrap()
}

fn owner_person_id() -> PersonId {
    PersonId("p_owner-alpha".to_string())
}

fn owner_approval_context(join_request_bytes: &[u8]) -> OwnerApprovalContextV2 {
    OwnerApprovalContextV2::pair_machine_approve(PairMachineApprovalContextInput {
        hh_id: household_id(),
        owner_p_id: owner_person_id(),
        cursor: 7,
        m_id: machine_id(),
        addr: "192.0.2.10:8091".to_string(),
        transport: JoinTransport::Lan,
        ttl_unix: NOW + 60,
        nonce: [0x11; 32],
        join_request_hash: join_request_hash(join_request_bytes),
        capabilities: vec!["machine-cert".to_string(), "shamir-2pc".to_string()],
        issued_at: NOW,
        expires_at: NOW + 60,
        replay_nonce: [0x22; 32],
    })
}

fn registration_binding(bytes: &[u8]) -> OwnerWebauthnRegistrationBinding {
    OwnerWebauthnRegistrationBinding::from_canonical_binding(
        "owner-webauthn-recovery-consume",
        bytes,
    )
    .unwrap()
}

fn apple_anonymous_registration_response() -> RegisterPublicKeyCredential {
    serde_json::from_value(json!({
            "id": "u_tliFf-aXRLg9XIz-SuQ0XBlbE",
            "rawId": "u_tliFf-aXRLg9XIz-SuQ0XBlbE",
            "response": {
                "attestationObject": "o2NmbXRlYXBwbGVnYXR0U3RtdKJjYWxnJmN4NWOCWQJHMIICQzCCAcmgAwIBAgIGAXZFUv6nMAoGCCqGSM49BAMCMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAxMjA4MDIyNzE1WhcNMjAxMjExMDIyNzE1WjCBkTFJMEcGA1UEAwxAOWFhOTBjN2M5MzZhNGUxYmI4Njg5NjVmMTQ3YTQzOTlmMTQwY2Y0MDliNDM0ZjkwNTliMmQ0ZjVhM2NmYzA5MjEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATU-GOH9U5e9ecWPuItKNcE-7y0fRbshaHqTvtpC3eUkGn5x6eYrV6TOQL6FQUzdK7ZJ6AjDPl47TSUq4aKzRqto1UwUzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB_wQEAwIE8DAzBgkqhkiG92NkCAIEJjAkoSIEIKjioMU9kg_qZHwWHSISq1v9elHxtmnw0YKwsz1Ut06-MAoGCCqGSM49BAMCA2gAMGUCMA7yhkkMMAJnuIS7hHzMP5SoTuHjofCTu1rYQZ9aamb5OJzJ1rYPrbun83_qiikyPgIxAMYPCraOZ1QHEgDngtYaQDoRdkIOxvQ60wJh7KN0fEmmRUVwa-RTaFvNFMv6fh2-KlkCODCCAjQwggG6oAMCAQICEFYlU5XHp_tA6-Io2CYIU7YwCgYIKoZIzj0EAwMwSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM4MDFaFw0zMDAzMTMwMDAwMDBaMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASDLocvJhSRgQIlufX81rtjeLX1Xz_LBFvHNZk0df1UkETfm_4ZIRdlxpod2gULONRQg0AaQ0-yTREtVsPhz7_LmJH-wGlggb75bLx3yI3dr0alruHdUVta-quTvpwLJpGjZjBkMBIGA1UdEwEB_wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUJtdk2cV4wlpn0afeaxLQG2PxxtcwHQYDVR0OBBYEFOuugsT_oaxbUdTPJGEFAL5jvXeIMA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEA3YsaNIGl-tnbtOdle4QeFEwnt1uHakGGwrFHV1Azcifv5VRFfvZIlQxjLlxIPnDBAjAsimBE3CAfz-Wbw00pMMFIeFHZYO1qdfHrSsq-OM0luJfQyAW-8Mf3iwelccboDgdoYXV0aERhdGFYmNoUsfKpHi3fFS3-SiJ9vGALAUcpOl78tKnz0RXnirZbRQAAAAAAAAAAAAAAAAAAAAAAAAAAABS7-2WIV_5pdEuD1cjP5K5DRcGVsaUBAgMmIAEhWCDU-GOH9U5e9ecWPuItKNcE-7y0fRbshaHqTvtpC3eUkCJYIGn5x6eYrV6TOQL6FQUzdK7ZJ6AjDPl47TSUq4aKzRqt",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSlRiazd5ZWtJS09aUXd3ZEdXN05lRElmeHJZSzBQdnVZeHN1ZS0tRzlOSSIsIm9yaWdpbiI6Imh0dHBzOi8vc3BlY3RyYWwubG9jYWw6ODQ0MyJ9"
            },
            "type": "public-key"
        }))
        .unwrap()
}

fn patch_local_attested_challenge(
    rp: &mut OwnerWebauthnRp,
    challenge_id: &OwnerWebauthnChallengeId,
    challenge: &str,
) {
    let stored = rp
        .challenges
        .challenges
        .get_mut(challenge_id)
        .expect("local attested challenge exists");
    let ChallengeState::LocalAttestedRegistration(local) = &mut stored.state else {
        panic!("challenge is local attested");
    };
    let mut state = serde_json::to_value(&local.state).unwrap();
    state["challenge"] = json!(challenge);
    local.state = serde_json::from_value(state).unwrap();
}

fn patch_local_attested_challenge_for_apple_fixture(
    rp: &mut OwnerWebauthnRp,
    challenge_id: &OwnerWebauthnChallengeId,
) {
    const APPLE_ANONYMOUS_CHALLENGE: &str = "JTbk7yekIKOZQwwdGW7NeDIfxrYK0PvuYxsue--G9NI";
    patch_local_attested_challenge(rp, challenge_id, APPLE_ANONYMOUS_CHALLENGE);
}

#[derive(Debug, Deserialize)]
struct ManualLocalAppleAttestationFixture {
    rp_id: String,
    origin: String,
    credential: RegisterPublicKeyCredential,
}

fn client_data_json(credential: &RegisterPublicKeyCredential) -> serde_json::Value {
    serde_json::from_slice(credential.response.client_data_json.as_slice()).unwrap()
}

fn client_data_string<'a>(client_data: &'a serde_json::Value, key: &str) -> &'a str {
    client_data
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("clientDataJSON {key} is a string"))
}

fn register_with_softpasskey(
    rp: &mut OwnerWebauthnRp,
    rng: &mut StdRng,
) -> (OwnerWebauthnCredential, WebauthnAuthenticator<SoftPasskey>) {
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

#[test]
fn tenant_rp_id_and_origin_are_validated_by_webauthn_rs() {
    let ok = OwnerWebauthnConfig::new(
        "alpha.example.test",
        Url::parse("https://alpha.example.test").unwrap(),
        "Soyeht Alpha",
    );
    assert!(ok.is_ok());

    let bad = OwnerWebauthnConfig::new(
        "alpha.example.test",
        Url::parse("https://beta.example.test").unwrap(),
        "Soyeht Alpha",
    );
    assert!(matches!(bad, Err(OwnerWebauthnError::InvalidRpConfig(_))));
}

#[test]
fn registration_state_is_server_side_single_use() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(42);
    let (challenge_id, _challenge) = rp
        .start_registration(
            &mut rng,
            NOW,
            Uuid::new_v4(),
            "owner-alpha",
            "Owner Alpha",
            &[],
        )
        .unwrap();
    assert_eq!(rp.challenge_store_len(), 1);

    let first = rp.challenges.take_registration(&challenge_id, NOW);
    assert!(first.is_ok());
    assert_eq!(rp.challenge_store_len(), 0);

    let replay = rp.challenges.take_registration(&challenge_id, NOW);
    assert!(matches!(replay, Err(OwnerWebauthnError::ChallengeNotFound)));
}

#[test]
fn expired_registration_challenge_is_removed_and_rejected() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(43);
    let (challenge_id, _challenge) = rp
        .start_registration(
            &mut rng,
            NOW,
            Uuid::new_v4(),
            "owner-alpha",
            "Owner Alpha",
            &[],
        )
        .unwrap();

    let expired = rp.challenges.take_registration(&challenge_id, NOW + 61);
    assert!(matches!(expired, Err(OwnerWebauthnError::ChallengeExpired)));
    let replay = rp.challenges.take_registration(&challenge_id, NOW);
    assert!(matches!(replay, Err(OwnerWebauthnError::ChallengeNotFound)));
}

#[test]
fn bound_registration_mismatch_does_not_consume_challenge() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(4301);
    let expected = registration_binding(b"canonical-recovery-consume-context");
    let mismatch = registration_binding(b"tampered-recovery-consume-context");
    let (challenge_id, challenge) = rp
        .start_registration_from(
            &mut rng,
            NOW,
            OwnerWebauthnRegistrationStart {
                owner_user_id: Uuid::new_v4(),
                owner_name: "owner-alpha",
                owner_display_name: "Owner Alpha",
                existing_credentials: &[],
                binding: Some(expected.clone()),
            },
        )
        .unwrap();
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let response = authenticator
        .do_registration(Url::parse("https://alpha.example.test").unwrap(), challenge)
        .unwrap();

    let err = rp
        .finish_registration_with_binding(NOW, &challenge_id, &response, &mismatch)
        .unwrap_err();
    assert!(matches!(err, OwnerWebauthnError::ChallengeContextMismatch));
    assert_eq!(rp.challenge_store_len(), 1);

    let credential = rp
        .finish_registration_with_binding(NOW, &challenge_id, &response, &expected)
        .unwrap();
    assert_eq!(credential.credential_id_bytes(), response.raw_id.as_slice());
    assert_eq!(rp.challenge_store_len(), 0);
}

#[test]
fn unbound_finish_rejects_bound_registration_without_consuming() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(4302);
    let expected = registration_binding(b"canonical-recovery-consume-context");
    let (challenge_id, challenge) = rp
        .start_registration_from(
            &mut rng,
            NOW,
            OwnerWebauthnRegistrationStart {
                owner_user_id: Uuid::new_v4(),
                owner_name: "owner-alpha",
                owner_display_name: "Owner Alpha",
                existing_credentials: &[],
                binding: Some(expected.clone()),
            },
        )
        .unwrap();
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let response = authenticator
        .do_registration(Url::parse("https://alpha.example.test").unwrap(), challenge)
        .unwrap();

    let err = rp
        .finish_registration(NOW, &challenge_id, &response)
        .unwrap_err();
    assert!(matches!(
        err,
        OwnerWebauthnError::ChallengeContextUnexpected
    ));
    assert_eq!(rp.challenge_store_len(), 1);

    rp.finish_registration_with_binding(NOW, &challenge_id, &response, &expected)
        .unwrap();
    assert_eq!(rp.challenge_store_len(), 0);
}

#[test]
fn macos_local_attested_registration_requests_apple_anonymous_and_separates_state() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(4303);
    let (challenge_id, challenge) = rp
        .start_macos_local_attested_registration_from(
            &mut rng,
            NOW,
            &OwnerWebauthnRegistrationStart {
                owner_user_id: Uuid::new_v4(),
                owner_name: "owner-alpha",
                owner_display_name: "Owner Alpha",
                existing_credentials: &[],
                binding: None,
            },
        )
        .unwrap();

    assert!(matches!(
        challenge.public_key.attestation.as_ref(),
        Some(AttestationConveyancePreference::Direct)
    ));
    assert_eq!(
        challenge
            .public_key
            .attestation_formats
            .as_ref()
            .map(Vec::as_slice),
        Some([AttestationFormat::AppleAnonymous].as_slice())
    );
    let selection = challenge
        .public_key
        .authenticator_selection
        .as_ref()
        .expect("local attested start requests authenticator selection");
    assert_eq!(
        selection.authenticator_attachment,
        Some(AuthenticatorAttachment::Platform)
    );
    assert_eq!(
        selection.user_verification,
        UserVerificationPolicy::Required
    );
    assert!(selection.require_resident_key);
    assert!(matches!(
        rp.challenges.registration(&challenge_id, NOW),
        Err(OwnerWebauthnError::ChallengeKindMismatch)
    ));
    assert_eq!(rp.challenge_store_len(), 1);
}

#[test]
fn local_apple_root_policy_is_single_pinned_root() {
    let ca_list = macos_local_attested_registration::apple_webauthn_root_ca_list().unwrap();
    assert_eq!(ca_list.len(), 1);
    assert_eq!(
        macos_local_attested_registration::APPLE_WEBAUTHN_ROOT_POLICY_VERSION,
        "apple-webauthn-root-ca-2020-03-18"
    );
    assert_eq!(
        macos_local_attested_registration::APPLE_WEBAUTHN_ROOT_CA_SHA256_FINGERPRINT,
        "09:15:DD:5C:07:A2:8D:B5:49:D1:F6:77:BB:5A:75:D4:BF:BE:95:61:A7:73:42:43:27:76:2E:9E:02:F9:BB:29"
    );
}

#[test]
fn macos_local_attested_registration_rejects_expired_apple_anonymous_fixture() {
    let mut rp = spectral_apple_fixture_rp();
    let mut rng = StdRng::seed_from_u64(4304);
    let (challenge_id, _challenge) = rp
        .start_macos_local_attested_registration_from(
            &mut rng,
            NOW,
            &OwnerWebauthnRegistrationStart {
                owner_user_id: Uuid::new_v4(),
                owner_name: "owner-alpha",
                owner_display_name: "Owner Alpha",
                existing_credentials: &[],
                binding: None,
            },
        )
        .unwrap();
    patch_local_attested_challenge_for_apple_fixture(&mut rp, &challenge_id);
    let response = apple_anonymous_registration_response();

    let err = rp
        .finish_macos_local_attested_registration(NOW, &challenge_id, &response)
        .unwrap_err();

    assert!(matches!(err, OwnerWebauthnError::Ceremony(_)));
    assert_eq!(rp.challenge_store_len(), 0);
}

#[test]
#[ignore = "manual hardware evidence; requires SOYEHT_LOCAL_APPLE_ATTESTATION_FIXTURE"]
fn macos_local_attested_registration_manual_hardware_fixture_verifies_current_apple_chain() {
    let fixture_path = std::env::var("SOYEHT_LOCAL_APPLE_ATTESTATION_FIXTURE")
        .expect("set SOYEHT_LOCAL_APPLE_ATTESTATION_FIXTURE to an untracked local fixture path");
    let fixture_bytes = std::fs::read(&fixture_path).expect("read local Apple attestation fixture");
    let fixture: ManualLocalAppleAttestationFixture =
        serde_json::from_slice(&fixture_bytes).expect("parse local Apple attestation fixture");
    let origin = Url::parse(&fixture.origin).unwrap_or_else(|_| panic!("fixture origin is a URL"));
    let client_data = client_data_json(&fixture.credential);
    assert_eq!(client_data_string(&client_data, "type"), "webauthn.create");
    let challenge = client_data_string(&client_data, "challenge").to_string();
    if client_data_string(&client_data, "origin") != fixture.origin {
        panic!("clientDataJSON origin must match fixture origin");
    }

    let config =
        OwnerWebauthnConfig::new(fixture.rp_id, origin, "Soyeht Local Attestation Evidence")
            .unwrap_or_else(|_| panic!("fixture RP/origin pair is valid"))
            .with_challenge_ttl(Duration::from_secs(60));
    let mut rp = OwnerWebauthnRp::new(config).unwrap();
    let mut rng = StdRng::seed_from_u64(4308);
    let (challenge_id, _challenge) = rp
        .start_macos_local_attested_registration_from(
            &mut rng,
            NOW,
            &OwnerWebauthnRegistrationStart {
                owner_user_id: Uuid::new_v4(),
                owner_name: "owner-alpha",
                owner_display_name: "Owner Alpha",
                existing_credentials: &[],
                binding: None,
            },
        )
        .unwrap();
    patch_local_attested_challenge(&mut rp, &challenge_id, &challenge);

    let verified = rp
        .finish_macos_local_attested_registration(NOW, &challenge_id, &fixture.credential)
        .expect("fresh hardware Apple Anonymous fixture verifies at current time");
    let evidence = verified.evidence();
    assert_eq!(
        evidence.attestation_format(),
        &AttestationFormat::AppleAnonymous
    );
    assert!(evidence.user_verified());
    assert!(!evidence.backup_eligible());
    assert!(!evidence.backup_state());
    assert_eq!(
        evidence.root_policy_version(),
        macos_local_attested_registration::APPLE_WEBAUTHN_ROOT_POLICY_VERSION
    );
    assert_eq!(
        evidence.root_ca_sha256_fingerprint(),
        macos_local_attested_registration::APPLE_WEBAUTHN_ROOT_CA_SHA256_FINGERPRINT
    );
    assert_eq!(rp.challenge_store_len(), 0);

    eprintln!(
        "local_apple_attestation_manual_evidence verified=true format={:?} uv={} be={} bs={} root_policy={} root_fingerprint={}",
        evidence.attestation_format(),
        evidence.user_verified(),
        evidence.backup_eligible(),
        evidence.backup_state(),
        evidence.root_policy_version(),
        evidence.root_ca_sha256_fingerprint(),
    );
}

#[test]
fn local_apple_attestation_policy_requires_apple_uv_and_device_bound_flags() {
    let accepted = synthetic_core_credential(
        b"apple-local-credential",
        "apple",
        json!({ "AnonCa": [] }),
        true,
        false,
        false,
    );
    let verified =
        macos_local_attested_registration::verified_local_apple_attested_credential_from_core(
            accepted,
        )
        .unwrap();
    assert_eq!(verified.credential_id_bytes(), b"apple-local-credential");
    assert_eq!(
        verified.evidence().root_policy_version(),
        macos_local_attested_registration::APPLE_WEBAUTHN_ROOT_POLICY_VERSION
    );
    let (owner_credential, evidence) = verified.into_owner_webauthn_credential();
    assert_eq!(
        owner_credential.credential_id_bytes(),
        b"apple-local-credential"
    );
    assert_eq!(
        evidence.root_ca_sha256_fingerprint(),
        macos_local_attested_registration::APPLE_WEBAUTHN_ROOT_CA_SHA256_FINGERPRINT
    );

    let cases = [
        synthetic_core_credential(
            b"wrong-format",
            "packed",
            json!({ "AnonCa": [] }),
            true,
            false,
            false,
        ),
        synthetic_core_credential(
            b"wrong-attestation-data",
            "apple",
            json!("None"),
            true,
            false,
            false,
        ),
        synthetic_core_credential(
            b"uv-false",
            "apple",
            json!({ "AnonCa": [] }),
            false,
            false,
            false,
        ),
        synthetic_core_credential(
            b"backup-eligible",
            "apple",
            json!({ "AnonCa": [] }),
            true,
            true,
            false,
        ),
        synthetic_core_credential(
            b"backup-state",
            "apple",
            json!({ "AnonCa": [] }),
            true,
            false,
            true,
        ),
    ];
    for credential in cases {
        let err =
            macos_local_attested_registration::verified_local_apple_attested_credential_from_core(
                credential,
            )
            .unwrap_err();
        assert!(matches!(err, OwnerWebauthnError::LocalAttestationPolicy(_)));
    }
}

#[test]
fn local_attested_finish_rejects_normal_registration_challenge_without_consuming() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(4306);
    let (challenge_id, _challenge) = rp
        .start_registration(
            &mut rng,
            NOW,
            Uuid::new_v4(),
            "owner-alpha",
            "Owner Alpha",
            &[],
        )
        .unwrap();
    let response = apple_anonymous_registration_response();

    let err = rp
        .finish_macos_local_attested_registration(NOW, &challenge_id, &response)
        .unwrap_err();

    assert!(matches!(err, OwnerWebauthnError::ChallengeKindMismatch));
    assert!(rp.challenges.registration(&challenge_id, NOW).is_ok());
    assert_eq!(rp.challenge_store_len(), 1);
}

#[test]
fn challenge_kind_mismatch_consumes_state() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(44);
    let (challenge_id, _challenge) = rp
        .start_registration(
            &mut rng,
            NOW,
            Uuid::new_v4(),
            "owner-alpha",
            "Owner Alpha",
            &[],
        )
        .unwrap();

    let wrong_kind = rp.challenges.take_authentication(&challenge_id, NOW);
    assert!(matches!(
        wrong_kind,
        Err(OwnerWebauthnError::ChallengeKindMismatch)
    ));
    assert!(rp.challenges.is_empty());
}

#[test]
fn assertion_requires_at_least_one_active_credential() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(45);
    let err = rp.start_assertion(&mut rng, NOW, &[]).unwrap_err();
    assert!(matches!(err, OwnerWebauthnError::NoActiveCredentials));
}

#[test]
fn credential_store_tracks_active_and_revoked_credentials() {
    let mut store = OwnerWebauthnCredentialStore::default();
    store.add(synthetic_credential(b"owner-passkey-1")).unwrap();
    store.add(synthetic_credential(b"owner-passkey-2")).unwrap();

    assert_eq!(store.credentials().len(), 2);
    assert_eq!(store.active_count(), 2);

    store.revoke_by_credential_id(b"owner-passkey-1").unwrap();
    assert_eq!(store.credentials().len(), 2);
    assert_eq!(store.active_count(), 1);
    assert_eq!(
        store.active_credentials()[0].credential_id_bytes(),
        b"owner-passkey-2"
    );
}

#[test]
fn credential_store_rejects_duplicate_credential_ids() {
    let mut store = OwnerWebauthnCredentialStore::default();
    store.add(synthetic_credential(b"owner-passkey-1")).unwrap();
    let err = store
        .add(synthetic_credential(b"owner-passkey-1"))
        .unwrap_err();
    assert!(matches!(err, OwnerWebauthnError::DuplicateCredential));
}

#[test]
fn credential_store_rejects_unknown_revocation() {
    let mut store = OwnerWebauthnCredentialStore::default();
    let err = store
        .revoke_by_credential_id(b"missing-passkey")
        .unwrap_err();
    assert!(matches!(err, OwnerWebauthnError::CredentialNotFound));
}

#[test]
fn assertion_uses_only_active_credentials() {
    let mut store = OwnerWebauthnCredentialStore::default();
    store.add(synthetic_credential(b"owner-passkey-1")).unwrap();
    store.add(synthetic_credential(b"owner-passkey-2")).unwrap();
    store.revoke_by_credential_id(b"owner-passkey-1").unwrap();

    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(46);
    let (challenge_id, _challenge) = rp
        .start_assertion(&mut rng, NOW, store.credentials())
        .unwrap();

    assert_eq!(rp.challenge_store_len(), 1);
    assert!(
        rp.challenges
            .take_authentication(&challenge_id, NOW)
            .is_ok()
    );
}

#[test]
fn assertion_rejects_all_revoked_credentials() {
    let mut store = OwnerWebauthnCredentialStore::default();
    store.add(synthetic_credential(b"owner-passkey-1")).unwrap();
    store.revoke_by_credential_id(b"owner-passkey-1").unwrap();

    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(47);
    let err = rp
        .start_assertion(&mut rng, NOW, store.credentials())
        .unwrap_err();
    assert!(matches!(err, OwnerWebauthnError::NoActiveCredentials));
    assert_eq!(rp.challenge_store_len(), 0);
}

#[test]
fn softpasskey_register_and_assertion_round_trip() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(48);
    let (mut credential, mut authenticator) = register_with_softpasskey(&mut rp, &mut rng);

    let (challenge_id, challenge) = rp
        .start_assertion(&mut rng, NOW + 1, &[credential.clone()])
        .unwrap();
    let assertion = authenticator
        .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
        .unwrap();

    rp.finish_assertion(NOW + 1, &challenge_id, &assertion, &mut credential)
        .unwrap();
    assert_eq!(rp.challenge_store_len(), 0);

    let replay = rp.finish_assertion(NOW + 1, &challenge_id, &assertion, &mut credential);
    assert!(matches!(replay, Err(OwnerWebauthnError::ChallengeNotFound)));
}

#[test]
fn owner_approval_assertion_requires_bound_context_bytes() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(50);
    let (mut credential, mut authenticator) = register_with_softpasskey(&mut rp, &mut rng);
    let expected_context = owner_approval_context(b"join request A");

    let (challenge_id, challenge) = rp
        .start_owner_approval_assertion(&mut rng, NOW + 1, &[credential.clone()], &expected_context)
        .unwrap();
    let assertion = authenticator
        .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
        .unwrap();

    rp.finish_owner_approval_assertion(
        NOW + 1,
        &challenge_id,
        &assertion,
        &mut credential,
        &expected_context,
    )
    .unwrap();
    assert_eq!(rp.challenge_store_len(), 0);

    let replay = rp.finish_owner_approval_assertion(
        NOW + 1,
        &challenge_id,
        &assertion,
        &mut credential,
        &expected_context,
    );
    assert!(matches!(replay, Err(OwnerWebauthnError::ChallengeNotFound)));
}

#[test]
fn owner_approval_assertion_rejects_context_a_challenge_with_context_b_body() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(51);
    let (mut credential, mut authenticator) = register_with_softpasskey(&mut rp, &mut rng);
    let expected_context = owner_approval_context(b"join request A");
    let submitted_context = owner_approval_context(b"join request B");

    let (challenge_id, challenge) = rp
        .start_owner_approval_assertion(&mut rng, NOW + 1, &[credential.clone()], &expected_context)
        .unwrap();
    let assertion = authenticator
        .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
        .unwrap();

    let err = rp
        .finish_owner_approval_assertion(
            NOW + 1,
            &challenge_id,
            &assertion,
            &mut credential,
            &submitted_context,
        )
        .unwrap_err();
    assert!(matches!(err, OwnerWebauthnError::ChallengeContextMismatch));
    assert_eq!(rp.challenge_store_len(), 0);

    let replay = rp.finish_owner_approval_assertion(
        NOW + 1,
        &challenge_id,
        &assertion,
        &mut credential,
        &expected_context,
    );
    assert!(matches!(replay, Err(OwnerWebauthnError::ChallengeNotFound)));
}

#[test]
fn owner_approval_assertion_rejects_expired_and_consumed_context_challenges() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(52);
    let (mut credential, mut authenticator) = register_with_softpasskey(&mut rp, &mut rng);
    let expected_context = owner_approval_context(b"join request A");

    let (expired_id, challenge) = rp
        .start_owner_approval_assertion(&mut rng, NOW + 1, &[credential.clone()], &expected_context)
        .unwrap();
    let assertion = authenticator
        .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
        .unwrap();
    let expired = rp.finish_owner_approval_assertion(
        NOW + 62,
        &expired_id,
        &assertion,
        &mut credential,
        &expected_context,
    );
    assert!(matches!(expired, Err(OwnerWebauthnError::ChallengeExpired)));

    let (challenge_id, challenge) = rp
        .start_owner_approval_assertion(&mut rng, NOW + 2, &[credential.clone()], &expected_context)
        .unwrap();
    let assertion = authenticator
        .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
        .unwrap();
    rp.finish_owner_approval_assertion(
        NOW + 2,
        &challenge_id,
        &assertion,
        &mut credential,
        &expected_context,
    )
    .unwrap();
    let consumed = rp.finish_owner_approval_assertion(
        NOW + 2,
        &challenge_id,
        &assertion,
        &mut credential,
        &expected_context,
    );
    assert!(matches!(
        consumed,
        Err(OwnerWebauthnError::ChallengeNotFound)
    ));
}

#[test]
fn owner_approval_finish_rejects_and_consumes_legacy_unbound_challenge() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(53);
    let (mut credential, mut authenticator) = register_with_softpasskey(&mut rp, &mut rng);
    let expected_context = owner_approval_context(b"join request A");

    let (challenge_id, challenge) = rp
        .start_assertion(&mut rng, NOW + 1, &[credential.clone()])
        .unwrap();
    let assertion = authenticator
        .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
        .unwrap();

    let err = rp
        .finish_owner_approval_assertion(
            NOW + 1,
            &challenge_id,
            &assertion,
            &mut credential,
            &expected_context,
        )
        .unwrap_err();
    assert!(matches!(err, OwnerWebauthnError::ChallengeContextMissing));

    let replay = rp.finish_assertion(NOW + 1, &challenge_id, &assertion, &mut credential);
    assert!(matches!(replay, Err(OwnerWebauthnError::ChallengeNotFound)));
    assert_eq!(rp.challenge_store_len(), 0);
}

#[test]
fn legacy_assertion_finish_rejects_context_bound_challenge() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(54);
    let (mut credential, mut authenticator) = register_with_softpasskey(&mut rp, &mut rng);
    let expected_context = owner_approval_context(b"join request A");

    let (challenge_id, challenge) = rp
        .start_owner_approval_assertion(&mut rng, NOW + 1, &[credential.clone()], &expected_context)
        .unwrap();
    let assertion = authenticator
        .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
        .unwrap();

    let err = rp
        .finish_assertion(NOW + 1, &challenge_id, &assertion, &mut credential)
        .unwrap_err();
    assert!(matches!(
        err,
        OwnerWebauthnError::ChallengeContextUnexpected
    ));
}

#[test]
fn finish_paths_reject_authentication_result_for_wrong_credential() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(55);
    let (mut signing_credential, mut signing_authenticator) =
        register_with_softpasskey(&mut rp, &mut rng);
    let (mut other_credential, _) = register_with_softpasskey(&mut rp, &mut rng);

    let (legacy_id, legacy_challenge) = rp
        .start_assertion(&mut rng, NOW + 1, &[signing_credential.clone()])
        .unwrap();
    let legacy_assertion = signing_authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            legacy_challenge,
        )
        .unwrap();
    let err = rp
        .finish_assertion(
            NOW + 1,
            &legacy_id,
            &legacy_assertion,
            &mut other_credential,
        )
        .unwrap_err();
    assert!(matches!(err, OwnerWebauthnError::CredentialMismatch));
    assert_eq!(rp.challenge_store_len(), 0);

    let expected_context = owner_approval_context(b"join request A");
    let (approval_id, approval_challenge) = rp
        .start_owner_approval_assertion(
            &mut rng,
            NOW + 2,
            &[signing_credential.clone()],
            &expected_context,
        )
        .unwrap();
    let approval_assertion = signing_authenticator
        .do_authentication(
            Url::parse("https://alpha.example.test").unwrap(),
            approval_challenge,
        )
        .unwrap();
    let err = rp
        .finish_owner_approval_assertion(
            NOW + 2,
            &approval_id,
            &approval_assertion,
            &mut other_credential,
            &expected_context,
        )
        .unwrap_err();
    assert!(matches!(err, OwnerWebauthnError::CredentialMismatch));
    assert_eq!(rp.challenge_store_len(), 0);

    let replay = rp.finish_owner_approval_assertion(
        NOW + 2,
        &approval_id,
        &approval_assertion,
        &mut signing_credential,
        &expected_context,
    );
    assert!(matches!(replay, Err(OwnerWebauthnError::ChallengeNotFound)));
}

#[test]
fn softpasskey_assertion_rejects_origin_mismatch() {
    let mut rp = rp();
    let mut rng = StdRng::seed_from_u64(56);
    let (credential, mut authenticator) = register_with_softpasskey(&mut rp, &mut rng);

    let (_challenge_id, challenge) = rp
        .start_assertion(&mut rng, NOW + 1, &[credential])
        .unwrap();
    let assertion = authenticator
        .do_authentication(Url::parse("https://beta.example.test").unwrap(), challenge);

    assert!(assertion.is_err());
}

#[test]
fn sign_count_policy_treats_zero_as_synced_passkey_unknown_baseline() {
    assert!(validate_next_sign_count(0, 0).is_ok());
    assert!(validate_next_sign_count(0, 1).is_ok());
    assert!(validate_next_sign_count(0, 10).is_ok());
    assert!(validate_next_sign_count(1, 2).is_ok());
}

#[test]
fn sign_count_rejects_regression_after_counter_is_established() {
    assert!(matches!(
        validate_next_sign_count(10, 10),
        Err(OwnerWebauthnError::SignCountRegression {
            previous: 10,
            next: 10
        })
    ));
    assert!(matches!(
        validate_next_sign_count(10, 9),
        Err(OwnerWebauthnError::SignCountRegression {
            previous: 10,
            next: 9
        })
    ));
    assert!(matches!(
        validate_next_sign_count(10, 0),
        Err(OwnerWebauthnError::SignCountRegression {
            previous: 10,
            next: 0
        })
    ));
}
