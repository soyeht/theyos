use std::sync::{Arc, Barrier};

use household_rs::ids::HouseholdId;
use household_rs::machine_cert::PersonId;
use household_rs::secure_upgrade::{
    SecureUpgradeAppAttestTranscriptInput, SecureUpgradeChallengeScope,
    SecureUpgradeChallengeStore, SecureUpgradeChallengeStoreError, SecureUpgradeOperation,
    SecureUpgradePlatform, SecureUpgradeProofEnvironment, SecureUpgradeProofModel,
    SecureUpgradeTranscript,
};

const NOW: u64 = 1_714_972_800;
const EXPIRES_AT: u64 = NOW + 300;
const HH_ID: &str = "hh_fnlwza7qi4rxuadflfmxocnx5rwdb3ef2meq6unnh7qqiosfyain";
const OWNER_P_ID: &str = "p_ty3yfdchyn7nethoiefhrolfjxavzfe2bngb4tzzqy7cl3uqjfcq";

fn transcript(challenge_id: &str, owner_key_id: &str) -> SecureUpgradeTranscript {
    SecureUpgradeTranscript::app_attest(SecureUpgradeAppAttestTranscriptInput {
        hh_id: HouseholdId::parse(HH_ID.to_string()).expect("fixture hh_id parses"),
        owner_p_id: PersonId(OWNER_P_ID.to_string()),
        owner_key_id: owner_key_id.to_string(),
        challenge_id: challenge_id.to_string(),
        issued_at: NOW,
        expires_at: EXPIRES_AT,
        app_team_id: "TEAMID1234".to_string(),
        app_bundle_id: "com.example.soyeht".to_string(),
        proof_key_id: "appattest-key-alpha".to_string(),
        proof_environment: SecureUpgradeProofEnvironment::Production,
        platform: SecureUpgradePlatform::Ios,
    })
}

#[test]
fn issue_persists_expected_transcript_digest_and_scope() {
    let store = SecureUpgradeChallengeStore::new();
    let transcript = transcript("su-challenge-alpha", "owner-key-alpha");
    let canonical = transcript.to_canonical_bytes().unwrap();
    let challenge_digest =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(&canonical);

    let record = store.issue(transcript, NOW).unwrap();

    assert_eq!(store.len(), 1);
    assert_eq!(record.challenge_id(), "su-challenge-alpha");
    assert_eq!(record.issued_at_unix(), NOW);
    assert_eq!(record.expires_at_unix(), EXPIRES_AT);
    assert_eq!(record.canonical_transcript_bytes(), canonical.as_slice());
    assert_eq!(record.challenge_digest(), challenge_digest);
    assert_eq!(
        record.scope(),
        &SecureUpgradeChallengeScope {
            hh_id: HouseholdId::parse(HH_ID.to_string()).unwrap(),
            owner_p_id: PersonId(OWNER_P_ID.to_string()),
            owner_key_id: "owner-key-alpha".to_string(),
            challenge_id: "su-challenge-alpha".to_string(),
            op: SecureUpgradeOperation::SecureUpgradeWithIphone,
            app_team_id: "TEAMID1234".to_string(),
            app_bundle_id: "com.example.soyeht".to_string(),
            proof_model: SecureUpgradeProofModel::AppAttest,
            proof_key_id: "appattest-key-alpha".to_string(),
            proof_environment: SecureUpgradeProofEnvironment::Production,
            platform: SecureUpgradePlatform::Ios,
            target_provenance: "ios-app-attest-owner".to_string(),
        }
    );
}

#[test]
fn duplicate_issue_fails_closed() {
    let store = SecureUpgradeChallengeStore::new();
    store
        .issue(transcript("su-challenge-alpha", "owner-key-alpha"), NOW)
        .unwrap();

    assert_eq!(
        store.issue(
            transcript("su-challenge-alpha", "owner-key-replacement"),
            NOW
        ),
        Err(SecureUpgradeChallengeStoreError::DuplicateChallenge)
    );
}

#[test]
fn consume_matching_transcript_succeeds_once() {
    let store = SecureUpgradeChallengeStore::new();
    let transcript = transcript("su-challenge-alpha", "owner-key-alpha");
    let canonical = transcript.to_canonical_bytes().unwrap();
    let expected = store.issue(transcript, NOW).unwrap();

    let consumed = store
        .consume_matching_transcript("su-challenge-alpha", &canonical, NOW)
        .unwrap();

    assert_eq!(consumed, expected);
    assert!(store.is_empty());
    assert_eq!(
        store.consume_matching_transcript("su-challenge-alpha", &canonical, NOW),
        Err(SecureUpgradeChallengeStoreError::ChallengeNotFound)
    );
}

#[test]
fn bound_field_swap_with_same_challenge_id_is_rejected_without_consuming() {
    let store = SecureUpgradeChallengeStore::new();
    let expected = transcript("su-challenge-alpha", "owner-key-alpha");
    let expected_canonical = expected.to_canonical_bytes().unwrap();
    store.issue(expected, NOW).unwrap();

    let tampered = transcript("su-challenge-alpha", "owner-key-beta");
    let tampered_canonical = tampered.to_canonical_bytes().unwrap();

    assert_eq!(
        store.consume_matching_transcript("su-challenge-alpha", &tampered_canonical, NOW),
        Err(SecureUpgradeChallengeStoreError::TranscriptMismatch)
    );
    assert_eq!(store.len(), 1);
    assert!(
        store
            .consume_matching_transcript("su-challenge-alpha", &expected_canonical, NOW)
            .is_ok()
    );
}

#[test]
fn submitted_challenge_id_mismatch_does_not_consume_expected_record() {
    let store = SecureUpgradeChallengeStore::new();
    let expected = transcript("su-challenge-alpha", "owner-key-alpha");
    let expected_canonical = expected.to_canonical_bytes().unwrap();
    store.issue(expected, NOW).unwrap();

    let wrong_challenge = transcript("su-challenge-beta", "owner-key-alpha");
    let wrong_canonical = wrong_challenge.to_canonical_bytes().unwrap();

    assert_eq!(
        store.consume_matching_transcript("su-challenge-alpha", &wrong_canonical, NOW),
        Err(SecureUpgradeChallengeStoreError::ChallengeIdMismatch)
    );
    assert_eq!(store.len(), 1);
    assert!(
        store
            .consume_matching_transcript("su-challenge-alpha", &expected_canonical, NOW)
            .is_ok()
    );
}

#[test]
fn expired_challenge_fails_closed_and_is_removed() {
    let store = SecureUpgradeChallengeStore::new();
    let transcript = transcript("su-challenge-alpha", "owner-key-alpha");
    let canonical = transcript.to_canonical_bytes().unwrap();
    store.issue(transcript, NOW).unwrap();

    assert_eq!(
        store.consume_matching_transcript("su-challenge-alpha", &canonical, EXPIRES_AT + 1),
        Err(SecureUpgradeChallengeStoreError::ChallengeExpired)
    );
    assert!(store.is_empty());
}

#[test]
fn cannot_issue_already_expired_challenge() {
    let store = SecureUpgradeChallengeStore::new();

    assert_eq!(
        store.issue(
            transcript("su-challenge-alpha", "owner-key-alpha"),
            EXPIRES_AT + 1
        ),
        Err(SecureUpgradeChallengeStoreError::ChallengeExpired)
    );
    assert!(store.is_empty());
}

#[test]
fn concurrent_consume_has_one_winner() {
    let store = Arc::new(SecureUpgradeChallengeStore::new());
    let transcript = transcript("su-challenge-alpha", "owner-key-alpha");
    let canonical = Arc::new(transcript.to_canonical_bytes().unwrap());
    store.issue(transcript, NOW).unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let handles = (0..2)
        .map(|_| {
            let store = Arc::clone(&store);
            let canonical = Arc::clone(&canonical);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .consume_matching_transcript("su-challenge-alpha", canonical.as_slice(), NOW)
                    .is_ok()
            })
        })
        .collect::<Vec<_>>();

    let winners = handles
        .into_iter()
        .map(|handle| usize::from(handle.join().expect("consume thread")))
        .sum::<usize>();
    assert_eq!(winners, 1);
    assert!(store.is_empty());
}
