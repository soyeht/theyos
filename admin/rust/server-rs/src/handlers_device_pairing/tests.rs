#![cfg(test)]

use super::{
    ApprovedPairing, DEVICE_PAIRING_MAX_PENDING, DEVICE_PAIRING_TTL_SECS, DevicePairingStore,
    DevicePairingStoreError, PendingInsert, decode_public_key, validate_device_name,
    validate_platform, validate_request_version,
};

use crate::pairing_device_certificate::VerifiedPairingDeviceCertificate;

const NOW: u64 = 1_700_000_000;

fn pubkey(seed: u8) -> Vec<u8> {
    // 65-byte uncompressed-style placeholder is rejected by the real
    // key parser, but the store only stores raw bytes, so any unique
    // opaque blob exercises the dedupe / identity logic here.
    let mut bytes = vec![0u8; 33];
    bytes[0] = 0x02;
    bytes[1] = seed;
    bytes
}

fn approved_fixture() -> ApprovedPairing {
    ApprovedPairing {
        household_id: "hh_test".to_string(),
        person_id: "p_test".to_string(),
        person_cert_cbor: vec![1, 2, 3],
        device_cert_cbor: Vec::new(),
        capabilities: vec!["household.add_machine".to_string()],
    }
}

#[test]
fn create_returns_new_then_dedupes_same_device() {
    let store = DevicePairingStore::new();
    let first = store
        .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
        .expect("create");
    let (first_id, first_token) = match first {
        PendingInsert::New {
            request_id, token, ..
        } => (request_id, token),
        PendingInsert::Existing { .. } => panic!("first insert should be New"),
    };

    let second = store
        .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
        .expect("dedupe");
    match second {
        PendingInsert::Existing {
            request_id, token, ..
        } => {
            assert_eq!(request_id, first_id);
            assert_eq!(token, first_token);
        }
        PendingInsert::New { .. } => panic!("same device should dedupe to Existing"),
    }
}

#[test]
fn distinct_devices_create_distinct_records() {
    let store = DevicePairingStore::new();
    let a = store
        .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
        .expect("create a");
    let b = store
        .create_or_dedupe_pending(pubkey(2), "beta".into(), "ios".into(), NOW)
        .expect("create b");
    let id_a = match a {
        PendingInsert::New { request_id, .. } => request_id,
        PendingInsert::Existing { .. } => panic!("a should be New"),
    };
    let id_b = match b {
        PendingInsert::New { request_id, .. } => request_id,
        PendingInsert::Existing { .. } => panic!("b should be New"),
    };
    assert_ne!(id_a, id_b);
}

#[test]
fn expired_pending_is_cleaned_up_and_not_deduped() {
    let store = DevicePairingStore::new();
    let first = store
        .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
        .expect("create");
    let first_id = match first {
        PendingInsert::New { request_id, .. } => request_id,
        PendingInsert::Existing { .. } => panic!("first should be New"),
    };

    // Advance past the TTL: the prior record must be cleaned up and a
    // fresh request minted instead of a dedupe.
    let later = NOW + DEVICE_PAIRING_TTL_SECS + 1;
    let second = store
        .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), later)
        .expect("create after expiry");
    let second_id = match second {
        PendingInsert::New { request_id, .. } => request_id,
        PendingInsert::Existing { .. } => panic!("expired record must not dedupe"),
    };
    assert_ne!(first_id, second_id);
}

#[test]
fn max_pending_returns_full() {
    let store = DevicePairingStore::new();
    for i in 0..DEVICE_PAIRING_MAX_PENDING {
        store
            .create_or_dedupe_pending(
                pubkey(u8::try_from(i).expect("seed fits in u8")),
                format!("dev-{i}"),
                "ios".into(),
                NOW,
            )
            .expect("fill capacity");
    }
    let overflow =
        store.create_or_dedupe_pending(pubkey(250), "overflow".into(), "ios".into(), NOW);
    assert_eq!(overflow.unwrap_err(), DevicePairingStoreError::Full);
}

#[test]
fn poll_token_mismatch_is_rejected() {
    let store = DevicePairingStore::new();
    let created = store
        .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
        .expect("create");
    let request_id = match created {
        PendingInsert::New { request_id, .. } => request_id,
        PendingInsert::Existing { .. } => panic!("should be New"),
    };
    let err = store
        .poll(&request_id, "not-the-token", NOW)
        .expect_err("token mismatch");
    assert_eq!(err, DevicePairingStoreError::TokenMismatch);
}

#[test]
fn poll_unknown_request_is_not_found() {
    let store = DevicePairingStore::new();
    let err = store
        .poll("missing", "token", NOW)
        .expect_err("unknown request");
    assert_eq!(err, DevicePairingStoreError::NotFound);
}

#[test]
fn approve_finalizes_and_blocks_second_finalize() {
    let store = DevicePairingStore::new();
    let created = store
        .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
        .expect("create");
    let (request_id, token) = match created {
        PendingInsert::New {
            request_id, token, ..
        } => (request_id, token),
        PendingInsert::Existing { .. } => panic!("should be New"),
    };

    store
        .approve(
            &request_id,
            VerifiedPairingDeviceCertificate::store_fixture(vec![9, 9, 9], pubkey(1)),
            approved_fixture(),
            NOW,
        )
        .expect("approve");

    // The device-cert bytes passed to approve override the fixture's
    // empty placeholder and surface via poll.
    let state = store.poll(&request_id, &token, NOW).expect("poll approved");
    match state {
        super::DevicePairingPollState::Approved(approved) => {
            assert_eq!(approved.device_cert_cbor, vec![9, 9, 9]);
            assert_eq!(approved.household_id, "hh_test");
        }
        other => panic!("expected Approved, got {other:?}"),
    }

    // A second finalize (approve or reject) must be refused.
    let reapprove = store.approve(
        &request_id,
        VerifiedPairingDeviceCertificate::store_fixture(vec![1], pubkey(1)),
        approved_fixture(),
        NOW,
    );
    assert_eq!(
        reapprove.unwrap_err(),
        DevicePairingStoreError::AlreadyFinalized
    );
    let reject_after = store.reject(&request_id, NOW);
    assert_eq!(
        reject_after.unwrap_err(),
        DevicePairingStoreError::AlreadyFinalized
    );
}

#[test]
fn a_verified_certificate_for_another_request_does_not_finalize() {
    let store = DevicePairingStore::new();
    let PendingInsert::New {
        request_id, token, ..
    } = store
        .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
        .unwrap()
    else {
        panic!("new request expected")
    };
    let wrong = VerifiedPairingDeviceCertificate::store_fixture(vec![9], pubkey(2));
    assert_eq!(
        store
            .approve(&request_id, wrong, approved_fixture(), NOW)
            .unwrap_err(),
        DevicePairingStoreError::CertificateMismatch
    );
    assert!(matches!(
        store.poll(&request_id, &token, NOW).unwrap(),
        super::DevicePairingPollState::Pending
    ));
}

#[test]
fn reject_finalizes_and_blocks_approve() {
    let store = DevicePairingStore::new();
    let created = store
        .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
        .expect("create");
    let (request_id, token) = match created {
        PendingInsert::New {
            request_id, token, ..
        } => (request_id, token),
        PendingInsert::Existing { .. } => panic!("should be New"),
    };

    store.reject(&request_id, NOW).expect("reject");
    let state = store.poll(&request_id, &token, NOW).expect("poll rejected");
    assert!(matches!(state, super::DevicePairingPollState::Rejected));

    let approve_after = store.approve(
        &request_id,
        VerifiedPairingDeviceCertificate::store_fixture(vec![1], pubkey(1)),
        approved_fixture(),
        NOW,
    );
    assert_eq!(
        approve_after.unwrap_err(),
        DevicePairingStoreError::AlreadyFinalized
    );
}

#[test]
fn approve_after_expiry_is_rejected() {
    let store = DevicePairingStore::new();
    let created = store
        .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
        .expect("create");
    let request_id = match created {
        PendingInsert::New { request_id, .. } => request_id,
        PendingInsert::Existing { .. } => panic!("should be New"),
    };
    let later = NOW + DEVICE_PAIRING_TTL_SECS + 1;
    // Expired records are cleaned up on access, so finalizing reports
    // the request as gone (NotFound) rather than Expired.
    let err = store
        .approve(
            &request_id,
            VerifiedPairingDeviceCertificate::store_fixture(vec![1], pubkey(1)),
            approved_fixture(),
            later,
        )
        .expect_err("expired approve");
    assert_eq!(err, DevicePairingStoreError::NotFound);
}

#[test]
fn poll_after_expiry_reports_expired_state() {
    let store = DevicePairingStore::new();
    let created = store
        .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
        .expect("create");
    let (request_id, token) = match created {
        PendingInsert::New {
            request_id, token, ..
        } => (request_id, token),
        PendingInsert::Existing { .. } => panic!("should be New"),
    };
    // Poll exactly at the boundary where the record still exists but is
    // no longer valid: cleanup uses `> now`, so at expires_at the record
    // is removed and poll reports NotFound.
    let at_expiry = NOW + DEVICE_PAIRING_TTL_SECS;
    let err = store
        .poll(&request_id, &token, at_expiry)
        .expect_err("expired poll");
    assert_eq!(err, DevicePairingStoreError::NotFound);
}

#[test]
fn list_owner_visible_reflects_pending_then_finalized() {
    let store = DevicePairingStore::new();
    let created = store
        .create_or_dedupe_pending(pubkey(1), "alpha".into(), "ios".into(), NOW)
        .expect("create");
    let request_id = match created {
        PendingInsert::New { request_id, .. } => request_id,
        PendingInsert::Existing { .. } => panic!("should be New"),
    };

    let pending = store.list_owner_visible(NOW);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].status, "pending");
    assert_eq!(pending[0].device_name, "alpha");
    assert_eq!(pending[0].platform, "ios");

    store.reject(&request_id, NOW).expect("reject");
    let after = store.list_owner_visible(NOW);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].status, "rejected");
}

#[test]
fn validate_request_version_accepts_only_v1() {
    assert!(validate_request_version(1).is_ok());
    assert_eq!(
        validate_request_version(0).unwrap_err(),
        "version_unsupported"
    );
    assert_eq!(
        validate_request_version(2).unwrap_err(),
        "version_unsupported"
    );
}

#[test]
fn validate_device_name_trims_and_bounds() {
    assert_eq!(validate_device_name("  My Mac  ").unwrap(), "My Mac");
    assert_eq!(
        validate_device_name("   ").unwrap_err(),
        "device_name_invalid"
    );
    let too_long = "x".repeat(65);
    assert_eq!(
        validate_device_name(&too_long).unwrap_err(),
        "device_name_invalid"
    );
    assert_eq!(
        validate_device_name("bad\u{0007}name").unwrap_err(),
        "device_name_invalid"
    );
}

#[test]
fn validate_platform_allows_known_only() {
    assert_eq!(validate_platform("ios").unwrap(), "ios");
    assert_eq!(validate_platform("ipados").unwrap(), "ipados");
    assert_eq!(
        validate_platform("android").unwrap_err(),
        "platform_invalid"
    );
    assert_eq!(validate_platform("macos").unwrap_err(), "platform_invalid");
}

#[test]
fn decode_public_key_rejects_garbage() {
    assert!(decode_public_key("!!!not-base64!!!").is_err());
    assert!(decode_public_key("").is_err());
}
