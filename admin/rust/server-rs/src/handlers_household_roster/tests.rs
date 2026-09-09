#![cfg(test)]

use super::*;
use household_rs::StorageError;
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::machine_cert::{MachineCert, Platform, SignOptions};
use household_rs::machine_roster_evidence::{RosterEvidenceOutcome, RosterEvidenceSnapshot};
use household_rs::machine_roster_store::{StoreIoStage, StoreTarget};
use household_rs::owner_auth::OwnerAuthError;
use serde::Deserialize;
use serde::de::{IgnoredAny, MapAccess, Visitor};
use std::fmt;
use std::io;

struct MapOnly;

impl<'de> Deserialize<'de> for MapOnly {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct MapOnlyVisitor;

        impl<'de> Visitor<'de> for MapOnlyVisitor {
            type Value = MapOnly;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a CBOR map")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(MapOnly)
            }
        }

        deserializer.deserialize_map(MapOnlyVisitor)
    }
}

fn signed_evidence(outcome: RosterEvidenceOutcome) -> SignedRosterEvidence {
    let household_key = P256Keypair::generate();
    let machine_key = P256Keypair::generate();
    let hh_id = household_rs::ids::derive_household_id(&household_key.public());
    let cert = MachineCert::sign(
        &household_key,
        &machine_key.public(),
        &SignOptions {
            hh_id: hh_id.clone(),
            hostname: "studio-mac".into(),
            platform: Platform::Macos,
            joined_at: 1_714_972_800,
        },
    )
    .unwrap();
    let snapshot = outcome.is_available().then_some(RosterEvidenceSnapshot {
        hh_id,
        state_kind: 0,
        floor_secs: 1_714_972_800,
        genesis_checkpoint: None,
        accepted_checkpoint: None,
        predecessor_checkpoint: None,
        conflicting_checkpoint: None,
    });
    build_signed_evidence(outcome, [0xA5; 32], &cert, &machine_key, snapshot.as_ref()).unwrap()
}

#[test]
fn evidence_response_snapshot_body_is_a_nested_map() {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AvailableDecoded {
        client_nonce: serde_bytes::ByteBuf,
        full_snapshot_digest: serde_bytes::ByteBuf,
        outcome: String,
        signature: serde_bytes::ByteBuf,
        signer_m_id: String,
        signer_machine_cert: serde_bytes::ByteBuf,
        signer_machine_cert_fingerprint: serde_bytes::ByteBuf,
        snapshot_body: MapOnly,
        state_evidence_digest: serde_bytes::ByteBuf,
        v: u8,
    }

    let encoded = encode_evidence_body(&signed_evidence(RosterEvidenceOutcome::Available)).unwrap();
    let decoded: AvailableDecoded = household_rs::cbor::from_canonical_slice(&encoded).unwrap();
    assert_eq!(decoded.client_nonce.as_ref(), &[0xA5; 32]);
    assert_eq!(decoded.full_snapshot_digest.len(), 32);
    assert_eq!(decoded.outcome, "available");
    assert!(!decoded.signature.is_empty());
    assert!(!decoded.signer_m_id.is_empty());
    assert!(!decoded.signer_machine_cert.is_empty());
    assert_eq!(decoded.signer_machine_cert_fingerprint.len(), 32);
    let _map_type_proof = decoded.snapshot_body;
    assert_eq!(decoded.state_evidence_digest.len(), 32);
    assert_eq!(decoded.v, 1);
}

#[test]
fn evidence_unavailable_response_has_exactly_seven_keys_and_no_body() {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct UnavailableDecoded {
        client_nonce: serde_bytes::ByteBuf,
        outcome: String,
        signature: serde_bytes::ByteBuf,
        signer_m_id: String,
        signer_machine_cert: serde_bytes::ByteBuf,
        signer_machine_cert_fingerprint: serde_bytes::ByteBuf,
        v: u8,
    }

    let encoded = encode_evidence_body(&signed_evidence(
        RosterEvidenceOutcome::UnavailableClockState,
    ))
    .unwrap();
    let decoded: UnavailableDecoded = household_rs::cbor::from_canonical_slice(&encoded).unwrap();
    assert_eq!(decoded.client_nonce.as_ref(), &[0xA5; 32]);
    assert_eq!(decoded.outcome, "unavailable_clock_state");
    assert!(!decoded.signature.is_empty());
    assert!(!decoded.signer_m_id.is_empty());
    assert!(!decoded.signer_machine_cert.is_empty());
    assert_eq!(decoded.signer_machine_cert_fingerprint.len(), 32);
    assert_eq!(decoded.v, 1);
}

#[test]
fn evidence_request_nonce_serializes_as_bstr32_with_exact_keyset() {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RequestDecoded {
        client_nonce: serde_bytes::ByteBuf,
        v: u8,
    }

    let encoded = household_rs::cbor::to_canonical_vec(&EvidenceRequest {
        client_nonce: [0x5A; 32],
        v: 1,
    })
    .unwrap();
    let decoded: RequestDecoded = household_rs::cbor::from_canonical_slice(&encoded).unwrap();
    assert_eq!(decoded.client_nonce.as_ref(), &[0x5A; 32]);
    assert_eq!(decoded.v, 1);
}

#[test]
fn every_integrity_error_has_its_exact_wire_literal() {
    let cases = [
        (
            ChainIntegrityError::NonCanonicalRecord,
            "integrity_non_canonical",
        ),
        (ChainIntegrityError::DuplicateKey, "integrity_duplicate_key"),
        (ChainIntegrityError::UnknownField, "integrity_unknown_field"),
        (ChainIntegrityError::NullField, "integrity_null_field"),
        (ChainIntegrityError::VersionMismatch, "integrity_version"),
        (
            ChainIntegrityError::HouseholdMismatch,
            "integrity_household",
        ),
        (ChainIntegrityError::InvalidStateKeySet, "integrity_key_set"),
        (
            ChainIntegrityError::CheckpointDecode,
            "integrity_checkpoint_decode",
        ),
        (
            ChainIntegrityError::CheckpointSignature,
            "integrity_checkpoint_signature",
        ),
        (
            ChainIntegrityError::OwnerCertificate,
            "integrity_owner_certificate",
        ),
        (
            ChainIntegrityError::OwnerContinuity,
            "integrity_owner_continuity",
        ),
        (ChainIntegrityError::SequenceRelation, "integrity_sequence"),
        (ChainIntegrityError::HashRelation, "integrity_hash"),
        (ChainIntegrityError::Projection, "integrity_projection"),
        (
            ChainIntegrityError::ForkReapplyMismatch,
            "integrity_fork_reapply",
        ),
        (ChainIntegrityError::Temporal, "integrity_temporal"),
        (ChainIntegrityError::EpochRelation, "integrity_epoch"),
    ];

    assert_eq!(cases.len(), 17, "one row per ChainIntegrityError variant");
    let mut seen = std::collections::BTreeSet::new();
    for (error, expected) in cases {
        assert!(
            seen.insert(expected),
            "duplicate integrity wire literal {expected}"
        );
        assert_eq!(
            integrity_wire(error),
            expected,
            "wire literal for {error:?}"
        );
    }
}

#[test]
fn every_store_error_has_its_exact_status_and_wire_literal() {
    let cases: Vec<(RosterStoreError, StatusCode, &'static str)> = vec![
        (
            RosterStoreError::Io {
                stage: StoreIoStage::ReadChain,
                path: PathBuf::from("/redacted"),
                source: io::Error::other("synthetic"),
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            "store_io",
        ),
        (
            RosterStoreError::UnsafeFileType {
                target: StoreTarget::AcceptedChain,
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            "unsafe_file_type",
        ),
        (
            RosterStoreError::TempAlreadyExists,
            StatusCode::INTERNAL_SERVER_ERROR,
            "temp_already_exists",
        ),
        (
            RosterStoreError::ModeMismatch,
            StatusCode::INTERNAL_SERVER_ERROR,
            "mode_mismatch",
        ),
        (
            RosterStoreError::InvalidPath,
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_path",
        ),
        (
            RosterStoreError::LockTimeout,
            StatusCode::SERVICE_UNAVAILABLE,
            "lock_timeout",
        ),
        (
            RosterStoreError::NotInitialized,
            StatusCode::SERVICE_UNAVAILABLE,
            "not_initialized",
        ),
        (
            RosterStoreError::AlreadyInitialized,
            StatusCode::CONFLICT,
            "already_initialized",
        ),
        (
            RosterStoreError::InconsistentProvisioningState,
            StatusCode::INTERNAL_SERVER_ERROR,
            "inconsistent_provisioning_state",
        ),
        (
            RosterStoreError::ReadbackMismatch,
            StatusCode::INTERNAL_SERVER_ERROR,
            "readback_mismatch",
        ),
        (
            RosterStoreError::LatchPoisoned,
            StatusCode::INTERNAL_SERVER_ERROR,
            "latch_poisoned",
        ),
        (
            RosterStoreError::Integrity(ChainIntegrityError::Temporal),
            StatusCode::INTERNAL_SERVER_ERROR,
            "integrity_temporal",
        ),
        (
            RosterStoreError::Storage(StorageError::Io {
                path: PathBuf::from("/redacted"),
                kind: "synthetic".into(),
                hint: "synthetic".into(),
            }),
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage",
        ),
        (
            RosterStoreError::Household(HouseholdError::InvalidRecord("synthetic".into())),
            StatusCode::INTERNAL_SERVER_ERROR,
            "household",
        ),
        (
            RosterStoreError::OwnerAuth(OwnerAuthError::InvalidState("synthetic".into())),
            StatusCode::INTERNAL_SERVER_ERROR,
            "owner_auth",
        ),
        (
            RosterStoreError::InvalidCurrentOwnerAuthority,
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_current_owner_authority",
        ),
    ];

    assert_eq!(cases.len(), 16, "one row per RosterStoreError variant");
    let mut seen = std::collections::BTreeSet::new();
    for (error, expected_status, expected_literal) in cases {
        assert!(
            seen.insert(expected_literal),
            "duplicate store wire literal {expected_literal}"
        );
        assert_eq!(
            store_error_wire(&error),
            (expected_status, expected_literal),
            "wire pair for {error:?}"
        );
    }
}

#[test]
fn every_response_helper_sets_cbor_and_no_store_headers() {
    let responses = [
        cbor_response(StatusCode::OK, vec![0xA0]),
        error_response(StatusCode::BAD_REQUEST, "invalid_request"),
        error_response(StatusCode::CONFLICT, "already_initialized"),
        error_response(StatusCode::PAYLOAD_TOO_LARGE, "body_not_allowed"),
        error_response(StatusCode::SERVICE_UNAVAILABLE, "clock_unavailable"),
        error_response(StatusCode::INTERNAL_SERVER_ERROR, "store_io"),
    ];

    for response in responses {
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static(CONTENT_TYPE))
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
    }
}
