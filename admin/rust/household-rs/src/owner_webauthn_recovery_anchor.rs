//! Keystore-backed anti-rollback anchor for owner-passkey recovery readiness.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use thiserror::Error;

use crate::cbor;
use crate::error::{HouseholdError, KeystoreError};
use crate::household_record::HouseholdRecord;
use crate::ids::HouseholdId;
use crate::owner_webauthn_recovery::{
    OwnerWebauthnRecoveryAuthority, OwnerWebauthnRecoveryError, OwnerWebauthnRecoveryHead,
    verified_owner_webauthn_recovery_head,
};
use crate::person_cert::PersonCert;

const ANCHOR_SCHEMA_VERSION: u8 = 1;
const ANCHOR_PURPOSE: &str = "owner-webauthn-recovery-anchor";
const HEAD_HASH_LEN: usize = 32;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerWebauthnRecoveryAnchor {
    #[serde(rename = "v")]
    version: u8,
    purpose: String,
    hh_id: HouseholdId,
    owner_p_id: crate::machine_cert::PersonId,
    sequence: u64,
    #[serde(with = "serde_bytes")]
    head_hash: ByteBuf,
}

impl OwnerWebauthnRecoveryAnchor {
    #[must_use]
    pub fn new(
        record: &HouseholdRecord,
        owner_person_cert: &PersonCert,
        sequence: u64,
        head_hash: [u8; HEAD_HASH_LEN],
    ) -> Self {
        Self {
            version: ANCHOR_SCHEMA_VERSION,
            purpose: ANCHOR_PURPOSE.to_string(),
            hh_id: record.hh_id.clone(),
            owner_p_id: owner_person_cert.p_id.clone(),
            sequence,
            head_hash: ByteBuf::from(head_hash.to_vec()),
        }
    }

    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub fn head_hash(&self) -> &[u8] {
        self.head_hash.as_ref()
    }

    fn validate(
        &self,
        record: &HouseholdRecord,
        owner_person_cert: &PersonCert,
    ) -> Result<[u8; HEAD_HASH_LEN], OwnerWebauthnRecoveryAnchorError> {
        if self.version != ANCHOR_SCHEMA_VERSION {
            return Err(OwnerWebauthnRecoveryAnchorError::Invalid(format!(
                "anchor version {} unsupported",
                self.version
            )));
        }
        if self.purpose != ANCHOR_PURPOSE {
            return Err(OwnerWebauthnRecoveryAnchorError::Invalid(format!(
                "anchor purpose {:?} unsupported",
                self.purpose
            )));
        }
        if self.hh_id != record.hh_id {
            return Err(OwnerWebauthnRecoveryAnchorError::Invalid(
                "anchor household id mismatch".into(),
            ));
        }
        if self.owner_p_id != owner_person_cert.p_id {
            return Err(OwnerWebauthnRecoveryAnchorError::Invalid(
                "anchor owner person id mismatch".into(),
            ));
        }
        self.head_hash.as_ref().try_into().map_err(|_| {
            OwnerWebauthnRecoveryAnchorError::Invalid("anchor head_hash must be 32 bytes".into())
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerWebauthnRecoveryAnchorStatus {
    EmptyRecoveryNoAnchor,
    Created {
        head: OwnerWebauthnRecoveryHead,
    },
    Verified {
        head: OwnerWebauthnRecoveryHead,
    },
    Advanced {
        previous: OwnerWebauthnRecoveryAnchor,
        head: OwnerWebauthnRecoveryHead,
    },
}

#[derive(Debug, Error)]
pub enum OwnerWebauthnRecoveryAnchorError {
    #[error("owner webauthn recovery: {0}")]
    Recovery(#[from] OwnerWebauthnRecoveryError),
    #[error("protocol: {0}")]
    Protocol(#[from] HouseholdError),
    #[error("keystore: {0}")]
    Keystore(#[from] KeystoreError),
    #[error("owner webauthn recovery anchor missing")]
    MissingAnchor,
    #[error("owner webauthn recovery rollback detected: {0}")]
    Rollback(String),
    #[error("owner webauthn recovery anchor invalid: {0}")]
    Invalid(String),
}

#[must_use]
pub fn owner_webauthn_recovery_anchor_account(hh_id: &HouseholdId) -> String {
    format!("household.owner_webauthn_recovery.anchor.{hh_id}")
}

pub fn read_owner_webauthn_recovery_anchor(
    keystore: &dyn keystore_rs::KeystoreBackend,
    hh_id: &HouseholdId,
) -> Result<Option<OwnerWebauthnRecoveryAnchor>, OwnerWebauthnRecoveryAnchorError> {
    let account = owner_webauthn_recovery_anchor_account(hh_id);
    match keystore.get(&account) {
        Ok(bytes) => Ok(Some(cbor::from_canonical_slice(&bytes)?)),
        Err(KeystoreError::NotFound { .. }) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn write_owner_webauthn_recovery_anchor(
    keystore: &dyn keystore_rs::KeystoreBackend,
    anchor: &OwnerWebauthnRecoveryAnchor,
) -> Result<(), OwnerWebauthnRecoveryAnchorError> {
    let account = owner_webauthn_recovery_anchor_account(&anchor.hh_id);
    keystore.set(&account, &cbor::to_canonical_vec(anchor)?)?;
    Ok(())
}

pub fn classify_owner_webauthn_recovery_anchor_read_only(
    keystore: &dyn keystore_rs::KeystoreBackend,
    authority: &OwnerWebauthnRecoveryAuthority,
    record: &HouseholdRecord,
    owner_person_cert: &PersonCert,
) -> Result<OwnerWebauthnRecoveryAnchorStatus, OwnerWebauthnRecoveryAnchorError> {
    authority.verify(record, owner_person_cert)?;
    let head = verified_owner_webauthn_recovery_head(authority, record, owner_person_cert)?;
    let existing = read_owner_webauthn_recovery_anchor(keystore, &record.hh_id)?;

    match (existing, head) {
        (None, None) => Ok(OwnerWebauthnRecoveryAnchorStatus::EmptyRecoveryNoAnchor),
        (Some(_), None) => Err(OwnerWebauthnRecoveryAnchorError::Rollback(
            "anchor exists but recovery log is empty".into(),
        )),
        (None, Some(_)) => Err(OwnerWebauthnRecoveryAnchorError::MissingAnchor),
        (Some(anchor), Some(head)) => {
            validate_recovery_anchor_prefix(&anchor, &head, authority, record, owner_person_cert)?;
            if head.sequence == anchor.sequence {
                Ok(OwnerWebauthnRecoveryAnchorStatus::Verified { head })
            } else {
                Ok(OwnerWebauthnRecoveryAnchorStatus::Advanced {
                    previous: anchor,
                    head,
                })
            }
        }
    }
}

pub fn advance_owner_webauthn_recovery_anchor_after_commit(
    keystore: &dyn keystore_rs::KeystoreBackend,
    authority: &OwnerWebauthnRecoveryAuthority,
    record: &HouseholdRecord,
    owner_person_cert: &PersonCert,
) -> Result<OwnerWebauthnRecoveryAnchorStatus, OwnerWebauthnRecoveryAnchorError> {
    authority.verify(record, owner_person_cert)?;
    let head = verified_owner_webauthn_recovery_head(authority, record, owner_person_cert)?
        .ok_or_else(|| OwnerWebauthnRecoveryAnchorError::Invalid("recovery log is empty".into()))?;
    let existing = read_owner_webauthn_recovery_anchor(keystore, &record.hh_id)?;

    match existing {
        None => {
            let anchor = OwnerWebauthnRecoveryAnchor::new(
                record,
                owner_person_cert,
                head.sequence,
                head.head_hash,
            );
            write_owner_webauthn_recovery_anchor(keystore, &anchor)?;
            Ok(OwnerWebauthnRecoveryAnchorStatus::Created { head })
        }
        Some(anchor) => {
            validate_recovery_anchor_prefix(&anchor, &head, authority, record, owner_person_cert)?;
            if head.sequence == anchor.sequence {
                return Ok(OwnerWebauthnRecoveryAnchorStatus::Verified { head });
            }
            let previous = anchor;
            let new_anchor = OwnerWebauthnRecoveryAnchor::new(
                record,
                owner_person_cert,
                head.sequence,
                head.head_hash,
            );
            write_owner_webauthn_recovery_anchor(keystore, &new_anchor)?;
            Ok(OwnerWebauthnRecoveryAnchorStatus::Advanced { previous, head })
        }
    }
}

fn validate_recovery_anchor_prefix(
    anchor: &OwnerWebauthnRecoveryAnchor,
    head: &OwnerWebauthnRecoveryHead,
    authority: &OwnerWebauthnRecoveryAuthority,
    record: &HouseholdRecord,
    owner_person_cert: &PersonCert,
) -> Result<(), OwnerWebauthnRecoveryAnchorError> {
    let anchored_hash = anchor.validate(record, owner_person_cert)?;
    let anchored_sequence = usize::try_from(anchor.sequence).map_err(|_| {
        OwnerWebauthnRecoveryAnchorError::Invalid("anchor sequence overflow".to_string())
    })?;
    let Some(entry_at_anchor) = authority.entries().get(anchored_sequence) else {
        return Err(OwnerWebauthnRecoveryAnchorError::Rollback(format!(
            "local head sequence {} is older than anchor sequence {}",
            head.sequence,
            anchor.sequence()
        )));
    };
    if entry_at_anchor.entry_hash()? != anchored_hash {
        return Err(OwnerWebauthnRecoveryAnchorError::Rollback(
            "entry hash at anchored sequence diverged".into(),
        ));
    }
    if head.sequence < anchor.sequence() {
        return Err(OwnerWebauthnRecoveryAnchorError::Rollback(format!(
            "local head sequence {} is older than anchor sequence {}",
            head.sequence,
            anchor.sequence()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use keystore_rs::FileKeystore;

    use super::*;
    use crate::ids::{MachineId, derive_household_id};
    use crate::keys::{IdentityKey, P256Keypair};
    use crate::owner_webauthn_recovery::{RecoveryCodeVerifier, SignedOwnerWebauthnRecoveryEvent};
    use crate::person_cert::{PersonCert, SignOwnerOptions};

    const NOW: u64 = 1_800_000_000;

    fn file_keystore(root: &Path) -> FileKeystore {
        FileKeystore::new(root, keystore_rs::SERVICE)
    }

    fn record_with(root: &P256Keypair) -> HouseholdRecord {
        let hh_pub = root.public();
        HouseholdRecord {
            version: HouseholdRecord::SCHEMA_VERSION,
            hh_id: derive_household_id(&hh_pub),
            hh_pub,
            name: "Alpha Household".to_string(),
            created_at: NOW,
            shamir_k: 1,
            shamir_n: 1,
            members: vec![MachineId::parse(format!("m_{}", "b".repeat(52))).unwrap()],
            is_follower: false,
        }
    }

    fn owner_cert(root: &P256Keypair, record: &HouseholdRecord) -> PersonCert {
        let owner_key = P256Keypair::generate();
        PersonCert::sign_owner(
            root,
            SignOwnerOptions {
                hh_id: record.hh_id.clone(),
                p_pub: owner_key.public(),
                display_name: "Owner Alpha".to_string(),
                issued_at: NOW,
            },
        )
        .unwrap()
    }

    fn setup() -> (P256Keypair, HouseholdRecord, PersonCert) {
        let root = P256Keypair::generate();
        let record = record_with(&root);
        let owner_cert = owner_cert(&root, &record);
        (root, record, owner_cert)
    }

    fn verifier(seed: u8) -> RecoveryCodeVerifier {
        RecoveryCodeVerifier::from_code_bytes([seed; 32], b"test recovery code")
    }

    fn two_entry_authority(
        root: &P256Keypair,
        record: &HouseholdRecord,
        owner_cert: &PersonCert,
    ) -> (
        OwnerWebauthnRecoveryAuthority,
        SignedOwnerWebauthnRecoveryEvent,
        SignedOwnerWebauthnRecoveryEvent,
    ) {
        let first = OwnerWebauthnRecoveryAuthority::sign_next(
            root,
            record,
            owner_cert,
            None,
            b"owner-passkey-1",
            verifier(1),
            NOW,
        )
        .unwrap();
        let second = OwnerWebauthnRecoveryAuthority::sign_next(
            root,
            record,
            owner_cert,
            Some(&first),
            b"owner-passkey-1",
            verifier(2),
            NOW + 1,
        )
        .unwrap();
        let mut authority = OwnerWebauthnRecoveryAuthority::new();
        authority.push_signed(first.clone());
        authority.push_signed(second.clone());
        (authority, first, second)
    }

    #[test]
    fn account_label_is_stable_and_household_scoped() {
        let (_root, record, _owner_cert) = setup();
        let account = owner_webauthn_recovery_anchor_account(&record.hh_id);
        assert!(account.starts_with("household.owner_webauthn_recovery.anchor.hh_"));
        assert!(!account.contains('/'));
        assert!(!account.contains(".."));
    }

    #[test]
    fn empty_recovery_without_anchor_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let store = file_keystore(tmp.path());
        let (_root, record, owner_cert) = setup();
        let authority = OwnerWebauthnRecoveryAuthority::new();

        let status = classify_owner_webauthn_recovery_anchor_read_only(
            &store,
            &authority,
            &record,
            &owner_cert,
        )
        .unwrap();

        assert_eq!(
            status,
            OwnerWebauthnRecoveryAnchorStatus::EmptyRecoveryNoAnchor
        );
        assert!(
            read_owner_webauthn_recovery_anchor(&store, &record.hh_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn read_only_classifier_rejects_non_empty_recovery_without_anchor() {
        let tmp = tempfile::tempdir().unwrap();
        let store = file_keystore(tmp.path());
        let (root, record, owner_cert) = setup();
        let (authority, _first, _second) = two_entry_authority(&root, &record, &owner_cert);

        let err = classify_owner_webauthn_recovery_anchor_read_only(
            &store,
            &authority,
            &record,
            &owner_cert,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            OwnerWebauthnRecoveryAnchorError::MissingAnchor
        ));
    }

    #[test]
    fn commit_advance_creates_first_recovery_anchor() {
        let tmp = tempfile::tempdir().unwrap();
        let store = file_keystore(tmp.path());
        let (root, record, owner_cert) = setup();
        let (authority, _first, second) = two_entry_authority(&root, &record, &owner_cert);

        let status = advance_owner_webauthn_recovery_anchor_after_commit(
            &store,
            &authority,
            &record,
            &owner_cert,
        )
        .unwrap();

        assert_eq!(
            status,
            OwnerWebauthnRecoveryAnchorStatus::Created {
                head: OwnerWebauthnRecoveryHead {
                    sequence: 1,
                    head_hash: second.entry_hash().unwrap(),
                },
            }
        );
        let anchor = read_owner_webauthn_recovery_anchor(&store, &record.hh_id)
            .unwrap()
            .unwrap();
        assert_eq!(anchor.sequence(), 1);
        assert_eq!(anchor.head_hash(), second.entry_hash().unwrap());
    }

    #[test]
    fn read_only_classifier_reports_advanced_without_writing_anchor() {
        let tmp = tempfile::tempdir().unwrap();
        let store = file_keystore(tmp.path());
        let (root, record, owner_cert) = setup();
        let (authority, first, second) = two_entry_authority(&root, &record, &owner_cert);
        let anchor =
            OwnerWebauthnRecoveryAnchor::new(&record, &owner_cert, 0, first.entry_hash().unwrap());
        write_owner_webauthn_recovery_anchor(&store, &anchor).unwrap();

        let status = classify_owner_webauthn_recovery_anchor_read_only(
            &store,
            &authority,
            &record,
            &owner_cert,
        )
        .unwrap();

        assert_eq!(
            status,
            OwnerWebauthnRecoveryAnchorStatus::Advanced {
                previous: anchor,
                head: OwnerWebauthnRecoveryHead {
                    sequence: 1,
                    head_hash: second.entry_hash().unwrap(),
                },
            }
        );
        let persisted = read_owner_webauthn_recovery_anchor(&store, &record.hh_id)
            .unwrap()
            .unwrap();
        assert_eq!(persisted.sequence(), 0);
        assert_eq!(persisted.head_hash(), first.entry_hash().unwrap());
    }

    #[test]
    fn anchor_rejects_truncated_recovery_log() {
        let tmp = tempfile::tempdir().unwrap();
        let store = file_keystore(tmp.path());
        let (root, record, owner_cert) = setup();
        let (_authority, first, second) = two_entry_authority(&root, &record, &owner_cert);
        let anchor =
            OwnerWebauthnRecoveryAnchor::new(&record, &owner_cert, 1, second.entry_hash().unwrap());
        write_owner_webauthn_recovery_anchor(&store, &anchor).unwrap();
        let mut truncated = OwnerWebauthnRecoveryAuthority::new();
        truncated.push_signed(first);

        let err = classify_owner_webauthn_recovery_anchor_read_only(
            &store,
            &truncated,
            &record,
            &owner_cert,
        )
        .unwrap_err();

        assert!(matches!(err, OwnerWebauthnRecoveryAnchorError::Rollback(_)));
    }
}
