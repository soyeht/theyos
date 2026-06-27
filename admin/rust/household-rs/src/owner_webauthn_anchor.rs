//! Keystore-backed anti-rollback anchor for owner-passkey authority logs.
//!
//! The owner passkey authority log lives inside `household_auth_state.cbor`, so
//! a rollback of that file can replay an older signed log. This module stores
//! the verified authority head in a separate durable keystore entry. Runtime
//! enforcement is wired later; this slice is data-model and helper code only.
//!
//! The rollback guarantee is only as strong as the keystore backend's own
//! rollback resistance. A software/file keystore can detect partial rollback
//! where `household_auth_state.cbor` moves backward while the anchor remains
//! current, but it cannot detect a full snapshot restore that rolls both the
//! auth state and keystore back together. High-assurance enforcement should use
//! hardware- or OS-backed durable keystore state and treat file-backed anchors
//! as dev/CI or explicitly caveated fallback.
//!
//! Future mutation wiring must persist the updated authority log before
//! advancing this anchor. If the anchor is written ahead of the durable log, the
//! next load correctly fails closed as rollback/truncation, but that creates an
//! avoidable local brick until operator recovery.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use thiserror::Error;

use crate::cbor;
use crate::error::{HouseholdError, KeystoreError};
use crate::household_record::HouseholdRecord;
use crate::ids::HouseholdId;
use crate::owner_webauthn_authority::{OwnerWebauthnAuthority, OwnerWebauthnAuthorityError};
use crate::person_cert::PersonCert;

const ANCHOR_SCHEMA_VERSION: u8 = 1;
const ANCHOR_PURPOSE: &str = "owner-webauthn-authority-anchor";
const HEAD_HASH_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerWebauthnAnchorMode {
    /// Default-off migration mode: a verified non-empty authority without an
    /// anchor is treated as trusted existing state and anchored at its head.
    MigrationDefaultOff,
    /// Enforcement mode: a verified non-empty authority must already have a
    /// keystore anchor, otherwise loading fails closed.
    Enforcement,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerWebauthnAuthorityAnchor {
    #[serde(rename = "v")]
    version: u8,
    purpose: String,
    hh_id: HouseholdId,
    owner_p_id: crate::machine_cert::PersonId,
    sequence: u64,
    #[serde(with = "serde_bytes")]
    head_hash: ByteBuf,
}

impl OwnerWebauthnAuthorityAnchor {
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
    ) -> Result<[u8; HEAD_HASH_LEN], OwnerWebauthnAnchorError> {
        if self.version != ANCHOR_SCHEMA_VERSION {
            return Err(OwnerWebauthnAnchorError::Invalid(format!(
                "anchor version {} unsupported",
                self.version
            )));
        }
        if self.purpose != ANCHOR_PURPOSE {
            return Err(OwnerWebauthnAnchorError::Invalid(format!(
                "anchor purpose {:?} unsupported",
                self.purpose
            )));
        }
        if self.hh_id != record.hh_id {
            return Err(OwnerWebauthnAnchorError::Invalid(
                "anchor household id mismatch".into(),
            ));
        }
        if self.owner_p_id != owner_person_cert.p_id {
            return Err(OwnerWebauthnAnchorError::Invalid(
                "anchor owner person id mismatch".into(),
            ));
        }
        self.head_hash.as_ref().try_into().map_err(|_| {
            OwnerWebauthnAnchorError::Invalid("anchor head_hash must be 32 bytes".into())
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerWebauthnAuthorityHead {
    pub sequence: u64,
    pub head_hash: [u8; HEAD_HASH_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerWebauthnAnchorStatus {
    EmptyAuthorityNoAnchor,
    Migrated {
        head: OwnerWebauthnAuthorityHead,
    },
    Verified {
        head: OwnerWebauthnAuthorityHead,
    },
    Advanced {
        previous: OwnerWebauthnAuthorityAnchor,
        head: OwnerWebauthnAuthorityHead,
    },
}

#[derive(Debug, Error)]
pub enum OwnerWebauthnAnchorError {
    #[error("owner webauthn authority: {0}")]
    Authority(#[from] OwnerWebauthnAuthorityError),
    #[error("protocol: {0}")]
    Protocol(#[from] HouseholdError),
    #[error("keystore: {0}")]
    Keystore(#[from] KeystoreError),
    #[error("owner webauthn authority anchor missing")]
    MissingAnchor,
    #[error("owner webauthn authority rollback detected: {0}")]
    Rollback(String),
    #[error("owner webauthn authority anchor invalid: {0}")]
    Invalid(String),
}

#[must_use]
pub fn owner_webauthn_authority_anchor_account(hh_id: &HouseholdId) -> String {
    format!("household.owner_webauthn_authority.anchor.{hh_id}")
}

pub fn read_owner_webauthn_authority_anchor(
    keystore: &dyn keystore_rs::KeystoreBackend,
    hh_id: &HouseholdId,
) -> Result<Option<OwnerWebauthnAuthorityAnchor>, OwnerWebauthnAnchorError> {
    let account = owner_webauthn_authority_anchor_account(hh_id);
    match keystore.get(&account) {
        Ok(bytes) => Ok(Some(cbor::from_canonical_slice(&bytes)?)),
        Err(KeystoreError::NotFound { .. }) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn write_owner_webauthn_authority_anchor(
    keystore: &dyn keystore_rs::KeystoreBackend,
    anchor: &OwnerWebauthnAuthorityAnchor,
) -> Result<(), OwnerWebauthnAnchorError> {
    let account = owner_webauthn_authority_anchor_account(&anchor.hh_id);
    keystore.set(&account, &cbor::to_canonical_vec(anchor)?)?;
    Ok(())
}

pub fn verified_owner_webauthn_authority_head(
    authority: &OwnerWebauthnAuthority,
    record: &HouseholdRecord,
    owner_person_cert: &PersonCert,
) -> Result<Option<OwnerWebauthnAuthorityHead>, OwnerWebauthnAnchorError> {
    authority.reconstruct(record, owner_person_cert)?;
    let Some((index, entry)) = authority.entries().iter().enumerate().next_back() else {
        return Ok(None);
    };
    Ok(Some(OwnerWebauthnAuthorityHead {
        sequence: u64::try_from(index).map_err(|_| {
            OwnerWebauthnAnchorError::Invalid("authority sequence overflow".to_string())
        })?,
        head_hash: entry.entry_hash()?,
    }))
}

pub fn verify_or_update_owner_webauthn_authority_anchor(
    keystore: &dyn keystore_rs::KeystoreBackend,
    authority: &OwnerWebauthnAuthority,
    record: &HouseholdRecord,
    owner_person_cert: &PersonCert,
    mode: OwnerWebauthnAnchorMode,
) -> Result<OwnerWebauthnAnchorStatus, OwnerWebauthnAnchorError> {
    authority.reconstruct(record, owner_person_cert)?;
    let head = verified_owner_webauthn_authority_head(authority, record, owner_person_cert)?;
    let existing = read_owner_webauthn_authority_anchor(keystore, &record.hh_id)?;

    match (existing, head) {
        (None, None) => Ok(OwnerWebauthnAnchorStatus::EmptyAuthorityNoAnchor),
        (Some(_), None) => Err(OwnerWebauthnAnchorError::Rollback(
            "anchor exists but authority log is empty".into(),
        )),
        (None, Some(head)) => match mode {
            OwnerWebauthnAnchorMode::MigrationDefaultOff => {
                let anchor = OwnerWebauthnAuthorityAnchor::new(
                    record,
                    owner_person_cert,
                    head.sequence,
                    head.head_hash,
                );
                write_owner_webauthn_authority_anchor(keystore, &anchor)?;
                Ok(OwnerWebauthnAnchorStatus::Migrated { head })
            }
            OwnerWebauthnAnchorMode::Enforcement => Err(OwnerWebauthnAnchorError::MissingAnchor),
        },
        (Some(anchor), Some(head)) => {
            let anchored_hash = anchor.validate(record, owner_person_cert)?;
            let anchored_sequence = usize::try_from(anchor.sequence).map_err(|_| {
                OwnerWebauthnAnchorError::Invalid("anchor sequence overflow".to_string())
            })?;
            let Some(entry_at_anchor) = authority.entries().get(anchored_sequence) else {
                return Err(OwnerWebauthnAnchorError::Rollback(format!(
                    "local head sequence {} is older than anchor sequence {}",
                    head.sequence, anchor.sequence
                )));
            };
            if entry_at_anchor.entry_hash()? != anchored_hash {
                return Err(OwnerWebauthnAnchorError::Rollback(
                    "entry hash at anchored sequence diverged".into(),
                ));
            }
            if head.sequence < anchor.sequence {
                return Err(OwnerWebauthnAnchorError::Rollback(format!(
                    "local head sequence {} is older than anchor sequence {}",
                    head.sequence, anchor.sequence
                )));
            }
            if head.sequence == anchor.sequence {
                return Ok(OwnerWebauthnAnchorStatus::Verified { head });
            }

            let previous = anchor;
            let new_anchor = OwnerWebauthnAuthorityAnchor::new(
                record,
                owner_person_cert,
                head.sequence,
                head.head_hash,
            );
            write_owner_webauthn_authority_anchor(keystore, &new_anchor)?;
            Ok(OwnerWebauthnAnchorStatus::Advanced { previous, head })
        }
    }
}

pub fn classify_owner_webauthn_authority_anchor_read_only(
    keystore: &dyn keystore_rs::KeystoreBackend,
    authority: &OwnerWebauthnAuthority,
    record: &HouseholdRecord,
    owner_person_cert: &PersonCert,
) -> Result<OwnerWebauthnAnchorStatus, OwnerWebauthnAnchorError> {
    authority.reconstruct(record, owner_person_cert)?;
    let head = verified_owner_webauthn_authority_head(authority, record, owner_person_cert)?;
    let existing = read_owner_webauthn_authority_anchor(keystore, &record.hh_id)?;

    match (existing, head) {
        (None, None) => Ok(OwnerWebauthnAnchorStatus::EmptyAuthorityNoAnchor),
        (Some(_), None) => Err(OwnerWebauthnAnchorError::Rollback(
            "anchor exists but authority log is empty".into(),
        )),
        (None, Some(_)) => Err(OwnerWebauthnAnchorError::MissingAnchor),
        (Some(anchor), Some(head)) => {
            let anchored_hash = anchor.validate(record, owner_person_cert)?;
            let anchored_sequence = usize::try_from(anchor.sequence).map_err(|_| {
                OwnerWebauthnAnchorError::Invalid("anchor sequence overflow".to_string())
            })?;
            let Some(entry_at_anchor) = authority.entries().get(anchored_sequence) else {
                return Err(OwnerWebauthnAnchorError::Rollback(format!(
                    "local head sequence {} is older than anchor sequence {}",
                    head.sequence, anchor.sequence
                )));
            };
            if entry_at_anchor.entry_hash()? != anchored_hash {
                return Err(OwnerWebauthnAnchorError::Rollback(
                    "entry hash at anchored sequence diverged".into(),
                ));
            }
            if head.sequence < anchor.sequence {
                return Err(OwnerWebauthnAnchorError::Rollback(format!(
                    "local head sequence {} is older than anchor sequence {}",
                    head.sequence, anchor.sequence
                )));
            }
            if head.sequence == anchor.sequence {
                return Ok(OwnerWebauthnAnchorStatus::Verified { head });
            }

            Ok(OwnerWebauthnAnchorStatus::Advanced {
                previous: anchor,
                head,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use keystore_rs::FileKeystore;
    use serde_json::json;
    use webauthn_rs::prelude::Passkey;

    use super::*;
    use crate::ids::{MachineId, derive_household_id};
    use crate::keys::{IdentityKey, P256Keypair};
    use crate::owner_webauthn::OwnerWebauthnCredential;
    use crate::owner_webauthn_authority::{
        OwnerWebauthnCredentialEventAction, SignedOwnerWebauthnCredentialEvent,
    };
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

    fn credential(id: &[u8]) -> OwnerWebauthnCredential {
        OwnerWebauthnCredential::new(synthetic_passkey(id))
    }

    fn setup() -> (P256Keypair, HouseholdRecord, PersonCert) {
        let root = P256Keypair::generate();
        let record = record_with(&root);
        let owner_cert = owner_cert(&root, &record);
        (root, record, owner_cert)
    }

    fn two_entry_authority(
        root: &P256Keypair,
        record: &HouseholdRecord,
        owner_cert: &PersonCert,
    ) -> (
        OwnerWebauthnAuthority,
        SignedOwnerWebauthnCredentialEvent,
        SignedOwnerWebauthnCredentialEvent,
    ) {
        let genesis = OwnerWebauthnAuthority::sign_genesis(
            root,
            record,
            owner_cert,
            credential(b"owner-passkey-1"),
            NOW,
        )
        .unwrap();
        let second = OwnerWebauthnAuthority::sign_append(
            root,
            record,
            owner_cert,
            &genesis,
            b"owner-passkey-1",
            OwnerWebauthnCredentialEventAction::Add {
                credential: Box::new(credential(b"owner-passkey-2")),
            },
            NOW + 1,
        )
        .unwrap();
        let mut authority = OwnerWebauthnAuthority::new();
        authority.push_signed(genesis.clone());
        authority.push_signed(second.clone());
        (authority, genesis, second)
    }

    fn append_third(
        root: &P256Keypair,
        record: &HouseholdRecord,
        owner_cert: &PersonCert,
        genesis: &SignedOwnerWebauthnCredentialEvent,
        second: &SignedOwnerWebauthnCredentialEvent,
    ) -> OwnerWebauthnAuthority {
        let third = OwnerWebauthnAuthority::sign_append(
            root,
            record,
            owner_cert,
            second,
            b"owner-passkey-2",
            OwnerWebauthnCredentialEventAction::Add {
                credential: Box::new(credential(b"owner-passkey-3")),
            },
            NOW + 2,
        )
        .unwrap();
        let mut authority = OwnerWebauthnAuthority::new();
        authority.push_signed(genesis.clone());
        authority.push_signed(second.clone());
        authority.push_signed(third);
        authority
    }

    #[test]
    fn account_label_is_stable_and_household_scoped() {
        let (_root, record, _owner_cert) = setup();
        let account = owner_webauthn_authority_anchor_account(&record.hh_id);
        assert!(account.starts_with("household.owner_webauthn_authority.anchor.hh_"));
        assert!(!account.contains('/'));
        assert!(!account.contains(".."));
    }

    #[test]
    fn empty_authority_without_anchor_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let store = file_keystore(tmp.path());
        let (_root, record, owner_cert) = setup();
        let authority = OwnerWebauthnAuthority::new();

        let status = verify_or_update_owner_webauthn_authority_anchor(
            &store,
            &authority,
            &record,
            &owner_cert,
            OwnerWebauthnAnchorMode::Enforcement,
        )
        .unwrap();

        assert_eq!(status, OwnerWebauthnAnchorStatus::EmptyAuthorityNoAnchor);
        assert!(
            read_owner_webauthn_authority_anchor(&store, &record.hh_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn migration_mode_anchors_verified_non_empty_authority() {
        let tmp = tempfile::tempdir().unwrap();
        let store = file_keystore(tmp.path());
        let (root, record, owner_cert) = setup();
        let (authority, _genesis, second) = two_entry_authority(&root, &record, &owner_cert);

        let status = verify_or_update_owner_webauthn_authority_anchor(
            &store,
            &authority,
            &record,
            &owner_cert,
            OwnerWebauthnAnchorMode::MigrationDefaultOff,
        )
        .unwrap();

        assert_eq!(
            status,
            OwnerWebauthnAnchorStatus::Migrated {
                head: OwnerWebauthnAuthorityHead {
                    sequence: 1,
                    head_hash: second.entry_hash().unwrap(),
                },
            }
        );
        let anchor = read_owner_webauthn_authority_anchor(&store, &record.hh_id)
            .unwrap()
            .unwrap();
        assert_eq!(anchor.sequence(), 1);
        assert_eq!(anchor.head_hash(), second.entry_hash().unwrap());
    }

    #[test]
    fn enforcement_mode_rejects_non_empty_authority_without_anchor() {
        let tmp = tempfile::tempdir().unwrap();
        let store = file_keystore(tmp.path());
        let (root, record, owner_cert) = setup();
        let (authority, _genesis, _second) = two_entry_authority(&root, &record, &owner_cert);

        let err = verify_or_update_owner_webauthn_authority_anchor(
            &store,
            &authority,
            &record,
            &owner_cert,
            OwnerWebauthnAnchorMode::Enforcement,
        )
        .unwrap_err();

        assert!(matches!(err, OwnerWebauthnAnchorError::MissingAnchor));
    }

    #[test]
    fn exact_anchor_at_head_verifies() {
        let tmp = tempfile::tempdir().unwrap();
        let store = file_keystore(tmp.path());
        let (root, record, owner_cert) = setup();
        let (authority, _genesis, second) = two_entry_authority(&root, &record, &owner_cert);
        let anchor = OwnerWebauthnAuthorityAnchor::new(
            &record,
            &owner_cert,
            1,
            second.entry_hash().unwrap(),
        );
        write_owner_webauthn_authority_anchor(&store, &anchor).unwrap();

        let status = verify_or_update_owner_webauthn_authority_anchor(
            &store,
            &authority,
            &record,
            &owner_cert,
            OwnerWebauthnAnchorMode::Enforcement,
        )
        .unwrap();

        assert_eq!(
            status,
            OwnerWebauthnAnchorStatus::Verified {
                head: OwnerWebauthnAuthorityHead {
                    sequence: 1,
                    head_hash: second.entry_hash().unwrap(),
                },
            }
        );
    }

    #[test]
    fn anchor_rejects_truncated_log() {
        let tmp = tempfile::tempdir().unwrap();
        let store = file_keystore(tmp.path());
        let (root, record, owner_cert) = setup();
        let (_full, genesis, second) = two_entry_authority(&root, &record, &owner_cert);
        let anchor = OwnerWebauthnAuthorityAnchor::new(
            &record,
            &owner_cert,
            1,
            second.entry_hash().unwrap(),
        );
        write_owner_webauthn_authority_anchor(&store, &anchor).unwrap();
        let mut truncated = OwnerWebauthnAuthority::new();
        truncated.push_signed(genesis);

        let err = verify_or_update_owner_webauthn_authority_anchor(
            &store,
            &truncated,
            &record,
            &owner_cert,
            OwnerWebauthnAnchorMode::Enforcement,
        )
        .unwrap_err();

        assert!(matches!(err, OwnerWebauthnAnchorError::Rollback(_)));
    }

    #[test]
    fn anchor_rejects_divergent_entry_at_anchored_sequence() {
        let tmp = tempfile::tempdir().unwrap();
        let store = file_keystore(tmp.path());
        let (root, record, owner_cert) = setup();
        let (_full, genesis, second) = two_entry_authority(&root, &record, &owner_cert);
        let anchor = OwnerWebauthnAuthorityAnchor::new(
            &record,
            &owner_cert,
            1,
            second.entry_hash().unwrap(),
        );
        write_owner_webauthn_authority_anchor(&store, &anchor).unwrap();
        let alternate_second = OwnerWebauthnAuthority::sign_append(
            &root,
            &record,
            &owner_cert,
            &genesis,
            b"owner-passkey-1",
            OwnerWebauthnCredentialEventAction::Add {
                credential: Box::new(credential(b"owner-passkey-alt")),
            },
            NOW + 1,
        )
        .unwrap();
        let mut divergent = OwnerWebauthnAuthority::new();
        divergent.push_signed(genesis);
        divergent.push_signed(alternate_second);

        let err = verify_or_update_owner_webauthn_authority_anchor(
            &store,
            &divergent,
            &record,
            &owner_cert,
            OwnerWebauthnAnchorMode::Enforcement,
        )
        .unwrap_err();

        assert!(matches!(err, OwnerWebauthnAnchorError::Rollback(_)));
    }

    #[test]
    fn valid_log_extending_anchor_advances_anchor() {
        let tmp = tempfile::tempdir().unwrap();
        let store = file_keystore(tmp.path());
        let (root, record, owner_cert) = setup();
        let (_two, genesis, second) = two_entry_authority(&root, &record, &owner_cert);
        let anchor = OwnerWebauthnAuthorityAnchor::new(
            &record,
            &owner_cert,
            1,
            second.entry_hash().unwrap(),
        );
        write_owner_webauthn_authority_anchor(&store, &anchor).unwrap();
        let extended = append_third(&root, &record, &owner_cert, &genesis, &second);
        let third_hash = extended.entries()[2].entry_hash().unwrap();

        let status = verify_or_update_owner_webauthn_authority_anchor(
            &store,
            &extended,
            &record,
            &owner_cert,
            OwnerWebauthnAnchorMode::Enforcement,
        )
        .unwrap();

        assert_eq!(
            status,
            OwnerWebauthnAnchorStatus::Advanced {
                previous: anchor,
                head: OwnerWebauthnAuthorityHead {
                    sequence: 2,
                    head_hash: third_hash,
                },
            }
        );
        let advanced = read_owner_webauthn_authority_anchor(&store, &record.hh_id)
            .unwrap()
            .unwrap();
        assert_eq!(advanced.sequence(), 2);
        assert_eq!(advanced.head_hash(), third_hash);
    }

    #[test]
    fn read_only_classifier_reports_advanced_without_writing_anchor() {
        let tmp = tempfile::tempdir().unwrap();
        let store = file_keystore(tmp.path());
        let (root, record, owner_cert) = setup();
        let (_two, genesis, second) = two_entry_authority(&root, &record, &owner_cert);
        let anchor = OwnerWebauthnAuthorityAnchor::new(
            &record,
            &owner_cert,
            1,
            second.entry_hash().unwrap(),
        );
        write_owner_webauthn_authority_anchor(&store, &anchor).unwrap();
        let extended = append_third(&root, &record, &owner_cert, &genesis, &second);
        let third_hash = extended.entries()[2].entry_hash().unwrap();

        let status = classify_owner_webauthn_authority_anchor_read_only(
            &store,
            &extended,
            &record,
            &owner_cert,
        )
        .unwrap();

        assert_eq!(
            status,
            OwnerWebauthnAnchorStatus::Advanced {
                previous: anchor,
                head: OwnerWebauthnAuthorityHead {
                    sequence: 2,
                    head_hash: third_hash,
                },
            }
        );
        let persisted = read_owner_webauthn_authority_anchor(&store, &record.hh_id)
            .unwrap()
            .unwrap();
        assert_eq!(persisted.sequence(), 1);
        assert_eq!(persisted.head_hash(), second.entry_hash().unwrap());
    }

    #[test]
    fn invalid_signed_chain_fails_before_anchor_migration() {
        let tmp = tempfile::tempdir().unwrap();
        let store = file_keystore(tmp.path());
        let (root, record, owner_cert) = setup();
        let genesis = OwnerWebauthnAuthority::sign_genesis(
            &root,
            &record,
            &owner_cert,
            credential(b"owner-passkey-1"),
            NOW,
        )
        .unwrap();
        let mut tampered = OwnerWebauthnAuthority::sign_append(
            &root,
            &record,
            &owner_cert,
            &genesis,
            b"owner-passkey-1",
            OwnerWebauthnCredentialEventAction::Add {
                credential: Box::new(credential(b"owner-passkey-2")),
            },
            NOW + 1,
        )
        .unwrap();
        tampered.event.issued_at += 1;
        let mut authority = OwnerWebauthnAuthority::new();
        authority.push_signed(genesis);
        authority.push_signed(tampered);

        let err = verify_or_update_owner_webauthn_authority_anchor(
            &store,
            &authority,
            &record,
            &owner_cert,
            OwnerWebauthnAnchorMode::MigrationDefaultOff,
        )
        .unwrap_err();

        assert!(matches!(err, OwnerWebauthnAnchorError::Authority(_)));
        assert!(
            read_owner_webauthn_authority_anchor(&store, &record.hh_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn malformed_anchor_hash_length_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let store = file_keystore(tmp.path());
        let (root, record, owner_cert) = setup();
        let (authority, _genesis, _second) = two_entry_authority(&root, &record, &owner_cert);
        let malformed = OwnerWebauthnAuthorityAnchor {
            version: ANCHOR_SCHEMA_VERSION,
            purpose: ANCHOR_PURPOSE.to_string(),
            hh_id: record.hh_id.clone(),
            owner_p_id: owner_cert.p_id.clone(),
            sequence: 1,
            head_hash: ByteBuf::from(vec![0xAA; HEAD_HASH_LEN - 1]),
        };
        write_owner_webauthn_authority_anchor(&store, &malformed).unwrap();

        let err = verify_or_update_owner_webauthn_authority_anchor(
            &store,
            &authority,
            &record,
            &owner_cert,
            OwnerWebauthnAnchorMode::Enforcement,
        )
        .unwrap_err();

        assert!(matches!(err, OwnerWebauthnAnchorError::Invalid(_)));
    }
}
