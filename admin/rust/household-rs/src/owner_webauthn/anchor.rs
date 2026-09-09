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
use crate::owner_webauthn::authority::{OwnerWebauthnAuthority, OwnerWebauthnAuthorityError};
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
mod tests;
