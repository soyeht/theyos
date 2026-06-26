//! Persisted owner auth state loaded by theyOS for `PoP` validation.

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::{HouseholdError, StorageError};
use crate::household_record::HouseholdRecord;
use crate::owner_webauthn::OwnerWebauthnCredentialStore;
use crate::owner_webauthn_authority::{OwnerWebauthnAuthority, OwnerWebauthnAuthorityError};
use crate::person_cert::PersonCert;
use crate::storage::{self, atomic_write_cbor};

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct HouseholdAuthState {
    #[serde(rename = "v")]
    pub version: u8,
    pub hh_id: crate::ids::HouseholdId,
    pub owner_person_cert: PersonCert,
    #[serde(default, skip_serializing_if = "OwnerWebauthnAuthority::is_empty")]
    pub owner_webauthn: OwnerWebauthnAuthority,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Error)]
pub enum OwnerAuthError {
    #[error("storage: {0}")]
    Storage(#[from] StorageError),
    #[error("protocol: {0}")]
    Protocol(#[from] HouseholdError),
    #[error("owner webauthn authority: {0}")]
    OwnerWebauthn(#[from] OwnerWebauthnAuthorityError),
    #[error("invalid owner auth state: {0}")]
    InvalidState(String),
}

impl HouseholdAuthState {
    pub const SCHEMA_VERSION: u8 = 1;

    #[must_use]
    pub fn new(record: &HouseholdRecord, owner_person_cert: PersonCert) -> Self {
        Self {
            version: Self::SCHEMA_VERSION,
            hh_id: record.hh_id.clone(),
            created_at: owner_person_cert.issued_at,
            updated_at: owner_person_cert.issued_at,
            owner_person_cert,
            owner_webauthn: OwnerWebauthnAuthority::new(),
        }
    }

    pub fn verify(&self, record: &HouseholdRecord, now: u64) -> Result<(), OwnerAuthError> {
        if self.version != Self::SCHEMA_VERSION {
            return Err(OwnerAuthError::InvalidState(format!(
                "version {} unsupported",
                self.version
            )));
        }
        if self.hh_id != record.hh_id {
            return Err(OwnerAuthError::InvalidState(format!(
                "hh_id mismatch: expected {}, got {}",
                record.hh_id, self.hh_id
            )));
        }
        self.owner_person_cert
            .verify(&record.hh_id, &record.hh_pub, now)?;
        self.owner_webauthn
            .verify(record, &self.owner_person_cert)?;
        if self.created_at != self.owner_person_cert.issued_at {
            return Err(OwnerAuthError::InvalidState(
                "created_at must equal owner cert issued_at".into(),
            ));
        }
        if self.owner_webauthn.is_empty() {
            if self.updated_at != self.created_at {
                return Err(OwnerAuthError::InvalidState(
                    "updated_at must equal created_at when owner webauthn authority is empty"
                        .into(),
                ));
            }
        } else if self.updated_at < self.created_at {
            return Err(OwnerAuthError::InvalidState(
                "updated_at must be >= created_at".into(),
            ));
        }
        Ok(())
    }

    pub fn owner_webauthn_credentials(
        &self,
        record: &HouseholdRecord,
    ) -> Result<OwnerWebauthnCredentialStore, OwnerAuthError> {
        Ok(self
            .owner_webauthn
            .reconstruct(record, &self.owner_person_cert)?)
    }

    pub fn owner_has_active_webauthn_credential(
        &self,
        record: &HouseholdRecord,
    ) -> Result<bool, OwnerAuthError> {
        Ok(self.owner_webauthn_credentials(record)?.active_count() > 0)
    }

    pub fn save(&self, state_dir: &Path) -> Result<(), OwnerAuthError> {
        // `household_auth_state.cbor` is the durable commit record. The
        // standalone cert file is a projection for fixtures/client diagnostics;
        // projection failures must not make the committed auth state unusable.
        atomic_write_cbor(&storage::household_auth_state_path(state_dir), self)?;
        write_owner_cert_projection(state_dir, &self.owner_person_cert);
        Ok(())
    }

    pub fn load_optional(
        state_dir: &Path,
        record: &HouseholdRecord,
        now: u64,
    ) -> Result<Option<Self>, OwnerAuthError> {
        let auth_path = storage::household_auth_state_path(state_dir);
        let cert_path = storage::owner_person_cert_path(state_dir);
        let auth: Option<Self> = storage::read_optional_cbor(&auth_path)?;
        let cert: Option<PersonCert> = storage::read_optional_cbor(&cert_path)?;
        match (auth, cert) {
            (None, None) => Ok(None),
            (Some(auth), Some(cert)) => {
                if auth.owner_person_cert != cert {
                    return Err(OwnerAuthError::InvalidState(
                        "owner_person_cert.cbor does not match household_auth_state.cbor".into(),
                    ));
                }
                auth.verify(record, now)?;
                Ok(Some(auth))
            }
            (Some(auth), None) => {
                auth.verify(record, now)?;
                write_owner_cert_projection(state_dir, &auth.owner_person_cert);
                Ok(Some(auth))
            }
            (None, Some(_)) => {
                let _ = storage::delete_owner_person_cert(state_dir);
                Ok(None)
            }
        }
    }
}

fn write_owner_cert_projection(state_dir: &Path, cert: &PersonCert) {
    if let Err(e) = atomic_write_cbor(&storage::owner_person_cert_path(state_dir), cert) {
        tracing::warn!(
            stage = "owner_auth.projection_write_failed",
            error = %e,
            "owner_person_cert.cbor projection was not written; auth state remains committed"
        );
    }
}
