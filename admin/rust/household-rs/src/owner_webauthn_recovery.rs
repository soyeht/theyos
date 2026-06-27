//! Durable owner-passkey recovery readiness authority.
//!
//! This module models only recovery-code provision/rotation readiness. It does
//! not consume recovery codes and it does not grant owner auth by itself. Runtime
//! handlers must still require a live owner `WebAuthn` step-up before mutating this
//! authority.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use thiserror::Error;

use crate::cbor;
use crate::error::{HouseholdError, KeystoreError};
use crate::household_record::HouseholdRecord;
use crate::keys::{IdentityKey, verify_signature};
use crate::machine_cert::PersonId;
use crate::person_cert::PersonCert;

const EVENT_TYPE: &str = "owner_webauthn_recovery_event";
const EVENT_SCHEMA_VERSION: u8 = 1;
const AUTHORITY_SCHEMA_VERSION: u8 = 1;
const HASH_LEN: usize = 32;
const SALT_LEN: usize = 32;
const VERIFIER_CONTEXT: &str = "soyeht owner webauthn recovery code verifier v1";

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct OwnerWebauthnRecoveryAuthority {
    #[serde(rename = "v")]
    version: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    entries: Vec<SignedOwnerWebauthnRecoveryEvent>,
}

impl OwnerWebauthnRecoveryAuthority {
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: AUTHORITY_SCHEMA_VERSION,
            entries: Vec::new(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn entries(&self) -> &[SignedOwnerWebauthnRecoveryEvent] {
        &self.entries
    }

    pub fn push_signed(&mut self, entry: SignedOwnerWebauthnRecoveryEvent) {
        if self.version == 0 {
            self.version = AUTHORITY_SCHEMA_VERSION;
        }
        self.entries.push(entry);
    }

    pub fn replace_after_authoritative_prefix(
        &mut self,
        authoritative_sequence: Option<u64>,
        entry: SignedOwnerWebauthnRecoveryEvent,
    ) -> Result<(), OwnerWebauthnRecoveryError> {
        let expected_sequence = authoritative_sequence.map_or(0, |sequence| sequence + 1);
        if entry.event.sequence != expected_sequence {
            return Err(OwnerWebauthnRecoveryError::Invalid(format!(
                "replacement event sequence {} != expected {}",
                entry.event.sequence, expected_sequence
            )));
        }
        let retain_len = usize::try_from(expected_sequence).map_err(|_| {
            OwnerWebauthnRecoveryError::Invalid("authoritative sequence overflow".to_string())
        })?;
        if retain_len > self.entries.len() {
            return Err(OwnerWebauthnRecoveryError::Invalid(
                "authoritative prefix exceeds recovery log".into(),
            ));
        }
        if self.version == 0 {
            self.version = AUTHORITY_SCHEMA_VERSION;
        }
        self.entries.truncate(retain_len);
        self.entries.push(entry);
        Ok(())
    }

    pub fn verify(
        &self,
        record: &HouseholdRecord,
        owner_person_cert: &PersonCert,
    ) -> Result<(), OwnerWebauthnRecoveryError> {
        if self.version == 0 && self.entries.is_empty() {
            return Ok(());
        }
        if self.version != AUTHORITY_SCHEMA_VERSION {
            return Err(OwnerWebauthnRecoveryError::Invalid(format!(
                "version {} unsupported",
                self.version
            )));
        }

        let mut previous_hash: Option<[u8; HASH_LEN]> = None;
        for (index, entry) in self.entries.iter().enumerate() {
            entry.verify_signature(record)?;
            entry
                .event
                .validate_common(record, owner_person_cert, index, previous_hash)?;
            previous_hash = Some(entry.entry_hash()?);
        }
        Ok(())
    }

    pub fn sign_next(
        signer: &dyn IdentityKey,
        record: &HouseholdRecord,
        owner_person_cert: &PersonCert,
        previous_entry: Option<&SignedOwnerWebauthnRecoveryEvent>,
        actor_credential_id: &[u8],
        verifier: RecoveryCodeVerifier,
        issued_at: u64,
    ) -> Result<SignedOwnerWebauthnRecoveryEvent, OwnerWebauthnRecoveryError> {
        let (sequence, prev_hash) = if let Some(previous) = previous_entry {
            (
                previous.event.sequence + 1,
                Some(ByteBuf::from(previous.entry_hash()?.to_vec())),
            )
        } else {
            (0, None)
        };
        let action = if sequence == 0 {
            OwnerWebauthnRecoveryEventAction::Provision { verifier }
        } else {
            OwnerWebauthnRecoveryEventAction::Rotate { verifier }
        };
        let event = OwnerWebauthnRecoveryEvent {
            version: EVENT_SCHEMA_VERSION,
            event_type: EVENT_TYPE.to_string(),
            hh_id: record.hh_id.clone(),
            owner_p_id: owner_person_cert.p_id.clone(),
            sequence,
            prev_hash,
            actor: OwnerWebauthnRecoveryActor::OwnerCredential {
                credential_id: ByteBuf::from(actor_credential_id.to_vec()),
            },
            issued_at,
            action,
        };
        SignedOwnerWebauthnRecoveryEvent::sign(event, signer)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SignedOwnerWebauthnRecoveryEvent {
    pub event: OwnerWebauthnRecoveryEvent,
    pub signature: crate::keys::P256Signature,
}

impl SignedOwnerWebauthnRecoveryEvent {
    pub fn sign(
        event: OwnerWebauthnRecoveryEvent,
        signer: &dyn IdentityKey,
    ) -> Result<Self, OwnerWebauthnRecoveryError> {
        let canonical = event.signing_bytes()?;
        let signature = signer.sign(&canonical)?;
        Ok(Self { event, signature })
    }

    pub fn verify_signature(
        &self,
        record: &HouseholdRecord,
    ) -> Result<(), OwnerWebauthnRecoveryError> {
        verify_signature(
            &record.hh_pub,
            &self.event.signing_bytes()?,
            &self.signature,
        )?;
        Ok(())
    }

    pub fn entry_hash(&self) -> Result<[u8; HASH_LEN], OwnerWebauthnRecoveryError> {
        let bytes = cbor::to_canonical_vec(self)?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct OwnerWebauthnRecoveryEvent {
    #[serde(rename = "v")]
    pub version: u8,
    #[serde(rename = "type")]
    pub event_type: String,
    pub hh_id: crate::ids::HouseholdId,
    pub owner_p_id: PersonId,
    pub sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<ByteBuf>,
    pub actor: OwnerWebauthnRecoveryActor,
    pub issued_at: u64,
    pub action: OwnerWebauthnRecoveryEventAction,
}

impl OwnerWebauthnRecoveryEvent {
    fn signing_bytes(&self) -> Result<Vec<u8>, OwnerWebauthnRecoveryError> {
        Ok(cbor::to_canonical_vec(self)?)
    }

    fn validate_common(
        &self,
        record: &HouseholdRecord,
        owner_person_cert: &PersonCert,
        index: usize,
        expected_prev_hash: Option<[u8; HASH_LEN]>,
    ) -> Result<(), OwnerWebauthnRecoveryError> {
        if self.version != EVENT_SCHEMA_VERSION {
            return Err(OwnerWebauthnRecoveryError::Invalid(format!(
                "event version {} unsupported",
                self.version
            )));
        }
        if self.event_type != EVENT_TYPE {
            return Err(OwnerWebauthnRecoveryError::Invalid(format!(
                "event type {:?} unsupported",
                self.event_type
            )));
        }
        if self.hh_id != record.hh_id {
            return Err(OwnerWebauthnRecoveryError::Invalid(
                "event household id mismatch".into(),
            ));
        }
        if self.owner_p_id != owner_person_cert.p_id {
            return Err(OwnerWebauthnRecoveryError::Invalid(
                "event owner person id mismatch".into(),
            ));
        }
        let expected_sequence = u64::try_from(index)
            .map_err(|_| OwnerWebauthnRecoveryError::Invalid("event index overflow".to_string()))?;
        if self.sequence != expected_sequence {
            return Err(OwnerWebauthnRecoveryError::Invalid(format!(
                "event sequence {} != expected {}",
                self.sequence, expected_sequence
            )));
        }
        match expected_prev_hash {
            None if self.prev_hash.is_none() => {}
            Some(expected) => {
                let actual = self.prev_hash.as_ref().ok_or_else(|| {
                    OwnerWebauthnRecoveryError::Invalid("missing prev_hash".into())
                })?;
                if actual.as_ref() != expected {
                    return Err(OwnerWebauthnRecoveryError::Invalid(
                        "prev_hash mismatch".into(),
                    ));
                }
            }
            None => {
                return Err(OwnerWebauthnRecoveryError::Invalid(
                    "genesis prev_hash must be absent".into(),
                ));
            }
        }
        match &self.actor {
            OwnerWebauthnRecoveryActor::OwnerCredential { credential_id } => {
                if credential_id.is_empty() {
                    return Err(OwnerWebauthnRecoveryError::Invalid(
                        "actor credential id is empty".into(),
                    ));
                }
            }
        }
        self.action.validate_for_sequence(index)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerWebauthnRecoveryActor {
    OwnerCredential {
        #[serde(with = "serde_bytes")]
        credential_id: ByteBuf,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerWebauthnRecoveryEventAction {
    Provision { verifier: RecoveryCodeVerifier },
    Rotate { verifier: RecoveryCodeVerifier },
}

impl OwnerWebauthnRecoveryEventAction {
    fn validate_for_sequence(&self, index: usize) -> Result<(), OwnerWebauthnRecoveryError> {
        match (index, self) {
            (0, Self::Provision { verifier }) => verifier.validate(),
            (0, Self::Rotate { .. }) => Err(OwnerWebauthnRecoveryError::Invalid(
                "genesis recovery event must provision".into(),
            )),
            (_, Self::Provision { .. }) => Err(OwnerWebauthnRecoveryError::Invalid(
                "provision may only be recovery genesis".into(),
            )),
            (_, Self::Rotate { verifier }) => verifier.validate(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCodeVerifier {
    #[serde(rename = "v")]
    version: u8,
    #[serde(with = "serde_bytes")]
    salt: ByteBuf,
    #[serde(with = "serde_bytes")]
    verifier: ByteBuf,
}

impl RecoveryCodeVerifier {
    #[must_use]
    pub fn from_code_bytes(salt: [u8; SALT_LEN], code: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(VERIFIER_CONTEXT);
        hasher.update(&salt);
        hasher.update(code);
        Self {
            version: 1,
            salt: ByteBuf::from(salt.to_vec()),
            verifier: ByteBuf::from(hasher.finalize().as_bytes().to_vec()),
        }
    }

    fn validate(&self) -> Result<(), OwnerWebauthnRecoveryError> {
        if self.version != 1 {
            return Err(OwnerWebauthnRecoveryError::Invalid(format!(
                "recovery verifier version {} unsupported",
                self.version
            )));
        }
        if self.salt.len() != SALT_LEN {
            return Err(OwnerWebauthnRecoveryError::Invalid(
                "recovery verifier salt must be 32 bytes".into(),
            ));
        }
        if self.verifier.len() != HASH_LEN {
            return Err(OwnerWebauthnRecoveryError::Invalid(
                "recovery verifier hash must be 32 bytes".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum OwnerWebauthnRecoveryError {
    #[error("owner webauthn recovery invalid: {0}")]
    Invalid(String),
    #[error("protocol: {0}")]
    Protocol(#[from] HouseholdError),
    #[error("sign: {0}")]
    Sign(#[from] KeystoreError),
}

pub fn verified_owner_webauthn_recovery_head(
    authority: &OwnerWebauthnRecoveryAuthority,
    record: &HouseholdRecord,
    owner_person_cert: &PersonCert,
) -> Result<Option<OwnerWebauthnRecoveryHead>, OwnerWebauthnRecoveryError> {
    authority.verify(record, owner_person_cert)?;
    let Some((index, entry)) = authority.entries().iter().enumerate().next_back() else {
        return Ok(None);
    };
    Ok(Some(OwnerWebauthnRecoveryHead {
        sequence: u64::try_from(index).map_err(|_| {
            OwnerWebauthnRecoveryError::Invalid("recovery sequence overflow".to_string())
        })?,
        head_hash: entry.entry_hash()?,
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerWebauthnRecoveryHead {
    pub sequence: u64,
    pub head_hash: [u8; HASH_LEN],
}
