//! Durable owner-passkey recovery readiness authority.
//!
//! This module models recovery-code provision, rotation, and one-shot consume
//! state. It does not grant owner auth by itself. Runtime provision/rotation
//! handlers must require a live owner `WebAuthn` step-up. A future consume
//! runtime must not require a live passkey step-up; it must prove recovery-code
//! possession through a dedicated flow.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use subtle::ConstantTimeEq;
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
        let mut previous_carried_active_verifier = None;
        for (index, entry) in self.entries.iter().enumerate() {
            entry.verify_signature(record)?;
            entry.event.validate_common(
                record,
                owner_person_cert,
                index,
                previous_hash,
                previous_carried_active_verifier,
            )?;
            previous_hash = Some(entry.entry_hash()?);
            previous_carried_active_verifier = Some(entry.event.action.carries_active_verifier());
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

    pub fn sign_consume(
        signer: &dyn IdentityKey,
        record: &HouseholdRecord,
        owner_person_cert: &PersonCert,
        previous_entry: &SignedOwnerWebauthnRecoveryEvent,
        issued_at: u64,
    ) -> Result<SignedOwnerWebauthnRecoveryEvent, OwnerWebauthnRecoveryError> {
        if !previous_entry.event.action.carries_active_verifier() {
            return Err(OwnerWebauthnRecoveryError::Invalid(
                "previous recovery event is not an active verifier".into(),
            ));
        }
        let previous_hash = previous_entry.entry_hash()?;
        let event = OwnerWebauthnRecoveryEvent {
            version: EVENT_SCHEMA_VERSION,
            event_type: EVENT_TYPE.to_string(),
            hh_id: record.hh_id.clone(),
            owner_p_id: owner_person_cert.p_id.clone(),
            sequence: previous_entry.event.sequence + 1,
            prev_hash: Some(ByteBuf::from(previous_hash.to_vec())),
            actor: OwnerWebauthnRecoveryActor::RecoveryProof {
                verifier_head_sequence: previous_entry.event.sequence,
                verifier_head_hash: ByteBuf::from(previous_hash.to_vec()),
            },
            issued_at,
            action: OwnerWebauthnRecoveryEventAction::Consume,
        };
        SignedOwnerWebauthnRecoveryEvent::sign(event, signer)
    }

    #[must_use]
    pub fn latest_verifier(&self) -> Option<&RecoveryCodeVerifier> {
        self.entries
            .last()
            .and_then(|entry| entry.event.action.verifier())
    }

    #[must_use]
    pub fn recovery_ready(&self) -> bool {
        self.latest_verifier().is_some()
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
        previous_carried_active_verifier: Option<bool>,
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
        match (index, &self.actor, &self.action) {
            (
                _,
                OwnerWebauthnRecoveryActor::OwnerCredential { credential_id },
                OwnerWebauthnRecoveryEventAction::Provision { .. }
                | OwnerWebauthnRecoveryEventAction::Rotate { .. },
            ) => {
                if credential_id.is_empty() {
                    return Err(OwnerWebauthnRecoveryError::Invalid(
                        "actor credential id is empty".into(),
                    ));
                }
            }
            (
                _,
                OwnerWebauthnRecoveryActor::OwnerCredential { .. },
                OwnerWebauthnRecoveryEventAction::Consume,
            ) => {
                return Err(OwnerWebauthnRecoveryError::Invalid(
                    "owner credential actor may not consume recovery".into(),
                ));
            }
            (
                0,
                OwnerWebauthnRecoveryActor::RecoveryProof { .. },
                OwnerWebauthnRecoveryEventAction::Consume,
            ) => {
                return Err(OwnerWebauthnRecoveryError::Invalid(
                    "recovery actor may not be genesis".into(),
                ));
            }
            (
                _,
                OwnerWebauthnRecoveryActor::RecoveryProof {
                    verifier_head_sequence,
                    verifier_head_hash,
                },
                OwnerWebauthnRecoveryEventAction::Consume,
            ) => {
                if verifier_head_hash.len() != HASH_LEN {
                    return Err(OwnerWebauthnRecoveryError::Invalid(
                        "recovery actor verifier head hash must be 32 bytes".into(),
                    ));
                }
                let expected_sequence = u64::try_from(index - 1).map_err(|_| {
                    OwnerWebauthnRecoveryError::Invalid("recovery actor index overflow".into())
                })?;
                if *verifier_head_sequence != expected_sequence {
                    return Err(OwnerWebauthnRecoveryError::Invalid(
                        "recovery actor verifier sequence mismatch".into(),
                    ));
                }
                let expected_hash = expected_prev_hash.ok_or_else(|| {
                    OwnerWebauthnRecoveryError::Invalid(
                        "recovery actor missing verifier head hash".into(),
                    )
                })?;
                if verifier_head_hash.as_ref() != expected_hash {
                    return Err(OwnerWebauthnRecoveryError::Invalid(
                        "recovery actor verifier head hash mismatch".into(),
                    ));
                }
                if !previous_carried_active_verifier.unwrap_or(false) {
                    return Err(OwnerWebauthnRecoveryError::Invalid(
                        "recovery consume must reference an active verifier".into(),
                    ));
                }
            }
            (
                _,
                OwnerWebauthnRecoveryActor::RecoveryProof { .. },
                OwnerWebauthnRecoveryEventAction::Provision { .. }
                | OwnerWebauthnRecoveryEventAction::Rotate { .. },
            ) => {
                return Err(OwnerWebauthnRecoveryError::Invalid(
                    "recovery actor may only consume recovery".into(),
                ));
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
    RecoveryProof {
        verifier_head_sequence: u64,
        #[serde(with = "serde_bytes")]
        verifier_head_hash: ByteBuf,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerWebauthnRecoveryEventAction {
    Provision { verifier: RecoveryCodeVerifier },
    Rotate { verifier: RecoveryCodeVerifier },
    Consume,
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
            (0, Self::Consume) => Err(OwnerWebauthnRecoveryError::Invalid(
                "consume may not be recovery genesis".into(),
            )),
            (_, Self::Consume) => Ok(()),
        }
    }

    #[must_use]
    fn verifier(&self) -> Option<&RecoveryCodeVerifier> {
        match self {
            Self::Provision { verifier } | Self::Rotate { verifier } => Some(verifier),
            Self::Consume => None,
        }
    }

    #[must_use]
    fn carries_active_verifier(&self) -> bool {
        match self {
            Self::Provision { .. } | Self::Rotate { .. } => true,
            Self::Consume => false,
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

    pub fn matches_code_bytes(&self, code: &[u8]) -> Result<bool, OwnerWebauthnRecoveryError> {
        self.validate()?;
        let salt: [u8; SALT_LEN] = self.salt.as_ref().try_into().map_err(|_| {
            OwnerWebauthnRecoveryError::Invalid("recovery verifier salt must be 32 bytes".into())
        })?;
        let candidate = Self::from_code_bytes(salt, code);
        Ok(bool::from(candidate.verifier.ct_eq(&self.verifier)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{MachineId, derive_household_id};
    use crate::keys::P256Keypair;
    use crate::person_cert::{PersonCert, SignOwnerOptions};

    const NOW: u64 = 1_800_000_000;

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

    fn verifier(code: &[u8]) -> RecoveryCodeVerifier {
        RecoveryCodeVerifier::from_code_bytes([0xA5; SALT_LEN], code)
    }

    #[test]
    fn recovery_verifier_matches_code_bytes_without_exposing_plaintext() {
        let verifier = verifier(b"high-entropy-recovery-code");
        assert!(
            verifier
                .matches_code_bytes(b"high-entropy-recovery-code")
                .unwrap()
        );
        assert!(!verifier.matches_code_bytes(b"wrong-code").unwrap());
    }

    #[test]
    fn consume_invalidates_recovery_readiness_and_rejects_duplicate_consume() {
        let (root, record, owner_cert) = setup();
        let provision = OwnerWebauthnRecoveryAuthority::sign_next(
            &root,
            &record,
            &owner_cert,
            None,
            b"owner-passkey-1",
            verifier(b"high-entropy-recovery-code"),
            NOW,
        )
        .unwrap();
        let consume = OwnerWebauthnRecoveryAuthority::sign_consume(
            &root,
            &record,
            &owner_cert,
            &provision,
            NOW + 1,
        )
        .unwrap();
        assert_eq!(
            consume.event.actor,
            OwnerWebauthnRecoveryActor::RecoveryProof {
                verifier_head_sequence: 0,
                verifier_head_hash: ByteBuf::from(provision.entry_hash().unwrap().to_vec()),
            }
        );

        let mut authority = OwnerWebauthnRecoveryAuthority::new();
        authority.push_signed(provision.clone());
        assert!(authority.recovery_ready());
        authority.push_signed(consume.clone());
        authority.verify(&record, &owner_cert).unwrap();
        assert!(!authority.recovery_ready());
        assert!(authority.latest_verifier().is_none());

        let duplicate = OwnerWebauthnRecoveryAuthority::sign_consume(
            &root,
            &record,
            &owner_cert,
            &consume,
            NOW + 2,
        );
        assert!(matches!(
            duplicate,
            Err(OwnerWebauthnRecoveryError::Invalid(_))
        ));

        let consume_hash = consume.entry_hash().unwrap();
        let duplicate = SignedOwnerWebauthnRecoveryEvent::sign(
            OwnerWebauthnRecoveryEvent {
                version: EVENT_SCHEMA_VERSION,
                event_type: EVENT_TYPE.to_string(),
                hh_id: record.hh_id.clone(),
                owner_p_id: owner_cert.p_id.clone(),
                sequence: 2,
                prev_hash: Some(ByteBuf::from(consume_hash.to_vec())),
                actor: OwnerWebauthnRecoveryActor::RecoveryProof {
                    verifier_head_sequence: 1,
                    verifier_head_hash: ByteBuf::from(consume_hash.to_vec()),
                },
                issued_at: NOW + 2,
                action: OwnerWebauthnRecoveryEventAction::Consume,
            },
            &root,
        )
        .unwrap();
        let mut tampered_authority = OwnerWebauthnRecoveryAuthority::new();
        tampered_authority.push_signed(provision);
        tampered_authority.push_signed(consume);
        tampered_authority.push_signed(duplicate);
        let err = tampered_authority.verify(&record, &owner_cert).unwrap_err();
        assert!(matches!(err, OwnerWebauthnRecoveryError::Invalid(_)));
    }

    #[test]
    fn consume_must_reference_immediate_recovery_head() {
        let (root, record, owner_cert) = setup();
        let provision = OwnerWebauthnRecoveryAuthority::sign_next(
            &root,
            &record,
            &owner_cert,
            None,
            b"owner-passkey-1",
            verifier(b"high-entropy-recovery-code"),
            NOW,
        )
        .unwrap();
        let mut consume = OwnerWebauthnRecoveryAuthority::sign_consume(
            &root,
            &record,
            &owner_cert,
            &provision,
            NOW + 1,
        )
        .unwrap();
        consume.event.actor = OwnerWebauthnRecoveryActor::RecoveryProof {
            verifier_head_sequence: 0,
            verifier_head_hash: ByteBuf::from(vec![0xEE; HASH_LEN]),
        };
        consume.signature = root.sign(&consume.event.signing_bytes().unwrap()).unwrap();

        let mut authority = OwnerWebauthnRecoveryAuthority::new();
        authority.push_signed(provision);
        authority.push_signed(consume);
        let err = authority.verify(&record, &owner_cert).unwrap_err();
        assert!(matches!(err, OwnerWebauthnRecoveryError::Invalid(_)));
    }

    #[test]
    fn owner_credential_actor_may_not_consume_recovery() {
        let (root, record, owner_cert) = setup();
        let provision = OwnerWebauthnRecoveryAuthority::sign_next(
            &root,
            &record,
            &owner_cert,
            None,
            b"owner-passkey-1",
            verifier(b"high-entropy-recovery-code"),
            NOW,
        )
        .unwrap();
        let consume = SignedOwnerWebauthnRecoveryEvent::sign(
            OwnerWebauthnRecoveryEvent {
                version: EVENT_SCHEMA_VERSION,
                event_type: EVENT_TYPE.to_string(),
                hh_id: record.hh_id.clone(),
                owner_p_id: owner_cert.p_id.clone(),
                sequence: 1,
                prev_hash: Some(ByteBuf::from(provision.entry_hash().unwrap().to_vec())),
                actor: OwnerWebauthnRecoveryActor::OwnerCredential {
                    credential_id: ByteBuf::from(b"owner-passkey-1".to_vec()),
                },
                issued_at: NOW + 1,
                action: OwnerWebauthnRecoveryEventAction::Consume,
            },
            &root,
        )
        .unwrap();

        let mut authority = OwnerWebauthnRecoveryAuthority::new();
        authority.push_signed(provision);
        authority.push_signed(consume);
        let err = authority.verify(&record, &owner_cert).unwrap_err();
        assert!(matches!(err, OwnerWebauthnRecoveryError::Invalid(_)));
    }
}
