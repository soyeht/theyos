//! Durable owner-passkey credential authority.
//!
//! This module is data-model only. Live `WebAuthn` assertions authorize mutations
//! at handler time; persisted events are verified at boot with durable household
//! signatures so startup never has to re-verify ephemeral `WebAuthn` ceremonies.
//! The durable cryptographic authority is the household root signature on each
//! event; the actor credential records which already-active owner credential
//! authorized the live mutation and is enforced as log well-formedness/audit
//! state, not as the durable event signer.
//!
//! This slice verifies authenticity and hash-chain continuity. Rollback and
//! truncation protection is provided by the inert `owner_webauthn_anchor`
//! helpers; before owner-auth enforcement is flipped on, boot/handler code must
//! wire those helpers so load rejects logs older than the durable keystore
//! anchor.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use thiserror::Error;

use crate::cbor;
use crate::error::{HouseholdError, KeystoreError};
use crate::household_record::HouseholdRecord;
use crate::keys::{IdentityKey, P256Signature, verify_signature};
use crate::machine_cert::PersonId;
use crate::owner_webauthn::{OwnerWebauthnCredential, OwnerWebauthnCredentialStore};
use crate::person_cert::PersonCert;

const EVENT_TYPE: &str = "owner_webauthn_credential_event";
const EVENT_SCHEMA_VERSION: u8 = 1;
const AUTHORITY_SCHEMA_VERSION: u8 = 1;
const HASH_LEN: usize = 32;

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct OwnerWebauthnAuthority {
    #[serde(rename = "v")]
    version: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    entries: Vec<SignedOwnerWebauthnCredentialEvent>,
}

impl OwnerWebauthnAuthority {
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
    pub fn entries(&self) -> &[SignedOwnerWebauthnCredentialEvent] {
        &self.entries
    }

    pub fn push_signed(&mut self, entry: SignedOwnerWebauthnCredentialEvent) {
        if self.version == 0 {
            self.version = AUTHORITY_SCHEMA_VERSION;
        }
        self.entries.push(entry);
    }

    pub fn verify(
        &self,
        record: &HouseholdRecord,
        owner_person_cert: &PersonCert,
    ) -> Result<(), OwnerWebauthnAuthorityError> {
        self.reconstruct(record, owner_person_cert).map(|_| ())
    }

    pub fn reconstruct(
        &self,
        record: &HouseholdRecord,
        owner_person_cert: &PersonCert,
    ) -> Result<OwnerWebauthnCredentialStore, OwnerWebauthnAuthorityError> {
        if self.version == 0 && self.entries.is_empty() {
            return Ok(OwnerWebauthnCredentialStore::default());
        }
        if self.version != AUTHORITY_SCHEMA_VERSION {
            return Err(OwnerWebauthnAuthorityError::Invalid(format!(
                "version {} unsupported",
                self.version
            )));
        }
        if self.entries.is_empty() {
            return Ok(OwnerWebauthnCredentialStore::default());
        }

        let mut store = OwnerWebauthnCredentialStore::default();
        let mut previous_hash: Option<[u8; HASH_LEN]> = None;

        for (index, entry) in self.entries.iter().enumerate() {
            entry.verify_signature(record)?;
            entry
                .event
                .validate_common(record, owner_person_cert, index, previous_hash)?;
            apply_event(&mut store, &entry.event)?;
            previous_hash = Some(entry.entry_hash()?);
        }

        Ok(store)
    }

    pub fn sign_genesis(
        signer: &dyn IdentityKey,
        record: &HouseholdRecord,
        owner_person_cert: &PersonCert,
        credential: OwnerWebauthnCredential,
        issued_at: u64,
    ) -> Result<SignedOwnerWebauthnCredentialEvent, OwnerWebauthnAuthorityError> {
        let event = OwnerWebauthnCredentialEvent {
            version: EVENT_SCHEMA_VERSION,
            event_type: EVENT_TYPE.to_string(),
            hh_id: record.hh_id.clone(),
            owner_p_id: owner_person_cert.p_id.clone(),
            sequence: 0,
            prev_hash: None,
            actor: OwnerWebauthnEventActor::GenesisTofu,
            issued_at,
            action: OwnerWebauthnCredentialEventAction::Add {
                credential: Box::new(credential),
            },
        };
        SignedOwnerWebauthnCredentialEvent::sign(event, signer)
    }

    pub fn sign_append(
        signer: &dyn IdentityKey,
        record: &HouseholdRecord,
        owner_person_cert: &PersonCert,
        previous_entry: &SignedOwnerWebauthnCredentialEvent,
        actor_credential_id: &[u8],
        action: OwnerWebauthnCredentialEventAction,
        issued_at: u64,
    ) -> Result<SignedOwnerWebauthnCredentialEvent, OwnerWebauthnAuthorityError> {
        let event = OwnerWebauthnCredentialEvent {
            version: EVENT_SCHEMA_VERSION,
            event_type: EVENT_TYPE.to_string(),
            hh_id: record.hh_id.clone(),
            owner_p_id: owner_person_cert.p_id.clone(),
            sequence: previous_entry.event.sequence + 1,
            prev_hash: Some(ByteBuf::from(previous_entry.entry_hash()?.to_vec())),
            actor: OwnerWebauthnEventActor::OwnerCredential {
                credential_id: ByteBuf::from(actor_credential_id.to_vec()),
            },
            issued_at,
            action,
        };
        SignedOwnerWebauthnCredentialEvent::sign(event, signer)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SignedOwnerWebauthnCredentialEvent {
    pub event: OwnerWebauthnCredentialEvent,
    pub signature: P256Signature,
}

impl SignedOwnerWebauthnCredentialEvent {
    pub fn sign(
        event: OwnerWebauthnCredentialEvent,
        signer: &dyn IdentityKey,
    ) -> Result<Self, OwnerWebauthnAuthorityError> {
        let canonical = event.signing_bytes()?;
        let signature = signer.sign(&canonical)?;
        Ok(Self { event, signature })
    }

    pub fn verify_signature(
        &self,
        record: &HouseholdRecord,
    ) -> Result<(), OwnerWebauthnAuthorityError> {
        verify_signature(
            &record.hh_pub,
            &self.event.signing_bytes()?,
            &self.signature,
        )?;
        Ok(())
    }

    pub fn entry_hash(&self) -> Result<[u8; HASH_LEN], OwnerWebauthnAuthorityError> {
        let bytes = cbor::to_canonical_vec(self)?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct OwnerWebauthnCredentialEvent {
    #[serde(rename = "v")]
    pub version: u8,
    #[serde(rename = "type")]
    pub event_type: String,
    pub hh_id: crate::ids::HouseholdId,
    pub owner_p_id: PersonId,
    pub sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<ByteBuf>,
    pub actor: OwnerWebauthnEventActor,
    pub issued_at: u64,
    pub action: OwnerWebauthnCredentialEventAction,
}

impl OwnerWebauthnCredentialEvent {
    fn signing_bytes(&self) -> Result<Vec<u8>, OwnerWebauthnAuthorityError> {
        Ok(cbor::to_canonical_vec(self)?)
    }

    fn validate_common(
        &self,
        record: &HouseholdRecord,
        owner_person_cert: &PersonCert,
        index: usize,
        expected_prev_hash: Option<[u8; HASH_LEN]>,
    ) -> Result<(), OwnerWebauthnAuthorityError> {
        if self.version != EVENT_SCHEMA_VERSION {
            return Err(OwnerWebauthnAuthorityError::Invalid(format!(
                "event version {} unsupported",
                self.version
            )));
        }
        if self.event_type != EVENT_TYPE {
            return Err(OwnerWebauthnAuthorityError::Invalid(format!(
                "event type {:?} unsupported",
                self.event_type
            )));
        }
        if self.hh_id != record.hh_id {
            return Err(OwnerWebauthnAuthorityError::Invalid(
                "event household id mismatch".into(),
            ));
        }
        if self.owner_p_id != owner_person_cert.p_id {
            return Err(OwnerWebauthnAuthorityError::Invalid(
                "event owner person id mismatch".into(),
            ));
        }
        let expected_sequence = u64::try_from(index).map_err(|_| {
            OwnerWebauthnAuthorityError::Invalid("event index overflow".to_string())
        })?;
        if self.sequence != expected_sequence {
            return Err(OwnerWebauthnAuthorityError::Invalid(format!(
                "event sequence {} != expected {}",
                self.sequence, expected_sequence
            )));
        }
        match (index, &self.actor) {
            (0, OwnerWebauthnEventActor::GenesisTofu) => {}
            (0, _) => {
                return Err(OwnerWebauthnAuthorityError::Invalid(
                    "genesis event must use genesis actor".into(),
                ));
            }
            (_, OwnerWebauthnEventActor::GenesisTofu) => {
                return Err(OwnerWebauthnAuthorityError::Invalid(
                    "genesis actor may only sign sequence 0".into(),
                ));
            }
            (_, OwnerWebauthnEventActor::OwnerCredential { credential_id }) => {
                if credential_id.is_empty() {
                    return Err(OwnerWebauthnAuthorityError::Invalid(
                        "actor credential id is empty".into(),
                    ));
                }
            }
        }
        match expected_prev_hash {
            None if self.prev_hash.is_none() => {}
            Some(expected) => {
                let actual = self.prev_hash.as_ref().ok_or_else(|| {
                    OwnerWebauthnAuthorityError::Invalid("missing prev_hash".into())
                })?;
                if actual.as_ref() != expected {
                    return Err(OwnerWebauthnAuthorityError::Invalid(
                        "prev_hash mismatch".into(),
                    ));
                }
            }
            None => {
                return Err(OwnerWebauthnAuthorityError::Invalid(
                    "genesis prev_hash must be absent".into(),
                ));
            }
        }
        self.action.validate_for_sequence(index)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerWebauthnEventActor {
    GenesisTofu,
    OwnerCredential {
        #[serde(with = "serde_bytes")]
        credential_id: ByteBuf,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerWebauthnCredentialEventAction {
    Add {
        credential: Box<OwnerWebauthnCredential>,
    },
    Revoke {
        #[serde(with = "serde_bytes")]
        credential_id: ByteBuf,
    },
}

impl OwnerWebauthnCredentialEventAction {
    fn validate_for_sequence(&self, index: usize) -> Result<(), OwnerWebauthnAuthorityError> {
        match (index, self) {
            (_, Self::Add { credential }) => validate_added_credential(credential),
            (0, Self::Revoke { .. }) => Err(OwnerWebauthnAuthorityError::Invalid(
                "genesis event must add the first credential".into(),
            )),
            (_, Self::Revoke { credential_id }) => {
                if credential_id.is_empty() {
                    return Err(OwnerWebauthnAuthorityError::Invalid(
                        "revoked credential id is empty".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum OwnerWebauthnAuthorityError {
    #[error("owner webauthn authority invalid: {0}")]
    Invalid(String),
    #[error("protocol: {0}")]
    Protocol(#[from] HouseholdError),
    #[error("sign: {0}")]
    Sign(#[from] KeystoreError),
    #[error("credential store: {0}")]
    CredentialStore(#[from] crate::owner_webauthn::OwnerWebauthnError),
}

fn validate_added_credential(
    credential: &OwnerWebauthnCredential,
) -> Result<(), OwnerWebauthnAuthorityError> {
    if credential.credential_id_bytes().is_empty() {
        return Err(OwnerWebauthnAuthorityError::Invalid(
            "added credential id is empty".into(),
        ));
    }
    if credential.is_revoked() {
        return Err(OwnerWebauthnAuthorityError::Invalid(
            "added credential is already revoked".into(),
        ));
    }
    Ok(())
}

fn apply_event(
    store: &mut OwnerWebauthnCredentialStore,
    event: &OwnerWebauthnCredentialEvent,
) -> Result<(), OwnerWebauthnAuthorityError> {
    if let OwnerWebauthnEventActor::OwnerCredential { credential_id } = &event.actor {
        let active = store.credentials().iter().any(|credential| {
            credential.credential_id_bytes() == credential_id.as_ref() && !credential.is_revoked()
        });
        if !active {
            return Err(OwnerWebauthnAuthorityError::Invalid(
                "actor credential was not active before event".into(),
            ));
        }
    }

    match &event.action {
        OwnerWebauthnCredentialEventAction::Add { credential } => {
            store.add((**credential).clone())?;
        }
        OwnerWebauthnCredentialEventAction::Revoke { credential_id } => {
            store.revoke_by_credential_id(credential_id.as_ref())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use webauthn_rs::prelude::Passkey;

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

    #[test]
    fn empty_authority_reconstructs_empty_store() {
        let (_root, record, owner_cert) = setup();
        let store = OwnerWebauthnAuthority::new()
            .reconstruct(&record, &owner_cert)
            .unwrap();
        assert_eq!(store.active_count(), 0);
    }

    #[test]
    fn genesis_event_is_hh_root_signed_and_reconstructs_first_credential() {
        let (root, record, owner_cert) = setup();
        let genesis = OwnerWebauthnAuthority::sign_genesis(
            &root,
            &record,
            &owner_cert,
            credential(b"owner-passkey-1"),
            NOW,
        )
        .unwrap();
        let mut authority = OwnerWebauthnAuthority::new();
        authority.push_signed(genesis);

        let store = authority.reconstruct(&record, &owner_cert).unwrap();
        assert_eq!(store.active_count(), 1);
        assert_eq!(
            store.active_credentials()[0].credential_id_bytes(),
            b"owner-passkey-1"
        );
    }

    #[test]
    fn tampered_event_fails_signature_verification() {
        let (root, record, owner_cert) = setup();
        let mut genesis = OwnerWebauthnAuthority::sign_genesis(
            &root,
            &record,
            &owner_cert,
            credential(b"owner-passkey-1"),
            NOW,
        )
        .unwrap();
        genesis.event.issued_at += 1;
        let mut authority = OwnerWebauthnAuthority::new();
        authority.push_signed(genesis);

        let err = authority.reconstruct(&record, &owner_cert).unwrap_err();
        assert!(matches!(err, OwnerWebauthnAuthorityError::Protocol(_)));
    }

    #[test]
    fn append_event_requires_active_actor_and_hash_chain() {
        let (root, record, owner_cert) = setup();
        let genesis = OwnerWebauthnAuthority::sign_genesis(
            &root,
            &record,
            &owner_cert,
            credential(b"owner-passkey-1"),
            NOW,
        )
        .unwrap();
        let second = OwnerWebauthnAuthority::sign_append(
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
        let mut authority = OwnerWebauthnAuthority::new();
        authority.push_signed(genesis);
        authority.push_signed(second);

        let store = authority.reconstruct(&record, &owner_cert).unwrap();
        assert_eq!(store.active_count(), 2);
    }

    #[test]
    fn append_event_from_revoked_actor_fails_closed() {
        let (root, record, owner_cert) = setup();
        let genesis = OwnerWebauthnAuthority::sign_genesis(
            &root,
            &record,
            &owner_cert,
            credential(b"owner-passkey-1"),
            NOW,
        )
        .unwrap();
        let revoke = OwnerWebauthnAuthority::sign_append(
            &root,
            &record,
            &owner_cert,
            &genesis,
            b"owner-passkey-1",
            OwnerWebauthnCredentialEventAction::Revoke {
                credential_id: ByteBuf::from(b"owner-passkey-1".to_vec()),
            },
            NOW + 1,
        )
        .unwrap();
        let after_revoke = OwnerWebauthnAuthority::sign_append(
            &root,
            &record,
            &owner_cert,
            &revoke,
            b"owner-passkey-1",
            OwnerWebauthnCredentialEventAction::Add {
                credential: Box::new(credential(b"owner-passkey-2")),
            },
            NOW + 2,
        )
        .unwrap();
        let mut authority = OwnerWebauthnAuthority::new();
        authority.push_signed(genesis);
        authority.push_signed(revoke);
        authority.push_signed(after_revoke);

        let err = authority.reconstruct(&record, &owner_cert).unwrap_err();
        assert!(matches!(err, OwnerWebauthnAuthorityError::Invalid(_)));
    }

    #[test]
    fn re_add_of_revoked_credential_id_fails_closed() {
        let (root, record, owner_cert) = setup();
        let genesis = OwnerWebauthnAuthority::sign_genesis(
            &root,
            &record,
            &owner_cert,
            credential(b"owner-passkey-1"),
            NOW,
        )
        .unwrap();
        let second = OwnerWebauthnAuthority::sign_append(
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
        let revoke = OwnerWebauthnAuthority::sign_append(
            &root,
            &record,
            &owner_cert,
            &second,
            b"owner-passkey-2",
            OwnerWebauthnCredentialEventAction::Revoke {
                credential_id: ByteBuf::from(b"owner-passkey-1".to_vec()),
            },
            NOW + 2,
        )
        .unwrap();
        let re_add = OwnerWebauthnAuthority::sign_append(
            &root,
            &record,
            &owner_cert,
            &revoke,
            b"owner-passkey-2",
            OwnerWebauthnCredentialEventAction::Add {
                credential: Box::new(credential(b"owner-passkey-1")),
            },
            NOW + 3,
        )
        .unwrap();
        let mut authority = OwnerWebauthnAuthority::new();
        authority.push_signed(genesis);
        authority.push_signed(second);
        authority.push_signed(revoke);
        authority.push_signed(re_add);

        let err = authority.reconstruct(&record, &owner_cert).unwrap_err();
        assert!(matches!(
            err,
            OwnerWebauthnAuthorityError::CredentialStore(
                crate::owner_webauthn::OwnerWebauthnError::DuplicateCredential
            )
        ));
    }

    #[test]
    fn wrong_prev_hash_fails_reconstruction() {
        let (root, record, owner_cert) = setup();
        let genesis = OwnerWebauthnAuthority::sign_genesis(
            &root,
            &record,
            &owner_cert,
            credential(b"owner-passkey-1"),
            NOW,
        )
        .unwrap();
        let mut second = OwnerWebauthnAuthority::sign_append(
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
        second.event.prev_hash = Some(ByteBuf::from(vec![0xAB; HASH_LEN]));
        second.signature = root.sign(&second.event.signing_bytes().unwrap()).unwrap();
        let mut authority = OwnerWebauthnAuthority::new();
        authority.push_signed(genesis);
        authority.push_signed(second);

        let err = authority.reconstruct(&record, &owner_cert).unwrap_err();
        assert!(matches!(err, OwnerWebauthnAuthorityError::Invalid(_)));
    }

    #[test]
    fn wrong_signer_fails_reconstruction() {
        let (root, record, owner_cert) = setup();
        let attacker = P256Keypair::generate();
        let genesis = OwnerWebauthnAuthority::sign_genesis(
            &attacker,
            &record,
            &owner_cert,
            credential(b"owner-passkey-1"),
            NOW,
        )
        .unwrap();
        let mut authority = OwnerWebauthnAuthority::new();
        authority.push_signed(genesis);

        let err = authority.reconstruct(&record, &owner_cert).unwrap_err();
        assert!(matches!(err, OwnerWebauthnAuthorityError::Protocol(_)));

        // The legitimate root still signs events accepted by the same record.
        let genesis = OwnerWebauthnAuthority::sign_genesis(
            &root,
            &record,
            &owner_cert,
            credential(b"owner-passkey-1"),
            NOW,
        )
        .unwrap();
        let mut authority = OwnerWebauthnAuthority::new();
        authority.push_signed(genesis);
        authority.reconstruct(&record, &owner_cert).unwrap();
    }

    #[test]
    fn added_credential_must_not_be_pre_revoked() {
        let (root, record, owner_cert) = setup();
        let mut pre_revoked = credential(b"owner-passkey-1");
        pre_revoked.revoke();
        let genesis =
            OwnerWebauthnAuthority::sign_genesis(&root, &record, &owner_cert, pre_revoked, NOW)
                .unwrap();
        let mut authority = OwnerWebauthnAuthority::new();
        authority.push_signed(genesis);

        let err = authority.reconstruct(&record, &owner_cert).unwrap_err();
        assert!(matches!(err, OwnerWebauthnAuthorityError::Invalid(_)));
    }

    #[test]
    fn rollback_truncation_requires_future_anchor() {
        let (root, record, owner_cert) = setup();
        let genesis = OwnerWebauthnAuthority::sign_genesis(
            &root,
            &record,
            &owner_cert,
            credential(b"owner-passkey-1"),
            NOW,
        )
        .unwrap();
        let second = OwnerWebauthnAuthority::sign_append(
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
        let mut full = OwnerWebauthnAuthority::new();
        full.push_signed(genesis.clone());
        full.push_signed(second);
        assert_eq!(
            full.reconstruct(&record, &owner_cert)
                .unwrap()
                .active_count(),
            2
        );

        let mut truncated = OwnerWebauthnAuthority::new();
        truncated.push_signed(genesis);
        assert_eq!(
            truncated
                .reconstruct(&record, &owner_cert)
                .unwrap()
                .active_count(),
            1
        );
    }
}
