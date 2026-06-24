//! Storage helper for Product A `relay_stream` Noise static keys.
//!
//! This module only provisions and loads the claw-side X25519 static key used
//! by the isolated `relay_stream` Noise seam. It is not wired into bootstrap,
//! claim ack, iOS, public listeners, or offer minting.

use std::fmt;

use keystore_rs::{KeystoreBackend, KeystoreError};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::claw_share_relay_stream_contract::{
    RelayStreamClawStaticPublicKey, RelayStreamContractError,
};
use crate::claw_share_relay_stream_noise::{
    RelayStreamNoiseError, RelayStreamNoiseStaticKeypair, RelayStreamNoiseStaticPrivateKey,
    generate_relay_stream_noise_static_keypair,
};

pub const RELAY_STREAM_NOISE_KEY_ACCOUNT_PREFIX: &str =
    "claw-share/relay-stream/noise-static-x25519/v1";
pub const RELAY_STREAM_NOISE_KEY_BLOB_VERSION: u8 = 1;
pub const DEFAULT_RELAY_STREAM_NOISE_KEY_ID: &str = "engine";

#[derive(Clone, Copy)]
pub struct RelayStreamNoiseKeyStore<'a> {
    backend: &'a dyn KeystoreBackend,
}

impl<'a> RelayStreamNoiseKeyStore<'a> {
    #[must_use]
    pub fn new(backend: &'a dyn KeystoreBackend) -> Self {
        Self { backend }
    }

    pub fn account_for_key_id(key_id: &str) -> Result<String, RelayStreamNoiseKeyStoreError> {
        relay_stream_noise_static_key_account(key_id)
    }

    pub fn get_or_create(
        &self,
        key_id: &str,
    ) -> Result<RelayStreamNoiseStaticKeypair, RelayStreamNoiseKeyStoreError> {
        let account = relay_stream_noise_static_key_account(key_id)?;
        match self.backend.get(&account) {
            Ok(bytes) => decode_key_blob(&bytes),
            Err(KeystoreError::NotFound { .. }) => {
                let keypair = generate_relay_stream_noise_static_keypair()?;
                let blob = encode_key_blob(&keypair)?;
                self.backend.set(&account, &blob)?;
                Ok(keypair)
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl fmt::Debug for RelayStreamNoiseKeyStore<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamNoiseKeyStore")
            .field("backend", &"redacted")
            .finish()
    }
}

pub fn relay_stream_noise_static_key_account(
    key_id: &str,
) -> Result<String, RelayStreamNoiseKeyStoreError> {
    let key_id = key_id.trim();
    if key_id.is_empty()
        || !key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(RelayStreamNoiseKeyStoreError::InvalidKeyId);
    }
    Ok(format!("{RELAY_STREAM_NOISE_KEY_ACCOUNT_PREFIX}/{key_id}"))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayStreamNoiseStaticKeyBlob {
    v: u8,
    #[serde(with = "serde_bytes")]
    private: ByteBuf,
    #[serde(with = "serde_bytes")]
    public: ByteBuf,
}

fn encode_key_blob(
    keypair: &RelayStreamNoiseStaticKeypair,
) -> Result<Vec<u8>, RelayStreamNoiseKeyStoreError> {
    let blob = RelayStreamNoiseStaticKeyBlob {
        v: RELAY_STREAM_NOISE_KEY_BLOB_VERSION,
        private: ByteBuf::from(keypair.private_key().as_bytes().to_vec()),
        public: ByteBuf::from(keypair.public_key().as_bytes().to_vec()),
    };
    household_rs::cbor::to_canonical_vec(&blob).map_err(RelayStreamNoiseKeyStoreError::Cbor)
}

fn decode_key_blob(
    bytes: &[u8],
) -> Result<RelayStreamNoiseStaticKeypair, RelayStreamNoiseKeyStoreError> {
    let blob: RelayStreamNoiseStaticKeyBlob = household_rs::cbor::from_canonical_slice(bytes)
        .map_err(RelayStreamNoiseKeyStoreError::Cbor)?;
    if blob.v != RELAY_STREAM_NOISE_KEY_BLOB_VERSION {
        return Err(RelayStreamNoiseKeyStoreError::VersionUnsupported(blob.v));
    }
    let private = RelayStreamNoiseStaticPrivateKey::try_new(blob.private.as_ref())?;
    let public = RelayStreamClawStaticPublicKey::try_new(blob.public.as_ref())?;
    Ok(RelayStreamNoiseStaticKeypair::from_parts(private, public))
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamNoiseKeyStoreError {
    #[error("relay stream Noise key id is invalid")]
    InvalidKeyId,

    #[error("relay stream Noise key blob version unsupported: {0}")]
    VersionUnsupported(u8),

    #[error("relay stream Noise keystore failed: {0}")]
    Keystore(#[from] KeystoreError),

    #[error("relay stream Noise key blob CBOR failed: {0}")]
    Cbor(household_rs::HouseholdError),

    #[error("relay stream Noise key blob rejected")]
    Noise(#[from] RelayStreamNoiseError),

    #[error("relay stream Noise public key rejected")]
    Contract(#[from] RelayStreamContractError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::claw_share::{SLOT_ID_LEN, SlotId};
    use household_rs::keys::{IdentityKey, P256Keypair};
    use keystore_rs::FileKeystore;

    use crate::claw_share_relay_stream_contract::{
        RelayStreamExpectedPath, RelayStreamOfferContract, RelayStreamOfferPayload,
        RelayStreamResource,
    };
    use crate::claw_share_relay_stream_noise::{
        RelayStreamNoiseInitiator, RelayStreamNoiseResponder,
    };
    use crate::claw_share_rendezvous_stream_relay::RendezvousToken;

    const NOW: u64 = 1_800_000_000;
    const NOT_AFTER: u64 = NOW + 60;

    fn owner() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap()
    }

    fn owner_pub() -> household_rs::keys::P256PublicKey {
        owner().public()
    }

    fn guest_pub() -> household_rs::keys::P256PublicKey {
        P256Keypair::from_secret_scalar(&[0x33; 32])
            .unwrap()
            .public()
    }

    fn backend(dir: &tempfile::TempDir) -> FileKeystore {
        FileKeystore::new(dir.path(), "com.soyeht.theyos.test")
    }

    fn token() -> RendezvousToken {
        RendezvousToken::try_new(vec![0x42; 16]).unwrap()
    }

    fn signed_offer(public: RelayStreamClawStaticPublicKey) -> RelayStreamOfferContract {
        let payload = RelayStreamOfferPayload::new(
            token(),
            "claw_alpha".to_string(),
            SlotId([0x22; SLOT_ID_LEN]),
            guest_pub(),
            RelayStreamResource::Pty,
            RelayStreamExpectedPath::RelayStream,
            "relay-stream://127.0.0.1:49152".to_string(),
            public,
            NOT_AFTER,
        );
        RelayStreamOfferContract::sign(payload, &owner()).unwrap()
    }

    fn blob(v: u8, private: Vec<u8>, public: Vec<u8>) -> Vec<u8> {
        household_rs::cbor::to_canonical_vec(&RelayStreamNoiseStaticKeyBlob {
            v,
            private: ByteBuf::from(private),
            public: ByteBuf::from(public),
        })
        .unwrap()
    }

    #[test]
    fn relay_contract_noise_keystore_account_is_stable_namespaced_and_versioned() {
        assert_eq!(
            RelayStreamNoiseKeyStore::account_for_key_id(DEFAULT_RELAY_STREAM_NOISE_KEY_ID)
                .unwrap(),
            "claw-share/relay-stream/noise-static-x25519/v1/engine"
        );
        assert!(matches!(
            RelayStreamNoiseKeyStore::account_for_key_id("../engine"),
            Err(RelayStreamNoiseKeyStoreError::InvalidKeyId)
        ));
    }

    #[test]
    fn relay_contract_noise_keystore_get_or_create_persists_and_reuses_key() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir);
        let store = RelayStreamNoiseKeyStore::new(&backend);
        let first = store
            .get_or_create(DEFAULT_RELAY_STREAM_NOISE_KEY_ID)
            .unwrap();
        let account =
            RelayStreamNoiseKeyStore::account_for_key_id(DEFAULT_RELAY_STREAM_NOISE_KEY_ID)
                .unwrap();

        let persisted = backend.get(&account).unwrap();
        assert!(!persisted.is_empty());

        let second = store
            .get_or_create(DEFAULT_RELAY_STREAM_NOISE_KEY_ID)
            .unwrap();
        assert_eq!(first.public_key(), second.public_key());
    }

    #[test]
    fn relay_contract_noise_keystore_rejects_bad_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir);
        let account = RelayStreamNoiseKeyStore::account_for_key_id("engine").unwrap();

        backend
            .set(&account, &blob(2, vec![0x11; 32], vec![0x22; 32]))
            .unwrap();
        assert!(matches!(
            RelayStreamNoiseKeyStore::new(&backend).get_or_create("engine"),
            Err(RelayStreamNoiseKeyStoreError::VersionUnsupported(2))
        ));

        backend
            .set(&account, &blob(1, vec![0x11; 31], vec![0x22; 32]))
            .unwrap();
        assert!(matches!(
            RelayStreamNoiseKeyStore::new(&backend).get_or_create("engine"),
            Err(RelayStreamNoiseKeyStoreError::Noise(
                RelayStreamNoiseError::StaticPrivateKeyMalformed { actual: 31 }
            ))
        ));

        backend
            .set(&account, &blob(1, vec![0x11; 32], vec![0x22; 31]))
            .unwrap();
        assert!(matches!(
            RelayStreamNoiseKeyStore::new(&backend).get_or_create("engine"),
            Err(RelayStreamNoiseKeyStoreError::Contract(
                RelayStreamContractError::StaticKeyMalformed { actual: 31 }
            ))
        ));

        backend.set(&account, b"not-cbor").unwrap();
        assert!(matches!(
            RelayStreamNoiseKeyStore::new(&backend).get_or_create("engine"),
            Err(RelayStreamNoiseKeyStoreError::Cbor(_))
        ));
    }

    #[test]
    fn relay_contract_noise_keystore_loaded_private_key_completes_handshake() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir);
        let store = RelayStreamNoiseKeyStore::new(&backend);
        let keypair = store
            .get_or_create(DEFAULT_RELAY_STREAM_NOISE_KEY_ID)
            .unwrap();
        let offer = signed_offer(keypair.public_key().clone());

        let mut initiator =
            RelayStreamNoiseInitiator::new(&offer, &owner_pub(), &guest_pub(), NOW).unwrap();
        let prologue = offer
            .to_noise_prologue_owner_verified(&owner_pub(), NOW)
            .unwrap();
        let mut responder =
            RelayStreamNoiseResponder::new(&prologue, keypair.private_key()).unwrap();
        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();
        let (msg2, mut responder_session) = responder.write_message_2().unwrap();
        let mut initiator_session = initiator.read_message_2(&msg2).unwrap();

        let ciphertext = initiator_session
            .encrypt(b"secret-through-keystore")
            .unwrap();
        assert_eq!(
            responder_session.decrypt(&ciphertext).unwrap(),
            b"secret-through-keystore"
        );
    }

    #[test]
    fn relay_contract_noise_keystore_debug_redacts_key_material() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir);
        let store = RelayStreamNoiseKeyStore::new(&backend);
        let keypair = store
            .get_or_create(DEFAULT_RELAY_STREAM_NOISE_KEY_ID)
            .unwrap();

        let debug_store = format!("{store:?}");
        let debug_keypair = format!("{keypair:?}");
        let private_hex = hex::encode(keypair.private_key().as_bytes());
        let public_hex = hex::encode(keypair.public_key().as_bytes());
        assert!(debug_store.contains("redacted"));
        assert!(debug_keypair.contains("redacted"));
        assert!(!debug_store.contains("secret-through-keystore"));
        assert!(!debug_keypair.contains("secret-through-keystore"));
        assert!(!debug_store.contains(&private_hex));
        assert!(!debug_keypair.contains(&private_hex));
        assert!(!debug_store.contains(&public_hex));
        assert!(!debug_keypair.contains(&public_hex));
    }
}
