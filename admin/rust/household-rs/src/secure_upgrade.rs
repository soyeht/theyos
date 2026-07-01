//! Canonical transcript for the Secure/Upgrade with iPhone proof ceremony.
//!
//! This module is intentionally inert. It pins and verifies proof bytes for a
//! future ceremony, but it does not mint strong owner provenance or enable any
//! fan-out gate.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

use crate::error::{HouseholdError, KeystoreError};
use crate::ids::HouseholdId;
use crate::keys::{IdentityKey, P256PublicKey, P256Signature, verify_signature};
use crate::machine_cert::PersonId;
use crate::person_cert::{PersonCert, SignOwnerOptions, VerifiedOwnerProvenance, derive_person_id};

pub const SECURE_UPGRADE_TRANSCRIPT_VERSION: u8 = 1;
pub const SECURE_UPGRADE_APP_ATTEST_REPLAY_RECORD_VERSION: u8 = 1;
pub const SECURE_UPGRADE_TRANSCRIPT_PURPOSE: &str = "secure-upgrade-owner";
pub const SECURE_UPGRADE_TRANSCRIPT_DOMAIN: &[u8] = b"soyeht-secure-upgrade-v1\0";
pub const SECURE_UPGRADE_APP_ATTEST_FORMAT: &str = "apple-appattest";
pub const SECURE_UPGRADE_APP_ATTEST_ROOT_CA_SHA256: [u8; 32] = [
    0x1c, 0xb9, 0x82, 0x3b, 0xa2, 0x8b, 0xa6, 0xad, 0x2d, 0x33, 0xa0, 0x06, 0x94, 0x1d, 0xe2, 0xae,
    0x4f, 0x51, 0x3e, 0xf1, 0xd4, 0xe8, 0x31, 0xb9, 0xf7, 0xe0, 0xfa, 0x7b, 0x62, 0x42, 0xc9, 0x32,
];
const SECURE_UPGRADE_MAX_OUTSTANDING_CHALLENGES: usize = 16_384;
const APP_ATTEST_AUTH_DATA_PREFIX_LEN: usize = 37;
const APP_ATTEST_AAGUID_LEN: usize = 16;
const APP_ATTEST_CREDENTIAL_ID_LEN_LEN: usize = 2;
const APP_ATTEST_NONCE_EXTENSION_PREFIX: &[u8] = &[0x30, 0x24, 0xa1, 0x22, 0x04, 0x20];
const APP_ATTEST_NONCE_EXTENSION_OID_COMPONENTS: &[u64] = &[1, 2, 840, 113635, 100, 8, 2];
const APP_ATTEST_AAGUID_DEVELOPMENT: &[u8; 16] = b"appattestdevelop";
const APP_ATTEST_AAGUID_PRODUCTION: &[u8; 16] = b"appattest\0\0\0\0\0\0\0";
static SECURE_UPGRADE_REPLAY_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
const SECURE_UPGRADE_APP_ATTEST_ROOT_CA_DER_B64: &str = concat!(
    "MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1B",
    "cHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UE",
    "CAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMM",
    "HUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYD",
    "VQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dy",
    "ctdhNbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEv",
    "Rq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSskRBT",
    "M72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByv",
    "siVbpTKwSga0kP0e8EeDS4+sQmTvb7vn53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3",
    "VcE3iexZZtKeYnpqtijVoyFraWVIyd/dganmrduC1bmTBGwD"
);

#[derive(Debug, Error)]
pub enum SecureUpgradeTranscriptError {
    #[error("unsupported secure-upgrade transcript version: {0}")]
    UnsupportedVersion(u8),
    #[error("secure-upgrade transcript purpose mismatch: {0}")]
    PurposeMismatch(String),
    #[error("secure-upgrade transcript expires before it is issued")]
    InvalidTimeWindow,
    #[error("secure-upgrade transcript field is invalid: {0}")]
    InvalidField(&'static str),
    #[error("secure-upgrade transcript target provenance does not match platform")]
    ProvenancePlatformMismatch,
    #[error("secure-upgrade transcript is not canonical CBOR")]
    NonCanonical,
    #[error("secure-upgrade transcript CBOR error: {0}")]
    Cbor(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecureUpgradeCommitmentError {
    #[error("secure-upgrade App Attest clientDataHash does not match challenge digest")]
    ClientDataHashMismatch,
    #[error("secure-upgrade owner signature input does not match challenge digest")]
    OwnerSignatureInputMismatch,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecureUpgradeChallengeStoreError {
    #[error("secure-upgrade challenge store is full")]
    StoreFull,
    #[error("secure-upgrade challenge already exists")]
    DuplicateChallenge,
    #[error("secure-upgrade challenge not found")]
    ChallengeNotFound,
    #[error("secure-upgrade challenge expired")]
    ChallengeExpired,
    #[error("secure-upgrade challenge id does not match stored transcript")]
    ChallengeIdMismatch,
    #[error("secure-upgrade challenge transcript does not match stored transcript")]
    TranscriptMismatch,
    #[error("secure-upgrade transcript error: {0}")]
    Transcript(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecureUpgradeAppAttestError {
    #[error("secure-upgrade transcript error: {0}")]
    Transcript(String),
    #[error("secure-upgrade App Attest CBOR error: {0}")]
    Cbor(String),
    #[error("secure-upgrade App Attest object is not a CBOR map")]
    TopLevelNotMap,
    #[error("secure-upgrade App Attest field is missing: {0}")]
    MissingField(&'static str),
    #[error("secure-upgrade App Attest field is duplicated: {0}")]
    DuplicateField(&'static str),
    #[error("secure-upgrade App Attest field is invalid: {0}")]
    InvalidField(&'static str),
    #[error("unsupported secure-upgrade App Attest format: {0}")]
    UnsupportedFormat(String),
    #[error("secure-upgrade App Attest authData is too short")]
    AuthDataTooShort,
    #[error("secure-upgrade App Attest authData lacks attested credential data")]
    MissingAttestedCredentialData,
    #[error("secure-upgrade App Attest credential id extends past authData")]
    CredentialIdOutOfBounds,
    #[error("secure-upgrade App Attest certificate chain is missing")]
    MissingCertificateChain,
    #[error("secure-upgrade App Attest nonce does not bind the challenge digest")]
    CertificateNonceMismatch,
    #[error("secure-upgrade App Attest rpIdHash does not match app identifier")]
    AppIdentifierHashMismatch,
    #[error("secure-upgrade App Attest X.509 chain verification is not implemented")]
    ChainVerificationUnavailable,
    #[error("secure-upgrade App Attest root certificate cannot be decoded")]
    RootCertificateDecode,
    #[error("secure-upgrade App Attest root certificate pin mismatch")]
    RootCertificatePinMismatch,
    #[error("secure-upgrade App Attest certificate parse error: {0}")]
    CertificateParse(String),
    #[error("secure-upgrade App Attest certificate chain verification failed: {0}")]
    CertificateChain(String),
    #[error("secure-upgrade App Attest certificate is not valid at verification time")]
    CertificateNotValidAtVerificationTime,
    #[error("secure-upgrade App Attest nonce certificate extension is missing")]
    CertificateNonceExtensionMissing,
    #[error("secure-upgrade App Attest nonce certificate extension is invalid")]
    CertificateNonceExtensionInvalid,
    #[error("secure-upgrade App Attest proof key id is invalid")]
    ProofKeyIdInvalid,
    #[error("secure-upgrade App Attest proof key id does not match leaf public key")]
    ProofKeyIdMismatch,
    #[error("secure-upgrade App Attest credential id does not match leaf public key")]
    CredentialIdMismatch,
    #[error("secure-upgrade App Attest attestation counter is not zero")]
    AttestationCounterMismatch,
    #[error("secure-upgrade App Attest AAGUID does not match proof environment")]
    AaguidEnvironmentMismatch,
    #[error("secure-upgrade App Attest leaf public key is unsupported")]
    UnsupportedPublicKey,
    #[error("secure-upgrade App Attest verification time is invalid")]
    InvalidVerificationTime,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecureUpgradeOwnerSignatureError {
    #[error("secure-upgrade transcript error: {0}")]
    Transcript(String),
    #[error("secure-upgrade owner key id does not match stored owner key")]
    OwnerKeyIdMismatch,
    #[error("secure-upgrade owner signature is not valid for challenge digest")]
    SignatureRejected,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecureUpgradeProofVerificationError {
    #[error("secure-upgrade App Attest verification failed: {0}")]
    AppAttest(#[from] SecureUpgradeAppAttestError),
    #[error("secure-upgrade owner signature verification failed: {0}")]
    OwnerSignature(#[from] SecureUpgradeOwnerSignatureError),
    #[error("secure-upgrade App Attest proof is not bound to the stored challenge digest")]
    AppAttestChallengeDigestMismatch,
    #[error("secure-upgrade owner signature is not bound to the stored challenge digest")]
    OwnerSignatureChallengeDigestMismatch,
    #[error("secure-upgrade proof result is not bound to the stored challenge digest")]
    ProofChallengeDigestMismatch,
    #[error("secure-upgrade owner signature key id does not match the stored challenge scope")]
    OwnerKeyIdMismatch,
    #[error("secure-upgrade target provenance does not match the stored challenge scope")]
    TargetProvenanceMismatch,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecureUpgradeAppAttestReplayError {
    #[error("secure-upgrade proof verification failed before replay recording: {0}")]
    Proof(#[from] SecureUpgradeProofVerificationError),
    #[error("secure-upgrade App Attest proof replayed a stored challenge digest")]
    AttestationChallengeReplay,
    #[error("secure-upgrade App Attest proof key is already recorded")]
    DuplicateProofKey,
    #[error("secure-upgrade App Attest proof key was reused for a different scope")]
    ProofKeyScopeMismatch,
    #[error("secure-upgrade App Attest proof key material changed")]
    ProofKeyMaterialMismatch,
    #[error("secure-upgrade App Attest attestation counter is not zero")]
    AttestationCounterMismatch,
    #[error("secure-upgrade App Attest replay record version is unsupported: {0}")]
    UnsupportedRecordVersion(u8),
    #[error("secure-upgrade App Attest replay record proof key does not match its storage key")]
    PersistedProofKeyMismatch,
    #[error("secure-upgrade App Attest replay storage IO error: {0}")]
    StorageIo(String),
    #[error("secure-upgrade App Attest replay storage JSON error: {0}")]
    StorageJson(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecureUpgradeCeremonyVerificationError {
    #[error("secure-upgrade challenge consume failed: {0}")]
    Challenge(#[from] SecureUpgradeChallengeStoreError),
    #[error("secure-upgrade proof verification failed: {0}")]
    Proof(#[from] SecureUpgradeProofVerificationError),
    #[error("secure-upgrade App Attest replay record failed: {0}")]
    Replay(#[from] SecureUpgradeAppAttestReplayError),
}

#[derive(Debug, Error)]
pub enum SecureUpgradeOwnerCertMintError {
    #[error("secure-upgrade owner cert mint household id does not match the verified ceremony")]
    HouseholdIdMismatch,
    #[error("secure-upgrade owner cert mint owner person id does not match the verified ceremony")]
    OwnerPersonIdMismatch,
    #[error(
        "secure-upgrade owner cert mint public key does not match the verified owner signature"
    )]
    OwnerPublicKeyMismatch,
    #[error("secure-upgrade owner cert signing failed: {0}")]
    Sign(#[from] KeystoreError),
}

impl From<HouseholdError> for SecureUpgradeTranscriptError {
    fn from(value: HouseholdError) -> Self {
        Self::Cbor(value.to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecureUpgradeOperation {
    SecureUpgradeWithIphone,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecureUpgradeProofModel {
    AppAttest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecureUpgradeProofEnvironment {
    Development,
    Production,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecureUpgradePlatform {
    #[serde(rename = "ios")]
    Ios,
    #[serde(rename = "ipados")]
    IpadOs,
}

impl SecureUpgradePlatform {
    #[must_use]
    pub fn app_attest_provenance(self) -> &'static str {
        match self {
            Self::Ios => PersonCert::OWNER_PROVENANCE_IOS_APP_ATTEST_OWNER,
            Self::IpadOs => PersonCert::OWNER_PROVENANCE_IPADOS_APP_ATTEST_OWNER,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecureUpgradeProofCommitments {
    pub client_data_hash: [u8; 32],
    pub owner_signature_input: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecureUpgradeCommitmentVerification {
    challenge_digest: [u8; 32],
}

impl SecureUpgradeCommitmentVerification {
    #[must_use]
    pub fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureUpgradeAppAttestObject {
    fmt: String,
    auth_data: Vec<u8>,
    rp_id_hash: [u8; 32],
    flags: u8,
    counter: u32,
    aaguid: [u8; 16],
    credential_id: Vec<u8>,
    credential_public_key_cose: Vec<u8>,
    x5c: Vec<Vec<u8>>,
    receipt: Option<Vec<u8>>,
}

impl SecureUpgradeAppAttestObject {
    pub fn parse(attestation_object_cbor: &[u8]) -> Result<Self, SecureUpgradeAppAttestError> {
        let value: ciborium::value::Value = ciborium::de::from_reader(attestation_object_cbor)
            .map_err(|e| SecureUpgradeAppAttestError::Cbor(e.to_string()))?;
        let ciborium::value::Value::Map(entries) = value else {
            return Err(SecureUpgradeAppAttestError::TopLevelNotMap);
        };
        let fmt = required_text_field(&entries, "fmt")?;
        if fmt != SECURE_UPGRADE_APP_ATTEST_FORMAT {
            return Err(SecureUpgradeAppAttestError::UnsupportedFormat(fmt));
        }
        let auth_data = required_bytes_field(&entries, "authData")?;
        let att_stmt = required_map_field(&entries, "attStmt")?;
        let x5c = required_x5c(att_stmt)?;
        let receipt = optional_bytes_field(att_stmt, "receipt")?;
        let parsed_auth = ParsedAppAttestAuthData::parse(&auth_data)?;

        Ok(Self {
            fmt,
            auth_data,
            rp_id_hash: parsed_auth.rp_id_hash,
            flags: parsed_auth.flags,
            counter: parsed_auth.counter,
            aaguid: parsed_auth.aaguid,
            credential_id: parsed_auth.credential_id,
            credential_public_key_cose: parsed_auth.credential_public_key_cose,
            x5c,
            receipt,
        })
    }

    #[must_use]
    pub fn fmt(&self) -> &str {
        &self.fmt
    }

    #[must_use]
    pub fn auth_data(&self) -> &[u8] {
        &self.auth_data
    }

    #[must_use]
    pub fn rp_id_hash(&self) -> [u8; 32] {
        self.rp_id_hash
    }

    #[must_use]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    #[must_use]
    pub fn counter(&self) -> u32 {
        self.counter
    }

    #[must_use]
    pub fn aaguid(&self) -> [u8; 16] {
        self.aaguid
    }

    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    #[must_use]
    pub fn credential_public_key_cose(&self) -> &[u8] {
        &self.credential_public_key_cose
    }

    #[must_use]
    pub fn x5c(&self) -> &[Vec<u8>] {
        &self.x5c
    }

    #[must_use]
    pub fn receipt(&self) -> Option<&[u8]> {
        self.receipt.as_deref()
    }

    #[must_use]
    pub fn expected_nonce(&self, challenge_digest: [u8; 32]) -> [u8; 32] {
        app_attest_nonce(self.auth_data(), challenge_digest)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureUpgradeAppAttestCommitmentBindings {
    challenge_digest: [u8; 32],
    app_identifier_hash: [u8; 32],
    certificate_nonce: [u8; 32],
    attestation_object: SecureUpgradeAppAttestObject,
}

impl SecureUpgradeAppAttestCommitmentBindings {
    #[must_use]
    pub fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }

    #[must_use]
    pub fn app_identifier_hash(&self) -> [u8; 32] {
        self.app_identifier_hash
    }

    #[must_use]
    pub fn certificate_nonce(&self) -> [u8; 32] {
        self.certificate_nonce
    }

    #[must_use]
    pub fn attestation_object(&self) -> &SecureUpgradeAppAttestObject {
        &self.attestation_object
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureUpgradeAppAttestVerification {
    bindings: SecureUpgradeAppAttestCommitmentBindings,
    proof_key_id_hash: [u8; 32],
    leaf_public_key_sha256: [u8; 32],
    root_ca_sha256: [u8; 32],
    leaf_not_before_unix: i64,
    leaf_not_after_unix: i64,
}

impl SecureUpgradeAppAttestVerification {
    #[must_use]
    pub fn bindings(&self) -> &SecureUpgradeAppAttestCommitmentBindings {
        &self.bindings
    }

    #[must_use]
    pub fn proof_key_id_hash(&self) -> [u8; 32] {
        self.proof_key_id_hash
    }

    #[must_use]
    pub fn leaf_public_key_sha256(&self) -> [u8; 32] {
        self.leaf_public_key_sha256
    }

    #[must_use]
    pub fn root_ca_sha256(&self) -> [u8; 32] {
        self.root_ca_sha256
    }

    #[must_use]
    pub fn leaf_not_before_unix(&self) -> i64 {
        self.leaf_not_before_unix
    }

    #[must_use]
    pub fn leaf_not_after_unix(&self) -> i64 {
        self.leaf_not_after_unix
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureUpgradeOwnerSignatureVerification {
    challenge_digest: [u8; 32],
    owner_key_id: String,
    owner_public_key: P256PublicKey,
}

impl SecureUpgradeOwnerSignatureVerification {
    #[must_use]
    pub fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }

    #[must_use]
    pub fn owner_key_id(&self) -> &str {
        &self.owner_key_id
    }

    #[must_use]
    pub fn owner_public_key(&self) -> &P256PublicKey {
        &self.owner_public_key
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SecureUpgradeProofVerificationInput<'a> {
    pub attestation_object_cbor: &'a [u8],
    pub owner_public_key: &'a P256PublicKey,
    pub owner_signature: &'a P256Signature,
    pub now_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureUpgradeProofVerification {
    challenge_digest: [u8; 32],
    app_attest: SecureUpgradeAppAttestVerification,
    owner_signature: SecureUpgradeOwnerSignatureVerification,
}

impl SecureUpgradeProofVerification {
    #[must_use]
    pub fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }

    #[must_use]
    pub fn app_attest(&self) -> &SecureUpgradeAppAttestVerification {
        &self.app_attest
    }

    #[must_use]
    pub fn owner_signature(&self) -> &SecureUpgradeOwnerSignatureVerification {
        &self.owner_signature
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureUpgradeVerifiedOwnerProvenance {
    challenge_digest: [u8; 32],
    owner_provenance: VerifiedOwnerProvenance,
}

impl SecureUpgradeVerifiedOwnerProvenance {
    #[must_use]
    pub fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }

    #[must_use]
    pub fn owner_provenance(&self) -> VerifiedOwnerProvenance {
        self.owner_provenance
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureUpgradeCeremonyVerification {
    challenge_record: SecureUpgradeChallengeRecord,
    proof: SecureUpgradeProofVerification,
    replay_record: SecureUpgradeAppAttestReplayRecord,
    verified_owner_provenance: SecureUpgradeVerifiedOwnerProvenance,
}

impl SecureUpgradeCeremonyVerification {
    #[must_use]
    pub fn challenge_record(&self) -> &SecureUpgradeChallengeRecord {
        &self.challenge_record
    }

    #[must_use]
    pub fn proof(&self) -> &SecureUpgradeProofVerification {
        &self.proof
    }

    #[must_use]
    pub fn replay_record(&self) -> &SecureUpgradeAppAttestReplayRecord {
        &self.replay_record
    }

    #[must_use]
    pub fn verified_owner_provenance(&self) -> &SecureUpgradeVerifiedOwnerProvenance {
        &self.verified_owner_provenance
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureUpgradeChallengeScope {
    pub hh_id: HouseholdId,
    pub owner_p_id: PersonId,
    pub owner_key_id: String,
    pub challenge_id: String,
    pub op: SecureUpgradeOperation,
    pub app_team_id: String,
    pub app_bundle_id: String,
    pub proof_model: SecureUpgradeProofModel,
    pub proof_key_id: String,
    pub proof_environment: SecureUpgradeProofEnvironment,
    pub platform: SecureUpgradePlatform,
    pub target_provenance: String,
}

impl SecureUpgradeChallengeScope {
    fn from_transcript(transcript: &SecureUpgradeTranscript) -> Self {
        Self {
            hh_id: transcript.hh_id.clone(),
            owner_p_id: transcript.owner_p_id.clone(),
            owner_key_id: transcript.owner_key_id.clone(),
            challenge_id: transcript.challenge_id.clone(),
            op: transcript.op,
            app_team_id: transcript.app_team_id.clone(),
            app_bundle_id: transcript.app_bundle_id.clone(),
            proof_model: transcript.proof_model,
            proof_key_id: transcript.proof_key_id.clone(),
            proof_environment: transcript.proof_environment,
            platform: transcript.platform,
            target_provenance: transcript.target_provenance.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureUpgradeAppAttestReplayRecord {
    #[serde(rename = "v")]
    version: u8,
    scope: SecureUpgradeChallengeScope,
    challenge_digest: [u8; 32],
    proof_key_id_hash: [u8; 32],
    leaf_public_key_sha256: [u8; 32],
    root_ca_sha256: [u8; 32],
    attestation_counter: u32,
    record_issued_at_unix: u64,
}

impl SecureUpgradeAppAttestReplayRecord {
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    #[must_use]
    pub fn scope(&self) -> &SecureUpgradeChallengeScope {
        &self.scope
    }

    #[must_use]
    pub fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }

    #[must_use]
    pub fn proof_key_id_hash(&self) -> [u8; 32] {
        self.proof_key_id_hash
    }

    #[must_use]
    pub fn leaf_public_key_sha256(&self) -> [u8; 32] {
        self.leaf_public_key_sha256
    }

    #[must_use]
    pub fn root_ca_sha256(&self) -> [u8; 32] {
        self.root_ca_sha256
    }

    #[must_use]
    pub fn attestation_counter(&self) -> u32 {
        self.attestation_counter
    }

    #[must_use]
    pub fn record_issued_at_unix(&self) -> u64 {
        self.record_issued_at_unix
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureUpgradeChallengeRecord {
    challenge_id: String,
    issued_at_unix: u64,
    expires_at_unix: u64,
    canonical_transcript_bytes: Vec<u8>,
    challenge_digest: [u8; 32],
    scope: SecureUpgradeChallengeScope,
}

impl SecureUpgradeChallengeRecord {
    #[must_use]
    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    #[must_use]
    pub fn issued_at_unix(&self) -> u64 {
        self.issued_at_unix
    }

    #[must_use]
    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    #[must_use]
    pub fn canonical_transcript_bytes(&self) -> &[u8] {
        &self.canonical_transcript_bytes
    }

    #[must_use]
    pub fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }

    #[must_use]
    pub fn scope(&self) -> &SecureUpgradeChallengeScope {
        &self.scope
    }
}

#[derive(Debug)]
pub struct SecureUpgradeAppAttestReplayStore {
    inner: Mutex<HashMap<[u8; 32], SecureUpgradeAppAttestReplayRecord>>,
}

impl Default for SecureUpgradeAppAttestReplayStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureUpgradeAppAttestReplayStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.lock_records().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn record_verified_attestation(
        &self,
        record: &SecureUpgradeChallengeRecord,
        proof: &SecureUpgradeProofVerification,
    ) -> Result<SecureUpgradeAppAttestReplayRecord, SecureUpgradeAppAttestReplayError> {
        let replay_record = verified_app_attest_replay_record(record, proof)?;

        let mut records = self.lock_records();
        if let Some(existing) = records.get(&replay_record.proof_key_id_hash) {
            return Err(classify_app_attest_replay_duplicate(
                existing,
                &replay_record,
            ));
        }
        records.insert(replay_record.proof_key_id_hash, replay_record.clone());
        Ok(replay_record)
    }

    fn lock_records(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], SecureUpgradeAppAttestReplayRecord>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Debug)]
pub struct SecureUpgradeDurableAppAttestReplayStore {
    dir: PathBuf,
    inner: Mutex<()>,
}

impl SecureUpgradeDurableAppAttestReplayStore {
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            inner: Mutex::new(()),
        }
    }

    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn record_verified_attestation(
        &self,
        record: &SecureUpgradeChallengeRecord,
        proof: &SecureUpgradeProofVerification,
    ) -> Result<SecureUpgradeAppAttestReplayRecord, SecureUpgradeAppAttestReplayError> {
        let replay_record = verified_app_attest_replay_record(record, proof)?;
        let _guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record_path = self.record_path(replay_record.proof_key_id_hash);
        if let Some(existing) =
            read_durable_app_attest_replay_record(&record_path, replay_record.proof_key_id_hash)?
        {
            return Err(classify_app_attest_replay_duplicate(
                &existing,
                &replay_record,
            ));
        }
        match write_durable_app_attest_replay_record_if_absent(&record_path, &replay_record)? {
            DurableReplayWriteResult::Written => Ok(replay_record),
            DurableReplayWriteResult::AlreadyExists => {
                let existing = read_durable_app_attest_replay_record(
                    &record_path,
                    replay_record.proof_key_id_hash,
                )?
                .ok_or_else(|| {
                    SecureUpgradeAppAttestReplayError::StorageIo(format!(
                        "durable replay record disappeared after existing-write race: {}",
                        record_path.display()
                    ))
                })?;
                Err(classify_app_attest_replay_duplicate(
                    &existing,
                    &replay_record,
                ))
            }
        }
    }

    fn record_path(&self, proof_key_id_hash: [u8; 32]) -> PathBuf {
        self.dir
            .join(format!("{}.json", hex::encode(proof_key_id_hash)))
    }
}

enum DurableReplayWriteResult {
    Written,
    AlreadyExists,
}

fn verified_app_attest_replay_record(
    record: &SecureUpgradeChallengeRecord,
    proof: &SecureUpgradeProofVerification,
) -> Result<SecureUpgradeAppAttestReplayRecord, SecureUpgradeAppAttestReplayError> {
    let expected_digest = SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
        record.canonical_transcript_bytes(),
    );
    if !bool::from(
        proof
            .challenge_digest
            .as_slice()
            .ct_eq(expected_digest.as_slice()),
    ) {
        return Err(SecureUpgradeAppAttestReplayError::Proof(
            SecureUpgradeProofVerificationError::ProofChallengeDigestMismatch,
        ));
    }
    let verified = verify_secure_upgrade_verified_proofs_for_challenge_record(
        record,
        proof.app_attest.clone(),
        proof.owner_signature.clone(),
    )?;
    let attestation_counter = verified
        .app_attest()
        .bindings()
        .attestation_object()
        .counter();
    if attestation_counter != 0 {
        return Err(SecureUpgradeAppAttestReplayError::AttestationCounterMismatch);
    }
    Ok(SecureUpgradeAppAttestReplayRecord {
        version: SECURE_UPGRADE_APP_ATTEST_REPLAY_RECORD_VERSION,
        scope: record.scope().clone(),
        challenge_digest: verified.challenge_digest(),
        proof_key_id_hash: verified.app_attest().proof_key_id_hash(),
        leaf_public_key_sha256: verified.app_attest().leaf_public_key_sha256(),
        root_ca_sha256: verified.app_attest().root_ca_sha256(),
        attestation_counter,
        record_issued_at_unix: record.issued_at_unix(),
    })
}

fn classify_app_attest_replay_duplicate(
    existing: &SecureUpgradeAppAttestReplayRecord,
    candidate: &SecureUpgradeAppAttestReplayRecord,
) -> SecureUpgradeAppAttestReplayError {
    if existing.version != SECURE_UPGRADE_APP_ATTEST_REPLAY_RECORD_VERSION {
        return SecureUpgradeAppAttestReplayError::UnsupportedRecordVersion(existing.version);
    }
    if !app_attest_replay_scope_matches(&existing.scope, &candidate.scope) {
        return SecureUpgradeAppAttestReplayError::ProofKeyScopeMismatch;
    }
    if existing.proof_key_id_hash != candidate.proof_key_id_hash
        || existing.leaf_public_key_sha256 != candidate.leaf_public_key_sha256
        || existing.root_ca_sha256 != candidate.root_ca_sha256
    {
        return SecureUpgradeAppAttestReplayError::ProofKeyMaterialMismatch;
    }
    if bool::from(
        existing
            .challenge_digest
            .as_slice()
            .ct_eq(candidate.challenge_digest.as_slice()),
    ) {
        return SecureUpgradeAppAttestReplayError::AttestationChallengeReplay;
    }
    SecureUpgradeAppAttestReplayError::DuplicateProofKey
}

fn read_durable_app_attest_replay_record(
    path: &Path,
    expected_proof_key_id_hash: [u8; 32],
) -> Result<Option<SecureUpgradeAppAttestReplayRecord>, SecureUpgradeAppAttestReplayError> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(SecureUpgradeAppAttestReplayError::StorageIo(format!(
                "read {}: {error}",
                path.display()
            )));
        }
    };
    let record: SecureUpgradeAppAttestReplayRecord =
        serde_json::from_str(&raw).map_err(|error| {
            SecureUpgradeAppAttestReplayError::StorageJson(format!(
                "parse {}: {error}",
                path.display()
            ))
        })?;
    if record.version != SECURE_UPGRADE_APP_ATTEST_REPLAY_RECORD_VERSION {
        return Err(SecureUpgradeAppAttestReplayError::UnsupportedRecordVersion(
            record.version,
        ));
    }
    if record.proof_key_id_hash != expected_proof_key_id_hash {
        return Err(SecureUpgradeAppAttestReplayError::PersistedProofKeyMismatch);
    }
    Ok(Some(record))
}

fn write_durable_app_attest_replay_record_if_absent(
    path: &Path,
    record: &SecureUpgradeAppAttestReplayRecord,
) -> Result<DurableReplayWriteResult, SecureUpgradeAppAttestReplayError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            SecureUpgradeAppAttestReplayError::StorageIo(format!(
                "create {}: {error}",
                parent.display()
            ))
        })?;
    }
    let tmp_path = durable_replay_tmp_path(path, record.challenge_digest);
    let json = serde_json::to_vec_pretty(record).map_err(|error| {
        SecureUpgradeAppAttestReplayError::StorageJson(format!("serialize replay record: {error}"))
    })?;
    {
        let mut tmp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|error| {
                SecureUpgradeAppAttestReplayError::StorageIo(format!(
                    "open tmp {}: {error}",
                    tmp_path.display()
                ))
            })?;
        tmp.write_all(&json).map_err(|error| {
            SecureUpgradeAppAttestReplayError::StorageIo(format!("write tmp: {error}"))
        })?;
        tmp.write_all(b"\n").map_err(|error| {
            SecureUpgradeAppAttestReplayError::StorageIo(format!("write tmp newline: {error}"))
        })?;
        tmp.sync_all().map_err(|error| {
            SecureUpgradeAppAttestReplayError::StorageIo(format!("fsync tmp: {error}"))
        })?;
    }
    let link_result = fs::hard_link(&tmp_path, path);
    let _ = fs::remove_file(&tmp_path);
    match link_result {
        Ok(()) => {
            sync_parent_dir(path)?;
            Ok(DurableReplayWriteResult::Written)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(DurableReplayWriteResult::AlreadyExists)
        }
        Err(error) => Err(SecureUpgradeAppAttestReplayError::StorageIo(format!(
            "link {} -> {}: {error}",
            tmp_path.display(),
            path.display()
        ))),
    }
}

fn durable_replay_tmp_path(path: &Path, challenge_digest: [u8; 32]) -> PathBuf {
    let counter = SECURE_UPGRADE_REPLAY_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!(
        "{}.tmp.{}.{}.{}",
        path.display(),
        std::process::id(),
        counter,
        hex::encode(challenge_digest)
    ))
}

fn sync_parent_dir(path: &Path) -> Result<(), SecureUpgradeAppAttestReplayError> {
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| {
                SecureUpgradeAppAttestReplayError::StorageIo(format!(
                    "fsync dir {}: {error}",
                    parent.display()
                ))
            })?;
    }
    Ok(())
}

fn app_attest_replay_scope_matches(
    existing: &SecureUpgradeChallengeScope,
    candidate: &SecureUpgradeChallengeScope,
) -> bool {
    existing.hh_id == candidate.hh_id
        && existing.owner_p_id == candidate.owner_p_id
        && existing.owner_key_id == candidate.owner_key_id
        && existing.op == candidate.op
        && existing.app_team_id == candidate.app_team_id
        && existing.app_bundle_id == candidate.app_bundle_id
        && existing.proof_model == candidate.proof_model
        && existing.proof_key_id == candidate.proof_key_id
        && existing.proof_environment == candidate.proof_environment
        && existing.platform == candidate.platform
        && existing.target_provenance == candidate.target_provenance
}

#[derive(Debug)]
pub struct SecureUpgradeChallengeStore {
    inner: Mutex<HashMap<String, SecureUpgradeChallengeRecord>>,
}

impl Default for SecureUpgradeChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureUpgradeChallengeStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.lock_records().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn issue(
        &self,
        transcript: SecureUpgradeTranscript,
        now_unix: u64,
    ) -> Result<SecureUpgradeChallengeRecord, SecureUpgradeChallengeStoreError> {
        if now_unix > transcript.expires_at {
            return Err(SecureUpgradeChallengeStoreError::ChallengeExpired);
        }
        let record = SecureUpgradeChallengeRecord::from_transcript(transcript)?;
        let mut records = self.lock_records();
        Self::prune_expired(&mut records, now_unix);
        if records.len() >= SECURE_UPGRADE_MAX_OUTSTANDING_CHALLENGES {
            return Err(SecureUpgradeChallengeStoreError::StoreFull);
        }
        if records.contains_key(record.challenge_id()) {
            return Err(SecureUpgradeChallengeStoreError::DuplicateChallenge);
        }
        records.insert(record.challenge_id.clone(), record.clone());
        Ok(record)
    }

    pub fn consume_matching_transcript(
        &self,
        challenge_id: &str,
        submitted_canonical_transcript_bytes: &[u8],
        now_unix: u64,
    ) -> Result<SecureUpgradeChallengeRecord, SecureUpgradeChallengeStoreError> {
        let submitted =
            SecureUpgradeTranscript::from_canonical_bytes(submitted_canonical_transcript_bytes)
                .map_err(SecureUpgradeChallengeStoreError::from_transcript_error)?;
        if submitted.challenge_id != challenge_id {
            return Err(SecureUpgradeChallengeStoreError::ChallengeIdMismatch);
        }
        let submitted_scope = SecureUpgradeChallengeScope::from_transcript(&submitted);
        let submitted_digest =
            SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
                submitted_canonical_transcript_bytes,
            );

        let mut records = self.lock_records();
        let Some(expected) = records.get(challenge_id) else {
            return Err(SecureUpgradeChallengeStoreError::ChallengeNotFound);
        };
        if now_unix > expected.expires_at_unix {
            records.remove(challenge_id);
            return Err(SecureUpgradeChallengeStoreError::ChallengeExpired);
        }
        let expected_digest =
            SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
                expected.canonical_transcript_bytes(),
            );
        let digest_matches = bool::from(
            submitted_digest
                .as_slice()
                .ct_eq(expected_digest.as_slice()),
        );
        if !digest_matches
            || submitted_canonical_transcript_bytes != expected.canonical_transcript_bytes()
            || submitted_scope != expected.scope
        {
            return Err(SecureUpgradeChallengeStoreError::TranscriptMismatch);
        }
        records
            .remove(challenge_id)
            .ok_or(SecureUpgradeChallengeStoreError::ChallengeNotFound)
    }

    fn lock_records(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, SecureUpgradeChallengeRecord>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn prune_expired(records: &mut HashMap<String, SecureUpgradeChallengeRecord>, now_unix: u64) {
        records.retain(|_, record| now_unix <= record.expires_at_unix);
    }
}

impl SecureUpgradeChallengeRecord {
    fn from_transcript(
        transcript: SecureUpgradeTranscript,
    ) -> Result<Self, SecureUpgradeChallengeStoreError> {
        let canonical_transcript_bytes = transcript
            .to_canonical_bytes()
            .map_err(SecureUpgradeChallengeStoreError::from_transcript_error)?;
        let challenge_digest =
            SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
                &canonical_transcript_bytes,
            );
        Ok(Self {
            challenge_id: transcript.challenge_id.clone(),
            issued_at_unix: transcript.issued_at,
            expires_at_unix: transcript.expires_at,
            canonical_transcript_bytes,
            challenge_digest,
            scope: SecureUpgradeChallengeScope::from_transcript(&transcript),
        })
    }
}

impl SecureUpgradeChallengeStoreError {
    fn from_transcript_error(error: SecureUpgradeTranscriptError) -> Self {
        Self::Transcript(error.to_string())
    }
}

#[derive(Debug)]
struct ParsedAppAttestAuthData {
    rp_id_hash: [u8; 32],
    flags: u8,
    counter: u32,
    aaguid: [u8; 16],
    credential_id: Vec<u8>,
    credential_public_key_cose: Vec<u8>,
}

impl ParsedAppAttestAuthData {
    fn parse(auth_data: &[u8]) -> Result<Self, SecureUpgradeAppAttestError> {
        if auth_data.len() < APP_ATTEST_AUTH_DATA_PREFIX_LEN {
            return Err(SecureUpgradeAppAttestError::AuthDataTooShort);
        }
        let credential_len_offset = APP_ATTEST_AUTH_DATA_PREFIX_LEN + APP_ATTEST_AAGUID_LEN;
        let credential_id_offset = credential_len_offset + APP_ATTEST_CREDENTIAL_ID_LEN_LEN;
        if auth_data.len() < credential_id_offset {
            return Err(SecureUpgradeAppAttestError::MissingAttestedCredentialData);
        }
        let credential_id_len = u16::from_be_bytes([
            auth_data[credential_len_offset],
            auth_data[credential_len_offset + 1],
        ]) as usize;
        if credential_id_len == 0 {
            return Err(SecureUpgradeAppAttestError::InvalidField(
                "authData.credential_id",
            ));
        }
        let credential_id_end = credential_id_offset
            .checked_add(credential_id_len)
            .ok_or(SecureUpgradeAppAttestError::CredentialIdOutOfBounds)?;
        if auth_data.len() < credential_id_end {
            return Err(SecureUpgradeAppAttestError::CredentialIdOutOfBounds);
        }
        let credential_public_key_cose = auth_data[credential_id_end..].to_vec();
        if credential_public_key_cose.is_empty() {
            return Err(SecureUpgradeAppAttestError::InvalidField(
                "authData.credential_public_key_cose",
            ));
        }

        Ok(Self {
            rp_id_hash: auth_data[..32]
                .try_into()
                .expect("authData prefix contains rpIdHash"),
            flags: auth_data[32],
            counter: u32::from_be_bytes(
                auth_data[33..APP_ATTEST_AUTH_DATA_PREFIX_LEN]
                    .try_into()
                    .expect("authData prefix contains counter"),
            ),
            aaguid: auth_data[APP_ATTEST_AUTH_DATA_PREFIX_LEN..credential_len_offset]
                .try_into()
                .expect("authData contains AAGUID"),
            credential_id: auth_data[credential_id_offset..credential_id_end].to_vec(),
            credential_public_key_cose,
        })
    }
}

#[must_use]
pub fn app_attest_app_identifier_hash(app_team_id: &str, app_bundle_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(app_team_id.as_bytes());
    hasher.update(b".");
    hasher.update(app_bundle_id.as_bytes());
    hasher.finalize().into()
}

#[must_use]
pub fn app_attest_nonce(auth_data: &[u8], challenge_digest: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(auth_data);
    hasher.update(challenge_digest);
    hasher.finalize().into()
}

pub fn verify_app_attest_commitment_bindings(
    attestation_object_cbor: &[u8],
    challenge_digest: [u8; 32],
    app_team_id: &str,
    app_bundle_id: &str,
    certificate_nonce: [u8; 32],
) -> Result<SecureUpgradeAppAttestCommitmentBindings, SecureUpgradeAppAttestError> {
    let attestation_object = SecureUpgradeAppAttestObject::parse(attestation_object_cbor)?;
    let expected_nonce = attestation_object.expected_nonce(challenge_digest);
    if !bool::from(
        expected_nonce
            .as_slice()
            .ct_eq(certificate_nonce.as_slice()),
    ) {
        return Err(SecureUpgradeAppAttestError::CertificateNonceMismatch);
    }
    let app_identifier_hash = app_attest_app_identifier_hash(app_team_id, app_bundle_id);
    if !bool::from(
        attestation_object
            .rp_id_hash()
            .as_slice()
            .ct_eq(app_identifier_hash.as_slice()),
    ) {
        return Err(SecureUpgradeAppAttestError::AppIdentifierHashMismatch);
    }
    Ok(SecureUpgradeAppAttestCommitmentBindings {
        challenge_digest,
        app_identifier_hash,
        certificate_nonce,
        attestation_object,
    })
}

pub fn verify_app_attest_commitment_bindings_for_transcript(
    attestation_object_cbor: &[u8],
    canonical_transcript_bytes: &[u8],
    certificate_nonce: [u8; 32],
) -> Result<SecureUpgradeAppAttestCommitmentBindings, SecureUpgradeAppAttestError> {
    let transcript = SecureUpgradeTranscript::from_canonical_bytes(canonical_transcript_bytes)
        .map_err(|e| SecureUpgradeAppAttestError::Transcript(e.to_string()))?;
    let challenge_digest =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
            canonical_transcript_bytes,
        );
    verify_app_attest_commitment_bindings(
        attestation_object_cbor,
        challenge_digest,
        &transcript.app_team_id,
        &transcript.app_bundle_id,
        certificate_nonce,
    )
}

pub fn verify_app_attest_attestation(
    attestation_object_cbor: &[u8],
    challenge_digest: [u8; 32],
    app_team_id: &str,
    app_bundle_id: &str,
    proof_key_id: &str,
    proof_environment: SecureUpgradeProofEnvironment,
    now_unix: u64,
) -> Result<SecureUpgradeAppAttestVerification, SecureUpgradeAppAttestError> {
    let attestation_object = SecureUpgradeAppAttestObject::parse(attestation_object_cbor)?;
    verify_app_attest_attestation_object(
        attestation_object,
        challenge_digest,
        app_team_id,
        app_bundle_id,
        proof_key_id,
        proof_environment,
        now_unix,
    )
}

pub fn verify_app_attest_attestation_for_transcript(
    attestation_object_cbor: &[u8],
    canonical_transcript_bytes: &[u8],
    now_unix: u64,
) -> Result<SecureUpgradeAppAttestVerification, SecureUpgradeAppAttestError> {
    let transcript = SecureUpgradeTranscript::from_canonical_bytes(canonical_transcript_bytes)
        .map_err(|e| SecureUpgradeAppAttestError::Transcript(e.to_string()))?;
    let challenge_digest =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
            canonical_transcript_bytes,
        );
    verify_app_attest_attestation(
        attestation_object_cbor,
        challenge_digest,
        &transcript.app_team_id,
        &transcript.app_bundle_id,
        &transcript.proof_key_id,
        transcript.proof_environment,
        now_unix,
    )
}

pub fn verify_owner_signature_for_transcript(
    canonical_transcript_bytes: &[u8],
    expected_owner_key_id: &str,
    owner_public_key: &P256PublicKey,
    owner_signature: &P256Signature,
) -> Result<SecureUpgradeOwnerSignatureVerification, SecureUpgradeOwnerSignatureError> {
    let transcript = SecureUpgradeTranscript::from_canonical_bytes(canonical_transcript_bytes)
        .map_err(|e| SecureUpgradeOwnerSignatureError::Transcript(e.to_string()))?;
    if transcript.owner_key_id != expected_owner_key_id {
        return Err(SecureUpgradeOwnerSignatureError::OwnerKeyIdMismatch);
    }
    let challenge_digest =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
            canonical_transcript_bytes,
        );
    verify_signature(owner_public_key, &challenge_digest, owner_signature)
        .map_err(|_| SecureUpgradeOwnerSignatureError::SignatureRejected)?;
    Ok(SecureUpgradeOwnerSignatureVerification {
        challenge_digest,
        owner_key_id: transcript.owner_key_id,
        owner_public_key: owner_public_key.clone(),
    })
}

pub fn verify_secure_upgrade_proof_for_challenge_record(
    record: &SecureUpgradeChallengeRecord,
    input: SecureUpgradeProofVerificationInput<'_>,
) -> Result<SecureUpgradeProofVerification, SecureUpgradeProofVerificationError> {
    let app_attest = verify_app_attest_attestation_for_transcript(
        input.attestation_object_cbor,
        record.canonical_transcript_bytes(),
        input.now_unix,
    )?;
    let owner_signature = verify_owner_signature_for_transcript(
        record.canonical_transcript_bytes(),
        &record.scope().owner_key_id,
        input.owner_public_key,
        input.owner_signature,
    )?;
    verify_secure_upgrade_verified_proofs_for_challenge_record(record, app_attest, owner_signature)
}

pub fn verify_secure_upgrade_verified_proofs_for_challenge_record(
    record: &SecureUpgradeChallengeRecord,
    app_attest: SecureUpgradeAppAttestVerification,
    owner_signature: SecureUpgradeOwnerSignatureVerification,
) -> Result<SecureUpgradeProofVerification, SecureUpgradeProofVerificationError> {
    let expected_digest = SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
        record.canonical_transcript_bytes(),
    );
    if !bool::from(
        app_attest
            .bindings
            .challenge_digest
            .as_slice()
            .ct_eq(expected_digest.as_slice()),
    ) {
        return Err(SecureUpgradeProofVerificationError::AppAttestChallengeDigestMismatch);
    }
    if !bool::from(
        owner_signature
            .challenge_digest
            .as_slice()
            .ct_eq(expected_digest.as_slice()),
    ) {
        return Err(SecureUpgradeProofVerificationError::OwnerSignatureChallengeDigestMismatch);
    }
    if owner_signature.owner_key_id != record.scope().owner_key_id {
        return Err(SecureUpgradeProofVerificationError::OwnerKeyIdMismatch);
    }
    Ok(SecureUpgradeProofVerification {
        challenge_digest: expected_digest,
        app_attest,
        owner_signature,
    })
}

pub fn verified_owner_provenance_from_secure_upgrade_proof(
    record: &SecureUpgradeChallengeRecord,
    proof: &SecureUpgradeProofVerification,
) -> Result<SecureUpgradeVerifiedOwnerProvenance, SecureUpgradeProofVerificationError> {
    let expected_digest = SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
        record.canonical_transcript_bytes(),
    );
    if !bool::from(
        proof
            .challenge_digest
            .as_slice()
            .ct_eq(expected_digest.as_slice()),
    ) {
        return Err(SecureUpgradeProofVerificationError::ProofChallengeDigestMismatch);
    }
    let verified = verify_secure_upgrade_verified_proofs_for_challenge_record(
        record,
        proof.app_attest.clone(),
        proof.owner_signature.clone(),
    )?;
    let expected_target = record.scope().platform.app_attest_provenance();
    if record.scope().target_provenance != expected_target {
        return Err(SecureUpgradeProofVerificationError::TargetProvenanceMismatch);
    }
    let owner_provenance = match record.scope().platform {
        SecureUpgradePlatform::Ios => VerifiedOwnerProvenance::IosAppAttestOwner,
        SecureUpgradePlatform::IpadOs => VerifiedOwnerProvenance::IpadOsAppAttestOwner,
    };
    Ok(SecureUpgradeVerifiedOwnerProvenance {
        challenge_digest: verified.challenge_digest,
        owner_provenance,
    })
}

pub fn verify_secure_upgrade_ceremony_for_challenge(
    challenge_store: &SecureUpgradeChallengeStore,
    replay_store: &SecureUpgradeDurableAppAttestReplayStore,
    challenge_id: &str,
    submitted_canonical_transcript_bytes: &[u8],
    proof_input: SecureUpgradeProofVerificationInput<'_>,
) -> Result<SecureUpgradeCeremonyVerification, SecureUpgradeCeremonyVerificationError> {
    let record = challenge_store.consume_matching_transcript(
        challenge_id,
        submitted_canonical_transcript_bytes,
        proof_input.now_unix,
    )?;
    let proof = verify_secure_upgrade_proof_for_challenge_record(&record, proof_input)?;
    let replay_record = replay_store.record_verified_attestation(&record, &proof)?;
    let verified_owner_provenance =
        verified_owner_provenance_from_secure_upgrade_proof(&record, &proof)?;
    Ok(SecureUpgradeCeremonyVerification {
        challenge_record: record,
        proof,
        replay_record,
        verified_owner_provenance,
    })
}

pub fn sign_owner_cert_with_secure_upgrade_verification(
    hh_key: &dyn IdentityKey,
    opts: SignOwnerOptions,
    verification: &SecureUpgradeCeremonyVerification,
) -> Result<PersonCert, SecureUpgradeOwnerCertMintError> {
    let scope = verification.challenge_record().scope();
    if opts.hh_id != scope.hh_id {
        return Err(SecureUpgradeOwnerCertMintError::HouseholdIdMismatch);
    }
    let owner_p_id = derive_person_id(&opts.p_pub);
    if owner_p_id != scope.owner_p_id {
        return Err(SecureUpgradeOwnerCertMintError::OwnerPersonIdMismatch);
    }
    if &opts.p_pub != verification.proof().owner_signature().owner_public_key() {
        return Err(SecureUpgradeOwnerCertMintError::OwnerPublicKeyMismatch);
    }
    PersonCert::sign_owner_with_verified_provenance(
        hh_key,
        opts,
        verification.verified_owner_provenance().owner_provenance(),
    )
    .map_err(SecureUpgradeOwnerCertMintError::from)
}

#[cfg(test)]
fn verify_secure_upgrade_verified_ceremony_for_challenge(
    challenge_store: &SecureUpgradeChallengeStore,
    replay_store: &SecureUpgradeDurableAppAttestReplayStore,
    challenge_id: &str,
    submitted_canonical_transcript_bytes: &[u8],
    now_unix: u64,
    proof: SecureUpgradeProofVerification,
) -> Result<SecureUpgradeCeremonyVerification, SecureUpgradeCeremonyVerificationError> {
    let record = challenge_store.consume_matching_transcript(
        challenge_id,
        submitted_canonical_transcript_bytes,
        now_unix,
    )?;
    let replay_record = replay_store.record_verified_attestation(&record, &proof)?;
    let verified_owner_provenance =
        verified_owner_provenance_from_secure_upgrade_proof(&record, &proof)?;
    Ok(SecureUpgradeCeremonyVerification {
        challenge_record: record,
        proof,
        replay_record,
        verified_owner_provenance,
    })
}

pub fn app_attest_root_certificate_der() -> Result<Vec<u8>, SecureUpgradeAppAttestError> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(SECURE_UPGRADE_APP_ATTEST_ROOT_CA_DER_B64)
        .map_err(|_| SecureUpgradeAppAttestError::RootCertificateDecode)?;
    let digest: [u8; 32] = Sha256::digest(&der).into();
    if !bool::from(digest.ct_eq(&SECURE_UPGRADE_APP_ATTEST_ROOT_CA_SHA256)) {
        return Err(SecureUpgradeAppAttestError::RootCertificatePinMismatch);
    }
    Ok(der)
}

fn verify_app_attest_attestation_object(
    attestation_object: SecureUpgradeAppAttestObject,
    challenge_digest: [u8; 32],
    app_team_id: &str,
    app_bundle_id: &str,
    proof_key_id: &str,
    proof_environment: SecureUpgradeProofEnvironment,
    now_unix: u64,
) -> Result<SecureUpgradeAppAttestVerification, SecureUpgradeAppAttestError> {
    let leaf_der = attestation_object
        .x5c()
        .first()
        .cloned()
        .ok_or(SecureUpgradeAppAttestError::MissingCertificateChain)?;
    let leaf_cert = parse_x509_certificate(&leaf_der)?;
    let now_i64 = i64::try_from(now_unix)
        .map_err(|_| SecureUpgradeAppAttestError::InvalidVerificationTime)?;
    let now_asn1 = x509_parser::time::ASN1Time::from_timestamp(now_i64)
        .map_err(|_| SecureUpgradeAppAttestError::InvalidVerificationTime)?;
    if !leaf_cert.validity().is_valid_at(now_asn1) {
        return Err(SecureUpgradeAppAttestError::CertificateNotValidAtVerificationTime);
    }

    let certificate_nonce = app_attest_certificate_nonce(&leaf_cert)?;
    let bindings = verify_app_attest_commitment_bindings_for_object(
        attestation_object,
        challenge_digest,
        app_team_id,
        app_bundle_id,
        certificate_nonce,
    )?;
    verify_app_attest_auth_data_policy(&bindings.attestation_object, proof_environment)?;

    let public_key_sha256 = app_attest_leaf_public_key_sha256(&leaf_cert)?;
    let proof_key_id_hash = decode_app_attest_proof_key_id(proof_key_id)?;
    if !bool::from(proof_key_id_hash.ct_eq(&public_key_sha256)) {
        return Err(SecureUpgradeAppAttestError::ProofKeyIdMismatch);
    }
    let credential_id = bindings.attestation_object.credential_id();
    if credential_id.len() != public_key_sha256.len()
        || !bool::from(credential_id.ct_eq(proof_key_id_hash.as_slice()))
    {
        return Err(SecureUpgradeAppAttestError::CredentialIdMismatch);
    }

    verify_app_attest_certificate_chain(bindings.attestation_object.x5c(), now_unix)?;

    Ok(SecureUpgradeAppAttestVerification {
        bindings,
        proof_key_id_hash,
        leaf_public_key_sha256: public_key_sha256,
        root_ca_sha256: SECURE_UPGRADE_APP_ATTEST_ROOT_CA_SHA256,
        leaf_not_before_unix: leaf_cert.validity().not_before.timestamp(),
        leaf_not_after_unix: leaf_cert.validity().not_after.timestamp(),
    })
}

fn verify_app_attest_auth_data_policy(
    attestation_object: &SecureUpgradeAppAttestObject,
    proof_environment: SecureUpgradeProofEnvironment,
) -> Result<(), SecureUpgradeAppAttestError> {
    if attestation_object.counter() != 0 {
        return Err(SecureUpgradeAppAttestError::AttestationCounterMismatch);
    }
    let expected_aaguid = match proof_environment {
        SecureUpgradeProofEnvironment::Development => APP_ATTEST_AAGUID_DEVELOPMENT,
        SecureUpgradeProofEnvironment::Production => APP_ATTEST_AAGUID_PRODUCTION,
    };
    if !bool::from(attestation_object.aaguid().ct_eq(expected_aaguid)) {
        return Err(SecureUpgradeAppAttestError::AaguidEnvironmentMismatch);
    }
    Ok(())
}

fn verify_app_attest_commitment_bindings_for_object(
    attestation_object: SecureUpgradeAppAttestObject,
    challenge_digest: [u8; 32],
    app_team_id: &str,
    app_bundle_id: &str,
    certificate_nonce: [u8; 32],
) -> Result<SecureUpgradeAppAttestCommitmentBindings, SecureUpgradeAppAttestError> {
    let expected_nonce = attestation_object.expected_nonce(challenge_digest);
    if !bool::from(
        expected_nonce
            .as_slice()
            .ct_eq(certificate_nonce.as_slice()),
    ) {
        return Err(SecureUpgradeAppAttestError::CertificateNonceMismatch);
    }
    let app_identifier_hash = app_attest_app_identifier_hash(app_team_id, app_bundle_id);
    if !bool::from(
        attestation_object
            .rp_id_hash()
            .as_slice()
            .ct_eq(app_identifier_hash.as_slice()),
    ) {
        return Err(SecureUpgradeAppAttestError::AppIdentifierHashMismatch);
    }
    Ok(SecureUpgradeAppAttestCommitmentBindings {
        challenge_digest,
        app_identifier_hash,
        certificate_nonce,
        attestation_object,
    })
}

fn verify_app_attest_certificate_chain(
    x5c: &[Vec<u8>],
    now_unix: u64,
) -> Result<(), SecureUpgradeAppAttestError> {
    let leaf = x5c
        .first()
        .ok_or(SecureUpgradeAppAttestError::MissingCertificateChain)?;
    let root_der = app_attest_root_certificate_der()?;
    let root_cert = CertificateDer::from(root_der.as_slice());
    let trust_anchor = webpki::anchor_from_trusted_cert(&root_cert)
        .map_err(|e| SecureUpgradeAppAttestError::CertificateChain(e.to_string()))?;
    let leaf_cert_der = CertificateDer::from(leaf.as_slice());
    let leaf_cert = webpki::EndEntityCert::try_from(&leaf_cert_der)
        .map_err(|e| SecureUpgradeAppAttestError::CertificateChain(e.to_string()))?;
    let intermediates = x5c
        .iter()
        .skip(1)
        .map(|cert| CertificateDer::from(cert.as_slice()))
        .collect::<Vec<_>>();
    let verification_time = UnixTime::since_unix_epoch(Duration::from_secs(now_unix));
    leaf_cert
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[trust_anchor],
            &intermediates,
            verification_time,
            AppAttestLeafEkuParseOnly,
            None,
            None,
        )
        .map_err(|e| SecureUpgradeAppAttestError::CertificateChain(e.to_string()))?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct AppAttestLeafEkuParseOnly;

impl webpki::ExtendedKeyUsageValidator for AppAttestLeafEkuParseOnly {
    fn validate(&self, iter: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        // Apple App Attest leaf certs are discriminated by the dedicated
        // pinned root plus the strict nonce extension, app-id hash, AAGUID,
        // counter and key bindings above. App Attest is not a TLS usage, so
        // this validator only rejects malformed EKU encodings instead of
        // treating EKU as the proof-policy discriminator.
        for key_purpose in iter {
            key_purpose?;
        }
        Ok(())
    }
}

fn parse_x509_certificate(der: &[u8]) -> Result<X509Certificate<'_>, SecureUpgradeAppAttestError> {
    let (remaining, certificate) = X509Certificate::from_der(der)
        .map_err(|e| SecureUpgradeAppAttestError::CertificateParse(e.to_string()))?;
    if !remaining.is_empty() {
        return Err(SecureUpgradeAppAttestError::CertificateParse(
            "trailing certificate data".to_string(),
        ));
    }
    Ok(certificate)
}

fn app_attest_certificate_nonce(
    leaf_cert: &X509Certificate<'_>,
) -> Result<[u8; 32], SecureUpgradeAppAttestError> {
    let oid = x509_parser::oid_registry::Oid::from(APP_ATTEST_NONCE_EXTENSION_OID_COMPONENTS)
        .map_err(|_| SecureUpgradeAppAttestError::CertificateNonceExtensionInvalid)?;
    let extension = leaf_cert
        .get_extension_unique(&oid)
        .map_err(|_| SecureUpgradeAppAttestError::CertificateNonceExtensionInvalid)?
        .ok_or(SecureUpgradeAppAttestError::CertificateNonceExtensionMissing)?;
    parse_app_attest_nonce_extension(extension.value)
}

fn parse_app_attest_nonce_extension(
    extension_value: &[u8],
) -> Result<[u8; 32], SecureUpgradeAppAttestError> {
    if extension_value.len() != APP_ATTEST_NONCE_EXTENSION_PREFIX.len() + 32
        || !extension_value.starts_with(APP_ATTEST_NONCE_EXTENSION_PREFIX)
    {
        return Err(SecureUpgradeAppAttestError::CertificateNonceExtensionInvalid);
    }
    extension_value[APP_ATTEST_NONCE_EXTENSION_PREFIX.len()..]
        .try_into()
        .map_err(|_| SecureUpgradeAppAttestError::CertificateNonceExtensionInvalid)
}

fn app_attest_leaf_public_key_sha256(
    leaf_cert: &X509Certificate<'_>,
) -> Result<[u8; 32], SecureUpgradeAppAttestError> {
    let public_key = leaf_cert
        .public_key()
        .parsed()
        .map_err(|e| SecureUpgradeAppAttestError::CertificateParse(e.to_string()))?;
    let PublicKey::EC(point) = public_key else {
        return Err(SecureUpgradeAppAttestError::UnsupportedPublicKey);
    };
    Ok(Sha256::digest(point.data()).into())
}

fn decode_app_attest_proof_key_id(
    proof_key_id: &str,
) -> Result<[u8; 32], SecureUpgradeAppAttestError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(proof_key_id)
        .map_err(|_| SecureUpgradeAppAttestError::ProofKeyIdInvalid)?;
    decoded
        .try_into()
        .map_err(|_| SecureUpgradeAppAttestError::ProofKeyIdInvalid)
}

fn required_text_field(
    entries: &[(ciborium::value::Value, ciborium::value::Value)],
    field: &'static str,
) -> Result<String, SecureUpgradeAppAttestError> {
    match required_field(entries, field)? {
        ciborium::value::Value::Text(value) => Ok(value.clone()),
        _ => Err(SecureUpgradeAppAttestError::InvalidField(field)),
    }
}

fn required_bytes_field(
    entries: &[(ciborium::value::Value, ciborium::value::Value)],
    field: &'static str,
) -> Result<Vec<u8>, SecureUpgradeAppAttestError> {
    match required_field(entries, field)? {
        ciborium::value::Value::Bytes(value) => Ok(value.clone()),
        _ => Err(SecureUpgradeAppAttestError::InvalidField(field)),
    }
}

fn optional_bytes_field(
    entries: &[(ciborium::value::Value, ciborium::value::Value)],
    field: &'static str,
) -> Result<Option<Vec<u8>>, SecureUpgradeAppAttestError> {
    match optional_field(entries, field)? {
        Some(ciborium::value::Value::Bytes(value)) => Ok(Some(value.clone())),
        Some(_) => Err(SecureUpgradeAppAttestError::InvalidField(field)),
        None => Ok(None),
    }
}

fn required_map_field<'a>(
    entries: &'a [(ciborium::value::Value, ciborium::value::Value)],
    field: &'static str,
) -> Result<&'a [(ciborium::value::Value, ciborium::value::Value)], SecureUpgradeAppAttestError> {
    match required_field(entries, field)? {
        ciborium::value::Value::Map(value) => Ok(value.as_slice()),
        _ => Err(SecureUpgradeAppAttestError::InvalidField(field)),
    }
}

fn required_x5c(
    att_stmt: &[(ciborium::value::Value, ciborium::value::Value)],
) -> Result<Vec<Vec<u8>>, SecureUpgradeAppAttestError> {
    let ciborium::value::Value::Array(certs) = required_field(att_stmt, "x5c")? else {
        return Err(SecureUpgradeAppAttestError::InvalidField("x5c"));
    };
    if certs.is_empty() {
        return Err(SecureUpgradeAppAttestError::MissingCertificateChain);
    }
    certs
        .iter()
        .map(|cert| match cert {
            ciborium::value::Value::Bytes(bytes) if !bytes.is_empty() => Ok(bytes.clone()),
            _ => Err(SecureUpgradeAppAttestError::InvalidField("x5c")),
        })
        .collect()
}

fn required_field<'a>(
    entries: &'a [(ciborium::value::Value, ciborium::value::Value)],
    field: &'static str,
) -> Result<&'a ciborium::value::Value, SecureUpgradeAppAttestError> {
    optional_field(entries, field)?.ok_or(SecureUpgradeAppAttestError::MissingField(field))
}

fn optional_field<'a>(
    entries: &'a [(ciborium::value::Value, ciborium::value::Value)],
    field: &'static str,
) -> Result<Option<&'a ciborium::value::Value>, SecureUpgradeAppAttestError> {
    let mut found = None;
    for (key, value) in entries {
        if matches!(key, ciborium::value::Value::Text(text) if text == field) {
            if found.is_some() {
                return Err(SecureUpgradeAppAttestError::DuplicateField(field));
            }
            found = Some(value);
        }
    }
    Ok(found)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureUpgradeAppAttestTranscriptInput {
    pub hh_id: HouseholdId,
    pub owner_p_id: PersonId,
    pub owner_key_id: String,
    pub challenge_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub app_team_id: String,
    pub app_bundle_id: String,
    pub proof_key_id: String,
    pub proof_environment: SecureUpgradeProofEnvironment,
    pub platform: SecureUpgradePlatform,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecureUpgradeTranscript {
    #[serde(rename = "v")]
    pub version: u8,
    pub purpose: String,
    pub op: SecureUpgradeOperation,
    pub hh_id: HouseholdId,
    pub owner_p_id: PersonId,
    pub owner_key_id: String,
    pub challenge_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub app_team_id: String,
    pub app_bundle_id: String,
    pub proof_model: SecureUpgradeProofModel,
    pub proof_key_id: String,
    pub proof_environment: SecureUpgradeProofEnvironment,
    pub platform: SecureUpgradePlatform,
    pub target_provenance: String,
}

impl SecureUpgradeTranscript {
    #[must_use]
    pub fn app_attest(input: SecureUpgradeAppAttestTranscriptInput) -> Self {
        Self {
            version: SECURE_UPGRADE_TRANSCRIPT_VERSION,
            purpose: SECURE_UPGRADE_TRANSCRIPT_PURPOSE.to_string(),
            op: SecureUpgradeOperation::SecureUpgradeWithIphone,
            hh_id: input.hh_id,
            owner_p_id: input.owner_p_id,
            owner_key_id: input.owner_key_id,
            challenge_id: input.challenge_id,
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            app_team_id: input.app_team_id,
            app_bundle_id: input.app_bundle_id,
            proof_model: SecureUpgradeProofModel::AppAttest,
            proof_key_id: input.proof_key_id,
            proof_environment: input.proof_environment,
            platform: input.platform,
            target_provenance: input.platform.app_attest_provenance().to_string(),
        }
    }

    pub fn validate_shape(&self) -> Result<(), SecureUpgradeTranscriptError> {
        if self.version != SECURE_UPGRADE_TRANSCRIPT_VERSION {
            return Err(SecureUpgradeTranscriptError::UnsupportedVersion(
                self.version,
            ));
        }
        if self.purpose != SECURE_UPGRADE_TRANSCRIPT_PURPOSE {
            return Err(SecureUpgradeTranscriptError::PurposeMismatch(
                self.purpose.clone(),
            ));
        }
        if self.expires_at < self.issued_at {
            return Err(SecureUpgradeTranscriptError::InvalidTimeWindow);
        }
        for (field, value) in [
            ("owner_key_id", self.owner_key_id.as_str()),
            ("challenge_id", self.challenge_id.as_str()),
            ("app_team_id", self.app_team_id.as_str()),
            ("app_bundle_id", self.app_bundle_id.as_str()),
            ("proof_key_id", self.proof_key_id.as_str()),
        ] {
            if value.is_empty() {
                return Err(SecureUpgradeTranscriptError::InvalidField(field));
            }
        }
        if self.proof_model != SecureUpgradeProofModel::AppAttest {
            return Err(SecureUpgradeTranscriptError::InvalidField("proof_model"));
        }
        if self.target_provenance != self.platform.app_attest_provenance() {
            return Err(SecureUpgradeTranscriptError::ProvenancePlatformMismatch);
        }
        Ok(())
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, SecureUpgradeTranscriptError> {
        self.validate_shape()?;
        crate::cbor::to_canonical_vec(self).map_err(SecureUpgradeTranscriptError::from)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SecureUpgradeTranscriptError> {
        let decoded: Self = crate::cbor::from_canonical_slice(bytes)
            .map_err(|e| SecureUpgradeTranscriptError::Cbor(e.to_string()))?;
        let canonical = decoded.to_canonical_bytes()?;
        if canonical != bytes {
            return Err(SecureUpgradeTranscriptError::NonCanonical);
        }
        Ok(decoded)
    }

    #[must_use]
    pub fn challenge_digest_from_canonical_transcript_bytes(canonical: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(SECURE_UPGRADE_TRANSCRIPT_DOMAIN);
        hasher.update(canonical);
        hasher.finalize().into()
    }

    pub fn challenge_digest(&self) -> Result<[u8; 32], SecureUpgradeTranscriptError> {
        let canonical = self.to_canonical_bytes()?;
        Ok(Self::challenge_digest_from_canonical_transcript_bytes(
            &canonical,
        ))
    }

    pub fn app_attest_client_data_hash(&self) -> Result<[u8; 32], SecureUpgradeTranscriptError> {
        self.challenge_digest()
    }

    pub fn owner_signature_input(&self) -> Result<[u8; 32], SecureUpgradeTranscriptError> {
        self.challenge_digest()
    }

    pub fn verify_proof_commitments(
        canonical_transcript_bytes: &[u8],
        commitments: SecureUpgradeProofCommitments,
    ) -> Result<SecureUpgradeCommitmentVerification, SecureUpgradeCommitmentError> {
        let expected_digest =
            Self::challenge_digest_from_canonical_transcript_bytes(canonical_transcript_bytes);
        if !bool::from(
            commitments
                .client_data_hash
                .as_slice()
                .ct_eq(expected_digest.as_slice()),
        ) {
            return Err(SecureUpgradeCommitmentError::ClientDataHashMismatch);
        }
        if !bool::from(
            commitments
                .owner_signature_input
                .as_slice()
                .ct_eq(expected_digest.as_slice()),
        ) {
            return Err(SecureUpgradeCommitmentError::OwnerSignatureInputMismatch);
        }
        Ok(SecureUpgradeCommitmentVerification {
            challenge_digest: expected_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use ciborium::value::Value;

    use super::*;
    use crate::keys::{IdentityKey, P256Keypair};

    const TEAM_ID: &str = "TEAMID1234";
    const BUNDLE_ID: &str = "com.example.soyeht";
    const HH_ID: &str = "hh_fnlwza7qi4rxuadflfmxocnx5rwdb3ef2meq6unnh7qqiosfyain";
    const OWNER_P_ID: &str = "p_ty3yfdchyn7nethoiefhrolfjxavzfe2bngb4tzzqy7cl3uqjfcq";
    const OWNER_KEY_ID: &str = "owner-key-ios-alpha";
    const NOW: u64 = 1_714_972_800;

    struct SyntheticAttestation {
        attestation_object_cbor: Vec<u8>,
        certificate_nonce: [u8; 32],
    }

    fn transcript(
        challenge_id: &str,
        owner_key_id: &str,
        platform: SecureUpgradePlatform,
    ) -> SecureUpgradeTranscript {
        transcript_with_owner_person_id(
            challenge_id,
            owner_key_id,
            platform,
            PersonId(OWNER_P_ID.to_string()),
        )
    }

    fn transcript_with_owner_person_id(
        challenge_id: &str,
        owner_key_id: &str,
        platform: SecureUpgradePlatform,
        owner_p_id: PersonId,
    ) -> SecureUpgradeTranscript {
        SecureUpgradeTranscript::app_attest(SecureUpgradeAppAttestTranscriptInput {
            hh_id: HouseholdId::parse(HH_ID.to_string()).expect("fixture hh_id parses"),
            owner_p_id,
            owner_key_id: owner_key_id.to_string(),
            challenge_id: challenge_id.to_string(),
            issued_at: NOW,
            expires_at: NOW + 300,
            app_team_id: TEAM_ID.to_string(),
            app_bundle_id: BUNDLE_ID.to_string(),
            proof_key_id: "app-attest-proof-key-alpha".to_string(),
            proof_environment: SecureUpgradeProofEnvironment::Development,
            platform,
        })
    }

    fn challenge_record_for_owner_person_id(
        challenge_id: &str,
        owner_key_id: &str,
        platform: SecureUpgradePlatform,
        owner_p_id: PersonId,
    ) -> SecureUpgradeChallengeRecord {
        let store = SecureUpgradeChallengeStore::new();
        store
            .issue(
                transcript_with_owner_person_id(challenge_id, owner_key_id, platform, owner_p_id),
                NOW,
            )
            .unwrap()
    }

    fn challenge_record(
        challenge_id: &str,
        owner_key_id: &str,
        platform: SecureUpgradePlatform,
    ) -> SecureUpgradeChallengeRecord {
        let store = SecureUpgradeChallengeStore::new();
        store
            .issue(transcript(challenge_id, owner_key_id, platform), NOW)
            .unwrap()
    }

    fn synthetic_auth_data(challenge_digest: [u8; 32]) -> Vec<u8> {
        let credential_id = challenge_digest;
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&app_attest_app_identifier_hash(TEAM_ID, BUNDLE_ID));
        auth_data.push(0x41);
        auth_data.extend_from_slice(&0_u32.to_be_bytes());
        auth_data.extend_from_slice(APP_ATTEST_AAGUID_DEVELOPMENT);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&credential_id);
        auth_data.extend_from_slice(&[0xa5, 0x01, 0x02]);
        auth_data
    }

    fn attestation_object(auth_data: Vec<u8>) -> Vec<u8> {
        let value = Value::Map(vec![
            (
                Value::Text("fmt".to_string()),
                Value::Text(SECURE_UPGRADE_APP_ATTEST_FORMAT.to_string()),
            ),
            (Value::Text("authData".to_string()), Value::Bytes(auth_data)),
            (
                Value::Text("attStmt".to_string()),
                Value::Map(vec![(
                    Value::Text("x5c".to_string()),
                    Value::Array(vec![Value::Bytes(vec![0x30, 0x03, 0x02, 0x01, 0x01])]),
                )]),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&value, &mut bytes).expect("synthetic App Attest CBOR encodes");
        bytes
    }

    fn synthetic_attestation_for_record(
        record: &SecureUpgradeChallengeRecord,
    ) -> SyntheticAttestation {
        let challenge_digest =
            SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
                record.canonical_transcript_bytes(),
            );
        let auth_data = synthetic_auth_data(challenge_digest);
        let certificate_nonce = app_attest_nonce(&auth_data, challenge_digest);
        SyntheticAttestation {
            attestation_object_cbor: attestation_object(auth_data),
            certificate_nonce,
        }
    }

    fn app_attest_verification_for_record(
        record: &SecureUpgradeChallengeRecord,
    ) -> SecureUpgradeAppAttestVerification {
        let synthetic = synthetic_attestation_for_record(record);
        let bindings = verify_app_attest_commitment_bindings_for_transcript(
            &synthetic.attestation_object_cbor,
            record.canonical_transcript_bytes(),
            synthetic.certificate_nonce,
        )
        .unwrap();
        SecureUpgradeAppAttestVerification {
            bindings,
            proof_key_id_hash: [0x11; 32],
            leaf_public_key_sha256: [0x11; 32],
            root_ca_sha256: SECURE_UPGRADE_APP_ATTEST_ROOT_CA_SHA256,
            leaf_not_before_unix: NOW as i64 - 60,
            leaf_not_after_unix: NOW as i64 + 300,
        }
    }

    fn owner_signature_verification_for_record(
        record: &SecureUpgradeChallengeRecord,
        owner_key: &P256Keypair,
    ) -> SecureUpgradeOwnerSignatureVerification {
        let challenge_digest =
            SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
                record.canonical_transcript_bytes(),
            );
        let signature = owner_key.sign(&challenge_digest).unwrap();
        verify_owner_signature_for_transcript(
            record.canonical_transcript_bytes(),
            &record.scope().owner_key_id,
            &owner_key.public(),
            &signature,
        )
        .unwrap()
    }

    fn verified_ceremony_for_record(
        record: &SecureUpgradeChallengeRecord,
        owner_key: &P256Keypair,
    ) -> SecureUpgradeCeremonyVerification {
        let challenge_store = SecureUpgradeChallengeStore::new();
        let record = challenge_store
            .issue(
                transcript_with_owner_person_id(
                    record.challenge_id(),
                    &record.scope().owner_key_id,
                    record.scope().platform,
                    record.scope().owner_p_id.clone(),
                ),
                NOW,
            )
            .unwrap();
        let canonical = record.canonical_transcript_bytes().to_vec();
        let proof = proof_verification_for_record(&record, owner_key);
        let replay_dir = tempfile::tempdir().expect("tempdir");
        let replay_store = SecureUpgradeDurableAppAttestReplayStore::new(replay_dir.path());
        verify_secure_upgrade_verified_ceremony_for_challenge(
            &challenge_store,
            &replay_store,
            record.challenge_id(),
            &canonical,
            NOW,
            proof,
        )
        .unwrap()
    }

    fn proof_verification_for_record(
        record: &SecureUpgradeChallengeRecord,
        owner_key: &P256Keypair,
    ) -> SecureUpgradeProofVerification {
        verify_secure_upgrade_verified_proofs_for_challenge_record(
            record,
            app_attest_verification_for_record(record),
            owner_signature_verification_for_record(record, owner_key),
        )
        .unwrap()
    }

    fn sign_owner_options_for_record(
        record: &SecureUpgradeChallengeRecord,
        owner_key: &P256Keypair,
    ) -> SignOwnerOptions {
        SignOwnerOptions {
            hh_id: record.scope().hh_id.clone(),
            p_pub: owner_key.public(),
            display_name: "Owner".to_string(),
            issued_at: NOW,
        }
    }

    #[test]
    fn verified_app_attest_and_owner_signature_share_one_stored_digest() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let app_attest = app_attest_verification_for_record(&record);
        let owner_signature = owner_signature_verification_for_record(&record, &owner_key);
        let expected_digest =
            SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
                record.canonical_transcript_bytes(),
            );

        let verification = verify_secure_upgrade_verified_proofs_for_challenge_record(
            &record,
            app_attest,
            owner_signature,
        )
        .unwrap();

        assert_eq!(verification.challenge_digest(), expected_digest);
        assert_eq!(
            verification.app_attest().bindings().challenge_digest(),
            expected_digest
        );
        assert_eq!(
            verification.owner_signature().challenge_digest(),
            expected_digest
        );
        assert_eq!(verification.owner_signature().owner_key_id(), OWNER_KEY_ID);
    }

    #[test]
    fn app_attest_from_another_challenge_is_rejected_by_single_digest_check() {
        let owner_key = P256Keypair::generate();
        let record_a = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let record_b = challenge_record(
            "su-challenge-beta",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let app_attest_b = app_attest_verification_for_record(&record_b);
        let owner_signature_a = owner_signature_verification_for_record(&record_a, &owner_key);

        assert_eq!(
            verify_secure_upgrade_verified_proofs_for_challenge_record(
                &record_a,
                app_attest_b,
                owner_signature_a,
            )
            .unwrap_err(),
            SecureUpgradeProofVerificationError::AppAttestChallengeDigestMismatch
        );
    }

    #[test]
    fn owner_signature_from_another_challenge_is_rejected_by_single_digest_check() {
        let owner_key = P256Keypair::generate();
        let record_a = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let record_b = challenge_record(
            "su-challenge-beta",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let app_attest_a = app_attest_verification_for_record(&record_a);
        let owner_signature_b = owner_signature_verification_for_record(&record_b, &owner_key);

        assert_eq!(
            verify_secure_upgrade_verified_proofs_for_challenge_record(
                &record_a,
                app_attest_a,
                owner_signature_b,
            )
            .unwrap_err(),
            SecureUpgradeProofVerificationError::OwnerSignatureChallengeDigestMismatch
        );
    }

    #[test]
    fn owner_key_id_mismatch_in_verified_outputs_is_rejected() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let app_attest = app_attest_verification_for_record(&record);
        let mut owner_signature = owner_signature_verification_for_record(&record, &owner_key);
        owner_signature.owner_key_id = "owner-key-ios-beta".to_string();

        assert_eq!(
            verify_secure_upgrade_verified_proofs_for_challenge_record(
                &record,
                app_attest,
                owner_signature,
            )
            .unwrap_err(),
            SecureUpgradeProofVerificationError::OwnerKeyIdMismatch
        );
    }

    #[test]
    fn verified_ios_proof_derives_ios_app_attest_owner_provenance_without_minting() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let proof = proof_verification_for_record(&record, &owner_key);

        let provenance =
            verified_owner_provenance_from_secure_upgrade_proof(&record, &proof).unwrap();

        assert_eq!(provenance.challenge_digest(), proof.challenge_digest());
        assert_eq!(
            provenance.owner_provenance(),
            VerifiedOwnerProvenance::IosAppAttestOwner
        );
    }

    #[test]
    fn verified_ipados_proof_derives_ipados_app_attest_owner_provenance_without_minting() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::IpadOs,
        );
        let proof = proof_verification_for_record(&record, &owner_key);

        let provenance =
            verified_owner_provenance_from_secure_upgrade_proof(&record, &proof).unwrap();

        assert_eq!(provenance.challenge_digest(), proof.challenge_digest());
        assert_eq!(
            provenance.owner_provenance(),
            VerifiedOwnerProvenance::IpadOsAppAttestOwner
        );
    }

    #[test]
    fn provenance_derivation_rejects_top_level_proof_digest_mismatch() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let mut proof = proof_verification_for_record(&record, &owner_key);
        proof.challenge_digest[0] ^= 0xff;

        assert_eq!(
            verified_owner_provenance_from_secure_upgrade_proof(&record, &proof).unwrap_err(),
            SecureUpgradeProofVerificationError::ProofChallengeDigestMismatch
        );
    }

    #[test]
    fn provenance_derivation_revalidates_inner_app_attest_digest() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let mut proof = proof_verification_for_record(&record, &owner_key);
        proof.app_attest.bindings.challenge_digest[0] ^= 0xff;

        assert_eq!(
            verified_owner_provenance_from_secure_upgrade_proof(&record, &proof).unwrap_err(),
            SecureUpgradeProofVerificationError::AppAttestChallengeDigestMismatch
        );
    }

    #[test]
    fn provenance_derivation_revalidates_inner_owner_signature_digest() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let mut proof = proof_verification_for_record(&record, &owner_key);
        proof.owner_signature.challenge_digest[0] ^= 0xff;

        assert_eq!(
            verified_owner_provenance_from_secure_upgrade_proof(&record, &proof).unwrap_err(),
            SecureUpgradeProofVerificationError::OwnerSignatureChallengeDigestMismatch
        );
    }

    #[test]
    fn replay_store_records_verified_attestation_without_minting() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let proof = proof_verification_for_record(&record, &owner_key);
        let replay_store = SecureUpgradeAppAttestReplayStore::new();

        let replay_record = replay_store
            .record_verified_attestation(&record, &proof)
            .unwrap();

        assert_eq!(replay_store.len(), 1);
        assert_eq!(
            replay_record.version(),
            SECURE_UPGRADE_APP_ATTEST_REPLAY_RECORD_VERSION
        );
        assert_eq!(replay_record.scope(), record.scope());
        assert_eq!(replay_record.challenge_digest(), proof.challenge_digest());
        assert_eq!(
            replay_record.proof_key_id_hash(),
            proof.app_attest().proof_key_id_hash()
        );
        assert_eq!(
            replay_record.leaf_public_key_sha256(),
            proof.app_attest().leaf_public_key_sha256()
        );
        assert_eq!(replay_record.attestation_counter(), 0);
    }

    #[test]
    fn replay_store_rejects_same_challenge_digest_replay() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let proof = proof_verification_for_record(&record, &owner_key);
        let replay_store = SecureUpgradeAppAttestReplayStore::new();

        replay_store
            .record_verified_attestation(&record, &proof)
            .unwrap();

        assert_eq!(
            replay_store
                .record_verified_attestation(&record, &proof)
                .unwrap_err(),
            SecureUpgradeAppAttestReplayError::AttestationChallengeReplay
        );
        assert_eq!(replay_store.len(), 1);
    }

    #[test]
    fn replay_store_rejects_same_proof_key_for_new_challenge() {
        let owner_key = P256Keypair::generate();
        let record_a = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let record_b = challenge_record(
            "su-challenge-beta",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let proof_a = proof_verification_for_record(&record_a, &owner_key);
        let proof_b = proof_verification_for_record(&record_b, &owner_key);
        let replay_store = SecureUpgradeAppAttestReplayStore::new();

        replay_store
            .record_verified_attestation(&record_a, &proof_a)
            .unwrap();

        assert_eq!(
            replay_store
                .record_verified_attestation(&record_b, &proof_b)
                .unwrap_err(),
            SecureUpgradeAppAttestReplayError::DuplicateProofKey
        );
    }

    #[test]
    fn replay_store_rejects_proof_not_bound_to_record() {
        let owner_key = P256Keypair::generate();
        let record_a = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let record_b = challenge_record(
            "su-challenge-beta",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let proof_b = proof_verification_for_record(&record_b, &owner_key);
        let replay_store = SecureUpgradeAppAttestReplayStore::new();

        assert_eq!(
            replay_store
                .record_verified_attestation(&record_a, &proof_b)
                .unwrap_err(),
            SecureUpgradeAppAttestReplayError::Proof(
                SecureUpgradeProofVerificationError::ProofChallengeDigestMismatch
            )
        );
        assert!(replay_store.is_empty());
    }

    #[test]
    fn replay_store_rejects_top_level_proof_digest_mismatch() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let mut proof = proof_verification_for_record(&record, &owner_key);
        proof.challenge_digest[0] ^= 0xff;
        let replay_store = SecureUpgradeAppAttestReplayStore::new();

        assert_eq!(
            replay_store
                .record_verified_attestation(&record, &proof)
                .unwrap_err(),
            SecureUpgradeAppAttestReplayError::Proof(
                SecureUpgradeProofVerificationError::ProofChallengeDigestMismatch
            )
        );
        assert!(replay_store.is_empty());
    }

    #[test]
    fn replay_store_rejects_same_proof_key_with_changed_material() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let proof = proof_verification_for_record(&record, &owner_key);
        let mut changed_material = proof.clone();
        changed_material.app_attest.leaf_public_key_sha256[0] ^= 0xff;
        let replay_store = SecureUpgradeAppAttestReplayStore::new();

        replay_store
            .record_verified_attestation(&record, &proof)
            .unwrap();

        assert_eq!(
            replay_store
                .record_verified_attestation(&record, &changed_material)
                .unwrap_err(),
            SecureUpgradeAppAttestReplayError::ProofKeyMaterialMismatch
        );
    }

    #[test]
    fn replay_store_rejects_nonzero_attestation_counter() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let mut proof = proof_verification_for_record(&record, &owner_key);
        proof.app_attest.bindings.attestation_object.counter = 1;
        let replay_store = SecureUpgradeAppAttestReplayStore::new();

        assert_eq!(
            replay_store
                .record_verified_attestation(&record, &proof)
                .unwrap_err(),
            SecureUpgradeAppAttestReplayError::AttestationCounterMismatch
        );
        assert!(replay_store.is_empty());
    }

    #[test]
    fn durable_replay_store_persists_canonical_proof_key_record() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let proof = proof_verification_for_record(&record, &owner_key);
        let dir = tempfile::tempdir().expect("tempdir");
        let durable_store = SecureUpgradeDurableAppAttestReplayStore::new(dir.path());

        let replay_record = durable_store
            .record_verified_attestation(&record, &proof)
            .unwrap();

        let persisted_path = dir.path().join(format!(
            "{}.json",
            hex::encode(proof.app_attest().proof_key_id_hash())
        ));
        assert!(persisted_path.exists());
        let persisted: SecureUpgradeAppAttestReplayRecord =
            serde_json::from_str(&std::fs::read_to_string(persisted_path).unwrap()).unwrap();
        assert_eq!(persisted, replay_record);
        assert_eq!(
            replay_record.version(),
            SECURE_UPGRADE_APP_ATTEST_REPLAY_RECORD_VERSION
        );
    }

    #[test]
    fn durable_replay_store_survives_reopen_and_rejects_same_digest_replay() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let proof = proof_verification_for_record(&record, &owner_key);
        let dir = tempfile::tempdir().expect("tempdir");
        SecureUpgradeDurableAppAttestReplayStore::new(dir.path())
            .record_verified_attestation(&record, &proof)
            .unwrap();

        let reopened = SecureUpgradeDurableAppAttestReplayStore::new(dir.path());

        assert_eq!(
            reopened
                .record_verified_attestation(&record, &proof)
                .unwrap_err(),
            SecureUpgradeAppAttestReplayError::AttestationChallengeReplay
        );
    }

    #[test]
    fn durable_replay_store_survives_reopen_and_rejects_same_key_new_challenge() {
        let owner_key = P256Keypair::generate();
        let record_a = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let record_b = challenge_record(
            "su-challenge-beta",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let proof_a = proof_verification_for_record(&record_a, &owner_key);
        let proof_b = proof_verification_for_record(&record_b, &owner_key);
        let dir = tempfile::tempdir().expect("tempdir");
        SecureUpgradeDurableAppAttestReplayStore::new(dir.path())
            .record_verified_attestation(&record_a, &proof_a)
            .unwrap();

        let reopened = SecureUpgradeDurableAppAttestReplayStore::new(dir.path());

        assert_eq!(
            reopened
                .record_verified_attestation(&record_b, &proof_b)
                .unwrap_err(),
            SecureUpgradeAppAttestReplayError::DuplicateProofKey
        );
    }

    #[test]
    fn durable_replay_store_rejects_changed_material_after_reopen() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let proof = proof_verification_for_record(&record, &owner_key);
        let mut changed_material = proof.clone();
        changed_material.app_attest.leaf_public_key_sha256[0] ^= 0xff;
        let dir = tempfile::tempdir().expect("tempdir");
        SecureUpgradeDurableAppAttestReplayStore::new(dir.path())
            .record_verified_attestation(&record, &proof)
            .unwrap();

        let reopened = SecureUpgradeDurableAppAttestReplayStore::new(dir.path());

        assert_eq!(
            reopened
                .record_verified_attestation(&record, &changed_material)
                .unwrap_err(),
            SecureUpgradeAppAttestReplayError::ProofKeyMaterialMismatch
        );
    }

    #[test]
    fn durable_replay_store_fails_closed_on_corrupt_persisted_record() {
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let proof = proof_verification_for_record(&record, &owner_key);
        let dir = tempfile::tempdir().expect("tempdir");
        let durable_store = SecureUpgradeDurableAppAttestReplayStore::new(dir.path());
        durable_store
            .record_verified_attestation(&record, &proof)
            .unwrap();
        let persisted_path = dir.path().join(format!(
            "{}.json",
            hex::encode(proof.app_attest().proof_key_id_hash())
        ));
        std::fs::write(persisted_path, "{not-json").unwrap();

        let err = durable_store
            .record_verified_attestation(&record, &proof)
            .unwrap_err();

        assert!(matches!(
            err,
            SecureUpgradeAppAttestReplayError::StorageJson(_)
        ));
    }

    #[test]
    fn durable_replay_store_allows_one_atomic_writer_across_instances() {
        let owner_key = P256Keypair::generate();
        let record = Arc::new(challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        ));
        let proof = Arc::new(proof_verification_for_record(&record, &owner_key));
        let dir = tempfile::tempdir().expect("tempdir");
        let store_a = Arc::new(SecureUpgradeDurableAppAttestReplayStore::new(dir.path()));
        let store_b = Arc::new(SecureUpgradeDurableAppAttestReplayStore::new(dir.path()));
        let barrier = Arc::new(Barrier::new(2));

        let (result_a, result_b) = std::thread::scope(|scope| {
            let record_a = Arc::clone(&record);
            let proof_a = Arc::clone(&proof);
            let store_a = Arc::clone(&store_a);
            let barrier_a = Arc::clone(&barrier);
            let handle_a = scope.spawn(move || {
                barrier_a.wait();
                store_a.record_verified_attestation(&record_a, &proof_a)
            });

            let record_b = Arc::clone(&record);
            let proof_b = Arc::clone(&proof);
            let store_b = Arc::clone(&store_b);
            let barrier_b = Arc::clone(&barrier);
            let handle_b = scope.spawn(move || {
                barrier_b.wait();
                store_b.record_verified_attestation(&record_b, &proof_b)
            });

            (handle_a.join().unwrap(), handle_b.join().unwrap())
        });

        let successes = usize::from(result_a.is_ok()) + usize::from(result_b.is_ok());
        assert_eq!(successes, 1);
        let replay_errors = [result_a, result_b]
            .into_iter()
            .filter_map(Result::err)
            .filter(|err| *err == SecureUpgradeAppAttestReplayError::AttestationChallengeReplay)
            .count();
        assert_eq!(replay_errors, 1);
    }

    #[test]
    fn verified_ceremony_consumes_challenge_records_replay_and_returns_provenance_without_minting()
    {
        let owner_key = P256Keypair::generate();
        let challenge_store = SecureUpgradeChallengeStore::new();
        let transcript = transcript(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let record = challenge_store.issue(transcript, NOW).unwrap();
        let canonical = record.canonical_transcript_bytes().to_vec();
        let proof = proof_verification_for_record(&record, &owner_key);
        let replay_dir = tempfile::tempdir().expect("tempdir");
        let replay_store = SecureUpgradeDurableAppAttestReplayStore::new(replay_dir.path());

        let verification = verify_secure_upgrade_verified_ceremony_for_challenge(
            &challenge_store,
            &replay_store,
            "su-challenge-alpha",
            &canonical,
            NOW,
            proof.clone(),
        )
        .unwrap();

        assert!(challenge_store.is_empty());
        assert_eq!(
            verification.challenge_record().challenge_id(),
            "su-challenge-alpha"
        );
        assert_eq!(
            verification.proof().challenge_digest(),
            proof.challenge_digest()
        );
        assert_eq!(
            verification.replay_record().challenge_digest(),
            proof.challenge_digest()
        );
        assert_eq!(
            verification.verified_owner_provenance().owner_provenance(),
            VerifiedOwnerProvenance::IosAppAttestOwner
        );
        assert_eq!(
            std::fs::read_dir(replay_dir.path()).unwrap().count(),
            1,
            "durable replay record is written exactly once"
        );
    }

    #[test]
    fn secure_upgrade_minter_signs_owner_cert_only_from_verified_ceremony() {
        let hh_key = P256Keypair::generate();
        let owner_key = P256Keypair::generate();
        let owner_p_id = derive_person_id(&owner_key.public());
        let record = challenge_record_for_owner_person_id(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
            owner_p_id.clone(),
        );
        let verification = verified_ceremony_for_record(&record, &owner_key);

        let cert = sign_owner_cert_with_secure_upgrade_verification(
            &hh_key,
            sign_owner_options_for_record(&record, &owner_key),
            &verification,
        )
        .unwrap();

        assert_eq!(cert.hh_id, record.scope().hh_id);
        assert_eq!(cert.p_id, owner_p_id);
        assert_eq!(
            cert.owner_auth_tier_text(),
            Some(PersonCert::OWNER_AUTH_TIER_STRONG)
        );
        assert_eq!(
            cert.owner_provenance_text(),
            Some(PersonCert::OWNER_PROVENANCE_IOS_APP_ATTEST_OWNER)
        );
        assert!(cert.has_strong_owner_provenance());
        cert.verify(&record.scope().hh_id, &hh_key.public(), NOW)
            .unwrap();
    }

    #[test]
    fn secure_upgrade_minter_rejects_household_id_mismatch() {
        let hh_key = P256Keypair::generate();
        let owner_key = P256Keypair::generate();
        let owner_p_id = derive_person_id(&owner_key.public());
        let record = challenge_record_for_owner_person_id(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
            owner_p_id,
        );
        let verification = verified_ceremony_for_record(&record, &owner_key);
        let mut opts = sign_owner_options_for_record(&record, &owner_key);
        opts.hh_id = crate::ids::derive_household_id(&P256Keypair::generate().public());

        assert!(matches!(
            sign_owner_cert_with_secure_upgrade_verification(&hh_key, opts, &verification)
                .unwrap_err(),
            SecureUpgradeOwnerCertMintError::HouseholdIdMismatch
        ));
    }

    #[test]
    fn secure_upgrade_minter_rejects_owner_person_id_mismatch() {
        let hh_key = P256Keypair::generate();
        let owner_key = P256Keypair::generate();
        let record = challenge_record(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let verification = verified_ceremony_for_record(&record, &owner_key);

        assert!(matches!(
            sign_owner_cert_with_secure_upgrade_verification(
                &hh_key,
                sign_owner_options_for_record(&record, &owner_key),
                &verification,
            )
            .unwrap_err(),
            SecureUpgradeOwnerCertMintError::OwnerPersonIdMismatch
        ));
    }

    #[test]
    fn secure_upgrade_minter_rejects_owner_public_key_mismatch() {
        let hh_key = P256Keypair::generate();
        let minted_owner_key = P256Keypair::generate();
        let proof_owner_key = P256Keypair::generate();
        let owner_p_id = derive_person_id(&minted_owner_key.public());
        let record = challenge_record_for_owner_person_id(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
            owner_p_id,
        );
        let verification = verified_ceremony_for_record(&record, &proof_owner_key);

        assert!(matches!(
            sign_owner_cert_with_secure_upgrade_verification(
                &hh_key,
                sign_owner_options_for_record(&record, &minted_owner_key),
                &verification,
            )
            .unwrap_err(),
            SecureUpgradeOwnerCertMintError::OwnerPublicKeyMismatch
        ));
    }

    #[test]
    fn verified_ceremony_rejects_second_challenge_for_same_app_attest_key() {
        let owner_key = P256Keypair::generate();
        let challenge_store = SecureUpgradeChallengeStore::new();
        let record_a = challenge_store
            .issue(
                transcript(
                    "su-challenge-alpha",
                    OWNER_KEY_ID,
                    SecureUpgradePlatform::Ios,
                ),
                NOW,
            )
            .unwrap();
        let record_b = challenge_store
            .issue(
                transcript(
                    "su-challenge-beta",
                    OWNER_KEY_ID,
                    SecureUpgradePlatform::Ios,
                ),
                NOW,
            )
            .unwrap();
        let canonical_a = record_a.canonical_transcript_bytes().to_vec();
        let canonical_b = record_b.canonical_transcript_bytes().to_vec();
        let proof_a = proof_verification_for_record(&record_a, &owner_key);
        let proof_b = proof_verification_for_record(&record_b, &owner_key);
        let replay_dir = tempfile::tempdir().expect("tempdir");
        let replay_store = SecureUpgradeDurableAppAttestReplayStore::new(replay_dir.path());

        verify_secure_upgrade_verified_ceremony_for_challenge(
            &challenge_store,
            &replay_store,
            "su-challenge-alpha",
            &canonical_a,
            NOW,
            proof_a,
        )
        .unwrap();

        assert_eq!(
            verify_secure_upgrade_verified_ceremony_for_challenge(
                &challenge_store,
                &replay_store,
                "su-challenge-beta",
                &canonical_b,
                NOW,
                proof_b,
            )
            .unwrap_err(),
            SecureUpgradeCeremonyVerificationError::Replay(
                SecureUpgradeAppAttestReplayError::DuplicateProofKey
            )
        );
        assert!(challenge_store.is_empty());
    }

    #[test]
    fn full_ceremony_fails_closed_until_real_app_attest_fixture_is_available() {
        let owner_key = P256Keypair::generate();
        let challenge_store = SecureUpgradeChallengeStore::new();
        let transcript = transcript(
            "su-challenge-alpha",
            OWNER_KEY_ID,
            SecureUpgradePlatform::Ios,
        );
        let record = challenge_store.issue(transcript, NOW).unwrap();
        let canonical = record.canonical_transcript_bytes().to_vec();
        let challenge_digest =
            SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(&canonical);
        let owner_signature = owner_key.sign(&challenge_digest).unwrap();
        let synthetic = synthetic_attestation_for_record(&record);
        let replay_dir = tempfile::tempdir().expect("tempdir");
        let replay_store = SecureUpgradeDurableAppAttestReplayStore::new(replay_dir.path());

        let err = verify_secure_upgrade_ceremony_for_challenge(
            &challenge_store,
            &replay_store,
            "su-challenge-alpha",
            &canonical,
            SecureUpgradeProofVerificationInput {
                attestation_object_cbor: &synthetic.attestation_object_cbor,
                owner_public_key: &owner_key.public(),
                owner_signature: &owner_signature,
                now_unix: NOW,
            },
        )
        .unwrap_err();

        assert!(matches!(
            err,
            SecureUpgradeCeremonyVerificationError::Proof(
                SecureUpgradeProofVerificationError::AppAttest(_)
            )
        ));
        assert!(challenge_store.is_empty());
        assert_eq!(std::fs::read_dir(replay_dir.path()).unwrap().count(), 0);
    }
}
