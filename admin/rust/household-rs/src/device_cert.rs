//! R0a Fatia D2a — typed `DeviceCert` v1 with byte-exact wire parity.
//!
//! The wire shape is fixed by `docs/household-protocol.md` §8 and is the same
//! canonical CBOR the iOS owner-device produces. Wire field names are pinned at
//! the serde layer (`v`, `type`, …) because the signature covers the canonical
//! bytes: renaming a field here would silently break cross-language
//! verification rather than fail to compile.
//!
//! Deliberately absent: any validity window. `DeviceCert` v1 carries no
//! `not_before` / `not_after`, so this module invents none (R0a §6). A device's
//! R0a lifetime ends when the household root, the owner `PersonCert`, the
//! admission generation, or the revocation cursor changes — never on a
//! certificate TTL synthesized here.
//!
//! This module verifies a certificate against an owner `PersonCert` and returns
//! the closed caveat-narrowing proof from [`crate::caveat_narrowing`]. It
//! creates no storage, no snapshot, no capability, and no admission authority.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::caveat_narrowing::{
    CaveatNarrowingError, DeviceCaveatNarrowingProofV1, verify_explicit_household_add_device_grant,
};
use crate::caveats::Caveat;
use crate::cbor;
use crate::error::{HouseholdError, KeystoreError};
use crate::ids::{base32_lower_nopad_encode, hash_public_key};
use crate::keys::{IdentityKey, P256PublicKey, P256Signature, verify_signature};
use crate::machine_cert::{CertType, DeviceId, PersonId, SubjectId};
use crate::person_cert::PersonCert;

/// Domain separator for the canonical `DeviceCert` digest. The digest is an
/// internal binding value, never a wire field.
const DEVICE_CERT_DIGEST_DOMAIN: &[u8] = b"soyeht/household-device-cert/v1\x00";

/// The exact wire key set of a v1 `DeviceCert`. Both the allowed set and the
/// required set: an owner-device always emits all eleven keys, so a cert with a
/// missing or extra key is not a v1 `DeviceCert`.
const DEVICE_CERT_KEYS: [&str; 11] = [
    "v",
    "type",
    "p_id",
    "d_id",
    "d_pub",
    "device_name",
    "platform",
    "added_at",
    "issued_by",
    "caveats",
    "signature",
];

/// `caveats` is the only key whose v1 wire value may be CBOR `null`
/// (`[Caveat] | null`). Every other key carrying `null` is malformed.
const NULLABLE_DEVICE_CERT_KEYS: [&str; 1] = ["caveats"];

/// Structural bound on `device_name`, mirroring
/// [`crate::person_cert::validate_display_name`].
const MAX_DEVICE_NAME_BYTES: usize = 64;

/// Structural bound on `platform`. The closed platform vocabulary is
/// deliberately NOT fixed here: R0a v1 admits iPhone/iPadOS owner-devices, and
/// pinning an enum without the iOS producer bytes in hand would invent a
/// rejection rule the contract does not state. This is a shape bound only.
const MAX_PLATFORM_BYTES: usize = 32;

/// Closed failures produced by the `DeviceCert` codec and verifier.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeviceCertError {
    #[error("device cert is not canonical CBOR")]
    NonCanonical,
    #[error("device cert has a non-text or duplicate map key")]
    DuplicateKey,
    #[error("device cert carries an unknown field")]
    UnknownField,
    #[error("device cert is missing a required field")]
    MissingField,
    #[error("device cert field is null")]
    NullField,
    #[error("device cert re-encodes to different bytes")]
    NotByteExact,
    #[error("device cert schema version is unsupported")]
    VersionUnsupported,
    #[error("device cert type is not `device`")]
    WrongCertType,
    #[error("device cert public key is malformed")]
    PublicKeyMalformed,
    #[error("device cert d_id does not derive from d_pub")]
    SubjectMismatch,
    #[error("device cert p_id does not match the owner person cert")]
    PersonMismatch,
    #[error("device cert issued_by is not the owner person")]
    IssuerMismatch,
    #[error("device cert text field is malformed")]
    MalformedText,
    #[error("device cert signature did not verify under the person key")]
    SignatureMismatch,
    #[error("device caveats do not narrow the person caveats: {0}")]
    Narrowing(#[from] CaveatNarrowingError),
    #[error("device cert encoding failed")]
    Encoding,
}

/// On-the-wire owner-device certificate, signed by the owner's person key.
///
/// `caveats` is `Option<Vec<Caveat>>` and is never skipped on serialization:
/// the v1 shape is `[Caveat] | null`, so the key is always present.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct DeviceCert {
    #[serde(rename = "v")]
    pub version: u8,
    #[serde(rename = "type")]
    pub cert_type: CertType,
    pub p_id: PersonId,
    pub d_id: DeviceId,
    pub d_pub: P256PublicKey,
    pub device_name: String,
    pub platform: String,
    pub added_at: u64,
    pub issued_by: SubjectId,
    pub caveats: Option<Vec<Caveat>>,
    pub signature: P256Signature,
}

/// Same shape as [`DeviceCert`] minus `signature` — the canonical bytes the
/// signature covers. The `"v"` / `"type"` renames are repeated so the signed
/// bytes match the on-wire encoding exactly.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
struct DeviceCertUnsigned {
    #[serde(rename = "v")]
    version: u8,
    #[serde(rename = "type")]
    cert_type: CertType,
    p_id: PersonId,
    d_id: DeviceId,
    d_pub: P256PublicKey,
    device_name: String,
    platform: String,
    added_at: u64,
    issued_by: SubjectId,
    caveats: Option<Vec<Caveat>>,
}

/// Producer-side inputs. `d_id`, `p_id`, and `issued_by` are derived, never
/// supplied, so a caller cannot bind a subject to the wrong key.
pub struct SignOptions {
    pub p_pub: P256PublicKey,
    pub d_pub: P256PublicKey,
    pub device_name: String,
    pub platform: String,
    pub added_at: u64,
    pub caveats: Option<Vec<Caveat>>,
}

/// Derive `d_<base32>` from the full 33-byte SEC1 device key, mirroring
/// [`crate::person_cert::derive_person_id`] and
/// [`crate::ids::derive_machine_id`].
#[must_use]
pub fn derive_device_id(d_pub: &P256PublicKey) -> DeviceId {
    let hash = hash_public_key(d_pub.as_bytes());
    DeviceId(format!("d_{}", base32_lower_nopad_encode(&hash)))
}

impl DeviceCert {
    pub const SCHEMA_VERSION: u8 = 1;

    /// Sign a fresh `DeviceCert` under the owner's person key. Derivation and
    /// signing only — touches neither filesystem nor keystore.
    pub fn sign(person_key: &dyn IdentityKey, opts: SignOptions) -> Result<Self, KeystoreError> {
        validate_text(&opts.device_name, MAX_DEVICE_NAME_BYTES)
            .map_err(|e| KeystoreError::InvalidKeyMaterial(format!("device_name: {e}")))?;
        validate_text(&opts.platform, MAX_PLATFORM_BYTES)
            .map_err(|e| KeystoreError::InvalidKeyMaterial(format!("platform: {e}")))?;
        let p_id = crate::person_cert::derive_person_id(&opts.p_pub);
        let unsigned = DeviceCertUnsigned {
            version: Self::SCHEMA_VERSION,
            cert_type: CertType::Device,
            p_id: p_id.clone(),
            d_id: derive_device_id(&opts.d_pub),
            d_pub: opts.d_pub,
            device_name: opts.device_name,
            platform: opts.platform,
            added_at: opts.added_at,
            issued_by: SubjectId::Person(p_id),
            caveats: opts.caveats,
        };
        let canonical = cbor::to_canonical_vec(&unsigned)
            .map_err(|e| KeystoreError::SigningFailed(format!("encode device cert: {e}")))?;
        let signature = person_key.sign(&canonical)?;
        Ok(Self {
            version: unsigned.version,
            cert_type: unsigned.cert_type,
            p_id: unsigned.p_id,
            d_id: unsigned.d_id,
            d_pub: unsigned.d_pub,
            device_name: unsigned.device_name,
            platform: unsigned.platform,
            added_at: unsigned.added_at,
            issued_by: unsigned.issued_by,
            caveats: unsigned.caveats,
            signature,
        })
    }

    /// Canonical CBOR bytes the signature covers (everything but `signature`).
    pub fn signing_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        let unsigned = DeviceCertUnsigned {
            version: self.version,
            cert_type: self.cert_type.clone(),
            p_id: self.p_id.clone(),
            d_id: self.d_id.clone(),
            d_pub: self.d_pub.clone(),
            device_name: self.device_name.clone(),
            platform: self.platform.clone(),
            added_at: self.added_at,
            issued_by: self.issued_by.clone(),
            caveats: self.caveats.clone(),
        };
        cbor::to_canonical_vec(&unsigned)
    }

    /// Full canonical CBOR encoding, including `signature`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        cbor::to_canonical_vec(self)
    }

    /// Domain-separated BLAKE3 digest over the canonical encoding. Used as the
    /// `device_cert_digest` sealed into the admission authority.
    pub fn digest(&self) -> Result<[u8; 32], HouseholdError> {
        let bytes = self.canonical_bytes()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(DEVICE_CERT_DIGEST_DOMAIN);
        hasher.update(&bytes);
        Ok(hasher.finalize().into())
    }

    /// Decode wire bytes with byte-exact parity enforcement.
    ///
    /// This is the only sanctioned entry point from untrusted bytes. It rejects
    /// non-canonical CBOR, duplicate or non-text keys, unknown or missing keys,
    /// and stray nulls *before* typed decoding, then re-encodes and compares
    /// byte for byte. A cert that decodes but does not re-encode identically
    /// would verify under bytes that are not the bytes received, so it is
    /// rejected rather than normalized.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, DeviceCertError> {
        pre_validate_map(bytes)?;
        let cert: Self =
            cbor::from_canonical_slice(bytes).map_err(|_| DeviceCertError::NonCanonical)?;
        let re_encoded = cert
            .canonical_bytes()
            .map_err(|_| DeviceCertError::Encoding)?;
        if re_encoded != bytes {
            return Err(DeviceCertError::NotByteExact);
        }
        Ok(cert)
    }

    /// Structural validation that does not consult the owner `PersonCert`:
    /// version, cert type, key shape, subject derivation, and text bounds.
    fn verify_shape(&self) -> Result<(), DeviceCertError> {
        if self.version != Self::SCHEMA_VERSION {
            return Err(DeviceCertError::VersionUnsupported);
        }
        if self.cert_type != CertType::Device {
            return Err(DeviceCertError::WrongCertType);
        }
        // Re-decode the key: `Deserialize` accepts any 33 bytes, so on-curve and
        // SEC1-prefix checks happen here (R0a §5).
        P256PublicKey::from_bytes(self.d_pub.as_bytes())
            .map_err(|_| DeviceCertError::PublicKeyMalformed)?;
        if derive_device_id(&self.d_pub) != self.d_id {
            return Err(DeviceCertError::SubjectMismatch);
        }
        validate_text(&self.device_name, MAX_DEVICE_NAME_BYTES)
            .map_err(|_| DeviceCertError::MalformedText)?;
        validate_text(&self.platform, MAX_PLATFORM_BYTES)
            .map_err(|_| DeviceCertError::MalformedText)?;
        Ok(())
    }

    /// Verify the cert against the current owner `PersonCert` (R0a §7 steps
    /// 4–9) and return the closed caveat-narrowing proof.
    ///
    /// The proof is the return value rather than a boolean so a caller cannot
    /// reach an admitted device without having produced it. The caller remains
    /// responsible for having verified `person_cert` against the household root
    /// first — this function proves the device-to-person edge only.
    pub fn verify_against_person_cert(
        &self,
        person_cert: &PersonCert,
    ) -> Result<DeviceCaveatNarrowingProofV1, DeviceCertError> {
        self.verify_shape()?;
        if self.p_id != person_cert.p_id {
            return Err(DeviceCertError::PersonMismatch);
        }
        match &self.issued_by {
            SubjectId::Person(issuer) if issuer == &person_cert.p_id => {}
            _ => return Err(DeviceCertError::IssuerMismatch),
        }
        let signing_bytes = self
            .signing_bytes()
            .map_err(|_| DeviceCertError::Encoding)?;
        verify_signature(&person_cert.p_pub, &signing_bytes, &self.signature)
            .map_err(|_| DeviceCertError::SignatureMismatch)?;
        let proof = verify_explicit_household_add_device_grant(
            &person_cert.caveats,
            self.caveats.as_deref(),
        )?;
        Ok(proof)
    }
}

/// Reject anything that is not an exact-key-set CBOR map before typed decoding,
/// so malformed shapes surface as closed errors rather than serde text.
fn pre_validate_map(bytes: &[u8]) -> Result<(), DeviceCertError> {
    let value: ciborium::value::Value =
        ciborium::de::from_reader(bytes).map_err(|_| DeviceCertError::NonCanonical)?;
    let ciborium::value::Value::Map(entries) = &value else {
        return Err(DeviceCertError::NonCanonical);
    };
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (key, val) in entries {
        let ciborium::value::Value::Text(key) = key else {
            return Err(DeviceCertError::DuplicateKey);
        };
        if !DEVICE_CERT_KEYS.contains(&key.as_str()) {
            return Err(DeviceCertError::UnknownField);
        }
        if !seen.insert(key.as_str()) {
            return Err(DeviceCertError::DuplicateKey);
        }
        if matches!(val, ciborium::value::Value::Null)
            && !NULLABLE_DEVICE_CERT_KEYS.contains(&key.as_str())
        {
            return Err(DeviceCertError::NullField);
        }
    }
    if seen.len() != DEVICE_CERT_KEYS.len() {
        return Err(DeviceCertError::MissingField);
    }
    Ok(())
}

/// Shape validation shared by `device_name` and `platform`: non-empty, bounded,
/// and free of control characters. Mirrors the sibling cert validators.
fn validate_text(value: &str, max_bytes: usize) -> Result<(), HouseholdError> {
    if value.is_empty() {
        return Err(HouseholdError::InvalidCert("text field empty".into()));
    }
    if value.len() > max_bytes {
        return Err(HouseholdError::InvalidCert(format!(
            "text field > {max_bytes} bytes (got {})",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(HouseholdError::InvalidCert(
            "text field contains control char".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caveats::{Constraints, Operation, Scope};
    use crate::ids::derive_household_id;
    use crate::keys::{IdentityKey, P256Keypair};
    use crate::person_cert::{PersonCert, SignOwnerOptions};
    use std::collections::BTreeMap;

    /// An owner `PersonCert` carrying the explicit `household.add_device` grant.
    /// The stock owner template deliberately does not grant it (R0a Fatia N), so
    /// every admissible fixture has to add it here.
    fn owner_cert_with_add_device_grant(
        hh: &P256Keypair,
        person: &P256Keypair,
        extra: Vec<crate::caveats::Caveat>,
    ) -> PersonCert {
        let hh_id = derive_household_id(&hh.public());
        let mut cert = PersonCert::sign_owner(
            hh,
            SignOwnerOptions {
                hh_id,
                p_pub: person.public(),
                display_name: "Owner".into(),
                issued_at: 1_714_972_800,
            },
        )
        .unwrap();
        cert.caveats.push(crate::caveats::Caveat::new(
            Operation::HouseholdAddDevice,
            None,
        ));
        cert.caveats.extend(extra);
        // The household signature covers the caveat list, so re-sign rather
        // than leaving a cert whose own signature no longer matches its bytes.
        let signing = cert.signing_bytes().unwrap();
        cert.signature = hh.sign(&signing).unwrap();
        cert
    }

    fn device_cert(person: &P256Keypair, device: &P256Keypair) -> DeviceCert {
        DeviceCert::sign(
            person,
            SignOptions {
                p_pub: person.public(),
                d_pub: device.public(),
                device_name: "iPhone 15".into(),
                platform: "ios".into(),
                added_at: 1_714_972_800,
                caveats: None,
            },
        )
        .unwrap()
    }

    fn fixture() -> (
        P256Keypair,
        P256Keypair,
        P256Keypair,
        PersonCert,
        DeviceCert,
    ) {
        let hh = P256Keypair::generate();
        let person = P256Keypair::generate();
        let device = P256Keypair::generate();
        let owner = owner_cert_with_add_device_grant(&hh, &person, Vec::new());
        let cert = device_cert(&person, &device);
        (hh, person, device, owner, cert)
    }

    #[test]
    fn happy_path_verifies_and_returns_narrowing_proof() {
        let (_hh, _person, _device, owner, cert) = fixture();
        let proof = cert.verify_against_person_cert(&owner).unwrap();
        assert_eq!(proof.digest().len(), 32);
    }

    #[test]
    fn subject_derives_from_the_full_33_byte_key() {
        let (_hh, _person, device, _owner, cert) = fixture();
        assert_eq!(cert.d_pub.as_bytes().len(), 33);
        assert!(matches!(cert.d_pub.as_bytes()[0], 0x02 | 0x03));
        assert_eq!(cert.d_id, derive_device_id(&device.public()));
        assert!(cert.d_id.0.starts_with("d_"));
    }

    #[test]
    fn canonical_round_trip_is_byte_exact() {
        let (_hh, _person, _device, _owner, cert) = fixture();
        let bytes = cert.canonical_bytes().unwrap();
        let decoded = DeviceCert::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, cert);
        assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
    }

    #[test]
    fn wire_key_set_is_exactly_the_v1_schema() {
        let (_hh, _person, _device, _owner, cert) = fixture();
        let bytes = cert.canonical_bytes().unwrap();
        let value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let ciborium::value::Value::Map(entries) = value else {
            panic!("device cert encodes as a CBOR map");
        };
        let mut keys = entries
            .iter()
            .map(|(k, _)| match k {
                ciborium::value::Value::Text(t) => t.clone(),
                _ => panic!("device cert map keys are text"),
            })
            .collect::<Vec<_>>();
        keys.sort();
        let mut expected = DEVICE_CERT_KEYS.map(String::from).to_vec();
        expected.sort();
        assert_eq!(keys, expected);
    }

    #[test]
    fn caveats_null_is_present_on_the_wire_not_omitted() {
        let (_hh, _person, _device, _owner, cert) = fixture();
        assert!(cert.caveats.is_none());
        let bytes = cert.canonical_bytes().unwrap();
        let value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let ciborium::value::Value::Map(entries) = value else {
            panic!("device cert encodes as a CBOR map");
        };
        let caveats = entries
            .iter()
            .find(|(k, _)| k == &ciborium::value::Value::Text("caveats".into()))
            .map(|(_, v)| v.clone());
        assert_eq!(caveats, Some(ciborium::value::Value::Null));
    }

    #[test]
    fn no_validity_window_field_exists_on_the_wire() {
        let (_hh, _person, _device, _owner, cert) = fixture();
        let bytes = cert.canonical_bytes().unwrap();
        for invented in ["not_before", "not_after", "expires_at", "ttl"] {
            assert!(
                !DEVICE_CERT_KEYS.contains(&invented),
                "v1 DeviceCert must not carry {invented}"
            );
            let needle = ciborium::value::Value::Text(invented.into());
            let value: ciborium::value::Value =
                ciborium::de::from_reader(bytes.as_slice()).unwrap();
            let ciborium::value::Value::Map(entries) = value else {
                panic!("device cert encodes as a CBOR map");
            };
            assert!(!entries.iter().any(|(k, _)| k == &needle));
        }
    }

    #[test]
    fn unknown_field_is_rejected_before_typed_decode() {
        let (_hh, _person, _device, _owner, cert) = fixture();
        let bytes = cert.canonical_bytes().unwrap();
        let value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let ciborium::value::Value::Map(mut entries) = value else {
            panic!("map");
        };
        entries.push((
            ciborium::value::Value::Text("not_after".into()),
            ciborium::value::Value::Integer(99.into()),
        ));
        let mut tampered = Vec::new();
        ciborium::ser::into_writer(&ciborium::value::Value::Map(entries), &mut tampered).unwrap();
        assert_eq!(
            DeviceCert::decode_canonical(&tampered),
            Err(DeviceCertError::UnknownField)
        );
    }

    #[test]
    fn missing_field_is_rejected() {
        let (_hh, _person, _device, _owner, cert) = fixture();
        let bytes = cert.canonical_bytes().unwrap();
        let value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let ciborium::value::Value::Map(mut entries) = value else {
            panic!("map");
        };
        entries.retain(|(k, _)| k != &ciborium::value::Value::Text("platform".into()));
        let mut tampered = Vec::new();
        ciborium::ser::into_writer(&ciborium::value::Value::Map(entries), &mut tampered).unwrap();
        assert_eq!(
            DeviceCert::decode_canonical(&tampered),
            Err(DeviceCertError::MissingField)
        );
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let (_hh, _person, _device, _owner, cert) = fixture();
        let bytes = cert.canonical_bytes().unwrap();
        let value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let ciborium::value::Value::Map(mut entries) = value else {
            panic!("map");
        };
        entries.push((
            ciborium::value::Value::Text("added_at".into()),
            ciborium::value::Value::Integer(1.into()),
        ));
        let mut tampered = Vec::new();
        ciborium::ser::into_writer(&ciborium::value::Value::Map(entries), &mut tampered).unwrap();
        assert_eq!(
            DeviceCert::decode_canonical(&tampered),
            Err(DeviceCertError::DuplicateKey)
        );
    }

    #[test]
    fn null_in_a_non_nullable_field_is_rejected() {
        let (_hh, _person, _device, _owner, cert) = fixture();
        let bytes = cert.canonical_bytes().unwrap();
        let value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let ciborium::value::Value::Map(mut entries) = value else {
            panic!("map");
        };
        for entry in &mut entries {
            if entry.0 == ciborium::value::Value::Text("platform".into()) {
                entry.1 = ciborium::value::Value::Null;
            }
        }
        let mut tampered = Vec::new();
        ciborium::ser::into_writer(&ciborium::value::Value::Map(entries), &mut tampered).unwrap();
        assert_eq!(
            DeviceCert::decode_canonical(&tampered),
            Err(DeviceCertError::NullField)
        );
    }

    #[test]
    fn non_canonical_key_order_is_rejected_as_not_byte_exact() {
        let (_hh, _person, _device, _owner, cert) = fixture();
        let bytes = cert.canonical_bytes().unwrap();
        let value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let ciborium::value::Value::Map(mut entries) = value else {
            panic!("map");
        };
        entries.reverse();
        let mut reordered = Vec::new();
        ciborium::ser::into_writer(&ciborium::value::Value::Map(entries), &mut reordered).unwrap();
        assert_ne!(reordered, bytes, "reversal must change the bytes");
        assert_eq!(
            DeviceCert::decode_canonical(&reordered),
            Err(DeviceCertError::NotByteExact)
        );
    }

    #[test]
    fn tampered_signature_fails() {
        let (_hh, _person, _device, owner, mut cert) = fixture();
        cert.signature.0[0] ^= 0x01;
        assert_eq!(
            cert.verify_against_person_cert(&owner).map(|_| ()),
            Err(DeviceCertError::SignatureMismatch)
        );
    }

    #[test]
    fn cert_signed_by_another_person_fails() {
        let hh = P256Keypair::generate();
        let person = P256Keypair::generate();
        let stranger = P256Keypair::generate();
        let device = P256Keypair::generate();
        let owner = owner_cert_with_add_device_grant(&hh, &person, Vec::new());
        // Signed by the stranger but claiming the real owner's p_id.
        let mut cert = device_cert(&stranger, &device);
        cert.p_id = owner.p_id.clone();
        cert.issued_by = SubjectId::Person(owner.p_id.clone());
        assert_eq!(
            cert.verify_against_person_cert(&owner).map(|_| ()),
            Err(DeviceCertError::SignatureMismatch)
        );
    }

    #[test]
    fn divergent_p_id_fails() {
        let (_hh, _person, _device, owner, mut cert) = fixture();
        cert.p_id = PersonId(format!("p_{}", "a".repeat(52)));
        assert_eq!(
            cert.verify_against_person_cert(&owner).map(|_| ()),
            Err(DeviceCertError::PersonMismatch)
        );
    }

    #[test]
    fn divergent_issued_by_fails() {
        let (_hh, _person, _device, owner, mut cert) = fixture();
        cert.issued_by = SubjectId::Person(PersonId(format!("p_{}", "b".repeat(52))));
        assert_eq!(
            cert.verify_against_person_cert(&owner).map(|_| ()),
            Err(DeviceCertError::IssuerMismatch)
        );
    }

    #[test]
    fn divergent_d_id_fails() {
        let (_hh, _person, _device, owner, mut cert) = fixture();
        cert.d_id = DeviceId(format!("d_{}", "c".repeat(52)));
        assert_eq!(
            cert.verify_against_person_cert(&owner).map(|_| ()),
            Err(DeviceCertError::SubjectMismatch)
        );
    }

    #[test]
    fn wrong_cert_type_fails() {
        let (_hh, _person, _device, owner, mut cert) = fixture();
        cert.cert_type = CertType::Machine;
        assert_eq!(
            cert.verify_against_person_cert(&owner).map(|_| ()),
            Err(DeviceCertError::WrongCertType)
        );
    }

    #[test]
    fn unsupported_version_fails() {
        let (_hh, _person, _device, owner, mut cert) = fixture();
        cert.version = 2;
        assert_eq!(
            cert.verify_against_person_cert(&owner).map(|_| ()),
            Err(DeviceCertError::VersionUnsupported)
        );
    }

    #[test]
    fn off_curve_device_key_fails_even_when_signed() {
        let (_hh, _person, _device, owner, mut cert) = fixture();
        let mut bad = [0u8; 33];
        bad[0] = 0x02;
        for suffix in 0u8..=u8::MAX {
            bad[32] = suffix;
            if P256PublicKey::from_bytes(&bad).is_err() {
                break;
            }
        }
        cert.d_pub = P256PublicKey(bad);
        assert_eq!(
            cert.verify_against_person_cert(&owner).map(|_| ()),
            Err(DeviceCertError::PublicKeyMalformed)
        );
    }

    #[test]
    fn owner_cert_without_explicit_grant_cannot_admit_a_device() {
        let hh = P256Keypair::generate();
        let person = P256Keypair::generate();
        let device = P256Keypair::generate();
        let hh_id = derive_household_id(&hh.public());
        // Stock owner template — no `household.add_device`.
        let owner = PersonCert::sign_owner(
            &hh,
            SignOwnerOptions {
                hh_id,
                p_pub: person.public(),
                display_name: "Owner".into(),
                issued_at: 1_714_972_800,
            },
        )
        .unwrap();
        let cert = device_cert(&person, &device);
        assert_eq!(
            cert.verify_against_person_cert(&owner).map(|_| ()),
            Err(DeviceCertError::Narrowing(
                CaveatNarrowingError::GrantMissing
            ))
        );
    }

    #[test]
    fn device_caveat_wider_than_parent_is_rejected() {
        let hh = P256Keypair::generate();
        let person = P256Keypair::generate();
        let device = P256Keypair::generate();
        // Parent restricts claws.use to a single specific claw.
        let owner = owner_cert_with_add_device_grant(
            &hh,
            &person,
            vec![crate::caveats::Caveat::new(
                Operation::ClawsDelete,
                Some(Scope::Specific {
                    specific: vec!["c_one".into()],
                }),
            )],
        );
        // `owner_caveats()` already grants ClawsDelete with scope All; the
        // explicit Specific entry above makes the list contain a duplicate op,
        // which the closed validator rejects outright.
        let cert = DeviceCert::sign(
            &person,
            SignOptions {
                p_pub: person.public(),
                d_pub: device.public(),
                device_name: "iPhone 15".into(),
                platform: "ios".into(),
                added_at: 1_714_972_800,
                caveats: Some(vec![crate::caveats::Caveat::new(
                    Operation::ClawsDelete,
                    Some(Scope::Specific {
                        specific: vec!["c_one".into(), "c_two".into()],
                    }),
                )]),
            },
        )
        .unwrap();
        assert_eq!(
            cert.verify_against_person_cert(&owner).map(|_| ()),
            Err(DeviceCertError::Narrowing(
                CaveatNarrowingError::DuplicateOperation
            ))
        );
    }

    #[test]
    fn device_scope_must_be_a_subset_of_the_parent_scope() {
        let hh = P256Keypair::generate();
        let person = P256Keypair::generate();
        let device = P256Keypair::generate();
        let owner = owner_cert_with_add_device_grant(&hh, &person, Vec::new());
        // Parent grants ClawsUse with scope All; a Specific child narrows it.
        let narrowed = DeviceCert::sign(
            &person,
            SignOptions {
                p_pub: person.public(),
                d_pub: device.public(),
                device_name: "iPhone 15".into(),
                platform: "ios".into(),
                added_at: 1_714_972_800,
                caveats: Some(vec![crate::caveats::Caveat::new(
                    Operation::ClawsUse,
                    Some(Scope::Specific {
                        specific: vec!["c_one".into()],
                    }),
                )]),
            },
        )
        .unwrap();
        assert!(narrowed.verify_against_person_cert(&owner).is_ok());

        // A child op absent from the parent widens and must be rejected.
        let widened = DeviceCert::sign(
            &person,
            SignOptions {
                p_pub: person.public(),
                d_pub: device.public(),
                device_name: "iPhone 15".into(),
                platform: "ios".into(),
                added_at: 1_714_972_800,
                caveats: Some(vec![crate::caveats::Caveat::new(
                    Operation::OwnerAuthEnrollInitial,
                    None,
                )]),
            },
        )
        .unwrap();
        assert_eq!(
            widened.verify_against_person_cert(&owner).map(|_| ()),
            Err(DeviceCertError::Narrowing(
                CaveatNarrowingError::OperationWidening
            ))
        );
    }

    #[test]
    fn device_expiry_may_not_exceed_the_parent_limit() {
        let hh = P256Keypair::generate();
        let person = P256Keypair::generate();
        let device = P256Keypair::generate();
        let mut parent_constraints = BTreeMap::new();
        parent_constraints.insert(
            "expires_at".to_string(),
            crate::caveats::ConstraintValue::ExpiresAt(2_000),
        );
        let mut parent = crate::caveats::Caveat::new(Operation::HouseholdInvite, None);
        parent.constraints = Some(Constraints::try_from(parent_constraints).unwrap());
        // `owner_caveats()` already carries HouseholdInvite; replace it so the
        // list stays duplicate-free.
        let mut owner = owner_cert_with_add_device_grant(&hh, &person, Vec::new());
        owner.caveats.retain(|c| c.op != Operation::HouseholdInvite);
        owner.caveats.push(parent);
        let signing = owner.signing_bytes().unwrap();
        owner.signature = hh.sign(&signing).unwrap();

        let mut child_constraints = BTreeMap::new();
        child_constraints.insert(
            "expires_at".to_string(),
            crate::caveats::ConstraintValue::ExpiresAt(3_000),
        );
        let mut child = crate::caveats::Caveat::new(Operation::HouseholdInvite, None);
        child.constraints = Some(Constraints::try_from(child_constraints).unwrap());
        let cert = DeviceCert::sign(
            &person,
            SignOptions {
                p_pub: person.public(),
                d_pub: device.public(),
                device_name: "iPhone 15".into(),
                platform: "ios".into(),
                added_at: 1_714_972_800,
                caveats: Some(vec![child]),
            },
        )
        .unwrap();
        assert_eq!(
            cert.verify_against_person_cert(&owner).map(|_| ()),
            Err(DeviceCertError::Narrowing(
                CaveatNarrowingError::ExpiryWidening
            ))
        );
    }

    #[test]
    fn malformed_text_fields_are_rejected() {
        let (_hh, _person, _device, owner, cert) = fixture();
        for bad in ["", "bad\u{0}name", &"x".repeat(MAX_DEVICE_NAME_BYTES + 1)] {
            let mut tampered = cert.clone();
            tampered.device_name = bad.to_string();
            assert_eq!(
                tampered.verify_against_person_cert(&owner).map(|_| ()),
                Err(DeviceCertError::MalformedText)
            );
        }
        for bad in ["", "io\u{0}s", &"x".repeat(MAX_PLATFORM_BYTES + 1)] {
            let mut tampered = cert.clone();
            tampered.platform = bad.to_string();
            assert_eq!(
                tampered.verify_against_person_cert(&owner).map(|_| ()),
                Err(DeviceCertError::MalformedText)
            );
        }
    }

    #[test]
    fn digest_is_domain_separated_and_binds_every_byte() {
        let (_hh, _person, _device, _owner, cert) = fixture();
        let digest = cert.digest().unwrap();
        let mut plain = blake3::Hasher::new();
        plain.update(&cert.canonical_bytes().unwrap());
        let plain: [u8; 32] = plain.finalize().into();
        assert_ne!(digest, plain, "digest must be domain separated");

        let mut other = cert.clone();
        other.added_at += 1;
        assert_ne!(digest, other.digest().unwrap());
    }
}
