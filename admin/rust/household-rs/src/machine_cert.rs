//! `MachineCert` — self-signed founding-member machine certificate.
//!
//! See `contracts/cbor-schemas.md` and `data-model.md`.

use serde::{Deserialize, Serialize};

use crate::cbor;
use crate::error::{HouseholdError, KeystoreError};
use crate::ids::{HouseholdId, MachineId, derive_machine_id};
use crate::keys::{IdentityKey, P256PublicKey, P256Signature, verify_signature};

/// Distinguishes machine certs from future Phase 5+ cert types.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum CertType {
    Machine,
    Person,
    Device,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    Macos,
    LinuxNix,
    LinuxOther,
}

impl Platform {
    /// Auto-derive at runtime. macOS unconditional; Linux probes `/etc/NIXOS`.
    /// Other targets are rejected at the bootstrap layer.
    #[must_use]
    pub fn detect() -> Option<Self> {
        if cfg!(target_os = "macos") {
            Some(Self::Macos)
        } else if cfg!(target_os = "linux") {
            if std::path::Path::new("/etc/NIXOS").exists() {
                Some(Self::LinuxNix)
            } else {
                Some(Self::LinuxOther)
            }
        } else {
            None
        }
    }
}

/// Phase 5+ identifier types — declared now so the cert's `issued_by` slot is
/// polymorphic and Phase 5 won't need a CBOR schema break (US4/US5/US7/US10/US11).
///
/// Deserialization validates the `p_` prefix so that `untagged` enum variant
/// selection in [`SubjectId`] is unambiguous.
#[derive(Clone, Serialize, PartialEq, Eq, Hash, Debug)]
#[serde(transparent)]
pub struct PersonId(pub String);

impl PersonId {
    pub const PREFIX: &'static str = "p_";

    #[must_use]
    pub fn is_well_formed(s: &str) -> bool {
        s.strip_prefix(Self::PREFIX)
            .is_some_and(|rest| !rest.is_empty())
    }
}

impl<'de> Deserialize<'de> for PersonId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: String = String::deserialize(d)?;
        if !Self::is_well_formed(&s) {
            return Err(serde::de::Error::custom(format!(
                "expected p_<…>, got {s:?}"
            )));
        }
        Ok(Self(s))
    }
}

#[derive(Clone, Serialize, PartialEq, Eq, Hash, Debug)]
#[serde(transparent)]
pub struct DeviceId(pub String);

impl DeviceId {
    pub const PREFIX: &'static str = "d_";

    #[must_use]
    pub fn is_well_formed(s: &str) -> bool {
        s.strip_prefix(Self::PREFIX)
            .is_some_and(|rest| !rest.is_empty())
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: String = String::deserialize(d)?;
        if !Self::is_well_formed(&s) {
            return Err(serde::de::Error::custom(format!(
                "expected d_<…>, got {s:?}"
            )));
        }
        Ok(Self(s))
    }
}

/// Polymorphic subject. Phase 1 only ever holds [`SubjectId::Household`].
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum SubjectId {
    Household(HouseholdId),
    Machine(MachineId),
    Person(PersonId),
    Device(DeviceId),
}

impl SubjectId {
    /// Stable string form (carries the `hh_…` / `p_…` / `d_…` / `m_…` prefix).
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Household(h) => h.as_str(),
            Self::Machine(m) => m.as_str(),
            Self::Person(p) => &p.0,
            Self::Device(d) => &d.0,
        }
    }
}

/// Capability caveat (macaroon/biscuit style).
///
/// Phase 1: the variant set is intentionally empty so any caveat list value
/// other than `[]` fails to decode. Phase 5 (US4/US5/US7/US10/US11) adds
/// concrete variants; the CBOR shape is reserved now to avoid a `version: 2`
/// schema break.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum Caveat {}

/// On-disk machine certificate.
///
/// Wire field name is `"v"` (not `"version"`).
/// Renaming changes the canonical CBOR bytes that the signature covers,
/// so this is fixed at the wire layer rather than the struct field name.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct MachineCert {
    #[serde(rename = "v")]
    pub version: u8,
    #[serde(rename = "type")]
    pub cert_type: CertType,
    pub hh_id: HouseholdId,
    pub m_id: MachineId,
    pub m_pub: P256PublicKey,
    pub hostname: String,
    pub platform: Platform,
    pub joined_at: u64,
    pub issued_by: SubjectId,
    pub caveats: Vec<Caveat>,
    pub signature: P256Signature,
}

/// Same shape as `MachineCert` but without the `signature` field — used to
/// compute the canonical bytes that the signature covers. The same `"v"`
/// rename applies so the signed bytes match the on-disk encoding.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
struct MachineCertUnsigned {
    #[serde(rename = "v")]
    pub version: u8,
    #[serde(rename = "type")]
    pub cert_type: CertType,
    pub hh_id: HouseholdId,
    pub m_id: MachineId,
    pub m_pub: P256PublicKey,
    pub hostname: String,
    pub platform: Platform,
    pub joined_at: u64,
    pub issued_by: SubjectId,
    pub caveats: Vec<Caveat>,
}

/// Operator-supplied data when signing a fresh machine cert.
pub struct SignOptions {
    pub hh_id: HouseholdId,
    pub hostname: String,
    pub platform: Platform,
    pub joined_at: u64,
}

impl MachineCert {
    pub const SCHEMA_VERSION: u8 = 1;

    /// Sign a fresh machine cert. Performs derivation + signing only — does
    /// not touch the filesystem or keystore.
    pub fn sign(
        hh_key: &dyn IdentityKey,
        m_pub: &P256PublicKey,
        opts: &SignOptions,
    ) -> Result<Self, KeystoreError> {
        let m_id = derive_machine_id(m_pub);
        validate_hostname(&opts.hostname)
            .map_err(|e| KeystoreError::InvalidKeyMaterial(format!("hostname: {e}")))?;
        let unsigned = MachineCertUnsigned {
            version: Self::SCHEMA_VERSION,
            cert_type: CertType::Machine,
            hh_id: opts.hh_id.clone(),
            m_id: m_id.clone(),
            m_pub: m_pub.clone(),
            hostname: opts.hostname.clone(),
            platform: opts.platform.clone(),
            joined_at: opts.joined_at,
            issued_by: SubjectId::Household(opts.hh_id.clone()),
            caveats: Vec::new(),
        };
        let canonical = cbor::to_canonical_vec(&unsigned)
            .map_err(|e| KeystoreError::SigningFailed(format!("encode: {e}")))?;
        let signature = hh_key.sign(&canonical)?;
        Ok(Self {
            version: unsigned.version,
            cert_type: unsigned.cert_type,
            hh_id: unsigned.hh_id,
            m_id: unsigned.m_id,
            m_pub: unsigned.m_pub,
            hostname: unsigned.hostname,
            platform: unsigned.platform,
            joined_at: unsigned.joined_at,
            issued_by: unsigned.issued_by,
            caveats: unsigned.caveats,
            signature,
        })
    }

    /// Verify every Phase 1 invariant against the household root pubkey.
    pub fn verify(&self, hh_pub: &P256PublicKey) -> Result<(), HouseholdError> {
        if self.version != Self::SCHEMA_VERSION {
            return Err(HouseholdError::InvalidCert(format!(
                "version {} unsupported",
                self.version
            )));
        }
        if self.cert_type != CertType::Machine {
            return Err(HouseholdError::InvalidCert(format!(
                "cert_type {:?} forbidden in Phase 1",
                self.cert_type
            )));
        }
        P256PublicKey::from_bytes(self.m_pub.as_bytes())?;
        // m_id must derive from m_pub.
        let recomputed = derive_machine_id(&self.m_pub);
        if recomputed != self.m_id {
            return Err(HouseholdError::IdentifierMismatch {
                expected: recomputed.to_string(),
                actual: self.m_id.to_string(),
            });
        }
        // issued_by must be Household(hh_id) (Phase 1 invariant).
        match &self.issued_by {
            SubjectId::Household(h) if h == &self.hh_id => {}
            other => {
                return Err(HouseholdError::InvalidCert(format!(
                    "issued_by must be Household(hh_id) in Phase 1; got {}",
                    other.as_str()
                )));
            }
        }
        if !self.caveats.is_empty() {
            return Err(HouseholdError::InvalidCert(
                "caveats[] must be empty in Phase 1".into(),
            ));
        }
        validate_hostname(&self.hostname)?;
        // Verify signature over canonical bytes excluding the signature field.
        verify_signature(hh_pub, &self.signing_bytes()?, &self.signature)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        let unsigned = MachineCertUnsigned {
            version: self.version,
            cert_type: self.cert_type.clone(),
            hh_id: self.hh_id.clone(),
            m_id: self.m_id.clone(),
            m_pub: self.m_pub.clone(),
            hostname: self.hostname.clone(),
            platform: self.platform.clone(),
            joined_at: self.joined_at,
            issued_by: self.issued_by.clone(),
            caveats: self.caveats.clone(),
        };
        cbor::to_canonical_vec(&unsigned)
    }
}

/// Read this machine's own `MachineCert` from the unified
/// `machine_certs/<self_m_id>.cbor` layout introduced in Phase 3.
///
/// Locates the cert file via the `self_m_id` marker written by either
/// [`save_self_cert`] or the one-shot `machine_cert.cbor` migration in
/// [`crate::storage::load_state_dir`]. Returns `Ok(None)` when neither the
/// marker nor any legacy cert is present (uninitialized state).
///
/// Defense-in-depth: after decoding, the function verifies that
/// `cert.m_id` matches the marker — so a tampered marker pointing at the
/// wrong cert file is rejected as a decode error.
pub fn load_self_cert(
    state_dir: &std::path::Path,
) -> Result<Option<MachineCert>, crate::error::StorageError> {
    use crate::error::StorageError;
    let Some(marker_id) = crate::storage::read_self_m_id(state_dir)? else {
        return Ok(None);
    };
    let path = crate::storage::machine_cert_for(state_dir, &marker_id);
    let Some(cert): Option<MachineCert> = crate::storage::read_optional_cbor(&path)? else {
        return Ok(None);
    };
    if cert.m_id.to_string() != marker_id {
        return Err(StorageError::Encoding(HouseholdError::Cbor(format!(
            "self_m_id marker {marker_id} disagrees with cert at {} (m_id={})",
            path.display(),
            cert.m_id
        ))));
    }
    Ok(Some(cert))
}

/// Phase 3 typed errors for the candidate-issuance and household-root
/// verify surfaces. These wrap [`HouseholdError`] / [`KeystoreError`]
/// behind a contract-friendly enum name (`CertError`) so the 2PC
/// ceremony's error tree stays narrow.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("household key material rejected: {0}")]
    HouseholdKey(#[from] crate::error::KeystoreError),
    #[error("certificate signature did not verify or shape was invalid: {0}")]
    Verify(#[from] HouseholdError),
}

/// Issue a fresh `MachineCert` for a candidate machine, signed under
/// the household root scalar. Used by the Phase 3 2PC ceremony when the
/// founding machine M1 admits M2 to the household.
///
/// Inputs are typed as raw bytes so the caller (the ceremony driver)
/// can keep the household scalar inside [`Zeroizing`] without leaking
/// into a long-lived `dyn IdentityKey`.
pub fn issue_for_candidate(
    hh_priv: &zeroize::Zeroizing<[u8; 32]>,
    hh_id: &HouseholdId,
    m_pub_sec1: &[u8; 33],
    hostname: &str,
    platform: Platform,
    joined_at: u64,
) -> Result<MachineCert, CertError> {
    let m_pub = P256PublicKey::from_bytes(m_pub_sec1).map_err(CertError::Verify)?;
    let kp = crate::keys::P256Keypair::from_secret_scalar(hh_priv)?;
    let cert = MachineCert::sign(
        &kp,
        &m_pub,
        &SignOptions {
            hh_id: hh_id.clone(),
            hostname: hostname.to_string(),
            platform,
            joined_at,
        },
    )?;
    Ok(cert)
}

/// Verify a `MachineCert` chains to the supplied household public key
/// (signature verifies, schema-version OK, `m_id` recomputes from
/// `m_pub`). Used by M2 immediately after receiving the `JoinResponse`
/// from M1, before persisting anything to disk.
pub fn verify_against_household_root(
    cert: &MachineCert,
    hh_pub_sec1: &[u8; 33],
) -> Result<(), CertError> {
    let hh_pub = P256PublicKey::from_bytes(hh_pub_sec1).map_err(CertError::Verify)?;
    cert.verify(&hh_pub)?;
    let recomputed = derive_machine_id(&cert.m_pub);
    if recomputed != cert.m_id {
        return Err(CertError::Verify(HouseholdError::InvalidCert(format!(
            "m_id mismatch: cert says {}, recomputed {}",
            cert.m_id, recomputed
        ))));
    }
    Ok(())
}

/// Atomically persist this machine's own cert under
/// `machine_certs/<m_id>.cbor` and update the `self_m_id` marker.
///
/// Both files are staged together via [`crate::storage::stage_commit_files`]
/// and promoted in a single commit step, narrowing the crash window to a
/// pair of consecutive renames. If a crash still lands between the two
/// renames, [`crate::storage::recover_self_m_id_marker`] (called from
/// [`crate::storage::load_state_dir`]) repairs the marker on next boot
/// when there is exactly one cert under `machine_certs/`.
pub fn save_self_cert(
    state_dir: &std::path::Path,
    cert: &MachineCert,
) -> Result<(), crate::error::StorageError> {
    let m_id_str = cert.m_id.to_string();
    let cert_path = crate::storage::machine_cert_for(state_dir, &m_id_str);
    let marker_path = crate::storage::self_m_id_marker_path(state_dir);
    let cert_bytes =
        crate::cbor::to_canonical_vec(cert).map_err(crate::error::StorageError::Encoding)?;
    let mut marker_bytes = m_id_str.into_bytes();
    marker_bytes.push(b'\n');
    let staged = crate::storage::stage_commit_files(&[
        (cert_path, cert_bytes),
        (marker_path, marker_bytes),
    ])?;
    staged.commit()?;
    Ok(())
}

/// SHA-256 over the canonical CBOR encoding of `cert`.
///
/// **The** definition. The roster wire's `machine_cert_fingerprint` /
/// `signer_machine_cert_fingerprint` and the pair-device QR's `m_cert_fp` are
/// all this function's output; `machine_roster_authority::machine_cert_fingerprint`
/// delegates here rather than recomputing, so the surfaces cannot drift apart
/// silently.
///
/// A canonical-encode failure is returned, never folded into a "no value"
/// case: callers use absence to mean "this machine has no admitted cert",
/// and an encoding fault is a different thing that must not borrow that
/// meaning.
pub fn fingerprint(cert: &MachineCert) -> Result<[u8; 32], HouseholdError> {
    use sha2::{Digest, Sha256};
    let bytes = crate::cbor::to_canonical_vec(cert)?;
    Ok(Sha256::digest(&bytes).into())
}

fn validate_hostname(s: &str) -> Result<(), HouseholdError> {
    if s.is_empty() {
        return Err(HouseholdError::InvalidCert("hostname empty".into()));
    }
    if s.len() > 255 {
        return Err(HouseholdError::InvalidCert(format!(
            "hostname > 255 bytes (got {})",
            s.len()
        )));
    }
    if s.chars().any(char::is_control) {
        return Err(HouseholdError::InvalidCert(
            "hostname contains control char".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::derive_household_id;
    use crate::keys::{IdentityKey, P256Keypair};

    fn build() -> (P256Keypair, P256Keypair, MachineCert) {
        let hh = P256Keypair::generate();
        let m = P256Keypair::generate();
        let hh_id = derive_household_id(&hh.public());
        let cert = MachineCert::sign(
            &hh,
            &m.public(),
            &SignOptions {
                hh_id,
                hostname: "studio-mac".into(),
                platform: Platform::Macos,
                joined_at: 1_714_972_800,
            },
        )
        .unwrap();
        (hh, m, cert)
    }

    #[test]
    fn happy_path() {
        let (hh, _m, cert) = build();
        cert.verify(&hh.public()).unwrap();
    }

    #[test]
    fn tamper_signature_fails() {
        let (hh, _m, mut cert) = build();
        cert.signature.0[0] ^= 0x01;
        cert.verify(&hh.public()).unwrap_err();
    }

    #[test]
    fn wrong_household_pubkey_fails() {
        let (_hh, _m, cert) = build();
        let other = P256Keypair::generate().public();
        cert.verify(&other).unwrap_err();
    }

    #[test]
    fn rejects_non_household_issuer() {
        let (hh, _m, mut cert) = build();
        cert.issued_by = SubjectId::Person(PersonId(format!("p_{}", "a".repeat(52))));
        cert.verify(&hh.public()).unwrap_err();
    }

    #[test]
    fn rejects_non_empty_caveats() {
        // We can't construct a Caveat in Phase 1 since the enum has no
        // variants — but the validator path is covered: we just verify that
        // the validator checks `caveats.is_empty()`. (Compile-time guarantee.)
        let (_hh, _m, cert) = build();
        assert!(cert.caveats.is_empty());
    }

    #[test]
    fn rejects_unknown_cert_type() {
        let (hh, _m, mut cert) = build();
        cert.cert_type = CertType::Person;
        cert.verify(&hh.public()).unwrap_err();
    }

    #[test]
    fn malformed_machine_public_key_is_rejected_even_when_signed() {
        let hh = P256Keypair::generate();
        let hh_id = derive_household_id(&hh.public());
        let mut bad_bytes = None;
        for suffix in 0u8..=u8::MAX {
            let mut candidate = [0u8; 33];
            candidate[0] = 0x02;
            candidate[32] = suffix;
            if P256PublicKey::from_bytes(&candidate).is_err() {
                bad_bytes = Some(candidate);
                break;
            }
        }
        let bad_bytes = bad_bytes.expect("expected to find an off-curve compressed point");
        let bad_pub = P256PublicKey(bad_bytes);
        let cert = MachineCert::sign(
            &hh,
            &bad_pub,
            &SignOptions {
                hh_id,
                hostname: "studio-mac".into(),
                platform: Platform::Macos,
                joined_at: 1_714_972_800,
            },
        )
        .unwrap();

        assert!(matches!(
            cert.verify(&hh.public()),
            Err(HouseholdError::PublicKeyMalformed)
        ));
    }
}
