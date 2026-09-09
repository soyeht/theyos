use serde::de::{self, Deserializer, Unexpected};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::ids::{HouseholdId, MachineId};
use crate::keys::{P256PublicKey, P256Signature};
use crate::machine_cert::PersonId;

pub(crate) const REVOCATION_KIND: &str = "household-machine-roster-revocation/v1";
pub(crate) const CHECKPOINT_KIND: &str = "household-machine-roster-checkpoint/v1";
pub(crate) const REVOCATION_VERSION: u8 = 1;
pub(crate) const CHECKPOINT_VERSION: u8 = 1;

// ─── Strict bstr helpers (bstr-only; reject CBOR array/null) ────────────────

pub(crate) mod bstr32 {
    use serde::de::{self, Deserializer, Visitor};
    use serde::ser::Serializer;
    use std::fmt;
    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(b)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = [u8; 32];
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a byte string of exactly 32 bytes")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<[u8; 32], E> {
                if v.len() != 32 {
                    return Err(E::custom(format!("expected 32 bytes, got {}", v.len())));
                }
                let mut o = [0u8; 32];
                o.copy_from_slice(v);
                Ok(o)
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<[u8; 32], E> {
                self.visit_bytes(&v)
            }
        }
        d.deserialize_bytes(V)
    }
}

pub(crate) mod bstr33_key {
    use crate::keys::P256PublicKey;
    use serde::de::{self, Deserializer, Visitor};
    use serde::ser::Serializer;
    use std::fmt;
    pub fn serialize<S: Serializer>(k: &P256PublicKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&k.0)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<P256PublicKey, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = P256PublicKey;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a byte string of exactly 33 bytes (P-256 compressed)")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<P256PublicKey, E> {
                P256PublicKey::from_bytes(v).map_err(|e| E::custom(format!("P256PublicKey: {e}")))
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<P256PublicKey, E> {
                self.visit_bytes(&v)
            }
        }
        d.deserialize_bytes(V)
    }
}

pub(crate) mod bstr64_sig {
    use crate::keys::P256Signature;
    use serde::de::{self, Deserializer, Visitor};
    use serde::ser::Serializer;
    use std::fmt;
    pub fn serialize<S: Serializer>(sig: &P256Signature, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&sig.0)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<P256Signature, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = P256Signature;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a byte string of exactly 64 bytes (P-256 ECDSA r||s)")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<P256Signature, E> {
                P256Signature::from_bytes(v).map_err(|e| E::custom(format!("P256Signature: {e}")))
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<P256Signature, E> {
                self.visit_bytes(&v)
            }
        }
        d.deserialize_bytes(V)
    }
}

pub(crate) mod bstr_var {
    use serde::de::{self, Deserializer, Visitor};
    use serde::ser::Serializer;
    use std::fmt;
    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(b)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a byte string")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
        }
        d.deserialize_bytes(V)
    }
}

// ─── Enums (manual serde uint; reject unknown) ──────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RevocationReason {
    Compromised = 0,
    Lost = 1,
    Retired = 2,
    Replaced = 3,
    OwnerAction = 4,
}

impl Serialize for RevocationReason {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(*self as u8)
    }
}
impl<'de> Deserialize<'de> for RevocationReason {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match u8::deserialize(d)? {
            0 => Ok(Self::Compromised),
            1 => Ok(Self::Lost),
            2 => Ok(Self::Retired),
            3 => Ok(Self::Replaced),
            4 => Ok(Self::OwnerAction),
            o => Err(de::Error::invalid_value(
                Unexpected::Unsigned(u64::from(o)),
                &"0..=4",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RevocationCascade {
    MachineOnly = 0,
    MachineAndDependents = 1,
}

impl Serialize for RevocationCascade {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(*self as u8)
    }
}
impl<'de> Deserialize<'de> for RevocationCascade {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match u8::deserialize(d)? {
            0 => Ok(Self::MachineOnly),
            1 => Ok(Self::MachineAndDependents),
            o => Err(de::Error::invalid_value(
                Unexpected::Unsigned(u64::from(o)),
                &"0 or 1",
            )),
        }
    }
}

// ─── MachineRosterMemberV1 (§8: 4 keys) ─────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineRosterMemberV1 {
    pub m_id: MachineId,
    #[serde(with = "bstr33_key")]
    pub m_pub: P256PublicKey,
    #[serde(with = "bstr_var")]
    pub machine_cert: Vec<u8>,
    #[serde(with = "bstr32")]
    pub machine_cert_fingerprint: [u8; 32],
}

// ─── MachineRosterRevocationV1 (§7: 16 keys) ────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineRosterRevocationV1 {
    pub v: u8,
    pub kind: String,
    pub hh_id: HouseholdId,
    #[serde(with = "bstr32")]
    pub epoch: [u8; 32],
    pub sequence: u64,
    #[serde(with = "bstr32")]
    pub prev_event_hash: [u8; 32],
    pub m_id: MachineId,
    #[serde(with = "bstr33_key")]
    pub m_pub: P256PublicKey,
    #[serde(with = "bstr32")]
    pub machine_cert_fingerprint: [u8; 32],
    pub revoked_at: u64,
    pub reason: RevocationReason,
    pub cascade: RevocationCascade,
    pub owner_p_id: PersonId,
    #[serde(with = "bstr32")]
    pub owner_cert_fingerprint: [u8; 32],
    #[serde(with = "bstr_var")]
    pub owner_person_cert: Vec<u8>,
    #[serde(with = "bstr64_sig")]
    pub signature: P256Signature,
}

// ─── MachineRosterCheckpointV1 (§9: 17 keys) ────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineRosterCheckpointV1 {
    pub v: u8,
    pub kind: String,
    pub hh_id: HouseholdId,
    #[serde(with = "bstr32")]
    pub epoch: [u8; 32],
    pub checkpoint_sequence: u64,
    #[serde(with = "bstr32")]
    pub prev_checkpoint_hash: [u8; 32],
    pub event_sequence: u64,
    #[serde(with = "bstr32")]
    pub event_head_hash: [u8; 32],
    #[serde(with = "bstr32")]
    pub mesh_log_digest: [u8; 32],
    pub issued_at: u64,
    pub not_after: u64,
    pub owner_p_id: PersonId,
    #[serde(with = "bstr32")]
    pub owner_cert_fingerprint: [u8; 32],
    pub active: Vec<MachineRosterMemberV1>,
    pub revocations: Vec<MachineRosterRevocationV1>,
    #[serde(with = "bstr_var")]
    pub owner_person_cert: Vec<u8>,
    #[serde(with = "bstr64_sig")]
    pub signature: P256Signature,
}

// ─── Schema validation (version/kind gate) ──────────────────────────────────

impl MachineRosterRevocationV1 {
    #[must_use]
    pub fn has_valid_schema(&self) -> bool {
        self.v == REVOCATION_VERSION && self.kind == REVOCATION_KIND
    }
}

impl MachineRosterCheckpointV1 {
    #[must_use]
    pub fn has_valid_schema(&self) -> bool {
        self.v == CHECKPOINT_VERSION && self.kind == CHECKPOINT_KIND
    }
}

// ─── CORE-CP2: Crypto / Authority ───────────────────────────────────────────

const REVOCATION_DOMAIN: &[u8] = b"soyeht/household-machine-roster-revocation/v1\x00";
const CHECKPOINT_DOMAIN: &[u8] = b"soyeht/household-machine-roster-checkpoint/v1\x00";
#[cfg(test)]
const EPOCH_DOMAIN: &[u8] = b"soyeht/household-machine-roster-epoch/v1\x00";

// ─── Typed errors (closed; no String catch-all) ─────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RosterCryptoError {
    CborEncode,
    CborDecode,
    #[cfg(test)]
    SignFailed,
    SignatureRejected,
    SchemaInvalid,
    CertDecode,
    CertNotCanonical,
    OwnerCertInvalid,
    WeakProvenance,
    HouseholdMismatch,
    OwnerIdMismatch,
    OwnerPubMismatch,
    #[cfg(test)]
    SignerPubMismatch,
    MissingCaveatAddMachine,
    MissingCaveatRevoke,
    FingerprintMismatch,
    MachineCertInvalid,
    MachineCertNotCanonical,
    MachineIdMismatch,
    MachinePubMismatch,
    MachineFingerprintMismatch,
    MachineHouseholdMismatch,
}

// ─── Private unsigned mirrors ───────────────────────────────────────────────

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RevocationUnsigned<'a> {
    v: u8,
    kind: &'a str,
    hh_id: &'a HouseholdId,
    #[serde(with = "bstr32")]
    epoch: &'a [u8; 32],
    sequence: u64,
    #[serde(with = "bstr32")]
    prev_event_hash: &'a [u8; 32],
    m_id: &'a MachineId,
    #[serde(with = "bstr33_key")]
    m_pub: &'a P256PublicKey,
    #[serde(with = "bstr32")]
    machine_cert_fingerprint: &'a [u8; 32],
    revoked_at: u64,
    reason: &'a RevocationReason,
    cascade: &'a RevocationCascade,
    owner_p_id: &'a PersonId,
    #[serde(with = "bstr32")]
    owner_cert_fingerprint: &'a [u8; 32],
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointUnsigned<'a> {
    v: u8,
    kind: &'a str,
    hh_id: &'a HouseholdId,
    #[serde(with = "bstr32")]
    epoch: &'a [u8; 32],
    checkpoint_sequence: u64,
    #[serde(with = "bstr32")]
    prev_checkpoint_hash: &'a [u8; 32],
    event_sequence: u64,
    #[serde(with = "bstr32")]
    event_head_hash: &'a [u8; 32],
    #[serde(with = "bstr32")]
    mesh_log_digest: &'a [u8; 32],
    issued_at: u64,
    not_after: u64,
    owner_p_id: &'a PersonId,
    #[serde(with = "bstr32")]
    owner_cert_fingerprint: &'a [u8; 32],
    active: &'a [MachineRosterMemberV1],
    revocations: &'a [MachineRosterRevocationV1],
}

// ─── Schema gate (private) ──────────────────────────────────────────────────

fn check_revocation_schema(r: &MachineRosterRevocationV1) -> Result<(), RosterCryptoError> {
    if r.v != REVOCATION_VERSION || r.kind != REVOCATION_KIND {
        return Err(RosterCryptoError::SchemaInvalid);
    }
    Ok(())
}

fn check_checkpoint_schema(c: &MachineRosterCheckpointV1) -> Result<(), RosterCryptoError> {
    if c.v != CHECKPOINT_VERSION || c.kind != CHECKPOINT_KIND {
        return Err(RosterCryptoError::SchemaInvalid);
    }
    Ok(())
}

// ─── Preimage / hash (pub(crate); schema-gated) ─────────────────────────────

fn revocation_unsigned_cbor(r: &MachineRosterRevocationV1) -> Result<Vec<u8>, RosterCryptoError> {
    let u = RevocationUnsigned {
        v: r.v,
        kind: &r.kind,
        hh_id: &r.hh_id,
        epoch: &r.epoch,
        sequence: r.sequence,
        prev_event_hash: &r.prev_event_hash,
        m_id: &r.m_id,
        m_pub: &r.m_pub,
        machine_cert_fingerprint: &r.machine_cert_fingerprint,
        revoked_at: r.revoked_at,
        reason: &r.reason,
        cascade: &r.cascade,
        owner_p_id: &r.owner_p_id,
        owner_cert_fingerprint: &r.owner_cert_fingerprint,
    };
    crate::cbor::to_canonical_vec(&u).map_err(|_| RosterCryptoError::CborEncode)
}

pub(crate) fn revocation_preimage(
    r: &MachineRosterRevocationV1,
) -> Result<Vec<u8>, RosterCryptoError> {
    check_revocation_schema(r)?;
    let cbor_bytes = revocation_unsigned_cbor(r)?;
    let mut preimage = Vec::with_capacity(REVOCATION_DOMAIN.len() + cbor_bytes.len());
    preimage.extend_from_slice(REVOCATION_DOMAIN);
    preimage.extend_from_slice(&cbor_bytes);
    Ok(preimage)
}

pub(crate) fn revocation_event_hash(
    r: &MachineRosterRevocationV1,
) -> Result<[u8; 32], RosterCryptoError> {
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(&revocation_preimage(r)?).into())
}

fn checkpoint_unsigned_cbor(c: &MachineRosterCheckpointV1) -> Result<Vec<u8>, RosterCryptoError> {
    let u = CheckpointUnsigned {
        v: c.v,
        kind: &c.kind,
        hh_id: &c.hh_id,
        epoch: &c.epoch,
        checkpoint_sequence: c.checkpoint_sequence,
        prev_checkpoint_hash: &c.prev_checkpoint_hash,
        event_sequence: c.event_sequence,
        event_head_hash: &c.event_head_hash,
        mesh_log_digest: &c.mesh_log_digest,
        issued_at: c.issued_at,
        not_after: c.not_after,
        owner_p_id: &c.owner_p_id,
        owner_cert_fingerprint: &c.owner_cert_fingerprint,
        active: &c.active,
        revocations: &c.revocations,
    };
    crate::cbor::to_canonical_vec(&u).map_err(|_| RosterCryptoError::CborEncode)
}

pub(crate) fn checkpoint_preimage(
    c: &MachineRosterCheckpointV1,
) -> Result<Vec<u8>, RosterCryptoError> {
    check_checkpoint_schema(c)?;
    let cbor_bytes = checkpoint_unsigned_cbor(c)?;
    let mut preimage = Vec::with_capacity(CHECKPOINT_DOMAIN.len() + cbor_bytes.len());
    preimage.extend_from_slice(CHECKPOINT_DOMAIN);
    preimage.extend_from_slice(&cbor_bytes);
    Ok(preimage)
}

pub(crate) fn checkpoint_hash(
    c: &MachineRosterCheckpointV1,
) -> Result<[u8; 32], RosterCryptoError> {
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(&checkpoint_preimage(c)?).into())
}

// ─── Epoch derivation (§9.2) ────────────────────────────────────────────────

#[cfg(test)]
pub(crate) fn derive_epoch(
    hh_id: &HouseholdId,
    owner_p_pub: &P256PublicKey,
    nonce: &[u8; 32],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(EPOCH_DOMAIN);
    h.update(hh_id.as_str().as_bytes());
    h.update(owner_p_pub.as_bytes());
    h.update(nonce);
    h.finalize().into()
}

// ─── Cert fingerprints (pub(crate)) ─────────────────────────────────────────

pub(crate) fn owner_cert_fingerprint(
    cert: &crate::person_cert::PersonCert,
) -> Result<[u8; 32], RosterCryptoError> {
    use sha2::{Digest, Sha256};
    let bytes = crate::cbor::to_canonical_vec(cert).map_err(|_| RosterCryptoError::CborEncode)?;
    Ok(Sha256::digest(&bytes).into())
}

/// Delegates to [`crate::machine_cert::fingerprint`], which is the single
/// definition. Recomputing it here would let the roster wire and the
/// pair-device QR drift apart without any test noticing.
pub(crate) fn machine_cert_fingerprint(
    cert: &crate::machine_cert::MachineCert,
) -> Result<[u8; 32], RosterCryptoError> {
    crate::machine_cert::fingerprint(cert).map_err(|_| RosterCryptoError::CborEncode)
}

// ─── Owner cert decode (private) ────────────────────────────────────────────

fn decode_owner_cert(
    cert_bytes: &[u8],
) -> Result<crate::person_cert::PersonCert, RosterCryptoError> {
    let cert: crate::person_cert::PersonCert =
        crate::cbor::from_canonical_slice(cert_bytes).map_err(|_| RosterCryptoError::CertDecode)?;
    let reencoded =
        crate::cbor::to_canonical_vec(&cert).map_err(|_| RosterCryptoError::CborEncode)?;
    if reencoded != cert_bytes {
        return Err(RosterCryptoError::CertNotCanonical);
    }
    Ok(cert)
}

// ─── Owner authority core (private; shared by sign and verify) ──────────────

fn validate_owner_cert_core(
    cert_bytes: &[u8],
    ctx: &RosterAuthorityContext<'_>,
) -> Result<(crate::person_cert::PersonCert, [u8; 32]), RosterCryptoError> {
    let cert = decode_owner_cert(cert_bytes)?;
    // D5: structural/identity/temporal + root signature FIRST (no caveats)
    cert.verify_rooted_identity(ctx.expected_hh_id, ctx.hh_pub, ctx.effective_now)
        .map_err(|_| RosterCryptoError::OwnerCertInvalid)?;
    // Strong provenance + expected owner identity
    if !cert.has_strong_owner_provenance() {
        return Err(RosterCryptoError::WeakProvenance);
    }
    if cert.p_id != *ctx.expected_p_id {
        return Err(RosterCryptoError::OwnerIdMismatch);
    }
    if cert.p_pub != *ctx.expected_p_pub {
        return Err(RosterCryptoError::OwnerPubMismatch);
    }
    // Caveat conjunction (separate from rooted identity)
    if !crate::caveats::permits(
        &cert.caveats,
        &crate::caveats::Operation::HouseholdAddMachine,
    ) {
        return Err(RosterCryptoError::MissingCaveatAddMachine);
    }
    if !crate::caveats::permits(&cert.caveats, &crate::caveats::Operation::HouseholdRevoke) {
        return Err(RosterCryptoError::MissingCaveatRevoke);
    }
    // RC4b: all remaining baseline owner_caveats must also be present
    for caveat in crate::caveats::owner_caveats() {
        if !crate::caveats::permits(&cert.caveats, &caveat.op) {
            return Err(RosterCryptoError::OwnerCertInvalid);
        }
    }
    let computed_fp = owner_cert_fingerprint(&cert)?;
    Ok((cert, computed_fp))
}

// ─── Sign-time fail-closed (pub(crate)) ─────────────────────────────────────

#[cfg(test)]
pub(crate) fn sign_revocation(
    r: &mut MachineRosterRevocationV1,
    owner_key: &dyn crate::keys::IdentityKey,
    cert_bytes: &[u8],
    ctx: &RosterAuthorityContext<'_>,
) -> Result<(), RosterCryptoError> {
    check_revocation_schema(r)?;
    if r.hh_id != *ctx.expected_hh_id {
        return Err(RosterCryptoError::HouseholdMismatch);
    }
    let (_cert, computed_fp) = validate_owner_cert_core(cert_bytes, ctx)?;
    if owner_key.public() != *ctx.expected_p_pub {
        return Err(RosterCryptoError::SignerPubMismatch);
    }
    r.owner_p_id = ctx.expected_p_id.clone();
    r.owner_person_cert = cert_bytes.to_vec();
    r.owner_cert_fingerprint = computed_fp;
    let preimage = revocation_preimage(r)?;
    r.signature = owner_key
        .sign(&preimage)
        .map_err(|_| RosterCryptoError::SignFailed)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn sign_checkpoint(
    c: &mut MachineRosterCheckpointV1,
    owner_key: &dyn crate::keys::IdentityKey,
    cert_bytes: &[u8],
    ctx: &RosterAuthorityContext<'_>,
) -> Result<(), RosterCryptoError> {
    check_checkpoint_schema(c)?;
    if c.hh_id != *ctx.expected_hh_id {
        return Err(RosterCryptoError::HouseholdMismatch);
    }
    let (_cert, computed_fp) = validate_owner_cert_core(cert_bytes, ctx)?;
    if owner_key.public() != *ctx.expected_p_pub {
        return Err(RosterCryptoError::SignerPubMismatch);
    }
    c.owner_p_id = ctx.expected_p_id.clone();
    c.owner_person_cert = cert_bytes.to_vec();
    c.owner_cert_fingerprint = computed_fp;
    let preimage = checkpoint_preimage(c)?;
    c.signature = owner_key
        .sign(&preimage)
        .map_err(|_| RosterCryptoError::SignFailed)?;
    Ok(())
}

// ─── Verify-time authority (pub(crate); full admission) ─────────────────────

pub(crate) fn verify_revocation_authority(
    rev: &MachineRosterRevocationV1,
    ctx: &RosterAuthorityContext<'_>,
) -> Result<(), RosterCryptoError> {
    check_revocation_schema(rev)?;
    if rev.hh_id != *ctx.expected_hh_id {
        return Err(RosterCryptoError::HouseholdMismatch);
    }
    if rev.owner_p_id != *ctx.expected_p_id {
        return Err(RosterCryptoError::OwnerIdMismatch);
    }
    let (_cert, computed_fp) = validate_owner_cert_core(&rev.owner_person_cert, ctx)?;
    if computed_fp != rev.owner_cert_fingerprint {
        return Err(RosterCryptoError::FingerprintMismatch);
    }
    let preimage = revocation_preimage(rev)?;
    crate::keys::verify_signature(ctx.expected_p_pub, &preimage, &rev.signature)
        .map_err(|_| RosterCryptoError::SignatureRejected)
}

pub(crate) fn verify_checkpoint_authority(
    c: &MachineRosterCheckpointV1,
    ctx: &RosterAuthorityContext<'_>,
) -> Result<(), RosterCryptoError> {
    check_checkpoint_schema(c)?;
    if c.hh_id != *ctx.expected_hh_id {
        return Err(RosterCryptoError::HouseholdMismatch);
    }
    if c.owner_p_id != *ctx.expected_p_id {
        return Err(RosterCryptoError::OwnerIdMismatch);
    }
    let (_cert, computed_fp) = validate_owner_cert_core(&c.owner_person_cert, ctx)?;
    if computed_fp != c.owner_cert_fingerprint {
        return Err(RosterCryptoError::FingerprintMismatch);
    }
    let preimage = checkpoint_preimage(c)?;
    crate::keys::verify_signature(ctx.expected_p_pub, &preimage, &c.signature)
        .map_err(|_| RosterCryptoError::SignatureRejected)
}

// ─── Member provenance (pub(crate); provenance only, NOT currency) ──────────

pub(crate) fn validate_member_provenance(
    member: &MachineRosterMemberV1,
    hh_pub: &P256PublicKey,
    expected_hh_id: &HouseholdId,
) -> Result<crate::machine_cert::MachineCert, RosterCryptoError> {
    let cert: crate::machine_cert::MachineCert =
        crate::cbor::from_canonical_slice(&member.machine_cert)
            .map_err(|_| RosterCryptoError::CborDecode)?;
    let reencoded =
        crate::cbor::to_canonical_vec(&cert).map_err(|_| RosterCryptoError::CborEncode)?;
    if reencoded != member.machine_cert {
        return Err(RosterCryptoError::MachineCertNotCanonical);
    }
    cert.verify(hh_pub)
        .map_err(|_| RosterCryptoError::MachineCertInvalid)?;
    if cert.hh_id != *expected_hh_id {
        return Err(RosterCryptoError::MachineHouseholdMismatch);
    }
    if cert.m_id != member.m_id {
        return Err(RosterCryptoError::MachineIdMismatch);
    }
    if cert.m_pub != member.m_pub {
        return Err(RosterCryptoError::MachinePubMismatch);
    }
    let computed_fp = machine_cert_fingerprint(&cert)?;
    if computed_fp != member.machine_cert_fingerprint {
        return Err(RosterCryptoError::MachineFingerprintMismatch);
    }
    Ok(cert)
}

// ─── CORE-CP3: State / Projection / Admission / Currency ────────────────────
// M: inner==outer signer equality NOT enforced in CP3 core.
// AdmissionContext.expected_p_pub is INNER expected owner identity.
// Outer Soyeht-PoP + inner==outer deferred to compound endpoint slice.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AcceptedRosterData {
    pub epoch: [u8; 32],
    pub checkpoint_sequence: u64,
    pub checkpoint_hash: [u8; 32],
    pub prev_checkpoint_hash: [u8; 32],
    pub event_sequence: u64,
    pub event_head_hash: [u8; 32],
    pub predecessor_event_sequence: u64,
    pub predecessor_event_head_hash: [u8; 32],
    pub issued_at: u64,
    pub not_after: u64,
    pub owner_cert_fingerprint: [u8; 32],
    pub genesis_basis: VerifiedGenesisRoster,
    pub active: Vec<MachineRosterMemberV1>,
    pub tombstones: Vec<MachineRosterRevocationV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AcceptedRosterChainState {
    NoGenesis,
    Accepted(Box<AcceptedRosterData>),
    CheckpointForkConflict {
        epoch: [u8; 32],
        sequence: u64,
        hashes: Vec<[u8; 32]>,
    },
    EventForkConflict {
        epoch: [u8; 32],
        sequence: u64,
        hashes: Vec<[u8; 32]>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CheckpointAdmissionResult {
    Accepted,
    IdempotentDuplicate,
    RejectedReplay,
    RejectedGap,
    RejectedRollback,
    RejectedMalformed,
    RejectedOwner,
    RejectedCaveat,
    RejectedSignature,
    RejectedTemporal,
    RejectedProjection,
    EpochMigrationRequired,
    CheckpointForkConflictRecorded,
    EventForkConflictRecorded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MachineCurrencyResult {
    Active {
        member: Box<MachineRosterMemberV1>,
    },
    Revoked {
        tombstone: Box<MachineRosterRevocationV1>,
    },
    NotListed,
    Unavailable {
        reason: UnavailableReason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum UnavailableReason {
    NoGenesis,
    CheckpointStale,
    CheckpointForkConflict,
    EventForkConflict,
    ClockStateUnavailable,
    OwnerAuthorityUnavailable,
}

const MAX_CHECKPOINT_LIFETIME_SECS: u64 = 300;
const MAX_FUTURE_SKEW_SECS: u64 = 60;

// ─── Admission context ──────────────────────────────────────────────────────

pub(crate) struct RosterAuthorityContext<'a> {
    pub hh_pub: &'a P256PublicKey,
    pub expected_hh_id: &'a HouseholdId,
    pub expected_p_id: &'a PersonId,
    pub expected_p_pub: &'a P256PublicKey,
    pub effective_now: u64,
}

pub(crate) struct AdmissionContext<'a> {
    pub authority: RosterAuthorityContext<'a>,
    pub clock_available: bool,
    pub bound_owner_cert_fingerprint: Option<[u8; 32]>,
}

impl AdmissionContext<'_> {
    fn owner_authority_available(&self, candidate_fp: &[u8; 32], has_prior_accepted: bool) -> bool {
        match self.bound_owner_cert_fingerprint {
            Some(fp) => fp == *candidate_fp,
            None => !has_prior_accepted,
        }
    }

    fn owner_available_for_currency(&self, state_fp: &[u8; 32]) -> bool {
        match self.bound_owner_cert_fingerprint {
            Some(fp) => fp == *state_fp,
            None => false,
        }
    }
}

// ─── W: Verified genesis basis (immutable projection basis) ─────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedGenesisRoster {
    pub epoch: [u8; 32],
    pub members: Vec<MachineRosterMemberV1>,
}

// ─── L: Canonical checkpoint wrapper ────────────────────────────────────────

pub(crate) struct CanonicalCheckpoint {
    inner: MachineRosterCheckpointV1,
}

impl CanonicalCheckpoint {
    pub(crate) fn from_raw(raw: &[u8]) -> Result<Self, CheckpointAdmissionResult> {
        let decoded: MachineRosterCheckpointV1 = crate::cbor::from_canonical_slice(raw)
            .map_err(|_| CheckpointAdmissionResult::RejectedMalformed)?;
        let reencoded = crate::cbor::to_canonical_vec(&decoded)
            .map_err(|_| CheckpointAdmissionResult::RejectedMalformed)?;
        if reencoded != raw {
            return Err(CheckpointAdmissionResult::RejectedMalformed);
        }
        // A1: schema gate v/kind before any admit/terminal logic
        if decoded.v != CHECKPOINT_VERSION || decoded.kind != CHECKPOINT_KIND {
            return Err(CheckpointAdmissionResult::RejectedMalformed);
        }
        Ok(Self { inner: decoded })
    }

    pub(crate) fn checkpoint(&self) -> &MachineRosterCheckpointV1 {
        &self.inner
    }
}

// ─── Error classification (exhaustive) ──────────────────────────────────────

fn classify_crypto_error(e: &RosterCryptoError) -> CheckpointAdmissionResult {
    match e {
        RosterCryptoError::CborEncode
        | RosterCryptoError::CborDecode
        | RosterCryptoError::CertDecode
        | RosterCryptoError::CertNotCanonical
        | RosterCryptoError::SchemaInvalid => CheckpointAdmissionResult::RejectedMalformed,
        RosterCryptoError::MissingCaveatAddMachine | RosterCryptoError::MissingCaveatRevoke => {
            CheckpointAdmissionResult::RejectedCaveat
        }
        RosterCryptoError::SignatureRejected => CheckpointAdmissionResult::RejectedSignature,
        #[cfg(test)]
        RosterCryptoError::SignFailed => CheckpointAdmissionResult::RejectedSignature,
        RosterCryptoError::OwnerCertInvalid
        | RosterCryptoError::WeakProvenance
        | RosterCryptoError::OwnerIdMismatch
        | RosterCryptoError::OwnerPubMismatch
        | RosterCryptoError::FingerprintMismatch
        | RosterCryptoError::HouseholdMismatch => CheckpointAdmissionResult::RejectedOwner,
        #[cfg(test)]
        RosterCryptoError::SignerPubMismatch => CheckpointAdmissionResult::RejectedOwner,
        RosterCryptoError::MachineCertInvalid
        | RosterCryptoError::MachineCertNotCanonical
        | RosterCryptoError::MachineIdMismatch
        | RosterCryptoError::MachinePubMismatch
        | RosterCryptoError::MachineFingerprintMismatch
        | RosterCryptoError::MachineHouseholdMismatch => {
            CheckpointAdmissionResult::RejectedProjection
        }
    }
}

// ─── Revocation validation (full authority) ─────────────────────────────────

fn validate_embedded_revocation(
    rev: &MachineRosterRevocationV1,
    expected_epoch: &[u8; 32],
    ctx: &AdmissionContext<'_>,
) -> Result<(), CheckpointAdmissionResult> {
    if rev.v != REVOCATION_VERSION || rev.kind != REVOCATION_KIND {
        return Err(CheckpointAdmissionResult::RejectedMalformed);
    }
    if rev.epoch != *expected_epoch {
        return Err(CheckpointAdmissionResult::RejectedMalformed);
    }
    verify_revocation_authority(rev, &ctx.authority).map_err(|e| classify_crypto_error(&e))?;
    Ok(())
}

// ─── Projection from accepted state + candidate ─────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProjectionError {
    EventHashChainBroken,
    EventHeadMismatch,
    EventSequenceMismatch,
    OwnerFpMismatch,
    RevokedNotPreviouslyActive,
    RevokedTargetMismatch,
    DuplicateRevocation,
    ActiveSortInvalid,
    ActiveDuplicateId,
    ActiveDuplicatePub,
    ActiveDuplicateFingerprint,
    MemberProvenanceInvalid,
    ProjectedMismatch,
    RevocationValidation(CheckpointAdmissionResult),
}

fn project_from_state(
    candidate: &MachineRosterCheckpointV1,
    genesis_basis: &VerifiedGenesisRoster,
    ctx: &AdmissionContext<'_>,
) -> Result<(Vec<MachineRosterMemberV1>, Vec<MachineRosterRevocationV1>), ProjectionError> {
    // O: Validate ALL member provenance in candidate.active
    for member in &candidate.active {
        validate_member_provenance(member, ctx.authority.hh_pub, ctx.authority.expected_hh_id)
            .map_err(|_| ProjectionError::MemberProvenanceInvalid)?;
    }

    // O: Duplicate detection via BTreeSet (global)
    let mut seen_ids: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut seen_pubs: std::collections::BTreeSet<&[u8]> = std::collections::BTreeSet::new();
    let mut seen_fps: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
    for member in &candidate.active {
        if !seen_ids.insert(member.m_id.as_str()) {
            return Err(ProjectionError::ActiveDuplicateId);
        }
        if !seen_pubs.insert(member.m_pub.as_bytes()) {
            return Err(ProjectionError::ActiveDuplicatePub);
        }
        if !seen_fps.insert(member.machine_cert_fingerprint) {
            return Err(ProjectionError::ActiveDuplicateFingerprint);
        }
    }
    for w in candidate.active.windows(2) {
        if w[0].m_id.as_str() >= w[1].m_id.as_str() {
            return Err(ProjectionError::ActiveSortInvalid);
        }
    }

    // event_sequence must equal revocations.len()
    if candidate.event_sequence != candidate.revocations.len() as u64 {
        // len() is usize, safe on 64-bit
        return Err(ProjectionError::EventSequenceMismatch);
    }

    // Genesis: revocations empty, event zero
    if candidate.checkpoint_sequence == 1 {
        if !candidate.revocations.is_empty()
            || candidate.event_sequence != 0
            || candidate.event_head_hash != [0u8; 32]
        {
            return Err(ProjectionError::EventHeadMismatch);
        }
        // Genesis active must equal genesis basis members
        if candidate.active.len() != genesis_basis.members.len() {
            return Err(ProjectionError::ProjectedMismatch);
        }
        for (ca, ga) in candidate.active.iter().zip(genesis_basis.members.iter()) {
            if ca != ga {
                return Err(ProjectionError::ProjectedMismatch);
            }
        }
        return Ok((candidate.active.clone(), vec![]));
    }

    // Non-genesis: validate all embedded revocations (full authority)
    for rev in &candidate.revocations {
        validate_embedded_revocation(rev, &candidate.epoch, ctx)
            .map_err(ProjectionError::RevocationValidation)?;
    }

    // Hash chain from zero
    let mut prev_hash = [0u8; 32];
    for (i, rev) in candidate.revocations.iter().enumerate() {
        let expected_seq = (i + 1) as u64;
        if rev.sequence != expected_seq {
            return Err(ProjectionError::EventHashChainBroken);
        }
        if rev.prev_event_hash != prev_hash {
            return Err(ProjectionError::EventHashChainBroken);
        }
        if rev.owner_cert_fingerprint != candidate.owner_cert_fingerprint {
            return Err(ProjectionError::OwnerFpMismatch);
        }
        let event_hash =
            revocation_event_hash(rev).map_err(|_| ProjectionError::EventHashChainBroken)?;
        prev_hash = event_hash;
    }

    // Event head
    if candidate.event_sequence > 0 {
        if candidate.event_head_hash != prev_hash {
            return Err(ProjectionError::EventHeadMismatch);
        }
    } else if candidate.event_head_hash != [0u8; 32] {
        return Err(ProjectionError::EventHeadMismatch);
    }

    // W: Replay from genesis basis (immutable)
    let mut tombstoned_ids: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for rev in &candidate.revocations {
        let mid = rev.m_id.as_str();
        if tombstoned_ids.contains(mid) {
            return Err(ProjectionError::DuplicateRevocation);
        }
        // P: Target must be in genesis basis with exact m_id + m_pub + fp
        let Some(target) = genesis_basis
            .members
            .iter()
            .find(|m| m.m_id.as_str() == mid)
        else {
            return Err(ProjectionError::RevokedNotPreviouslyActive);
        };
        if rev.m_pub != target.m_pub {
            return Err(ProjectionError::RevokedTargetMismatch);
        }
        if rev.machine_cert_fingerprint != target.machine_cert_fingerprint {
            return Err(ProjectionError::RevokedTargetMismatch);
        }
        tombstoned_ids.insert(mid);
    }

    // Expected active = genesis members minus tombstoned (full member equality)
    let expected_active: Vec<MachineRosterMemberV1> = genesis_basis
        .members
        .iter()
        .filter(|m| !tombstoned_ids.contains(m.m_id.as_str()))
        .cloned()
        .collect();

    // V: Compare FULL MachineRosterMemberV1 (including machine_cert bytes)
    if candidate.active.len() != expected_active.len() {
        return Err(ProjectionError::ProjectedMismatch);
    }
    for (ca, ea) in candidate.active.iter().zip(expected_active.iter()) {
        if ca != ea {
            return Err(ProjectionError::ProjectedMismatch);
        }
    }

    Ok((candidate.active.clone(), candidate.revocations.clone()))
}

// ─── Admission (pure state machine) ─────────────────────────────────────────

pub(crate) fn admit_checkpoint(
    canonical: &CanonicalCheckpoint,
    current: &AcceptedRosterChainState,
    ctx: &AdmissionContext<'_>,
) -> (AcceptedRosterChainState, CheckpointAdmissionResult) {
    let candidate = canonical.checkpoint();

    // T: Clock precondition first
    if !ctx.clock_available {
        return (current.clone(), CheckpointAdmissionResult::RejectedTemporal);
    }

    // T: Terminal fork states (independent of candidate/owner)
    match current {
        AcceptedRosterChainState::CheckpointForkConflict { .. } => {
            return (
                current.clone(),
                CheckpointAdmissionResult::CheckpointForkConflictRecorded,
            );
        }
        AcceptedRosterChainState::EventForkConflict { .. } => {
            return (
                current.clone(),
                CheckpointAdmissionResult::EventForkConflictRecorded,
            );
        }
        _ => {}
    }

    // A2/A3: State pre-classification BEFORE authority verification
    match current {
        AcceptedRosterChainState::NoGenesis => {
            if candidate.checkpoint_sequence != 1 {
                return (current.clone(), CheckpointAdmissionResult::RejectedGap);
            }
            if candidate.prev_checkpoint_hash != [0u8; 32] {
                return (current.clone(), CheckpointAdmissionResult::RejectedGap);
            }
            if candidate.event_sequence != 0
                || candidate.event_head_hash != [0u8; 32]
                || !candidate.revocations.is_empty()
            {
                return (
                    current.clone(),
                    CheckpointAdmissionResult::RejectedMalformed,
                );
            }
        }
        AcceptedRosterChainState::Accepted(data) => {
            let epoch = &data.epoch;
            let genesis_basis = &data.genesis_basis;
            // Epoch FIRST
            if candidate.epoch != *epoch {
                return (
                    current.clone(),
                    CheckpointAdmissionResult::EpochMigrationRequired,
                );
            }
            // Basis epoch defense
            if genesis_basis.epoch != candidate.epoch {
                return (
                    current.clone(),
                    CheckpointAdmissionResult::RejectedProjection,
                );
            }
            // ctx.bound fp must match STATE fp
            if !ctx.owner_authority_available(&data.owner_cert_fingerprint, true) {
                return (current.clone(), CheckpointAdmissionResult::RejectedOwner);
            }
        }
        _ => {}
    }

    // Owner authority (exhaustive classification; schema gated in CanonicalCheckpoint)
    match verify_checkpoint_authority(candidate, &ctx.authority) {
        Ok(()) => {}
        Err(e) => return (current.clone(), classify_crypto_error(&e)),
    }

    // K: candidate fp continuity (after authority verified)
    if let AcceptedRosterChainState::Accepted(data) = current {
        if candidate.owner_cert_fingerprint != data.owner_cert_fingerprint {
            return (current.clone(), CheckpointAdmissionResult::RejectedOwner);
        }
    }
    // NoGenesis: ctx.bound Some must match candidate fp; None permitted
    if matches!(current, AcceptedRosterChainState::NoGenesis) {
        if let Some(bound_fp) = ctx.bound_owner_cert_fingerprint {
            if bound_fp != candidate.owner_cert_fingerprint {
                return (current.clone(), CheckpointAdmissionResult::RejectedOwner);
            }
        }
    }

    let Ok(candidate_hash) = checkpoint_hash(candidate) else {
        return (
            current.clone(),
            CheckpointAdmissionResult::RejectedMalformed,
        );
    };

    // Freshness (U: checked arithmetic)
    let Some(future_limit) = ctx
        .authority
        .effective_now
        .checked_add(MAX_FUTURE_SKEW_SECS)
    else {
        return (current.clone(), CheckpointAdmissionResult::RejectedTemporal);
    };
    if candidate.issued_at > future_limit {
        return (current.clone(), CheckpointAdmissionResult::RejectedTemporal);
    }
    if ctx.authority.effective_now > candidate.not_after {
        return (current.clone(), CheckpointAdmissionResult::RejectedTemporal);
    }
    if candidate.not_after.saturating_sub(candidate.issued_at) > MAX_CHECKPOINT_LIFETIME_SECS {
        return (current.clone(), CheckpointAdmissionResult::RejectedTemporal);
    }
    if candidate.issued_at > candidate.not_after {
        return (current.clone(), CheckpointAdmissionResult::RejectedTemporal);
    }

    // Chain logic
    match current {
        AcceptedRosterChainState::NoGenesis => {
            // Genesis shape already validated in pre-classification above
            // W: basis derived from candidate for genesis
            let basis = VerifiedGenesisRoster {
                epoch: candidate.epoch,
                members: candidate.active.clone(),
            };
            match project_from_state(candidate, &basis, ctx) {
                Ok((active, tombstones)) => {
                    let new_state =
                        AcceptedRosterChainState::Accepted(Box::new(AcceptedRosterData {
                            epoch: candidate.epoch,
                            checkpoint_sequence: candidate.checkpoint_sequence,
                            checkpoint_hash: candidate_hash,
                            prev_checkpoint_hash: candidate.prev_checkpoint_hash,
                            event_sequence: candidate.event_sequence,
                            event_head_hash: candidate.event_head_hash,
                            predecessor_event_sequence: 0,
                            predecessor_event_head_hash: [0u8; 32],
                            issued_at: candidate.issued_at,
                            not_after: candidate.not_after,
                            owner_cert_fingerprint: candidate.owner_cert_fingerprint,
                            genesis_basis: basis,
                            active,
                            tombstones,
                        }));
                    (new_state, CheckpointAdmissionResult::Accepted)
                }
                Err(ProjectionError::RevocationValidation(r)) => (current.clone(), r),
                Err(_) => (
                    current.clone(),
                    CheckpointAdmissionResult::RejectedProjection,
                ),
            }
        }
        AcceptedRosterChainState::Accepted(data) => {
            let epoch = &data.epoch;
            let checkpoint_sequence = &data.checkpoint_sequence;
            let checkpoint_hash = &data.checkpoint_hash;
            let prev_checkpoint_hash = &data.prev_checkpoint_hash;
            let event_sequence = &data.event_sequence;
            let event_head_hash = &data.event_head_hash;
            let predecessor_event_sequence = &data.predecessor_event_sequence;
            let predecessor_event_head_hash = &data.predecessor_event_head_hash;
            let issued_at = &data.issued_at;
            let genesis_basis = &data.genesis_basis;
            let accepted_tombstones = &data.tombstones;
            // Epoch/basis/fp already checked in pre-classification above
            // Replay
            if candidate.checkpoint_sequence < *checkpoint_sequence {
                return (current.clone(), CheckpointAdmissionResult::RejectedReplay);
            }
            // Same sequence
            if candidate.checkpoint_sequence == *checkpoint_sequence {
                // Exact duplicate
                if candidate_hash == *checkpoint_hash {
                    return (
                        current.clone(),
                        CheckpointAdmissionResult::IdempotentDuplicate,
                    );
                }
                // (3) D18b: issued_at regression BEFORE fork
                if candidate.issued_at < *issued_at {
                    return (current.clone(), CheckpointAdmissionResult::RejectedTemporal);
                }
                // D18a: same-seq fork requires same prev_checkpoint_hash
                if candidate.prev_checkpoint_hash != *prev_checkpoint_hash {
                    return (current.clone(), CheckpointAdmissionResult::RejectedGap);
                }
                // W/D15: same-seq seq1 uses candidate-derived basis
                let fork_basis = if *checkpoint_sequence == 1 {
                    VerifiedGenesisRoster {
                        epoch: candidate.epoch,
                        members: candidate.active.clone(),
                    }
                } else {
                    genesis_basis.clone()
                };
                // D19: predecessor event content verification before fork
                // 1) M < N_prev => RejectedRollback
                if candidate.event_sequence < *predecessor_event_sequence {
                    return (current.clone(), CheckpointAdmissionResult::RejectedRollback);
                }
                // 2) Validate projection intrinsically (preserve typed errors)
                match project_from_state(candidate, &fork_basis, ctx) {
                    Ok(_) => {}
                    Err(ProjectionError::RevocationValidation(r)) => return (current.clone(), r),
                    Err(_) => {
                        return (
                            current.clone(),
                            CheckpointAdmissionResult::RejectedProjection,
                        );
                    }
                }
                // 3) Compute intermediate head at N_prev (checked usize)
                let Ok(n_prev) = usize::try_from(*predecessor_event_sequence) else {
                    return (
                        current.clone(),
                        CheckpointAdmissionResult::RejectedProjection,
                    );
                };
                let intermediate_head = if n_prev == 0 {
                    [0u8; 32]
                } else {
                    if candidate.revocations.len() < n_prev {
                        return (
                            current.clone(),
                            CheckpointAdmissionResult::RejectedProjection,
                        );
                    }
                    let Ok(h) = revocation_event_hash(&candidate.revocations[n_prev - 1]) else {
                        return (
                            current.clone(),
                            CheckpointAdmissionResult::RejectedProjection,
                        );
                    };
                    h
                };
                // 4) Intermediate head != H_prev => RejectedProjection (never fork)
                if intermediate_head != *predecessor_event_head_hash {
                    return (
                        current.clone(),
                        CheckpointAdmissionResult::RejectedProjection,
                    );
                }
                // 5) Match => CheckpointForkConflict persisted
                let new_state = AcceptedRosterChainState::CheckpointForkConflict {
                    epoch: *epoch,
                    sequence: *checkpoint_sequence,
                    hashes: vec![*checkpoint_hash, candidate_hash],
                };
                (
                    new_state,
                    CheckpointAdmissionResult::CheckpointForkConflictRecorded,
                )
            } else {
                // Next sequence (delegated to shared evaluator)
                let input = NextSeqInput {
                    epoch: *epoch,
                    checkpoint_sequence: *checkpoint_sequence,
                    checkpoint_hash: *checkpoint_hash,
                    event_sequence: *event_sequence,
                    event_head_hash: *event_head_hash,
                    issued_at: *issued_at,
                    genesis_basis,
                    tombstones: accepted_tombstones,
                };
                match evaluate_next_seq(candidate, candidate_hash, &input, ctx) {
                    NextSeqDecision::Mutating { state, result } => (state, result),
                    NextSeqDecision::Rejected(r) => (current.clone(), r),
                }
            }
        }
        _ => (
            current.clone(),
            CheckpointAdmissionResult::RejectedProjection,
        ),
    }
}

// ─── Next-seq evaluator (private; shared by admit_checkpoint + historical) ──

struct NextSeqInput<'a> {
    epoch: [u8; 32],
    checkpoint_sequence: u64,
    checkpoint_hash: [u8; 32],
    event_sequence: u64,
    event_head_hash: [u8; 32],
    issued_at: u64,
    genesis_basis: &'a VerifiedGenesisRoster,
    tombstones: &'a [MachineRosterRevocationV1],
}

enum NextSeqDecision {
    Mutating {
        state: AcceptedRosterChainState,
        result: CheckpointAdmissionResult,
    },
    Rejected(CheckpointAdmissionResult),
}

fn evaluate_next_seq(
    candidate: &MachineRosterCheckpointV1,
    candidate_hash: [u8; 32],
    input: &NextSeqInput<'_>,
    ctx: &AdmissionContext<'_>,
) -> NextSeqDecision {
    let Some(expected_next) = input.checkpoint_sequence.checked_add(1) else {
        return NextSeqDecision::Rejected(CheckpointAdmissionResult::RejectedGap);
    };
    if candidate.checkpoint_sequence != expected_next {
        return NextSeqDecision::Rejected(CheckpointAdmissionResult::RejectedGap);
    }
    if candidate.prev_checkpoint_hash != input.checkpoint_hash {
        return NextSeqDecision::Rejected(CheckpointAdmissionResult::RejectedGap);
    }
    if candidate.issued_at < input.issued_at {
        return NextSeqDecision::Rejected(CheckpointAdmissionResult::RejectedTemporal);
    }
    if candidate.event_sequence < input.event_sequence {
        return NextSeqDecision::Rejected(CheckpointAdmissionResult::RejectedRollback);
    }
    let basis = input.genesis_basis.clone();

    if candidate.event_sequence == input.event_sequence
        && candidate.event_head_hash != input.event_head_hash
    {
        match project_from_state(candidate, &basis, ctx) {
            Ok(_) => {
                let new_state = AcceptedRosterChainState::EventForkConflict {
                    epoch: input.epoch,
                    sequence: input.event_sequence,
                    hashes: vec![input.event_head_hash, candidate.event_head_hash],
                };
                return NextSeqDecision::Mutating {
                    state: new_state,
                    result: CheckpointAdmissionResult::EventForkConflictRecorded,
                };
            }
            Err(ProjectionError::RevocationValidation(r)) => {
                return NextSeqDecision::Rejected(r);
            }
            Err(_) => {
                return NextSeqDecision::Rejected(CheckpointAdmissionResult::RejectedProjection);
            }
        }
    }

    if candidate.event_sequence > input.event_sequence {
        let Ok(n) = usize::try_from(input.event_sequence) else {
            return NextSeqDecision::Rejected(CheckpointAdmissionResult::RejectedProjection);
        };
        if input.tombstones.len() != n {
            return NextSeqDecision::Rejected(CheckpointAdmissionResult::RejectedProjection);
        }
        if candidate.revocations.len() < n {
            return NextSeqDecision::Rejected(CheckpointAdmissionResult::RejectedProjection);
        }
        let prefix_exact = candidate.revocations[..n]
            .iter()
            .zip(input.tombstones.iter())
            .all(|(c, a)| c == a);
        if !prefix_exact {
            let intermediate_head = if n == 0 {
                [0u8; 32]
            } else {
                let Ok(h) = revocation_event_hash(&candidate.revocations[n - 1]) else {
                    return NextSeqDecision::Rejected(
                        CheckpointAdmissionResult::RejectedProjection,
                    );
                };
                h
            };
            match project_from_state(candidate, &basis, ctx) {
                Ok(_) => {
                    let new_state = AcceptedRosterChainState::EventForkConflict {
                        epoch: input.epoch,
                        sequence: input.event_sequence,
                        hashes: vec![input.event_head_hash, intermediate_head],
                    };
                    return NextSeqDecision::Mutating {
                        state: new_state,
                        result: CheckpointAdmissionResult::EventForkConflictRecorded,
                    };
                }
                Err(ProjectionError::RevocationValidation(r)) => {
                    return NextSeqDecision::Rejected(r);
                }
                Err(_) => {
                    return NextSeqDecision::Rejected(
                        CheckpointAdmissionResult::RejectedProjection,
                    );
                }
            }
        }
        if n > 0 {
            let Ok(h_n) = revocation_event_hash(&candidate.revocations[n - 1]) else {
                return NextSeqDecision::Rejected(CheckpointAdmissionResult::RejectedProjection);
            };
            if h_n != input.event_head_hash {
                match project_from_state(candidate, &basis, ctx) {
                    Ok(_) => {
                        let new_state = AcceptedRosterChainState::EventForkConflict {
                            epoch: input.epoch,
                            sequence: input.event_sequence,
                            hashes: vec![input.event_head_hash, h_n],
                        };
                        return NextSeqDecision::Mutating {
                            state: new_state,
                            result: CheckpointAdmissionResult::EventForkConflictRecorded,
                        };
                    }
                    Err(ProjectionError::RevocationValidation(r)) => {
                        return NextSeqDecision::Rejected(r);
                    }
                    Err(_) => {
                        return NextSeqDecision::Rejected(
                            CheckpointAdmissionResult::RejectedProjection,
                        );
                    }
                }
            }
        }
    }

    match project_from_state(candidate, &basis, ctx) {
        Ok((active, tombstones)) => {
            let new_state = AcceptedRosterChainState::Accepted(Box::new(AcceptedRosterData {
                epoch: candidate.epoch,
                checkpoint_sequence: candidate.checkpoint_sequence,
                checkpoint_hash: candidate_hash,
                prev_checkpoint_hash: candidate.prev_checkpoint_hash,
                event_sequence: candidate.event_sequence,
                event_head_hash: candidate.event_head_hash,
                predecessor_event_sequence: input.event_sequence,
                predecessor_event_head_hash: input.event_head_hash,
                issued_at: candidate.issued_at,
                not_after: candidate.not_after,
                owner_cert_fingerprint: candidate.owner_cert_fingerprint,
                genesis_basis: basis,
                active,
                tombstones,
            }));
            NextSeqDecision::Mutating {
                state: new_state,
                result: CheckpointAdmissionResult::Accepted,
            }
        }
        Err(ProjectionError::RevocationValidation(r)) => NextSeqDecision::Rejected(r),
        Err(_) => NextSeqDecision::Rejected(CheckpointAdmissionResult::RejectedProjection),
    }
}

// ─── Historical bridge (pub(crate); DS-CP2) ────────────────────────────────

#[derive(Debug)]
pub(crate) enum HistoricalBridgeError {
    Crypto(RosterCryptoError),
    Projection(ProjectionError),
    Admission(CheckpointAdmissionResult),
    Temporal,
}

pub(crate) fn derive_owner_binding_from_cert(
    cert_bytes: &[u8],
    expected_hh_id: &HouseholdId,
    hh_pub: &P256PublicKey,
    at_time: u64,
) -> Result<(PersonId, P256PublicKey, [u8; 32]), RosterCryptoError> {
    let cert = decode_owner_cert(cert_bytes)?;
    cert.verify_rooted_identity(expected_hh_id, hh_pub, at_time)
        .map_err(|_| RosterCryptoError::OwnerCertInvalid)?;
    if !cert.has_strong_owner_provenance() {
        return Err(RosterCryptoError::WeakProvenance);
    }
    for caveat in crate::caveats::owner_caveats() {
        if !crate::caveats::permits(&cert.caveats, &caveat.op) {
            return Err(RosterCryptoError::OwnerCertInvalid);
        }
    }
    let fp = owner_cert_fingerprint(&cert)?;
    Ok((cert.p_id.clone(), cert.p_pub, fp))
}

pub(crate) fn verify_checkpoint_full_historical(
    c: &MachineRosterCheckpointV1,
    ctx: &RosterAuthorityContext<'_>,
) -> Result<(), RosterCryptoError> {
    verify_checkpoint_authority(c, ctx)?;
    for rev in &c.revocations {
        check_revocation_schema(rev)?;
        if rev.epoch != c.epoch {
            return Err(RosterCryptoError::SchemaInvalid);
        }
        if rev.hh_id != *ctx.expected_hh_id {
            return Err(RosterCryptoError::HouseholdMismatch);
        }
        verify_revocation_authority(rev, ctx)?;
    }
    Ok(())
}

pub(crate) fn historical_reapply_next(
    current: &CanonicalCheckpoint,
    predecessor_cp: &MachineRosterCheckpointV1,
    genesis_basis: &VerifiedGenesisRoster,
    pred_ctx: &AdmissionContext<'_>,
    curr_ctx: &AdmissionContext<'_>,
) -> Result<AcceptedRosterChainState, HistoricalBridgeError> {
    let current_cp = current.checkpoint();

    if pred_ctx.authority.effective_now != predecessor_cp.issued_at {
        return Err(HistoricalBridgeError::Temporal);
    }
    if curr_ctx.authority.effective_now != current_cp.issued_at {
        return Err(HistoricalBridgeError::Temporal);
    }
    if !pred_ctx.clock_available || !curr_ctx.clock_available {
        return Err(HistoricalBridgeError::Temporal);
    }
    if pred_ctx.authority.expected_hh_id != curr_ctx.authority.expected_hh_id {
        return Err(HistoricalBridgeError::Crypto(
            RosterCryptoError::HouseholdMismatch,
        ));
    }
    if pred_ctx.authority.hh_pub != curr_ctx.authority.hh_pub {
        return Err(HistoricalBridgeError::Crypto(
            RosterCryptoError::HouseholdMismatch,
        ));
    }
    if pred_ctx.authority.expected_p_id != curr_ctx.authority.expected_p_id {
        return Err(HistoricalBridgeError::Crypto(
            RosterCryptoError::OwnerIdMismatch,
        ));
    }
    if pred_ctx.authority.expected_p_pub != curr_ctx.authority.expected_p_pub {
        return Err(HistoricalBridgeError::Crypto(
            RosterCryptoError::OwnerPubMismatch,
        ));
    }
    let (Some(pred_fp), Some(curr_fp)) = (
        pred_ctx.bound_owner_cert_fingerprint,
        curr_ctx.bound_owner_cert_fingerprint,
    ) else {
        return Err(HistoricalBridgeError::Crypto(
            RosterCryptoError::FingerprintMismatch,
        ));
    };
    if pred_fp != curr_fp {
        return Err(HistoricalBridgeError::Crypto(
            RosterCryptoError::FingerprintMismatch,
        ));
    }
    if predecessor_cp.owner_cert_fingerprint != pred_fp {
        return Err(HistoricalBridgeError::Crypto(
            RosterCryptoError::FingerprintMismatch,
        ));
    }
    if current_cp.owner_cert_fingerprint != curr_fp {
        return Err(HistoricalBridgeError::Crypto(
            RosterCryptoError::FingerprintMismatch,
        ));
    }

    if predecessor_cp
        .issued_at
        .checked_add(MAX_FUTURE_SKEW_SECS)
        .is_none()
    {
        return Err(HistoricalBridgeError::Temporal);
    }
    if predecessor_cp.issued_at > predecessor_cp.not_after {
        return Err(HistoricalBridgeError::Temporal);
    }
    if predecessor_cp
        .not_after
        .saturating_sub(predecessor_cp.issued_at)
        > MAX_CHECKPOINT_LIFETIME_SECS
    {
        return Err(HistoricalBridgeError::Temporal);
    }
    if current_cp
        .issued_at
        .checked_add(MAX_FUTURE_SKEW_SECS)
        .is_none()
    {
        return Err(HistoricalBridgeError::Temporal);
    }
    if current_cp.issued_at > current_cp.not_after {
        return Err(HistoricalBridgeError::Temporal);
    }
    if current_cp.not_after.saturating_sub(current_cp.issued_at) > MAX_CHECKPOINT_LIFETIME_SECS {
        return Err(HistoricalBridgeError::Temporal);
    }

    if predecessor_cp.epoch != genesis_basis.epoch {
        return Err(HistoricalBridgeError::Admission(
            CheckpointAdmissionResult::EpochMigrationRequired,
        ));
    }
    if current_cp.epoch != predecessor_cp.epoch {
        return Err(HistoricalBridgeError::Admission(
            CheckpointAdmissionResult::EpochMigrationRequired,
        ));
    }

    verify_checkpoint_full_historical(predecessor_cp, &pred_ctx.authority)
        .map_err(HistoricalBridgeError::Crypto)?;
    verify_checkpoint_full_historical(current_cp, &curr_ctx.authority)
        .map_err(HistoricalBridgeError::Crypto)?;

    let curr_hash = checkpoint_hash(current_cp).map_err(HistoricalBridgeError::Crypto)?;

    let (_, pred_tombstones) = project_from_state(predecessor_cp, genesis_basis, pred_ctx)
        .map_err(HistoricalBridgeError::Projection)?;
    let pred_hash = checkpoint_hash(predecessor_cp).map_err(HistoricalBridgeError::Crypto)?;

    let input = NextSeqInput {
        epoch: predecessor_cp.epoch,
        checkpoint_sequence: predecessor_cp.checkpoint_sequence,
        checkpoint_hash: pred_hash,
        event_sequence: predecessor_cp.event_sequence,
        event_head_hash: predecessor_cp.event_head_hash,
        issued_at: predecessor_cp.issued_at,
        genesis_basis,
        tombstones: &pred_tombstones,
    };

    match evaluate_next_seq(current_cp, curr_hash, &input, curr_ctx) {
        NextSeqDecision::Mutating {
            state,
            result: CheckpointAdmissionResult::Accepted,
        } => Ok(state),
        NextSeqDecision::Mutating { result, .. } => Err(HistoricalBridgeError::Admission(result)),
        NextSeqDecision::Rejected(r) => Err(HistoricalBridgeError::Admission(r)),
    }
}

// ─── Currency derivation (internal only) ────────────────────────────────────

/// Shared prefix of `derive_machine_currency`: clock → terminal chain →
/// owner authority → stale, stopping before the per-machine lookup. Exists
/// so `current_snapshot()` (`machine_roster_store.rs`) and
/// `derive_machine_currency` below run through the identical admissibility
/// check and cannot silently diverge — see RED-R21.
pub(crate) fn admit_current_accepted_data<'a>(
    state: &'a AcceptedRosterChainState,
    ctx: &AdmissionContext<'_>,
) -> Result<&'a AcceptedRosterData, UnavailableReason> {
    if !ctx.clock_available {
        return Err(UnavailableReason::ClockStateUnavailable);
    }
    match state {
        AcceptedRosterChainState::NoGenesis => Err(UnavailableReason::NoGenesis),
        AcceptedRosterChainState::CheckpointForkConflict { .. } => {
            Err(UnavailableReason::CheckpointForkConflict)
        }
        AcceptedRosterChainState::EventForkConflict { .. } => {
            Err(UnavailableReason::EventForkConflict)
        }
        AcceptedRosterChainState::Accepted(data) => {
            if !ctx.owner_available_for_currency(&data.owner_cert_fingerprint) {
                return Err(UnavailableReason::OwnerAuthorityUnavailable);
            }
            if ctx.authority.effective_now > data.not_after {
                return Err(UnavailableReason::CheckpointStale);
            }
            Ok(data)
        }
    }
}

pub(crate) fn derive_machine_currency(
    state: &AcceptedRosterChainState,
    m_id: &MachineId,
    ctx: &AdmissionContext<'_>,
) -> MachineCurrencyResult {
    let data = match admit_current_accepted_data(state, ctx) {
        Ok(data) => data,
        Err(reason) => return MachineCurrencyResult::Unavailable { reason },
    };
    if let Some(rev) = data.tombstones.iter().find(|r| r.m_id == *m_id) {
        return MachineCurrencyResult::Revoked {
            tombstone: Box::new(rev.clone()),
        };
    }
    if let Some(member) = data.active.iter().find(|m| m.m_id == *m_id) {
        return MachineCurrencyResult::Active {
            member: Box::new(member.clone()),
        };
    }
    MachineCurrencyResult::NotListed
}

// ─── Roster snapshot view (D-1, B-ROSTER-ADAPTER v2 CFX-1/CFX-2) ────────────
//
// Projection of `AcceptedRosterData` exposed outside household-rs: exactly
// the four `checkpoint_*` fields Proof-R/Proof-I v6 sign
// (`checkpoint_hash`, `checkpoint_sequence`, `checkpoint_event_head`,
// `not_after`), plus `hh_id`/`active`/`revoked_m_ids`. Everything else on
// `AcceptedRosterData` (`epoch`, `prev_checkpoint_hash`, `event_sequence`,
// `predecessor_*`, `owner_cert_fingerprint`, `genesis_basis`) does not cross
// this boundary.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterMemberView {
    m_id: MachineId,
    m_pub: P256PublicKey,
    machine_cert_fingerprint: [u8; 32],
}

impl RosterMemberView {
    #[must_use]
    pub fn m_id(&self) -> &MachineId {
        &self.m_id
    }

    #[must_use]
    pub fn m_pub(&self) -> &P256PublicKey {
        &self.m_pub
    }

    #[must_use]
    pub fn machine_cert_fingerprint(&self) -> [u8; 32] {
        self.machine_cert_fingerprint
    }
}

impl From<&MachineRosterMemberV1> for RosterMemberView {
    fn from(member: &MachineRosterMemberV1) -> Self {
        Self {
            m_id: member.m_id.clone(),
            m_pub: member.m_pub.clone(),
            machine_cert_fingerprint: member.machine_cert_fingerprint,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterSnapshotView {
    hh_id: HouseholdId,
    checkpoint_hash: [u8; 32],
    checkpoint_sequence: u64,
    checkpoint_event_head: [u8; 32],
    not_after: u64,
    active: Vec<RosterMemberView>,
    revoked_m_ids: Vec<MachineId>,
}

impl RosterSnapshotView {
    pub(crate) fn project(hh_id: &HouseholdId, data: &AcceptedRosterData) -> Self {
        Self {
            hh_id: hh_id.clone(),
            checkpoint_hash: data.checkpoint_hash,
            checkpoint_sequence: data.checkpoint_sequence,
            checkpoint_event_head: data.event_head_hash,
            not_after: data.not_after,
            active: data.active.iter().map(RosterMemberView::from).collect(),
            revoked_m_ids: data.tombstones.iter().map(|r| r.m_id.clone()).collect(),
        }
    }

    #[must_use]
    pub fn hh_id(&self) -> &HouseholdId {
        &self.hh_id
    }

    #[must_use]
    pub fn checkpoint_hash(&self) -> [u8; 32] {
        self.checkpoint_hash
    }

    #[must_use]
    pub fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }

    #[must_use]
    pub fn checkpoint_event_head(&self) -> [u8; 32] {
        self.checkpoint_event_head
    }

    #[must_use]
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    #[must_use]
    pub fn lookup_active(&self, m_id: &MachineId) -> Option<&RosterMemberView> {
        self.active.iter().find(|m| m.m_id == *m_id)
    }

    #[must_use]
    pub fn is_revoked(&self, m_id: &MachineId) -> bool {
        self.revoked_m_ids.iter().any(|r| r == m_id)
    }

    #[must_use]
    pub fn revoked_m_ids(&self) -> &[MachineId] {
        &self.revoked_m_ids
    }

    pub fn active_m_ids(&self) -> impl Iterator<Item = &MachineId> + '_ {
        self.active.iter().map(RosterMemberView::m_id)
    }

    #[must_use]
    pub fn is_active(&self, m_id: &MachineId) -> bool {
        self.lookup_active(m_id).is_some() && !self.is_revoked(m_id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RosterSnapshotError {
    #[error("not initialized")]
    NotInitialized,
    #[error("latch poisoned")]
    LatchPoisoned,
    #[error(transparent)]
    Io(#[from] crate::machine_roster_store::RosterStoreError),
    #[error("clock state unavailable")]
    ClockStateUnavailable,
    #[error("no genesis")]
    NoGenesis,
    #[error("checkpoint fork conflict")]
    CheckpointForkConflict,
    #[error("event fork conflict")]
    EventForkConflict,
    #[error("owner authority unavailable")]
    OwnerAuthorityUnavailable,
    #[error("checkpoint stale")]
    CheckpointStale,
}

impl From<UnavailableReason> for RosterSnapshotError {
    fn from(reason: UnavailableReason) -> Self {
        match reason {
            UnavailableReason::ClockStateUnavailable => Self::ClockStateUnavailable,
            UnavailableReason::NoGenesis => Self::NoGenesis,
            UnavailableReason::CheckpointForkConflict => Self::CheckpointForkConflict,
            UnavailableReason::EventForkConflict => Self::EventForkConflict,
            UnavailableReason::OwnerAuthorityUnavailable => Self::OwnerAuthorityUnavailable,
            UnavailableReason::CheckpointStale => Self::CheckpointStale,
        }
    }
}

// ─── Peer expectation (D-1, B-ROSTER-ADAPTER v2 CFX-4, erratum1) ────────────
//
// erratum1 (`daisy-b-roster-adapter-v2-erratum1.0f8b9952…`) blocks this on
// D-9: no authenticated source for `selected_m_id` exists or is measured
// yet, so no PUBLIC production constructor exists for `PeerExpectation` —
// not even for the `LocalOwnerPresentSelection` variant alone. The only
// constructor is `#[cfg(test)] pub(crate)`, same pattern already used by
// `OwnerSiteRosterSnapshot::injected_for_harness` and
// `MachineRosterCoordinator::from_validated_with_clock` in this codebase.
// `ExpectedResponder`/`from_peer_expectation` are therefore out of scope
// this round too — with no production constructor for `PeerExpectation`,
// there is nothing that can reach them in production.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerSelectionSource {
    LocalOwnerPresentSelection,
    // Variantes futuras (SignedConnectionIntent, AuthenticatedRendezvousOffer,
    // ...) só entram quando D-9 tiver uma fonte medida.
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerExpectation {
    checkpoint_hash: [u8; 32],
    m_id: MachineId,
    source: PeerSelectionSource,
}

impl PeerExpectation {
    // NENHUM constructor público de produção existe ainda. A ausência É o
    // gate de D-9 (RED-R23), não uma nota de aviso ao lado de um
    // constructor que funciona.

    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        checkpoint_hash: [u8; 32],
        m_id: MachineId,
        source: PeerSelectionSource,
    ) -> Self {
        Self {
            checkpoint_hash,
            m_id,
            source,
        }
    }

    #[must_use]
    pub fn checkpoint_hash(&self) -> [u8; 32] {
        self.checkpoint_hash
    }

    #[must_use]
    pub fn m_id(&self) -> &MachineId {
        &self.m_id
    }

    #[must_use]
    pub fn source(&self) -> PeerSelectionSource {
        self.source
    }
}

/// The redemption side of CFX-4: turning a `PeerExpectation` into an
/// `ExpectedResponder` bound to a specific snapshot. `ExpectedResponder`
/// itself does not exist anywhere else in this repository yet (`grep -rn
/// ExpectedResponder admin/rust` is empty) — there is no bare-`MachineId`
/// constructor to remove (RED-R19 is trivially true: it never existed).
///
/// This *is* implementable and testable now, independent of D-9/erratum1:
/// the only way to obtain a `PeerExpectation` to pass in is
/// `#[cfg(test)] injected_for_harness` (no production constructor exists),
/// so `from_peer_expectation` has no production caller regardless of
/// whether this function itself is gated — gating the function would only
/// hide its own logic from tests. What erratum1 blocks is `PeerExpectation`
/// acquiring a production source; it does not need this pairing check
/// itself to also be hidden.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedResponder {
    hh_id: HouseholdId,
    m_id: MachineId,
    cert_fingerprint: [u8; 32],
}

impl ExpectedResponder {
    #[must_use]
    pub fn hh_id(&self) -> &HouseholdId {
        &self.hh_id
    }

    #[must_use]
    pub fn m_id(&self) -> &MachineId {
        &self.m_id
    }

    #[must_use]
    pub fn cert_fingerprint(&self) -> [u8; 32] {
        self.cert_fingerprint
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectedResponderError {
    /// `expectation` was sealed against a different snapshot revision than
    /// `snapshot` — checked FIRST: a stale/foreign expectation must not
    /// fall through to "not active" or "revoked" and produce a misleading
    /// reason for what is really a pairing error (RED-R18).
    ExpectationSnapshotMismatch,
    MachineRevoked,
    MachineNotActive,
}

impl ExpectedResponder {
    /// Order matters and is pinned by test: checkpoint-hash mismatch first
    /// (RED-R18 — a pairing error, not a membership error), then revoked,
    /// then not-active, then success with the member's fingerprint.
    pub fn from_peer_expectation(
        expectation: PeerExpectation,
        snapshot: &RosterSnapshotView,
    ) -> Result<Self, ExpectedResponderError> {
        if expectation.checkpoint_hash != snapshot.checkpoint_hash() {
            return Err(ExpectedResponderError::ExpectationSnapshotMismatch);
        }
        if snapshot.is_revoked(&expectation.m_id) {
            return Err(ExpectedResponderError::MachineRevoked);
        }
        let member = snapshot
            .lookup_active(&expectation.m_id)
            .ok_or(ExpectedResponderError::MachineNotActive)?;
        Ok(Self {
            hh_id: snapshot.hh_id().clone(),
            m_id: expectation.m_id,
            cert_fingerprint: member.machine_cert_fingerprint(),
        })
    }
}

/// D-1 (audit round 3): what `MeshSessionRegistry::register` accepts in
/// place of a caller-supplied bare `MachineId` + a session-self-reported
/// identity. A session handle claiming its own `peer_m_id()` is still just
/// a claim — nothing stops a buggy or malicious `H` from lying. A
/// `SealedBinding` instead carries exactly the fields an `ExpectedResponder`
/// (itself only constructible by passing `ExpectedResponder::from_peer_expectation`'s
/// revoked/active/hash-pairing checks against a real snapshot) already
/// proved, plus the checkpoint revision that snapshot was captured at:
/// `hh_id`, `m_id`, `machine_cert_fingerprint`, `checkpoint_hash`,
/// `checkpoint_sequence`. The registry's `register` no longer trusts
/// anything the handle itself reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBinding {
    hh_id: HouseholdId,
    m_id: MachineId,
    machine_cert_fingerprint: [u8; 32],
    checkpoint_hash: [u8; 32],
    checkpoint_sequence: u64,
}

impl SealedBinding {
    /// `responder` proves `m_id` was active, non-revoked and paired to
    /// `snapshot`'s exact `checkpoint_hash` at the moment
    /// `from_peer_expectation` ran; `snapshot` additionally supplies the
    /// `checkpoint_sequence` that `ExpectedResponder` itself does not carry
    /// (`PeerExpectation` only seals a hash). Caller is expected to have
    /// obtained `responder` from this same `snapshot` — nothing here
    /// re-verifies that pairing beyond what `from_peer_expectation` already
    /// checked, so this is a projection, not a second authorization step.
    #[must_use]
    pub fn from_expected_responder(
        responder: &ExpectedResponder,
        snapshot: &RosterSnapshotView,
    ) -> Self {
        Self {
            hh_id: responder.hh_id().clone(),
            m_id: responder.m_id().clone(),
            machine_cert_fingerprint: responder.cert_fingerprint(),
            checkpoint_hash: snapshot.checkpoint_hash(),
            checkpoint_sequence: snapshot.checkpoint_sequence(),
        }
    }

    #[must_use]
    pub fn hh_id(&self) -> &HouseholdId {
        &self.hh_id
    }

    #[must_use]
    pub fn m_id(&self) -> &MachineId {
        &self.m_id
    }

    #[must_use]
    pub fn machine_cert_fingerprint(&self) -> [u8; 32] {
        self.machine_cert_fingerprint
    }

    #[must_use]
    pub fn checkpoint_hash(&self) -> [u8; 32] {
        self.checkpoint_hash
    }

    #[must_use]
    pub fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }
}

// ─── Responder-side peer binding (D-1 successor, @kiana E1) ────────────────
//
// `PeerExpectation`/`ExpectedResponder` are structurally initiator-only: the
// initiator pre-declares WHICH `m_id` it expects to reach before any
// connection exists (`PeerExpectation::m_id`), then `from_peer_expectation`
// checks that pre-declaration against a real snapshot. A RESPONDER has no
// such pre-declaration to check — it learns a peer's claimed identity only
// once an inbound connection attempt has already been authenticated at the
// transport layer. That authentication (proving "this inbound bytestream
// really is machine X") is NOT household-rs's job; it belongs to the
// not-yet-integrated B-SESSAO CORE wire/session handshake (see this module's
// scope notes elsewhere, and `mesh_session_registry.rs`'s own doc comment).
// What IS household-rs's job, symmetrically with the initiator side, is the
// roster-authority half only: given an m_id the transport layer has ALREADY
// authenticated for this specific inbound attempt, check it against a real
// `RosterSnapshotView` the same way `from_peer_expectation` does for the
// initiator — active, non-revoked, at this exact revision.
//
// `AuthenticatedPeerClaim` is a SEPARATE type from `PeerExpectation`/
// `ExpectedResponder` — not a wrapper, not a reuse. An inbound authenticated
// claim and a locally pre-declared expectation are different authorities
// with different failure semantics and different origins; folding them into
// one type would let a future caller silently satisfy an initiator-shaped
// check with responder-shaped evidence, or vice versa. Its only constructor
// is `#[cfg(test)] pub(crate)`, for the same reason `PeerExpectation` has
// none in production: there is no measured, authenticated source for an
// inbound peer's claimed `m_id` wired into household-rs yet — that source
// is the not-yet-built B-SESSAO CORE handshake. The absence IS the gate
// (RED-R23's own reasoning, mirrored here), not a warning next to a
// constructor that works.
//
// **Open integration blocker, registered explicitly, not closed here**
// (round D-1 successor, @kiana recheck): `pub(crate)` is a HARD crate
// boundary regardless of build mode — it is not merely "gated pending a
// measured source" the way a `#[cfg(test)]`-only item is. Once the
// B-SESSAO CORE handshake exists, it will live in a DIFFERENT crate
// (`mesh-session-core-rs`/its runtime), and a `pub(crate)` item in
// household-rs is structurally invisible to it FOREVER, in every build
// mode — "integrate the handshake" alone can never make this path
// reachable from production, no matter what else changes. Production
// wiring needs one of: (a) an opaque, capability-shaped facade this type
// accepts as proof (the shape D-9 is expected to define — not decided or
// built here), or (b) an explicitly-approved typed dependency from
// `mesh-session-core-rs` onto household-rs internals. Neither exists yet.
// This round deliberately does NOT invent either — exposing a raw,
// forgeable, cross-crate-reachable constructor "just to compile" would
// itself be the vulnerability E1 exists to prevent. What this round DOES
// close, and what is safe to rely on today: the roster-authority
// projection itself (`SealedBinding::from_responding_peer`, below) is
// real, tested, and origin-agnostic — whatever eventually proves an
// `AuthenticatedPeerClaim` can hand it straight to this same, already-
// audited check. Only the "how does a responder legitimately construct
// the claim in production" half remains open.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPeerClaim {
    m_id: MachineId,
}

impl AuthenticatedPeerClaim {
    // NENHUM constructor público de produção existe ainda — mesma
    // disciplina de `PeerExpectation::injected_for_harness` (RED-R23).

    #[cfg(test)]
    pub(crate) fn injected_for_harness(m_id: MachineId) -> Self {
        Self { m_id }
    }

    #[must_use]
    pub fn m_id(&self) -> &MachineId {
        &self.m_id
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RespondingPeerError {
    MachineRevoked,
    MachineNotActive,
}

impl SealedBinding {
    /// Responder-side origin (D-1 successor, @kiana E1) — see this
    /// section's module-level comment for why this is a distinct path from
    /// [`from_expected_responder`](Self::from_expected_responder), not a
    /// variant of it. Performs exactly the roster-authority half
    /// `ExpectedResponder::from_peer_expectation` performs for the
    /// initiator: revoked first (mirroring RED-R18's ordering), then
    /// active — both against `snapshot` — so a responder and an initiator
    /// produce identically-shaped refusals for identically-shaped roster
    /// states.
    pub fn from_responding_peer(
        claim: &AuthenticatedPeerClaim,
        snapshot: &RosterSnapshotView,
    ) -> Result<Self, RespondingPeerError> {
        if snapshot.is_revoked(claim.m_id()) {
            return Err(RespondingPeerError::MachineRevoked);
        }
        let member = snapshot
            .lookup_active(claim.m_id())
            .ok_or(RespondingPeerError::MachineNotActive)?;
        Ok(Self {
            hh_id: snapshot.hh_id().clone(),
            m_id: claim.m_id().clone(),
            machine_cert_fingerprint: member.machine_cert_fingerprint(),
            checkpoint_hash: snapshot.checkpoint_hash(),
            checkpoint_sequence: snapshot.checkpoint_sequence(),
        })
    }
}

// ─── Runtime-facade membership projection (Lane R, @ilia) ──────────────────
//
// Feature-gated: only compiled when `mesh-session-runtime` is enabled.
// `D1MembershipKey` (mesh-session-core-rs) is the ceremony's own
// capability — constructed only by that crate's own handshake code,
// after `verify_frame` + delegation + checkpoint all succeed (and after
// nonce consumption), carrying 6 fields: `session_id`, `hh_id`,
// `peer_m_id`, `peer_cert_fingerprint`, `checkpoint_hash`,
// `checkpoint_sequence`. `session_id` is a ceremony-freshness token that
// belongs entirely to the core/D1 admission layer (its own nonce ledger
// already closes replay) — it is deliberately never read here and never
// enters `SealedBinding`. The other 5 fields are compared, in full,
// against the CURRENT roster snapshot before a `SealedBinding` is ever
// produced — a stronger check than `from_responding_peer` above, which
// never had `peer_cert_fingerprint` to compare against at all.
//
// Error is a single, opaque, fieldless type — see `MembershipKeyRejected`
// and `validate_membership_fields`'s own doc for exactly how "no oracle"
// is enforced structurally, not just by convention.

#[cfg(feature = "mesh-session-runtime")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipKeyRejected;

#[cfg(feature = "mesh-session-runtime")]
impl std::fmt::Display for MembershipKeyRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "membership key rejected")
    }
}

#[cfg(feature = "mesh-session-runtime")]
impl std::error::Error for MembershipKeyRejected {}

#[cfg(feature = "mesh-session-runtime")]
impl SealedBinding {
    /// Projects a real `D1MembershipKey` into a `SealedBinding`, or
    /// rejects it. `session_id` is read by nothing here — see the module
    /// comment above.
    ///
    /// **Declared partition (2026-08-05, @ilia audit of `29dc6139`,
    /// independently verified line-by-line, narrowed by @zain's
    /// structural analysis — not a defect, but undeclared before this
    /// note, which promised more than the code delivered):** `peer_m_id`
    /// does NOT go through the same unconditional-then-combine path as
    /// the other 4 fields. It is resolved by roster lookup FIRST, with
    /// two early returns — revoked, then absent — both completing before
    /// any of the 4 comparisons below ever run. `MembershipKeyRejected`
    /// itself still leaks nothing (no variant, no field, identical
    /// `Display`/`Debug` on every path), but the CONTROL FLOW differs,
    /// and is timing-distinguishable, from "m_id valid but one of the
    /// other 4 fields wrong." Accepted as-is, not closed, because calling
    /// this function already requires holding the exact
    /// `&RosterSnapshotView` the m_id would be looked up against — a
    /// caller who can observe this distinction could have read the
    /// roster directly and learned the same thing; the check reveals
    /// only existence/revocation status the caller's own snapshot already
    /// carries, never a secret. **This condition is load-bearing: if this
    /// code path ever becomes reachable by a principal that does NOT
    /// already hold the snapshot, the partition stops being acceptable**
    /// (@zain) — re-audit this note if that ever changes.
    ///
    /// Two DIFFERENT reasons hold the two halves of this ordering, not
    /// one: `lookup_active` before `fingerprint_matches` needs no test at
    /// all — it is a DATA dependency the compiler enforces
    /// (`fingerprint_matches` reads `member.machine_cert_fingerprint()`,
    /// and `member` IS `lookup_active`'s return value). `is_revoked`
    /// before the 4 comparisons has no such dependency and is
    /// behaviorally unobservable if moved — see
    /// `membership_key_is_revoked_check_precedes_field_comparisons`
    /// below, which pins exactly that ONE relationship, not the whole
    /// function's shape.
    pub fn from_membership_key(
        key: &mesh_session_core_rs::intent::D1MembershipKey,
        snapshot: &RosterSnapshotView,
    ) -> Result<Self, MembershipKeyRejected> {
        validate_membership_fields(
            key.hh_id(),
            key.peer_m_id(),
            key.peer_cert_fingerprint(),
            key.checkpoint_hash(),
            key.checkpoint_sequence(),
            snapshot,
        )
    }
}

/// The real comparison logic, factored to primitive-typed arguments so it
/// is directly, non-vacuously testable without a real `D1MembershipKey`
/// — its constructor is `pub(crate)` to mesh-session-core-rs, genuinely
/// unreachable from any other crate, including this one, even in tests
/// (verified: the only two construction sites are inside that crate's
/// own `run_responder_handshake`/`run_initiator_handshake`, both
/// `pub(crate)` there too).
///
/// Revoked/not-active is checked FIRST, matching `from_responding_peer`'s
/// existing ordering exactly — an unavoidable, pre-existing short-circuit
/// (there is no member to compare fields against if the `m_id` isn't
/// active), not something new introduced here. **This IS an observable
/// partition, and only `is_revoked`'s position within it is a genuine,
/// pinned choice** — see `SealedBinding::from_membership_key`'s own doc
/// for the full declaration, including why `lookup_active` before
/// `fingerprint_matches` needs no pin at all (compiler-enforced data
/// dependency) while `is_revoked`'s position does (no such dependency,
/// behaviorally unobservable if moved). Past that gate, all 4 remaining
/// field comparisons (`hh_id`, fingerprint, `checkpoint_hash`,
/// `checkpoint_sequence`) are evaluated UNCONDITIONALLY and combined with
/// a single `&&`, checked once — no per-field early return among THESE
/// four, so no observable control-flow or timing difference between
/// fingerprint being wrong and `checkpoint_sequence` being wrong
/// specifically.
#[cfg(feature = "mesh-session-runtime")]
fn validate_membership_fields(
    hh_id: &str,
    peer_m_id: &str,
    peer_cert_fingerprint: &[u8],
    checkpoint_hash: &[u8],
    checkpoint_sequence: u64,
    snapshot: &RosterSnapshotView,
) -> Result<SealedBinding, MembershipKeyRejected> {
    let m_id = MachineId(peer_m_id.to_string());
    if snapshot.is_revoked(&m_id) {
        return Err(MembershipKeyRejected);
    }
    let member = snapshot.lookup_active(&m_id).ok_or(MembershipKeyRejected)?;

    let hh_id_matches = hh_id == snapshot.hh_id().0.as_str();
    let fingerprint_matches = peer_cert_fingerprint == member.machine_cert_fingerprint().as_slice();
    let checkpoint_hash_matches = checkpoint_hash == snapshot.checkpoint_hash().as_slice();
    let checkpoint_sequence_matches = checkpoint_sequence == snapshot.checkpoint_sequence();

    if !(hh_id_matches
        && fingerprint_matches
        && checkpoint_hash_matches
        && checkpoint_sequence_matches)
    {
        return Err(MembershipKeyRejected);
    }

    Ok(SealedBinding {
        hh_id: snapshot.hh_id().clone(),
        m_id,
        machine_cert_fingerprint: member.machine_cert_fingerprint(),
        checkpoint_hash: snapshot.checkpoint_hash(),
        checkpoint_sequence: snapshot.checkpoint_sequence(),
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
