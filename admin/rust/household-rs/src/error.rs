//! Typed errors for the household crate.
//!
//! Every error carries a `stage`/`kind`/`hint` triple for the structured-log
//! contract in FR-014. The `Display` form embeds a human-readable hint so the
//! caller can surface it directly to the operator.

use std::path::PathBuf;
use thiserror::Error;

// KeystoreError lives in the `keystore-rs` crate now; re-exported here so
// downstream code (bootstrap, callers of household-rs) keeps importing
// `household_rs::error::KeystoreError` unchanged.
pub use keystore_rs::KeystoreError;

/// Cryptographic / encoding errors at the protocol layer (CBOR, signatures,
/// identifier derivation).
#[derive(Debug, Error)]
pub enum HouseholdError {
    #[error("cbor: {0}")]
    Cbor(String),

    #[error("identifier malformed: {0}")]
    Identifier(String),

    #[error("identifier mismatch: expected {expected}, got {actual}")]
    IdentifierMismatch { expected: String, actual: String },

    #[error("public key malformed (must be 33-byte SEC1 compressed P-256)")]
    PublicKeyMalformed,

    #[error("signature malformed (must be 64-byte raw r||s ECDSA P-256)")]
    SignatureMalformed,

    #[error("signature verification failed")]
    SignatureMismatch,

    #[error("invalid record: {0}")]
    InvalidRecord(String),

    #[error("invalid certificate: {0}")]
    InvalidCert(String),

    #[error("base32 decode failed: {0}")]
    Base32(String),

    #[error("base64 decode failed: {0}")]
    Base64(String),

    #[error("QR encoding failed: {0}")]
    QrEncode(String),
}

/// Errors from atomic CBOR file I/O.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("filesystem error at {path}: {kind}: {hint}")]
    Io {
        path: PathBuf,
        kind: String,
        hint: String,
    },

    #[error("disk full while writing {path}: {hint}")]
    OutOfSpace { path: PathBuf, hint: String },

    #[error("permission denied at {path}: {hint}")]
    PermissionDenied { path: PathBuf, hint: String },

    /// A semantic rename was issued, but its parent-directory durability
    /// barrier failed. The destination may already contain the new value;
    /// callers must re-read/reconcile and must not run no-effect rollback.
    #[error("storage effect may have taken effect at {path}: {hint}")]
    MayHaveTakenEffect { path: PathBuf, hint: String },

    #[error("encode/decode failure: {0}")]
    Encoding(#[from] HouseholdError),
}

impl StorageError {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Io { .. } => "storage.io",
            Self::OutOfSpace { .. } => "storage.out_of_space",
            Self::PermissionDenied { .. } => "storage.permission_denied",
            Self::MayHaveTakenEffect { .. } => "storage.may_have_taken_effect",
            Self::Encoding(_) => "storage.encoding",
        }
    }

    #[must_use]
    pub fn hint(&self) -> String {
        match self {
            Self::Io { hint, .. }
            | Self::OutOfSpace { hint, .. }
            | Self::PermissionDenied { hint, .. }
            | Self::MayHaveTakenEffect { hint, .. } => hint.clone(),
            Self::Encoding(e) => e.to_string(),
        }
    }
}

/// Errors emitted by the bootstrap orchestrator.
#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("keystore failure during {stage}: {source}")]
    Keystore {
        #[source]
        source: KeystoreError,
        stage: &'static str,
    },

    #[error("storage failure during {stage}: {source}")]
    Storage {
        #[source]
        source: StorageError,
        stage: &'static str,
    },

    #[error("encoding/protocol failure during {stage}: {source}")]
    Encoding {
        #[source]
        source: HouseholdError,
        stage: &'static str,
    },

    #[error("household_record.cbor present but machine_cert.cbor missing")]
    CertMissingButRecordPresent,

    #[error("household_record.cbor missing but machine_cert.cbor present")]
    RecordMissingButCertPresent,

    #[error("platform unsupported: {0}")]
    PlatformUnsupported(String),

    #[error("system clock error during {stage}: {message}")]
    Clock {
        stage: &'static str,
        message: String,
    },

    #[error("invalid bootstrap option: {0}")]
    InvalidOption(String),
}

impl BootstrapError {
    /// Stable machine-readable `error.stage` for structured logs.
    #[must_use]
    pub fn stage(&self) -> &'static str {
        match self {
            Self::Keystore { stage, .. }
            | Self::Storage { stage, .. }
            | Self::Encoding { stage, .. }
            | Self::Clock { stage, .. } => stage,
            Self::CertMissingButRecordPresent | Self::RecordMissingButCertPresent => {
                "bootstrap.load"
            }
            Self::PlatformUnsupported(_) => "bootstrap.platform_check",
            Self::InvalidOption(_) => "bootstrap.opts",
        }
    }

    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Keystore { source, .. } => source.kind(),
            Self::Storage { source, .. } => source.kind(),
            Self::Encoding { .. } => "encoding",
            Self::CertMissingButRecordPresent => "load.cert_missing",
            Self::RecordMissingButCertPresent => "load.record_missing",
            Self::PlatformUnsupported(_) => "platform.unsupported",
            Self::Clock { .. } => "clock.invalid",
            Self::InvalidOption(_) => "opts.invalid",
        }
    }

    #[must_use]
    pub fn hint(&self) -> String {
        match self {
            Self::Keystore { source, .. } => source.hint(),
            Self::Storage { source, .. } => source.hint(),
            Self::Encoding { source, .. } => source.to_string(),
            Self::CertMissingButRecordPresent => {
                "household_record.cbor exists but machine_cert.cbor is missing — run `theyos install` to repair, or remove the household directory and re-bootstrap".into()
            }
            Self::RecordMissingButCertPresent => {
                "machine_cert.cbor exists but household_record.cbor is missing — remove the household directory and re-bootstrap".into()
            }
            Self::PlatformUnsupported(p) => {
                format!("platform '{p}' is not supported in Phase 1 — supported: macOS 14+ (SE), Linux x86_64/aarch64")
            }
            Self::Clock { message, .. } => {
                format!("system clock must be after Unix epoch before bootstrap can sign identity records: {message}")
            }
            Self::InvalidOption(o) => o.clone(),
        }
    }
}
