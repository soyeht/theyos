//! Typed errors for the OS keystore wrapper.
//!
//! Each variant carries enough context for a structured-log emitter to record
//! `error.kind` / `error.hint` triples (matching the household-rs FR-014
//! observability contract, which is the original consumer of this type).

use thiserror::Error;

/// Errors from the OS keystore wrapper. Each variant carries a `hint` field so
/// the caller can show the operator the recovery action.
#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("keystore unavailable: {hint}")]
    Unavailable { hint: String },

    #[error("keystore permission denied: {hint}")]
    PermissionDenied { hint: String },

    /// Secure-Enclave-specific availability error. Kept here for backward
    /// compatibility with the household-rs error contract — keystore-rs itself
    /// does not own the SE code path (that lives in `household-rs::keys_se`),
    /// but consumers map SE errors through this variant for consistency.
    #[error("Secure Enclave unavailable on this machine: {hint}")]
    SeUnavailable { hint: String },

    #[error("entry not found: {label}")]
    NotFound { label: String },

    /// A [`KeystoreBackend::create_only`](crate::KeystoreBackend::create_only)
    /// call found an existing entry and left it untouched.
    #[error("keystore entry already exists: {label}")]
    Conflict { label: String },

    /// A backend cannot perform the requested operation at all (structurally,
    /// not "temporarily down") — e.g. `create_only` on a backend whose
    /// underlying API has no race-free create primitive. Distinct from
    /// [`Self::Unavailable`], which means the same operation would work if
    /// the service were reachable/unlocked.
    #[error("keystore operation not supported: {hint}")]
    Unsupported { hint: String },

    /// A reinspection step (used to resolve a
    /// [`CreateOutcome`](crate::CreateOutcome) after an ambiguous install)
    /// found the on-disk entry is not what it should be: a symlink where a
    /// regular file is required, a non-regular file, or a mode/owner that
    /// doesn't match what this backend itself writes. Fails closed rather
    /// than reading through it — an entry with these properties was never
    /// produced by this backend's own `set`/`create_only`, so trusting its
    /// content would mean trusting whatever placed it there.
    #[error("keystore entry failed a security check for {label}: {hint}")]
    SecurityViolation { label: String, hint: String },

    #[error("keystore I/O error: {kind}: {hint}")]
    Io { kind: String, hint: String },

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),
}

impl KeystoreError {
    /// Stable machine-readable error kind for the `error.kind` log field.
    /// These strings are part of the observability contract — do NOT rename
    /// without bumping log-consumer schema.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Unavailable { .. } => "keystore.unavailable",
            Self::PermissionDenied { .. } => "se.permission_denied",
            Self::SeUnavailable { .. } => "se.unavailable",
            Self::NotFound { .. } => "keystore.not_found",
            Self::Conflict { .. } => "keystore.conflict",
            Self::Unsupported { .. } => "keystore.unsupported",
            Self::SecurityViolation { .. } => "keystore.security_violation",
            Self::Io { .. } => "keystore.io",
            Self::SigningFailed(_) => "keystore.signing_failed",
            Self::InvalidKeyMaterial(_) => "keystore.invalid_key_material",
        }
    }

    /// Operator-facing hint string (matches the `error.hint` log field).
    #[must_use]
    pub fn hint(&self) -> String {
        match self {
            Self::Unavailable { hint }
            | Self::PermissionDenied { hint }
            | Self::SeUnavailable { hint }
            | Self::Io { hint, .. }
            | Self::Unsupported { hint }
            | Self::SecurityViolation { hint, .. } => hint.clone(),
            Self::NotFound { label } => format!("entry {label} missing from keystore"),
            Self::Conflict { label } => format!("entry {label} already exists"),
            Self::SigningFailed(msg) | Self::InvalidKeyMaterial(msg) => msg.clone(),
        }
    }
}
