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
            | Self::Io { hint, .. } => hint.clone(),
            Self::NotFound { label } => format!("entry {label} missing from keystore"),
            Self::SigningFailed(msg) | Self::InvalidKeyMaterial(msg) => msg.clone(),
        }
    }
}
