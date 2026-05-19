//! Cross-platform OS-keystore wrapper for theyOS.
//!
//! Two backends, one trait:
//!
//! - [`SystemKeystore`] — the OS-native credential store. On macOS this is
//!   Keychain Services via the `security-framework` crate; on Linux it's the
//!   `keyring` crate (Secret Service or kernel keyring).
//! - [`FileKeystore`] — a `0600` on-disk fallback for hosts where the system
//!   keystore is unavailable (CI runners, headless servers, macOS without an
//!   accessible login keychain). Opted into explicitly by the caller.
//!
//! Both implement [`KeystoreBackend`] so call sites can target the trait and
//! swap freely (production uses System; tests use File pointed at a tempdir).
//!
//! ## Why this crate exists
//!
//! The original code lived in `household-rs::keystore` and was bound to
//! 32-byte cryptographic scalars. theyOS now needs the same keystore to hold
//! variable-length secrets (LLM API keys, OAuth tokens, etc.) for the LLM
//! proxy. The generic primitives moved here; household-rs keeps its
//! domain-specific helpers (`hh_priv_account`, `se_household_label`, etc.) on
//! top of this crate.
//!
//! ## Service namespace
//!
//! All theyOS keystore entries live under [`SERVICE`] = `com.soyeht.theyos`.
//! Distinct consumers pick distinct *account* prefixes:
//!
//! - household identity:  `household.private_key.<hh_id>`, `machine.private_key.<m_id>`
//! - LLM provider keys:   `llm.api_key.<provider>`, `llm.oauth.<provider>`
//!
//! Keystore entries persist across upgrades because both the service prefix
//! and account labels are stable.

#![allow(clippy::missing_errors_doc)]

mod error;

pub use error::KeystoreError;

pub mod file_backend;

#[cfg(target_os = "linux")]
pub mod linux_backend;

#[cfg(target_os = "linux")]
pub mod tpm_backend;

#[cfg(target_os = "macos")]
pub mod macos_backend;

pub use file_backend::FileKeystore;

#[cfg(target_os = "linux")]
pub use linux_backend::LinuxSystemKeystore as SystemKeystore;

#[cfg(target_os = "linux")]
pub use tpm_backend::{TpmKeystore, tpm2_available};

#[cfg(target_os = "macos")]
pub use macos_backend::MacosSystemKeystore as SystemKeystore;

/// Service prefix used for every theyOS keystore entry. Stable across crates
/// and across upgrades — do not change without a migration plan for existing
/// users' Keychain / Secret Service entries.
pub const SERVICE: &str = "com.soyeht.theyos";

/// Operator-facing hint shown when macOS Keychain returns access-denied.
pub const MACOS_KEYCHAIN_DENIED_HINT: &str =
    "Allow theyos to access the Keychain in System Settings → Privacy & Security.";

/// Operator-facing hint shown when the Linux Secret Service is unreachable
/// (e.g. gnome-keyring is not installed or not unlocked).
pub const LINUX_SECRET_SERVICE_UNAVAILABLE_HINT: &str = "Install and unlock gnome-keyring/Secret Service, or set THEYOS_KEYRING=kernel \
     to use the Linux kernel keyring backend.";

/// Construct a [`KeystoreError::PermissionDenied`] for macOS Keychain access
/// failures, attaching the documented operator hint.
#[must_use]
pub fn macos_keychain_denied_error() -> KeystoreError {
    KeystoreError::PermissionDenied {
        hint: MACOS_KEYCHAIN_DENIED_HINT.into(),
    }
}

/// Construct a [`KeystoreError::Unavailable`] for Linux Secret-Service
/// unavailability, attaching the documented operator hint.
#[must_use]
pub fn linux_secret_service_unavailable_error() -> KeystoreError {
    KeystoreError::Unavailable {
        hint: LINUX_SECRET_SERVICE_UNAVAILABLE_HINT.into(),
    }
}

/// Generic backend trait. Implementations store opaque byte values under
/// `(service, account)` keys.
///
/// All methods are synchronous because the underlying OS APIs are synchronous;
/// callers that need async should wrap calls in `spawn_blocking`. Backends are
/// `Send + Sync` so they can be shared across threads in long-lived services
/// (e.g. the LLM proxy).
pub trait KeystoreBackend: Send + Sync {
    /// Read the secret bytes stored under `account`.
    ///
    /// Returns [`KeystoreError::NotFound`] when the account does not exist.
    fn get(&self, account: &str) -> Result<Vec<u8>, KeystoreError>;

    /// Write `value` under `account`, overwriting any existing entry.
    fn set(&self, account: &str, value: &[u8]) -> Result<(), KeystoreError>;

    /// Best-effort delete. Returns `Ok(())` when the account is already
    /// absent — the post-condition is "the entry is gone", not "we unlinked
    /// it ourselves".
    fn delete(&self, account: &str) -> Result<(), KeystoreError>;
}
