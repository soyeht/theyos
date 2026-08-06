//! Linux Secret Service / kernel-keyring backend via the `keyring` crate.
//!
//! Two sub-backends are selectable at runtime via the `THEYOS_KEYRING` env
//! var:
//!
//! - unset / any other value: Secret Service (`gnome-keyring`, `KWallet`, …).
//!   Standard desktop path.
//! - `kernel`: Linux kernel keyring (`keyutils`). Used by headless servers /
//!   CI environments that have no Secret Service daemon. Values do not
//!   persist across reboots in this mode.

use crate::{
    KeystoreBackend, KeystoreError, LINUX_SECRET_SERVICE_UNAVAILABLE_HINT, SERVICE,
    linux_secret_service_unavailable_error,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

fn configure_backend_from_env() {
    if std::env::var("THEYOS_KEYRING").is_ok_and(|v| v.eq_ignore_ascii_case("kernel")) {
        keyring::set_default_credential_builder(keyring::keyutils::default_credential_builder());
    }
}

/// Linux system keystore. Service prefix defaults to [`SERVICE`] but can be
/// overridden if a caller is operating on entries outside the theyOS
/// namespace (rare).
#[derive(Debug, Clone)]
pub struct LinuxSystemKeystore {
    service: String,
}

impl Default for LinuxSystemKeystore {
    fn default() -> Self {
        Self::new(SERVICE)
    }
}

impl LinuxSystemKeystore {
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

impl KeystoreBackend for LinuxSystemKeystore {
    fn get(&self, account: &str) -> Result<Vec<u8>, KeystoreError> {
        configure_backend_from_env();
        let entry = keyring::Entry::new(&self.service, account).map_err(map_keyring_err)?;
        let password = entry.get_password().map_err(map_keyring_err)?;
        B64.decode(password)
            .map_err(|e| KeystoreError::InvalidKeyMaterial(format!("base64: {e}")))
    }

    fn set(&self, account: &str, value: &[u8]) -> Result<(), KeystoreError> {
        configure_backend_from_env();
        let entry = keyring::Entry::new(&self.service, account).map_err(map_keyring_err)?;
        entry
            .set_password(&B64.encode(value))
            .map_err(map_keyring_err)?;
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<(), KeystoreError> {
        configure_backend_from_env();
        let entry = keyring::Entry::new(&self.service, account).map_err(map_keyring_err)?;
        // NoEntry → idempotent delete; treat the same as Ok.
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(other) => Err(map_keyring_err(other)),
        }
    }
}

/// Map a `keyring` crate error to our typed [`KeystoreError`].
///
/// Public-but-hidden to support contract tests in downstream crates that
/// verify the error mapping shape without depending on `keyring` directly.
#[doc(hidden)]
#[must_use]
pub fn map_keyring_err(e: keyring::Error) -> KeystoreError {
    match e {
        keyring::Error::NoEntry => KeystoreError::NotFound {
            label: "(unknown)".into(),
        },
        keyring::Error::PlatformFailure(_) | keyring::Error::NoStorageAccess(_) => {
            linux_secret_service_unavailable_error()
        }
        other => KeystoreError::Io {
            kind: format!("{other:?}"),
            hint: LINUX_SECRET_SERVICE_UNAVAILABLE_HINT.into(),
        },
    }
}
