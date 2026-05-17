//! OS keystore wrapper.
//!
//! - On Linux, the 32-byte private scalar is stored via the `keyring` crate
//!   using the kernel keyring backend.
//! - On macOS, the private scalar lives **inside the Secure Enclave** —
//!   nothing software-side stores it; the keystore label is the only handle
//!   and lookup happens via `SecItemCopyMatching` (see [`crate::keys_se`]).
//!
//! This module owns the cross-platform error mapping; backend-specific code
//! sits in [`crate::keys_se`] (macOS) and the `linux` submodule below.

#![allow(dead_code)]

use crate::error::KeystoreError;
use crate::ids::{HouseholdId, MachineId};

/// Stable keystore service prefix used across crates.
pub const SERVICE: &str = "com.soyeht.theyos";

/// Exact operator hint for macOS Keychain access denial.
pub const MACOS_KEYCHAIN_DENIED_HINT: &str =
    "Allow theyos to access the Keychain in System Settings → Privacy & Security.";

/// Exact operator hint for Linux kernel keyring unavailability.
pub const LINUX_SECRET_SERVICE_UNAVAILABLE_HINT: &str =
    "Enable Linux kernel keyring support and ensure the user session keyring is available.";

/// Contract helper for mapping a macOS Keychain-denied backend failure.
#[doc(hidden)]
#[must_use]
pub fn macos_keychain_denied_error() -> KeystoreError {
    KeystoreError::PermissionDenied {
        hint: MACOS_KEYCHAIN_DENIED_HINT.into(),
    }
}

/// Contract helper for mapping a Linux kernel-keyring-unavailable backend failure.
#[doc(hidden)]
#[must_use]
pub fn linux_secret_service_unavailable_error() -> KeystoreError {
    KeystoreError::Unavailable {
        hint: LINUX_SECRET_SERVICE_UNAVAILABLE_HINT.into(),
    }
}

/// Account label for the household private key, parametrised by `hh_id`.
#[must_use]
pub fn hh_priv_account(hh_id: &HouseholdId) -> String {
    format!("household.private_key.{}", hh_id.as_str())
}

/// Account label for the machine private key, parametrised by `m_id`.
#[must_use]
pub fn m_priv_account(m_id: &MachineId) -> String {
    format!("machine.private_key.{}", m_id.as_str())
}

/// macOS Keychain label for an SE-resident household key.
#[must_use]
pub fn se_household_label(hh_id: &HouseholdId) -> String {
    format!("com.soyeht.theyos.household.{}", hh_id.as_str())
}

/// macOS Keychain label for an SE-resident machine key.
#[must_use]
pub fn se_machine_label(m_id: &MachineId) -> String {
    format!("com.soyeht.theyos.machine.{}", m_id.as_str())
}

/// Phase 1 creates the SE key before the derived `hh_id`/`m_id` exists, so
/// create and load both use fixed labels for the singleton local identity.
#[must_use]
pub fn se_bootstrap_label(which: &str) -> String {
    format!("com.soyeht.theyos.{which}.bootstrap")
}

/// File-based fallback keystore. Used **only** when the operator opts into
/// software keys via `THEYOS_FORCE_SOFTWARE_KEYS=1` (covers the macOS-no-SE
/// case — Intel pre-T2 hardware, CI runners with no SE access).
///
/// Stores the 32-byte scalar at `<state_dir>/household/secrets/{account}.bin`
/// with `mode 0600`.
pub mod software_fallback {
    use std::fs::{self, OpenOptions};
    use std::io::{ErrorKind, Read, Write};
    use std::path::{Path, PathBuf};

    use super::KeystoreError;

    fn secrets_dir(state_dir: &Path) -> PathBuf {
        state_dir.join("household").join("secrets")
    }

    fn account_path(state_dir: &Path, account: &str) -> PathBuf {
        secrets_dir(state_dir).join(format!("{account}.bin"))
    }

    pub fn write_secret_scalar(
        state_dir: &Path,
        account: &str,
        scalar: &[u8; 32],
    ) -> Result<(), KeystoreError> {
        let dir = secrets_dir(state_dir);
        if let Err(e) = fs::create_dir_all(&dir) {
            return Err(KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("create {}: {e}", dir.display()),
            });
        }
        let path = account_path(state_dir, account);
        write_0600(&path, scalar).map_err(|e| KeystoreError::Io {
            kind: e.kind().to_string(),
            hint: format!("write {}: {e}", path.display()),
        })?;
        Ok(())
    }

    /// Best-effort destruction of the on-disk scalar file. Returns `Ok(())`
    /// when the file is already absent — the post-condition is "the file is
    /// gone", not "we unlinked it ourselves".
    ///
    /// Used by the Phase 3 Shamir transition (`CeremonyTxn::commit`) to wipe
    /// the sole-machine `HH_priv` from the file fallback once the household
    /// has grown to N≥2. After this call no software-fallback caller can
    /// read the scalar back.
    pub fn delete_secret_scalar(state_dir: &Path, account: &str) -> Result<(), KeystoreError> {
        let path = account_path(state_dir, account);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("delete {}: {e}", path.display()),
            }),
        }
    }

    pub fn read_secret_scalar(state_dir: &Path, account: &str) -> Result<[u8; 32], KeystoreError> {
        let path = account_path(state_dir, account);
        let mut f = match OpenOptions::new().read(true).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(KeystoreError::NotFound {
                    label: format!("{} (file fallback)", path.display()),
                });
            }
            Err(e) => {
                return Err(KeystoreError::Io {
                    kind: e.kind().to_string(),
                    hint: format!("open {}: {e}", path.display()),
                });
            }
        };
        let mut bytes = Vec::with_capacity(32);
        f.read_to_end(&mut bytes).map_err(|e| KeystoreError::Io {
            kind: e.kind().to_string(),
            hint: format!("read {}: {e}", path.display()),
        })?;
        if bytes.len() != 32 {
            return Err(KeystoreError::InvalidKeyMaterial(format!(
                "expected 32-byte scalar in {}, got {}",
                path.display(),
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    #[cfg(unix)]
    fn write_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let tmp_path = path.with_extension("bin.tmp");
        match fs::remove_file(&tmp_path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        if let Err(e) = f.write_all(bytes) {
            drop(f);
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        if let Err(e) = f.sync_all() {
            drop(f);
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        drop(f);
        fs::rename(&tmp_path, path)?;
        if let Some(parent) = path.parent() {
            let dir = OpenOptions::new().read(true).open(parent)?;
            dir.sync_all()?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn write_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        let tmp_path = path.with_extension("bin.tmp");
        match fs::remove_file(&tmp_path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        if let Err(e) = f.write_all(bytes) {
            drop(f);
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        if let Err(e) = f.sync_all() {
            drop(f);
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        drop(f);
        fs::rename(&tmp_path, path)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::{
        KeystoreError, LINUX_SECRET_SERVICE_UNAVAILABLE_HINT, SERVICE,
        linux_secret_service_unavailable_error,
    };

    fn configure_backend_from_env() {
        if std::env::var("THEYOS_KEYRING")
            .map(|v| v.eq_ignore_ascii_case("kernel"))
            .unwrap_or(false)
        {
            keyring::set_default_credential_builder(keyring::keyutils::default_credential_builder());
        }
    }

    /// Write a 32-byte private scalar (base64-encoded) under `(SERVICE, account)`.
    pub fn write_secret_scalar(account: &str, scalar: &[u8; 32]) -> Result<(), KeystoreError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        configure_backend_from_env();
        let entry = keyring::Entry::new(SERVICE, account).map_err(map_keyring_err)?;
        entry
            .set_password(&B64.encode(scalar))
            .map_err(map_keyring_err)?;
        Ok(())
    }

    /// Read a 32-byte private scalar.
    pub fn read_secret_scalar(account: &str) -> Result<[u8; 32], KeystoreError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        configure_backend_from_env();
        let entry = keyring::Entry::new(SERVICE, account).map_err(map_keyring_err)?;
        let pw = entry.get_password().map_err(map_keyring_err)?;
        let bytes = B64
            .decode(pw)
            .map_err(|e| KeystoreError::InvalidKeyMaterial(format!("base64: {e}")))?;
        if bytes.len() != 32 {
            return Err(KeystoreError::InvalidKeyMaterial(format!(
                "expected 32-byte scalar, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    pub fn delete_secret_scalar(account: &str) -> Result<(), KeystoreError> {
        configure_backend_from_env();
        let entry = keyring::Entry::new(SERVICE, account).map_err(map_keyring_err)?;
        entry.delete_credential().map_err(map_keyring_err)?;
        Ok(())
    }

    pub(super) fn map_keyring_err(e: keyring::Error) -> KeystoreError {
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
}

/// Contract helper for Linux keyring error-mapping tests.
#[cfg(target_os = "linux")]
#[doc(hidden)]
#[must_use]
pub fn map_linux_keyring_error_for_contract(error: keyring::Error) -> KeystoreError {
    linux::map_keyring_err(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::base32_lower_nopad_encode;

    #[test]
    fn account_labels_stable() {
        let hh = HouseholdId(format!("hh_{}", base32_lower_nopad_encode(&[7u8; 32])));
        let m = MachineId(format!("m_{}", base32_lower_nopad_encode(&[7u8; 32])));
        assert!(hh_priv_account(&hh).starts_with("household.private_key.hh_"));
        assert!(m_priv_account(&m).starts_with("machine.private_key.m_"));
    }
}
