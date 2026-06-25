//! Domain-specific keystore helpers for the household crate.
//!
//! The generic cross-platform keystore primitives — [`KeystoreError`],
//! [`SERVICE`], the Secret Service / Keychain / file backends — live in the
//! `keystore-rs` crate and are re-exported below. This module adds the
//! identifier-shaped account labels that the household ceremony uses and
//! preserves the legacy 32-byte scalar API consumed by [`crate::bootstrap`]
//! and [`crate::keys_se`].
//!
//! Backward compat invariants:
//!
//! - Same service prefix (`com.soyeht.theyos`) — Keychain / Secret Service
//!   entries written by older builds continue to load.
//! - Same account labels (`household.private_key.<hh_id>`,
//!   `machine.private_key.<m_id>`, `com.soyeht.theyos.<which>.bootstrap`).
//! - Same call signatures on `software_fallback::*` and `linux::*` so
//!   existing call sites do not need to change.

#![allow(dead_code)]

use crate::ids::{HouseholdId, MachineId};

// Generic keystore surface re-exported so callers can `use crate::keystore::*`
// like before. The error type comes through `crate::error::KeystoreError`,
// which is itself a re-export of `keystore_rs::KeystoreError`.
pub use keystore_rs::{
    KeystoreError, LINUX_SECRET_SERVICE_UNAVAILABLE_HINT, MACOS_KEYCHAIN_DENIED_HINT, SERVICE,
    linux_secret_service_unavailable_error, macos_keychain_denied_error,
};

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

/// File-based fallback keystore for 32-byte cryptographic scalars.
///
/// Used **only** when the operator opts into software keys via
/// `THEYOS_FORCE_SOFTWARE_KEYS=1` (covers the macOS-no-SE case — Intel pre-T2
/// hardware, CI runners with no SE access).
///
/// Stores scalars at `<state_dir>/household/secrets/<account>.bin` with mode
/// `0600`. This domain-specific on-disk layout pre-dates the keystore-rs
/// extraction and is preserved verbatim — bootstrap tests load files from
/// these exact paths to simulate keystore corruption.
///
/// New code that needs a generic file-backed keystore should use
/// [`keystore_rs::FileKeystore`] directly with its own service namespacing.
pub mod software_fallback {
    use std::fs::{self, OpenOptions};
    use std::io::{ErrorKind, Read, Write};
    use std::path::{Path, PathBuf};

    use super::KeystoreError;
    use zeroize::Zeroize;

    fn secrets_dir(state_dir: &Path) -> PathBuf {
        state_dir.join("household").join("secrets")
    }

    fn account_path(state_dir: &Path, account: &str) -> PathBuf {
        secrets_dir(state_dir).join(format!("{account}.bin"))
    }

    /// Create `dir` if missing and, on unix, restrict it to owner-only `0o700`.
    /// Idempotent: also tightens an already-existing directory whose mode is
    /// more permissive, so installs created under a looser umask before this
    /// guard existed get repaired on the next write. The scalar file itself is
    /// already written `0o600`; this stops the secrets directory from being
    /// listable by other local users (which would leak the account labels, i.e.
    /// which household / machine ids exist).
    fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(dir)?.permissions();
            if perms.mode() & 0o777 != 0o700 {
                perms.set_mode(0o700);
                fs::set_permissions(dir, perms)?;
            }
        }
        Ok(())
    }

    pub fn write_secret_scalar(
        state_dir: &Path,
        account: &str,
        scalar: &[u8; 32],
    ) -> Result<(), KeystoreError> {
        let dir = secrets_dir(state_dir);
        if let Err(e) = ensure_private_dir(&dir) {
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
            let err = KeystoreError::InvalidKeyMaterial(format!(
                "expected 32-byte scalar in {}, got {}",
                path.display(),
                bytes.len()
            ));
            bytes.zeroize();
            return Err(err);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        // Wipe the heap copy of the scalar before returning. `out` is the
        // caller-owned result; its key type zeroizes on its own drop.
        bytes.zeroize();
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

/// Linux Secret Service / kernel-keyring wrapper for 32-byte cryptographic
/// scalars. Delegates to [`keystore_rs::SystemKeystore`] (which is
/// `LinuxSystemKeystore` on Linux) and re-imposes the 32-byte invariant.
#[cfg(target_os = "linux")]
pub mod linux {
    use keystore_rs::{KeystoreBackend, SystemKeystore};

    use super::KeystoreError;

    fn store() -> SystemKeystore {
        SystemKeystore::default()
    }

    pub fn write_secret_scalar(account: &str, scalar: &[u8; 32]) -> Result<(), KeystoreError> {
        store().set(account, scalar)
    }

    pub fn read_secret_scalar(account: &str) -> Result<[u8; 32], KeystoreError> {
        let bytes = store().get(account)?;
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
        store().delete(account)
    }
}

/// Contract helper kept for the keystore-error test in
/// `tests/keystore_errors.rs`. Delegates to keystore-rs.
#[cfg(target_os = "linux")]
#[doc(hidden)]
#[must_use]
pub fn map_linux_keyring_error_for_contract(error: keyring::Error) -> KeystoreError {
    keystore_rs::linux_backend::map_keyring_err(error)
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

    #[test]
    fn software_fallback_read_round_trip() {
        let td = tempfile::tempdir().unwrap();
        let scalar = [9u8; 32];
        software_fallback::write_secret_scalar(td.path(), "household.private_key.hh_rt", &scalar)
            .unwrap();
        let got = software_fallback::read_secret_scalar(td.path(), "household.private_key.hh_rt")
            .unwrap();
        assert_eq!(got, scalar);
    }

    #[cfg(unix)]
    #[test]
    fn software_fallback_write_uses_owner_only_perms() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempfile::tempdir().unwrap();
        software_fallback::write_secret_scalar(td.path(), "machine.private_key.m_perm", &[7u8; 32])
            .unwrap();

        let file = td
            .path()
            .join("household")
            .join("secrets")
            .join("machine.private_key.m_perm.bin");
        let dir = td.path().join("household").join("secrets");
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600,
            "scalar file must be owner-only"
        );
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "secrets dir must be owner-only (not listable by other local users)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn software_fallback_tightens_preexisting_loose_dir() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempfile::tempdir().unwrap();
        let dir = td.path().join("household").join("secrets");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        software_fallback::write_secret_scalar(
            td.path(),
            "household.private_key.hh_tight",
            &[3u8; 32],
        )
        .unwrap();

        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "a pre-existing permissive secrets dir must be tightened on write"
        );
    }
}
