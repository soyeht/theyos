//! TPM2-sealed file backend via `systemd-creds`.
//!
//! Linux-only. Wraps [`FileKeystore`] for storage and shells out to
//! `systemd-creds encrypt/decrypt --with-key=tpm2` for crypto. The
//! plaintext value is never written to disk — it travels through
//! stdin/stdout pipes between this process and `systemd-creds`.
//!
//! ## Threat model
//!
//! - **At rest**: each `(service, account)` lands as a sealed blob in a
//!   `0600` file under `<state_dir>/secrets/<service>/<account>.bin`.
//!   The blob is encrypted to the host's TPM2; moving the file to another
//!   host (clone disk, restore backup) makes it un-decryptable.
//! - **Name-bound**: each blob is sealed with `--name=<account>` so an
//!   attacker who can rename files (e.g. via a path-traversal bug
//!   elsewhere) cannot point one provider's blob at another provider's
//!   account.
//! - **Host integrity**: `--with-key=tpm2` derives the encryption key
//!   directly from the host's TPM2 chip. Clone-disk attacks fail
//!   because the cloned VM either has no TPM or a different one. We
//!   deliberately do NOT use `host+tpm2` here because that variant
//!   also reads `/var/lib/systemd/credential.secret` (root-only), and
//!   the proxy runs as the service user — the TPM-only variant lets
//!   `theyos-llm-proxy` decrypt without elevated privileges. Trade-off
//!   captured in the v1.1 followup as an option to harden further.
//!
//! ## Operational notes
//!
//! - Requires systemd ≥ 250 (released 2021-12). NixOS 22.11+ ships this.
//! - First-boot encryption needs the TPM2 to be present and writable;
//!   subsequent unseal needs nothing from the operator.
//! - Decrypt failures (host migrated, PCRs changed, TPM cleared) surface
//!   as [`KeystoreError::Io`] with a hint pointing at the systemd-creds
//!   error message — the operator must re-add the credential.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use crate::{FileKeystore, KeystoreBackend, KeystoreError};

/// Path to the `systemd-creds` binary. `which` would be more portable but
/// this avoids pulling in a dep — the path resolution is one-shot and
/// cached.
const SYSTEMD_CREDS: &str = "systemd-creds";

/// TPM2-sealed file keystore. See module docs.
#[derive(Debug, Clone)]
pub struct TpmKeystore {
    inner: FileKeystore,
}

impl TpmKeystore {
    /// Build a TPM-sealed keystore rooted at `state_dir`, scoped to
    /// `service`. The on-disk layout matches [`FileKeystore`] —
    /// sealed-vs-plain is invisible to readers, so an operator who
    /// switches backends discovers the change at decrypt time, not at
    /// open time.
    #[must_use]
    pub fn new(state_dir: impl AsRef<Path>, service: impl Into<String>) -> Self {
        Self {
            inner: FileKeystore::new(state_dir, service),
        }
    }
}

impl KeystoreBackend for TpmKeystore {
    fn get(&self, account: &str) -> Result<Vec<u8>, KeystoreError> {
        let ciphertext = self.inner.get(account)?;
        decrypt_with_systemd_creds(account, &ciphertext)
    }

    fn set(&self, account: &str, value: &[u8]) -> Result<(), KeystoreError> {
        let ciphertext = encrypt_with_systemd_creds(account, value)?;
        self.inner.set(account, &ciphertext)
    }

    fn delete(&self, account: &str) -> Result<(), KeystoreError> {
        self.inner.delete(account)
    }
}

/// Run `systemd-creds encrypt --with-key=tpm2 --name=<account> - -`,
/// feeding `plaintext` through stdin and reading the sealed blob from
/// stdout. The blob is binary by default (no `--pretty`); we keep it as
/// raw bytes to round-trip cleanly.
fn encrypt_with_systemd_creds(account: &str, plaintext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let mut child = Command::new(SYSTEMD_CREDS)
        .arg("encrypt")
        .arg("--with-key=tpm2")
        .arg(format!("--name={account}"))
        .arg("-") // input from stdin
        .arg("-") // output to stdout
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| KeystoreError::Unavailable {
            hint: format!("spawn {SYSTEMD_CREDS}: {e} (install systemd ≥ 250)"),
        })?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| KeystoreError::Io {
                kind: "no stdin".into(),
                hint: format!("{SYSTEMD_CREDS} child has no stdin pipe"),
            })?;
        stdin
            .write_all(plaintext)
            .map_err(|e| KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("write to {SYSTEMD_CREDS} stdin: {e}"),
            })?;
    }

    let output = child.wait_with_output().map_err(|e| KeystoreError::Io {
        kind: e.kind().to_string(),
        hint: format!("wait {SYSTEMD_CREDS}: {e}"),
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(KeystoreError::Io {
            kind: format!("systemd-creds encrypt exit {}", output.status),
            hint: stderr.trim().to_string(),
        });
    }
    Ok(output.stdout)
}

/// Run `systemd-creds decrypt --name=<account> - -`, feeding ciphertext
/// through stdin and reading plaintext from stdout. The `--name=` flag
/// makes the operation reject a blob sealed under a different account —
/// this is the bind that turns a path-traversal bug elsewhere into a
/// decrypt-failure rather than a credential mixup.
fn decrypt_with_systemd_creds(account: &str, ciphertext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let mut child = Command::new(SYSTEMD_CREDS)
        .arg("decrypt")
        .arg(format!("--name={account}"))
        .arg("-")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| KeystoreError::Unavailable {
            hint: format!("spawn {SYSTEMD_CREDS}: {e}"),
        })?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| KeystoreError::Io {
                kind: "no stdin".into(),
                hint: format!("{SYSTEMD_CREDS} child has no stdin pipe"),
            })?;
        stdin
            .write_all(ciphertext)
            .map_err(|e| KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("write to {SYSTEMD_CREDS} stdin: {e}"),
            })?;
    }

    let output = child.wait_with_output().map_err(|e| KeystoreError::Io {
        kind: e.kind().to_string(),
        hint: format!("wait {SYSTEMD_CREDS}: {e}"),
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(KeystoreError::Io {
            kind: format!("systemd-creds decrypt exit {}", output.status),
            hint: format!(
                "{} (host PCR/TPM state may have changed; re-add credential)",
                stderr.trim()
            ),
        });
    }
    Ok(output.stdout)
}

/// `true` when the running host can probably seal credentials to a TPM2.
///
/// Cached for the process lifetime — TPM presence does not change at
/// runtime, and the probe is non-trivial (it spawns systemd-creds). A
/// `false` return is a sticky decision: the caller picks the file
/// fallback and we stay there until restart.
#[must_use]
pub fn tpm2_available() -> bool {
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(probe_tpm2)
}

fn probe_tpm2() -> bool {
    // Cheap kernel-level check first: if there's no /sys/class/tpm/tpm0
    // the host literally has no TPM device, so don't even spawn.
    if !Path::new("/sys/class/tpm/tpm0").exists() {
        tracing::debug!("no /sys/class/tpm/tpm0 — TPM2 backend unavailable");
        return false;
    }

    // The kernel knows about a TPM; now check whether we can actually
    // talk to it. `has-tpm2` only tests kernel support — on hosts
    // where /dev/tpmrm0 is root-only (NixOS without
    // `security.tpm2.enable`), the proxy daemon (running as the
    // service user) would pass this check and then fail at first
    // encrypt/decrypt with InteractiveAuthenticationRequired. So we
    // must verify the resource-manager device is reachable from THIS
    // process, not just from the kernel's point of view.
    match std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/tpmrm0")
    {
        Ok(_) => {
            tracing::debug!("TPM2 backend available (/dev/tpmrm0 readable)");
            true
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "TPM2 device /dev/tpmrm0 not accessible to this process; falling back. \
                 On NixOS enable `security.tpm2.enable = true` and add the proxy user \
                 to the `tss` group."
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn delete_is_idempotent_without_tpm() {
        // Delete only touches the file backend; safe to test without a TPM.
        let dir = TempDir::new().unwrap();
        let ks = TpmKeystore::new(dir.path(), "test.service");
        ks.delete("never.existed").expect("missing key delete is ok");
    }

    /// Round-trip end-to-end. Gated on a real TPM2 + systemd-creds — CI
    /// runners without TPM skip. Run locally on bignix/devs to verify.
    #[test]
    fn encrypt_then_decrypt_round_trip() {
        if !tpm2_available() {
            eprintln!("skipping: no TPM2 available on this host");
            return;
        }
        let dir = TempDir::new().unwrap();
        let ks = TpmKeystore::new(dir.path(), "test.tpm.roundtrip");
        let plaintext = b"sk-aurora-test-0123456789abcdef";
        ks.set("llm.api_key.test", plaintext).unwrap();
        let got = ks.get("llm.api_key.test").unwrap();
        assert_eq!(got, plaintext);
    }

    #[test]
    fn name_binding_rejects_mismatched_account() {
        if !tpm2_available() {
            eprintln!("skipping: no TPM2 available on this host");
            return;
        }
        let dir = TempDir::new().unwrap();
        let ks = TpmKeystore::new(dir.path(), "test.tpm.binding");
        ks.set("provider.a", b"secret-a").unwrap();

        // Manually rename the file to look like provider.b — decrypt
        // should reject because the sealed --name doesn't match.
        let src = ks
            .inner
            .path_for("provider.a");
        let dst = ks.inner.path_for("provider.b");
        std::fs::rename(&src, &dst).unwrap();

        let err = ks.get("provider.b").unwrap_err();
        assert!(
            matches!(err, KeystoreError::Io { .. }),
            "expected Io error, got {err:?}",
        );
    }
}
