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

use zeroize::Zeroize;

use crate::file_backend::InstallOutcome;
use crate::{CreateOutcome, FileKeystore, KeystoreBackend, KeystoreError};

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

    /// See [`FileKeystore::sweep_orphaned_create_attempts`] — `create_only`
    /// on this backend delegates to the same file-backed install path, so a
    /// crash mid-`create_only` leaves an orphaned tmp file the same way
    /// (holding sealed ciphertext here rather than plaintext, but still
    /// secret material that does not expire on its own).
    pub fn sweep_orphaned_create_attempts(&self) -> std::io::Result<usize> {
        self.inner.sweep_orphaned_create_attempts()
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

    /// Seals `value` and publishes it iff `account` is absent.
    ///
    /// Does NOT delegate to [`FileKeystore::create_only`] — that backend
    /// compares raw bytes, which is wrong here: `systemd-creds encrypt` is
    /// randomized (each call produces a different sealed blob for the same
    /// plaintext), so a byte-for-byte comparison of two ciphertexts of the
    /// identical plaintext would never match, turning a caller's own
    /// idempotent retry into a spurious [`CreateOutcome::Conflict`] instead
    /// of the [`CreateOutcome::ExistingExactDurable`] it should see. Instead
    /// this installs via the same underlying no-replace primitive
    /// ([`FileKeystore::raw_attempt_install`]) but, on anything short of a
    /// clean durable install, reinspects and compares at the PLAINTEXT
    /// level — decrypting the on-disk ciphertext, comparing to `value`, and
    /// zeroizing the decrypted buffer once the comparison is done. The
    /// underlying encryption is never bypassed: File never sees plaintext,
    /// only this module does, only transiently, and this method — like
    /// File's — never overwrites an existing entry.
    fn create_only(&self, account: &str, value: &[u8]) -> Result<CreateOutcome, KeystoreError> {
        self.inner.ensure_dir().map_err(|e| KeystoreError::Io {
            kind: e.kind().to_string(),
            hint: format!("create secrets dir: {e}"),
        })?;
        let ciphertext = encrypt_with_systemd_creds(account, value)?;
        match self.inner.raw_attempt_install(account, &ciphertext) {
            Ok(InstallOutcome::Durable) => Ok(CreateOutcome::CreatedDurable),
            Ok(InstallOutcome::Ambiguous(_) | InstallOutcome::ProvenConflict) | Err(_) => {
                self.stabilize_and_classify_plaintext(account, value)
            }
        }
    }
}

impl TpmKeystore {
    /// Reinspect the sealed blob currently at `account`'s path (if any),
    /// decrypt it, and compare the PLAINTEXT to `expected` — never the raw
    /// ciphertext, since two sealed blobs of identical plaintext are never
    /// byte-identical. See [`KeystoreBackend::create_only`]'s impl on this
    /// type for why this exists instead of delegating to
    /// [`FileKeystore::create_only`].
    ///
    /// Delegates to [`FileKeystore::reinspect_and_stabilize`] so the
    /// durability proof runs against the SAME fd the ciphertext was read
    /// from (no re-open-by-path between compare and fsync) — the same
    /// TOCTOU guarantee File's own comparison gets, not a weaker one just
    /// because the comparison itself needs a decrypt step first.
    fn stabilize_and_classify_plaintext(
        &self,
        account: &str,
        expected: &[u8],
    ) -> Result<CreateOutcome, KeystoreError> {
        self.inner.reinspect_and_stabilize(account, |ciphertext| {
            // An existing blob that fails to decrypt at all (wrong TPM
            // state, corrupted, sealed under a stale key) is a genuine
            // operational failure, not an ambiguity a retry would resolve —
            // propagate it (via `?`) rather than guessing.
            let mut existing_plaintext = decrypt_with_systemd_creds(account, ciphertext)?;
            let matches = existing_plaintext.as_slice() == expected;
            existing_plaintext.zeroize();
            Ok(matches)
        })
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
        let stdin = child.stdin.as_mut().ok_or_else(|| KeystoreError::Io {
            kind: "no stdin".into(),
            hint: format!("{SYSTEMD_CREDS} child has no stdin pipe"),
        })?;
        stdin.write_all(plaintext).map_err(|e| KeystoreError::Io {
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
        let stdin = child.stdin.as_mut().ok_or_else(|| KeystoreError::Io {
            kind: "no stdin".into(),
            hint: format!("{SYSTEMD_CREDS} child has no stdin pipe"),
        })?;
        stdin.write_all(ciphertext).map_err(|e| KeystoreError::Io {
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
    match std::fs::OpenOptions::new().read(true).open("/dev/tpmrm0") {
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
        ks.delete("never.existed")
            .expect("missing key delete is ok");
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
        let src = ks.inner.path_for("provider.a");
        let dst = ks.inner.path_for("provider.b");
        std::fs::rename(&src, &dst).unwrap();

        let err = ks.get("provider.b").unwrap_err();
        assert!(
            matches!(err, KeystoreError::Io { .. }),
            "expected Io error, got {err:?}",
        );
    }

    #[test]
    fn create_only_seals_and_round_trips() {
        if !tpm2_available() {
            eprintln!("skipping: no TPM2 available on this host");
            return;
        }
        let dir = TempDir::new().unwrap();
        let ks = TpmKeystore::new(dir.path(), "test.tpm.create_only");
        assert_eq!(
            ks.create_only("llm.api_key.created", b"sk-created-0123456789")
                .unwrap(),
            CreateOutcome::CreatedDurable
        );
        assert_eq!(
            ks.get("llm.api_key.created").unwrap(),
            b"sk-created-0123456789"
        );
    }

    #[test]
    fn create_only_different_plaintext_is_conflict_leaves_first_seal_untouched() {
        if !tpm2_available() {
            eprintln!("skipping: no TPM2 available on this host");
            return;
        }
        let dir = TempDir::new().unwrap();
        let ks = TpmKeystore::new(dir.path(), "test.tpm.create_only_conflict");
        assert_eq!(
            ks.create_only("acct", b"first").unwrap(),
            CreateOutcome::CreatedDurable
        );
        assert_eq!(
            ks.create_only("acct", b"second").unwrap(),
            CreateOutcome::Conflict
        );
        assert_eq!(ks.get("acct").unwrap(), b"first");
    }

    /// The whole reason `create_only` here does NOT delegate to
    /// `FileKeystore::create_only`: `systemd-creds encrypt` is randomized,
    /// so re-sealing the SAME plaintext produces a different ciphertext
    /// every time. A byte-level comparison (what File does) would see two
    /// different blobs and wrongly report Conflict on a caller's own
    /// idempotent retry. This must converge to ExistingExactDurable
    /// instead, proving the plaintext-level comparison actually runs.
    #[test]
    fn create_only_same_plaintext_retry_converges_despite_randomized_ciphertext() {
        if !tpm2_available() {
            eprintln!("skipping: no TPM2 available on this host");
            return;
        }
        let dir = TempDir::new().unwrap();
        let ks = TpmKeystore::new(dir.path(), "test.tpm.create_only_idempotent");
        let plaintext = b"sk-same-plaintext-every-time";

        assert_eq!(
            ks.create_only("acct", plaintext).unwrap(),
            CreateOutcome::CreatedDurable
        );
        let first_ciphertext = ks.inner.get("acct").unwrap();

        assert_eq!(
            ks.create_only("acct", plaintext).unwrap(),
            CreateOutcome::ExistingExactDurable,
            "same plaintext resubmitted must converge, not spuriously conflict"
        );
        // The on-disk ciphertext must be untouched by the retry (create_only
        // never overwrites) — still decrypts to the same plaintext.
        assert_eq!(ks.inner.get("acct").unwrap(), first_ciphertext);
        assert_eq!(ks.get("acct").unwrap(), plaintext);
    }
}
