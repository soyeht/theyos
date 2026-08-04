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
//! ## What is NOT claimed
//!
//! - **No PCR policy.** This backend passes `--with-key=tpm2` and nothing
//!   else; it does NOT pass `--tpm2-pcrs=`, so the sealed blob is bound to
//!   the TPM but not to any measured boot state. An attacker who can boot
//!   the same physical host with a modified kernel or initrd can still
//!   unseal. Earlier revisions of these docs referred to "PCRs changed" as
//!   a decrypt-failure cause, which implied a PCR binding that was never
//!   configured — corrected here rather than left to read as a guarantee.
//!   Adding a PCR policy is a deliberate decision (it makes every legitimate
//!   firmware/kernel update invalidate every stored credential), so it needs
//!   an explicit, measured policy choice rather than a silently-added flag.
//! - **No crash-durability claim from the subprocess.** `systemd-creds`
//!   returning success means the ciphertext was produced, not that anything
//!   is on disk; the durability claim comes entirely from the
//!   [`FileKeystore`] install protocol underneath.
//!
//! ## Operational notes
//!
//! - Requires systemd ≥ 250 (released 2021-12). NixOS 22.11+ ships this.
//! - First-boot encryption needs the TPM2 to be present and writable;
//!   subsequent unseal needs nothing from the operator.
//! - Decrypt failures (host migrated to different hardware, TPM cleared or
//!   reprovisioned) surface as [`KeystoreError::Io`] with a hint pointing at
//!   the systemd-creds error message — the operator must re-add the
//!   credential.

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

    /// Build a TPM keystore permitted to operate inside the crate-reserved
    /// opaque namespace. `pub(crate)`: the capability [`crate::opaque_p256`]
    /// holds and no downstream can obtain.
    pub(crate) fn new_for_reserved_namespace(
        state_dir: impl AsRef<Path>,
        service: impl Into<String>,
    ) -> Self {
        Self {
            inner: FileKeystore::new_for_reserved_namespace(state_dir, service),
        }
    }

    /// The underlying file store, so callers inside this crate can reach the
    /// hardened fd-relative readers rather than the legacy path-based
    /// [`KeystoreBackend::get`]. Sealing happens above this: what the file
    /// store holds is always ciphertext.
    pub(crate) fn file_store(&self) -> &FileKeystore {
        &self.inner
    }

    /// Decrypt a blob already fetched (and proven durable) by the caller.
    /// Split out from [`KeystoreBackend::get`] so the hardened reader can
    /// decide EXISTENCE from the storage layer and use decryption only to
    /// interpret bytes it has already validated.
    /// Takes no `self`: decryption is a pure function of the account name
    /// and the blob, and keeping it that way makes it obvious that no
    /// instance state can influence what a given blob decrypts to.
    pub(crate) fn decrypt_blob(account: &str, ciphertext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        decrypt_with_systemd_creds(account, ciphertext)
    }

    /// Take the exclusive create-lock — see [`FileKeystore::lock_for_sweep`].
    pub fn lock_for_sweep(&self) -> Result<crate::file_backend::SweepGuard, KeystoreError> {
        self.inner.lock_for_sweep()
    }

    /// See [`FileKeystore::sweep_orphaned_create_attempts`] — `create_only`
    /// on this backend uses the same file-backed install path, so a crash
    /// mid-`create_only` leaves an orphaned scratch file the same way
    /// (holding sealed ciphertext here rather than plaintext, but still
    /// secret material that does not expire on its own).
    pub fn sweep_orphaned_create_attempts(
        &self,
        guard: &crate::file_backend::SweepGuard,
    ) -> Result<crate::file_backend::SweepReport, KeystoreError> {
        self.inner.sweep_orphaned_create_attempts(guard)
    }
}

impl KeystoreBackend for TpmKeystore {
    fn get(&self, account: &str) -> Result<Vec<u8>, KeystoreError> {
        let mut ciphertext = self.inner.get(account)?;
        let plain = decrypt_with_systemd_creds(account, &ciphertext);
        // Wipe on BOTH outcomes, so the `?` shorthand cannot skip it. The
        // sealed blob is derived from a private scalar; leaving it in a
        // freed allocation is a smaller leak than the plaintext but it is
        // still one, and the whole point of the rule is not to relitigate
        // each buffer's severity at each site.
        ciphertext.zeroize();
        plain
    }

    fn set(&self, account: &str, value: &[u8]) -> Result<(), KeystoreError> {
        let mut ciphertext = encrypt_with_systemd_creds(account, value)?;
        let stored = self.inner.set(account, &ciphertext);
        ciphertext.zeroize();
        stored
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
        // Directory setup and the filesystem-allowlist gate run BEFORE the
        // encryption: if this store is somewhere we refuse to make durability
        // claims about, fail closed without spending a `systemd-creds`
        // invocation, and without the plaintext ever reaching a subprocess.
        self.inner.preflight()?;
        let mut ciphertext = encrypt_with_systemd_creds(account, value)?;
        let installed = self.inner.raw_attempt_install(account, &ciphertext);
        // Wiped before the classification below branches, so no arm can
        // return without it having happened.
        ciphertext.zeroize();
        match installed {
            Ok(InstallOutcome::Durable) => Ok(CreateOutcome::CreatedDurable),
            // These three are genuine ambiguity about the DESTINATION, and
            // reinspecting the store is how they get resolved.
            Ok(
                InstallOutcome::Ambiguous(_)
                | InstallOutcome::ProvenConflict
                | InstallOutcome::TmpNameExhausted,
            ) => self.stabilize_and_classify_plaintext(account, value),
            // An `Err` here is NOT one of those. It comes from before the
            // install could be attempted at all — the store would not open,
            // the filesystem allowlist refused it, the lock could not be
            // taken — and it used to be swallowed by an `| Err(_)` arm that
            // sent it down the same stabilization path.
            //
            // That flattened a refusal into an outcome. A `SecurityViolation`
            // from the allowlist would come back as a `Conflict` or a
            // `MayHaveTakenEffect` derived from whatever happened to be in
            // the store, with the reason for refusing gone. The file backing
            // has always propagated this (`raw_attempt_install(...)?` in
            // `create_only_unix`); the sealed backing simply did not, so the
            // two disagreed about the same condition and the sealed one was
            // the weaker.
            Err(e) => Err(e),
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

/// Stand-in for the `systemd-creds` subprocess.
///
/// Everything this backend does around the seal — the pre-publish ordering,
/// the outcome classification, the zeroize discipline — is logic that has
/// nothing to do with a TPM, but on a host without one the subprocess fails
/// immediately and none of it is ever reached. That is why those paths went
/// unverified: the only hosts that could exercise them were the ones nobody
/// runs the suite on.
///
/// With the runner injected, a host with no TPM can drive the classification
/// directly. It does NOT substitute for the functional TPM gate — a fake
/// seal proves nothing about sealing — and the tests that need real hardware
/// stay `#[ignore]`d behind `require_tpm2`.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct CredsRunner {
    pub encrypt: fn(&str, &[u8]) -> Result<Vec<u8>, KeystoreError>,
    pub decrypt: fn(&str, &[u8]) -> Result<Vec<u8>, KeystoreError>,
}

#[cfg(test)]
thread_local! {
    static CREDS_RUNNER: std::cell::Cell<Option<CredsRunner>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_creds_runner(runner: Option<CredsRunner>) {
    CREDS_RUNNER.with(|c| c.set(runner));
}

#[cfg(test)]
fn injected_runner() -> Option<CredsRunner> {
    CREDS_RUNNER.with(std::cell::Cell::get)
}

/// Run `systemd-creds encrypt --with-key=tpm2 --name=<account> - -`,
/// feeding `plaintext` through stdin and reading the sealed blob from
/// stdout. The blob is binary by default (no `--pretty`); we keep it as
/// raw bytes to round-trip cleanly.
fn encrypt_with_systemd_creds(account: &str, plaintext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    #[cfg(test)]
    if let Some(runner) = injected_runner() {
        return (runner.encrypt)(account, plaintext);
    }
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

    let mut output = child.wait_with_output().map_err(|e| KeystoreError::Io {
        kind: e.kind().to_string(),
        hint: format!("wait {SYSTEMD_CREDS}: {e}"),
    })?;
    if !output.status.success() {
        // Ciphertext rather than plaintext, and a failed encrypt may have
        // emitted only a fragment of it — but a partial seal of a private
        // scalar is still derived from that scalar, and the buffer costs
        // nothing to wipe. The rule is that no buffer downstream of key
        // material is dropped unwiped, not that each one is individually
        // argued to be harmless.
        output.stdout.zeroize();
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
    #[cfg(test)]
    if let Some(runner) = injected_runner() {
        return (runner.decrypt)(account, ciphertext);
    }

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

    let mut output = child.wait_with_output().map_err(|e| KeystoreError::Io {
        kind: e.kind().to_string(),
        hint: format!("wait {SYSTEMD_CREDS}: {e}"),
    })?;
    if !output.status.success() {
        // `output.stdout` on THIS path is the most sensitive buffer in the
        // crate that nothing was wiping: a decrypt that fails part-way still
        // wrote whatever plaintext it had already produced, so a truncated
        // private scalar can be sitting in it. Dropping the `Output` frees
        // that allocation without clearing it.
        //
        // A failed decrypt is exactly when this is most likely — a changed
        // PCR state or a replaced TPM can fail after some output has already
        // been emitted.
        output.stdout.zeroize();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(KeystoreError::Io {
            kind: format!("systemd-creds decrypt exit {}", output.status),
            hint: format!(
                "{} (host PCR/TPM state may have changed; re-add credential)",
                stderr.trim()
            ),
        });
    }
    // On success ownership moves to the caller, which zeroizes it — see
    // `OpaqueP256Slots::load_signing_key`, which wipes the buffer on the
    // success path AND on every rejection path.
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

    /// Environment variable that turns the TPM tests from "skipped" into
    /// "must work".
    const REQUIRE_TPM_ENV: &str = "THEYOS_REQUIRE_TPM2";

    /// Gate for tests that need a real TPM2.
    ///
    /// These tests are `#[ignore]`d, so they never run by accident and can
    /// never be counted as passing when they did nothing. That matters:
    /// previously each of them opened with an early `return` when no TPM was
    /// present, which the harness reported as `ok` — a bignix run showed six
    /// TPM tests "passing" on a host with no `/dev/tpm*` at all, none of
    /// which had exercised a single line of the sealing path.
    ///
    /// Run them explicitly with `cargo test -- --ignored`. In that mode a
    /// missing TPM still cannot silently pass: with `THEYOS_REQUIRE_TPM2=1`
    /// set (how a real functional gate should invoke this) the absence is a
    /// hard panic rather than a skip.
    fn require_tpm2() {
        if tpm2_available() {
            return;
        }
        let demanded = std::env::var(REQUIRE_TPM_ENV).is_ok_and(|v| v != "0");
        assert!(
            !demanded,
            "{REQUIRE_TPM_ENV} is set but no usable TPM2 was found on this host: the \
             functional TPM gate cannot be satisfied here, and reporting success would \
             claim coverage that does not exist"
        );
        panic!(
            "no usable TPM2 on this host, so this test cannot verify anything. It is \
             #[ignore]d for exactly this reason; set {REQUIRE_TPM_ENV}=1 on a TPM-equipped \
             host to run the functional gate."
        );
    }

    #[test]
    fn delete_is_idempotent_without_tpm() {
        // Delete only touches the file backend; safe to test without a TPM.
        let dir = TempDir::new().unwrap();
        let ks = TpmKeystore::new(dir.path(), "test.service");
        ks.delete("never.existed")
            .expect("missing key delete is ok");
    }

    /// Restores the real subprocess even if the test panics, so one failing
    /// test cannot leave a fake seal armed for the next one on this thread.
    struct RunnerGuard;
    impl Drop for RunnerGuard {
        fn drop(&mut self) {
            set_creds_runner(None);
        }
    }

    /// A seal that is trivially reversible. It proves NOTHING about sealing —
    /// that is what the `require_tpm2` gate is for — and exists only so the
    /// logic wrapped AROUND the subprocess can be driven on a host with no
    /// TPM.
    fn fake_runner() -> CredsRunner {
        // The `Result` is not removable: this has to match the fn-pointer
        // type in `CredsRunner`, which the real subprocess also inhabits and
        // which genuinely fails. A fake that cannot fail is the point here.
        #[allow(clippy::unnecessary_wraps)]
        fn encrypt(account: &str, plaintext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
            let mut out = format!("fake:{account}:").into_bytes();
            out.extend_from_slice(plaintext);
            Ok(out)
        }
        fn decrypt(account: &str, ciphertext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
            // Bound to the account exactly as `--name=` binds the real one,
            // so a blob from another account fails here too.
            let prefix = format!("fake:{account}:").into_bytes();
            ciphertext
                .strip_prefix(prefix.as_slice())
                .map(<[u8]>::to_vec)
                .ok_or_else(|| KeystoreError::Io {
                    kind: "fake decrypt refused".into(),
                    hint: "blob was sealed under a different account".into(),
                })
        }
        CredsRunner { encrypt, decrypt }
    }

    /// A pre-install refusal must reach the caller AS a refusal.
    ///
    /// The sealed backing used to funnel every `Err` from
    /// `raw_attempt_install` into the same stabilization path as a genuine
    /// destination ambiguity. A `SecurityViolation` — the filesystem
    /// allowlist refusing the store — therefore came back as an ordinary
    /// `CreateOutcome` derived from whatever was already on disk, with the
    /// reason for refusing discarded.
    ///
    /// The reserved-namespace guard is used to produce a real refusal from
    /// that same call, because it fails for a reason the store's contents
    /// cannot mask.
    #[test]
    fn pre_install_refusal_is_not_reclassified_as_an_outcome() {
        set_creds_runner(Some(fake_runner()));
        let _g = RunnerGuard;

        let dir = TempDir::new().unwrap();
        // Control: with the fake seal in place the ordinary path works, so a
        // failure below is attributable to the refusal and not to the fake.
        let ok = TpmKeystore::new(dir.path(), "test.classify");
        assert_eq!(
            ok.create_only("slot", b"value").unwrap(),
            CreateOutcome::CreatedDurable
        );
        assert_eq!(
            ok.create_only("slot", b"value").unwrap(),
            CreateOutcome::ExistingExactDurable,
            "the same plaintext must converge despite randomized ciphertext"
        );
        assert_eq!(
            ok.create_only("slot", b"different").unwrap(),
            CreateOutcome::Conflict,
            "a different plaintext under the same account is a conflict"
        );

        // The refusal itself.
        let reserved = TpmKeystore::new(
            dir.path(),
            format!(
                "svc{}-x",
                crate::file_backend::RESERVED_OPAQUE_NAMESPACE_MARKER
            ),
        );
        match reserved.create_only("slot", b"value") {
            Err(KeystoreError::Unsupported { .. } | KeystoreError::SecurityViolation { .. }) => {}
            other => panic!("a refusal must not be reported as an outcome: {other:?}"),
        }
    }

    /// Round-trip end-to-end. Gated on a real TPM2 + systemd-creds — CI
    /// runners without TPM skip. Run locally on bignix/devs to verify.
    #[test]
    #[ignore = "needs a real TPM2; see require_tpm2()"]
    fn encrypt_then_decrypt_round_trip() {
        require_tpm2();
        let dir = TempDir::new().unwrap();
        let ks = TpmKeystore::new(dir.path(), "test.tpm.roundtrip");
        let plaintext = b"sk-aurora-test-0123456789abcdef";
        ks.set("llm.api_key.test", plaintext).unwrap();
        let got = ks.get("llm.api_key.test").unwrap();
        assert_eq!(got, plaintext);
    }

    #[test]
    #[ignore = "needs a real TPM2; see require_tpm2()"]
    fn name_binding_rejects_mismatched_account() {
        require_tpm2();
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
    #[ignore = "needs a real TPM2; see require_tpm2()"]
    fn create_only_seals_and_round_trips() {
        require_tpm2();
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
    #[ignore = "needs a real TPM2; see require_tpm2()"]
    fn create_only_different_plaintext_is_conflict_leaves_first_seal_untouched() {
        require_tpm2();
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
    /// idempotent retry. This must converge to `ExistingExactDurable`
    /// instead, proving the plaintext-level comparison actually runs.
    #[test]
    #[ignore = "needs a real TPM2; see require_tpm2()"]
    fn create_only_same_plaintext_retry_converges_despite_randomized_ciphertext() {
        require_tpm2();
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
