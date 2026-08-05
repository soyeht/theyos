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
//! - **Running unprivileged needs two separate grants, not one.** This
//!   backend does not talk to `/dev/tpmrm0` itself — it shells out to
//!   `systemd-creds`, and systemd performs the TPM operation in a separate
//!   privileged service reached over varlink, which authorizes by CALLER
//!   UID. So the service user needs (a) access to the TPM device (on NixOS:
//!   `security.tpm2.enable = true` plus `tss` group membership) *and* (b) a
//!   polkit rule permitting it to call `io.systemd.credentials.*`. Granting
//!   only (a) yields a process that can open the device and is still refused
//!   at the first seal. [`tpm2_availability`] detects exactly this and
//!   reports [`Tpm2Availability::AuthorizationDenied`].
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

/// Test-only override for the two filesystem facts the probe reads, so a
/// host with no TPM can drive every branch of the classification.
///
/// Only the filesystem answers are faked. The seal step still goes through
/// [`encrypt_with_systemd_creds`], i.e. through [`CredsRunner`] — so a test
/// that wants "device is fine but the service refuses" injects a runner that
/// refuses, exactly as the real service would. Nothing here substitutes for
/// the functional gate: a fake seal proves nothing about sealing.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct ProbeOverrides {
    pub sys_tpm0_exists: bool,
    pub tpmrm0_openable: bool,
}

#[cfg(test)]
thread_local! {
    static PROBE_OVERRIDES: std::cell::Cell<Option<ProbeOverrides>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_probe_overrides(o: Option<ProbeOverrides>) {
    PROBE_OVERRIDES.with(|c| c.set(o));
}

#[cfg(test)]
fn probe_overrides() -> Option<ProbeOverrides> {
    PROBE_OVERRIDES.with(std::cell::Cell::get)
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

/// Kernel's view of a TPM chip. Absent ⇒ the host has no TPM at all.
const SYS_TPM0: &str = "/sys/class/tpm/tpm0";
/// Resource-manager device the TPM stack talks through.
const DEV_TPMRM0: &str = "/dev/tpmrm0";

/// Credential name used by the capability probe. Distinct from any real
/// account: the probe seals a constant, never a caller's value.
const PROBE_NAME: &str = "theyos-tpm2-capability-probe";
/// Constant, non-secret probe plaintext. Sealing it proves the capability
/// without putting any real key material through the subprocess.
const PROBE_PLAINTEXT: &[u8] = b"theyos-tpm2-capability-probe";

/// Varlink error names systemd returns when the CALLER is not authorized to
/// use the credentials service, as distinct from anything being wrong with
/// the TPM. `InteractiveAuthenticationRequired` is what systemd 259 returns
/// when polkit would need to ask; `PermissionDenied` is the systemd 261
/// wording when it refuses outright.
///
/// This is string matching on stderr, which is fragile — but it is the only
/// channel the CLI exposes, and misclassification is deliberately not
/// safety-relevant: every non-success outcome is unavailable and fails
/// closed. The distinction changes only which remediation we log.
const AUTHZ_DENIED_MARKERS: &[&str] = &[
    "InteractiveAuthenticationRequired",
    "PermissionDenied",
    "Permission denied",
];

/// Why the TPM2 backend is (or is not) usable *by this process, as this uid*.
///
/// The distinction that matters operationally is
/// [`Self::AuthorizationDenied`] vs the rest: it is the only one an operator
/// fixes with a policy rule rather than with hardware or a device permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpm2Availability {
    /// A dummy seal actually succeeded as this uid.
    Available,
    /// No `/sys/class/tpm/tpm0` — the host has no TPM chip.
    NoTpmDevice,
    /// TPM present, but `/dev/tpmrm0` is not openable by this process.
    DeviceNotAccessible,
    /// TPM present and reachable, but `systemd-creds` refused the caller.
    /// Hardware is fine; this uid is not permitted to use the credentials
    /// service.
    AuthorizationDenied,
    /// TPM present and reachable, caller authorized (or the refusal was not
    /// an authorization one), but the seal did not succeed: TPM busy or
    /// unprovisioned, `systemd-creds` missing, or another operational fault.
    SealUnavailable,
}

impl Tpm2Availability {
    /// Whether the TPM backend may be selected.
    #[must_use]
    pub fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }

    /// Operator-facing remediation for this outcome.
    #[must_use]
    pub fn remediation(self) -> &'static str {
        match self {
            Self::Available => "none",
            Self::NoTpmDevice => {
                "this host has no TPM2 chip; provision one or accept the file backend"
            }
            Self::DeviceNotAccessible => {
                "grant this process access to /dev/tpmrm0 (on NixOS: `security.tpm2.enable = true` \
                 and add the service user to the `tss` group)"
            }
            Self::AuthorizationDenied => {
                "authorize this uid to call the systemd credentials service (polkit rule for \
                 `io.systemd.credentials.*`); device permission alone is NOT sufficient"
            }
            Self::SealUnavailable => {
                "check that systemd-creds is installed and the TPM is provisioned and not in use"
            }
        }
    }
}

/// `true` when this process, **as the uid it is running under**, can actually
/// seal a credential to the host TPM2.
///
/// Cached for the process lifetime — neither TPM presence nor this process's
/// uid changes at runtime, and the probe is non-trivial (it spawns
/// `systemd-creds` and performs a real seal). A `false` return is a sticky
/// decision: the caller picks the file fallback and we stay there until
/// restart.
#[must_use]
pub fn tpm2_available() -> bool {
    tpm2_availability().is_available()
}

/// Like [`tpm2_available`] but reports *why*, so the selection site can log
/// a remediation the operator can act on.
#[must_use]
pub fn tpm2_availability() -> Tpm2Availability {
    static CACHED: OnceLock<Tpm2Availability> = OnceLock::new();
    *CACHED.get_or_init(probe_tpm2)
}

/// Does the kernel see a TPM chip?
fn sys_tpm0_present() -> bool {
    #[cfg(test)]
    if let Some(o) = probe_overrides() {
        return o.sys_tpm0_exists;
    }
    Path::new(SYS_TPM0).exists()
}

/// Can THIS process open the resource-manager device?
fn tpmrm0_openable() -> bool {
    #[cfg(test)]
    if let Some(o) = probe_overrides() {
        return o.tpmrm0_openable;
    }
    match std::fs::OpenOptions::new().read(true).open(DEV_TPMRM0) {
        Ok(_) => true,
        Err(e) => {
            tracing::debug!(error = %e, "{DEV_TPMRM0} not openable by this process");
            false
        }
    }
}

/// Attempt a harmless dummy seal as this uid.
///
/// This is the capability check proper. It runs the SAME code path the
/// backend uses (`encrypt_with_systemd_creds`), so whatever would refuse a
/// real seal refuses this one, and it leaves **no persistent artifact**:
/// `systemd-creds encrypt … - -` reads stdin and writes stdout, touching no
/// file, and the resulting blob is wiped rather than returned.
fn effective_seal_probe() -> Result<(), KeystoreError> {
    let mut sealed = encrypt_with_systemd_creds(PROBE_NAME, PROBE_PLAINTEXT)?;
    sealed.zeroize();
    Ok(())
}

/// Split a failed probe seal into "you are not allowed" vs "it did not work".
fn classify_seal_failure(err: &KeystoreError) -> Tpm2Availability {
    let text = err.to_string();
    if AUTHZ_DENIED_MARKERS.iter().any(|m| text.contains(m)) {
        Tpm2Availability::AuthorizationDenied
    } else {
        Tpm2Availability::SealUnavailable
    }
}

fn probe_tpm2() -> Tpm2Availability {
    // Cheap kernel-level check first: if there's no /sys/class/tpm/tpm0 the
    // host literally has no TPM device, so don't even spawn.
    if !sys_tpm0_present() {
        tracing::debug!("no {SYS_TPM0} — TPM2 backend unavailable");
        return Tpm2Availability::NoTpmDevice;
    }

    // The kernel knows about a TPM; check the device is reachable from THIS
    // process. Cheap, and it separates "no permission on the device" from
    // "no permission at the service" in the reported reason.
    if !tpmrm0_openable() {
        tracing::warn!(
            remediation = Tpm2Availability::DeviceNotAccessible.remediation(),
            "TPM2 device {DEV_TPMRM0} not accessible to this process; falling back"
        );
        return Tpm2Availability::DeviceNotAccessible;
    }

    // Device access is NOT the permission that decides. The backend never
    // talks to /dev/tpmrm0 itself: it shells out to `systemd-creds`, and
    // systemd performs the TPM operation in a separate privileged service
    // reached over varlink, which authorizes by CALLER UID. A service user
    // can therefore hold `tss` membership, open the device, and still be
    // refused at first encrypt.
    //
    // That is not hypothetical — it is this backend's own deployment. The
    // module docs choose `--with-key=tpm2` over `host+tpm2` precisely so the
    // proxy can run as the service user rather than root, which is exactly
    // the uid that gets refused. An earlier revision of this probe stopped at
    // the device check and documented that check as preventing "pass the
    // check then fail at first encrypt"; measured on a vTPM guest, it did not
    // — the service user passed and then failed. So the probe now performs
    // the capability itself.
    match effective_seal_probe() {
        Ok(()) => {
            tracing::debug!("TPM2 backend available (dummy seal succeeded as this uid)");
            Tpm2Availability::Available
        }
        Err(e) => {
            let outcome = classify_seal_failure(&e);
            tracing::warn!(
                error = %e,
                outcome = ?outcome,
                remediation = outcome.remediation(),
                "TPM2 present and reachable but sealing failed as this uid; falling back"
            );
            outcome
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
        let availability = tpm2_availability();
        if availability.is_available() {
            return;
        }
        let demanded = std::env::var(REQUIRE_TPM_ENV).is_ok_and(|v| v != "0");
        assert!(
            !demanded,
            "{REQUIRE_TPM_ENV} is set but this process cannot seal to a TPM2 here \
             ({availability:?}): the functional TPM gate cannot be satisfied, and reporting \
             success would claim coverage that does not exist. Remediation: {}",
            availability.remediation()
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

    // ---------------------------------------------------------------------
    // Effective-capability probe.
    //
    // These drive `probe_tpm2` (uncached) rather than `tpm2_available` (which
    // memoizes for the process and so could only ever be observed once).
    // ---------------------------------------------------------------------

    thread_local! {
        /// Every seal attempted, in order, as `(account, plaintext)`.
        ///
        /// A bare counter would not discriminate: with the capability probe
        /// removed, the ONE call observed is `create_only`'s rather than the
        /// probe's, and a count of 1 reads identically either way. What
        /// separates the two is *who* was sealed, so record that.
        static ENCRYPT_LOG: std::cell::RefCell<Vec<(String, Vec<u8>)>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    fn reset_probe_counters() {
        ENCRYPT_LOG.with(|c| c.borrow_mut().clear());
    }
    fn encrypt_log() -> Vec<(String, Vec<u8>)> {
        ENCRYPT_LOG.with(|c| c.borrow().clone())
    }
    fn encrypt_calls() -> usize {
        ENCRYPT_LOG.with(|c| c.borrow().len())
    }
    fn record_encrypt(account: &str, plaintext: &[u8]) {
        let entry = (account.to_owned(), plaintext.to_vec());
        ENCRYPT_LOG.with(|c| c.borrow_mut().push(entry));
    }

    /// Restores the real filesystem probe even if the test panics.
    struct ProbeGuard;
    impl Drop for ProbeGuard {
        fn drop(&mut self) {
            set_probe_overrides(None);
        }
    }

    fn device_is_fine() {
        set_probe_overrides(Some(ProbeOverrides {
            sys_tpm0_exists: true,
            tpmrm0_openable: true,
        }));
    }

    /// A runner that refuses every seal with the stderr systemd actually
    /// emits. `refusal` selects the wording.
    macro_rules! refusing_runner {
        ($name:ident, $kind:expr, $hint:expr) => {
            fn $name() -> CredsRunner {
                fn encrypt(account: &str, plaintext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
                    record_encrypt(account, plaintext);
                    Err(KeystoreError::Io {
                        kind: $kind.into(),
                        hint: $hint.into(),
                    })
                }
                fn decrypt(_a: &str, _c: &[u8]) -> Result<Vec<u8>, KeystoreError> {
                    unreachable!("the capability probe never decrypts")
                }
                CredsRunner { encrypt, decrypt }
            }
        };
    }

    // systemd 261 wording, observed in the vTPM guest for a `tss` member with
    // no polkit authorization.
    refusing_runner!(
        denies_permission_runner,
        "systemd-creds encrypt exit exit status: 1",
        "Failed to encrypt: org.varlink.service.PermissionDenied"
    );
    // systemd 259 wording, observed on bignix for a non-root caller.
    refusing_runner!(
        interactive_auth_runner,
        "systemd-creds encrypt exit exit status: 1",
        "Failed to encrypt: io.systemd.InteractiveAuthenticationRequired"
    );
    // A genuinely operational failure: nothing to do with who is calling.
    refusing_runner!(
        tpm_busy_runner,
        "systemd-creds encrypt exit exit status: 1",
        "Failed to encrypt: TPM2 device is busy"
    );

    /// Succeeds, and records what it was asked to seal.
    fn counting_ok_runner() -> CredsRunner {
        #[allow(clippy::unnecessary_wraps)]
        fn encrypt(account: &str, plaintext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
            record_encrypt(account, plaintext);
            let mut out = format!("fake:{account}:").into_bytes();
            out.extend_from_slice(plaintext);
            Ok(out)
        }
        fn decrypt(account: &str, ciphertext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
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

    /// THE regression this whole change exists for.
    ///
    /// Device access and the permission that decides are different resources.
    /// A `tss` member opens `/dev/tpmrm0` fine and is still refused by the
    /// credentials service, because the TPM work happens in a separate
    /// privileged service that authorizes by caller uid. The previous probe
    /// stopped at the device and returned "available" here.
    #[test]
    fn probe_refuses_when_the_device_is_readable_but_the_service_denies_this_uid() {
        reset_probe_counters();
        device_is_fine();
        set_creds_runner(Some(denies_permission_runner()));
        let (_p, _r) = (ProbeGuard, RunnerGuard);

        assert_eq!(
            probe_tpm2(),
            Tpm2Availability::AuthorizationDenied,
            "device readable + service refusal must be reported as an authorization denial, \
             not as availability"
        );
        assert_eq!(
            encrypt_calls(),
            1,
            "the probe must actually attempt the capability, not infer it"
        );
    }

    /// The systemd 259 spelling of the same refusal.
    #[test]
    fn probe_refuses_on_interactive_authentication_required_too() {
        reset_probe_counters();
        device_is_fine();
        set_creds_runner(Some(interactive_auth_runner()));
        let (_p, _r) = (ProbeGuard, RunnerGuard);

        assert_eq!(probe_tpm2(), Tpm2Availability::AuthorizationDenied);
    }

    /// An authorization denial must be distinguishable from the TPM simply
    /// not working — same fail-closed outcome, different remediation.
    #[test]
    fn probe_separates_an_operational_failure_from_an_authorization_one() {
        reset_probe_counters();
        device_is_fine();
        set_creds_runner(Some(tpm_busy_runner()));
        let (_p, _r) = (ProbeGuard, RunnerGuard);

        let outcome = probe_tpm2();
        assert_eq!(outcome, Tpm2Availability::SealUnavailable);
        assert_ne!(
            outcome,
            Tpm2Availability::AuthorizationDenied,
            "a busy TPM must not be reported as a policy problem — the operator would \
             go add a polkit rule that changes nothing"
        );
        assert!(!outcome.is_available(), "still fails closed");
    }

    /// The authorized path: available is claimed only after a seal SUCCEEDS.
    #[test]
    fn probe_reports_available_only_after_a_seal_succeeds() {
        reset_probe_counters();
        device_is_fine();
        set_creds_runner(Some(counting_ok_runner()));
        let (_p, _r) = (ProbeGuard, RunnerGuard);

        assert_eq!(probe_tpm2(), Tpm2Availability::Available);
        assert!(probe_tpm2().is_available());
    }

    /// The dummy seal must be harmless: a constant, under a probe-specific
    /// name, never a caller's account or value.
    #[test]
    fn the_capability_probe_seals_only_a_constant_under_its_own_name() {
        reset_probe_counters();
        device_is_fine();
        set_creds_runner(Some(counting_ok_runner()));
        let (_p, _r) = (ProbeGuard, RunnerGuard);

        assert_eq!(probe_tpm2(), Tpm2Availability::Available);
        assert_eq!(
            encrypt_log(),
            vec![(PROBE_NAME.to_owned(), PROBE_PLAINTEXT.to_vec())],
            "the probe must seal its own constant, never a caller's account or value"
        );
    }

    /// No TPM at all: classify as such, and do not spend a subprocess.
    #[test]
    fn probe_reports_no_tpm_device_without_attempting_a_seal() {
        reset_probe_counters();
        set_probe_overrides(Some(ProbeOverrides {
            sys_tpm0_exists: false,
            tpmrm0_openable: false,
        }));
        set_creds_runner(Some(counting_ok_runner()));
        let (_p, _r) = (ProbeGuard, RunnerGuard);

        assert_eq!(probe_tpm2(), Tpm2Availability::NoTpmDevice);
        assert_eq!(encrypt_calls(), 0, "no TPM ⇒ no subprocess");
    }

    /// TPM present but the device is not ours to open: still a device-level
    /// finding, distinct from a service-level one.
    #[test]
    fn probe_reports_device_not_accessible_without_attempting_a_seal() {
        reset_probe_counters();
        set_probe_overrides(Some(ProbeOverrides {
            sys_tpm0_exists: true,
            tpmrm0_openable: false,
        }));
        set_creds_runner(Some(counting_ok_runner()));
        let (_p, _r) = (ProbeGuard, RunnerGuard);

        assert_eq!(probe_tpm2(), Tpm2Availability::DeviceNotAccessible);
        assert_eq!(encrypt_calls(), 0);
    }

    /// Fail closed BEFORE `create_only`.
    ///
    /// This models the selection site (`llm_proxy_rs::resolve_kind`): consult
    /// availability, and only then use the backend. With the refusal detected
    /// at the probe, `create_only` is never attempted — so the caller's
    /// plaintext never reaches a subprocess and nothing is installed. If the
    /// probe wrongly reported availability, `create_only` would run and the
    /// encrypt count would be 2.
    #[test]
    fn authorization_denial_fails_closed_before_create_only() {
        reset_probe_counters();
        device_is_fine();
        set_creds_runner(Some(denies_permission_runner()));
        let (_p, _r) = (ProbeGuard, RunnerGuard);

        let dir = TempDir::new().unwrap();
        let ks = TpmKeystore::new(dir.path(), "test.tpm.fail_closed");

        let availability = probe_tpm2();
        if availability.is_available() {
            // Deliberately reachable: this is the branch a wrong probe takes.
            let _ = ks.create_only("acct", b"sk-real-caller-secret");
        }

        // The identity of what was sealed is the discriminator, not the count:
        // remove the capability probe and this is still exactly one call, but
        // it is `create_only`'s, carrying the caller's real secret.
        assert_eq!(
            encrypt_log(),
            vec![(PROBE_NAME.to_owned(), PROBE_PLAINTEXT.to_vec())],
            "the only seal attempted must be the probe's own constant — create_only must \
             never have been reached, so the caller's plaintext never enters a subprocess"
        );
        assert!(
            ks.get("acct").is_err(),
            "nothing may be installed when the backend was refused"
        );
    }
}
