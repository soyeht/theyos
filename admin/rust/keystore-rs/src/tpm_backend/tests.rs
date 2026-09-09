#![cfg(test)]

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
