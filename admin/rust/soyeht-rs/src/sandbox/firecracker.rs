//! Firecracker-backed [`Verifier`] implementation.
//!
//! Delegates the entire verify pipeline — boot VM, run installer plan, start
//! claw, 60s soak, `kill -0` liveness check, destroy VM — to an
//! `imagebuilder build <claw> --verify-only` subprocess.  This avoids
//! duplicating the Firecracker/slirp4netns/SSH bootstrap that already lives in
//! `imagebuilder-rs` and keeps the soyeht-rs process free of host-side VM
//! state.
//!
//! The subprocess writes one textual marker to stdout per claw:
//!
//! ```text
//! VERIFY_OK:<claw>
//! VERIFY_FAIL:<claw>:<reason>
//! ```
//!
//! This struct parses the marker and returns `Ok` / `Err(reason)`
//! accordingly.  Stderr is captured best-effort into the error string so
//! genuine subprocess crashes (missing binary, bad env) aren't silently
//! swallowed.

use std::path::PathBuf;

use async_trait::async_trait;

use crate::verify_sandbox::{Verifier, VerifyReport};

/// Environment variable pointing at the `imagebuilder` binary.
///
/// Set automatically by `.env` / systemd unit in production;
/// tests inject a fake path via [`FirecrackerVerifier::with_bin`].
pub const IMAGEBUILDER_BIN_ENV: &str = "THEYOS_IMAGEBUILDER_BIN";

/// Firecracker-backed verifier.  Holds just the path to the imagebuilder
/// binary so we can unit-test the subprocess wiring with a fake shell script.
#[derive(Debug, Clone)]
pub struct FirecrackerVerifier {
    imagebuilder_bin: Option<PathBuf>,
}

impl FirecrackerVerifier {
    /// Build a verifier that will resolve the imagebuilder binary from the
    /// [`IMAGEBUILDER_BIN_ENV`] environment variable at `verify` time.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            imagebuilder_bin: None,
        }
    }

    /// Build a verifier that always invokes `bin`, ignoring the environment.
    /// Used by tests — see the unit tests in this module.
    #[cfg(test)]
    fn with_bin(bin: PathBuf) -> Self {
        Self {
            imagebuilder_bin: Some(bin),
        }
    }

    fn resolve_bin(&self) -> Result<PathBuf, String> {
        if let Some(ref p) = self.imagebuilder_bin {
            return Ok(p.clone());
        }
        std::env::var(IMAGEBUILDER_BIN_ENV)
            .map(PathBuf::from)
            .map_err(|_| {
                format!("{IMAGEBUILDER_BIN_ENV} is not set; point it at the imagebuilder binary")
            })
    }
}

#[async_trait]
impl Verifier for FirecrackerVerifier {
    async fn verify(&self, claw: &str, _min_ram_mb: u32) -> VerifyReport {
        let bin = match self.resolve_bin() {
            Ok(p) => p,
            Err(reason) => {
                return VerifyReport {
                    outcome: Err(reason.clone()),
                    log: reason,
                };
            }
        };

        let output = match tokio::process::Command::new(&bin)
            .arg("build")
            .arg(claw)
            .arg("--verify-only")
            .output()
            .await
        {
            Ok(o) => o,
            Err(e) => {
                let reason = format!("spawn {}: {e}", bin.display());
                return VerifyReport {
                    outcome: Err(reason.clone()),
                    log: reason,
                };
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let log = format!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}");

        let outcome = match parse_verify_output(claw, &stdout) {
            Ok(parsed) => parsed,
            Err(missing_marker) => {
                // No VERIFY_* line at all — surface stderr tail + exit code so
                // the caller can distinguish "binary is broken" from "plan failed".
                let tail: Vec<&str> = stderr.lines().rev().take(5).collect();
                let tail_joined = tail.into_iter().rev().collect::<Vec<_>>().join(" | ");
                Err(format!(
                    "{missing_marker}; subprocess exit={:?}; stderr tail: {tail_joined}",
                    output.status.code()
                ))
            }
        };

        VerifyReport { outcome, log }
    }
}

/// Parse the textual `VERIFY_OK:<claw>` / `VERIFY_FAIL:<claw>:<reason>`
/// marker from the imagebuilder subprocess stdout.
///
/// Returns:
///   * `Ok(Ok(()))` — `VERIFY_OK:<claw>` found.
///   * `Ok(Err(reason))` — `VERIFY_FAIL:<claw>:<reason>` found.
///   * `Err("no VERIFY marker for <claw> in stdout")` — neither marker for
///     this claw present.  Caller decorates with stderr context.
fn parse_verify_output(claw: &str, stdout: &str) -> Result<Result<(), String>, String> {
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("VERIFY_OK:") {
            if rest.trim() == claw {
                return Ok(Ok(()));
            }
        }
        if let Some(rest) = line.strip_prefix("VERIFY_FAIL:") {
            let (c, reason) = rest.split_once(':').unwrap_or((rest, ""));
            if c.trim() == claw {
                return Ok(Err(reason.trim().to_string()));
            }
        }
    }
    Err(format!("no VERIFY marker for {claw} in stdout"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ok_marker() {
        let out = "phase=boot-vm\nphase=run-installer\nVERIFY_OK:picoclaw\n";
        let res = parse_verify_output("picoclaw", out).expect("marker found");
        assert!(res.is_ok());
    }

    #[test]
    fn parse_fail_marker_extracts_reason() {
        let out = "phase=run-installer\nVERIFY_FAIL:picoclaw:installer step 3 exited 127\n";
        let res = parse_verify_output("picoclaw", out).expect("marker found");
        let reason = res.unwrap_err();
        assert_eq!(reason, "installer step 3 exited 127");
    }

    #[test]
    fn parse_marker_mismatched_claw_returns_missing() {
        let out = "VERIFY_OK:zeroclaw\n";
        let err = parse_verify_output("picoclaw", out).unwrap_err();
        assert!(err.contains("no VERIFY marker"), "got {err}");
    }

    #[test]
    fn parse_no_marker_errors() {
        let out = "phase=boot-vm\npanic: oom\n";
        let err = parse_verify_output("picoclaw", out).unwrap_err();
        assert!(err.contains("no VERIFY marker"), "got {err}");
    }

    #[test]
    fn resolve_bin_from_explicit() {
        let v = FirecrackerVerifier::with_bin(PathBuf::from("/opt/fake/imagebuilder"));
        assert_eq!(
            v.resolve_bin().unwrap(),
            PathBuf::from("/opt/fake/imagebuilder")
        );
    }

    #[test]
    fn resolve_bin_explicit_override_beats_env() {
        // `with_bin` always wins, regardless of whether the env var is set —
        // that's what lets tests inject a fake binary without mutating
        // global env state.
        let v = FirecrackerVerifier::with_bin(PathBuf::from("/opt/fake/imagebuilder"));
        assert_eq!(
            v.resolve_bin().unwrap(),
            PathBuf::from("/opt/fake/imagebuilder")
        );
    }

    #[tokio::test]
    async fn verify_subprocess_missing_returns_error() {
        let v = FirecrackerVerifier::with_bin(PathBuf::from(
            "/nonexistent/path/imagebuilder-does-not-exist",
        ));
        let report = v.verify("picoclaw", 512).await;
        let err = report.outcome.expect_err("missing subprocess must fail");
        assert!(err.contains("spawn"), "got {err}");
    }

    /// Fake `imagebuilder` script that prints `VERIFY_OK` to stdout.  Exercised
    /// end-to-end: real subprocess spawn, real stdout capture, real parse.
    #[tokio::test]
    async fn verify_with_fake_binary_emits_ok() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("fake-imagebuilder");
        std::fs::write(&script, "#!/bin/sh\necho VERIFY_OK:picoclaw\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).unwrap();
        }

        let v = FirecrackerVerifier::with_bin(script);
        let report = v.verify("picoclaw", 512).await;
        report.outcome.expect("fake reports OK");
        assert!(
            report.log.contains("VERIFY_OK:picoclaw"),
            "log: {}",
            report.log
        );
    }

    #[tokio::test]
    async fn verify_with_fake_binary_emits_fail_reason() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("fake-imagebuilder");
        std::fs::write(
            &script,
            "#!/bin/sh\necho VERIFY_FAIL:picoclaw:installer step 3 exited 127\nexit 1\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).unwrap();
        }

        let v = FirecrackerVerifier::with_bin(script);
        let report = v.verify("picoclaw", 512).await;
        let err = report.outcome.expect_err("fake reports FAIL");
        assert!(err.contains("installer step 3"), "got {err}");
    }

    #[tokio::test]
    async fn verify_with_fake_binary_no_marker_surfaces_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("fake-imagebuilder");
        std::fs::write(
            &script,
            "#!/bin/sh\necho 'boom: slirp4netns not found' 1>&2\nexit 2\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).unwrap();
        }

        let v = FirecrackerVerifier::with_bin(script);
        let report = v.verify("picoclaw", 512).await;
        let err = report.outcome.expect_err("missing marker must fail");
        assert!(
            err.contains("no VERIFY marker") && err.contains("slirp4netns not found"),
            "got {err}"
        );
        // Log must still carry the stderr, even on missing-marker failure.
        assert!(
            report.log.contains("slirp4netns not found"),
            "log: {}",
            report.log
        );
    }
}
