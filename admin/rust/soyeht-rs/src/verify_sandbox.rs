//! `Verifier` trait — disposable VM for `soyeht claws-verify`.
//!
//! A [`Verifier`] runs a claw's install plan end-to-end in a throwaway sandbox
//! VM and reports back success or a single-line failure reason.  The actual
//! plan execution, 60s soak, and `kill -0` liveness probe happen *inside* the
//! sandbox (via `imagebuilder build --verify-only` for the Firecracker
//! backend) — the host side only parses the outcome.
//!
//! Keeping the trait surface this small means tests can swap in a synchronous
//! fake without having to model SSH sessions.

use async_trait::async_trait;

use crate::sandbox::firecracker;

/// Which kind of disposable sandbox to spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxKind {
    /// Firecracker microVM on Linux (production verify target).
    Firecracker,
    /// Apple Virtualization.framework VM on macOS (not yet implemented).
    Mac,
}

impl SandboxKind {
    /// Parse a CLI string like `"firecracker"` or `"mac"`.
    ///
    /// # Errors
    ///
    /// Returns an error describing the allowed values if `s` is not one of
    /// `"firecracker"` or `"mac"`.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_lowercase().as_str() {
            "firecracker" | "linux" => Ok(Self::Firecracker),
            "mac" | "macos" => Ok(Self::Mac),
            other => Err(format!(
                "unknown sandbox kind {other:?}: expected 'firecracker' or 'mac'"
            )),
        }
    }
}

/// Report emitted by one [`Verifier::verify`] call.
///
/// The log is the full subprocess stdout + stderr (combined for the
/// Firecracker backend).  `claws_verify` persists it under
/// `artifacts/verify/<claw>-<ts>.log` regardless of the outcome so failure
/// diagnosis has everything the sandbox said.
#[derive(Debug)]
pub struct VerifyReport {
    /// `Ok(())` on `VERIFY_OK`, `Err(reason)` on `VERIFY_FAIL` or any
    /// wiring error (missing subprocess, bad stdout marker, etc.).
    pub outcome: Result<(), String>,
    /// Raw subprocess output suitable for dumping to a log file.
    pub log: String,
}

/// End-to-end install-plan verifier running inside a disposable VM.
///
/// Implementations are expected to boot a fresh VM, execute the builtin or
/// template [`vmrunner_rs::installer_plan::InstallerPlan`] for `claw`, start
/// the entry point, sleep 60s, check liveness via `kill -0`, and destroy the
/// VM — all inside the `verify` call.  The host side (see
/// [`claws_verify`](crate::claws_verify)) only records the outcome + log.
#[async_trait]
pub trait Verifier: Send + Sync {
    /// Run the install plan + smoke test for `claw` in a fresh sandbox.
    ///
    /// `min_ram_mb` is passed through so the backend can refuse to boot if
    /// the host lacks capacity.  Never panics — all failure modes are
    /// reported through [`VerifyReport::outcome`].
    async fn verify(&self, claw: &str, min_ram_mb: u32) -> VerifyReport;
}

/// Construct a [`Verifier`] for the requested sandbox kind.
///
/// # Errors
///
/// Returns an error if the sandbox kind is not supported on this platform.
pub fn make_verifier(kind: SandboxKind) -> Result<Box<dyn Verifier>, String> {
    match kind {
        SandboxKind::Firecracker => Ok(Box::new(firecracker::FirecrackerVerifier::from_env())),
        SandboxKind::Mac => {
            Err("Mac sandbox not implemented in v1 — use --sandbox firecracker".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_kind_parse_valid() {
        assert_eq!(
            SandboxKind::parse("firecracker").unwrap(),
            SandboxKind::Firecracker
        );
        assert_eq!(
            SandboxKind::parse("FIRECRACKER").unwrap(),
            SandboxKind::Firecracker
        );
        assert_eq!(
            SandboxKind::parse("linux").unwrap(),
            SandboxKind::Firecracker
        );
        assert_eq!(SandboxKind::parse(" mac ").unwrap(), SandboxKind::Mac);
        assert_eq!(SandboxKind::parse("macos").unwrap(), SandboxKind::Mac);
    }

    #[test]
    fn sandbox_kind_parse_invalid() {
        let err = SandboxKind::parse("docker").unwrap_err();
        assert!(err.contains("unknown"), "got {err}");
    }

    #[test]
    fn make_verifier_mac_returns_not_implemented() {
        let Err(err) = make_verifier(SandboxKind::Mac) else {
            panic!("Mac must not be implemented yet");
        };
        assert!(err.contains("not implemented"), "got {err}");
    }
}
