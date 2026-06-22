//! Shared constants — single source of truth for values used across the workspace.

/// Default admin panel HTTP port.
pub const DEFAULT_ADMIN_PORT: u16 = 8892;

/// ANSI 24-bit bold + color escape for the theyOS terminal prompt (#00D9A3).
pub const PROMPT_COLOR_OK: &str = "\\033[1;38;2;0;217;163m";

/// ANSI 24-bit bold + color escape for the theyOS terminal prompt on error (#F59E0B).
pub const PROMPT_COLOR_WARN: &str = "\\033[1;38;2;245;158;11m";

// ── Firecracker asset pinning ────────────────────────────────────────────────

/// Pinned Firecracker release version for automated download.
pub const FIRECRACKER_VERSION: &str = "v1.15.0";

/// SHA-256 of `firecracker-v1.15.0-x86_64.tgz`.
pub const FIRECRACKER_SHA256_X86_64: &str =
    "00cadf7f21e709e939dc0c8d16e2d2ce7b975a62bec6c50f74b421cc8ab3cab4";

/// SHA-256 of `firecracker-v1.15.0-aarch64.tgz`.
pub const FIRECRACKER_SHA256_AARCH64: &str =
    "58325e6c3c539482a412ec0b60e6f539c3320adebcf8179c7629d06736aee0bd";

/// Expected kernel filename (without directory).
pub use crate::guest_net::KERNEL_FILENAME;

// ── Artifact registry ──────────────────────────────────────────────────────

/// Default base URL for the pre-built artifact registry.
///
/// Points to `latest.json` manifests committed in the repo and served via
/// `raw.githubusercontent.com`.  Override at runtime via
/// `THEYOS_ARTIFACT_REGISTRY_URL`.
pub const ARTIFACT_REGISTRY_DEFAULT_URL: &str =
    "https://raw.githubusercontent.com/soyeht/theyos/main/artifacts";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firecracker_version_starts_with_v() {
        assert!(FIRECRACKER_VERSION.starts_with('v'));
    }

    #[test]
    fn firecracker_sha256_are_valid_hex() {
        for sha in [FIRECRACKER_SHA256_X86_64, FIRECRACKER_SHA256_AARCH64] {
            assert_eq!(sha.len(), 64, "SHA-256 must be 64 hex chars");
            assert!(
                sha.chars().all(|c| c.is_ascii_hexdigit()),
                "SHA-256 must be hex"
            );
        }
    }

    #[test]
    fn kernel_filename_starts_with_vmlinux() {
        assert!(KERNEL_FILENAME.starts_with("vmlinux"));
    }
}
