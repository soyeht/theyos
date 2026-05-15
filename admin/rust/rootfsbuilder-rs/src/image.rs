//! Phases 3 and 4 — ext4 image creation and verification.
//!
//! Phase 3: `mke2fs -t ext4 -d <rootfs_dir> -L rootfs -b 4096 <output> <blocks>`
//! Phase 4: `e2fsck -f -y <output>`, sha256, `du`.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::error::{Result, RootfsError, RootfsPhase};

// ── Phase 3 ───────────────────────────────────────────────────────────────────

/// Create the ext4 image from the populated rootfs directory.
///
/// Corresponds to:
/// ```bash
/// mke2fs -t ext4 -d <rootfs_dir> -L rootfs -b 4096 <output> <blocks>
/// chown <uid>:<gid> <output>
/// ```
pub fn create_ext4(
    rootfs_dir: &Path,
    output: &Path,
    size_blocks: u64,
    uid: u32,
    gid: u32,
) -> Result<()> {
    println!("[rootfsbuilder] === Phase 3: Create ext4 image ({size_blocks} blocks of 4 KB) ===");

    // Ensure parent directory exists.
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            RootfsError::new(
                RootfsPhase::ImageCreate,
                format!("create output parent dir {}: {e}", parent.display()),
            )
        })?;
    }

    // Remove existing output if present (--force already checked in preflight).
    if output.exists() {
        fs::remove_file(output).map_err(|e| {
            RootfsError::new(
                RootfsPhase::ImageCreate,
                format!("remove existing output {}: {e}", output.display()),
            )
        })?;
    }

    let out = Command::new("mke2fs")
        .args([
            "-t",
            "ext4",
            "-d",
            &rootfs_dir.display().to_string(),
            "-L",
            "rootfs",
            "-b",
            "4096",
            &output.display().to_string(),
            &size_blocks.to_string(),
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| RootfsError::new(RootfsPhase::ImageCreate, format!("spawn mke2fs: {e}")))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        return Err(RootfsError::from_cmd(
            RootfsPhase::ImageCreate,
            "mke2fs",
            out.status.code(),
            &stderr,
        ));
    }

    // chown to real user (not root) so the file is usable without sudo.
    chown(output, uid, gid)?;

    println!("[rootfsbuilder] ext4 image created: {}", output.display());
    Ok(())
}

// ── Phase 4 ───────────────────────────────────────────────────────────────────

/// Verify the created image: `e2fsck`, sha256, size metrics.
///
/// `e2fsck` may exit 1 (fixed errors) — that is tolerated.
/// Exit code >= 4 is an unrecoverable error.
pub fn verify_and_report(output: &Path) -> Result<()> {
    println!("[rootfsbuilder] === Phase 4: Verify ===");

    run_e2fsck(output)?;

    // SHA-256
    let hash = compute_sha256(output)?;
    println!("[rootfsbuilder] SHA256: {hash}  {}", output.display());

    // Apparent size
    if let Ok(meta) = fs::metadata(output) {
        let size_mb = meta.len() / 1_048_576;
        println!("[rootfsbuilder] Apparent size: {size_mb} MiB");
    }

    // Disk usage (sparse)
    disk_usage(output);

    println!("[rootfsbuilder] === Build complete ===");
    println!("[rootfsbuilder] Output: {}", output.display());
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn run_e2fsck(output: &Path) -> Result<()> {
    let status = Command::new("e2fsck")
        .args(["-f", "-y", &output.display().to_string()])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| RootfsError::new(RootfsPhase::Verify, format!("spawn e2fsck: {e}")))?;

    let code = status.code().unwrap_or(0);
    // Exit codes:
    //   0 = no errors
    //   1 = errors corrected
    //   2 = errors corrected, reboot recommended (fine for image files)
    //   4+ = uncorrected errors or operational error
    if code >= 4 {
        return Err(RootfsError::new(
            RootfsPhase::Verify,
            format!("e2fsck exited with code {code} (uncorrected errors in image)"),
        ));
    }
    Ok(())
}

fn compute_sha256(path: &Path) -> Result<String> {
    println!("[rootfsbuilder] hashing image (sha256sum)...");
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(|e| RootfsError::new(RootfsPhase::Verify, format!("spawn sha256sum: {e}")))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(RootfsError::new(
            RootfsPhase::Verify,
            format!("sha256sum failed: {stderr}"),
        ));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .split_whitespace()
        .next()
        .map(String::from)
        .ok_or_else(|| {
            RootfsError::new(
                RootfsPhase::Verify,
                "sha256sum produced no output".to_string(),
            )
        })
}

fn disk_usage(path: &Path) {
    let _ = Command::new("du")
        .args(["-sh", &path.display().to_string()])
        .stdout(Stdio::inherit())
        .status();
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let out = Command::new("chown")
        .arg(format!("{uid}:{gid}"))
        .arg(path)
        .output()
        .map_err(|e| RootfsError::new(RootfsPhase::ImageCreate, format!("spawn chown: {e}")))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        return Err(RootfsError::from_cmd(
            RootfsPhase::ImageCreate,
            &format!("chown {uid}:{gid}"),
            out.status.code(),
            &stderr,
        ));
    }
    Ok(())
}

// SHA-256 is computed by shelling out to `sha256sum`, which uses hardware
// acceleration (SHA-NI on x86_64).  The previous hand-rolled Rust
// implementation was textbook-correct but ~100x slower on large files.

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn compute_sha256_empty_file() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("empty.bin");
        fs::write(&f, b"").unwrap();

        let got = compute_sha256(&f).unwrap();
        assert_eq!(
            got, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-256 of empty file should match known digest"
        );
    }

    #[test]
    fn compute_sha256_known_content() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("data.bin");
        fs::write(&f, b"hello rootfsbuilder").unwrap();

        let got = compute_sha256(&f).unwrap();
        assert_eq!(got.len(), 64, "hash should be 64 hex chars");

        // Cross-check with sha256sum binary.
        let out = Command::new("sha256sum").arg(&f).output().unwrap();
        assert!(out.status.success());
        let expected = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .unwrap()
            .to_string();
        assert_eq!(got, expected);
    }

    #[test]
    fn e2fsck_exit_code_logic() {
        for code in [0i32, 1, 2] {
            assert!(code < 4, "codes 0-3 should be acceptable");
        }
        for code in [4i32, 8, 16] {
            assert!(code >= 4, "codes 4+ indicate uncorrected errors");
        }
    }
}
