//! Artifact installer — downloads, verifies, and installs pre-built artifacts.
//!
//! All operations are **synchronous** (uses `ureq` for HTTP, `zstd` for
//! decompression, `sha2` for hashing).  The caller (`install_worker`) wraps
//! them in `tokio::task::spawn_blocking`.
//!
//! # Atomicity guarantee
//!
//! The install never leaves `current` pointing at a partial state:
//!
//! 1. Download + hash to a temp directory (`.installing-<random>`)
//! 2. Decompress zstd → rootfs.ext4
//! 3. Write `golden.meta.json`
//! 4. Atomic `fs::rename` to the final fingerprint directory
//! 5. Atomic symlink update for `current`
//!
//! If any step fails, the temp directory is cleaned up and `current` is untouched.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use core_rs::artifact_meta;
use core_rs::artifact_registry::ArtifactManifest;

use super::artifact_resolver::ArtifactError;

// ── Installer ───────────────────────────────────────────────────────────────

/// Installs pre-built golden rootfs artifacts into the local asset storage.
pub struct ArtifactInstaller {
    assets_dir: PathBuf,
    http: ureq::Agent,
}

impl ArtifactInstaller {
    /// Create a new installer.
    ///
    /// `assets_dir` is `~/firecracker/assets/` — the root of the DAG storage.
    #[must_use]
    pub fn new(assets_dir: &Path) -> Self {
        let http = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(10))
            .timeout_read(std::time::Duration::from_secs(300))
            .build();

        Self {
            assets_dir: assets_dir.to_path_buf(),
            http,
        }
    }

    /// Download, verify, and install an artifact atomically.
    ///
    /// Returns the path to the installed rootfs on success.
    ///
    /// `progress_cb` is called periodically with `(bytes_downloaded, total_bytes)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError`] on download failure, hash mismatch,
    /// decompression error, insufficient disk space, or I/O error.
    pub fn install(
        &self,
        manifest: &ArtifactManifest,
        progress_cb: impl Fn(u64, u64),
    ) -> Result<PathBuf, ArtifactError> {
        let goldens_claw_dir = self.assets_dir.join("goldens").join(&manifest.claw);
        fs::create_dir_all(&goldens_claw_dir)?;
        let fingerprint = artifact_meta::Fingerprint::new(&manifest.fingerprint);
        let final_dir =
            artifact_meta::golden_version_dir(&self.assets_dir, &manifest.claw, &fingerprint);

        if final_dir.exists() {
            if artifact_dir_complete(&final_dir) {
                let current_link =
                    artifact_meta::golden_current_link(&self.assets_dir, &manifest.claw);
                artifact_meta::update_current_link(&current_link, &fingerprint).map_err(|e| {
                    ArtifactError::Io(io::Error::other(format!("update current symlink: {e}")))
                })?;
                return Ok(final_dir.join("rootfs.ext4"));
            }

            let current_link = artifact_meta::golden_current_link(&self.assets_dir, &manifest.claw);
            if current_points_to(&current_link, &final_dir)? {
                return Err(ArtifactError::Io(io::Error::other(format!(
                    "existing artifact directory is incomplete and currently active: {}",
                    final_dir.display()
                ))));
            }

            fs::remove_dir_all(&final_dir)?;
        }

        // 0. Check disk space (heuristic: need ~4x compressed size)
        self.check_disk_space(manifest)?;

        // 1. Create temp directory for atomic install
        let temp_name = format!(".installing-{}", core_rs::id::generate_id("dl"));
        let temp_dir = goldens_claw_dir.join(&temp_name);
        fs::create_dir_all(&temp_dir)?;

        // Guard: clean up temp dir on failure
        let committed = std::cell::Cell::new(false);
        let cleanup_dir = temp_dir.clone();
        let _cleanup = scopeguard::OnScopeExit::new(|| {
            if !committed.get() {
                let _ = fs::remove_dir_all(&cleanup_dir);
            }
        });

        // 2. Download with streaming SHA-256
        let zst_path = temp_dir.join("rootfs.ext4.zst");
        let actual_sha256 =
            self.download_with_hash(&manifest.url, &zst_path, manifest.size_bytes, &progress_cb)?;

        // 3. Verify SHA-256
        if actual_sha256 != manifest.sha256 {
            return Err(ArtifactError::HashMismatch {
                expected: manifest.sha256.clone(),
                actual: actual_sha256,
            });
        }

        // 4. Decompress zstd → rootfs.ext4
        let rootfs_path = temp_dir.join("rootfs.ext4");
        decompress_zstd(&zst_path, &rootfs_path)?;

        // 5. Remove compressed file (no longer needed)
        let _ = fs::remove_file(&zst_path);

        // 6. Write golden.meta.json (compatible with existing DAG layout)
        //
        // The three SHA-256 fields must be the real build-input hashes so that
        // DAG staleness detection, `doctor`, and `artifacts sync` work
        // identically for pre-built and locally-built goldens.
        let meta = artifact_meta::GoldenMeta {
            claw_type: manifest.claw.clone(),
            fingerprint: artifact_meta::Fingerprint::new(&manifest.fingerprint),
            base_rootfs_sha256: manifest.base_rootfs_sha256.clone(),
            installer_plan_sha256: manifest.installer_plan_sha256.clone(),
            kernel_sha256: manifest.kernel_sha256.clone(),
            builder_version: format!("prebuilt-{}", manifest.version),
            created_at: manifest.published_at.clone(),
        };
        artifact_meta::write_meta(&temp_dir.join("golden.meta.json"), &meta).map_err(|e| {
            ArtifactError::Io(io::Error::other(format!("write golden.meta.json: {e}")))
        })?;

        // 7. Atomic rename: temp_dir → final fingerprint directory
        fs::rename(&temp_dir, &final_dir)?;
        committed.set(true);

        // 8. Update `current` symlink atomically
        let current_link = artifact_meta::golden_current_link(&self.assets_dir, &manifest.claw);
        artifact_meta::update_current_link(&current_link, &fingerprint).map_err(|e| {
            ArtifactError::Io(io::Error::other(format!("update current symlink: {e}")))
        })?;

        tracing::info!(
            "[artifact-installer] installed {}/{} (fp={})",
            manifest.claw,
            manifest.version,
            fingerprint.short(),
        );

        Ok(final_dir.join("rootfs.ext4"))
    }

    /// Check available disk space before downloading.
    fn check_disk_space(&self, manifest: &ArtifactManifest) -> Result<(), ArtifactError> {
        let need_bytes = manifest.size_bytes.saturating_mul(4);
        let need_mb = need_bytes / (1024 * 1024);

        // Use statvfs to check available space
        #[cfg(unix)]
        {
            let path_cstr = std::ffi::CString::new(self.assets_dir.to_string_lossy().as_bytes())
                .unwrap_or_default();

            // SAFETY: statvfs is a libc function; we pass a valid NUL-terminated
            // path and a zeroed struct. The result is read-only numeric fields.
            #[allow(unsafe_code)]
            let available = unsafe {
                let mut stat: libc::statvfs = std::mem::zeroed();
                if libc::statvfs(path_cstr.as_ptr(), std::ptr::addr_of_mut!(stat)) == 0 {
                    // f_bavail/f_frsize types vary by platform (u32 on Linux, u64 on macOS).
                    // Allow both cast directions to keep cross-platform.
                    #[allow(clippy::unnecessary_cast, clippy::cast_lossless)]
                    ((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
                } else {
                    return Ok(()); // Can't check — proceed optimistically
                }
            };

            let have_mb = available / (1024 * 1024);
            if available < need_bytes {
                return Err(ArtifactError::InsufficientDisk { need_mb, have_mb });
            }
        }

        Ok(())
    }

    /// Download a URL to a file, computing SHA-256 while streaming.
    ///
    /// Returns the hex-encoded SHA-256 digest.
    fn download_with_hash(
        &self,
        url: &str,
        dest: &Path,
        total_bytes: u64,
        progress_cb: &impl Fn(u64, u64),
    ) -> Result<String, ArtifactError> {
        use std::fmt::Write as _;

        let response = self
            .http
            .get(url)
            .call()
            .map_err(|e| ArtifactError::Download(format!("{url}: {e}")))?;

        let mut reader = response.into_reader();
        let mut file = fs::File::create(dest)?;
        let mut hasher = Sha256::new();

        let mut buf = vec![0u8; 256 * 1024]; // 256 KiB chunks
        let mut downloaded: u64 = 0;

        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| ArtifactError::Download(format!("read: {e}")))?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])?;
            hasher.update(&buf[..n]);
            downloaded += n as u64;
            progress_cb(downloaded, total_bytes);
        }

        file.flush()?;
        drop(file);

        let digest = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for b in digest {
            let _ = write!(hex, "{b:02x}");
        }
        Ok(hex)
    }
}

/// Decompress a zstd-compressed file.
fn decompress_zstd(src: &Path, dest: &Path) -> Result<(), ArtifactError> {
    let input = fs::File::open(src)?;
    let mut decoder = zstd::Decoder::new(input)
        .map_err(|e| ArtifactError::Decompress(format!("zstd init: {e}")))?;

    let mut output = fs::File::create(dest)?;
    io::copy(&mut decoder, &mut output)
        .map_err(|e| ArtifactError::Decompress(format!("zstd decompress: {e}")))?;

    output.flush()?;
    Ok(())
}

fn artifact_dir_complete(dir: &Path) -> bool {
    dir.join("rootfs.ext4").is_file() && dir.join("golden.meta.json").is_file()
}

fn current_points_to(link_path: &Path, dir: &Path) -> Result<bool, ArtifactError> {
    let target = match fs::read_link(link_path) {
        Ok(target) => target,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(ArtifactError::Io(e)),
    };

    let target_abs = if target.is_relative() {
        match link_path.parent() {
            Some(parent) => parent.join(target),
            None => return Ok(false),
        }
    } else {
        target
    };

    Ok(target_abs == dir)
}

// ── Scope guard (simple inline, no extra dep) ───────────────────────────────

mod scopeguard {
    pub struct OnScopeExit<F: FnOnce()>(Option<F>);

    impl<F: FnOnce()> OnScopeExit<F> {
        pub fn new(f: F) -> Self {
            Self(Some(f))
        }
    }

    impl<F: FnOnce()> Drop for OnScopeExit<F> {
        fn drop(&mut self) {
            if let Some(f) = self.0.take() {
                f();
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
