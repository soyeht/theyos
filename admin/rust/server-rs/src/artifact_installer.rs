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
mod tests {
    use super::*;

    fn make_manifest(sha256: &str) -> ArtifactManifest {
        ArtifactManifest {
            manifest_version: 1,
            claw: "testclaw".into(),
            version: "1.0.0".into(),
            arch: "x86_64-linux".into(),
            fingerprint: "e".repeat(64),
            base_rootfs_version: "v2".into(),
            sha256: sha256.into(),
            size_bytes: 100,
            url: "http://127.0.0.1:1/nonexistent".into(),
            published_at: "2026-04-01T00:00:00Z".into(),
            channel: "stable".into(),
            base_rootfs_sha256: "b".repeat(64),
            installer_plan_sha256: "c".repeat(64),
            kernel_sha256: "d".repeat(64),
            kernel_version: None,
            firecracker_version: None,
            runtime_min_version: None,
        }
    }

    #[test]
    fn installer_new_sets_assets_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let installer = ArtifactInstaller::new(tmp.path());
        assert_eq!(installer.assets_dir, tmp.path());
    }

    #[test]
    fn decompress_zstd_roundtrip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let original = b"hello world, this is a test of zstd compression!";

        // Compress
        let zst_path = tmp.path().join("test.zst");
        let mut encoder = zstd::Encoder::new(fs::File::create(&zst_path).unwrap(), 3).unwrap();
        encoder.write_all(original).unwrap();
        encoder.finish().unwrap();

        // Decompress
        let out_path = tmp.path().join("test.out");
        decompress_zstd(&zst_path, &out_path).unwrap();

        let result = fs::read(&out_path).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn install_fails_on_unreachable_url() {
        let tmp = tempfile::TempDir::new().unwrap();
        let assets_dir = tmp.path().join("assets");
        fs::create_dir_all(&assets_dir).unwrap();

        let installer = ArtifactInstaller::new(&assets_dir);
        let manifest = make_manifest(&"a".repeat(64));

        let result = installer.install(&manifest, |_, _| {});
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ArtifactError::Download(_)),
            "expected Download error, got: {err}"
        );

        // Temp dir should be cleaned up
        let goldens = assets_dir.join("goldens").join("testclaw");
        if goldens.exists() {
            let entries: Vec<_> = fs::read_dir(&goldens)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(".installing-"))
                .collect();
            assert!(
                entries.is_empty(),
                "temp directory should be cleaned up on failure"
            );
        }
    }

    #[test]
    fn scope_guard_runs_on_drop() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let ran = AtomicBool::new(false);
        {
            let _guard = scopeguard::OnScopeExit::new(|| {
                ran.store(true, Ordering::Relaxed);
            });
        }
        assert!(ran.load(Ordering::Relaxed));
    }

    /// Full happy-path test: serve a zstd-compressed file from a local HTTP
    /// server, install it, and verify the golden directory, meta, and symlink.
    #[test]
    fn install_happy_path_with_fixture_server() {
        use sha2::{Digest, Sha256};
        use std::fmt::Write as _;

        let tmp = tempfile::TempDir::new().unwrap();
        let assets_dir = tmp.path().join("assets");
        fs::create_dir_all(&assets_dir).unwrap();

        // 1. Create a fake rootfs and compress it with zstd
        let rootfs_content = b"fake rootfs ext4 data for testing";
        let mut zst_buf = Vec::new();
        {
            let mut encoder = zstd::Encoder::new(&mut zst_buf, 1).unwrap();
            encoder.write_all(rootfs_content).unwrap();
            encoder.finish().unwrap();
        }

        // 2. Compute SHA-256 of the compressed data
        let digest = Sha256::digest(&zst_buf);
        let mut sha256_hex = String::with_capacity(64);
        for b in digest {
            let _ = write!(sha256_hex, "{b:02x}");
        }

        // 3. Serve the zstd file from a local HTTP server
        let zst_bytes = zst_buf.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let download_url = format!("http://127.0.0.1:{port}/rootfs.ext4.zst");

        let listener_clone = listener.try_clone().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener_clone.accept() {
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut stream, &mut buf);
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    zst_bytes.len()
                );
                let _ = std::io::Write::write_all(&mut stream, header.as_bytes());
                let _ = std::io::Write::write_all(&mut stream, &zst_bytes);
            }
        });

        // 4. Build manifest with correct sha256
        let manifest = ArtifactManifest {
            manifest_version: 1,
            claw: "testclaw".into(),
            version: "1.0.0".into(),
            arch: core_rs::artifact_registry::host_arch(),
            fingerprint: "e".repeat(64),
            base_rootfs_version: "v2".into(),
            sha256: sha256_hex,
            size_bytes: zst_buf.len() as u64,
            url: download_url,
            published_at: "2026-04-01T00:00:00Z".into(),
            channel: "stable".into(),
            base_rootfs_sha256: "b".repeat(64),
            installer_plan_sha256: "c".repeat(64),
            kernel_sha256: "d".repeat(64),
            kernel_version: Some(core_rs::guest_net::KERNEL_FILENAME.into()),
            firecracker_version: None,
            runtime_min_version: None,
        };

        // 5. Install
        let installer = ArtifactInstaller::new(&assets_dir);
        let progress_calls = std::cell::Cell::new(0u32);
        let result = installer.install(&manifest, |_dl, _total| {
            progress_calls.set(progress_calls.get() + 1);
        });
        assert!(result.is_ok(), "install should succeed, got: {result:?}");

        let rootfs_path = result.unwrap();
        assert!(
            rootfs_path.exists(),
            "rootfs should exist at {rootfs_path:?}"
        );

        // 6. Verify decompressed content matches original
        let installed_content = fs::read(&rootfs_path).unwrap();
        assert_eq!(installed_content, rootfs_content, "rootfs content mismatch");

        // 7. Verify golden directory structure
        let golden_dir = assets_dir
            .join("goldens")
            .join("testclaw")
            .join("e".repeat(64));
        assert!(golden_dir.is_dir(), "golden dir should exist");
        assert!(
            golden_dir.join("rootfs.ext4").is_file(),
            "rootfs.ext4 should exist"
        );
        assert!(
            golden_dir.join("golden.meta.json").is_file(),
            "golden.meta.json should exist"
        );

        // 8. Verify golden.meta.json has correct field values
        let meta_content = fs::read_to_string(golden_dir.join("golden.meta.json")).unwrap();
        let meta: serde_json::Value = serde_json::from_str(&meta_content).unwrap();
        assert_eq!(meta["claw_type"], "testclaw");
        assert_eq!(meta["fingerprint"], "e".repeat(64));
        assert_eq!(meta["base_rootfs_sha256"], "b".repeat(64));
        assert_eq!(meta["installer_plan_sha256"], "c".repeat(64));
        assert_eq!(meta["kernel_sha256"], "d".repeat(64));
        assert_eq!(meta["builder_version"], "prebuilt-1.0.0");

        // 9. Verify `current` symlink points to the fingerprint dir
        let current_link = assets_dir.join("goldens").join("testclaw").join("current");
        assert!(current_link.exists(), "current symlink should exist");
        let target = fs::read_link(&current_link).unwrap();
        assert_eq!(
            target.to_string_lossy(),
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "current should point to fingerprint dir"
        );

        // 10. Verify progress callback was called
        assert!(
            progress_calls.get() > 0,
            "progress callback should have been called"
        );

        // 11. No .installing-* temp dirs left behind
        let goldens_claw = assets_dir.join("goldens").join("testclaw");
        let temp_dirs: Vec<_> = fs::read_dir(&goldens_claw)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".installing-"))
            .collect();
        assert!(
            temp_dirs.is_empty(),
            "no temp dirs should remain after success"
        );
    }

    /// Test that hash mismatch is caught correctly (corrupted download).
    #[test]
    fn install_detects_hash_mismatch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let assets_dir = tmp.path().join("assets");
        fs::create_dir_all(&assets_dir).unwrap();

        // Serve some data
        let data = b"some data";
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/file");

        let data_owned = data.to_vec();
        let listener_clone = listener.try_clone().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener_clone.accept() {
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut stream, &mut buf);
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    data_owned.len()
                );
                let _ = std::io::Write::write_all(&mut stream, header.as_bytes());
                let _ = std::io::Write::write_all(&mut stream, &data_owned);
            }
        });

        // Manifest with wrong sha256
        let manifest = ArtifactManifest {
            manifest_version: 1,
            claw: "testclaw".into(),
            version: "1.0.0".into(),
            arch: core_rs::artifact_registry::host_arch(),
            fingerprint: "e".repeat(64),
            base_rootfs_version: "v2".into(),
            sha256: "0".repeat(64), // wrong hash
            size_bytes: data.len() as u64,
            url,
            published_at: "2026-04-01T00:00:00Z".into(),
            channel: "stable".into(),
            base_rootfs_sha256: "b".repeat(64),
            installer_plan_sha256: "c".repeat(64),
            kernel_sha256: "d".repeat(64),
            kernel_version: None,
            firecracker_version: None,
            runtime_min_version: None,
        };

        let installer = ArtifactInstaller::new(&assets_dir);
        let result = installer.install(&manifest, |_, _| {});
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ArtifactError::HashMismatch { .. }),
            "expected HashMismatch, got: {err}"
        );

        // Temp dir should be cleaned up
        let goldens = assets_dir.join("goldens").join("testclaw");
        if goldens.exists() {
            let temp_dirs: Vec<_> = fs::read_dir(&goldens)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(".installing-"))
                .collect();
            assert!(
                temp_dirs.is_empty(),
                "temp dir should be cleaned up on hash mismatch"
            );
        }
    }

    #[test]
    fn install_reuses_existing_complete_fingerprint_without_deleting_current() {
        let tmp = tempfile::TempDir::new().unwrap();
        let assets_dir = tmp.path().join("assets");
        fs::create_dir_all(&assets_dir).unwrap();

        let fingerprint = artifact_meta::Fingerprint::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let final_dir = artifact_meta::golden_version_dir(&assets_dir, "testclaw", &fingerprint);
        fs::create_dir_all(&final_dir).unwrap();
        fs::write(final_dir.join("rootfs.ext4"), b"existing rootfs").unwrap();

        let meta = artifact_meta::GoldenMeta {
            claw_type: "testclaw".into(),
            fingerprint: fingerprint.clone(),
            base_rootfs_sha256: "b".repeat(64),
            installer_plan_sha256: "c".repeat(64),
            kernel_sha256: "d".repeat(64),
            builder_version: "prebuilt-1.0.0".into(),
            created_at: "2026-04-01T00:00:00Z".into(),
        };
        artifact_meta::write_meta(&final_dir.join("golden.meta.json"), &meta).unwrap();

        let current_link = artifact_meta::golden_current_link(&assets_dir, "testclaw");
        artifact_meta::update_current_link(&current_link, &fingerprint).unwrap();

        let manifest = ArtifactManifest {
            manifest_version: 1,
            claw: "testclaw".into(),
            version: "1.0.0".into(),
            arch: core_rs::artifact_registry::host_arch(),
            fingerprint: fingerprint.as_str().to_string(),
            base_rootfs_version: "v2".into(),
            sha256: "7".repeat(64),
            size_bytes: 16,
            url: "http://127.0.0.1:1/unused".into(),
            published_at: "2026-04-01T00:00:00Z".into(),
            channel: "stable".into(),
            base_rootfs_sha256: "b".repeat(64),
            installer_plan_sha256: "c".repeat(64),
            kernel_sha256: "d".repeat(64),
            kernel_version: None,
            firecracker_version: None,
            runtime_min_version: None,
        };

        let installer = ArtifactInstaller::new(&assets_dir);
        let result = installer.install(&manifest, |_, _| {});
        assert!(result.is_ok(), "install should reuse existing final dir");
        assert_eq!(
            fs::read(final_dir.join("rootfs.ext4")).unwrap(),
            b"existing rootfs"
        );
        assert_eq!(
            fs::read_link(&current_link).unwrap(),
            PathBuf::from(fingerprint.as_str())
        );
    }

    /// Brother 8 RED: `resolve(claw)` fetches by the *requested* claw (URL
    /// path), but `install()` turns the *manifest body* `claw` into
    /// `create_dir_all` / `remove_dir_all` targets — and nothing compared
    /// the two. This test publishes a manifest whose `claw` disagrees with
    /// the requested claw and asserts on the **disk paths** that the flow
    /// creates (the effect site), not on any returned value.
    #[test]
    fn install_never_writes_outside_the_requested_claw_directory() {
        use sha2::{Digest, Sha256};
        use std::fmt::Write as _;

        for (body_claw, forbidden_rel) in
            [("../escaped", "escaped"), ("attacker", "goldens/attacker")]
        {
            let tmp = tempfile::TempDir::new().unwrap();
            let assets_dir = tmp.path().join("assets");
            fs::create_dir_all(&assets_dir).unwrap();

            // Compress a fake rootfs and hash the compressed bytes (same
            // recipe as install_happy_path_with_fixture_server).
            let rootfs_content = b"fake rootfs for the brother-8 red";
            let mut zst_buf = Vec::new();
            {
                let mut encoder = zstd::Encoder::new(&mut zst_buf, 1).unwrap();
                encoder.write_all(rootfs_content).unwrap();
                encoder.finish().unwrap();
            }
            let digest = Sha256::digest(&zst_buf);
            let mut sha256_hex = String::with_capacity(64);
            for b in digest {
                let _ = write!(sha256_hex, "{b:02x}");
            }

            // Bind first so the manifest URL can point at this server; then
            // serve [latest.json, rootfs.ext4.zst] in request order.
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let base_url = format!("http://127.0.0.1:{port}");

            let manifest = ArtifactManifest {
                manifest_version: 1,
                claw: body_claw.into(),
                version: "1.0.0".into(),
                arch: core_rs::artifact_registry::host_arch(),
                fingerprint: "e".repeat(64),
                base_rootfs_version: "v2".into(),
                sha256: sha256_hex,
                size_bytes: zst_buf.len() as u64,
                url: format!("{base_url}/rootfs.ext4.zst"),
                published_at: "2026-04-01T00:00:00Z".into(),
                channel: "stable".into(),
                base_rootfs_sha256: "b".repeat(64),
                installer_plan_sha256: "c".repeat(64),
                kernel_sha256: "d".repeat(64),
                kernel_version: None,
                firecracker_version: None,
                runtime_min_version: None,
            };
            let bodies: Vec<Vec<u8>> = vec![
                serde_json::to_string(&manifest).unwrap().into_bytes(),
                zst_buf,
            ];
            std::thread::spawn(move || {
                for body in bodies {
                    if let Ok((mut stream, _)) = listener.accept() {
                        let mut buf = [0u8; 8192];
                        let _ = std::io::Read::read(&mut stream, &mut buf);
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = std::io::Write::write_all(&mut stream, header.as_bytes());
                        let _ = std::io::Write::write_all(&mut stream, &body);
                    }
                }
            });

            // Request "victim"; the registry answers with a manifest whose
            // body names a different claw. If resolve() lets it through,
            // install() writes to the body's directory.
            let resolver = super::super::artifact_resolver::ArtifactResolver::new(&base_url);
            if let Ok(manifest) = resolver.resolve("victim") {
                let installer = ArtifactInstaller::new(&assets_dir);
                let _ = installer.install(&manifest, |_, _| {});
            }

            // Effect site: nothing may exist outside goldens/victim.
            let forbidden = assets_dir.join(forbidden_rel);
            assert!(
                !forbidden.exists(),
                "manifest body claw {body_claw:?} steered the install outside \
                 the requested claw directory: {} exists",
                forbidden.display(),
            );
        }
    }
}
