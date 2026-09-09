#![cfg(test)]

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

    for (body_claw, forbidden_rel) in [("../escaped", "escaped"), ("attacker", "goldens/attacker")]
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
