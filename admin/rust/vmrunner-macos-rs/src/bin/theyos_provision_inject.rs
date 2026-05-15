//! `theyos-provision-inject` — Privileged APFS provisioning helper.
//!
//! Runs as root (via `sudo`). Mounts the macOS guest disk image with
//! `-o owners`, writes all provision files with correct `root:wheel`
//! ownership, and unmounts.
//!
//! # Usage
//!
//! ```text
//! sudo theyos-provision-inject \
//!   --disk /path/to/disk.img \
//!   --ssh-pubkey "ssh-ed25519 AAAA..." \
//!   --plist-dir /path/to/scripts/launchd
//! ```
//!
//! # Output
//!
//! Prints a JSON manifest of all operations to stdout.
//! Errors go to stderr with a non-zero exit code.

#[cfg(target_os = "macos")]
#[allow(unsafe_code)] // Required for libc::geteuid() and libc::chown()
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::PathBuf;
    use std::process::Command;

    use vmrunner_macos_rs::macos_guest;

    // ── Parse args ───────────────────────────────────────────────────────────
    let args: Vec<String> = std::env::args().collect();
    let disk_path = arg_value(&args, "--disk").ok_or("missing --disk <path>")?;
    let ssh_pubkey = arg_value(&args, "--ssh-pubkey").ok_or("missing --ssh-pubkey <key>")?;
    let plist_dir = arg_value(&args, "--plist-dir").unwrap_or_default();

    let disk = PathBuf::from(&disk_path);
    if !disk.exists() {
        return Err(format!("disk image not found: {disk_path}").into());
    }

    // Verify we are running as root
    if unsafe { libc::geteuid() } != 0 {
        return Err("theyos-provision-inject must run as root (via sudo)".into());
    }

    let mut manifest = Manifest {
        disk: disk_path.clone(),
        ..Default::default()
    };

    // ── Step 1: Attach disk image ────────────────────────────────────────────
    eprintln!("[provision-inject] Attaching disk image...");
    let attach_out = Command::new("hdiutil")
        .args(["attach", "-nomount", "-plist", &disk_path])
        .output()?;
    if !attach_out.status.success() {
        return Err(format!(
            "hdiutil attach failed: {}",
            String::from_utf8_lossy(&attach_out.stderr)
        )
        .into());
    }
    let plist_str = String::from_utf8_lossy(&attach_out.stdout);

    // ── Step 2: Find Data volume ─────────────────────────────────────────────
    let data_dev = macos_guest::find_apfs_data_volume(&plist_str)
        .map_err(|e| format!("find Data volume: {e}"))?;
    eprintln!("[provision-inject] Found Data volume: {data_dev}");

    // Extract base disk device for detach later
    let base_disk = extract_base_disk(&plist_str);

    // ── Step 3: Mount with ownership ─────────────────────────────────────────
    let mount_dir = tempfile::TempDir::new()?;
    let mp = mount_dir.path();
    eprintln!(
        "[provision-inject] Mounting {data_dev} at {}...",
        mp.display()
    );

    let mount_out = Command::new("mount")
        .args(["-t", "apfs", "-o", "owners,nobrowse", &data_dev])
        .arg(mp)
        .output()?;
    if !mount_out.status.success() {
        // Detach before returning error
        if let Some(ref bd) = base_disk {
            let _ = Command::new("hdiutil").args(["detach", bd]).output();
        }
        return Err(format!(
            "mount failed: {}",
            String::from_utf8_lossy(&mount_out.stderr)
        )
        .into());
    }
    manifest.mount_point = mp.display().to_string();

    // ── Step 4: Write provision files ────────────────────────────────────────
    // All writes happen as root — files get correct ownership automatically.

    let result = write_all_files(mp, &ssh_pubkey, &plist_dir, &mut manifest);

    // ── Step 5: Unmount + detach (always, even on error) ─────────────────────
    eprintln!("[provision-inject] Unmounting...");
    let _ = Command::new("umount").arg(mp).output();

    if let Some(ref bd) = base_disk {
        detach_with_retry(bd);
    }

    // Check write result after cleanup
    result?;

    // ── Step 6: Re-mount read-only and verify the manifest ───────────────────
    // The write path above trusts std::fs::write() + chown() success, but
    // doesn't prove the bytes/metadata survived the unmount. Verifying after
    // umount+detach catches APFS owners-flag races (silent UID/GID drop) and
    // any case where the bytes were buffered but not flushed.
    eprintln!("[provision-inject] Verifying manifest post-unmount...");
    verify_manifest(&disk_path, &manifest)?;

    // ── Output manifest ──────────────────────────────────────────────────────
    manifest.ok = true;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    eprintln!("[provision-inject] Done.");
    Ok(())
}

/// Re-attach the disk read-only and assert every manifest entry has the
/// expected owner (root:wheel) and mode. Detaches before returning.
#[cfg(target_os = "macos")]
fn verify_manifest(disk_path: &str, manifest: &Manifest) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;
    use vmrunner_macos_rs::macos_guest;

    // Attach read-only, no mount (we mount manually with explicit options).
    let attach_out = Command::new("hdiutil")
        .args(["attach", "-readonly", "-nomount", "-plist", disk_path])
        .output()?;
    if !attach_out.status.success() {
        return Err(format!(
            "verify: hdiutil attach failed: {}",
            String::from_utf8_lossy(&attach_out.stderr)
        )
        .into());
    }
    let plist_str = String::from_utf8_lossy(&attach_out.stdout);

    let data_dev = macos_guest::find_apfs_data_volume(&plist_str)
        .map_err(|e| format!("verify: find Data volume: {e}"))?;
    let base_disk = extract_base_disk(&plist_str);

    let mount_dir = tempfile::TempDir::new()?;
    let mp = mount_dir.path();
    let mount_out = Command::new("mount")
        .args(["-t", "apfs", "-o", "ro,owners,nobrowse", &data_dev])
        .arg(mp)
        .output()?;
    if !mount_out.status.success() {
        if let Some(ref bd) = base_disk {
            let _ = Command::new("hdiutil").args(["detach", bd]).output();
        }
        return Err(format!(
            "verify: mount failed: {}",
            String::from_utf8_lossy(&mount_out.stderr)
        )
        .into());
    }

    // Iterate entries; collect all mismatches before returning so the user
    // sees the full picture (not just the first bad file).
    let mut mismatches: Vec<String> = Vec::new();
    for entry in &manifest.files_written {
        let on_disk = mp.join(&entry.path);
        let meta = match std::fs::symlink_metadata(&on_disk) {
            Ok(m) => m,
            Err(e) => {
                mismatches.push(format!("{}: missing on disk ({e})", entry.path));
                continue;
            }
        };
        if meta.uid() != 0 || meta.gid() != 0 {
            mismatches.push(format!(
                "{}: owner {}:{} (expected 0:0)",
                entry.path,
                meta.uid(),
                meta.gid()
            ));
        }
        let actual_mode = meta.mode() & 0o7777;
        let expected_mode = u32::from_str_radix(&entry.mode, 8).unwrap_or(0);
        if actual_mode != expected_mode {
            mismatches.push(format!(
                "{}: mode {:o} (expected {})",
                entry.path, actual_mode, entry.mode
            ));
        }
        let is_dir = meta.is_dir();
        let want_dir = entry.kind == "dir";
        if is_dir != want_dir {
            mismatches.push(format!(
                "{}: kind {} (expected {})",
                entry.path,
                if is_dir { "dir" } else { "file" },
                entry.kind
            ));
        }
    }

    let _ = Command::new("umount").arg(mp).output();
    if let Some(ref bd) = base_disk {
        detach_with_retry(bd);
    }

    if !mismatches.is_empty() {
        return Err(format!(
            "verify: {} mismatch(es) post-unmount:\n  {}",
            mismatches.len(),
            mismatches.join("\n  ")
        )
        .into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn write_all_files(
    mp: &std::path::Path,
    ssh_pubkey: &str,
    plist_dir: &str,
    manifest: &mut Manifest,
) -> Result<(), Box<dyn std::error::Error>> {
    use vmrunner_macos_rs::macos_guest;

    let claw_types = macos_guest::CLAW_TYPE_NAMES;

    // ── LaunchDaemons directory ───────────────────────────────────────────
    let launchd_dir = mp.join("Library/LaunchDaemons");
    std::fs::create_dir_all(&launchd_dir)?;

    // 1. com.theyos.sshd.plist (the key file — enables SSH on first boot)
    let sshd_path = launchd_dir.join("com.theyos.sshd.plist");
    std::fs::write(&sshd_path, macos_guest::sshd_plist_xml())?;
    set_root_wheel(&sshd_path, 0o644)?;
    manifest.file_written(&sshd_path, mp, "644");

    // 2. com.theyos.provision.plist (first-boot setup script)
    let provision_path = launchd_dir.join("com.theyos.provision.plist");
    std::fs::write(&provision_path, macos_guest::provision_plist_xml())?;
    set_root_wheel(&provision_path, 0o644)?;
    manifest.file_written(&provision_path, mp, "644");

    // ── Provision directory ──────────────────────────────────────────────
    let provision_dir = mp.join("private/var/root/.theyos-provision");
    std::fs::create_dir_all(&provision_dir)?;
    set_root_wheel(&provision_dir, 0o755)?;
    manifest.dir_written(&provision_dir, mp, "755");

    // 3. setup.sh
    let setup_path = provision_dir.join("setup.sh");
    std::fs::write(&setup_path, macos_guest::setup_sh(ssh_pubkey, claw_types))?;
    set_root_wheel(&setup_path, 0o755)?;
    manifest.file_written(&setup_path, mp, "755");

    // 4. authorized_keys (for provision script)
    let ak_provision = provision_dir.join("authorized_keys");
    std::fs::write(&ak_provision, ssh_pubkey)?;
    set_root_wheel(&ak_provision, 0o600)?;
    manifest.file_written(&ak_provision, mp, "600");

    // 5. Claw-type LaunchDaemon plists
    let plist_path = std::path::Path::new(plist_dir);
    for claw_type in claw_types {
        let src = plist_path.join(format!("com.theyos.{claw_type}.plist"));
        let dst = provision_dir.join(format!("com.theyos.{claw_type}.plist"));
        if src.exists() {
            std::fs::copy(&src, &dst)?;
            set_root_wheel(&dst, 0o644)?;
            manifest.file_written(&dst, mp, "644");
        }
    }

    // ── .AppleSetupDone ──────────────────────────────────────────────────
    // Skips Setup Assistant on first boot. Without correct ownership, launchd
    // may not bootstrap LaunchDaemons (Setup Assistant gates user-session
    // services; LaunchDaemons run as root but the OOBE flow can still block
    // first-boot daemon startup if file metadata is unexpected).
    let var_db = mp.join("private/var/db");
    std::fs::create_dir_all(&var_db)?;
    let setup_done = var_db.join(".AppleSetupDone");
    std::fs::write(&setup_done, b"")?;
    set_root_wheel(&setup_done, 0o644)?;
    manifest.file_written(&setup_done, mp, "644");

    // ── SSH config ───────────────────────────────────────────────────────
    // sshd_config.d/200-theyos.conf
    let sshd_conf_dir = mp.join("private/etc/ssh/sshd_config.d");
    std::fs::create_dir_all(&sshd_conf_dir)?;
    let conf_path = sshd_conf_dir.join("200-theyos.conf");
    std::fs::write(&conf_path, "PermitRootLogin yes\nStrictModes no\n")?;
    set_root_wheel(&conf_path, 0o644)?;
    manifest.file_written(&conf_path, mp, "644");

    // ── Direct authorized_keys ───────────────────────────────────────────
    let ssh_dir = mp.join("private/var/root/.ssh");
    std::fs::create_dir_all(&ssh_dir)?;
    set_root_wheel(&ssh_dir, 0o700)?;
    manifest.dir_written(&ssh_dir, mp, "700");
    let ak_path = ssh_dir.join("authorized_keys");
    std::fs::write(&ak_path, ssh_pubkey)?;
    set_root_wheel(&ak_path, 0o600)?;
    manifest.file_written(&ak_path, mp, "600");

    // ── SSH host keys ────────────────────────────────────────────────────
    let etc_ssh = mp.join("private/etc/ssh");
    std::fs::create_dir_all(&etc_ssh)?;

    let host_key_types: &[(&str, &str)] = &[("ed25519", ""), ("rsa", "4096"), ("ecdsa", "256")];
    for (ktype, bits) in host_key_types {
        let key_path = etc_ssh.join(format!("ssh_host_{ktype}_key"));
        if !key_path.exists() {
            let mut cmd = std::process::Command::new("ssh-keygen");
            cmd.args(["-t", ktype, "-f", key_path.to_str().unwrap_or("")]);
            if !bits.is_empty() {
                cmd.args(["-b", bits]);
            }
            cmd.args(["-N", "", "-q"]);
            let status = cmd.status()?;
            if status.success() {
                manifest.host_keys_generated.push(ktype.to_string());
                eprintln!("[provision-inject] Generated SSH host key: {ktype}");
            } else {
                manifest
                    .warnings
                    .push(format!("ssh-keygen -{ktype} failed"));
            }
        }
    }

    eprintln!("[provision-inject] All provision files written with root:wheel ownership");
    Ok(())
}

/// Set file ownership to root:wheel (UID 0, GID 0) and permissions.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn set_root_wheel(path: &std::path::Path, mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    // Set permissions
    std::fs::set_permissions(
        path,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(mode),
    )?;

    // Set ownership to root:wheel (0:0)
    let c_path = std::ffi::CString::new(path.to_str().unwrap_or(""))?;
    let ret = unsafe { libc::chown(c_path.as_ptr(), 0, 0) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("chown root:wheel {}: {err}", path.display()).into());
    }
    Ok(())
}

/// Extract first whole-disk device from hdiutil plist output for detach.
#[cfg(target_os = "macos")]
fn extract_base_disk(plist_output: &str) -> Option<String> {
    plist_output.lines().find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix("<string>/dev/disk")?;
        let suffix = rest.strip_suffix("</string>")?;
        if suffix.chars().all(|c| c.is_ascii_digit()) {
            Some(format!("/dev/disk{suffix}"))
        } else {
            None
        }
    })
}

/// Detach disk with retry (3 attempts, 2s intervals, force on failure).
#[cfg(target_os = "macos")]
fn detach_with_retry(base_disk: &str) {
    use std::process::Command;

    for attempt in 1..=3u8 {
        let result = Command::new("hdiutil").args(["detach", base_disk]).output();
        match result {
            Ok(o) if o.status.success() => return,
            Ok(o) => {
                eprintln!(
                    "[provision-inject] detach attempt {attempt}: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
            Err(e) => {
                eprintln!("[provision-inject] detach attempt {attempt}: {e}");
            }
        }
        if attempt < 3 {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }
    eprintln!("[provision-inject] Normal detach failed, forcing...");
    let _ = Command::new("hdiutil")
        .args(["detach", "-force", base_disk])
        .output();
}

/// Parse `--key value` from args.
#[cfg(target_os = "macos")]
fn arg_value(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

// ── Manifest ─────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
#[derive(Default, serde::Serialize)]
struct Manifest {
    ok: bool,
    disk: String,
    mount_point: String,
    files_written: Vec<FileEntry>,
    host_keys_generated: Vec<String>,
    warnings: Vec<String>,
}

#[cfg(target_os = "macos")]
#[derive(serde::Serialize)]
struct FileEntry {
    path: String,
    mode: String,
    owner: String,
    /// `"file"` or `"dir"` — verification needs both, mode semantics differ.
    kind: String,
}

#[cfg(target_os = "macos")]
impl Manifest {
    fn file_written(
        &mut self,
        full_path: &std::path::Path,
        mount_point: &std::path::Path,
        mode: &str,
    ) {
        self.entry(full_path, mount_point, mode, "file");
    }

    fn dir_written(
        &mut self,
        full_path: &std::path::Path,
        mount_point: &std::path::Path,
        mode: &str,
    ) {
        self.entry(full_path, mount_point, mode, "dir");
    }

    fn entry(
        &mut self,
        full_path: &std::path::Path,
        mount_point: &std::path::Path,
        mode: &str,
        kind: &str,
    ) {
        let rel = full_path.strip_prefix(mount_point).map_or_else(
            |_| full_path.display().to_string(),
            |p| p.display().to_string(),
        );
        self.files_written.push(FileEntry {
            path: rel,
            mode: mode.to_string(),
            owner: "root:wheel".to_string(),
            kind: kind.to_string(),
        });
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("theyos-provision-inject requires macOS");
    std::process::exit(1);
}
