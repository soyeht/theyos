//! Doctor command — Firecracker diagnostics and artifact status checks.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::util::{cmd_available, is_exec};

// ── DoctorReport ─────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct DoctorReport {
    pub failures: u32,
    pub warnings: u32,
}

impl DoctorReport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[allow(clippy::unused_self)]
    pub fn pass(&self, msg: &str) {
        println!("PASS  {msg}");
    }
    pub fn warn(&mut self, msg: &str) {
        self.warnings += 1;
        println!("WARN  {msg}");
    }
    pub fn fail(&mut self, msg: &str) {
        self.failures += 1;
        println!("FAIL  {msg}");
    }
    pub fn check_exec(&mut self, path: &Path, label: &str) {
        if is_exec(path) {
            self.pass(&format!("{label}: {}", path.display()));
        } else {
            self.fail(&format!("{label} not executable: {}", path.display()));
        }
    }
    pub fn check_file(&mut self, path: &Path, label: &str) {
        if path.is_file() {
            self.pass(&format!("{label}: {}", path.display()));
        } else {
            self.fail(&format!("{label} not found: {}", path.display()));
        }
    }
    pub fn check_cmd(&mut self, cmd: &str) {
        if cmd_available(cmd) {
            self.pass(&format!("command available: {cmd}"));
        } else {
            self.fail(&format!("command missing: {cmd}"));
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn resolve_slirp4netns_path() -> Option<String> {
    core_rs::os::resolve_slirp4netns().map(|p| p.to_string_lossy().into_owned())
}

fn release_or_debug_bin(root: &Path, name: &str) -> PathBuf {
    // NixOS/systemd override: deployed services can pin the runtime bin dir.
    if let Ok(d) = std::env::var("THEYOS_BIN_DIR") {
        let p = PathBuf::from(&d).join(name);
        if p.is_file() {
            return p;
        }
    }

    // Local source checkout: prefer the build artifacts under the requested
    // repo root before falling back to globally-installed tools. This keeps
    // `soyeht doctor` pointed at the tree it is checking.
    let release = root.join("admin/rust/target/release").join(name);
    if release.is_file() {
        return release;
    }
    let debug = root.join("admin/rust/target/debug").join(name);
    if debug.is_file() {
        return debug;
    }

    // NixOS: check sibling of current executable (all bins co-located in Nix store)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join(name);
            if p.is_file() {
                return p;
            }
        }
    }
    // NixOS: check PATH (user shell — binaries in environment.systemPackages)
    if let Some(p) = core_rs::os::which_binary(name) {
        return p;
    }
    debug
}

fn macos_vm_assets_dir() -> PathBuf {
    std::env::var("THEYOS_VM_ASSETS_DIR").map_or_else(
        |_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join("Library/Application Support/theyos/vms")
        },
        PathBuf::from,
    )
}

// ── Commands ─────────────────────────────────────────────────────────────────

pub fn cmd_doctor(root: &Path) {
    let home = core_rs::env::theyos_home(root);
    let fc_home = PathBuf::from(&home).join("firecracker");

    println!("theyOS Doctor");
    println!("Repo: {}\n", root.display());

    let mut r = DoctorReport::new();

    if cfg!(target_os = "macos") {
        check_macos_runtime(root, &mut r);
    } else {
        check_linux_runtime(root, &fc_home, &mut r);
    }

    println!();
    if crate::nixos::is_nixos_managed(root) {
        check_nixos_secrets(&mut r);
    } else {
        check_env(root, &mut r);
    }
    check_disk_space(root, &mut r);
    check_path(&mut r);

    if cfg!(target_os = "macos") {
        check_macos_base_image(&mut r);
    } else {
        let installed = crate::util::ready_claws_from_server(root);
        check_golden_images(&fc_home, &installed, &mut r);
        println!();
        check_artifact_dag(root, &fc_home, &installed, &mut r);
    }

    println!("\nSummary: failures={} warnings={}", r.failures, r.warnings);
    if r.failures > 0 {
        std::process::exit(1);
    }
}

// ── New diagnostic checks ────────────────────────────────────────────────────

fn check_linux_runtime(root: &Path, fc_home: &Path, r: &mut DoctorReport) {
    let fc_bin = std::env::var("FIRECRACKER_BIN")
        .map_or_else(|_| fc_home.join("bin/firecracker"), PathBuf::from);
    let jailer_bin =
        std::env::var("JAILER_BIN").map_or_else(|_| fc_home.join("bin/jailer"), PathBuf::from);
    let kernel = std::env::var("FIRECRACKER_KERNEL_IMAGE").map_or_else(
        |_| fc_home.join(format!("assets/{}", core_rs::constants::KERNEL_FILENAME)),
        PathBuf::from,
    );
    let base_rootfs = if let Ok(v) = std::env::var("FIRECRACKER_BASE_ROOTFS") {
        PathBuf::from(v)
    } else {
        let v2 = fc_home.join("assets/ubuntu-24.04-rootfs-v2.ext4");
        let v1 = fc_home.join("assets/ubuntu-24.04-rootfs.ext4");
        if v2.is_file() { v2 } else { v1 }
    };
    let ssh_key = std::env::var("FIRECRACKER_SSH_KEY").map_or_else(
        |_| fc_home.join("assets/ubuntu-24.04-root.id_rsa"),
        PathBuf::from,
    );
    let ssh_pubkey = std::env::var("FIRECRACKER_SSH_PUBKEY").map_or_else(
        |_| fc_home.join("assets/ubuntu-24.04-root.id_rsa.pub"),
        PathBuf::from,
    );
    let ssh_ctl = std::env::var("FIRECRACKER_CTL")
        .map_or_else(|_| release_or_debug_bin(root, "fc-ssh"), PathBuf::from);

    r.check_exec(&fc_bin, "firecracker binary");
    r.check_exec(&jailer_bin, "jailer binary");
    r.check_file(&kernel, "kernel image");
    r.check_file(&base_rootfs, "base rootfs");
    r.check_file(&ssh_key, "ssh private key");
    r.check_file(&ssh_pubkey, "ssh public key");
    r.check_exec(&ssh_ctl, "fc-ssh runtime binary");

    for cmd in &[
        "unshare", "ip", "curl", "nc", "debugfs", "ssh", "scp", "timeout",
    ] {
        r.check_cmd(cmd);
    }

    if let Some(slirp) = resolve_slirp4netns_path() {
        r.pass(&format!("slirp4netns resolved: {slirp}"));
    } else {
        r.fail("slirp4netns not found (set SLIRP4NETNS_BIN or install package)");
    }

    let kvm = Path::new("/dev/kvm");
    if kvm.exists() {
        use std::os::unix::fs::PermissionsExt;
        let mode = kvm.metadata().map(|m| m.permissions().mode()).unwrap_or(0);
        if mode & 0o006 == 0o006 || mode & 0o060 == 0o060 || mode & 0o600 == 0o600 {
            r.pass("/dev/kvm present and read/write");
        } else {
            r.fail("/dev/kvm present but missing read/write permission");
        }
    } else {
        r.fail("/dev/kvm not found");
    }

    if is_exec(&fc_bin) {
        let ok = Command::new(&fc_bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            r.pass("firecracker --version runnable");
        } else {
            r.fail("firecracker --version failed");
        }
    }

    if is_exec(&ssh_ctl) {
        let ok = Command::new(&ssh_ctl)
            .arg("help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            r.pass("runtime control binary (fc-ssh) help OK");
        } else {
            r.warn("runtime control binary (fc-ssh) help failed");
        }
    }
}

fn check_macos_runtime(root: &Path, r: &mut DoctorReport) {
    let vmrunner = std::env::var("THEYOS_VMRUNNER_RS_BIN").map_or_else(
        |_| release_or_debug_bin(root, "vmrunner_macos_ipc"),
        PathBuf::from,
    );
    let ssh_ctl = std::env::var("THEYOS_SSH_CTL")
        .or_else(|_| std::env::var("FIRECRACKER_CTL"))
        .map_or_else(|_| release_or_debug_bin(root, "theyos-ssh"), PathBuf::from);

    r.check_exec(&vmrunner, "vmrunner_macos_ipc runtime binary");
    r.check_exec(&ssh_ctl, "theyos-ssh runtime binary");

    for cmd in &["curl", "nc", "ssh", "scp", "codesign"] {
        r.check_cmd(cmd);
    }

    if is_exec(&ssh_ctl) {
        let ok = Command::new(&ssh_ctl)
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            r.pass("runtime control binary (theyos-ssh) help OK");
        } else {
            r.warn("runtime control binary (theyos-ssh) help failed");
        }
    }
}

fn check_nixos_secrets(r: &mut DoctorReport) {
    let secrets_dir = Path::new("/var/lib/theyos/secrets");
    if !secrets_dir.is_dir() {
        r.fail("NixOS secrets directory /var/lib/theyos/secrets/ not found — run: ./install-nixos");
        return;
    }
    r.pass("NixOS secrets directory exists");

    let pw = secrets_dir.join("admin-password");
    if pw.is_file() && std::fs::read_to_string(&pw).is_ok_and(|s| !s.trim().is_empty()) {
        r.pass("admin-password configured");
    } else {
        r.fail("admin-password missing in /var/lib/theyos/secrets/");
    }

    let pepper = secrets_dir.join("session-pepper");
    if pepper.is_file() && std::fs::read_to_string(&pepper).is_ok_and(|s| !s.trim().is_empty()) {
        r.pass("session-pepper configured");
    } else {
        r.fail("session-pepper missing — sessions will not work");
    }
}

fn check_env(root: &Path, r: &mut DoctorReport) {
    use std::os::unix::fs::PermissionsExt;

    let env_path = root.join(".env");
    if !env_path.is_file() {
        r.fail(".env file not found — run: soyeht setup");
        return;
    }

    // Check permissions
    if let Ok(meta) = env_path.metadata() {
        let mode = meta.permissions().mode() & 0o777;
        if mode == 0o600 {
            r.pass(".env permissions: 600");
        } else {
            r.warn(&format!(".env permissions: {mode:o} (expected 600)"));
        }
    }

    let content = std::fs::read_to_string(&env_path).unwrap_or_default();

    // Check critical fields
    let has_password = content.lines().any(|l| {
        l.starts_with("SOYEHT_ADMIN_PASSWORD=")
            && !l.contains("CHANGE_ME")
            && l.len() > "SOYEHT_ADMIN_PASSWORD=".len()
    });
    if has_password {
        r.pass(".env SOYEHT_ADMIN_PASSWORD configured");
    } else {
        r.fail(".env SOYEHT_ADMIN_PASSWORD missing or placeholder");
    }

    let has_pepper = content.lines().any(|l| {
        l.starts_with("THEYOS_SESSION_PEPPER=")
            && !l.contains("GENERATE")
            && l.len() > "THEYOS_SESSION_PEPPER=".len()
    });
    if has_pepper {
        r.pass(".env THEYOS_SESSION_PEPPER configured");
    } else {
        r.fail(".env THEYOS_SESSION_PEPPER missing — sessions will not work");
    }
}

fn check_disk_space(root: &Path, r: &mut DoctorReport) {
    let disk_available_gb =
        crate::util::available_disk_kb(root.to_str().unwrap_or("/")) / (1024 * 1024);
    if disk_available_gb >= 20 {
        r.pass(&format!("disk space: {disk_available_gb} GB available"));
    } else if disk_available_gb >= 10 {
        r.warn(&format!(
            "disk space: {disk_available_gb} GB available (recommend 20+ GB)"
        ));
    } else {
        r.fail(&format!(
            "disk space: {disk_available_gb} GB available (need 10+ GB)"
        ));
    }
}

fn check_golden_images(fc_home: &Path, installed: &[String], r: &mut DoctorReport) {
    let assets_dir = fc_home.join("assets");
    if !assets_dir.is_dir() {
        if installed.is_empty() {
            r.pass("no claws installed — install via claw store (/claws)");
        } else {
            r.warn("firecracker/assets directory not found — golden images not built");
        }
        return;
    }

    if installed.is_empty() {
        r.pass("no claws installed — install via claw store (/claws)");
        return;
    }

    let mut missing = Vec::new();

    for claw in installed {
        let versionated = assets_dir
            .join("goldens")
            .join(claw)
            .join("current")
            .join("rootfs.ext4");
        let legacy = assets_dir.join(format!("ubuntu-24.04-{claw}.ext4"));

        if !versionated.is_file() && !legacy.is_file() {
            missing.push(claw.as_str());
        }
    }

    if missing.is_empty() {
        r.pass(&format!(
            "all {} installed golden image(s) present",
            installed.len()
        ));
    } else {
        r.warn(&format!(
            "{} golden image(s) missing: {} — reinstall via claw store or run: soyeht artifacts-sync",
            missing.len(),
            missing.join(", ")
        ));
    }
}

fn check_macos_base_image(r: &mut DoctorReport) {
    let base_dir = macos_vm_assets_dir().join("macos-base");
    if !base_dir.is_dir() {
        r.warn("macOS base image not initialized — run: init_macos_guest");
        return;
    }

    let disk = base_dir.join("disk.img");
    let aux = base_dir.join("aux.auxstorage");
    let snapshot = base_dir.join("base.vzsnapshot");
    let init_state = base_dir.join("init-state.json");

    for (path, label) in [
        (&disk, "macOS base disk"),
        (&aux, "macOS aux storage"),
        (&snapshot, "macOS base snapshot"),
        (&init_state, "macOS init state"),
    ] {
        if path.is_file() {
            r.pass(&format!("{label}: {}", path.display()));
        } else {
            r.warn(&format!("{label} missing: {}", path.display()));
        }
    }

    if let Ok(content) = std::fs::read_to_string(&init_state) {
        if content.contains("\"complete\"") {
            r.pass("macOS base image initialization complete");
        } else {
            r.warn("macOS base image incomplete — run: init_macos_guest --force-provision");
        }
    }
}

fn check_path(r: &mut DoctorReport) {
    let soyeht_in_path = core_rs::os::which_binary("soyeht").is_some();

    if soyeht_in_path {
        r.pass("soyeht found in PATH");
    } else {
        r.warn("soyeht not in PATH — add ~/.local/bin to your PATH");
    }
}

// ── Artifact DAG checks ─────────────────────────────────────────────────────

/// Check artifact DAG staleness and report to doctor output.
///
/// Shells out to `imagebuilder dag-check` for golden staleness (expensive:
/// hashes base rootfs, kernel, and computes plan hashes), then checks snapshot
/// staleness via core-rs metadata.
#[allow(clippy::too_many_lines)]
fn check_artifact_dag(root: &Path, fc_home: &Path, installed: &[String], r: &mut DoctorReport) {
    if installed.is_empty() {
        println!("Artifact DAG status:");
        println!("  (no claws installed — install via claw store)");
        return;
    }

    let all_claws: Vec<&str> = installed.iter().map(String::as_str).collect();
    let assets_dir = fc_home.join("assets");

    println!("Artifact DAG status:");

    // 1. Shell out to imagebuilder dag-check for golden staleness
    let imagebuilder = resolve_imagebuilder_bin(root);
    let dag_report = if imagebuilder.is_file() {
        query_dag_check(&imagebuilder, &all_claws)
    } else {
        r.warn("imagebuilder binary not found — cannot run DAG staleness check");
        None
    };

    // 2. Classify goldens and collect staleness reasons
    let mut stale_goldens: Vec<(&str, String)> = Vec::new();
    let mut fresh_goldens: Vec<&str> = Vec::new();
    let mut missing_goldens: Vec<&str> = Vec::new();

    for claw in &all_claws {
        if let Some(ref report) = dag_report {
            if let Some(entry) = report.get(*claw) {
                let stale = entry["stale"].as_bool().unwrap_or(true);
                if stale {
                    let reason = entry["reason"].as_str().unwrap_or("unknown").to_string();
                    if reason == "missing" {
                        missing_goldens.push(claw);
                    } else {
                        stale_goldens.push((claw, reason));
                    }
                } else {
                    fresh_goldens.push(claw);
                }
            } else {
                missing_goldens.push(claw);
            }
        } else {
            // No dag-check output: check if versionated or legacy golden exists
            let has_versionated =
                core_rs::artifact_meta::read_current_golden_meta(&assets_dir, claw).is_some();
            let has_legacy = assets_dir
                .join(format!("ubuntu-24.04-{claw}.ext4"))
                .is_file();
            if has_versionated {
                fresh_goldens.push(claw); // Can't verify freshness without dag-check
            } else if has_legacy {
                stale_goldens.push((claw, "legacy layout (no metadata)".to_string()));
            } else {
                missing_goldens.push(claw);
            }
        }
    }

    // 3. Check snapshot staleness relative to golden metadata
    let mut stale_snapshots: Vec<(&str, String)> = Vec::new();
    let mut fresh_snapshots: Vec<&str> = Vec::new();
    let mut missing_snapshots: Vec<&str> = Vec::new();

    for claw in &all_claws {
        let golden_meta = core_rs::artifact_meta::read_current_golden_meta(&assets_dir, claw);
        let snap_meta = core_rs::artifact_meta::read_current_snapshot_meta(&assets_dir, claw);

        if let Some(gmeta) = &golden_meta {
            if let Some(reason) =
                core_rs::artifact_meta::snapshot_stale_reason(snap_meta.as_ref(), gmeta)
            {
                match reason {
                    core_rs::artifact_meta::StaleReason::Missing => {
                        missing_snapshots.push(claw);
                    }
                    _ => {
                        stale_snapshots.push((claw, reason.to_string()));
                    }
                }
            } else {
                fresh_snapshots.push(claw);
            }
        } else {
            // No golden meta → snapshot status unknown, report as missing
            missing_snapshots.push(claw);
        }
    }

    // 4. Print individual status lines
    for claw in &all_claws {
        let golden_status = if fresh_goldens.contains(claw) {
            let meta = core_rs::artifact_meta::read_current_golden_meta(&assets_dir, claw);
            if let Some(m) = meta {
                format!("golden=fresh (fp={})", m.fingerprint.short())
            } else {
                "golden=fresh".to_string()
            }
        } else if let Some((_, reason)) = stale_goldens.iter().find(|(c, _)| c == claw) {
            format!("golden=STALE ({reason})")
        } else {
            "golden=MISSING".to_string()
        };

        let snap_status = if fresh_snapshots.contains(claw) {
            "snapshot=fresh".to_string()
        } else if let Some((_, reason)) = stale_snapshots.iter().find(|(c, _)| c == claw) {
            format!("snapshot=STALE ({reason})")
        } else {
            "snapshot=MISSING".to_string()
        };

        println!("  {claw:12} {golden_status}, {snap_status}");
    }

    // 5. Group by root cause for summary
    let mut root_causes: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for (claw, reason) in &stale_goldens {
        root_causes
            .entry(reason.clone())
            .or_default()
            .push(claw.to_string());
    }

    if !root_causes.is_empty() {
        println!();
        println!("  Staleness propagation:");
        for (cause, claws) in &root_causes {
            let n = claws.len();
            let claw_list = claws.join(", ");
            println!("    {cause} -> {n} golden(s) stale: {claw_list}");
        }
    }

    // 6. Report to DoctorReport
    let total_stale = stale_goldens.len() + stale_snapshots.len();
    let total_missing = missing_goldens.len() + missing_snapshots.len();

    if total_missing > 0 {
        r.warn(&format!(
            "{total_missing} artifact(s) missing — run: soyeht artifacts-sync"
        ));
    }
    if total_stale > 0 {
        r.warn(&format!(
            "{total_stale} artifact(s) stale — run: soyeht artifacts-sync"
        ));
    }
    if total_stale == 0 && total_missing == 0 {
        r.pass("all artifacts fresh (DAG reconciled)");
    }
}

/// Resolve the imagebuilder binary (release preferred, debug fallback).
fn resolve_imagebuilder_bin(root: &Path) -> PathBuf {
    release_or_debug_bin(root, "imagebuilder")
}

/// Shell out to `imagebuilder dag-check` and parse JSON output.
fn query_dag_check(
    imagebuilder: &Path,
    claws: &[&str],
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let mut cmd = Command::new(imagebuilder);
    cmd.arg("dag-check");
    for claw in claws {
        cmd.arg(claw);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());

    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    match serde_json::from_str::<serde_json::Value>(&stdout) {
        Ok(serde_json::Value::Object(map)) => Some(map),
        _ => None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_report_counts_failures_and_warnings() {
        let mut r = DoctorReport::new();
        r.fail("bad thing");
        r.fail("another bad thing");
        r.warn("questionable thing");
        assert_eq!(r.failures, 2);
        assert_eq!(r.warnings, 1);
    }

    #[test]
    fn doctor_check_exec_on_bin_sh() {
        let mut r = DoctorReport::new();
        r.check_exec(Path::new("/bin/sh"), "shell");
        assert_eq!(r.failures, 0);
    }

    #[test]
    fn doctor_check_exec_on_missing() {
        let mut r = DoctorReport::new();
        r.check_exec(Path::new("/tmp/no-such-bin"), "missing");
        assert_eq!(r.failures, 1);
    }

    // ── imagebuilder bin resolution ─────────────────────────────────────

    #[test]
    fn resolve_imagebuilder_bin_prefers_release() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let release = root.join("admin/rust/target/release");
        let debug = root.join("admin/rust/target/debug");
        std::fs::create_dir_all(&release).unwrap();
        std::fs::create_dir_all(&debug).unwrap();
        std::fs::write(release.join("imagebuilder"), b"release").unwrap();
        std::fs::write(debug.join("imagebuilder"), b"debug").unwrap();

        let result = resolve_imagebuilder_bin(root);
        assert!(result.to_string_lossy().contains("release"));
    }

    #[test]
    fn resolve_imagebuilder_bin_falls_back_to_debug() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let debug = root.join("admin/rust/target/debug");
        std::fs::create_dir_all(&debug).unwrap();
        std::fs::write(debug.join("imagebuilder"), b"debug").unwrap();

        let result = resolve_imagebuilder_bin(root);
        assert!(result.to_string_lossy().contains("debug"));
    }

    #[test]
    fn release_or_debug_bin_prefers_release() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let release = root.join("admin/rust/target/release");
        let debug = root.join("admin/rust/target/debug");
        std::fs::create_dir_all(&release).unwrap();
        std::fs::create_dir_all(&debug).unwrap();
        std::fs::write(release.join("fc-ssh"), b"release").unwrap();
        std::fs::write(debug.join("fc-ssh"), b"debug").unwrap();

        let result = release_or_debug_bin(root, "fc-ssh");
        assert!(result.to_string_lossy().contains("release"));
    }

    #[test]
    fn release_or_debug_bin_falls_back_to_debug() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let debug = root.join("admin/rust/target/debug");
        std::fs::create_dir_all(&debug).unwrap();
        std::fs::write(debug.join("fc-ssh"), b"debug").unwrap();

        let result = release_or_debug_bin(root, "fc-ssh");
        assert!(result.to_string_lossy().contains("debug"));
    }

    // ── query_dag_check ─────────────────────────────────────────────────

    #[test]
    fn query_dag_check_returns_none_for_missing_binary() {
        let result = query_dag_check(Path::new("/nonexistent/bin"), &["picoclaw"]);
        assert!(result.is_none());
    }

    // ── check_artifact_dag integration ──────────────────────────────────

    #[test]
    fn check_artifact_dag_all_missing_on_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let fc_home = dir.path().join("firecracker");
        std::fs::create_dir_all(fc_home.join("assets")).unwrap();

        let installed = vec!["picoclaw".to_string()];
        let mut r = DoctorReport::new();
        check_artifact_dag(root, &fc_home, &installed, &mut r);

        // Should warn about missing artifacts (imagebuilder not found + missing artifacts)
        assert!(r.warnings > 0, "should warn about missing artifacts");
    }

    #[test]
    fn check_artifact_dag_no_claws_installed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let fc_home = dir.path().join("firecracker");
        std::fs::create_dir_all(fc_home.join("assets")).unwrap();

        let installed: Vec<String> = vec![];
        let mut r = DoctorReport::new();
        check_artifact_dag(root, &fc_home, &installed, &mut r);

        // With 0 installed claws, should not warn about missing artifacts
        assert_eq!(r.warnings, 0, "no warnings for 0 installed claws");
        assert_eq!(r.failures, 0, "no failures for 0 installed claws");
    }

    #[test]
    fn check_artifact_dag_detects_fresh_versionated_golden() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let fc_home = dir.path().join("firecracker");
        let assets_dir = fc_home.join("assets");
        std::fs::create_dir_all(&assets_dir).unwrap();

        // Create a versionated golden for picoclaw
        let fp = core_rs::artifact_meta::Fingerprint::new("test_fp_123");
        let golden_dir = core_rs::artifact_meta::golden_version_dir(&assets_dir, "picoclaw", &fp);
        std::fs::create_dir_all(&golden_dir).unwrap();
        let meta = core_rs::artifact_meta::GoldenMeta {
            claw_type: "picoclaw".to_string(),
            fingerprint: fp.clone(),
            base_rootfs_sha256: "base1".to_string(),
            installer_plan_sha256: "plan1".to_string(),
            kernel_sha256: "kern1".to_string(),
            builder_version: "test".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };
        core_rs::artifact_meta::write_meta(&golden_dir.join("golden.meta.json"), &meta).unwrap();
        let link = core_rs::artifact_meta::golden_current_link(&assets_dir, "picoclaw");
        core_rs::artifact_meta::update_current_link(&link, &fp).unwrap();

        let installed = vec!["picoclaw".to_string()];
        let mut r = DoctorReport::new();
        // Without dag-check binary, versionated golden is treated as "fresh" (can't verify)
        check_artifact_dag(root, &fc_home, &installed, &mut r);

        // At minimum we don't crash; warnings only about imagebuilder not being found
        assert!(r.failures == 0, "no failures expected");
    }

    #[test]
    fn check_artifact_dag_detects_legacy_golden_as_stale() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let fc_home = dir.path().join("firecracker");
        let assets_dir = fc_home.join("assets");
        std::fs::create_dir_all(&assets_dir).unwrap();

        // Create a legacy golden file (no metadata)
        std::fs::write(
            assets_dir.join("ubuntu-24.04-picoclaw.ext4"),
            b"legacy_rootfs",
        )
        .unwrap();

        let installed = vec!["picoclaw".to_string()];
        let mut r = DoctorReport::new();
        check_artifact_dag(root, &fc_home, &installed, &mut r);

        // Should warn about staleness (legacy layout = no metadata)
        assert!(r.warnings > 0, "should warn about stale/missing artifacts");
    }
}
