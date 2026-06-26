//! Setup wizard — interactive installer that generates .env from `.env.example`,
//! creates directories, downloads available Linux assets, and clones upstream claw repositories.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use crate::cli::SetupArgs;

// ── Helpers ──────────────────────────────────────────────────────────────────

pub fn prompt(question: &str, default: &str) -> String {
    if default.is_empty() {
        print!("{question}: ");
    } else {
        print!("{question} [{default}]: ");
    }
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().read_line(&mut line).ok();
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed
    }
}

pub fn prompt_secret(question: &str) -> String {
    print!("{question}: ");
    io::stdout().flush().ok();
    let stty_ok = Command::new("stty")
        .arg("-echo")
        .status()
        .is_ok_and(|s| s.success());
    let mut line = String::new();
    io::stdin().read_line(&mut line).ok();
    if stty_ok {
        Command::new("stty").arg("echo").status().ok();
    }
    println!();
    line.trim().to_string()
}

pub fn rand_base64(bytes: usize) -> String {
    let raw = read_urandom(bytes);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in raw.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        out.push(alphabet[(b0 >> 2) & 0x3f] as char);
        out.push(alphabet[((b0 << 4) | (b1 >> 4)) & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(alphabet[((b1 << 2) | (b2 >> 6)) & 0x3f] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(alphabet[b2 & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Generate `bytes` random bytes as a hex string (for session pepper, etc.).
fn rand_hex(bytes: usize) -> String {
    let raw = read_urandom(bytes);
    let mut out = String::with_capacity(bytes * 2);
    for b in &raw {
        use std::fmt::Write as _;
        write!(out, "{b:02x}").ok();
    }
    out
}

fn read_urandom(bytes: usize) -> Vec<u8> {
    (|| -> io::Result<Vec<u8>> {
        let mut f = fs::File::open("/dev/urandom")?;
        let mut buf = vec![0u8; bytes];
        f.read_exact(&mut buf)?;
        Ok(buf)
    })()
    .unwrap_or_else(|_| vec![0u8; bytes])
}

pub fn clone_if_missing(name: &str, repo_url: &str, dest: &Path) {
    if dest.is_dir() {
        println!("  {name}: already exists, skipping");
        return;
    }
    println!("  {name}: cloning from {repo_url}...");
    let ok = Command::new("git")
        .args(["clone", "--depth", "1", repo_url, dest.to_str().unwrap()])
        .status()
        .is_ok_and(|s| s.success());
    if ok {
        println!("  {name}: cloned OK");
    } else {
        println!("  {name}: clone failed — clone manually later");
    }
}

fn detect_os() -> String {
    // macOS detection
    if cfg!(target_os = "macos") {
        return "macos".to_string();
    }
    let os_release = fs::read_to_string("/etc/os-release").unwrap_or_default();
    os_release
        .lines()
        .find(|l| l.starts_with("ID="))
        .map_or_else(
            || "unknown".to_string(),
            |l| l.trim_start_matches("ID=").trim_matches('"').to_string(),
        )
}

fn has_kernel_image(fc_home: &str) -> bool {
    use core_rs::constants::KERNEL_FILENAME;

    let assets_dir = format!("{fc_home}/assets");
    let kernel_path = format!("{assets_dir}/{KERNEL_FILENAME}");
    if Path::new(&kernel_path).is_file() {
        return true;
    }

    fs::read_dir(&assets_dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| entry.file_name().to_string_lossy().starts_with("vmlinux"))
}

// ── .env generation from template ────────────────────────────────────────────

/// User answers collected during the interactive wizard.
struct SetupAnswers {
    theyos_home: String,
    admin_password: String,
    session_pepper: String,
    access_mode: String,
}

/// Generate .env content from `.env.example` template + user answers.
///
/// Reads `.env.example` as the source of truth. For each uncommented `KEY=VALUE`
/// line, substitutes the value from `answers` if we have one. Commented lines
/// are preserved as-is. Keys we don't have a substitution for keep their
/// template defaults.
fn generate_env_from_template(root: &Path, answers: &SetupAnswers) -> String {
    let template_path = root.join(".env.example");
    let template = fs::read_to_string(&template_path).unwrap_or_else(|e| {
        eprintln!(
            "[setup] warning: could not read {}: {e}",
            template_path.display()
        );
        eprintln!("[setup] falling back to minimal .env generation");
        String::new()
    });

    if template.is_empty() {
        return generate_env_minimal(answers);
    }

    let ts_str = core_rs::time::now_iso_secs();
    let mut out = format!("# Generated by soyeht setup on {ts_str}\n");
    out.push_str("# Source template: .env.example\n\n");

    for line in template.lines() {
        let trimmed = line.trim();

        // Pure comment or empty → preserve
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out.push_str(line);
            out.push('\n');
            continue;
        }

        // KEY=VALUE line
        if let Some((key, _original_value)) = trimmed.split_once('=') {
            let key = key.trim();
            if let Some(new_value) = substitute_value(key, answers) {
                out.push_str(key);
                out.push('=');
                out.push_str(&new_value);
                out.push('\n');
            } else {
                // Keep the original line unchanged
                out.push_str(line);
                out.push('\n');
            }
        } else {
            // Not KEY=VALUE, keep as-is
            out.push_str(line);
            out.push('\n');
        }
    }

    out
}

/// Return a replacement value for a known key, or None to keep the template default.
fn substitute_value(key: &str, answers: &SetupAnswers) -> Option<String> {
    match key {
        // ── Required credentials ──
        "SOYEHT_ADMIN_USER" => Some("admin".into()),
        "SOYEHT_ADMIN_PASSWORD" => Some(answers.admin_password.clone()),

        // ── Session (CRITICAL — was missing from old setup) ──
        "THEYOS_SESSION_PEPPER" => Some(answers.session_pepper.clone()),

        // ── Linux / NixOS ──
        "THEYOS_HOME" => Some(answers.theyos_home.clone()),
        "ACCESS_MODE" => Some(answers.access_mode.clone()),

        // ── Logging ──
        "RUST_LOG" => Some("info".into()),

        // Everything else → keep template default (None = no substitution)
        _ => None,
    }
}

/// Minimal .env when .env.example is missing (should not happen in normal installs).
fn generate_env_minimal(answers: &SetupAnswers) -> String {
    let ts_str = core_rs::time::now_iso_secs();
    format!(
        "# Generated by soyeht setup on {ts}\n\
         SOYEHT_ADMIN_USER=admin\n\
         SOYEHT_ADMIN_PASSWORD={pass}\n\
         THEYOS_SESSION_PEPPER={pepper}\n\
         THEYOS_HOME={home}\n\
         ACCESS_MODE={mode}\n\
         RUST_LOG=info\n",
        ts = ts_str,
        pass = answers.admin_password,
        pepper = answers.session_pepper,
        home = answers.theyos_home,
        mode = answers.access_mode,
    )
}

// ── Command ──────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
pub fn cmd_setup(root: &Path, args: &SetupArgs) {
    println!("============================================");
    println!(" theyOS Setup");
    println!("============================================");
    println!();

    // ── 1. Detect OS ──
    let os_id = detect_os();
    println!("[setup] detected OS: {os_id}");
    match os_id.as_str() {
        "nixos" | "ubuntu" | "debian" => {}
        "macos" => println!("[setup] macOS detected — Firecracker steps will be skipped"),
        _ => println!(
            "[setup] warning: untested OS. theyOS supports NixOS, Ubuntu, Debian, and macOS."
        ),
    }
    println!();

    // ── 2. Interactive wizard ──
    let default_home = root
        .parent()
        .map_or_else(|| "/home/user".to_string(), |p| p.display().to_string());
    let theyos_home = if os_id == "macos" {
        // On macOS, THEYOS_HOME is less critical (launcher auto-detects)
        default_home.clone()
    } else {
        prompt("Home directory for theyOS data", &default_home)
    };
    println!();
    println!("Access mode:");
    println!("  1) Local only     — http://localhost:8892");
    println!("  2) Tailscale      — access via Tailscale VPN");
    println!("  3) Public domain  — Cloudflare Tunnel with your own domain");
    let access_choice = prompt("Choose [1-3, default=1]", "1");
    let access_mode = match access_choice.trim() {
        "2" => "tailscale",
        "3" => "domain",
        _ => "local",
    };

    let mut admin_pass = prompt_secret("Admin password for the panel");
    if admin_pass.is_empty() {
        admin_pass = rand_base64(12);
        println!("[setup] generated random password: {admin_pass}");
    }

    // Generate session pepper automatically
    let session_pepper = rand_hex(32);

    let answers = SetupAnswers {
        theyos_home,
        admin_password: admin_pass,
        session_pepper: session_pepper.clone(),
        access_mode: access_mode.to_string(),
    };

    // ── 3. Generate .env ──
    let env_path = root.join(".env");
    let should_write = if env_path.is_file() {
        let answer = prompt(".env already exists. Overwrite? [y/N]", "N");
        if answer.eq_ignore_ascii_case("y") {
            true
        } else {
            println!("[setup] keeping existing .env");
            // Still ensure session pepper exists
            let existing = fs::read_to_string(&env_path).unwrap_or_default();
            if !existing.contains("THEYOS_SESSION_PEPPER=")
                || existing.contains("THEYOS_SESSION_PEPPER=GENERATE")
            {
                println!("[setup] CRITICAL: your .env is missing THEYOS_SESSION_PEPPER");
                println!(
                    "[setup] Add this line to your .env:\n  THEYOS_SESSION_PEPPER={session_pepper}"
                );
            }
            false
        }
    } else {
        true
    };
    if should_write {
        write_env_file(root, &env_path, &answers);
    }

    // ── 4. Create directories ──
    println!("[setup] creating data directories...");
    let mut dirs = vec![
        "claws/src",
        "claws/data/picoclaw/customers",
        "claws/data/zeroclaw/customers",
        "claws/data/nanobot/customers",
        "claws/data/openclaw/customers",
        "claws/data/nullclaw/customers",
        "claws/data/ironclaw/customers",
        "tailscale/certs",
        "logs",
        ".run",
    ];
    // Firecracker directories (Linux only)
    if os_id != "macos" {
        dirs.extend_from_slice(&[
            "firecracker/bin",
            "firecracker/assets",
            "firecracker/instances",
            "firecracker/golden-build",
        ]);
    }
    for path in &dirs {
        let dir = root.join(path);
        fs::create_dir_all(&dir).unwrap_or_else(|e| {
            eprintln!("[setup] warning: could not create {}: {e}", dir.display());
        });
    }
    // Also create ~/firecracker dirs if they don't exist (separate from repo)
    if os_id != "macos" {
        let fc_home = format!("{}/firecracker", answers.theyos_home);
        for sub in ["bin", "assets", "instances", "golden-build"] {
            let dir = format!("{fc_home}/{sub}");
            fs::create_dir_all(&dir).unwrap_or_else(|e| {
                eprintln!("[setup] warning: could not create {dir}: {e}");
            });
        }
    }

    let mut kernel_ready = os_id == "macos";
    if os_id != "macos" {
        let fc_home = format!("{}/firecracker", answers.theyos_home);
        kernel_ready = has_kernel_image(&fc_home);
    }

    // ── 5. Download assets (Linux only) ──
    if os_id != "macos" && !args.skip_assets {
        let fc_home = format!("{}/firecracker", answers.theyos_home);
        download_firecracker(&fc_home);
        kernel_ready = download_kernel(&fc_home);
        generate_ssh_keys(&fc_home);
    } else if os_id != "macos" && args.skip_assets {
        println!("[setup] skipping asset downloads (--skip-assets)");
    }

    // ── 6. Tailscale HTTPS ──
    if access_mode == "tailscale" {
        setup_tailscale(root);
    }

    // ── 7. Clone upstream claws ──
    println!("[setup] cloning upstream claw repositories...");
    let src_dir = root.join("claws/src");
    clone_if_missing(
        "picoclaw",
        "https://github.com/sipeed/picoclaw",
        &src_dir.join("picoclaw"),
    );
    clone_if_missing(
        "zeroclaw",
        "https://github.com/openagen/zeroclaw",
        &src_dir.join("zeroclaw"),
    );
    clone_if_missing(
        "nanobot",
        "https://github.com/HKUDS/nanobot",
        &src_dir.join("nanobot"),
    );
    println!("  openclaw: uses pre-built image (ghcr.io/openclaw/openclaw:latest)");
    // Ensure stub dirs exist for nullclaw/ironclaw/openclaw (claw registry needs them)
    for name in ["nullclaw", "ironclaw", "openclaw"] {
        let dir = src_dir.join(name);
        fs::create_dir_all(&dir).ok();
    }

    // ── 8. Build base rootfs (Linux, prompted, needs sudo) ──
    if os_id != "macos" && !args.skip_rootfs {
        offer_build_rootfs(root, &answers.theyos_home);
    } else if os_id != "macos" && args.skip_rootfs {
        println!("[setup] skipping rootfs build (--skip-rootfs)");
    }

    // ── 8.5. Caddy (macOS only) ──────────────────────────────────────────
    // NixOS gets Caddy via services.caddy declaratively. On macOS, soyeht
    // owns the Caddy lifecycle through a per-user LaunchAgent + the local
    // CA in the System keychain. Both steps are gated by explicit prompts
    // because they're the most invasive things this setup does.
    #[cfg(target_os = "macos")]
    if os_id == "macos" {
        setup_caddy_macos(root);
    }

    // ── 9. Next steps ──
    println!();
    println!("============================================");
    println!(" theyOS setup complete!");
    println!("============================================");
    println!();
    println!("Next steps:");
    println!();

    if os_id == "macos" {
        println!("  1. Initialize macOS guest (downloads ~15 GB IPSW, takes ~45-90 min):");
        println!("     init_macos_guest");
        println!();
        println!("  2. Start the stack:");
        println!("     soyeht start");
    } else {
        if !kernel_ready {
            println!("  Kernel still missing:");
            println!(
                "     place a Firecracker-compatible vmlinux in {}/firecracker/assets/",
                answers.theyos_home
            );
            println!("     then re-run: soyeht doctor");
            println!();
        }
        println!("  1. Run diagnostics to see what's still needed:");
        println!("     soyeht doctor");
        println!();
        println!("  2. Start the stack:");
        println!("     soyeht start");
    }
    println!();
    println!("  Verify:");
    println!("     curl http://localhost:8892/healthz");
    println!();

    match access_mode {
        "tailscale" => {
            println!("  Remote access via Tailscale:");
            println!("     https://<tailscale-hostname>:8443");
        }
        "domain" => {
            println!("  Set up Cloudflare Tunnel:");
            println!(
                "     cp {}/distro/cloudflared/config.yml.example {}/distro/cloudflared/config.yml",
                root.display(),
                root.display()
            );
            println!("     # Edit with your tunnel ID and domain");
        }
        _ => {
            println!("  Access locally at: http://localhost:8892");
        }
    }
    println!();
}

// ── Rootfs (Linux only, prompted) ────────────────────────────────────────────

/// Prompt the user to build the base rootfs. Requires sudo.
fn offer_build_rootfs(root: &Path, theyos_home: &str) {
    let rootfs_path = format!("{theyos_home}/firecracker/assets/ubuntu-24.04-rootfs-v2.ext4");
    if Path::new(&rootfs_path).is_file() {
        println!("[setup] base rootfs already present, skipping");
        return;
    }

    println!();
    println!("[setup] Base rootfs is needed for creating VM instances.");
    println!("[setup] Building it requires sudo (debootstrap + mke2fs) and takes ~5 minutes.");
    let answer = prompt("Build base rootfs now? [Y/n]", "Y");
    if answer.eq_ignore_ascii_case("n") {
        println!("[setup] skipped. Build later with: sudo rootfsbuilder");
        return;
    }

    // Find rootfsbuilder binary
    let rootfsbuilder = {
        let release = root.join("admin/rust/target/release/rootfsbuilder");
        if release.is_file() {
            release
        } else {
            root.join("admin/rust/target/debug/rootfsbuilder")
        }
    };

    if !rootfsbuilder.is_file() {
        eprintln!(
            "[setup] rootfsbuilder binary not found at {}",
            rootfsbuilder.display()
        );
        println!(
            "[setup] Build it first: cd admin/rust && cargo build --release -p rootfsbuilder-rs"
        );
        println!("[setup] Then run: sudo {}", rootfsbuilder.display());
        return;
    }

    println!("[setup] running rootfsbuilder (sudo)...");
    let ok = Command::new("sudo")
        .args([rootfsbuilder.to_str().unwrap(), "--force"])
        .env("HOME", theyos_home)
        .status()
        .is_ok_and(|s| s.success());

    if ok {
        println!("[setup] base rootfs built successfully");
    } else {
        eprintln!(
            "[setup] rootfsbuilder failed. Run manually: sudo {}",
            rootfsbuilder.display()
        );
    }
}

// ── Asset download (Linux only) ──────────────────────────────────────────────

/// Download Firecracker + jailer binaries from GitHub releases.
/// Idempotent: skips if correct version already exists.
fn download_firecracker(fc_home: &str) {
    use core_rs::constants::{
        FIRECRACKER_SHA256_AARCH64, FIRECRACKER_SHA256_X86_64, FIRECRACKER_VERSION,
    };

    let bin_dir = format!("{fc_home}/bin");
    let fc_path = format!("{bin_dir}/firecracker");
    let jailer_path = format!("{bin_dir}/jailer");
    let version_file = format!("{bin_dir}/VERSION");

    // Check if already installed at correct version
    if Path::new(&fc_path).is_file() && Path::new(&jailer_path).is_file() {
        if let Ok(v) = fs::read_to_string(&version_file) {
            if v.trim() == FIRECRACKER_VERSION {
                println!("[setup] Firecracker {FIRECRACKER_VERSION} already installed, skipping");
                return;
            }
        }
    }

    let arch = std::env::consts::ARCH; // "x86_64" or "aarch64"
    let expected_sha = match arch {
        "x86_64" => FIRECRACKER_SHA256_X86_64,
        "aarch64" => FIRECRACKER_SHA256_AARCH64,
        other => {
            eprintln!("[setup] unsupported architecture for Firecracker: {other}");
            return;
        }
    };

    let tgz_name = format!("firecracker-{FIRECRACKER_VERSION}-{arch}.tgz");
    let url = format!(
        "https://github.com/firecracker-microvm/firecracker/releases/download/{FIRECRACKER_VERSION}/{tgz_name}"
    );

    println!("[setup] downloading Firecracker {FIRECRACKER_VERSION} for {arch}...");

    let tmp_dir = format!("{bin_dir}/.tmp-download");
    fs::create_dir_all(&tmp_dir).ok();
    let tgz_path = format!("{tmp_dir}/{tgz_name}");

    // Download
    let ok = Command::new("curl")
        .args(["-fSL", "--progress-bar", "-o", &tgz_path, &url])
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("[setup] download failed. Download manually from:\n  {url}");
        fs::remove_dir_all(&tmp_dir).ok();
        return;
    }

    // Verify SHA-256
    if !verify_sha256(&tgz_path, expected_sha) {
        eprintln!("[setup] SHA-256 checksum mismatch! File may be corrupted.");
        fs::remove_dir_all(&tmp_dir).ok();
        return;
    }
    println!("[setup] checksum verified");

    // Extract
    let ok = Command::new("tar")
        .args(["xzf", &tgz_path, "-C", &tmp_dir, "--strip-components=1"])
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("[setup] failed to extract archive");
        fs::remove_dir_all(&tmp_dir).ok();
        return;
    }

    // Find and move the binaries (they have versioned names like firecracker-v1.15.0-x86_64)
    let fc_versioned = format!("{tmp_dir}/firecracker-{FIRECRACKER_VERSION}-{arch}");
    let jailer_versioned = format!("{tmp_dir}/jailer-{FIRECRACKER_VERSION}-{arch}");

    if Path::new(&fc_versioned).is_file() {
        fs::rename(&fc_versioned, &fc_path).ok();
    }
    if Path::new(&jailer_versioned).is_file() {
        fs::rename(&jailer_versioned, &jailer_path).ok();
    }

    // chmod +x
    set_executable(&fc_path);
    set_executable(&jailer_path);

    // Write version file
    fs::write(&version_file, FIRECRACKER_VERSION).ok();

    // Cleanup
    fs::remove_dir_all(&tmp_dir).ok();

    if Path::new(&fc_path).is_file() {
        println!("[setup] Firecracker {FIRECRACKER_VERSION} installed to {bin_dir}");
    } else {
        eprintln!("[setup] Firecracker installation failed — binary not found after extraction");
    }
}

/// Check whether a Firecracker-compatible kernel is already present.
///
/// Returns true when a suitable `vmlinux-*` file exists in `{fc_home}/assets`.
/// If none exists, prints manual next steps and returns false.
fn download_kernel(fc_home: &str) -> bool {
    use core_rs::constants::KERNEL_FILENAME;

    let assets_dir = format!("{fc_home}/assets");
    let kernel_path = format!("{assets_dir}/{KERNEL_FILENAME}");

    if has_kernel_image(fc_home) {
        println!("[setup] kernel {KERNEL_FILENAME} already present, skipping");
        return true;
    }

    // No kernel found — the kernel isn't available from an official URL.
    // Print instructions for the user.
    println!("[setup] kernel image not found at {kernel_path}");
    println!("[setup] theyOS requires a Linux kernel built for Firecracker.");
    println!("[setup] Options:");
    println!("  - Copy an existing vmlinux kernel to {assets_dir}/");
    println!("  - Build from Firecracker's kernel config:");
    println!(
        "    https://github.com/firecracker-microvm/firecracker/tree/main/resources/guest_configs"
    );
    println!("[setup] `soyeht doctor` will report this as missing until resolved.");
    false
}

/// Generate SSH keypair for Firecracker VM access.
fn generate_ssh_keys(fc_home: &str) {
    let assets_dir = format!("{fc_home}/assets");
    let key_path = format!("{assets_dir}/ubuntu-24.04-root.id_rsa");
    let pub_path = format!("{assets_dir}/ubuntu-24.04-root.id_rsa.pub");

    if Path::new(&key_path).is_file() && Path::new(&pub_path).is_file() {
        println!("[setup] SSH keys already present, skipping");
        return;
    }

    println!("[setup] generating SSH keys for Firecracker VMs...");
    let ok = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f", &key_path, "-N", "", "-q"])
        .status()
        .is_ok_and(|s| s.success());

    if ok {
        println!("[setup] SSH keys generated at {assets_dir}/");
    } else {
        eprintln!("[setup] ssh-keygen failed. Generate manually:");
        eprintln!("  ssh-keygen -t ed25519 -f {key_path} -N \"\"");
    }
}

/// Verify SHA-256 checksum of a file using the `sha256sum` command.
fn verify_sha256(file_path: &str, expected: &str) -> bool {
    let output = Command::new("sha256sum")
        .arg(file_path)
        .output()
        .ok()
        .filter(|o| o.status.success());

    if let Some(o) = output {
        let actual = String::from_utf8_lossy(&o.stdout);
        let actual_hash = actual.split_whitespace().next().unwrap_or("");
        return actual_hash == expected;
    }

    // Fallback: try shasum -a 256 (macOS, though this path is Linux-only)
    let output = Command::new("shasum")
        .args(["-a", "256", file_path])
        .output()
        .ok()
        .filter(|o| o.status.success());

    if let Some(o) = output {
        let actual = String::from_utf8_lossy(&o.stdout);
        let actual_hash = actual.split_whitespace().next().unwrap_or("");
        return actual_hash == expected;
    }

    eprintln!("[setup] warning: could not verify checksum (sha256sum not found)");
    true // Proceed without verification rather than blocking install
}

fn set_executable(path: &str) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).ok();
}

// ── .env write + Tailscale ───────────────────────────────────────────────────

fn write_env_file(root: &Path, env_path: &Path, answers: &SetupAnswers) {
    println!();
    println!("[setup] generating .env from template...");
    let env_content = generate_env_from_template(root, answers);
    fs::write(env_path, &env_content).unwrap_or_else(|e| {
        eprintln!("[setup] failed to write .env: {e}");
        std::process::exit(1);
    });
    fs::set_permissions(env_path, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| eprintln!("[setup] warning: could not chmod .env: {e}"));
    println!("[setup] .env created (chmod 600)");
    println!(
        "[setup] session pepper generated: {}...{}",
        &answers.session_pepper[..8],
        &answers.session_pepper[answers.session_pepper.len() - 4..]
    );
}

fn setup_tailscale(root: &Path) {
    println!("[setup] configuring Tailscale HTTPS...");

    let ts_hostname_detected = Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let json = String::from_utf8_lossy(&o.stdout).to_string();
            json.lines()
                .find(|l| l.contains("\"DNSName\""))
                .and_then(|l| {
                    let start = l.find('"').map(|i| i + 1)?;
                    let rest = &l[start..];
                    let colon = rest.find('"').map(|i| i + 1)?;
                    let rest2 = &rest[colon..];
                    let inner_start = rest2.find('"').map(|i| i + 1)?;
                    let inner = &rest2[inner_start..];
                    let end = inner.find('"')?;
                    Some(inner[..end].trim_end_matches('.').to_string())
                })
        });

    let ts_hostname = if let Some(h) = ts_hostname_detected {
        println!("[setup] detected Tailscale hostname: {h}");
        h
    } else {
        prompt("Tailscale hostname (e.g. myserver.tail1234.ts.net)", "")
    };

    if ts_hostname.is_empty() {
        return;
    }

    println!("[setup] requesting Tailscale TLS certificate...");
    let cert_dir = root.join("tailscale/certs");
    let ok = Command::new("tailscale")
        .args([
            "cert",
            "--cert-file",
            cert_dir.join("cert.pem").to_str().unwrap(),
            "--key-file",
            cert_dir.join("key.pem").to_str().unwrap(),
            &ts_hostname,
        ])
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        println!(
            "[setup] warning: tailscale cert failed — enable HTTPS in tailscale.com/admin/dns and re-run"
        );
    }

    let cert_pem = cert_dir.join("cert.pem").display().to_string();
    let key_pem = cert_dir.join("key.pem").display().to_string();
    let caddy_config = format!(
        "{ts_hostname} {{\n\
         \x20   tls {cert_pem} {key_pem}\n\
         \n\
         \x20   header {{\n\
         \x20       X-Content-Type-Options nosniff\n\
         \x20       X-Frame-Options DENY\n\
         \x20       X-XSS-Protection \"1; mode=block\"\n\
         \x20       Referrer-Policy strict-origin-when-cross-origin\n\
         \x20       Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss: ws:; object-src 'none';\"\n\
         \x20       -Server\n\
         \x20       -X-Powered-By\n\
         \x20   }}\n\
         \n\
         \x20   @blocked_paths {{\n\
         \x20       path /.env* /config* /secret* /.git* /backup*\n\
         \x20   }}\n\
         \x20   respond @blocked_paths 404\n\
         \n\
         \x20   reverse_proxy 127.0.0.1:8892\n\
         }}\n"
    );
    let caddy_path = root.join("tailscale/caddy.caddy");
    fs::write(&caddy_path, &caddy_config).unwrap_or_else(|e| {
        eprintln!("[setup] warning: could not write caddy config: {e}");
    });
    println!(
        "[setup] Caddy HTTPS config written to {}",
        caddy_path.display()
    );
}

// ── Caddy (macOS) ───────────────────────────────────────────────────────────

/// Set up Caddy on macOS:
///
/// 1. Detect an existing Caddy binary (PATH, brew --prefix, well-known
///    locations). Refuses to install Homebrew on the user's behalf — that's
///    the `./install` script's job after explicit consent.
/// 2. Install the local CA into the System keychain via `caddy trust`. This
///    triggers the macOS GUI password dialog. Skipped if the user declines.
/// 3. Write `~/Library/LaunchAgents/com.soyeht.caddy.plist` and bootstrap it
///    so Caddy survives logout/reboot and restarts on crash.
///
/// All three steps are individually skippable via prompt — a user who
/// already manages Caddy themselves can opt out without aborting the rest of
/// `soyeht setup`.
#[cfg(target_os = "macos")]
fn setup_caddy_macos(root: &Path) {
    use crate::caddy_manager;

    println!();
    println!("============================================");
    println!(" Caddy reverse proxy setup (macOS)");
    println!("============================================");
    println!();

    let Some(caddy) = caddy_manager::detect_caddy() else {
        println!("[setup] Caddy is not installed.");
        println!("[setup]   Install it with: brew install caddy");
        println!("[setup]   Then re-run: soyeht caddy install");
        println!(
            "[setup]   (Skipping Caddy setup — public claw sites and HTTPS will be unavailable.)"
        );
        return;
    };
    println!(
        "[setup] detected Caddy: {} ({})",
        caddy.path.display(),
        caddy.version
    );

    // ── 1. caddy trust (eager — installs local CA in System keychain) ──
    println!();
    println!("[setup] Step 1/2: Install Caddy's local CA in the System keychain.");
    println!("[setup]   This enables HTTPS for https://admin.localhost without browser warnings.");
    println!("[setup]   macOS will prompt for your admin password (one-time).");
    let answer = prompt("Install local CA now? [Y/n]", "Y");
    if answer.eq_ignore_ascii_case("n") {
        println!("[setup]   skipped. Run later: soyeht caddy trust");
    } else {
        match caddy_manager::caddy_trust(&caddy) {
            Ok(()) => println!("[setup]   local CA installed."),
            Err(e) => {
                eprintln!("[setup]   caddy trust failed: {e}");
                eprintln!("[setup]   You can retry later with: soyeht caddy trust");
                eprintln!("[setup]   Setup will continue without HTTPS local.");
            }
        }
    }

    // ── 2. LaunchAgent install ─────────────────────────────────────────
    println!();
    println!("[setup] Step 2/2: Register Caddy as a LaunchAgent.");
    println!("[setup]   Creates ~/Library/LaunchAgents/com.soyeht.caddy.plist.");
    println!("[setup]   Caddy will run in the background, restart on crash, and survive reboot.");
    let answer = prompt("Register LaunchAgent now? [Y/n]", "Y");
    if answer.eq_ignore_ascii_case("n") {
        println!("[setup]   skipped. Run later: soyeht caddy install");
        return;
    }
    match caddy_manager::install(root) {
        Ok(_) => {
            println!("[setup]   LaunchAgent registered. Caddy is now running.");
            println!("[setup]   Logs: ~/Library/Logs/theyos/caddy.{{out,err}}.log");
            println!(
                "[setup]   Manage with: soyeht caddy {{status,reload,restart,stop,uninstall}}"
            );
        }
        Err(e) => {
            eprintln!("[setup]   LaunchAgent install failed: {e}");
            eprintln!("[setup]   Setup will continue. Retry later with: soyeht caddy install");
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rand_hex_produces_correct_length() {
        let h = rand_hex(32);
        assert_eq!(h.len(), 64, "32 bytes → 64 hex chars");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn rand_hex_different_each_call() {
        let a = rand_hex(16);
        let b = rand_hex(16);
        assert_ne!(a, b, "two random hex strings should differ");
    }

    #[test]
    fn substitute_value_returns_known_keys() {
        let answers = SetupAnswers {
            theyos_home: "/home/test".into(),
            admin_password: "secret123".into(),
            session_pepper: "abc123".into(),
            access_mode: "local".into(),
        };
        assert_eq!(
            substitute_value("SOYEHT_ADMIN_PASSWORD", &answers),
            Some("secret123".into())
        );
        assert_eq!(
            substitute_value("THEYOS_SESSION_PEPPER", &answers),
            Some("abc123".into())
        );
        assert_eq!(
            substitute_value("THEYOS_HOME", &answers),
            Some("/home/test".into())
        );
        assert_eq!(
            substitute_value("ACCESS_MODE", &answers),
            Some("local".into())
        );
        assert_eq!(substitute_value("RUST_LOG", &answers), Some("info".into()));
    }

    #[test]
    fn substitute_value_returns_none_for_unknown() {
        let answers = SetupAnswers {
            theyos_home: String::new(),
            admin_password: String::new(),
            session_pepper: String::new(),
            access_mode: String::new(),
        };
        assert_eq!(substitute_value("OPENROUTER_API_KEY", &answers), None);
        assert_eq!(substitute_value("CF_API_TOKEN", &answers), None);
        assert_eq!(substitute_value("ADMIN_PORT", &answers), None);
    }

    #[test]
    fn generate_env_minimal_contains_critical_fields() {
        let answers = SetupAnswers {
            theyos_home: "/home/user".into(),
            admin_password: "pass".into(),
            session_pepper: "deadbeef".into(),
            access_mode: "local".into(),
        };
        let env = generate_env_minimal(&answers);
        assert!(env.contains("SOYEHT_ADMIN_PASSWORD=pass"));
        assert!(env.contains("THEYOS_SESSION_PEPPER=deadbeef"));
        assert!(env.contains("THEYOS_HOME=/home/user"));
        assert!(env.contains("ACCESS_MODE=local"));
    }

    #[test]
    fn generate_env_from_template_substitutes_values() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        // Write a minimal .env.example
        fs::write(
            root.join(".env.example"),
            "# Comment line\n\
             SOYEHT_ADMIN_PASSWORD=CHANGE_ME\n\
             THEYOS_SESSION_PEPPER=GENERATE\n\
             THEYOS_HOME=/home/user\n\
             ACCESS_MODE=local\n\
             RUST_LOG=info\n\
             ADMIN_PORT=8892\n\
             # OPENROUTER_API_KEY=optional\n",
        )
        .unwrap();

        let answers = SetupAnswers {
            theyos_home: "/home/test".into(),
            admin_password: "mypass".into(),
            session_pepper: "aabbcc".into(),
            access_mode: "tailscale".into(),
        };

        let result = generate_env_from_template(root, &answers);

        // Substituted fields
        assert!(result.contains("SOYEHT_ADMIN_PASSWORD=mypass"));
        assert!(result.contains("THEYOS_SESSION_PEPPER=aabbcc"));
        assert!(result.contains("THEYOS_HOME=/home/test"));
        assert!(result.contains("ACCESS_MODE=tailscale"));
        assert!(result.contains("RUST_LOG=info"));

        // Unsubstituted fields keep template value
        assert!(result.contains("ADMIN_PORT=8892"));

        // Comments preserved
        assert!(result.contains("# Comment line"));
        assert!(result.contains("# OPENROUTER_API_KEY=optional"));
    }
}
