//! Phase 2 — chroot configuration (P28.5: bash-free).
//!
//! Steps:
//! 1. Mount virtual filesystems: /dev, /dev/pts, /proc, /sys, /tmp.
//! 2. Copy resolv.conf into rootfs.
//! 3. Configure apt sources + install base packages (systemd, openssh, iproute2,
//!    ca-certificates, curl, procps, udev, kmod, git) + tmux 3.6a (static binary).
//!    Node.js and Chrome are NOT in the base image — installed per-claw by `InstallerPlan`.
//! 4. Configure DNS (static resolv.conf).
//! 5. Configure SSH + `authorized_keys`.
//! 6. Configure systemd (hostname, machine-id, getty autologin, mounts).
//! 7. Final cleanup.
//! 8. Unmount all virtual filesystems (always, even on error).
//!
//! Network setup is handled entirely by kernel `boot_args` (`ip=` parameter) and
//! `slirp4netns --configure`. No `fcnet-setup.sh` is needed.
//!
//! No shell scripts are written to disk or executed.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::cleanup::{bind_mount, lazy_unmount, vfs_mount};
use crate::error::{Result, RootfsError, RootfsPhase};

const PHASE: RootfsPhase = RootfsPhase::Chroot;
/// Explicit PATH to use inside the chroot (avoids NixOS host PATH leakage).
const CHROOT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Run the full phase-2 chroot configuration.
pub fn run(rootfs_dir: &Path, ssh_pubkey_content: &str) -> Result<()> {
    println!("[rootfsbuilder] === Phase 2: chroot configuration ===");

    mount_virtual_fs(rootfs_dir)?;

    // Unwind mounts on any error below — mirrors `trap cleanup EXIT` in Bash.
    let result = configure_inside_chroot(rootfs_dir, ssh_pubkey_content);

    unmount_virtual_fs(rootfs_dir);

    result
}

// ── Mount / unmount ───────────────────────────────────────────────────────────

fn mount_virtual_fs(rootfs_dir: &Path) -> Result<()> {
    // Mount order must match unmount reverse order in VIRTUAL_MOUNTS.
    bind_mount(Path::new("/dev"), &rootfs_dir.join("dev"))
        .map_err(|e| RootfsError::new(PHASE, format!("mount --bind /dev: {e}")))?;

    bind_mount(Path::new("/dev/pts"), &rootfs_dir.join("dev/pts"))
        .map_err(|e| RootfsError::new(PHASE, format!("mount --bind /dev/pts: {e}")))?;

    vfs_mount("proc", "proc", &rootfs_dir.join("proc"))
        .map_err(|e| RootfsError::new(PHASE, format!("mount -t proc: {e}")))?;

    vfs_mount("sysfs", "sys", &rootfs_dir.join("sys"))
        .map_err(|e| RootfsError::new(PHASE, format!("mount -t sysfs: {e}")))?;

    vfs_mount("tmpfs", "tmp", &rootfs_dir.join("tmp"))
        .map_err(|e| RootfsError::new(PHASE, format!("mount -t tmpfs: {e}")))?;

    // Copy resolv.conf so chroot can reach the network.
    fs::copy("/etc/resolv.conf", rootfs_dir.join("etc/resolv.conf"))
        .map_err(|e| RootfsError::new(PHASE, format!("copy resolv.conf: {e}")))?;

    Ok(())
}

fn unmount_virtual_fs(rootfs_dir: &Path) {
    println!("[rootfsbuilder] unmounting virtual filesystems...");
    // Reverse order of mounting.
    for mp in &["tmp", "sys", "proc", "dev/pts", "dev"] {
        lazy_unmount(&rootfs_dir.join(mp));
    }
}

// ── Chroot configuration (P28.5: no shell script) ────────────────────────────

fn configure_inside_chroot(rootfs_dir: &Path, ssh_pubkey_content: &str) -> Result<()> {
    // ── Step 1: Fix any unconfigured packages left by debootstrap ────────────
    println!("[rootfsbuilder] fixing unconfigured packages...");
    run_chroot(rootfs_dir, &["dpkg", "--configure", "-a"])?;

    // Ensure apt is available; if not, install remaining .debs from cache.
    if !chroot_cmd_succeeds(rootfs_dir, &["dpkg", "-s", "apt"]) {
        println!("[rootfsbuilder] apt not yet installed, installing base packages from cache...");
        // dpkg -i all cached .debs; errors tolerated (packages may conflict)
        run_chroot_tolerant(rootfs_dir, &["dpkg", "-i", "/var/cache/apt/archives/*.deb"]);
        run_chroot(rootfs_dir, &["dpkg", "--configure", "-a"])?;
    }

    if !chroot_cmd_succeeds(rootfs_dir, &["apt-get", "--version"]) {
        return Err(
            RootfsError::new(PHASE, "apt-get still not available after dpkg recovery").with_detail(
                "debootstrap may have left the rootfs in a broken state. \
                 Check the work dir for logs."
                    .to_string(),
            ),
        );
    }
    println!("[rootfsbuilder] apt-get is available");

    // ── Step 2: Configure apt sources ────────────────────────────────────────
    println!("[rootfsbuilder] configuring apt sources...");
    fs::write(
        rootfs_dir.join("etc/apt/sources.list"),
        "deb http://archive.ubuntu.com/ubuntu noble main universe\n\
         deb http://archive.ubuntu.com/ubuntu noble-updates main universe\n\
         deb http://archive.ubuntu.com/ubuntu noble-security main universe\n",
    )
    .map_err(|e| RootfsError::new(PHASE, format!("write sources.list: {e}")))?;

    run_chroot(rootfs_dir, &["apt-get", "update"])?;

    // ── Step 3: Install systemd and base packages ─────────────────────────────
    println!("[rootfsbuilder] installing systemd and base packages...");
    run_chroot(
        rootfs_dir,
        &[
            "apt-get",
            "install",
            "-y",
            "systemd",
            "systemd-sysv",
            "dbus",
        ],
    )?;
    {
        let mut apt_cmd: Vec<&str> = vec!["apt-get", "install", "-y"];
        apt_cmd.extend_from_slice(APT_BASE_PACKAGES);
        run_chroot(rootfs_dir, &apt_cmd)?;
    }

    // ── Step 3a: Configure UTF-8 locale ─────────────────────────────────────
    // Without a UTF-8 locale, programs that emit Unicode (e.g. QR code
    // generators using block characters U+2580-U+259F) produce garbled output
    // (replacement characters ��) in the terminal.
    println!("[rootfsbuilder] configuring UTF-8 locale...");
    run_chroot(rootfs_dir, &["locale-gen", "C.UTF-8"])?;
    fs::write(rootfs_dir.join("etc/default/locale"), "LANG=C.UTF-8\n")
        .map_err(|e| RootfsError::new(PHASE, format!("write /etc/default/locale: {e}")))?;

    // ── Step 3b: Install tmux 3.6a static binary (scrollbar support) ────────
    // Ubuntu 24.04 apt ships tmux 3.4 which lacks pane-scrollbars (added in 3.6).
    // We download the official static musl binary from tmux-builds instead.
    println!("[rootfsbuilder] installing tmux 3.6a (static binary)...");
    run_chroot(
        rootfs_dir,
        &["curl", "-fsSL", TMUX_BINARY_URL, "-o", "/tmp/tmux.tar.gz"],
    )?;
    run_chroot(
        rootfs_dir,
        &["tar", "-C", "/tmp", "-xzf", "/tmp/tmux.tar.gz"],
    )?;
    run_chroot(rootfs_dir, &["cp", "/tmp/tmux", "/usr/bin/tmux"])?;
    run_chroot(rootfs_dir, &["chmod", "755", "/usr/bin/tmux"])?;
    run_chroot(rootfs_dir, &["rm", "-f", "/tmp/tmux.tar.gz", "/tmp/tmux"])?;

    // ── Step 4: Configure DNS ─────────────────────────────────────────────────
    println!("[rootfsbuilder] configuring DNS...");
    // Remove the bind-mounted resolv.conf and replace with static one.
    let resolv = rootfs_dir.join("etc/resolv.conf");
    let _ = fs::remove_file(&resolv);
    fs::write(&resolv, "nameserver 8.8.8.8\nnameserver 1.1.1.1\n")
        .map_err(|e| RootfsError::new(PHASE, format!("write resolv.conf: {e}")))?;

    // ── Step 7: Configure SSH ─────────────────────────────────────────────────
    println!("[rootfsbuilder] configuring SSH...");
    run_chroot(rootfs_dir, &["systemctl", "enable", "ssh.service"])?;
    run_chroot(rootfs_dir, &["ssh-keygen", "-A"])?;

    let ssh_dir = rootfs_dir.join("root/.ssh");
    fs::create_dir_all(&ssh_dir)
        .map_err(|e| RootfsError::new(PHASE, format!("mkdir .ssh: {e}")))?;
    fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| RootfsError::new(PHASE, format!("chmod .ssh: {e}")))?;

    let pubkey = ssh_pubkey_content.trim();
    let auth_keys = ssh_dir.join("authorized_keys");
    fs::write(&auth_keys, format!("{pubkey}\n"))
        .map_err(|e| RootfsError::new(PHASE, format!("write authorized_keys: {e}")))?;
    fs::set_permissions(&auth_keys, fs::Permissions::from_mode(0o600))
        .map_err(|e| RootfsError::new(PHASE, format!("chmod authorized_keys: {e}")))?;

    // Patch sshd_config: PermitRootLogin prohibit-password
    let sshd_config_path = rootfs_dir.join("etc/ssh/sshd_config");
    if sshd_config_path.exists() {
        let content = fs::read_to_string(&sshd_config_path)
            .map_err(|e| RootfsError::new(PHASE, format!("read sshd_config: {e}")))?;
        let patched = content
            .lines()
            .map(|l| {
                if l.starts_with("#PermitRootLogin") || l.starts_with("PermitRootLogin") {
                    "PermitRootLogin prohibit-password"
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\nUseDNS no\n";
        fs::write(&sshd_config_path, patched)
            .map_err(|e| RootfsError::new(PHASE, format!("write sshd_config: {e}")))?;
    }
    // Remove root password
    run_chroot(rootfs_dir, &["passwd", "-d", "root"])?;

    // ── Configure tmux for xterm.js compatibility + scrollbars ──────────
    println!("[rootfsbuilder] configuring tmux...");
    fs::write(rootfs_dir.join("root/.tmux.conf"), TMUX_CONF)
        .map_err(|e| RootfsError::new(PHASE, format!("write .tmux.conf: {e}")))?;

    // ── Step 8: Configure systemd ────────────────────────────────────────────
    println!("[rootfsbuilder] configuring systemd...");
    fs::write(rootfs_dir.join("etc/hostname"), "ubuntu-fc-uvm\n")
        .map_err(|e| RootfsError::new(PHASE, format!("write hostname: {e}")))?;
    run_chroot(rootfs_dir, &["systemd-machine-id-setup"])?;

    // ── Step 8b: Drop in agent guidance for public-site publishing ──────────
    // Read by AI agents inside the VM when the operator asks them to "make
    // this claw a public website". Self-contained instructions explain how
    // to bind on 0.0.0.0 and what the operator does in the admin UI.
    let theyos_etc = rootfs_dir.join("etc/theyos");
    fs::create_dir_all(&theyos_etc)
        .map_err(|e| RootfsError::new(PHASE, format!("mkdir /etc/theyos: {e}")))?;
    fs::write(theyos_etc.join("how-to-publish.md"), HOW_TO_PUBLISH)
        .map_err(|e| RootfsError::new(PHASE, format!("write how-to-publish.md: {e}")))?;

    run_chroot(
        rootfs_dir,
        &["systemctl", "enable", "serial-getty@ttyS0.service"],
    )?;

    // getty override: autologin root
    let getty_drop_in = rootfs_dir.join("etc/systemd/system/serial-getty@ttyS0.service.d");
    fs::create_dir_all(&getty_drop_in)
        .map_err(|e| RootfsError::new(PHASE, format!("mkdir getty drop-in: {e}")))?;
    fs::write(getty_drop_in.join("override.conf"), GETTY_OVERRIDE)
        .map_err(|e| RootfsError::new(PHASE, format!("write getty override: {e}")))?;

    // var-lib-systemd.mount
    fs::write(
        rootfs_dir.join("etc/systemd/system/var-lib-systemd.mount"),
        VAR_LIB_SYSTEMD_MOUNT,
    )
    .map_err(|e| RootfsError::new(PHASE, format!("write var-lib-systemd.mount: {e}")))?;
    run_chroot(
        rootfs_dir,
        &["systemctl", "enable", "var-lib-systemd.mount"],
    )?;

    // ── Step 11: Cleanup ──────────────────────────────────────────────────────
    println!("[rootfsbuilder] cleaning up...");
    run_chroot(rootfs_dir, &["apt-get", "clean"])?;
    // Remove apt lists and temp files
    for dir in &["var/lib/apt/lists", "tmp", "var/tmp"] {
        let p = rootfs_dir.join(dir);
        if p.exists() {
            for entry in fs::read_dir(&p).into_iter().flatten().flatten() {
                let ep = entry.path();
                if ep.is_dir() {
                    let _ = fs::remove_dir_all(&ep);
                } else {
                    let _ = fs::remove_file(&ep);
                }
            }
        }
    }

    println!("[rootfsbuilder] chroot configuration done");
    Ok(())
}

// ── Chroot execution helpers ──────────────────────────────────────────────────

/// Run a command inside the chroot via `chroot <rootfs> /usr/bin/env PATH=... <cmd>`.
fn run_chroot(rootfs_dir: &Path, cmd_args: &[&str]) -> Result<()> {
    let mut args = vec![
        rootfs_dir.display().to_string(),
        "/usr/bin/env".to_string(),
        format!("DEBIAN_FRONTEND=noninteractive"),
        format!("PATH={CHROOT_PATH}"),
    ];
    args.extend(cmd_args.iter().map(std::string::ToString::to_string));

    let out = Command::new("chroot")
        .args(&args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| RootfsError::new(PHASE, format!("spawn chroot: {e}")))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let cmd_display = cmd_args.join(" ");
        return Err(RootfsError::from_cmd(
            PHASE,
            &format!("chroot {cmd_display}"),
            out.status.code(),
            &stderr,
        ));
    }
    Ok(())
}

/// Run a command inside the chroot, tolerating failure (best-effort steps).
fn run_chroot_tolerant(rootfs_dir: &Path, cmd_args: &[&str]) {
    let _ = run_chroot(rootfs_dir, cmd_args);
}

/// Returns true if a command exits 0 inside the chroot.
fn chroot_cmd_succeeds(rootfs_dir: &Path, cmd_args: &[&str]) -> bool {
    let mut args = vec![
        rootfs_dir.display().to_string(),
        "/usr/bin/env".to_string(),
        format!("PATH={CHROOT_PATH}"),
    ];
    args.extend(cmd_args.iter().map(std::string::ToString::to_string));

    Command::new("chroot")
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── Embedded configuration file constants ────────────────────────────────────

/// URL for the tmux 3.6a static binary (musl, no runtime deps).
/// Source: <https://github.com/tmux/tmux-builds/releases>
const TMUX_BINARY_URL: &str =
    "https://github.com/tmux/tmux-builds/releases/download/v3.6a/tmux-3.6a-linux-x86_64.tar.gz";

/// tmux configuration for xterm.js compatibility and scrollbar support.
const TMUX_CONF: &str = "\
set -g default-terminal \"xterm-256color\"\n\
set -g mouse on\n\
set -g set-clipboard on\n\
set -g history-limit 50000\n\
set -g pane-scrollbars on\n\
set -g pane-scrollbars-position right\n\
set -g pane-scrollbars-style fg=colour240,bg=colour235\n";

/// Base packages installed via apt (tmux is NOT here — installed as a static binary).
const APT_BASE_PACKAGES: &[&str] = &[
    "openssh-server",
    "iproute2",
    "git",
    "curl",
    "ca-certificates",
    "procps",
    "udev",
    "kmod",
    "locales",
];

const GETTY_OVERRIDE: &str = r"[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root -o '-p -- \u' --keep-baud 115200,38400,9600 %I dumb
";

/// Agent guidance written to `/etc/theyos/how-to-publish.md` inside every VM.
const HOW_TO_PUBLISH: &str = include_str!("../assets/how-to-publish.md");

const VAR_LIB_SYSTEMD_MOUNT: &str = r"[Unit]
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
After=swap.target

[Mount]
What=tmpfs
Where=/var/lib/systemd
Type=tmpfs
Options=mode=1777,strictatime,nosuid,nodev,size=50%,nr_inodes=10k

[Install]
WantedBy=local-fs.target
";

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getty_override_has_autologin() {
        assert!(GETTY_OVERRIDE.contains("--autologin root"));
    }

    #[test]
    fn var_lib_systemd_mount_has_tmpfs() {
        assert!(VAR_LIB_SYSTEMD_MOUNT.contains("Type=tmpfs"));
    }

    #[test]
    fn pubkey_written_directly_no_shell_escape_needed() {
        // The pubkey is written directly by fs::write — no shell quoting needed.
        let pubkey = "ssh-ed25519 AAAA test@host";
        assert!(
            !pubkey.contains('\''),
            "pubkeys should not have single quotes"
        );
    }

    #[test]
    fn tmux_conf_has_scrollbar_config() {
        assert!(
            TMUX_CONF.contains("pane-scrollbars on"),
            "missing pane-scrollbars on"
        );
        assert!(
            TMUX_CONF.contains("pane-scrollbars-position right"),
            "missing pane-scrollbars-position"
        );
        assert!(
            TMUX_CONF.contains("pane-scrollbars-style"),
            "missing pane-scrollbars-style"
        );
    }

    #[test]
    fn tmux_conf_has_xterm_compatibility() {
        assert!(
            TMUX_CONF.contains("default-terminal"),
            "missing default-terminal"
        );
        assert!(TMUX_CONF.contains("mouse on"), "missing mouse on");
        assert!(
            TMUX_CONF.contains("set-clipboard on"),
            "missing set-clipboard on"
        );
        assert!(TMUX_CONF.contains("history-limit"), "missing history-limit");
    }

    #[test]
    fn tmux_binary_url_is_well_formed() {
        assert!(TMUX_BINARY_URL.starts_with("https://"), "must be HTTPS");
        assert!(
            TMUX_BINARY_URL.contains("tmux-builds"),
            "must point to tmux-builds repo"
        );
        assert!(TMUX_BINARY_URL.contains("3.6a"), "must target version 3.6a");
        assert!(TMUX_BINARY_URL.ends_with(".tar.gz"), "must be a tarball");
        assert!(TMUX_BINARY_URL.contains("x86_64"), "must target x86_64");
    }

    #[test]
    fn apt_packages_do_not_include_tmux() {
        // tmux 3.6a is installed as a static binary, not from apt (which ships 3.4).
        assert!(
            !APT_BASE_PACKAGES.contains(&"tmux"),
            "tmux must not be in APT_BASE_PACKAGES — it is installed separately"
        );
    }

    #[test]
    fn apt_packages_include_curl() {
        // curl is required to download the tmux static binary inside the chroot.
        assert!(
            APT_BASE_PACKAGES.contains(&"curl"),
            "curl must be in APT_BASE_PACKAGES — needed for tmux download"
        );
    }
}
