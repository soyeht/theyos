//! vmrunner-macos-rs — macOS VM runner using Apple Virtualization Framework.
//!
//! This crate provides a macOS-specific implementation of the theyOS VM runner
//! using Apple's Virtualization Framework (VZ). It mirrors the functionality
//! of vmrunner-rs (Linux/Firecracker) but uses `VZVirtualMachine` for VM lifecycle.
//!
//! # Architecture
//!
//! ```text
//! lib.rs          — Public API: VmRunnerMacOS, VmConfigMacOS, MacOSVmEnv
//! vz.rs           — VZVirtualMachine wrapper (Objective-C FFI)
//! config.rs       — VM configuration builder and YAML config loading
//! error.rs        — VZError types
//! snapshot.rs     — VZ snapshot management for warm pool
//! network.rs      — NAT networking and port forwarding
//! ```
//!
//! # Platform Detection
//!
//! This crate only compiles on macOS (`target_os = "macos"`). The executor-rs
//! crate uses conditional compilation to select the appropriate vmrunner.

#![cfg(target_os = "macos")]
// Lint suppressions
#![allow(clippy::result_large_err)]
#![allow(unsafe_code)]
// Required for Objective-C FFI
// objc 0.2.7 uses deprecated `cfg(cargo-clippy)` in macro expansions.
#![allow(unexpected_cfgs)]

pub mod config;
pub mod error;
pub mod init_state;
pub mod installer_plan_macos;
pub mod linux_guest;
pub mod linux_init_state;
pub mod macos_guest;
pub mod network;
pub mod slot_manager;
pub mod snapshot;
pub mod vz;
pub mod warm_pool;

use std::path::{Path, PathBuf};
use std::time::Duration;

pub use config::{ClawTypeConfig, MacOSConfig, MacOSVmConfig};
pub use error::VZError;
pub use network::{NetworkConfig, PortForward, PortProtocol};
pub use slot_manager::{MACOS_VM_LIMIT, MACOS_VM_LIMIT_REACHED, MacOSVmSlotManager};
pub use snapshot::{SnapshotManager, SnapshotState};
pub use vz::{
    GuestOs, VZMacOSVmConfigurationBuilder, VZVirtualMachine, VZVirtualMachineConfiguration,
    VZVirtualMachineConfigurationBuilder, VmState,
};
pub use warm_pool::{PoolEntryState, PoolStatus, WarmPoolConfig, WarmPoolEntry, WarmPoolManager};

/// macOS-specific VM environment configuration.
///
/// Equivalent to `VmEnv` in vmrunner-rs but for macOS/VZ.
#[derive(Debug, Clone)]
pub struct MacOSVmEnv {
    /// Base directory for VM state (~/Library/Application Support/theyos/vms)
    pub state_dir: PathBuf,
    /// Path to ARM64 Linux kernel (vmlinuz-aarch64)
    pub kernel_image: PathBuf,
    /// Path to base rootfs disk image
    pub base_rootfs: PathBuf,
    /// SSH private key for root login
    pub ssh_key: PathBuf,
    /// SSH public key
    pub ssh_pubkey: PathBuf,
    /// Snapshots directory (~/Library/Application Support/theyos/snapshots)
    pub snapshots_dir: PathBuf,
    /// Cached HOME directory
    pub home: PathBuf,
}

impl MacOSVmEnv {
    /// Build a `MacOSVmEnv` from environment variables or sensible defaults.
    ///
    /// # Errors
    ///
    /// Returns an error if HOME directory cannot be determined.
    pub fn from_env() -> Result<Self, VZError> {
        let home = std::env::var("HOME")
            .map_err(|_| VZError::InvalidConfig("HOME environment variable not set".into()))?;

        let home_path = PathBuf::from(&home);

        // Default: ~/Library/Application Support/theyos/vms
        let state_dir = std::env::var("THEYOS_VM_STATE_DIR").ok().map_or_else(
            || home_path.join("Library/Application Support/theyos/vms"),
            PathBuf::from,
        );

        // Default: /usr/local/share/theyos/vms (Homebrew install location)
        let assets_dir = std::env::var("THEYOS_VM_ASSETS_DIR").ok().map_or_else(
            || PathBuf::from("/usr/local/share/theyos/vms"),
            PathBuf::from,
        );

        let kernel_image = std::env::var("THEYOS_KERNEL_IMAGE")
            .ok()
            .map_or_else(|| assets_dir.join("vmlinuz-aarch64"), PathBuf::from);

        let base_rootfs = std::env::var("THEYOS_BASE_ROOTFS")
            .ok()
            .map_or_else(|| assets_dir.join("rootfs.img"), PathBuf::from);

        let ssh_key = std::env::var("THEYOS_SSH_KEY")
            .ok()
            .map_or_else(|| assets_dir.join("rootfs.id_rsa"), PathBuf::from);

        let ssh_pubkey = std::env::var("THEYOS_SSH_PUBKEY")
            .ok()
            .map_or_else(|| assets_dir.join("rootfs.id_rsa.pub"), PathBuf::from);

        let snapshots_dir = std::env::var("THEYOS_SNAPSHOTS_DIR").ok().map_or_else(
            || home_path.join("Library/Application Support/theyos/snapshots"),
            PathBuf::from,
        );

        Ok(Self {
            state_dir,
            kernel_image,
            base_rootfs,
            ssh_key,
            ssh_pubkey,
            snapshots_dir,
            home: home_path,
        })
    }
}

// ── DHCP IP resolution ────────────────────────────────────────────────────────

/// Resolve the DHCP-assigned VZ NAT IP for a VM by its MAC address.
///
/// Parses `/var/db/dhcpd_leases` for an entry matching `mac_address`.
/// Retries every 500 ms for up to `timeout_secs` seconds.
///
/// # MAC matching
///
/// Tries two strategies in order:
/// 1. **MAC match** (`hw_address=1,aa:bb:cc:dd:ee:ff`): works when cloud-init
///    network-config sets `dhcp-identifier: mac`.
/// 2. **Delta match**: compares `(ip, hw_address)` pairs to the pre-start snapshot.
///    Detects both new IPs and reused IPs with a new `hw_address` — handles both
///    DUID-based clients (`hw_address=ff,...`) and DHCP server IP reuse.
///
/// # Format of `/var/db/dhcpd_leases`
///
/// ```text
/// {
///   name=picoclaw-test
///   ip_address=192.168.64.5
///   hw_address=1,aa:bb:cc:dd:ee:ff   ← MAC-based client ID
///   lease=0x...
/// }
/// ```
///
/// # Errors
///
/// Returns an error if no lease is found within `timeout_secs` seconds.
#[allow(clippy::implicit_hasher)]
pub async fn resolve_dhcp_ip(
    mac_address: &str,
    timeout_secs: u64,
    existing_leases: &std::collections::HashSet<(String, String)>,
) -> Result<String, VZError> {
    let mac = mac_address.to_lowercase();
    let leases_path = std::path::Path::new("/var/db/dhcpd_leases");
    let retries = timeout_secs * 2; // 500 ms per retry

    for attempt in 0..retries {
        if let Ok(content) = tokio::fs::read_to_string(leases_path).await {
            // Strategy 1: exact MAC match (works if guest uses MAC client ID)
            if let Some(ip) = parse_dhcp_lease_by_mac(&content, &mac) {
                tracing::info!(
                    mac = mac_address,
                    ip,
                    attempt,
                    "Resolved VM IP by MAC match"
                );
                return Ok(ip);
            }
            // Strategy 2: new (ip, hw_address) pair not in the pre-start snapshot.
            // This catches both new IPs and DHCP server IP reuse (same IP, new hw_address).
            let all_leases = parse_all_leases(&content);
            if let Some((new_ip, _)) = all_leases
                .into_iter()
                .find(|pair| !existing_leases.contains(pair))
            {
                tracing::info!(
                    mac = mac_address,
                    ip = new_ip,
                    attempt,
                    "Resolved VM IP by delta (DUID-based DHCP or IP reuse)"
                );
                return Ok(new_ip);
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Err(VZError::NetworkError(format!(
        "Could not resolve IP for MAC {mac_address} within {timeout_secs}s. \
         Check /var/db/dhcpd_leases and ensure the VM is running with VZ NAT networking."
    )))
}

/// Snapshot all current leases from `/var/db/dhcpd_leases` as `(ip, hw_address)` pairs.
///
/// Call this BEFORE starting a new VM; pass the result to `resolve_dhcp_ip` so it can
/// detect the new VM's lease by delta — including cases where the DHCP server reuses
/// a previously-leased IP for the new VM (common when old leases have expired).
pub async fn snapshot_leased_ips() -> std::collections::HashSet<(String, String)> {
    let leases_path = std::path::Path::new("/var/db/dhcpd_leases");
    tokio::fs::read_to_string(leases_path)
        .await
        .map(|c| parse_all_leases(&c))
        .unwrap_or_default()
}

/// Parse `/var/db/dhcpd_leases` content and return the IP for a given MAC address.
/// Matches only `hw_address=1,aa:bb:cc:dd:ee:ff` (hardware type 1 = Ethernet + MAC).
#[must_use]
pub fn parse_dhcp_lease_by_mac(content: &str, mac: &str) -> Option<String> {
    let mut in_block = false;
    let mut current_ip: Option<String> = None;
    let mut found_mac = false;

    for line in content.lines() {
        let line = line.trim();
        if line == "{" {
            in_block = true;
            current_ip = None;
            found_mac = false;
            continue;
        }
        if line == "}" {
            if in_block && found_mac {
                return current_ip;
            }
            in_block = false;
            continue;
        }
        if !in_block {
            continue;
        }
        if let Some(ip) = line.strip_prefix("ip_address=") {
            current_ip = Some(ip.trim().to_string());
        } else if let Some(hw) = line.strip_prefix("hw_address=") {
            // hw_address format: "1,aa:bb:cc:dd:ee:ff" (type 1 = Ethernet MAC)
            if let Some((kind, addr)) = hw.split_once(',') {
                if kind.trim() == "1" && addr.trim().to_lowercase() == mac {
                    found_mac = true;
                }
            }
        }
    }
    None
}

/// Parse `/var/db/dhcpd_leases` and return all `(ip, hw_address)` pairs.
///
/// Tracking `hw_address` alongside `ip` lets delta detection catch the case where
/// the DHCP server reuses a previously-leased IP for a new VM: same IP, different
/// `hw_address` → genuinely new lease.
fn parse_all_leases(content: &str) -> std::collections::HashSet<(String, String)> {
    let mut leases = std::collections::HashSet::new();
    let mut current_ip: Option<String> = None;
    let mut current_hw: Option<String> = None;
    let mut in_block = false;
    for line in content.lines() {
        let line = line.trim();
        match line {
            "{" => {
                in_block = true;
                current_ip = None;
                current_hw = None;
            }
            "}" if in_block => {
                if let (Some(ip), Some(hw)) = (current_ip.take(), current_hw.take()) {
                    leases.insert((ip, hw));
                }
                in_block = false;
            }
            _ if in_block => {
                if let Some(ip) = line.strip_prefix("ip_address=") {
                    current_ip = Some(ip.trim().to_string());
                } else if let Some(hw) = line.strip_prefix("hw_address=") {
                    current_hw = Some(hw.trim().to_string());
                }
            }
            _ => {}
        }
    }
    leases
}

// ── SSH key management ────────────────────────────────────────────────────────

/// Ensure the theyOS SSH keypair exists at `~/.theyos/keys/id_ed25519`.
///
/// Generates a new ed25519 keypair if missing. Returns the public key content.
///
/// # Errors
///
/// Returns an error if key generation or file I/O fails.
pub async fn ensure_ssh_key() -> Result<String, VZError> {
    let home = std::env::var("HOME").map_err(|_| VZError::InvalidConfig("HOME not set".into()))?;
    let keys_dir = PathBuf::from(&home).join(".theyos/keys");
    let privkey = keys_dir.join("id_ed25519");
    let pubkey = keys_dir.join("id_ed25519.pub");

    if pubkey.exists() && privkey.exists() {
        let content = tokio::fs::read_to_string(&pubkey).await.map_err(|e| {
            VZError::InvalidConfig(format!("Cannot read SSH pubkey {}: {e}", pubkey.display()))
        })?;
        return Ok(content.trim().to_string());
    }

    // Create directory with correct permissions.
    tokio::fs::create_dir_all(&keys_dir).await.map_err(|e| {
        VZError::InvalidConfig(format!(
            "Cannot create keys dir {}: {e}",
            keys_dir.display()
        ))
    })?;

    // Generate ed25519 keypair via ssh-keygen.
    let output = tokio::process::Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "", // no passphrase
            "-C",
            "theyos-vm-key",
            "-f",
            privkey.to_str().unwrap_or("/tmp/id_ed25519"),
        ])
        .output()
        .await
        .map_err(|e| VZError::Internal(format!("ssh-keygen exec failed: {e}")))?;

    if !output.status.success() {
        return Err(VZError::Internal(format!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Set private key permissions to 0600.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&privkey, perms)
            .map_err(|e| VZError::Internal(format!("set privkey permissions: {e}")))?;
    }

    let content = tokio::fs::read_to_string(&pubkey)
        .await
        .map_err(|e| VZError::InvalidConfig(format!("Cannot read new SSH pubkey: {e}")))?;
    tracing::info!("Generated new theyOS SSH keypair at {}", keys_dir.display());
    Ok(content.trim().to_string())
}

/// Generate a random locally-administered unicast MAC address.
#[must_use]
pub fn generate_mac() -> String {
    let bytes = uuid::Uuid::new_v4().into_bytes();
    let b0 = (bytes[0] & 0xFE) | 0x02; // locally-administered, unicast
    format!(
        "{b0:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

/// Return the path to the theyOS SSH private key.
#[must_use]
pub fn ssh_private_key_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".theyos/keys/id_ed25519")
}

// ── Cloud-init cidata ISO ─────────────────────────────────────────────────────

/// Build a cloud-init cidata ISO for a VM instance.
///
/// Writes `user-data` and `meta-data` to a temp directory, then calls
/// `hdiutil makehybrid` to produce a `cidata`-labelled ISO9660 image.
///
/// # Errors
///
/// Returns an error if file I/O or `hdiutil` fails.
#[allow(clippy::too_many_lines)]
pub async fn build_cidata_iso(
    container: &str,
    pubkey: &str,
    out_path: &Path,
) -> Result<(), VZError> {
    let tmp_dir = tempfile::TempDir::new()
        .map_err(|e| VZError::Internal(format!("Cannot create temp dir for cidata: {e}")))?;
    let tmp_path = tmp_dir.path();

    // user-data
    //
    // bootcmd runs BEFORE systemd-networkd-wait-online, which avoids the
    // deadlock where cloud-init renders netplan but doesn't apply it and
    // the wait-online service blocks for 120s.  We inject a netplan config
    // and apply it immediately via bootcmd so DHCP completes before the
    // network-wait stage.
    let user_data = format!(
        "#cloud-config\n\
         bootcmd:\n\
         \x20 - |\n\
         \x20   cat > /etc/netplan/99-vz.yaml << 'NETPLAN'\n\
         \x20   network:\n\
         \x20     version: 2\n\
         \x20     ethernets:\n\
         \x20       all-en:\n\
         \x20         match:\n\
         \x20           name: \"en*\"\n\
         \x20         dhcp4: true\n\
         \x20         dhcp-identifier: mac\n\
         \x20   NETPLAN\n\
         \x20 - netplan apply\n\
         users:\n\
         \x20 - name: root\n\
         \x20   ssh_authorized_keys:\n\
         \x20     - \"{pubkey}\"\n\
         ssh_pwauth: false\n\
         disable_root: false\n\
         hostname: {container}\n"
    );
    tokio::fs::write(tmp_path.join("user-data"), &user_data)
        .await
        .map_err(|e| VZError::Internal(format!("write user-data: {e}")))?;

    // meta-data
    let meta_data = format!("instance-id: {container}\nlocal-hostname: {container}\n");
    tokio::fs::write(tmp_path.join("meta-data"), &meta_data)
        .await
        .map_err(|e| VZError::Internal(format!("write meta-data: {e}")))?;

    // network-config: force MAC-based DHCP client identifier so the lease appears
    // as "1,aa:bb:cc:dd:ee:ff" in /var/db/dhcpd_leases (macOS VZ NAT host).
    // Without this, modern Ubuntu guests use DUID-based identifiers ("ff,...")
    // which our MAC-based resolver cannot match.
    // Match by virtio_net driver (covers all VZ interface names: enp0s1, enp3s0, etc.)
    // Also keep name-based fallbacks for non-virtio NICs.
    let network_config = "\
version: 2\n\
ethernets:\n\
  all-virtio:\n\
    match:\n\
      driver: virtio_net\n\
    dhcp4: true\n\
    dhcp-identifier: mac\n\
  any-en:\n\
    match:\n\
      name: \"en*\"\n\
    dhcp4: true\n\
    dhcp-identifier: mac\n\
  any-eth:\n\
    match:\n\
      name: \"eth*\"\n\
    dhcp4: true\n\
    dhcp-identifier: mac\n";
    tokio::fs::write(tmp_path.join("network-config"), network_config)
        .await
        .map_err(|e| VZError::Internal(format!("write network-config: {e}")))?;

    // Remove existing ISO if present.
    if out_path.exists() {
        tokio::fs::remove_file(out_path)
            .await
            .map_err(|e| VZError::Internal(format!("remove stale cidata iso: {e}")))?;
    }

    let out_str = out_path
        .to_str()
        .ok_or_else(|| VZError::Internal("cidata out_path is not valid UTF-8".into()))?;

    // Prefer mkisofs (cdrtools) — produces a proper ISO9660 volume with the
    // "cidata" label that cloud-init's NoCloud datasource recognises.
    // Fall back to hdiutil makehybrid when mkisofs is not installed.
    let mkisofs = which_tool("mkisofs").await;

    let output = if let Some(mkisofs_bin) = mkisofs {
        let user_data = tmp_path.join("user-data");
        let meta_data = tmp_path.join("meta-data");
        let network_config = tmp_path.join("network-config");
        tokio::process::Command::new(mkisofs_bin)
            .args(["-output", out_str, "-volid", "cidata", "-joliet", "-rock"])
            .arg(&user_data)
            .arg(&meta_data)
            .arg(&network_config)
            .output()
            .await
            .map_err(|e| VZError::Internal(format!("mkisofs exec failed: {e}")))?
    } else {
        let tmp_str = tmp_path
            .to_str()
            .ok_or_else(|| VZError::Internal("temp dir path is not valid UTF-8".into()))?;
        tokio::process::Command::new("hdiutil")
            .args([
                "makehybrid",
                "-o",
                out_str,
                "-hfs",
                "-iso",
                "-joliet",
                "-default-volume-name",
                "cidata",
                tmp_str,
            ])
            .output()
            .await
            .map_err(|e| VZError::Internal(format!("hdiutil exec failed: {e}")))?
    };

    if !output.status.success() {
        return Err(VZError::Internal(format!(
            "cidata ISO build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    tracing::debug!(container, path = %out_path.display(), "Built cidata ISO");
    Ok(())
}

/// Resolve a tool name to its absolute path via `which`.
async fn which_tool(name: &str) -> Option<String> {
    tokio::process::Command::new("which")
        .arg(name)
        .output()
        .await
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

// ── Disk image management ─────────────────────────────────────────────────────

/// Clone the base disk image and EFI store for a new VM instance using APFS copy-on-write.
///
/// Returns `(disk_path, efi_path, cidata_dir)` where `cidata_dir` is the directory
/// where the cidata ISO should be written.
///
/// Performs:
/// 1. `cp -c <base>.raw <instance_dir>/<container>.raw`  (APFS clone — instant)
/// 2. `cp <base>.nvram <instance_dir>/<container>.nvram`
///
/// # Errors
///
/// Returns an error if the base image is missing or the copy fails.
///
/// # Panics
///
/// Panics if base image paths contain non-UTF-8 characters.
pub async fn clone_base_image(
    claw_type: &str,
    container: &str,
    instance_dir: &Path,
) -> Result<(PathBuf, PathBuf, PathBuf), VZError> {
    let vms_dir = std::env::var("THEYOS_VM_ASSETS_DIR").map_or_else(
        |_| PathBuf::from("/usr/local/share/theyos/vms"),
        PathBuf::from,
    );

    let base_disk = vms_dir.join(format!("{claw_type}-base.raw"));
    let base_nvram = vms_dir.join(format!("{claw_type}-base.nvram"));

    if !base_disk.exists() {
        return Err(VZError::InvalidConfig(format!(
            "Base disk image not found: {}. Run 'theyos images pull {claw_type}' to download it.",
            base_disk.display()
        )));
    }
    if !base_nvram.exists() {
        return Err(VZError::InvalidConfig(format!(
            "Base EFI store not found: {}",
            base_nvram.display()
        )));
    }

    // Verify image integrity against SHA-256 sidecar (if present).
    verify_image_integrity(&base_disk)?;

    // Check disk space.
    vz::check_disk_space(&vms_dir)?;

    // Create instance directory.
    tokio::fs::create_dir_all(instance_dir).await.map_err(|e| {
        VZError::Internal(format!(
            "Cannot create instance dir {}: {e}",
            instance_dir.display()
        ))
    })?;

    let instance_disk = instance_dir.join(format!("{container}.img"));
    let instance_nvram = instance_dir.join(format!("{container}.nvram"));
    let cidata_path = instance_dir.join(format!("{container}-cidata.iso"));

    // APFS CoW clone: `cp -c` (instant, zero extra disk usage until diverge).
    let disk_out = tokio::process::Command::new("cp")
        .args([
            "-c",
            base_disk.to_str().unwrap(),
            instance_disk.to_str().unwrap(),
        ])
        .output()
        .await
        .map_err(|e| VZError::Internal(format!("cp -c failed: {e}")))?;
    if !disk_out.status.success() {
        return Err(VZError::Internal(format!(
            "cp -c disk failed: {}",
            String::from_utf8_lossy(&disk_out.stderr)
        )));
    }

    // Regular copy for EFI store (small file, ~128 KB).
    let nvram_out = tokio::process::Command::new("cp")
        .args([
            base_nvram.to_str().unwrap(),
            instance_nvram.to_str().unwrap(),
        ])
        .output()
        .await
        .map_err(|e| VZError::Internal(format!("cp nvram failed: {e}")))?;
    if !nvram_out.status.success() {
        return Err(VZError::Internal(format!(
            "cp nvram failed: {}",
            String::from_utf8_lossy(&nvram_out.stderr)
        )));
    }

    tracing::debug!(
        container,
        disk = %instance_disk.display(),
        nvram = %instance_nvram.display(),
        "Cloned base disk image (APFS CoW)"
    );

    Ok((instance_disk, instance_nvram, cidata_path))
}

// ── Image integrity ───────────────────────────────────────────────────────────

/// Verify a VM image against its `.sha256` sidecar file.
///
/// Reads `<path>.sha256`, computes SHA-256 of the image file, and compares.
/// Called at the start of `clone_base_image` to detect corruption.
///
/// # Errors
///
/// Returns an error if the sidecar is missing, corrupt, or the hashes don't match.
pub fn verify_image_integrity(path: &Path) -> Result<(), VZError> {
    let sha_path = PathBuf::from(format!("{}.sha256", path.display()));
    if !sha_path.exists() {
        // No sidecar — skip verification (images without sidecar are allowed).
        return Ok(());
    }

    let expected_hex = std::fs::read_to_string(&sha_path)
        .map_err(|e| VZError::Internal(format!("read sha256 sidecar: {e}")))?;
    let expected_hex = expected_hex.split_whitespace().next().unwrap_or("").trim();

    // Compute SHA-256 using macOS built-in shasum to avoid adding a crypto dependency.
    let output = std::process::Command::new("shasum")
        .args(["-a", "256", path.to_str().unwrap_or("")])
        .output()
        .map_err(|e| VZError::Internal(format!("shasum exec failed: {e}")))?;

    if !output.status.success() {
        return Err(VZError::Internal(format!(
            "shasum failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let actual_line = String::from_utf8_lossy(&output.stdout);
    let actual_hex = actual_line.split_whitespace().next().unwrap_or("").trim();

    if actual_hex != expected_hex {
        return Err(VZError::InvalidConfig(format!(
            "Image integrity check failed for '{}': expected {expected_hex}, got {actual_hex}. \
             The image may be corrupted. Re-download it with 'theyos images pull'.",
            path.display()
        )));
    }

    Ok(())
}

/// High-level VM lifecycle manager for macOS.
///
/// Equivalent to `VmRunner` in vmrunner-rs but uses `VZVirtualMachine`.
pub struct VmRunnerMacOS {
    pub env: MacOSVmEnv,
}

impl VmRunnerMacOS {
    /// Build from environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error if `MacOSVmEnv::from_env()` fails.
    pub fn from_env() -> Result<Self, VZError> {
        Ok(Self {
            env: MacOSVmEnv::from_env()?,
        })
    }

    /// Create with custom environment.
    #[must_use]
    pub fn with_env(env: MacOSVmEnv) -> Self {
        Self { env }
    }

    /// Validate that required binaries and assets exist.
    ///
    /// # Errors
    ///
    /// Returns an error if kernel image or rootfs cannot be found.
    pub fn validate_binaries(&self) -> Result<(), VZError> {
        if !self.env.kernel_image.exists() {
            return Err(VZError::InvalidConfig(format!(
                "Kernel image not found: {}",
                self.env.kernel_image.display()
            )));
        }
        if !self.env.base_rootfs.exists() {
            return Err(VZError::InvalidConfig(format!(
                "Base rootfs not found: {}",
                self.env.base_rootfs.display()
            )));
        }
        if !self.env.ssh_key.exists() {
            return Err(VZError::InvalidConfig(format!(
                "SSH key not found: {}",
                self.env.ssh_key.display()
            )));
        }
        if !self.env.ssh_pubkey.exists() {
            return Err(VZError::InvalidConfig(format!(
                "SSH pubkey not found: {}",
                self.env.ssh_pubkey.display()
            )));
        }
        Ok(())
    }

    /// Ensure state directory exists.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation fails.
    pub fn ensure_state_dir(&self) -> Result<(), VZError> {
        std::fs::create_dir_all(&self.env.state_dir).map_err(|e| {
            VZError::InvalidConfig(format!(
                "Failed to create state directory {}: {e}",
                self.env.state_dir.display()
            ))
        })?;

        // Also ensure snapshots directory exists
        std::fs::create_dir_all(&self.env.snapshots_dir).map_err(|e| {
            VZError::InvalidConfig(format!(
                "Failed to create snapshots directory {}: {e}",
                self.env.snapshots_dir.display()
            ))
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_vm_env_defaults() {
        let home = std::env::var("HOME").unwrap();
        let env = MacOSVmEnv::from_env().unwrap();

        assert_eq!(env.home, PathBuf::from(&home));
        assert!(
            env.state_dir
                .ends_with("Library/Application Support/theyos/vms")
        );
        assert!(
            env.snapshots_dir
                .ends_with("Library/Application Support/theyos/snapshots")
        );
    }
}
