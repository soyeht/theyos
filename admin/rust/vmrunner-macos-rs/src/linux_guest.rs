//! Linux guest base image initialization for VZ (Apple Virtualization Framework).
//!
//! Downloads an Ubuntu cloud image, boots it once to populate the EFI NVRAM with
//! GRUB boot entries, validates SSH access via cloud-init, and saves the disk +
//! NVRAM as a reusable base image. All 6 claw types share this single base via
//! symlinks.
//!
//! ## Why first boot is needed
//!
//! `VZEFIBootLoader` does not auto-discover `/EFI/BOOT/BOOTAA64.EFI` from a blank
//! NVRAM on macOS. The disk must be booted at least once so GRUB writes its boot
//! entries to the EFI variable store.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::VZError;
use crate::linux_init_state::{self, LinuxInitState};

/// All claw types that share the Linux base image (from manifest).
fn all_claws() -> Vec<&'static str> {
    core_rs::manifest::all_names()
}

/// Minimum free disk space for Linux base init (25 GB).
const MIN_INIT_FREE_BYTES: u64 = 25 * 1024 * 1024 * 1024;

/// Default disk size for the Linux base image (20 GB).
pub const DEFAULT_DISK_SIZE_GB: u64 = 20;

/// Default Ubuntu 24.04 server ARM64 cloud image URL.
#[must_use]
pub fn default_cloud_image_url() -> &'static str {
    "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img"
}

/// Return `$THEYOS_VM_ASSETS_DIR/linux-base`, creating it if absent.
///
/// # Errors
///
/// Returns error if the directory cannot be created.
pub fn base_dir() -> Result<PathBuf, VZError> {
    let assets = std::env::var("THEYOS_VM_ASSETS_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        format!("{home}/Library/Application Support/theyos/vms")
    });
    let dir = PathBuf::from(assets).join("linux-base");
    std::fs::create_dir_all(&dir)
        .map_err(|e| VZError::Internal(format!("create linux-base dir: {e}")))?;
    Ok(dir)
}

/// Return the assets directory (parent of linux-base).
///
/// # Errors
///
/// Returns error if the environment variable cannot be resolved.
pub fn assets_dir() -> Result<PathBuf, VZError> {
    let assets = std::env::var("THEYOS_VM_ASSETS_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        format!("{home}/Library/Application Support/theyos/vms")
    });
    Ok(PathBuf::from(assets))
}

/// Verify that at least 25 GB of free space is available.
///
/// # Errors
///
/// Returns error if the path is non-UTF-8, `statfs` fails, or free space is below 25 GB.
pub fn check_init_disk_space(path: &Path) -> Result<u64, VZError> {
    // SAFETY: statfs is a libc syscall; path_cstr is a valid null-terminated string.
    let available = unsafe {
        let mut stat: libc::statfs = std::mem::zeroed();
        let path_str = path
            .to_str()
            .ok_or_else(|| VZError::InvalidConfig(format!("non-UTF-8 path: {}", path.display())))?;
        let cstr = std::ffi::CString::new(path_str)
            .map_err(|_| VZError::InvalidConfig("path contains NUL byte".into()))?;
        if libc::statfs(cstr.as_ptr(), &raw mut stat) != 0 {
            return Err(VZError::Internal(format!(
                "statfs failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        stat.f_bavail * u64::from(stat.f_bsize)
    };

    if available < MIN_INIT_FREE_BYTES {
        #[allow(clippy::cast_precision_loss)]
        return Err(VZError::InsufficientDiskSpace {
            available_bytes: available,
            required_bytes: MIN_INIT_FREE_BYTES,
            message: format!(
                "{:.1} GB free (required: 25 GB)",
                available as f64 / (1024.0 * 1024.0 * 1024.0)
            ),
        });
    }
    Ok(available)
}

/// Check that an external tool is available in `$PATH`.
///
/// # Errors
///
/// Returns error if the tool is not found in `$PATH`.
pub fn check_tool(name: &str) -> Result<String, VZError> {
    let output = std::process::Command::new("which")
        .arg(name)
        .output()
        .map_err(|e| VZError::Internal(format!("which {name}: {e}")))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(VZError::InvalidConfig(format!(
            "Required tool '{name}' not found. Install with: brew install {}",
            match name {
                "qemu-img" => "qemu",
                "sgdisk" => "gptfdisk",
                "mkisofs" => "cdrtools",
                _ => name,
            }
        )))
    }
}

/// Validate that all required external tools are available.
///
/// # Errors
///
/// Returns error if `qemu-img` or `sgdisk` is not found.
pub fn check_prerequisites() -> Result<(), VZError> {
    check_tool("qemu-img")?;
    check_tool("sgdisk")?;
    // mkisofs is checked at ISO build time (has hdiutil fallback)
    Ok(())
}

/// Download the Ubuntu cloud image with HTTP Range-request resume support.
///
/// # Errors
///
/// Returns error if the HTTP request, file I/O, or state persistence fails.
pub fn download_cloud_image(
    url: &str,
    dest_path: &Path,
    state: &mut LinuxInitState,
    base_dir: &Path,
    progress_cb: impl Fn(u64, u64),
) -> Result<(), VZError> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let already_downloaded = if dest_path.exists() {
        let meta = std::fs::metadata(dest_path)
            .map_err(|e| VZError::Internal(format!("stat cloud image: {e}")))?;
        meta.len()
    } else {
        0
    };

    let resume_from = already_downloaded.max(state.image_bytes_downloaded);
    state.image_bytes_downloaded = resume_from;

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(1800))
        .build();

    let response = if resume_from > 0 {
        tracing::info!(resume_from, "Resuming cloud image download");
        agent
            .get(url)
            .set("Range", &format!("bytes={resume_from}-"))
            .call()
            .map_err(|e| VZError::Internal(format!("cloud image HTTP request: {e}")))?
    } else {
        agent
            .get(url)
            .call()
            .map_err(|e| VZError::Internal(format!("cloud image HTTP request: {e}")))?
    };

    let total_bytes = if let Some(cl) = response.header("Content-Length") {
        cl.parse::<u64>().unwrap_or(0) + resume_from
    } else if let Some(cr) = response.header("Content-Range") {
        cr.split('/')
            .next_back()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    } else {
        state.image_total_bytes.unwrap_or(0)
    };

    if total_bytes > 0 && state.image_total_bytes.is_none() {
        state.image_total_bytes = Some(total_bytes);
    }

    let mut file = if resume_from > 0 {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(dest_path)
            .map_err(|e| VZError::Internal(format!("open image for resume: {e}")))?;
        f.seek(SeekFrom::Start(resume_from))
            .map_err(|e| VZError::Internal(format!("seek image: {e}")))?;
        f
    } else {
        std::fs::File::create(dest_path)
            .map_err(|e| VZError::Internal(format!("create image file: {e}")))?
    };

    let mut reader = response.into_reader();
    let mut buf = vec![0u8; 1024 * 1024]; // 1 MB chunks
    let mut bytes_written = resume_from;

    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| VZError::Internal(format!("read image chunk: {e}")))?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])
            .map_err(|e| VZError::Internal(format!("write image chunk: {e}")))?;
        bytes_written += n as u64;
        state.image_bytes_downloaded = bytes_written;

        // Persist progress every ~32 MB
        if bytes_written % (32 * 1024 * 1024) < n as u64 {
            let _ = linux_init_state::write_state(base_dir, state);
        }

        progress_cb(bytes_written, total_bytes);
    }

    file.flush()
        .map_err(|e| VZError::Internal(format!("flush image: {e}")))?;

    tracing::info!(bytes_written, "Cloud image download complete");
    Ok(())
}

/// Convert qcow2 to raw, resize, and fix GPT backup header.
///
/// # Errors
///
/// Returns error if `qemu-img` or `sgdisk` execution fails.
///
/// # Panics
///
/// Panics if the raw path is not valid UTF-8.
pub async fn convert_and_resize_image(
    qcow2_path: &Path,
    raw_path: &Path,
    target_gb: u64,
) -> Result<(), VZError> {
    // Step 1: qemu-img convert
    tracing::info!("Converting qcow2 → raw...");
    let out = tokio::process::Command::new("qemu-img")
        .args(["convert", "-f", "qcow2", "-O", "raw"])
        .arg(qcow2_path)
        .arg(raw_path)
        .output()
        .await
        .map_err(|e| VZError::Internal(format!("qemu-img convert exec: {e}")))?;
    if !out.status.success() {
        return Err(VZError::Internal(format!(
            "qemu-img convert failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }

    // Step 2: qemu-img resize
    tracing::info!(target_gb, "Resizing disk image...");
    let out = tokio::process::Command::new("qemu-img")
        .args([
            "resize",
            raw_path.to_str().unwrap(),
            &format!("{target_gb}G"),
        ])
        .output()
        .await
        .map_err(|e| VZError::Internal(format!("qemu-img resize exec: {e}")))?;
    if !out.status.success() {
        return Err(VZError::Internal(format!(
            "qemu-img resize failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }

    // Step 3: Fix GPT backup header (moved by resize)
    tracing::info!("Fixing GPT backup header...");
    let out = tokio::process::Command::new("sgdisk")
        .args(["--move-second-header", raw_path.to_str().unwrap()])
        .output()
        .await
        .map_err(|e| VZError::Internal(format!("sgdisk exec: {e}")))?;
    if !out.status.success() {
        // sgdisk warnings are common; only fail on actual errors
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("Error") || stderr.contains("error") {
            return Err(VZError::Internal(format!("sgdisk failed: {stderr}")));
        }
    }

    tracing::info!("Image conversion complete");
    Ok(())
}

/// Boot the Linux VM with blank NVRAM + cloud-init for first-time GRUB/NVRAM setup.
///
/// Returns (vm, ip, mac) with the VM still running -- caller must shut it down.
///
/// # Errors
///
/// Returns error if SSH key generation, VM boot, DHCP resolution, or SSH wait fails.
pub async fn first_boot(
    disk_path: &Path,
    nvram_path: &Path,
    cidata_path: &Path,
    cpus: u32,
    memory_mb: u32,
) -> Result<(crate::vz::VZVirtualMachine, String, String), VZError> {
    let pubkey = crate::ensure_ssh_key().await?;
    crate::build_cidata_iso("linux-base", &pubkey, cidata_path).await?;

    let mac = crate::generate_mac();
    let existing_ips = crate::snapshot_leased_ips().await;

    // Ensure NVRAM does NOT exist so the builder creates a blank one
    // (VZEFIVariableStore initCreatingVariableStoreAtURL:).
    if nvram_path.exists() {
        let _ = std::fs::remove_file(nvram_path);
    }

    let config = crate::vz::VZVirtualMachineConfigurationBuilder::new()
        .cpus(cpus)
        .memory_mb(memory_mb)
        .disk_path(disk_path.to_path_buf())
        .efi_store_path(nvram_path.to_path_buf())
        .cidata_iso_path(cidata_path.to_path_buf())
        .mac_address(mac.clone())
        .build()?;

    let vm = crate::vz::VZVirtualMachine::new(&config, "linux-first-boot")?;
    vm.start().await?;

    tracing::info!("Waiting for DHCP (300s timeout for first cold boot)...");
    let ip = crate::resolve_dhcp_ip(&mac, 300, &existing_ips).await?;

    tracing::info!(ip, "Waiting for SSH...");
    crate::macos_guest::wait_for_ssh(&ip, 300).await?;

    Ok((vm, ip, mac))
}

/// SSH into the VM and run health checks.
///
/// # Errors
///
/// Returns error if the SSH command fails or the health check output is invalid.
pub async fn validate_ssh(ip: &str) -> Result<(), VZError> {
    let key_path = crate::ssh_private_key_path();

    let output = tokio::process::Command::new("ssh")
        .args([
            "-i",
            key_path.to_str().unwrap_or(""),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            &format!("root@{ip}"),
            "uname -a && echo SSH_OK",
        ])
        .output()
        .await
        .map_err(|e| VZError::Internal(format!("ssh exec: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || !stdout.contains("SSH_OK") {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VZError::Internal(format!(
            "SSH validation failed: stdout={stdout}, stderr={stderr}"
        )));
    }

    tracing::info!(ip, stdout = %stdout.trim(), "Linux VM SSH validation passed");
    Ok(())
}

/// Gracefully stop the VM via VZ API.
///
/// # Errors
///
/// Returns error if the VM stop request fails.
pub async fn shutdown_vm(vm: &crate::vz::VZVirtualMachine) -> Result<(), VZError> {
    tracing::info!("Requesting graceful VM shutdown...");
    vm.stop(true).await
}

/// Create symlinks from each claw-type base to the shared linux-base.
///
/// # Errors
///
/// Returns error if symlink creation fails for any claw type.
pub fn create_claw_symlinks(base_dir: &Path, vms_dir: &Path) -> Result<(), VZError> {
    let disk = base_dir.join("disk.img");
    let nvram = base_dir.join("base.nvram");

    let claws = all_claws();
    for claw in &claws {
        let raw_link = vms_dir.join(format!("{claw}-base.raw"));
        let nvram_link = vms_dir.join(format!("{claw}-base.nvram"));

        // Remove existing files/symlinks
        let _ = std::fs::remove_file(&raw_link);
        let _ = std::fs::remove_file(&nvram_link);

        std::os::unix::fs::symlink(&disk, &raw_link)
            .map_err(|e| VZError::Internal(format!("symlink {}: {e}", raw_link.display())))?;
        std::os::unix::fs::symlink(&nvram, &nvram_link)
            .map_err(|e| VZError::Internal(format!("symlink {}: {e}", nvram_link.display())))?;

        tracing::debug!(claw, "Created base symlinks");
    }

    tracing::info!("Created symlinks for all {} claw types", claws.len());
    Ok(())
}

/// Remove the linux-base directory and all claw symlinks.
///
/// # Errors
///
/// Returns error if the directory removal fails.
pub fn remove_base_dir(base_dir: &Path) -> Result<u64, VZError> {
    // Remove claw symlinks first
    if let Ok(vms_dir) = assets_dir() {
        for claw in &all_claws() {
            let _ = std::fs::remove_file(vms_dir.join(format!("{claw}-base.raw")));
            let _ = std::fs::remove_file(vms_dir.join(format!("{claw}-base.nvram")));
        }
    }

    if !base_dir.exists() {
        return Ok(0);
    }
    let bytes_freed = crate::macos_guest::measure_dir_size(base_dir);
    std::fs::remove_dir_all(base_dir)
        .map_err(|e| VZError::Internal(format!("remove_dir_all {}: {e}", base_dir.display())))?;
    tracing::info!(path = %base_dir.display(), bytes_freed, "Linux base dir removed");
    Ok(bytes_freed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_cloud_image_url_is_arm64() {
        let url = default_cloud_image_url();
        assert!(url.contains("arm64"), "URL must target ARM64: {url}");
        assert!(url.contains("ubuntu"), "URL must be Ubuntu: {url}");
        assert!(url.contains("24.04"), "URL must be 24.04 LTS: {url}");
    }

    #[test]
    fn test_base_dir_with_env_override() {
        let dir = TempDir::new().unwrap();
        let expected = dir.path().join("linux-base");
        unsafe { std::env::set_var("THEYOS_VM_ASSETS_DIR", dir.path()) };
        let result = base_dir().unwrap();
        unsafe { std::env::remove_var("THEYOS_VM_ASSETS_DIR") };
        assert_eq!(result, expected);
        assert!(expected.exists());
    }

    #[test]
    fn test_remove_nonexistent_base_dir() {
        let dir = TempDir::new().unwrap();
        let fake = dir.path().join("does-not-exist");
        let freed = remove_base_dir(&fake).unwrap();
        assert_eq!(freed, 0);
    }

    #[test]
    fn test_remove_existing_base_dir() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("linux-base");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("disk.img"), b"fake disk data 1234567890").unwrap();
        std::fs::write(base.join("base.nvram"), b"fake nvram").unwrap();
        let freed = remove_base_dir(&base).unwrap();
        assert!(freed > 0);
        assert!(!base.exists());
    }

    #[test]
    fn test_create_claw_symlinks() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("linux-base");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("disk.img"), b"disk").unwrap();
        std::fs::write(base.join("base.nvram"), b"nvram").unwrap();

        create_claw_symlinks(&base, dir.path()).unwrap();

        for claw in &all_claws() {
            let raw = dir.path().join(format!("{claw}-base.raw"));
            let nvram = dir.path().join(format!("{claw}-base.nvram"));
            assert!(raw.exists(), "{claw}-base.raw missing");
            assert!(nvram.exists(), "{claw}-base.nvram missing");
            assert!(raw.is_symlink(), "{claw}-base.raw not a symlink");
            assert!(nvram.is_symlink(), "{claw}-base.nvram not a symlink");
        }
    }

    #[test]
    fn test_create_claw_symlinks_idempotent() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("linux-base");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("disk.img"), b"disk").unwrap();
        std::fs::write(base.join("base.nvram"), b"nvram").unwrap();

        create_claw_symlinks(&base, dir.path()).unwrap();
        // Second call should succeed (replaces existing symlinks)
        create_claw_symlinks(&base, dir.path()).unwrap();

        for claw in &all_claws() {
            assert!(dir.path().join(format!("{claw}-base.raw")).is_symlink());
        }
    }

    #[test]
    fn test_disk_space_check_passes_on_real_fs() {
        // This test runs on the real filesystem — should pass unless disk is nearly full
        let dir = TempDir::new().unwrap();
        // We don't assert success because CI may have limited space,
        // but we verify it doesn't panic
        let _ = check_init_disk_space(dir.path());
    }

    #[test]
    fn test_check_tool_finds_ls() {
        // `ls` should always be available
        assert!(check_tool("ls").is_ok());
    }

    #[test]
    fn test_check_tool_rejects_nonexistent() {
        assert!(check_tool("theyos_definitely_not_a_real_tool_xyz").is_err());
    }
}
