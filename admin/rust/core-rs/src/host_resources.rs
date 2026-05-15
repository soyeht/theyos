//! Host resource detection: CPU, RAM, and disk space.
//!
//! Platform-specific implementations for macOS (`sysctl`, `host_statistics64`, `statfs`)
//! and Linux (`sysconf`, `/proc/meminfo`, `statvfs`).
//!
//! All unsafe blocks call libc FFI functions with documented safety invariants.

use std::path::{Path, PathBuf};

/// Detected host resource snapshot.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostResources {
    pub cpu_cores: u32,
    pub total_ram_mb: u64,
    pub available_ram_mb: u64,
    pub available_disk_gb: u64,
    pub total_disk_gb: u64,
}

/// Errors from host resource detection.
#[derive(Debug, thiserror::Error)]
pub enum HostResourceError {
    #[error("failed to detect CPU cores: {0}")]
    Cpu(String),
    #[error("failed to detect RAM: {0}")]
    Ram(String),
    #[error("failed to detect disk space: {0}")]
    Disk(String),
}

/// Detect all host resources at once.
///
/// If `disk_path` doesn't exist, walks up to an existing ancestor for disk stats.
///
/// # Errors
/// Returns [`HostResourceError`] if CPU, RAM, or disk detection fails.
pub fn detect_all(disk_path: &Path) -> Result<HostResources, HostResourceError> {
    let cpu_cores = detect_cpu_cores()?;
    let total_ram_mb = detect_total_ram_mb()?;
    let available_ram_mb = detect_available_ram_mb()?;
    // Walk up to an existing directory if disk_path doesn't exist yet
    let effective_disk_path = {
        let mut p = disk_path.to_path_buf();
        while !p.exists() {
            if let Some(parent) = p.parent() {
                p = parent.to_path_buf();
            } else {
                break;
            }
        }
        p
    };
    let (available_disk_gb, total_disk_gb) = detect_disk_space(&effective_disk_path)?;
    Ok(HostResources {
        cpu_cores,
        total_ram_mb,
        available_ram_mb,
        available_disk_gb,
        total_disk_gb,
    })
}

/// Resolve the filesystem path where VM instance disks are stored.
/// Single source of truth for capacity checks and instance creation.
pub fn resolve_instance_disk_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        std::env::var("THEYOS_VM_STATE_DIR").map_or_else(
            |_| PathBuf::from(home).join("Library/Application Support/theyos/vms"),
            PathBuf::from,
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::env::var("FIRECRACKER_STATE_DIR").map_or_else(
            |_| PathBuf::from("/var/lib/theyos/firecracker"),
            PathBuf::from,
        )
    }
}

// ── CPU detection ────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
/// # Errors
/// Returns [`HostResourceError::Cpu`] if `sysctlbyname` fails.
pub fn detect_cpu_cores() -> Result<u32, HostResourceError> {
    let mut count: u32 = 0;
    let mut size = std::mem::size_of::<u32>();
    let name = b"hw.physicalcpu\0";
    // SAFETY: sysctlbyname is a libc function; we pass valid pointers and sizes.
    let ret = unsafe {
        libc::sysctlbyname(
            name.as_ptr().cast::<libc::c_char>(),
            (&raw mut count).cast::<libc::c_void>(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return Err(HostResourceError::Cpu(format!(
            "sysctlbyname hw.physicalcpu failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(count)
}

#[cfg(not(target_os = "macos"))]
#[allow(unsafe_code)]
/// # Errors
/// Returns [`HostResourceError::Cpu`] if `sysconf` fails.
pub fn detect_cpu_cores() -> Result<u32, HostResourceError> {
    // SAFETY: sysconf is a libc function with no pointer arguments.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n <= 0 {
        return Err(HostResourceError::Cpu(
            "sysconf _SC_NPROCESSORS_ONLN failed".into(),
        ));
    }
    u32::try_from(n).map_err(|_| HostResourceError::Cpu(format!("core count too large: {n}")))
}

// ── RAM detection ────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
/// # Errors
/// Returns [`HostResourceError::Ram`] if `sysctlbyname` fails.
pub fn detect_total_ram_mb() -> Result<u64, HostResourceError> {
    let mut memsize: u64 = 0;
    let mut size = std::mem::size_of::<u64>();
    let name = b"hw.memsize\0";
    // SAFETY: sysctlbyname is a libc function; we pass valid pointers and sizes.
    let ret = unsafe {
        libc::sysctlbyname(
            name.as_ptr().cast::<libc::c_char>(),
            (&raw mut memsize).cast::<libc::c_void>(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return Err(HostResourceError::Ram(format!(
            "sysctlbyname hw.memsize failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(memsize / (1024 * 1024))
}

#[cfg(not(target_os = "macos"))]
#[allow(unsafe_code)]
/// # Errors
/// Returns [`HostResourceError::Ram`] if `sysconf` fails.
pub fn detect_total_ram_mb() -> Result<u64, HostResourceError> {
    // SAFETY: sysconf is a libc function with no pointer arguments.
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
    if pages <= 0 || page_size <= 0 {
        return Err(HostResourceError::Ram(
            "sysconf failed for RAM detection".into(),
        ));
    }
    let pages = u64::try_from(pages)
        .map_err(|_| HostResourceError::Ram(format!("invalid page count from sysconf: {pages}")))?;
    let page_size = u64::try_from(page_size).map_err(|_| {
        HostResourceError::Ram(format!("invalid page size from sysconf: {page_size}"))
    })?;
    Ok((pages * page_size) / (1024 * 1024))
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
/// # Errors
/// Returns [`HostResourceError::Ram`] if `host_statistics64` fails.
pub fn detect_available_ram_mb() -> Result<u64, HostResourceError> {
    // On macOS, use vm_statistics64 via host_statistics64.
    // SAFETY: mach_host_self and host_statistics64 are mach kernel APIs.
    #[allow(deprecated)] // libc suggests mach2 crate, but libc works fine here
    unsafe {
        let host = libc::mach_host_self();
        let mut vm_stat: libc::vm_statistics64 = std::mem::zeroed();
        #[allow(clippy::cast_possible_truncation)]
        // ratio of two small struct sizes, always fits u32
        let mut count = (std::mem::size_of::<libc::vm_statistics64>()
            / std::mem::size_of::<libc::integer_t>())
            as libc::mach_msg_type_number_t;
        let ret = libc::host_statistics64(
            host,
            libc::HOST_VM_INFO64,
            (&raw mut vm_stat).cast::<libc::integer_t>(),
            &raw mut count,
        );
        if ret != libc::KERN_SUCCESS {
            return Err(HostResourceError::Ram(format!(
                "host_statistics64 failed: {ret}"
            )));
        }
        let page_size = libc::vm_page_size as u64;
        let free = (u64::from(vm_stat.free_count) + u64::from(vm_stat.inactive_count)) * page_size;
        Ok(free / (1024 * 1024))
    }
}

#[cfg(not(target_os = "macos"))]
/// # Errors
/// Returns [`HostResourceError::Ram`] if `/proc/meminfo` cannot be read.
pub fn detect_available_ram_mb() -> Result<u64, HostResourceError> {
    let content = std::fs::read_to_string("/proc/meminfo")
        .map_err(|e| HostResourceError::Ram(format!("read /proc/meminfo: {e}")))?;
    // Use MemAvailable if present (Linux 3.14+), else MemFree + Buffers + Cached.
    let mut mem_available = None;
    let mut mem_free = 0u64;
    let mut buffers = 0u64;
    let mut cached = 0u64;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            mem_available = parse_meminfo_kb(rest);
        } else if let Some(rest) = line.strip_prefix("MemFree:") {
            mem_free = parse_meminfo_kb(rest).unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Buffers:") {
            buffers = parse_meminfo_kb(rest).unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Cached:") {
            cached = parse_meminfo_kb(rest).unwrap_or(0);
        }
    }
    let kb = mem_available.unwrap_or(mem_free + buffers + cached);
    Ok(kb / 1024)
}

#[cfg(not(target_os = "macos"))]
fn parse_meminfo_kb(s: &str) -> Option<u64> {
    s.trim().strip_suffix("kB")?.trim().parse().ok()
}

// ── Disk detection ───────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
/// # Errors
/// Returns [`HostResourceError::Disk`] if `statfs` fails or the path is invalid.
pub fn detect_disk_space(path: &Path) -> Result<(u64, u64), HostResourceError> {
    use std::ffi::CString;
    let c_path = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|e| HostResourceError::Disk(format!("invalid path: {e}")))?;
    // SAFETY: statfs is a libc function; we pass a valid C string and pointer.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::statfs(c_path.as_ptr(), &raw mut stat) };
    if ret != 0 {
        return Err(HostResourceError::Disk(format!(
            "statfs failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let block_size = u64::from(stat.f_bsize);
    let available_gb = (stat.f_bavail * block_size) / (1024 * 1024 * 1024);
    let total_gb = (stat.f_blocks * block_size) / (1024 * 1024 * 1024);
    Ok((available_gb, total_gb))
}

#[cfg(not(target_os = "macos"))]
fn statvfs_field_to_u64<T>(value: T) -> u64
where
    T: TryInto<u64>,
{
    value.try_into().unwrap_or(0)
}

#[cfg(not(target_os = "macos"))]
#[allow(unsafe_code)]
/// # Errors
/// Returns [`HostResourceError::Disk`] if `statvfs` fails or the path is invalid.
pub fn detect_disk_space(path: &Path) -> Result<(u64, u64), HostResourceError> {
    use std::ffi::CString;
    let c_path = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|e| HostResourceError::Disk(format!("invalid path: {e}")))?;
    // SAFETY: statvfs is a libc function; we pass a valid C string and pointer.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::statvfs(c_path.as_ptr(), &raw mut stat) };
    if ret != 0 {
        return Err(HostResourceError::Disk(format!(
            "statvfs failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let available_blocks = statvfs_field_to_u64(stat.f_bavail);
    let total_blocks = statvfs_field_to_u64(stat.f_blocks);
    let fragment_size = statvfs_field_to_u64(stat.f_frsize);
    let available_gb = (available_blocks * fragment_size) / (1024 * 1024 * 1024);
    let total_gb = (total_blocks * fragment_size) / (1024 * 1024 * 1024);
    Ok((available_gb, total_gb))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_cpu_cores() {
        let cores = detect_cpu_cores().expect("detect_cpu_cores");
        assert!(cores > 0, "must have at least 1 CPU core");
    }

    #[test]
    fn test_detect_total_ram_mb() {
        let ram = detect_total_ram_mb().expect("detect_total_ram_mb");
        assert!(ram > 256, "must have more than 256 MB RAM, got {ram}");
    }

    #[test]
    fn test_detect_available_ram_mb() {
        let avail = detect_available_ram_mb().expect("detect_available_ram_mb");
        assert!(avail > 0, "must have some available RAM");
    }

    #[test]
    fn test_detect_disk_space() {
        let (avail, total) = detect_disk_space(Path::new("/tmp")).expect("detect_disk_space");
        assert!(total > 0, "total disk must be > 0");
        assert!(
            avail <= total,
            "available ({avail}) must be <= total ({total})"
        );
    }

    #[test]
    fn test_detect_all() {
        let res = detect_all(Path::new("/tmp")).expect("detect_all");
        assert!(res.cpu_cores > 0);
        assert!(res.total_ram_mb > 256);
        assert!(res.available_ram_mb > 0);
        assert!(res.total_disk_gb > 0);
        assert!(res.available_disk_gb <= res.total_disk_gb);
    }

    #[test]
    fn test_resolve_instance_disk_path() {
        let path = resolve_instance_disk_path();
        assert!(!path.as_os_str().is_empty());
    }
}
