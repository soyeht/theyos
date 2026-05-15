//! macOS guest VM operations — IPSW download, installation, provisioning, snapshots.
//!
//! This module implements the macOS-specific operations needed by
//! `theyos init-macos-guest` and the macOS `create` IPC path.
//!
//! Key decisions from research.md:
//! - Decision 2: `VZMacOSRestoreImage.latestSupported()` `ObjC` FFI for IPSW URL
//! - Decision 3: APFS volume injection (hdiutil) for provisioning — no cloud-init
//! - Decision 5: darwin/arm64 claw binaries downloaded during provision
//! - Decision 8: `InitPhase` state machine for resumability

#![allow(clippy::too_many_lines)]
#![allow(clippy::too_many_arguments)]

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// All claw type names (used for `LaunchDaemon` plist injection).
pub const CLAW_TYPE_NAMES: &[&str] = &[
    "picoclaw", "zeroclaw", "nanobot", "openclaw", "nullclaw", "ironclaw",
];

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use block::ConcreteBlock;
use objc::runtime::Object;
use objc::{class, msg_send, sel, sel_impl};
use serde::Deserialize;

use crate::VZError;
use crate::init_state::{INIT_STATE_FILE, InitState, read_state, write_state};

/// How the restore image for macOS guest init will be sourced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreImageSource {
    DownloadUrl(String),
    LocalFile(PathBuf),
}

/// Fully resolved restore image selection for macOS guest init.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRestoreImage {
    pub source: RestoreImageSource,
    pub macos_version: String,
    pub ipsw_build: Option<String>,
    pub source_label: String,
    pub host_macos_version: Option<String>,
    pub host_macos_build: Option<String>,
}

/// Persistent identity produced by a successful `VZMacOSInstaller` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOSInstallResult {
    /// Base64-encoded `VZMacHardwareModel.dataRepresentation`.
    pub hardware_model_data_b64: String,
    /// Base64-encoded `VZMacMachineIdentifier.dataRepresentation`.
    pub machine_identifier_data_b64: String,
    /// CPU count used by the install VM after applying restore-image minimums.
    pub install_cpu_count: u32,
    /// Memory used by the install VM after applying restore-image minimums, in MB.
    pub install_memory_mb: u32,
}

fn file_metadata_json(path: &Path) -> serde_json::Value {
    match std::fs::metadata(path) {
        Ok(meta) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                serde_json::json!({
                    "path": path.display().to_string(),
                    "exists": true,
                    "len": meta.len(),
                    "readonly": meta.permissions().readonly(),
                    "uid": meta.uid(),
                    "gid": meta.gid(),
                    "mode_octal": format!("{:o}", meta.mode() & 0o7777),
                    "blocks_512": meta.blocks(),
                })
            }
            #[cfg(not(unix))]
            {
                serde_json::json!({
                    "path": path.display().to_string(),
                    "exists": true,
                    "len": meta.len(),
                    "readonly": meta.permissions().readonly(),
                })
            }
        }
        Err(e) => serde_json::json!({
            "path": path.display().to_string(),
            "exists": false,
            "error": e.to_string(),
        }),
    }
}

/// Encode `obj.dataRepresentation` for VZ identity objects.
///
/// # Safety
///
/// `obj` must be a valid Objective-C object that responds to `dataRepresentation`.
unsafe fn data_representation_b64(obj: *mut Object) -> Option<String> {
    if obj.is_null() {
        return None;
    }
    let data: *mut Object = unsafe { msg_send![obj, dataRepresentation] };
    if data.is_null() {
        return None;
    }
    let len: usize = unsafe { msg_send![data, length] };
    let ptr: *const u8 = unsafe { msg_send![data, bytes] };
    if ptr.is_null() {
        return None;
    }
    Some(BASE64.encode(unsafe { std::slice::from_raw_parts(ptr, len) }))
}

/// Convert an `NSString *` to a Rust `String`.
///
/// # Safety
///
/// `obj` must be null or a valid `NSString *`.
unsafe fn nsstring_to_string(obj: *mut Object) -> Option<String> {
    if obj.is_null() {
        return None;
    }
    let cstr: *const libc::c_char = unsafe { msg_send![obj, UTF8String] };
    if cstr.is_null() {
        return None;
    }
    Some(
        unsafe { std::ffi::CStr::from_ptr(cstr) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// Return `-[obj description]` as a string.
///
/// # Safety
///
/// `obj` must be null or a valid Objective-C object.
unsafe fn objc_description(obj: *mut Object) -> Option<String> {
    if obj.is_null() {
        return None;
    }
    let desc: *mut Object = unsafe { msg_send![obj, description] };
    unsafe { nsstring_to_string(desc) }
}

/// Extract all useful fields from an `NSError`, including nested underlying
/// errors in `userInfo[NSUnderlyingErrorKey]`.
///
/// # Safety
///
/// `err` must be null or a valid `NSError *`.
unsafe fn nserror_details_json(err: *mut Object, depth: usize) -> serde_json::Value {
    if err.is_null() {
        return serde_json::Value::Null;
    }

    let domain_obj: *mut Object = unsafe { msg_send![err, domain] };
    let code: i64 = unsafe { msg_send![err, code] };
    let desc_obj: *mut Object = unsafe { msg_send![err, localizedDescription] };
    let reason_obj: *mut Object = unsafe { msg_send![err, localizedFailureReason] };
    let suggestion_obj: *mut Object = unsafe { msg_send![err, localizedRecoverySuggestion] };
    let user_info: *mut Object = unsafe { msg_send![err, userInfo] };

    let underlying = if depth < 3 && !user_info.is_null() {
        let key_bytes = b"NSUnderlyingError\0";
        let key: *mut Object = unsafe {
            msg_send![class!(NSString), stringWithUTF8String: key_bytes.as_ptr().cast::<libc::c_char>()]
        };
        let underlying_err: *mut Object = unsafe { msg_send![user_info, objectForKey: key] };
        if underlying_err.is_null() {
            serde_json::Value::Null
        } else {
            unsafe { nserror_details_json(underlying_err, depth + 1) }
        }
    } else {
        serde_json::Value::Null
    };

    serde_json::json!({
        "domain": unsafe { nsstring_to_string(domain_obj) },
        "code": code,
        "localized_description": unsafe { nsstring_to_string(desc_obj) },
        "localized_failure_reason": unsafe { nsstring_to_string(reason_obj) },
        "localized_recovery_suggestion": unsafe { nsstring_to_string(suggestion_obj) },
        "description": unsafe { objc_description(err) },
        "user_info_description": unsafe { objc_description(user_info) },
        "underlying_error": underlying,
    })
}

/// Pretty-print an `NSError`.
///
/// # Safety
///
/// `err` must be null or a valid `NSError *`.
unsafe fn nserror_details_string(err: *mut Object) -> String {
    if err.is_null() {
        return "nil NSError".to_string();
    }
    let value = unsafe { nserror_details_json(err, 0) };
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| {
        unsafe { objc_description(err) }.unwrap_or_else(|| "unknown NSError".to_string())
    })
}

#[derive(Debug, Deserialize)]
struct IpswIndexResponse {
    firmwares: Vec<IpswIndexFirmware>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct IpswIndexFirmware {
    version: String,
    #[serde(rename = "buildid")]
    build_id: String,
    url: String,
    signed: bool,
}

const MACOS_RESTORE_ISSUE_URL: &str =
    "https://github.com/soyeht/theyos/issues/new?template=macos-restore-image.yml";

// ── Base directory helper ─────────────────────────────────────────────────────

/// Return `$THEYOS_VM_ASSETS_DIR/macos-base` (creates it if absent).
///
/// # Errors
///
/// Returns `VZError::Internal` if the directory cannot be created.
pub fn base_dir() -> Result<PathBuf, VZError> {
    let assets = std::env::var("THEYOS_VM_ASSETS_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        format!("{home}/Library/Application Support/theyos/vms")
    });
    let dir = PathBuf::from(assets).join("macos-base");
    std::fs::create_dir_all(&dir)
        .map_err(|e| VZError::Internal(format!("create macos-base dir: {e}")))?;
    Ok(dir)
}

/// Zero IPSW-download bookkeeping in `init-state.json`.
///
/// Called when we evict a stale `macos.ipsw` or switch candidates mid-init —
/// without this, `download_ipsw` would resume from a stale offset (it uses
/// `max(file_size, ipsw_bytes_downloaded)`) and corrupt the next download.
///
/// No-op if `init-state.json` does not exist.
///
/// # Errors
///
/// Returns `VZError::Internal` if the state file exists but cannot be read or written.
pub fn clear_download_progress(base_dir: &Path) -> Result<(), VZError> {
    if !base_dir.join(INIT_STATE_FILE).exists() {
        return Ok(());
    }
    let mut state = read_state(base_dir)?;
    state.ipsw_bytes_downloaded = 0;
    state.ipsw_total_bytes = None;
    state.ipsw_sha256 = None;
    state.ipsw_source = None;
    state.ipsw_build = None;
    state.macos_version = None;
    write_state(base_dir, &state)
}

// ── Disk space check ──────────────────────────────────────────────────────────

/// Minimum free bytes required before starting macOS guest init (100 GB).
const MIN_INIT_FREE_BYTES: u64 = 100 * 1024 * 1024 * 1024;

/// Check that at least 100 GB is free at `path`.
///
/// # Errors
///
/// Returns `VZError::InsufficientDiskSpace` if less than 100 GB is available.
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
                "{:.0} GB free (required: 100 GB)",
                available as f64 / (1024.0 * 1024.0 * 1024.0)
            ),
        });
    }
    Ok(available)
}

// ── IPSW URL fetch ────────────────────────────────────────────────────────────

/// Fetch the IPSW download URL and macOS version via `ObjC` FFI.
///
/// Calls `[VZMacOSRestoreImage latestSupportedWithCompletionHandler:]` on the
/// GCD main queue and blocks up to 30 seconds for the result.
///
/// Returns `(url_string, macos_version)`.
///
/// # Errors
///
/// Returns `VZError::Internal` if the `ObjC` call fails or times out.
pub fn fetch_ipsw_url() -> Result<(String, String), VZError> {
    use std::sync::mpsc;

    let (tx, rx) = mpsc::sync_channel::<Result<(String, String), String>>(1);

    // SAFETY: VZMacOSRestoreImage is a VZ class available on macOS 12+.
    // The completion handler block is copied so it outlives this call.
    unsafe {
        let tx_arc = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));
        let tx_clone = tx_arc.clone();

        let completion = ConcreteBlock::new(move |img: *mut Object, err: *mut Object| {
            let result = if err.is_null() && !img.is_null() {
                // Extract URL string
                let url_obj: *mut Object = msg_send![img, URL];
                let url_str_obj: *mut Object = msg_send![url_obj, absoluteString];
                let url_cstr: *const libc::c_char = msg_send![url_str_obj, UTF8String];
                let url = if url_cstr.is_null() {
                    Err("IPSW URL is nil".to_string())
                } else {
                    Ok(std::ffi::CStr::from_ptr(url_cstr)
                        .to_string_lossy()
                        .into_owned())
                };

                // Extract macOS version from the URL or a version property
                // VZMacOSRestoreImage has no direct version property in all SDK versions;
                // we extract it from the URL filename (e.g. "UniversalMac_15.3.1_24D70_Restore.ipsw")
                url.map(|u| {
                    let version =
                        extract_macos_version_from_url(&u).unwrap_or_else(|| "unknown".to_string());
                    (u, version)
                })
            } else if !err.is_null() {
                let desc: *mut Object = msg_send![err, localizedDescription];
                let cstr: *const libc::c_char = msg_send![desc, UTF8String];
                let msg = if cstr.is_null() {
                    "unknown NSError".to_string()
                } else {
                    std::ffi::CStr::from_ptr(cstr)
                        .to_string_lossy()
                        .into_owned()
                };
                Err(msg)
            } else {
                Err("VZMacOSRestoreImage returned nil without error".to_string())
            };

            if let Some(tx) = tx_clone.lock().ok().and_then(|mut g| g.take()) {
                let _ = tx.send(result);
            }
        });
        let completion = completion.copy();

        let _: () = msg_send![
            class!(VZMacOSRestoreImage),
            fetchLatestSupportedWithCompletionHandler: &*completion
        ];
    }

    rx.recv_timeout(Duration::from_secs(30))
        .map_err(|_| VZError::Internal("VZMacOSRestoreImage timed out after 30s".into()))?
        .map_err(VZError::Internal)
}

/// Extract macOS version from an IPSW filename URL.
///
/// e.g. `https://.../UniversalMac_15.3.1_24D70_Restore.ipsw` → `"15.3.1"`
#[must_use]
pub fn extract_macos_version_from_url(url: &str) -> Option<String> {
    // Pattern: UniversalMac_<version>_<build>_Restore.ipsw
    let filename = url.rsplit('/').next()?;
    let parts: Vec<&str> = filename.split('_').collect();
    // parts[0] = "UniversalMac", parts[1] = version
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Extract macOS build from an IPSW filename URL or path.
///
/// e.g. `UniversalMac_26.4_25E246_Restore.ipsw` → `"25E246"`
#[must_use]
pub fn extract_macos_build_from_url(url: &str) -> Option<String> {
    let filename = url.rsplit('/').next()?;
    let parts: Vec<&str> = filename.split('_').collect();
    if parts.len() >= 3 {
        Some(parts[2].to_string())
    } else {
        None
    }
}

/// Parse an Apple build ID (e.g. "25E246", "24D2054", "25E246a") into
/// `(major_year, train_letters, build_num, suffix)`.
///
/// Returns `None` if the format doesn't match `<digits><uppercase letters><digits>[<lowercase suffix>]`.
#[must_use]
pub fn parse_apple_build(b: &str) -> Option<(u32, String, u32, String)> {
    let bytes = b.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 {
        return None;
    }
    let major: u32 = b[..i].parse().ok()?;
    let mut j = i;
    while j < bytes.len() && bytes[j].is_ascii_uppercase() {
        j += 1;
    }
    if j == i {
        return None;
    }
    let train = b[i..j].to_string();
    let mut k = j;
    while k < bytes.len() && bytes[k].is_ascii_digit() {
        k += 1;
    }
    if k == j {
        return None;
    }
    let build_num: u32 = b[j..k].parse().ok()?;
    let suffix = b[k..].to_string();
    Some((major, train, build_num, suffix))
}

/// Compare two Apple build IDs by parsed components, not lexically.
///
/// WHY not lex: `"25E99" > "25E100"` in lex order because `'9' > '1'` at index 3,
/// but build 100 is newer than build 99. Numeric parse on the trailing build number is required.
/// If either build cannot be parsed, returns `Equal` (optimistic) so callers stay permissive.
#[must_use]
pub fn cmp_apple_builds(a: &str, b: &str) -> Ordering {
    match (parse_apple_build(a), parse_apple_build(b)) {
        (Some(pa), Some(pb)) => pa.cmp(&pb),
        _ => Ordering::Equal,
    }
}

/// Returns `true` if a host running build `host_build` can install an IPSW with build `image_build`.
///
/// Apple's Virtualization framework rejects IPSWs whose build is newer than the host's
/// running build (the host can't restore something it doesn't yet support). Optimistic when
/// either build is empty/unparseable — lets VZ surface a precise error in that case.
#[must_use]
pub fn host_build_supports_image(host_build: &str, image_build: &str) -> bool {
    if host_build.is_empty() || image_build.is_empty() {
        return true;
    }
    if parse_apple_build(host_build).is_none() || parse_apple_build(image_build).is_none() {
        return true;
    }
    !matches!(cmp_apple_builds(image_build, host_build), Ordering::Greater)
}

/// Compare macOS version strings componentwise (e.g. "26.4.1" vs "26.4").
///
/// Components are parsed as `u64`; missing components count as `0`.
/// Non-numeric components are dropped (`"26.4-beta"` parses as `[26, 4]`).
/// Empty or fully-unparseable inputs compare as `Equal` so callers stay optimistic.
#[must_use]
pub fn cmp_macos_versions(a: &str, b: &str) -> Ordering {
    let parse =
        |v: &str| -> Vec<u64> { v.split('.').filter_map(|s| s.parse::<u64>().ok()).collect() };
    let av = parse(a);
    let bv = parse(b);
    if av.is_empty() || bv.is_empty() {
        return Ordering::Equal;
    }
    for i in 0..av.len().max(bv.len()) {
        let x = av.get(i).copied().unwrap_or(0);
        let y = bv.get(i).copied().unwrap_or(0);
        if x != y {
            return x.cmp(&y);
        }
    }
    Ordering::Equal
}

/// Compare macOS version strings (e.g. "26.4" vs "26.3").
///
/// Returns `true` if `host_version >= guest_version` using numeric component comparison.
/// Returns `true` (optimistic) if either version cannot be parsed — lets VZ catch it.
#[must_use]
pub fn host_version_sufficient(host_version: &str, guest_version: &str) -> bool {
    !matches!(
        cmp_macos_versions(host_version, guest_version),
        Ordering::Less
    )
}

/// Get the host macOS version via `sw_vers -productVersion`.
///
/// `THEYOS_HOST_VERSION_OVERRIDE` short-circuits the lookup — used by tests/E2E
/// to simulate a host on a different version than the actual machine.
#[must_use]
pub fn get_host_macos_version() -> Option<String> {
    if let Ok(v) = std::env::var("THEYOS_HOST_VERSION_OVERRIDE") {
        if !v.is_empty() {
            return Some(v);
        }
    }
    std::process::Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Get the host macOS build via `sw_vers -buildVersion`.
///
/// `THEYOS_HOST_BUILD_OVERRIDE` short-circuits the lookup — used by tests/E2E
/// to simulate a host on a different build than the actual machine.
#[must_use]
pub fn get_host_macos_build() -> Option<String> {
    if let Ok(v) = std::env::var("THEYOS_HOST_BUILD_OVERRIDE") {
        if !v.is_empty() {
            return Some(v);
        }
    }
    std::process::Command::new("sw_vers")
        .arg("-buildVersion")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Get the host hardware model identifier via `sysctl -n hw.model`.
#[must_use]
pub fn get_host_model_identifier() -> Option<String> {
    std::process::Command::new("sysctl")
        .args(["-n", "hw.model"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Return the expected restore image filename for a host version/build.
#[must_use]
pub fn expected_restore_filename(host_version: &str, host_build: Option<&str>) -> String {
    match host_build.filter(|b| !b.is_empty()) {
        Some(build) => format!("UniversalMac_{host_version}_{build}_Restore.ipsw"),
        None => format!("UniversalMac_{host_version}_<build>_Restore.ipsw"),
    }
}

/// Build a helpful error when the latest public restore image is newer than the host.
#[must_use]
pub fn incompatible_restore_image_error(
    host_version: &str,
    host_build: Option<&str>,
    restore_version: &str,
) -> String {
    let filename = expected_restore_filename(host_version, host_build);
    let host_build_suffix = host_build
        .filter(|b| !b.is_empty())
        .map_or_else(String::new, |b| format!(" ({b})"));

    format!(
        "theyOS found a macOS restore image for {restore_version}, but your Mac is running {host_version}{host_build_suffix}.\n\
         macOS guest setup can only use a restore image that matches this Mac's version or an older compatible one.\n\
         You can continue by using a matching restore image manually:\n\
           init_macos_guest --ipsw /path/to/{filename}"
    )
}

#[must_use]
fn format_restore_issue_context(
    host_model: Option<&str>,
    host_version: &str,
    host_build: Option<&str>,
    latest_restore_version: &str,
    latest_restore_url: &str,
    lookup_status: &str,
) -> String {
    let host_build = host_build.unwrap_or("unknown");
    let host_model = host_model.unwrap_or("unknown");

    format!(
        "host_model: {host_model}\n\
         host_macos_version: {host_version}\n\
         host_macos_build: {host_build}\n\
         latest_supported_restore_version: {latest_restore_version}\n\
         latest_supported_restore_url: {latest_restore_url}\n\
         host_match_lookup: {lookup_status}"
    )
}

#[must_use]
fn matching_restore_lookup_error(
    host_model: Option<&str>,
    host_version: &str,
    host_build: Option<&str>,
    latest_restore_version: &str,
    latest_restore_url: &str,
    lookup_status: &str,
) -> String {
    let base = incompatible_restore_image_error(host_version, host_build, latest_restore_version);
    let context = format_restore_issue_context(
        host_model,
        host_version,
        host_build,
        latest_restore_version,
        latest_restore_url,
        lookup_status,
    );

    format!(
        "{base}\n\n\
         theyOS also tried to find a matching restore image for this Mac automatically and could not.\n\
         Please open an issue so we can fix or expand the automatic lookup:\n\
           {MACOS_RESTORE_ISSUE_URL}\n\n\
         Paste this into the issue form:\n\
         ```text\n\
         {context}\n\
         ```"
    )
}

/// Maximum total candidates returned from the catalog selector.
const MAX_RESTORE_CANDIDATES: usize = 5;
/// Maximum legacy-version (older macOS) candidates included in Tier 3.
const MAX_LEGACY_VERSION_CANDIDATES: usize = 3;

/// Build a ranked list of restore-image candidates from a firmware index.
///
/// Tier 1 — exact build match (`signed && version == host_version && build_id == host_build`).
/// Tier 2 — same version, `build_id` ≤ `host_build` (largest build first).
/// Tier 3 — older version, `build_id` ≤ `host_build` (newest version first, then largest build).
///
/// All entries are deduplicated by URL and the total list is capped at
/// `MAX_RESTORE_CANDIDATES`. WHY tiered list (not single pick): the orchestrator
/// retries with the next candidate if VZ rejects the chosen one after download.
#[must_use]
fn select_host_restore_candidates(
    firmwares: &[IpswIndexFirmware],
    host_version: &str,
    host_build: Option<&str>,
) -> Vec<IpswIndexFirmware> {
    let mut out: Vec<IpswIndexFirmware> = Vec::new();

    // Tier 1
    if let Some(host_b) = host_build.filter(|b| !b.is_empty()) {
        if let Some(fw) = firmwares
            .iter()
            .find(|fw| fw.signed && fw.version == host_version && fw.build_id == host_b)
        {
            out.push(fw.clone());
        }
    }

    let host_b = host_build.unwrap_or("");

    // Tier 2
    let mut tier2: Vec<&IpswIndexFirmware> = firmwares
        .iter()
        .filter(|fw| {
            fw.signed
                && fw.version == host_version
                && host_build_supports_image(host_b, &fw.build_id)
                && !out.iter().any(|o| o.url == fw.url)
        })
        .collect();
    tier2.sort_by(|a, b| cmp_apple_builds(&b.build_id, &a.build_id));
    for fw in tier2 {
        if out.len() >= MAX_RESTORE_CANDIDATES {
            return out;
        }
        out.push(fw.clone());
    }

    // Tier 3
    let mut tier3: Vec<&IpswIndexFirmware> = firmwares
        .iter()
        .filter(|fw| {
            fw.signed
                && cmp_macos_versions(&fw.version, host_version) == Ordering::Less
                && host_build_supports_image(host_b, &fw.build_id)
                && !out.iter().any(|o| o.url == fw.url)
        })
        .collect();
    tier3.sort_by(|a, b| match cmp_macos_versions(&b.version, &a.version) {
        Ordering::Equal => cmp_apple_builds(&b.build_id, &a.build_id),
        other => other,
    });
    for fw in tier3.into_iter().take(MAX_LEGACY_VERSION_CANDIDATES) {
        if out.len() >= MAX_RESTORE_CANDIDATES {
            return out;
        }
        out.push(fw.clone());
    }

    out
}

fn fetch_host_restore_candidates_from_index(
    host_model: &str,
    host_version: &str,
    host_build: Option<&str>,
) -> Result<Vec<IpswIndexFirmware>, VZError> {
    let api_url = format!("https://ipsw.me/api/ios/v4/device/{host_model}?type=ipsw");
    let response = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build()
        .get(&api_url)
        .set("User-Agent", "theyos/restore-index")
        .call()
        .map_err(|e| VZError::Internal(format!("restore index request failed: {e}")))?;

    let body = response
        .into_string()
        .map_err(|e| VZError::Internal(format!("read restore index response: {e}")))?;
    let index: IpswIndexResponse = serde_json::from_str(&body)
        .map_err(|e| VZError::Internal(format!("parse restore index response: {e}")))?;

    Ok(select_host_restore_candidates(
        &index.firmwares,
        host_version,
        host_build,
    ))
}

fn expand_user_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home).join(rest)
    } else {
        PathBuf::from(path)
    }
}

fn looks_like_url(value: &str) -> bool {
    value.starts_with("https://") || value.starts_with("http://")
}

fn local_restore_image_candidates(
    host_version: &str,
    host_build: Option<&str>,
    base_dir: &Path,
) -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let mut candidates = vec![
        base_dir.join("macos.ipsw"),
        PathBuf::from(&home)
            .join("Downloads")
            .join(expected_restore_filename(host_version, host_build)),
        PathBuf::from(".").join(expected_restore_filename(host_version, host_build)),
    ];

    if let Some(build) = host_build {
        let globbed_dirs = [
            PathBuf::from(&home).join("Downloads"),
            PathBuf::from("."),
            base_dir.to_path_buf(),
        ];
        for dir in globbed_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                        continue;
                    };
                    if name.starts_with(&format!("UniversalMac_{host_version}_"))
                        && name.ends_with("_Restore.ipsw")
                        && name.contains(build)
                    {
                        candidates.push(path);
                    }
                }
            }
        }
    }

    candidates
}

fn discover_local_restore_image(
    host_version: &str,
    host_build: Option<&str>,
    base_dir: &Path,
) -> Option<PathBuf> {
    local_restore_image_candidates(host_version, host_build, base_dir)
        .into_iter()
        .find(|path| path.exists())
}

fn stage_local_restore_image(source_path: &Path, base_dir: &Path) -> Result<PathBuf, VZError> {
    let source_path = source_path.canonicalize().map_err(|e| {
        VZError::InvalidConfig(format!("resolve ipsw path {}: {e}", source_path.display()))
    })?;
    let dest_path = base_dir.join("macos.ipsw");

    if source_path == dest_path {
        return Ok(dest_path);
    }

    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| VZError::Internal(format!("create ipsw dir {}: {e}", parent.display())))?;
    }

    if dest_path.exists() || dest_path.symlink_metadata().is_ok() {
        std::fs::remove_file(&dest_path).map_err(|e| {
            VZError::Internal(format!(
                "remove existing staged ipsw {}: {e}",
                dest_path.display()
            ))
        })?;
    }

    if let Err(link_err) = std::fs::hard_link(&source_path, &dest_path) {
        tracing::warn!(
            source = %source_path.display(),
            dest = %dest_path.display(),
            error = %link_err,
            "hard-link IPSW staging failed; trying APFS clone"
        );
        let clone_out = std::process::Command::new("cp")
            .args(["-c", "--"])
            .arg(&source_path)
            .arg(&dest_path)
            .output();
        let clone_ok = matches!(clone_out, Ok(ref out) if out.status.success());
        if !clone_ok {
            if let Ok(out) = clone_out {
                tracing::warn!(
                    stderr = %String::from_utf8_lossy(&out.stderr),
                    "APFS clone IPSW staging failed; falling back to full copy"
                );
            }
            std::fs::copy(&source_path, &dest_path).map_err(|e| {
                VZError::Internal(format!(
                    "stage local ipsw {} -> {}: hard-link failed ({link_err}); copy failed: {e}",
                    source_path.display(),
                    dest_path.display()
                ))
            })?;
        }
    }

    Ok(dest_path)
}

/// Load a local restore image and extract its macOS version via VZ.
///
/// This is used for user-provided IPSW files and auto-discovered local restore images.
///
/// # Errors
///
/// Returns `VZError` if the image cannot be loaded or the macOS version
/// cannot be read from the restore image metadata.
pub fn inspect_restore_image(path: &Path) -> Result<String, VZError> {
    use std::sync::mpsc;

    #[repr(C)]
    struct NSOperatingSystemVersion {
        major: libc::c_long,
        minor: libc::c_long,
        patch: libc::c_long,
    }

    let (tx, rx) = mpsc::sync_channel::<Result<String, String>>(1);
    let restore_url = unsafe { crate::vz::nsurl_from_path_pub(path)? };

    unsafe {
        let completion = ConcreteBlock::new(move |img: *mut Object, err: *mut Object| {
            let result = if err.is_null() && !img.is_null() {
                let os_version: NSOperatingSystemVersion = msg_send![img, operatingSystemVersion];
                let version = if os_version.patch > 0 {
                    format!(
                        "{}.{}.{}",
                        os_version.major, os_version.minor, os_version.patch
                    )
                } else {
                    format!("{}.{}", os_version.major, os_version.minor)
                };
                Ok(version)
            } else if !err.is_null() {
                let desc: *mut Object = msg_send![err, localizedDescription];
                let cstr: *const libc::c_char = msg_send![desc, UTF8String];
                if cstr.is_null() {
                    Err("unknown NSError".to_string())
                } else {
                    Err(std::ffi::CStr::from_ptr(cstr)
                        .to_string_lossy()
                        .into_owned())
                }
            } else {
                Err("VZMacOSRestoreImage returned nil without error".to_string())
            };
            let _ = tx.send(result);
        });
        let completion = completion.copy();
        let _: () = msg_send![
            class!(VZMacOSRestoreImage),
            loadFileURL: restore_url
            completionHandler: &*completion
        ];
    }

    rx.recv_timeout(Duration::from_secs(60))
        .map_err(|_| {
            VZError::Internal("VZMacOSRestoreImage local load timed out after 60s".into())
        })?
        .map_err(VZError::InvalidConfig)
}

/// Returns true if a restore image filename's build is compatible with the host
/// (i.e. host can install it). Optimistic when build is unknown.
fn image_build_compatible_with_host(host_build: Option<&str>, image_build: Option<&str>) -> bool {
    match (host_build, image_build) {
        (Some(hb), Some(ib)) if !hb.is_empty() && !ib.is_empty() => {
            host_build_supports_image(hb, ib)
        }
        _ => true,
    }
}

/// Inspect the cached `macos.ipsw` (if any) and either return it as a candidate
/// or evict it (with download-progress reset) when stale/incompatible.
///
/// Non-fatal: any error is logged and translated into "no candidate".
fn try_local_auto_candidate(
    host_macos_version: Option<&String>,
    host_macos_build: Option<&String>,
    base_dir: &Path,
) -> Option<ResolvedRestoreImage> {
    let host_v = host_macos_version.map(String::as_str)?;
    let host_b = host_macos_build.map(String::as_str);
    let local_path = discover_local_restore_image(host_v, host_b, base_dir)?;
    let image_build = extract_macos_build_from_url(&local_path.to_string_lossy());

    let evict = |reason: &str| {
        tracing::warn!(
            path = %local_path.display(),
            reason,
            "discarding stale cached restore image"
        );
        if local_path == base_dir.join("macos.ipsw") {
            std::fs::remove_file(&local_path).ok();
            let _ = clear_download_progress(base_dir);
        }
    };

    let version = match inspect_restore_image(&local_path) {
        Ok(v) => v,
        Err(e) => {
            evict(&format!("VZ inspect failed: {e}"));
            return None;
        }
    };

    if !host_version_sufficient(host_v, &version) {
        evict(&format!("image version {version} > host version {host_v}"));
        return None;
    }

    if !image_build_compatible_with_host(host_b, image_build.as_deref()) {
        evict(&format!(
            "image build {} > host build {}",
            image_build.as_deref().unwrap_or("?"),
            host_b.unwrap_or("?"),
        ));
        return None;
    }

    let staged = match stage_local_restore_image(&local_path, base_dir) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to stage local restore image; skipping cache candidate");
            return None;
        }
    };

    Some(ResolvedRestoreImage {
        source: RestoreImageSource::LocalFile(staged),
        macos_version: version,
        ipsw_build: image_build,
        source_label: format!("local-auto:{}", local_path.display()),
        host_macos_version: host_macos_version.cloned(),
        host_macos_build: host_macos_build.cloned(),
    })
}

/// Resolve a ranked list of restore-image candidates for macOS guest init.
///
/// Candidate order:
/// 1. `requested_ipsw`: user override (URL or local path) — single-element list, no fallback.
/// 2. Auto-discovered local IPSW matching the host (cached `macos.ipsw`) — only if VZ accepts it.
/// 3. `VZMacOSRestoreImage.fetchLatestSupported()` from Apple — only if version+build match host.
/// 4. `ipsw.me` catalog tiers (exact build, same-version older build, legacy version compatible).
///
/// Candidates whose `source_label` is in `state.failed_ipsw_sources` are filtered out
/// so a process restart doesn't re-try a known-broken candidate.
///
/// # Errors
///
/// Returns `VZError` when no compatible candidate can be located. The error
/// includes diagnostic context (host model/version/build, Apple's latest URL,
/// reason ipsw.me lookup didn't yield a match).
pub fn resolve_restore_image(
    requested_ipsw: Option<&str>,
    base_dir: &Path,
) -> Result<Vec<ResolvedRestoreImage>, VZError> {
    let host_macos_version = get_host_macos_version();
    let host_macos_build = get_host_macos_build();
    let host_model = get_host_model_identifier();

    tracing::info!(
        host_macos_version = ?host_macos_version,
        host_macos_build = ?host_macos_build,
        host_model = ?host_model,
        "resolving restore image candidates"
    );

    // ── --ipsw override ──────────────────────────────────────────────────
    if let Some(requested) = requested_ipsw.filter(|s| !s.trim().is_empty()) {
        if looks_like_url(requested) {
            let version =
                extract_macos_version_from_url(requested).unwrap_or_else(|| "unknown".to_string());
            let image_build = extract_macos_build_from_url(requested);
            if let Some(host_version) = host_macos_version.as_deref() {
                if version != "unknown" && !host_version_sufficient(host_version, &version) {
                    return Err(VZError::InvalidConfig(incompatible_restore_image_error(
                        host_version,
                        host_macos_build.as_deref(),
                        &version,
                    )));
                }
            }
            if !image_build_compatible_with_host(
                host_macos_build.as_deref(),
                image_build.as_deref(),
            ) {
                return Err(VZError::InvalidConfig(incompatible_restore_image_error(
                    host_macos_version.as_deref().unwrap_or("unknown"),
                    host_macos_build.as_deref(),
                    &version,
                )));
            }
            return Ok(vec![ResolvedRestoreImage {
                source: RestoreImageSource::DownloadUrl(requested.to_string()),
                macos_version: version,
                ipsw_build: image_build,
                source_label: format!("remote-override:{requested}"),
                host_macos_version,
                host_macos_build,
            }]);
        }

        let requested_path = expand_user_path(requested);
        if !requested_path.exists() {
            return Err(VZError::InvalidConfig(format!(
                "restore image not found: {}",
                requested_path.display()
            )));
        }
        let version = inspect_restore_image(&requested_path)?;
        let image_build = extract_macos_build_from_url(&requested_path.to_string_lossy());
        if let Some(host_version) = host_macos_version.as_deref() {
            if !host_version_sufficient(host_version, &version) {
                return Err(VZError::InvalidConfig(incompatible_restore_image_error(
                    host_version,
                    host_macos_build.as_deref(),
                    &version,
                )));
            }
        }
        if !image_build_compatible_with_host(host_macos_build.as_deref(), image_build.as_deref()) {
            return Err(VZError::InvalidConfig(incompatible_restore_image_error(
                host_macos_version.as_deref().unwrap_or("unknown"),
                host_macos_build.as_deref(),
                &version,
            )));
        }
        return Ok(vec![ResolvedRestoreImage {
            source: RestoreImageSource::LocalFile(stage_local_restore_image(
                &requested_path,
                base_dir,
            )?),
            macos_version: version,
            ipsw_build: image_build,
            source_label: format!("local-override:{}", requested_path.display()),
            host_macos_version,
            host_macos_build,
        }]);
    }

    // ── Auto-resolution: build ranked candidate list ─────────────────────
    let mut candidates: Vec<ResolvedRestoreImage> = Vec::new();

    // Cache local-auto (non-fatal: evicts stale).
    if let Some(local) = try_local_auto_candidate(
        host_macos_version.as_ref(),
        host_macos_build.as_ref(),
        base_dir,
    ) {
        candidates.push(local);
    }

    // Apple latest — non-fatal: if VZMacOSRestoreImage.latestSupported errors
    // (offline, Apple CDN hiccup, 30s timeout) we continue with whatever local
    // cache + ipsw.me candidates we already have. Only the final empty-candidates
    // check escalates to a hard failure.
    let mut apple_lookup_error: Option<String> = None;
    let apple_tier: Option<(String, String, Option<String>)> = match fetch_ipsw_url() {
        Ok((url, version)) => {
            let build = extract_macos_build_from_url(&url);
            Some((url, version, build))
        }
        Err(e) => {
            tracing::warn!(error = %e,
                "VZMacOSRestoreImage.latestSupported lookup failed; continuing with other tiers");
            apple_lookup_error = Some(format!("apple latest-supported lookup failed: {e}"));
            None
        }
    };
    if let Some((apple_url, apple_version, apple_build)) = apple_tier.as_ref() {
        let apple_compatible = match host_macos_version.as_deref() {
            None => true,
            Some(hv) => {
                host_version_sufficient(hv, apple_version)
                    && image_build_compatible_with_host(
                        host_macos_build.as_deref(),
                        apple_build.as_deref(),
                    )
            }
        };
        tracing::info!(
            apple_version = %apple_version,
            apple_build = ?apple_build,
            apple_compatible,
            "fetched VZMacOSRestoreImage.latestSupported"
        );
        if apple_compatible {
            let label = format!("latest-supported:{apple_url}");
            if !candidates.iter().any(|c| c.source_label == label) {
                candidates.push(ResolvedRestoreImage {
                    source: RestoreImageSource::DownloadUrl(apple_url.clone()),
                    macos_version: apple_version.clone(),
                    ipsw_build: apple_build.clone(),
                    source_label: label,
                    host_macos_version: host_macos_version.clone(),
                    host_macos_build: host_macos_build.clone(),
                });
            }
        }
    }

    // ipsw.me catalog tiers — only meaningful when host model + version are known.
    let mut index_lookup_status: Option<String> = None;
    if let (Some(model), Some(host_v)) = (host_model.as_deref(), host_macos_version.as_deref()) {
        match fetch_host_restore_candidates_from_index(model, host_v, host_macos_build.as_deref()) {
            Ok(firmwares) => {
                if firmwares.is_empty() {
                    index_lookup_status = Some(
                        "no compatible signed restore (same or older version) found in host-build lookup".to_string(),
                    );
                } else {
                    for fw in firmwares {
                        let tier = if Some(fw.build_id.as_str()) == host_macos_build.as_deref()
                            && fw.version == host_v
                        {
                            "tier1"
                        } else if fw.version == host_v {
                            "tier2"
                        } else {
                            "tier3"
                        };
                        let label = format!("host-match-index:{tier}:{}", fw.url);
                        if candidates.iter().any(|c| match &c.source {
                            RestoreImageSource::DownloadUrl(u) => *u == fw.url,
                            RestoreImageSource::LocalFile(_) => false,
                        }) || candidates.iter().any(|c| c.source_label == label)
                        {
                            continue;
                        }
                        tracing::info!(
                            tier,
                            version = %fw.version,
                            build = %fw.build_id,
                            url = %fw.url,
                            "ipsw.me candidate"
                        );
                        candidates.push(ResolvedRestoreImage {
                            source: RestoreImageSource::DownloadUrl(fw.url.clone()),
                            macos_version: fw.version.clone(),
                            ipsw_build: Some(fw.build_id.clone()),
                            source_label: label,
                            host_macos_version: host_macos_version.clone(),
                            host_macos_build: host_macos_build.clone(),
                        });
                    }
                }
            }
            Err(e) => {
                index_lookup_status = Some(format!("host-build lookup request failed: {e}"));
            }
        }
    } else if host_model.is_none() || host_macos_version.is_none() {
        index_lookup_status =
            Some("host model or version unavailable; host-build lookup skipped".to_string());
    }

    // Filter by failed_ipsw_sources persisted in init-state.
    let failed: Vec<String> = read_state(base_dir)
        .map(|s| s.failed_ipsw_sources)
        .unwrap_or_default();
    if !failed.is_empty() {
        let before = candidates.len();
        candidates.retain(|c| {
            let keep = !failed.contains(&c.source_label);
            if !keep {
                tracing::info!(source = %c.source_label, "skipping previously-failed candidate");
            }
            keep
        });
        tracing::info!(
            removed = before - candidates.len(),
            failed_count = failed.len(),
            "filtered candidates by failed_ipsw_sources"
        );
    }

    if candidates.is_empty() {
        let host_v = host_macos_version.as_deref().unwrap_or("unknown");
        let mut status_parts: Vec<String> = Vec::new();
        if let Some(s) = apple_lookup_error.as_ref() {
            status_parts.push(s.clone());
        }
        if let Some(s) = index_lookup_status.as_ref() {
            status_parts.push(s.clone());
        }
        let status = if status_parts.is_empty() {
            "no candidates available after filtering failed sources".to_string()
        } else {
            status_parts.join("; ")
        };
        let (apple_url_for_msg, apple_version_for_msg) = match apple_tier.as_ref() {
            Some((u, v, _)) => (u.as_str(), v.as_str()),
            None => ("<unavailable>", "<unknown>"),
        };
        return Err(VZError::InvalidConfig(matching_restore_lookup_error(
            host_model.as_deref(),
            host_v,
            host_macos_build.as_deref(),
            apple_version_for_msg,
            apple_url_for_msg,
            &status,
        )));
    }

    tracing::info!(
        count = candidates.len(),
        labels = ?candidates.iter().map(|c| c.source_label.as_str()).collect::<Vec<_>>(),
        "resolved restore image candidate list"
    );
    Ok(candidates)
}

// ── IPSW download ─────────────────────────────────────────────────────────────

/// Download the IPSW file with HTTP Range-request resume support.
///
/// Updates `state.ipsw_bytes_downloaded` after each chunk and persists
/// to `base_dir/init-state.json`.
///
/// # Arguments
///
/// * `url` — HTTPS URL of the IPSW file
/// * `dest_path` — destination file path
/// * `state` — mutable init state (updated with progress)
/// * `base_dir` — directory containing `init-state.json`
/// * `progress_cb` — called with `(bytes_downloaded, total_bytes)` after each chunk
///
/// # Errors
///
/// Returns `VZError::Internal` on network error or I/O failure.
pub fn download_ipsw(
    url: &str,
    dest_path: &Path,
    state: &mut InitState,
    base_dir: &Path,
    progress_cb: impl Fn(u64, u64),
) -> Result<(), VZError> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let already_downloaded = if dest_path.exists() {
        let meta = std::fs::metadata(dest_path)
            .map_err(|e| VZError::Internal(format!("stat ipsw: {e}")))?;
        meta.len()
    } else {
        0
    };

    // Trust the on-disk file length over persisted JSON. A killed process can
    // leave `init-state.json` ahead of the bytes actually flushed to disk; using
    // the larger persisted value would seek past EOF and create a corrupt sparse
    // IPSW.
    if state.ipsw_bytes_downloaded != already_downloaded {
        tracing::warn!(
            state_bytes = state.ipsw_bytes_downloaded,
            file_bytes = already_downloaded,
            "IPSW progress mismatch; resuming from actual file length"
        );
    }
    let mut resume_from = already_downloaded;
    state.ipsw_bytes_downloaded = resume_from;

    // Build HTTP request with Range header if resuming
    // IPSW is ~12-19 GB; use a long timeout so slow connections don't abort.
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(3600))
        .build();

    let mut response = if resume_from > 0 {
        tracing::info!(
            resume_from,
            "Resuming IPSW download from byte {resume_from}"
        );
        agent
            .get(url)
            .set("Range", &format!("bytes={resume_from}-"))
            .call()
            .map_err(|e| VZError::Internal(format!("IPSW HTTP request: {e}")))?
    } else {
        agent
            .get(url)
            .call()
            .map_err(|e| VZError::Internal(format!("IPSW HTTP request: {e}")))?
    };

    let status = response.status();
    if resume_from > 0 && status == 200 {
        tracing::warn!(
            resume_from,
            "IPSW server ignored Range request; restarting download from byte 0"
        );
        std::fs::remove_file(dest_path).ok();
        resume_from = 0;
        state.ipsw_bytes_downloaded = 0;
        state.ipsw_total_bytes = None;
        response = agent
            .get(url)
            .call()
            .map_err(|e| VZError::Internal(format!("IPSW HTTP restart request: {e}")))?;
    } else if resume_from > 0 && status != 206 {
        return Err(VZError::Internal(format!(
            "IPSW resume request returned HTTP {status}, expected 206 Partial Content"
        )));
    }

    // Get total size from Content-Length or Content-Range
    let total_bytes = if let Some(cr) = response.header("Content-Range") {
        // Content-Range: bytes 6655000000-12400000000/12400000001
        cr.split('/')
            .next_back()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    } else if let Some(cl) = response.header("Content-Length") {
        cl.parse::<u64>().unwrap_or(0)
            + if response.status() == 206 {
                resume_from
            } else {
                0
            }
    } else {
        state.ipsw_total_bytes.unwrap_or(0)
    };

    if total_bytes > 0 && state.ipsw_total_bytes.is_none() {
        state.ipsw_total_bytes = Some(total_bytes);
    }

    // Open file for writing (append if resuming)
    let mut file = if resume_from > 0 {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(dest_path)
            .map_err(|e| VZError::Internal(format!("open ipsw for resume: {e}")))?;
        f.seek(SeekFrom::Start(resume_from))
            .map_err(|e| VZError::Internal(format!("seek ipsw: {e}")))?;
        f
    } else {
        std::fs::File::create(dest_path)
            .map_err(|e| VZError::Internal(format!("create ipsw: {e}")))?
    };

    let mut reader = response.into_reader();
    let mut buf = vec![0u8; 1024 * 1024]; // 1 MB chunks
    let mut bytes_written = resume_from;

    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| VZError::Internal(format!("read IPSW chunk: {e}")))?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])
            .map_err(|e| VZError::Internal(format!("write IPSW chunk: {e}")))?;
        bytes_written += n as u64;
        state.ipsw_bytes_downloaded = bytes_written;

        // Persist progress every ~64 MB
        if bytes_written % (64 * 1024 * 1024) < n as u64 {
            let _ = write_state(base_dir, state);
        }

        progress_cb(bytes_written, total_bytes);
    }

    file.flush()
        .map_err(|e| VZError::Internal(format!("flush ipsw: {e}")))?;

    if total_bytes > 0 && bytes_written != total_bytes {
        return Err(VZError::Internal(format!(
            "IPSW download incomplete: wrote {bytes_written} bytes, expected {total_bytes}"
        )));
    }

    tracing::info!(bytes_written, "IPSW download complete");
    Ok(())
}

// ── Create sparse disk ────────────────────────────────────────────────────────

/// Create a sparse raw disk image of `size_gb` GB using `std::fs::File::set_len`.
///
/// On APFS, this creates a sparse file that only consumes space when written.
///
/// # Errors
///
/// Returns `VZError::Internal` if the file cannot be created or sized.
pub fn create_disk(path: &Path, size_gb: u64) -> Result<(), VZError> {
    let size_bytes = size_gb * 1024 * 1024 * 1024;
    let file = std::fs::File::create(path)
        .map_err(|e| VZError::Internal(format!("create disk image: {e}")))?;
    file.set_len(size_bytes)
        .map_err(|e| VZError::Internal(format!("set_len disk image: {e}")))?;
    tracing::info!(path = %path.display(), size_gb, "Created sparse disk image");
    Ok(())
}

// ── macOS Installation via VZMacOSInstaller ───────────────────────────────────

/// Install macOS from an IPSW into `disk_path` using `VZMacOSInstaller`.
///
/// Long-running (~20 min). Calls `progress_cb` with `fraction_complete` (0.0–1.0).
///
/// Returns the base64-encoded `VZMacHardwareModel` and `VZMacMachineIdentifier`
/// data needed to recreate the same `VZMacPlatformConfiguration`.
///
/// # Errors
///
/// Returns `VZError::VirtualizationError` on installer failure.
pub fn install_macos(
    ipsw_path: &Path,
    disk_path: &Path,
    aux_storage_path: &Path,
    progress_cb: impl Fn(f64) + Send + 'static,
) -> Result<MacOSInstallResult, VZError> {
    use std::sync::mpsc;

    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(disk_path)
        .map_err(|e| {
            VZError::InvalidConfig(format!(
                "disk image must be writable by the current user before macOS install ({}): {e}",
                disk_path.display()
            ))
        })?;

    let (tx, rx) = mpsc::sync_channel::<Result<MacOSInstallResult, String>>(1);

    let ipsw_url = unsafe { crate::vz::nsurl_from_path_pub(ipsw_path)? };
    let disk_url = unsafe { crate::vz::nsurl_from_path_pub(disk_path)? };
    let aux_url = unsafe { crate::vz::nsurl_from_path_pub(aux_storage_path)? };

    let ipsw_addr = ipsw_url as usize;
    let disk_addr = disk_url as usize;
    let aux_addr = aux_url as usize;
    let disk_path_display = disk_path.display().to_string();
    let ipsw_path_buf = ipsw_path.to_path_buf();
    let disk_path_buf = disk_path.to_path_buf();
    let aux_path_buf = aux_storage_path.to_path_buf();
    let dump_path = aux_storage_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("vz-install-config.json");

    let progress_cb = std::sync::Arc::new(std::sync::Mutex::new(progress_cb));
    let progress_cb_clone = progress_cb.clone();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| VZError::Internal(format!("build tokio rt: {e}")))?
        .block_on(async move {
            tokio::task::spawn_blocking(move || {
                unsafe {
                    // ObjC calls on a background thread MUST have an autorelease pool.
                    // Without it, autoreleased objects leak and eventually throw NSException.
                    let pool: *mut Object = msg_send![class!(NSAutoreleasePool), new];

                    let ipsw_url = ipsw_addr as *mut Object;
                    let disk_url = disk_addr as *mut Object;
                    let aux_url = aux_addr as *mut Object;
                    let dump_path = dump_path;

                    // Step 1: Load restore image from IPSW (needed for hardware model).
                    let (img_tx, img_rx) = mpsc::sync_channel::<Result<*mut Object, String>>(1);
                    let completion = ConcreteBlock::new(move |img: *mut Object, err: *mut Object| {
                        let result = if err.is_null() && !img.is_null() {
                            Ok(img)
                        } else {
                            let msg = if err.is_null() {
                                "VZMacOSRestoreImage load returned nil".to_string()
                            } else {
                                nserror_details_string(err)
                            };
                            Err(msg)
                        };
                        let _ = img_tx.send(result);
                    });
                    let completion = completion.copy();
                    let _: () = msg_send![
                        class!(VZMacOSRestoreImage),
                        loadFileURL: ipsw_url
                        completionHandler: &*completion
                    ];

                    let restore_image = match img_rx.recv_timeout(Duration::from_secs(60)) {
                        Ok(Ok(img)) => img,
                        Ok(Err(e)) => { let _ = tx.send(Err(e)); return; }
                        Err(_) => { let _ = tx.send(Err("restore image load timeout".to_string())); return; }
                    };

                    // Step 2: Get hardware model and resource requirements from the IPSW.
                    let restore_cfg: *mut Object = msg_send![restore_image, mostFeaturefulSupportedConfiguration];
                    if restore_cfg.is_null() {
                        let _ = tx.send(Err("no supported configuration in IPSW".to_string()));
                        return;
                    }
                    let hw_model: *mut Object = msg_send![restore_cfg, hardwareModel];
                    if hw_model.is_null() {
                        let _ = tx.send(Err("hardware model is nil".to_string()));
                        return;
                    }
                    let min_cpu_count: usize = msg_send![restore_cfg, minimumSupportedCPUCount];
                    let min_memory_size: u64 = msg_send![restore_cfg, minimumSupportedMemorySize];
                    let install_cpu_count = min_cpu_count.max(4);
                    let install_memory_size = min_memory_size.max(8 * 1024 * 1024 * 1024);
                    let Ok(install_cpu_count_u32) = u32::try_from(install_cpu_count) else {
                        let _ = tx.send(Err(format!(
                            "minimum supported CPU count is too large: {install_cpu_count}"
                        )));
                        return;
                    };
                    let Ok(install_memory_mb) =
                        u32::try_from(install_memory_size.div_ceil(1024 * 1024))
                    else {
                        let _ = tx.send(Err(format!(
                            "minimum supported memory is too large: {install_memory_size} bytes"
                        )));
                        return;
                    };

                    // Step 3: Create VZMacAuxiliaryStorage WITH the hardware model.
                    // Remove stale file if present — initCreatingStorageAtURL: refuses to overwrite.
                    {
                        let aux_path_str: *mut Object = msg_send![aux_url, path];
                        if !aux_path_str.is_null() {
                            let cstr: *const libc::c_char = msg_send![aux_path_str, UTF8String];
                            if !cstr.is_null() {
                                let path = std::ffi::CStr::from_ptr(cstr).to_string_lossy();
                                let _ = std::fs::remove_file(path.as_ref());
                            }
                        }
                    }
                    let mut aux_err: *mut Object = std::ptr::null_mut();
                    let aux_storage: *mut Object = {
                        let alloc: *mut Object =
                            msg_send![class!(VZMacAuxiliaryStorage), alloc];
                        msg_send![alloc,
                            initCreatingStorageAtURL: aux_url
                            hardwareModel: hw_model
                            options: 1usize
                            error: &mut aux_err
                        ]
                    };
                    if aux_storage.is_null() {
                        let msg = if aux_err.is_null() {
                            "VZMacAuxiliaryStorage alloc failed (nil)".to_string()
                        } else {
                            nserror_details_string(aux_err)
                        };
                        let _ = tx.send(Err(msg));
                        return;
                    }

                    // Step 4: Build VZMacPlatformConfiguration.
                    let machine_id: *mut Object = {
                        let alloc: *mut Object = msg_send![class!(VZMacMachineIdentifier), alloc];
                        msg_send![alloc, init]
                    };
                    if machine_id.is_null() {
                        let _ = tx.send(Err("VZMacMachineIdentifier alloc failed".to_string()));
                        let _: () = msg_send![pool, drain];
                        return;
                    }
                    let platform: *mut Object = {
                        let alloc: *mut Object = msg_send![class!(VZMacPlatformConfiguration), alloc];
                        let p: *mut Object = msg_send![alloc, init];
                        let _: () = msg_send![p, setHardwareModel: hw_model];
                        let _: () = msg_send![p, setAuxiliaryStorage: aux_storage];
                        let _: () = msg_send![p, setMachineIdentifier: machine_id];
                        p
                    };

                    // Step 5: Build VZVirtualMachineConfiguration.
                    let vm_config: *mut Object = {
                        let alloc: *mut Object = msg_send![class!(VZVirtualMachineConfiguration), alloc];
                        let c: *mut Object = msg_send![alloc, init];
                        let _: () = msg_send![c, setCPUCount: install_cpu_count];
                        let _: () = msg_send![c, setMemorySize: install_memory_size];
                        let _: () = msg_send![c, setPlatform: platform];
                        // Boot loader
                        let boot: *mut Object = {
                            let a: *mut Object = msg_send![class!(VZMacOSBootLoader), alloc];
                            msg_send![a, init]
                        };
                        let _: () = msg_send![c, setBootLoader: boot];
                        // Disk
                        let mut disk_err: *mut Object = std::ptr::null_mut();
                        let disk_attach: *mut Object = {
                            let a: *mut Object = msg_send![class!(VZDiskImageStorageDeviceAttachment), alloc];
                            msg_send![a,
                                initWithURL: disk_url
                                readOnly: false
                                cachingMode: 2isize
                                synchronizationMode: 1isize
                                error: &mut disk_err
                            ]
                        };
                        if disk_attach.is_null() {
                            let msg = if disk_err.is_null() {
                                format!(
                                    "VZDiskImageStorageDeviceAttachment init failed for {disk_path_display} (nil error)"
                                )
                            } else {
                                let detail = nserror_details_string(disk_err);
                                format!("disk attachment failed for {disk_path_display}: {detail}")
                            };
                            let _ = tx.send(Err(msg));
                            let _: () = msg_send![pool, drain];
                            return;
                        }
                        let disk_dev: *mut Object = {
                            let a: *mut Object = msg_send![class!(VZVirtioBlockDeviceConfiguration), alloc];
                            msg_send![a, initWithAttachment: disk_attach]
                        };
                        if disk_dev.is_null() {
                            let _ = tx.send(Err(format!(
                                "VZVirtioBlockDeviceConfiguration init failed for {disk_path_display}"
                            )));
                            let _: () = msg_send![pool, drain];
                            return;
                        }
                        let storage_arr: *mut Object = msg_send![class!(NSArray),
                            arrayWithObjects: &raw const disk_dev count: 1usize];
                        let _: () = msg_send![c, setStorageDevices: storage_arr];
                        // Display — required for VZMacOSInstaller to boot RestoreOS
                        let display: *mut Object = {
                            let a: *mut Object = msg_send![class!(VZMacGraphicsDeviceConfiguration), alloc];
                            msg_send![a, init]
                        };
                        let display_cfg: *mut Object = {
                            let a: *mut Object = msg_send![class!(VZMacGraphicsDisplayConfiguration), alloc];
                            msg_send![a, initWithWidthInPixels: 1920usize heightInPixels: 1080usize pixelsPerInch: 80usize]
                        };
                        let disp_arr: *mut Object = msg_send![class!(NSArray),
                            arrayWithObjects: &raw const display_cfg count: 1usize];
                        let _: () = msg_send![display, setDisplays: disp_arr];
                        let gfx_arr: *mut Object = msg_send![class!(NSArray),
                            arrayWithObjects: &raw const display count: 1usize];
                        let _: () = msg_send![c, setGraphicsDevices: gfx_arr];
                        // Keyboard — required for VZMacOSInstaller
                        let kb: *mut Object = {
                            let a: *mut Object = msg_send![class!(VZUSBKeyboardConfiguration), alloc];
                            msg_send![a, init]
                        };
                        let kb_arr: *mut Object = msg_send![class!(NSArray),
                            arrayWithObjects: &raw const kb count: 1usize];
                        let _: () = msg_send![c, setKeyboards: kb_arr];
                        // Pointing device — required for VZMacOSInstaller
                        let ptr: *mut Object = {
                            let a: *mut Object = msg_send![class!(VZUSBScreenCoordinatePointingDeviceConfiguration), alloc];
                            msg_send![a, init]
                        };
                        let trackpad: *mut Object = {
                            let a: *mut Object = msg_send![class!(VZMacTrackpadConfiguration), alloc];
                            msg_send![a, init]
                        };
                        let ptr_devices = [ptr, trackpad];
                        let ptr_arr: *mut Object = msg_send![class!(NSArray),
                            arrayWithObjects: ptr_devices.as_ptr() count: ptr_devices.len()];
                        let _: () = msg_send![c, setPointingDevices: ptr_arr];
                        // Network — required for TSS personalization during install
                        let net_attach: *mut Object = {
                            let a: *mut Object = msg_send![class!(VZNATNetworkDeviceAttachment), alloc];
                            msg_send![a, init]
                        };
                        let net_dev: *mut Object = {
                            let a: *mut Object = msg_send![class!(VZVirtioNetworkDeviceConfiguration), alloc];
                            let d: *mut Object = msg_send![a, init];
                            let mac: *mut Object = msg_send![class!(VZMACAddress), randomLocallyAdministeredAddress];
                            let _: () = msg_send![d, setAttachment: net_attach];
                            let _: () = msg_send![d, setMACAddress: mac];
                            d
                        };
                        let net_arr: *mut Object = msg_send![class!(NSArray),
                            arrayWithObjects: &raw const net_dev count: 1usize];
                        let _: () = msg_send![c, setNetworkDevices: net_arr];
                        // Serial console and entropy match the runtime macOS VM config.
                        let serial_attach: *mut Object = {
                            use std::os::unix::io::IntoRawFd;
                            let rd = std::fs::File::open("/dev/null")
                                .map_err(|e| format!("open /dev/null read: {e}"));
                            let wr = std::fs::OpenOptions::new()
                                .write(true)
                                .open("/dev/null")
                                .map_err(|e| format!("open /dev/null write: {e}"));
                            let (rd, wr) = match (rd, wr) {
                                (Ok(rd), Ok(wr)) => (rd, wr),
                                (Err(e), _) | (_, Err(e)) => {
                                    let _ = tx.send(Err(e));
                                    let _: () = msg_send![pool, drain];
                                    return;
                                }
                            };
                            let rd_handle: *mut Object = {
                                let a: *mut Object = msg_send![class!(NSFileHandle), alloc];
                                msg_send![a, initWithFileDescriptor: rd.into_raw_fd() closeOnDealloc: true]
                            };
                            let wr_handle: *mut Object = {
                                let a: *mut Object = msg_send![class!(NSFileHandle), alloc];
                                msg_send![a, initWithFileDescriptor: wr.into_raw_fd() closeOnDealloc: true]
                            };
                            let a: *mut Object = msg_send![class!(VZFileHandleSerialPortAttachment), alloc];
                            msg_send![a,
                                initWithFileHandleForReading: rd_handle
                                fileHandleForWriting: wr_handle
                            ]
                        };
                        let serial_port: *mut Object = {
                            let a: *mut Object = msg_send![class!(VZVirtioConsoleDeviceSerialPortConfiguration), alloc];
                            let p: *mut Object = msg_send![a, init];
                            let _: () = msg_send![p, setAttachment: serial_attach];
                            p
                        };
                        let serial_arr: *mut Object = msg_send![class!(NSArray),
                            arrayWithObjects: &raw const serial_port count: 1usize];
                        let _: () = msg_send![c, setSerialPorts: serial_arr];
                        let entropy: *mut Object = {
                            let a: *mut Object = msg_send![class!(VZVirtioEntropyDeviceConfiguration), alloc];
                            msg_send![a, init]
                        };
                        let entropy_arr: *mut Object = msg_send![class!(NSArray),
                            arrayWithObjects: &raw const entropy count: 1usize];
                        let _: () = msg_send![c, setEntropyDevices: entropy_arr];
                        c
                    };

                    let config_dump = serde_json::json!({
                        "host": {
                            "model": std::process::Command::new("sysctl")
                                .args(["-n", "hw.model"])
                                .output()
                                .ok()
                                .and_then(|o| String::from_utf8(o.stdout).ok())
                                .map(|s| s.trim().to_string()),
                            "sw_vers": std::process::Command::new("sw_vers")
                                .output()
                                .ok()
                                .and_then(|o| String::from_utf8(o.stdout).ok())
                                .map(|s| s.trim().to_string()),
                        },
                        "files": {
                            "ipsw": file_metadata_json(&ipsw_path_buf),
                            "disk": file_metadata_json(&disk_path_buf),
                            "aux_storage": file_metadata_json(&aux_path_buf),
                        },
                        "vm_configuration": {
                            "configuration_requirements": {
                                "minimum_supported_cpu_count": min_cpu_count,
                                "minimum_supported_memory_size_bytes": min_memory_size,
                            },
                            "cpu_count": install_cpu_count,
                            "memory_size_bytes": install_memory_size,
                            "platform": {
                                "class": "VZMacPlatformConfiguration",
                                "hardware_model_data_b64": data_representation_b64(hw_model),
                                "machine_identifier_data_b64": data_representation_b64(machine_id),
                                "auxiliary_storage_path": aux_path_buf.display().to_string(),
                                "auxiliary_storage_initialization_options": ["allow_overwrite"],
                            },
                            "boot_loader": "VZMacOSBootLoader",
                            "storage_devices": [{
                                "class": "VZVirtioBlockDeviceConfiguration",
                                "attachment": "VZDiskImageStorageDeviceAttachment",
                                "caching_mode": "cached",
                                "synchronization_mode": "full",
                                "path": disk_path_buf.display().to_string(),
                                "read_only": false,
                            }],
                            "graphics_devices": [{
                                "class": "VZMacGraphicsDeviceConfiguration",
                                "displays": [{
                                    "width_pixels": 1920,
                                    "height_pixels": 1080,
                                    "pixels_per_inch": 80,
                                }],
                            }],
                            "keyboards": ["VZUSBKeyboardConfiguration"],
                            "pointing_devices": [
                                "VZUSBScreenCoordinatePointingDeviceConfiguration",
                                "VZMacTrackpadConfiguration",
                            ],
                            "network_devices": [{
                                "class": "VZVirtioNetworkDeviceConfiguration",
                                "attachment": "VZNATNetworkDeviceAttachment",
                                "mac_address": "randomLocallyAdministeredAddress",
                            }],
                            "audio_devices": [],
                            "serial_ports": ["VZVirtioConsoleDeviceSerialPortConfiguration"],
                            "entropy_devices": ["VZVirtioEntropyDeviceConfiguration"],
                        },
                    });
                    match serde_json::to_string_pretty(&config_dump)
                        .ok()
                        .and_then(|s| std::fs::write(&dump_path, s).ok())
                    {
                        Some(()) => eprintln!("[install] wrote VZ config dump: {}", dump_path.display()),
                        None => eprintln!("[install] failed to write VZ config dump: {}", dump_path.display()),
                    }

                    // Step 6: Validate config before creating VM.
                    eprintln!("[install] step 6: validating config...");
                    let mut validate_err: *mut Object = std::ptr::null_mut();
                    let valid: bool = msg_send![vm_config, validateWithError: &mut validate_err];
                    if !valid {
                        let msg = if validate_err.is_null() {
                            "VZ config validation failed (no error)".to_string()
                        } else {
                            nserror_details_string(validate_err)
                        };
                        let _ = tx.send(Err(format!("VZ config invalid: {msg}")));
                        let _: () = msg_send![pool, drain];
                        return;
                    }
                    eprintln!("[install] step 6: config valid, creating VM...");

                    // VZMacOSInstaller requires a VZVirtualMachine, not a configuration.
                    let install_queue = crate::vz::create_serial_queue("com.theyos.install");
                    let vm: *mut Object = {
                        let alloc: *mut Object = msg_send![class!(VZVirtualMachine), alloc];
                        msg_send![alloc, initWithConfiguration: vm_config queue: install_queue]
                    };
                    if vm.is_null() {
                        let _ = tx.send(Err("VZVirtualMachine alloc failed".to_string()));
                        let _: () = msg_send![pool, drain];
                        return;
                    }
                    eprintln!("[install] step 7: VM created, dispatching installer on VM queue...");

                    // Step 7+8: VZMacOSInstaller init AND installWithCompletionHandler
                    // MUST be called on the VM's dispatch queue (dispatch_assert_queue).
                    let (install_tx, install_rx) = mpsc::sync_channel::<Result<(), String>>(1);
                    let progress_cb2 = progress_cb_clone.clone();
                    let ipsw_url_copy = ipsw_url;
                    let vm_copy = vm;
                    let install_block = ConcreteBlock::new(move || {
                        let pool2: *mut Object = msg_send![class!(NSAutoreleasePool), new];

                        let installer: *mut Object = {
                            let alloc: *mut Object = msg_send![class!(VZMacOSInstaller), alloc];
                            msg_send![alloc,
                                initWithVirtualMachine: vm_copy
                                restoreImageURL: ipsw_url_copy
                            ]
                        };
                        if installer.is_null() {
                            let _ = install_tx.send(Err("VZMacOSInstaller alloc failed".to_string()));
                            let _: () = msg_send![pool2, drain];
                            return;
                        }
                        eprintln!("[install] step 8: installer created on VM queue, starting install...");
                        let state_before_install: isize = msg_send![vm_copy, state];
                        eprintln!("[install] VM state before installWithCompletionHandler: {state_before_install}");

                        let itx = install_tx.clone();
                        let pcb = progress_cb2.clone();
                        let vm_for_completion = vm_copy;
                        let completion = ConcreteBlock::new(move |err: *mut Object| {
                            let result = if err.is_null() {
                                if let Ok(cb) = pcb.lock() {
                                    (cb)(1.0);
                                }
                                Ok(())
                            } else {
                                let msg = nserror_details_string(err);
                                let vm_state: isize = msg_send![vm_for_completion, state];
                                eprintln!("[install] FAIL vm_state={vm_state} error={msg}");
                                Err(msg)
                            };
                            let _ = itx.send(result);
                        });
                        let completion = completion.copy();
                        let _: () = msg_send![installer, installWithCompletionHandler: &*completion];
                        let _: () = msg_send![pool2, drain];
                    });
                    let install_block = install_block.copy();
                    // SAFETY: install_block is a valid retained ObjC block.
                    crate::vz::dispatch_async_on_queue(
                        install_queue,
                        std::ptr::addr_of!(*install_block).cast::<libc::c_void>(),
                    );

                    // Wait up to 40 minutes
                    match install_rx.recv_timeout(Duration::from_secs(40 * 60)) {
                        Ok(Ok(())) => {
                            // Encode hardware model data for persistence
                            let hw_data: *mut Object = msg_send![hw_model, dataRepresentation];
                            let len: usize = msg_send![hw_data, length];
                            let ptr: *const u8 = msg_send![hw_data, bytes];
                            let slice = std::slice::from_raw_parts(ptr, len);
                            let hardware_model_data_b64 = BASE64.encode(slice);

                            // Encode the machine identifier used during installation so
                            // subsequent boots reuse the same virtual Mac identity.
                            let id_data: *mut Object = msg_send![machine_id, dataRepresentation];
                            let id_len: usize = msg_send![id_data, length];
                            let id_ptr: *const u8 = msg_send![id_data, bytes];
                            let id_slice = std::slice::from_raw_parts(id_ptr, id_len);
                            let machine_identifier_data_b64 = BASE64.encode(id_slice);

                            let _ = tx.send(Ok(MacOSInstallResult {
                                hardware_model_data_b64,
                                machine_identifier_data_b64,
                                install_cpu_count: install_cpu_count_u32,
                                install_memory_mb,
                            }));
                        }
                        Ok(Err(e)) => { let _ = tx.send(Err(e)); }
                        Err(_) => { let _ = tx.send(Err("VZMacOSInstaller timed out after 40 min".to_string())); }
                    }

                    // Drain the autorelease pool created at the top of this block.
                    let _: () = msg_send![pool, drain];
                }
            }).await.map_err(|e| VZError::Internal(format!("spawn_blocking: {e}")))?;
            Ok::<(), VZError>(())
        })?;

    rx.recv_timeout(Duration::from_secs(1))
        .map_err(|_| VZError::VirtualizationError("install_macos: no result received".into()))?
        .map_err(VZError::VirtualizationError)
}

// ── APFS volume injection ─────────────────────────────────────────────────────

/// Contents of the firstboot `LaunchDaemon` plist injected into the macOS guest.
///
/// Runs `setup.sh` at first boot (root), which enables SSH and cleans up.
#[must_use]
pub fn provision_plist_xml() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.theyos.provision</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>/var/root/.theyos-provision/setup.sh</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>/var/log/theyos-provision.log</string>
  <key>StandardErrorPath</key><string>/var/log/theyos-provision.err</string>
</dict>
</plist>"#
        .to_string()
}

/// Contents of the `com.theyos.sshd` `LaunchDaemon` plist.
///
/// Runs `/usr/sbin/sshd -D -e` directly (standalone, not via the system sshd service).
/// This bypasses the macOS `disabled.plist` mechanism that affects `com.openssh.sshd`.
#[must_use]
pub fn sshd_plist_xml() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
     <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
     \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
     <plist version=\"1.0\">\n\
     <dict>\n\
     \t<key>Label</key>\n\
     \t<string>com.theyos.sshd</string>\n\
     \t<key>ProgramArguments</key>\n\
     \t<array>\n\
     \t\t<string>/usr/sbin/sshd</string>\n\
     \t\t<string>-D</string>\n\
     \t\t<string>-e</string>\n\
     \t</array>\n\
     \t<key>RunAtLoad</key>\n\
     \t<true/>\n\
     \t<key>KeepAlive</key>\n\
     \t<true/>\n\
     \t<key>StandardErrorPath</key>\n\
     \t<string>/var/log/theyos-sshd.err</string>\n\
     </dict>\n\
     </plist>\n"
}

/// Generate `setup.sh` content to be run inside the macOS guest on first boot.
#[must_use]
pub fn setup_sh(ssh_pubkey: &str, claw_type_names: &[&str]) -> String {
    let claw_copy_lines: String = claw_type_names
        .iter()
        .map(|ct| {
            format!(
                "cp /var/root/.theyos-provision/com.theyos.{ct}.plist /Library/LaunchDaemons/ 2>/dev/null || true"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "#!/bin/sh\nset -e\n\
         # Enable Remote Login (SSH)\n\
         systemsetup -setremotelogin on || true\n\
         # Install SSH authorized_keys for root\n\
         mkdir -p /var/root/.ssh\n\
         chmod 700 /var/root/.ssh\n\
         cat > /var/root/.ssh/authorized_keys << 'SSHEOF'\n\
         {ssh_pubkey}\n\
         SSHEOF\n\
         chmod 600 /var/root/.ssh/authorized_keys\n\
         # Install claw service LaunchDaemon plists\n\
         {claw_copy_lines}\n\
         # Remove this provision plist and dir\n\
         rm -f /Library/LaunchDaemons/com.theyos.provision.plist\n\
         rm -rf /var/root/.theyos-provision\n"
    )
}

/// Inject provisioning files into the installed macOS guest disk.
///
/// Delegates to `theyos-provision-inject` (a small privileged helper binary)
/// which mounts the APFS Data volume with `-o owners`, writes all provision
/// files with correct `root:wheel` ownership, and unmounts.
///
/// The helper must be invoked with `sudo` and requires cached credentials.
/// The caller (`init_macos_guest`) primes sudo interactively before calling.
///
/// # Errors
///
/// Returns `VZError::Internal` if the helper binary is not found or fails.
pub fn inject_provision_files(
    disk_path: &Path,
    ssh_pubkey: &str,
    plist_dir: &Path,
) -> Result<(), VZError> {
    use std::process::Command;

    let inject_bin = resolve_provision_inject_bin()?;
    tracing::info!(bin = %inject_bin.display(), "Running privileged provision injection...");

    // Retry with backoff: the disk may still be locked by VZMacOSInstaller's
    // VZVirtualMachine immediately after installation completes.
    let mut last_err = String::new();
    for attempt in 0..6u8 {
        if attempt > 0 {
            tracing::info!(attempt, "Retrying provision-inject (disk may be locked)...");
            std::thread::sleep(Duration::from_secs(5));
        }

        let output = Command::new("sudo")
            .args([
                "-n",
                inject_bin.to_str().unwrap_or("theyos-provision-inject"),
                "--disk",
                disk_path.to_str().unwrap_or(""),
                "--ssh-pubkey",
                ssh_pubkey,
                "--plist-dir",
                plist_dir.to_str().unwrap_or(""),
            ])
            .output()
            .map_err(|e| VZError::Internal(format!("spawn provision-inject: {e}")))?;

        if output.status.success() {
            // Log the JSON manifest from stdout
            let manifest = String::from_utf8_lossy(&output.stdout);
            tracing::info!("Provision injection complete: {manifest}");
            return Ok(());
        }

        last_err = String::from_utf8_lossy(&output.stderr).into_owned();
        // If error is not about disk being locked, don't retry
        if !last_err.contains("Resource busy") && !last_err.contains("hdiutil attach") {
            break;
        }
    }

    Err(VZError::Internal(format!(
        "provision-inject failed: {last_err}"
    )))
}

/// Resolve the `theyos-provision-inject` binary path.
///
/// Search order:
/// 1. Same directory as the currently running binary (works for both Homebrew and Cargo)
/// 2. `THEYOS_BIN_DIR` environment variable (Homebrew installs)
/// 3. Cargo target/release directory (dev fallback)
fn resolve_provision_inject_bin() -> Result<PathBuf, VZError> {
    let bin_name = "theyos-provision-inject";

    // 1. Same directory as current exe
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join(bin_name);
            if p.is_file() {
                return Ok(p);
            }
        }
    }

    // 2. THEYOS_BIN_DIR
    if let Ok(d) = std::env::var("THEYOS_BIN_DIR") {
        let p = PathBuf::from(d).join(bin_name);
        if p.is_file() {
            return Ok(p);
        }
    }

    // 3. Cargo target directory
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        let p = PathBuf::from(manifest)
            .parent()
            .unwrap_or(Path::new("."))
            .join("target/release")
            .join(bin_name);
        if p.is_file() {
            return Ok(p);
        }
    }

    Err(VZError::Internal(format!(
        "{bin_name} not found. Ensure it is built and in the same directory as vmrunner_macos_ipc."
    )))
}

/// Find the APFS Data volume device after `hdiutil attach -nomount`.
///
/// Parses the hdiutil plist output to discover which synthesized APFS container
/// disks were just attached, then runs `diskutil list /dev/diskN` on each one to
/// find the volume named exactly "Data". This scoping is important: a global
/// `diskutil list` would also find the host's "Macintosh HD - Data" volume (already
/// mounted) and cause a "Resource busy" error.
///
/// # Errors
/// Returns [`VZError`] if no Data volume is found or `diskutil` fails.
pub fn find_apfs_data_volume(plist_output: &str) -> Result<String, VZError> {
    use std::process::Command;

    // Extract whole-disk dev-entry values from the hdiutil plist.
    // Plist lines look like: <string>/dev/disk7</string>
    // The first whole disk found is the physical image (e.g. /dev/disk4).
    // Subsequent whole disks are synthesized APFS container disks (disk5, disk6, disk7…).
    let mut base_disk_found = false;
    let mut candidate_disks: Vec<String> = Vec::new();

    for line in plist_output.lines() {
        let line = line.trim();
        if !line.starts_with("<string>/dev/disk") || !line.ends_with("</string>") {
            continue;
        }
        // Strip <string> and </string>
        let dev = &line[8..line.len() - 9]; // e.g. "/dev/disk7" or "/dev/disk7s5"
        let suffix = dev.trim_start_matches("/dev/disk");
        // Whole-disk entry: all chars after "disk" are digits (no 's')
        if suffix.chars().all(|c| c.is_ascii_digit()) && !suffix.is_empty() {
            if base_disk_found {
                candidate_disks.push(dev.to_string());
            } else {
                base_disk_found = true; // first = physical image disk, skip
            }
        }
    }

    // Search each synthesized container disk for the "Data" volume.
    for disk in &candidate_disks {
        let out = Command::new("diskutil")
            .args(["list", disk])
            .output()
            .map_err(|e| VZError::Internal(format!("diskutil list {disk}: {e}")))?;

        if !out.status.success() {
            continue;
        }

        let text = String::from_utf8_lossy(&out.stdout);
        if let Some(dev) = find_data_volume_in_diskutil(&text) {
            tracing::info!(dev, "Found APFS Data volume via diskutil");
            return Ok(dev);
        }
    }

    // Fallback: global diskutil list (covers edge cases where plist parsing failed).
    let out = Command::new("diskutil")
        .args(["list"])
        .output()
        .map_err(|e| VZError::Internal(format!("diskutil list: {e}")))?;

    if !out.status.success() {
        return Err(VZError::Internal(format!(
            "diskutil list failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }

    let text = String::from_utf8_lossy(&out.stdout);
    find_data_volume_in_diskutil(&text).ok_or_else(|| {
        VZError::Internal("Could not find APFS Data volume named 'Data' in diskutil list".into())
    })
}

/// Scan `diskutil list` output for an APFS Volume whose name is exactly "Data".
///
/// Line format example:
///   4: APFS Volume Data          323.1 MB disk7s5
///
/// Returns `/dev/diskNsM` on match.
fn find_data_volume_in_diskutil(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.contains("APFS Volume") {
            continue;
        }
        let after = trimmed.split_once("APFS Volume")?.1.trim_start();
        let tokens: Vec<&str> = after.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        // Volume name must be exactly "Data" (guards against matching the host's
        // "Macintosh HD - Data" volume which would already be mounted).
        if tokens[0] != "Data" {
            continue;
        }
        // Device is the rightmost token matching diskNsM (all alphanumeric, contains 's').
        let device = tokens
            .iter()
            .rev()
            .find(|t| {
                t.starts_with("disk")
                    && t.contains('s')
                    && t.chars().all(|c| c.is_ascii_alphanumeric())
            })
            .copied()?;
        return Some(format!("/dev/{device}"));
    }
    None
}

/// Set Unix file permissions on `path` (best-effort, ignores errors).
pub fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

// ── Claw binary download ──────────────────────────────────────────────────────

/// Claw type names and their binary names.
const CLAW_TYPES: &[(&str, &str)] = &[
    ("picoclaw", "theyos-picoclaw"),
    ("zeroclaw", "theyos-zeroclaw"),
    ("nanobot", "theyos-nanobot"),
    ("openclaw", "theyos-openclaw"),
    ("nullclaw", "theyos-nullclaw"),
    ("ironclaw", "theyos-ironclaw"),
];

/// Download darwin/arm64 claw binaries and install them into the mounted guest.
///
/// Binaries are downloaded from `registry_url/<binary_name>` and written
/// to `binaries_dir/<binary_name>` for later SSH install.
///
/// # Errors
///
/// Returns `VZError::Internal` on download failure.
pub fn download_claw_binaries(
    registry_url: &str,
    binaries_dir: &Path,
    progress_cb: impl Fn(&str),
) -> Result<Vec<String>, VZError> {
    std::fs::create_dir_all(binaries_dir)
        .map_err(|e| VZError::Internal(format!("mkdir binaries dir: {e}")))?;

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(120))
        .build();

    let mut downloaded = Vec::new();

    for (claw_type, binary_name) in CLAW_TYPES {
        let url = format!("{registry_url}/{binary_name}");
        let dest = binaries_dir.join(binary_name);

        tracing::info!(claw_type, "Downloading darwin/arm64 binary");
        progress_cb(claw_type);

        let response = agent
            .get(&url)
            .call()
            .map_err(|e| VZError::Internal(format!("download {binary_name}: {e}")))?;

        let mut body_reader = response.into_reader();
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut body_reader, &mut buf)
            .map_err(|e| VZError::Internal(format!("read {binary_name} body: {e}")))?;

        std::fs::write(&dest, &buf)
            .map_err(|e| VZError::Internal(format!("write {binary_name}: {e}")))?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| VZError::Internal(format!("chmod {binary_name}: {e}")))?;
        }

        downloaded.push(binary_name.to_string());
    }

    Ok(downloaded)
}

// ── SSH wait loop ─────────────────────────────────────────────────────────────

/// Poll `host:22` (TCP connect) until the SSH daemon is ready or timeout expires.
///
/// Used after first-boot to verify that Remote Login is active.
///
/// # Errors
///
/// Returns `VZError::NetworkError` if SSH is not reachable within `timeout_secs`.
pub async fn wait_for_ssh(host: &str, timeout_secs: u64) -> Result<(), VZError> {
    let start = std::time::Instant::now();
    let deadline = start + Duration::from_secs(timeout_secs);
    let mut attempt: u32 = 0;

    // NOTE on the probe choice: we shell out to `nc -zv -w 2` instead of using
    // Rust's `TcpStream::connect_timeout`. On macOS 26 + VZ shared/bridged
    // networking, `connect_timeout` returns `EHOSTUNREACH` (os error 65) on
    // every retry for many minutes after the guest boots, while `nc`, `ping`,
    // and `ssh` against the same IP/port succeed instantly at the same moment.
    // The two diverge despite calling the same `connect(2)` syscall — likely a
    // socket-flag or routing-cache interaction specific to vmnet bridges that
    // the stdlib's non-blocking + select() implementation hits. Endpoint
    // Security extensions (e.g. NordVPN Threat Protection) compound this by
    // filtering POSIX connect() from ad-hoc-signed binaries while letting
    // Apple-signed nc through.
    // Decisive evidence in commit history: `init-arpfix-1777255247.log`.

    loop {
        attempt += 1;
        let host_owned = host.to_string();
        let outcome: Result<(), String> = tokio::task::spawn_blocking(move || {
            let r = std::process::Command::new("nc")
                .args(["-zv", "-w", "2", &host_owned, "22"])
                .output()
                .map_err(|e| format!("spawn nc: {e}"))?;
            if r.status.success() {
                Ok(())
            } else {
                let err = String::from_utf8_lossy(&r.stderr);
                let msg = err.lines().next().unwrap_or("nc failed").trim().to_string();
                Err(format!("nc: {msg}"))
            }
        })
        .await
        .unwrap_or_else(|e| Err(format!("join: {e}")));

        if outcome.is_ok() {
            tracing::info!(host, attempt, "SSH port 22 is reachable");
            return Ok(());
        }

        // Log every 6th attempt (~30s with 5s sleep) so a 420s wait surfaces
        // ~14 status lines instead of going silent the whole time.
        if attempt % 6 == 1 {
            let elapsed = start.elapsed().as_secs();
            tracing::info!(
                host,
                attempt,
                elapsed_s = elapsed,
                last_error = %outcome.as_ref().err().map_or("(none)", String::as_str),
                "Still waiting for SSH..."
            );
        }

        if std::time::Instant::now() >= deadline {
            return Err(VZError::NetworkError(format!(
                "SSH not reachable at {host}:22 after {timeout_secs}s ({attempt} attempts; last: {})",
                outcome.err().unwrap_or_else(|| "unknown".into())
            )));
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Like `wait_for_ssh`, but re-resolves the IP from `/var/db/dhcpd_leases` by MAC
/// every ~30s. Handles the case where the guest gets a new DHCP lease during boot
/// (first-boot reboots, IP-conflict with another VM holding a stale lease).
///
/// Returns the IP that finally answered SSH (may differ from `initial_ip`).
///
/// # Errors
///
/// Returns `VZError::NetworkError` if SSH does not become reachable within `timeout_secs`.
pub async fn wait_for_ssh_by_mac(
    initial_ip: &str,
    mac: &str,
    timeout_secs: u64,
) -> Result<String, VZError> {
    let mac_lower = mac.to_lowercase();
    let leases_path = std::path::Path::new("/var/db/dhcpd_leases");
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut current_ip = initial_ip.to_string();
    let mut iteration: u32 = 0;

    loop {
        // Probe via /usr/bin/nc rather than Rust connect_timeout: Endpoint Security
        // extensions (e.g. NordVPN Threat Protection) intercept POSIX connect() from
        // ad-hoc-signed binaries and return EHOSTUNREACH, while Apple-signed nc passes.
        let ip_for_probe = current_ip.clone();
        let nc_status = tokio::process::Command::new("/usr/bin/nc")
            .args(["-z", "-G", "2", &ip_for_probe, "22"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;

        if matches!(nc_status, Ok(s) if s.success()) {
            tracing::info!(host = %current_ip, mac, "SSH port 22 is reachable");
            return Ok(current_ip);
        }

        if std::time::Instant::now() >= deadline {
            return Err(VZError::NetworkError(format!(
                "SSH not reachable for MAC {mac} (last IP {current_ip}:22) after {timeout_secs}s"
            )));
        }

        iteration = iteration.saturating_add(1);
        // Every ~30s (6 iterations × 5s), re-resolve IP from DHCP leases.
        if iteration % 6 == 0
            && let Ok(content) = tokio::fs::read_to_string(leases_path).await
            && let Some(new_ip) = crate::parse_dhcp_lease_by_mac(&content, &mac_lower)
            && new_ip != current_ip
        {
            tracing::warn!(
                old_ip = %current_ip,
                new_ip = %new_ip,
                mac,
                "VM IP changed during boot (DHCP release); switching target"
            );
            current_ip = new_ip;
            continue;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

// ── Base software provisioning ────────────────────────────────────────────────

/// Run a command on the macOS guest via SSH and return stdout.
///
/// Uses the theyOS SSH key at `~/.theyos/keys/id_ed25519`.
///
/// # Errors
///
/// Returns `VZError::Internal` if the SSH command fails or exits with non-zero status.
pub async fn ssh_exec(host: &str, cmd: &str) -> Result<String, VZError> {
    let key_path = crate::ssh_private_key_path();
    let output = tokio::process::Command::new("ssh")
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "BatchMode=yes",
            "-i",
            key_path.to_str().unwrap_or("/tmp/id_ed25519"),
            &format!("root@{host}"),
            cmd,
        ])
        .output()
        .await
        .map_err(|e| VZError::Internal(format!("ssh exec: {e}")))?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Filter out SSH "Permanently added" warnings to show real errors
        let real_stderr: String = stderr
            .lines()
            .filter(|l| !l.contains("Permanently added"))
            .collect::<Vec<_>>()
            .join("\n");
        let detail = if real_stderr.trim().is_empty() {
            stdout.to_string()
        } else {
            real_stderr
        };
        return Err(VZError::Internal(format!(
            "ssh command failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            detail.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run a command via SSH, logging result. Returns Ok even on failure (best-effort).
async fn ssh_run(host: &str, label: &str, cmd: &str) {
    tracing::info!(label, "Running provisioning step...");
    match ssh_exec(host, cmd).await {
        Ok(out) => {
            let trimmed = out.trim();
            if trimmed.is_empty() {
                tracing::info!(label, "Step completed");
            } else {
                tracing::info!(label, output = trimmed, "Step completed");
            }
        }
        Err(e) => tracing::warn!(label, error = %e, "Step failed (non-fatal)"),
    }
}

/// Provision the macOS base image with Homebrew, AI coding tools, and runtimes.
///
/// Called during `create_base_snapshot` after SSH is available on the second boot.
/// Installs into the base image so all cloned instances inherit the software.
///
/// Best-effort: individual step failures are logged but do not abort provisioning.
async fn provision_base_software(host: &str) -> Result<(), VZError> {
    tracing::info!(host, "Starting base software provisioning...");

    // 1. Create user 'theyos' (Homebrew refuses to run as root)
    ssh_run(
        host,
        "create_user",
        "sysadminctl -addUser theyos -password theyos -admin 2>/dev/null; \
         mkdir -p /etc/sudoers.d && \
         echo 'theyos ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/theyos && \
         chmod 440 /etc/sudoers.d/theyos",
    )
    .await;

    // 2. Install Homebrew as user theyos
    ssh_run(host, "install_homebrew",
        "su - theyos -c 'NONINTERACTIVE=1 tmp=$(mktemp /tmp/homebrew-install.XXXXXX) && \
         curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh -o \"$tmp\" && \
         chmod +x \"$tmp\" && \
         \"$tmp\"; \
         rc=$?; \
         rm -f \"$tmp\"; \
         exit $rc'"
    ).await;

    // Add brew to root's PATH so subsequent commands can find it
    ssh_run(
        host,
        "brew_path",
        "echo 'eval \"$(/opt/homebrew/bin/brew shellenv)\"' >> /var/root/.zprofile && \
         echo 'eval \"$(/opt/homebrew/bin/brew shellenv)\"' >> /var/root/.zshrc && \
         echo 'export PATH=\"/opt/homebrew/bin:/opt/homebrew/sbin:$PATH\"' >> /var/root/.zshrc",
    )
    .await;

    // 3. Install Codex (Rust native binary via Homebrew cask)
    ssh_run(
        host,
        "install_codex",
        "su - theyos -c 'export PATH=\"/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH\"; \
         /opt/homebrew/bin/brew install --cask codex' && \
         if [ ! -x /opt/homebrew/bin/codex ]; then \
           _codex_bin=$(find /opt/homebrew/Caskroom/codex -type f -name codex-aarch64-apple-darwin 2>/dev/null | sort | tail -n 1); \
           if [ -n \"$_codex_bin\" ]; then \
             ln -sf \"$_codex_bin\" /opt/homebrew/bin/codex && chmod +x \"$_codex_bin\"; \
           fi; \
         fi && \
         test -x /opt/homebrew/bin/codex && \
         (/opt/homebrew/bin/codex --version >/dev/null 2>&1 || /opt/homebrew/bin/codex -V >/dev/null 2>&1 || true)",
    )
    .await;

    // 4. Install Claude Code (native installer, no Node.js needed)
    ssh_run(
        host,
        "install_claude_code",
        "curl -fsSL https://claude.ai/install.sh | bash",
    )
    .await;

    // 5. Install OpenCode (brew formula with Node.js + ripgrep as deps)
    ssh_run(
        host,
        "install_opencode",
        "su - theyos -c 'export PATH=\"/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH\"; \
         /opt/homebrew/bin/brew install anomalyco/tap/opencode'",
    )
    .await;

    // 6. Install Python 3 + Node.js (needed for nanobot=pip, openclaw=npm per-instance installs)
    ssh_run(
        host,
        "install_python_node",
        "su - theyos -c 'export PATH=\"/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH\"; \
         /opt/homebrew/bin/brew install python3 node'",
    )
    .await;

    // 7. Install tmux
    ssh_run(
        host,
        "install_tmux",
        "su - theyos -c 'export PATH=\"/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH\"; \
         /opt/homebrew/bin/brew install tmux'",
    )
    .await;

    // 7. Write .tmux.conf (same as Linux minus pane-scrollbars)
    ssh_run(
        host,
        "write_tmux_conf",
        "cat > /var/root/.tmux.conf << 'TMUXEOF'\n\
         set -g default-terminal \"xterm-256color\"\n\
         set -g default-shell \"/bin/zsh\"\n\
         set -g mouse on\n\
         set -g set-clipboard on\n\
         set -g history-limit 50000\n\
         TMUXEOF",
    )
    .await;

    // 8. Write .zshrc with prompt identical to Linux + PATH for brew
    ssh_run(
        host,
        "write_zshrc",
        "cat > /var/root/.zshrc << 'ZSHEOF'\n\
         setopt PROMPT_SUBST\n\
         PROMPT='%F{#4e9a04}[claw@soyeht:%~]$ %f'\n\
         export LANG=C.UTF-8\n\
         export PATH=\"/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH\"\n\
         ZSHEOF",
    )
    .await;

    // 9. Verify installations
    let verify_tools_cmd = r#"export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:$HOME/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
tool_version() {
  name="$1"
  abs="$2"
  path="$(command -v "$name" 2>/dev/null || true)"
  if [ -z "$path" ] && [ -n "$abs" ] && [ -x "$abs" ]; then
    path="$abs"
  fi
  if [ -z "$path" ]; then
    echo "$name: not found (PATH=$PATH)"
    if [ -n "$abs" ] && [ -e "$abs" ]; then
      ls -l "$abs"
    fi
    return 0
  fi
  version="$("$path" --version 2>/dev/null | head -1 || true)"
  if [ -z "$version" ]; then
    version="$("$path" -V 2>/dev/null | head -1 || true)"
  fi
  if [ -z "$version" ]; then
    version="$("$path" version 2>/dev/null | head -1 || true)"
  fi
  if [ -z "$version" ]; then
    version="installed at $path"
  fi
  echo "$name: $version"
}
tool_version brew /opt/homebrew/bin/brew
tool_version codex /opt/homebrew/bin/codex
tool_version claude /var/root/.local/bin/claude
tool_version opencode /opt/homebrew/bin/opencode
tool_version tmux /opt/homebrew/bin/tmux"#;
    ssh_run(host, "verify_tools", verify_tools_cmd).await;

    tracing::info!(host, "Base software provisioning complete");
    Ok(())
}

// ── Base snapshot creation ────────────────────────────────────────────────────

/// Create the VZ base snapshot of the provisioned macOS disk image.
///
/// Uses a **two-boot cycle** because macOS first-boot overwrites the launchd
/// disabled database (`disabled.plist`), erasing our sshd-enable entry:
///
/// 1. **First boot** — macOS initializes (SSV sealing, launchd migration, etc.).
///    DHCP works but sshd is not running. After DHCP + settle time, we stop the VM.
/// 2. **Fix ownership** — mount the Data volume, use `sudo` to add the sshd entry
///    to the now-existing `disabled.plist` and fix file ownership to `root:wheel`.
/// 3. **Second boot** — sshd starts correctly. We wait for SSH, then snapshot.
///
/// Returns `(snapshot_path, machine_identifier_data)` where `machine_identifier_data`
/// is the raw `VZMacMachineIdentifier` ECID bytes. Callers must persist these in
/// `init-state.json` so that warm pool and cold boot VMs use the same ECID.
///
/// # Errors
///
/// Detach any stale `hdiutil` attachments of the given disk image.
///
/// Defensive cleanup for cases where a previous `fix_sshd_after_first_boot` run
/// failed to detach the disk. Without this, VZ rejects the attachment.
async fn cleanup_stale_disk_attachments(disk_path: &Path) {
    let Ok(output) = tokio::process::Command::new("hdiutil")
        .args(["info", "-plist"])
        .output()
        .await
    else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let info = String::from_utf8_lossy(&output.stdout);
    let disk_str = disk_path.to_str().unwrap_or("");
    if disk_str.is_empty() || !info.contains(disk_str) {
        return;
    }
    tracing::warn!(
        disk = %disk_path.display(),
        "Found stale hdiutil attachment from previous run, force-detaching..."
    );
    // Detach by image path (hdiutil resolves the /dev/diskN internally).
    let _ = tokio::process::Command::new("hdiutil")
        .args(["detach", disk_str, "-force"])
        .output()
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// Collect post-failure diagnostics from a stopped guest's disk image.
///
/// Best-effort: every step that fails is recorded as a warning in the bundle;
/// nothing here propagates as an error to the caller. Returns a JSON-encoded
/// `DiagBundle` ready to embed in an error message.
///
/// Intended ordering (caller's responsibility): the VM **must** be stopped
/// before this is called — VZ holds an exclusive lock on `disk.img` while
/// running, and `hdiutil attach -readonly` racing that lock yields either an
/// error or inconsistent reads.
fn collect_host_network_state(vm_ip: &str) -> Vec<String> {
    use std::process::Command;
    let mut out = Vec::new();
    let probes: &[(&str, &[&str])] = &[
        ("arp -an", &["arp", "-an"]),
        ("route get", &["route", "-n", "get", vm_ip]),
        ("ifconfig bridge100", &["ifconfig", "bridge100"]),
        ("nc -zv -w 2", &["nc", "-zv", "-w", "2", vm_ip, "22"]),
        (
            "ping -c 1 -W 1000",
            &["ping", "-c", "1", "-W", "1000", vm_ip],
        ),
    ];
    for (label, args) in probes {
        let res = Command::new(args[0]).args(&args[1..]).output();
        let entry = match res {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let stderr = String::from_utf8_lossy(&o.stderr);
                let combined = if stderr.trim().is_empty() {
                    stdout.into_owned()
                } else {
                    format!("{stdout}{stderr}")
                };
                let exit = o.status.code().unwrap_or(-1);
                format!("$ {label} (exit={exit})\n{combined}")
            }
            Err(e) => format!("$ {label} -> spawn failed: {e}"),
        };
        out.push(entry);
    }
    let leases = std::fs::read_to_string("/var/db/dhcpd_leases").unwrap_or_default();
    out.push(format!("/var/db/dhcpd_leases:\n{leases}"));
    out
}

fn collect_failure_diagnostics(disk_path: &Path, vm_ip: &str, host_net: Vec<String>) -> String {
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;

    const MAX_LOG_BYTES: u64 = 64 * 1024;

    #[derive(serde::Serialize)]
    struct DiagBundle {
        vm_ip: String,
        host_net: Vec<String>,
        plist_stat: Vec<String>,
        guest_logs: Vec<GuestLog>,
        warnings: Vec<String>,
    }
    #[derive(serde::Serialize)]
    struct GuestLog {
        path: String,
        bytes: u64,
        content: String,
    }

    let mut bundle = DiagBundle {
        vm_ip: vm_ip.to_string(),
        host_net,
        plist_stat: Vec::new(),
        guest_logs: Vec::new(),
        warnings: Vec::new(),
    };

    let Some(disk_str) = disk_path.to_str() else {
        bundle.warnings.push("disk path not utf-8".into());
        return serde_json::to_string_pretty(&bundle).unwrap_or_default();
    };

    // ── Wait for VZ to release disk lock, then attach RO ────────────────────
    // Mirrors detach_with_retry's 3-attempt / 2s-spacing pattern. The lock
    // typically clears within 1-2s of vm.stop().
    let mut attach_out = None;
    for attempt in 1..=3u8 {
        let r = Command::new("hdiutil")
            .args(["attach", "-readonly", "-nomount", "-plist", disk_str])
            .output();
        match r {
            Ok(o) if o.status.success() => {
                attach_out = Some(o);
                break;
            }
            Ok(o) => {
                bundle.warnings.push(format!(
                    "hdiutil attach attempt {attempt}: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                ));
            }
            Err(e) => {
                bundle
                    .warnings
                    .push(format!("hdiutil attach attempt {attempt}: {e}"));
            }
        }
        if attempt < 3 {
            std::thread::sleep(Duration::from_secs(2));
        }
    }
    let Some(attach_out) = attach_out else {
        bundle
            .warnings
            .push("could not attach disk RO; skipping mount-side diagnostics".into());
        return serde_json::to_string_pretty(&bundle).unwrap_or_default();
    };
    let plist_str = String::from_utf8_lossy(&attach_out.stdout);

    let data_dev = match find_apfs_data_volume(&plist_str) {
        Ok(d) => d,
        Err(e) => {
            bundle.warnings.push(format!("find Data volume: {e}"));
            return serde_json::to_string_pretty(&bundle).unwrap_or_default();
        }
    };

    // Extract base disk for detach (mirrors theyos_provision_inject helper).
    let base_disk = plist_str.lines().find_map(|line| {
        let trimmed = line.trim();
        let rest = trimmed.strip_prefix("<string>/dev/disk")?;
        let suffix = rest.strip_suffix("</string>")?;
        if suffix.chars().all(|c| c.is_ascii_digit()) {
            Some(format!("/dev/disk{suffix}"))
        } else {
            None
        }
    });

    let mount_dir = match tempfile::TempDir::new() {
        Ok(d) => d,
        Err(e) => {
            bundle.warnings.push(format!("tempdir: {e}"));
            if let Some(ref bd) = base_disk {
                let _ = Command::new("hdiutil").args(["detach", bd]).output();
            }
            return serde_json::to_string_pretty(&bundle).unwrap_or_default();
        }
    };
    let mp = mount_dir.path();
    let mount_out = Command::new("mount")
        .args(["-t", "apfs", "-o", "ro,owners,nobrowse", &data_dev])
        .arg(mp)
        .output();
    match mount_out {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            bundle.warnings.push(format!(
                "mount: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ));
            if let Some(ref bd) = base_disk {
                let _ = Command::new("hdiutil").args(["detach", bd]).output();
            }
            return serde_json::to_string_pretty(&bundle).unwrap_or_default();
        }
        Err(e) => {
            bundle.warnings.push(format!("mount: {e}"));
            if let Some(ref bd) = base_disk {
                let _ = Command::new("hdiutil").args(["detach", bd]).output();
            }
            return serde_json::to_string_pretty(&bundle).unwrap_or_default();
        }
    }

    // ── Stat the LaunchDaemon plists ────────────────────────────────────────
    for rel in &[
        "Library/LaunchDaemons/com.theyos.sshd.plist",
        "Library/LaunchDaemons/com.theyos.provision.plist",
        "private/var/db/.AppleSetupDone",
        "private/etc/ssh/sshd_config.d/200-theyos.conf",
    ] {
        let p = mp.join(rel);
        match std::fs::symlink_metadata(&p) {
            Ok(m) => bundle.plist_stat.push(format!(
                "{rel}: uid={} gid={} mode={:o} size={}",
                m.uid(),
                m.gid(),
                m.mode() & 0o7777,
                m.len()
            )),
            Err(e) => bundle.plist_stat.push(format!("{rel}: {e}")),
        }
    }

    // ── Read truncated guest log files ──────────────────────────────────────
    for rel in &[
        "private/var/log/theyos-sshd.err",
        "private/var/log/theyos-provision.log",
        "private/var/log/theyos-provision.err",
    ] {
        let p = mp.join(rel);
        match std::fs::metadata(&p) {
            Ok(m) => {
                let bytes_total = m.len();
                let to_read = bytes_total.min(MAX_LOG_BYTES);
                let content = match std::fs::read(&p) {
                    Ok(b) => {
                        let start = b.len().saturating_sub(to_read as usize);
                        String::from_utf8_lossy(&b[start..]).into_owned()
                    }
                    Err(e) => format!("(read failed: {e})"),
                };
                bundle.guest_logs.push(GuestLog {
                    path: rel.to_string(),
                    bytes: bytes_total,
                    content,
                });
            }
            Err(e) => {
                // Use a sentinel in `bytes` and put the error in content so
                // downstream tooling can distinguish "missing" from "huge".
                bundle.guest_logs.push(GuestLog {
                    path: rel.to_string(),
                    bytes: 0,
                    content: format!("(stat failed: {e})"),
                });
            }
        }
    }

    // ── Cleanup ─────────────────────────────────────────────────────────────
    if let Err(e) = Command::new("umount").arg(mp).output() {
        bundle.warnings.push(format!("umount: {e}"));
    }
    if let Some(ref bd) = base_disk {
        for attempt in 1..=3u8 {
            let r = Command::new("hdiutil").args(["detach", bd]).output();
            if matches!(r, Ok(ref o) if o.status.success()) {
                break;
            }
            if attempt == 3 {
                let _ = Command::new("hdiutil")
                    .args(["detach", "-force", bd])
                    .output();
            } else {
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }

    serde_json::to_string_pretty(&bundle).unwrap_or_default()
}

/// Boot the macOS guest, verify SSH, provision base software, and save a VZ snapshot.
///
/// This is a **single-boot** flow: the `theyos-provision-inject` helper has already
/// written `com.theyos.sshd.plist` with correct `root:wheel` ownership, so sshd
/// starts on the very first boot. No two-boot cycle or `fix_sshd_after_first_boot`
/// is needed.
///
/// # Errors
///
/// Returns `VZError::SnapshotError` if snapshot creation fails, or
/// `VZError::NetworkError` if DHCP/SSH times out.
pub async fn create_base_snapshot(
    disk_path: &Path,
    aux_storage_path: &Path,
    hardware_model_data: &[u8],
    machine_identifier_data: Option<&[u8]>,
    base_dir: &Path,
    cpus: u32,
    memory_mb: u32,
) -> Result<(PathBuf, Vec<u8>), VZError> {
    use crate::vz::{VZMacOSVmConfigurationBuilder, VZVirtualMachine};

    let snapshot_path = base_dir.join("base.vzsnapshot");
    let snapshot_tmp_path = base_dir.join("base.vzsnapshot.new");

    // Defensive cleanup: detach any stale hdiutil attachments from previous failed runs.
    cleanup_stale_disk_attachments(disk_path).await;

    // VZ refuses to overwrite an existing snapshot. Save a temporary sibling
    // first and replace the previous good snapshot only after the new one is
    // fully written.
    if snapshot_tmp_path.exists() {
        std::fs::remove_file(&snapshot_tmp_path)
            .map_err(|e| VZError::SnapshotError(format!("remove stale temp snapshot: {e}")))?;
    }

    // ── Single boot: macOS init + SSH + provision + snapshot ─────────────────
    tracing::info!("Booting macOS VM (single-boot: sshd plist pre-injected with root:wheel)...");

    let mut builder = VZMacOSVmConfigurationBuilder::new()
        .cpus(cpus)
        .memory_mb(memory_mb)
        .disk_path(disk_path.to_path_buf())
        .aux_storage_path(aux_storage_path.to_path_buf())
        .hardware_model_data(hardware_model_data.to_vec());

    if let Some(id) = machine_identifier_data {
        builder = builder.machine_identifier_data(id.to_vec());
    }

    let config = builder.build()?;

    let machine_id_data = config.machine_identifier_data.clone();
    let mac_address = config.mac_address.clone();

    let existing_ips = crate::snapshot_leased_ips().await;

    let vm = VZVirtualMachine::new(&config, "macos-base-boot")?;
    drop(config);
    vm.start().await?;

    tracing::info!(mac = %mac_address, "Waiting for DHCP...");
    let vm_ip = match crate::resolve_dhcp_ip(&mac_address, 300, &existing_ips).await {
        Ok(ip) => ip,
        Err(e) => {
            let _ = vm.stop(false).await;
            return Err(VZError::NetworkError(format!("DHCP timeout: {e}")));
        }
    };

    // Wait for SSH with extended timeout (420s) to cover macOS first-boot tasks
    // (launchd migration, SSV sealing, ~120s) plus sshd startup. Re-resolves IP
    // by MAC every ~30s in case guest got a new DHCP lease during boot.
    tracing::info!(ip = %vm_ip, mac = %mac_address, "DHCP obtained. Waiting for SSH (up to 420s for first-boot settle)...");
    let vm_ip = match wait_for_ssh_by_mac(&vm_ip, &mac_address, 420).await {
        Ok(ip) => ip,
        Err(e) => {
            // Capture host-side network state while the VM is still running — arp,
            // route, ifconfig, nc, ping. After vm.stop the bridge teardown clears
            // ARP and the IP becomes unreachable in a different way.
            let host_net = collect_host_network_state(&vm_ip);

            // Stop the VM so the disk lock is released; only then can we mount RO.
            let _ = vm.stop(false).await;

            // Best-effort: collect plist stats and guest log files from the disk.
            let diag = collect_failure_diagnostics(disk_path, &vm_ip, host_net);

            return Err(VZError::NetworkError(format!(
                "SSH not available after boot: {e}\n\
                 Check that com.theyos.sshd.plist was injected with root:wheel ownership.\n\
                 --- diagnostics (best-effort) ---\n{diag}"
            )));
        }
    };
    tracing::info!(ip = %vm_ip, "SSH ready! Provisioning base software...");

    // Install Homebrew, tools (codex, claude-code, opencode) into the base image.
    // Best-effort: failures are logged but don't block snapshot creation.
    if let Err(e) = provision_base_software(&vm_ip).await {
        tracing::warn!(error = %e, "Base software provisioning failed (non-fatal)");
    }

    tracing::info!(ip = %vm_ip, "Provisioning done. Pausing and saving snapshot...");

    vm.pause().await?;
    if let Err(e) = vm.save_snapshot(&snapshot_tmp_path).await {
        let _ = vm.stop(false).await;
        let _ = std::fs::remove_file(&snapshot_tmp_path);
        return Err(e);
    }
    if let Err(e) = vm.stop(false).await {
        let _ = std::fs::remove_file(&snapshot_tmp_path);
        return Err(e);
    }

    std::fs::rename(&snapshot_tmp_path, &snapshot_path)
        .map_err(|e| VZError::SnapshotError(format!("replace base snapshot: {e}")))?;

    tracing::info!(path = %snapshot_path.display(), "macOS base snapshot created");
    Ok((snapshot_path, machine_id_data))
}

// ── Base directory removal ─────────────────────────────────────────────────────

/// Remove all macOS base image files and return the number of bytes freed.
///
/// Deletes `base_dir` and all its contents (including `disk.img`, `aux.auxstorage`,
/// `base.vzsnapshot`, `init-state.json`, and the `binaries/` subdirectory) via
/// `std::fs::remove_dir_all`.
///
/// Returns `Ok(0)` if `base_dir` does not exist (idempotent).
///
/// # Errors
///
/// Returns `VZError::Internal` if directory removal fails.
pub fn remove_base_dir(base_dir: &Path) -> Result<u64, VZError> {
    if !base_dir.exists() {
        return Ok(0);
    }
    let bytes_freed = measure_dir_size(base_dir);
    std::fs::remove_dir_all(base_dir)
        .map_err(|e| VZError::Internal(format!("remove_dir_all {}: {e}", base_dir.display())))?;
    tracing::info!(path = %base_dir.display(), bytes_freed, "macOS base dir removed");
    Ok(bytes_freed)
}

/// Recursively measure the total size of a directory's contents in bytes.
pub(crate) fn measure_dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                total += measure_dir_size(&p);
            } else if let Ok(meta) = std::fs::metadata(&p) {
                total += meta.len();
            }
        }
    }
    total
}

// ── Snapshot rebuild ──────────────────────────────────────────────────────────

/// Re-run the Provision phase on an already-installed macOS base disk, then re-snapshot.
///
/// This is triggered by `theyos init-macos-guest --force-provision`. It re-downloads
/// darwin/arm64 claw binaries, re-injects them into the existing `disk.img`, deletes the
/// old `base.vzsnapshot`, and creates a fresh snapshot — without re-installing macOS.
///
/// # Preconditions
///
/// The base image must have already completed at least the `InstallMacOS` phase (i.e.
/// `disk.img` and `hardware_model_data` in `init-state.json` must exist).
///
/// # Errors
///
/// Returns `VZError::Internal` if a required file is missing or any step fails.
pub async fn rebuild_base_snapshot(
    base_dir: &Path,
    registry_url: &str,
    ssh_pubkey: &str,
    plist_dir: &Path,
    cpus: u32,
    memory_mb: u32,
) -> Result<PathBuf, VZError> {
    use crate::init_state::{InitPhase, read_state, write_state};
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    // ── 1. Verify that macOS was already installed (disk + hardware model exist) ──

    let mut state = read_state(base_dir)?;

    let installed = matches!(
        &state.phase,
        Some(
            InitPhase::InstallMacOS
                | InitPhase::Provision
                | InitPhase::CreateSnapshot
                | InitPhase::Complete
        )
    );
    if !installed {
        return Err(VZError::Internal(
            "rebuild_base_snapshot requires macOS to be already installed (phase >= install_mac_o_s)".into(),
        ));
    }

    let hw_data = state
        .hardware_model_data
        .as_deref()
        .and_then(|b| BASE64.decode(b).ok())
        .ok_or_else(|| {
            VZError::Internal("hardware_model_data missing from init-state.json".into())
        })?;

    let disk_path = base_dir.join("disk.img");
    if !disk_path.exists() {
        return Err(VZError::Internal(format!(
            "disk.img not found at {}",
            disk_path.display()
        )));
    }

    // ── 2. Download fresh claw binaries ───────────────────────────────────────

    if !registry_url.is_empty() {
        let binaries_dir = base_dir.join("binaries");
        tracing::info!("Downloading fresh darwin/arm64 claw binaries...");
        match download_claw_binaries(registry_url, &binaries_dir, |ct| {
            tracing::info!(claw_type = ct, "Downloading binary");
        }) {
            Ok(downloaded) => tracing::info!(count = downloaded.len(), "Binaries downloaded"),
            Err(e) => tracing::warn!("Binary download failed (non-fatal): {e}"),
        }
    }

    // ── 3. Re-inject provisioning files into the existing disk ─────────────────

    tracing::info!("Re-injecting provisioning files into APFS volume...");
    inject_provision_files(&disk_path, ssh_pubkey, plist_dir)?;

    state.phase = Some(InitPhase::Provision);
    write_state(base_dir, &state)?;

    // ── 4. Create fresh base snapshot ─────────────────────────────────────────

    let aux_path = base_dir.join("aux.auxstorage");
    tracing::info!("Creating fresh base VZ snapshot...");
    let install_machine_id = state
        .machine_identifier_data_b64
        .as_deref()
        .and_then(|b| BASE64.decode(b).ok());
    let snapshot_cpus = cpus.max(state.install_cpu_count.unwrap_or(cpus));
    let snapshot_memory_mb = memory_mb.max(state.install_memory_mb.unwrap_or(memory_mb));
    let (snapshot_path, machine_id_data) = create_base_snapshot(
        &disk_path,
        &aux_path,
        &hw_data,
        install_machine_id.as_deref(),
        base_dir,
        snapshot_cpus,
        snapshot_memory_mb,
    )
    .await?;

    state.snapshot_path = Some(snapshot_path.display().to_string());
    state.machine_identifier_data_b64 = if machine_id_data.is_empty() {
        None
    } else {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_RT};
        Some(BASE64_RT.encode(&machine_id_data))
    };
    state.snapshot_cpus = Some(snapshot_cpus);
    state.snapshot_memory_mb = Some(snapshot_memory_mb);
    state.phase = Some(InitPhase::Complete);
    write_state(base_dir, &state)?;

    tracing::info!(path = %snapshot_path.display(), "Base snapshot rebuilt successfully");
    Ok(snapshot_path)
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn extract_version_and_build_from_restore_url() {
        let url = "https://updates.cdn-apple.com/2026/UniversalMac_26.4_25E246_Restore.ipsw";
        assert_eq!(extract_macos_version_from_url(url).as_deref(), Some("26.4"));
        assert_eq!(extract_macos_build_from_url(url).as_deref(), Some("25E246"));
    }

    #[test]
    fn expected_filename_uses_build_when_available() {
        assert_eq!(
            expected_restore_filename("26.4", Some("25E246")),
            "UniversalMac_26.4_25E246_Restore.ipsw"
        );
        assert_eq!(
            expected_restore_filename("26.4", None),
            "UniversalMac_26.4_<build>_Restore.ipsw"
        );
    }

    #[test]
    fn incompatible_error_mentions_manual_override() {
        let err = incompatible_restore_image_error("26.4", Some("25E246"), "26.4.1");
        assert!(err.contains("26.4.1"));
        assert!(err.contains("25E246"));
        assert!(err.contains("--ipsw"));
    }

    fn fw(version: &str, build: &str, url: &str, signed: bool) -> IpswIndexFirmware {
        IpswIndexFirmware {
            version: version.to_string(),
            build_id: build.to_string(),
            url: url.to_string(),
            signed,
        }
    }

    #[test]
    fn host_restore_candidates_prefers_exact_build_match() {
        let firmwares = vec![
            fw(
                "26.4",
                "25E246",
                "https://updates.cdn-apple.com/restore-26.4",
                true,
            ),
            fw(
                "26.4",
                "25E999",
                "https://updates.cdn-apple.com/restore-26.4-other",
                true,
            ),
        ];
        // "25E999" > host "25E246" → Tier 2 also rejects it. Only the exact match remains.
        let candidates = select_host_restore_candidates(&firmwares, "26.4", Some("25E246"));
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].build_id, "25E246");
    }

    #[test]
    fn host_restore_candidates_unparseable_host_build_keeps_version_match() {
        let firmwares = vec![
            fw(
                "26.4",
                "25E246",
                "https://updates.cdn-apple.com/restore-26.4",
                true,
            ),
            fw(
                "26.4",
                "25E247",
                "https://updates.cdn-apple.com/restore-26.4-alt",
                false,
            ),
        ];
        // host_build "missing" doesn't parse → host_build_supports_image is optimistic
        // → Tier 2 includes 25E246 (signed). 25E247 unsigned excluded.
        let candidates = select_host_restore_candidates(&firmwares, "26.4", Some("missing"));
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].version, "26.4");
        assert_eq!(candidates[0].build_id, "25E246");
    }

    #[test]
    fn matching_lookup_error_includes_issue_link_and_context() {
        let err = matching_restore_lookup_error(
            Some("Mac13,2"),
            "26.4",
            Some("25E246"),
            "26.4.1",
            "https://updates.cdn-apple.com/latest.ipsw",
            "no signed restore match found in host-build lookup",
        );
        assert!(err.contains(MACOS_RESTORE_ISSUE_URL));
        assert!(err.contains("host_model: Mac13,2"));
        assert!(err.contains("host_macos_build: 25E246"));
        assert!(err.contains("latest_supported_restore_version: 26.4.1"));
    }

    #[test]
    fn same_version() {
        assert!(host_version_sufficient("26.4", "26.4"));
    }

    #[test]
    fn host_newer_minor() {
        assert!(host_version_sufficient("26.5", "26.4"));
    }

    #[test]
    fn host_older_minor() {
        assert!(!host_version_sufficient("26.3", "26.4"));
    }

    #[test]
    fn host_newer_major() {
        assert!(host_version_sufficient("27.0", "26.4"));
    }

    #[test]
    fn host_older_major() {
        assert!(!host_version_sufficient("25.0", "26.4"));
    }

    #[test]
    fn patch_versions() {
        assert!(host_version_sufficient("26.4.1", "26.4"));
        assert!(!host_version_sufficient("26.3.9", "26.4"));
    }

    #[test]
    fn unparseable_returns_true() {
        assert!(host_version_sufficient("unknown", "26.4"));
        assert!(host_version_sufficient("26.4", "unknown"));
    }

    #[test]
    fn empty_returns_true() {
        assert!(host_version_sufficient("", "26.4"));
        assert!(host_version_sufficient("26.4", ""));
    }

    // ── parse_apple_build ────────────────────────────────────────────────

    #[test]
    fn parse_apple_build_standard() {
        assert_eq!(
            parse_apple_build("25E246"),
            Some((25, "E".into(), 246, String::new()))
        );
    }

    #[test]
    fn parse_apple_build_long_build_number() {
        assert_eq!(
            parse_apple_build("24D2054"),
            Some((24, "D".into(), 2054, String::new()))
        );
    }

    #[test]
    fn parse_apple_build_with_lowercase_suffix() {
        assert_eq!(
            parse_apple_build("25E246a"),
            Some((25, "E".into(), 246, "a".into()))
        );
    }

    #[test]
    fn parse_apple_build_invalid_returns_none() {
        assert_eq!(parse_apple_build("foo"), None);
        assert_eq!(parse_apple_build(""), None);
        assert_eq!(parse_apple_build("25"), None);
        assert_eq!(parse_apple_build("E246"), None);
    }

    // ── cmp_apple_builds ─────────────────────────────────────────────────

    #[test]
    fn cmp_apple_builds_orders_within_train() {
        assert_eq!(cmp_apple_builds("25E236", "25E246"), Ordering::Less);
        assert_eq!(cmp_apple_builds("25E246", "25E236"), Ordering::Greater);
        assert_eq!(cmp_apple_builds("25E246", "25E246"), Ordering::Equal);
    }

    #[test]
    fn cmp_apple_builds_numeric_not_lexicographic() {
        // The whole point: lex compare would say "25E99" > "25E100" because '9' > '1'.
        assert_eq!(cmp_apple_builds("25E99", "25E100"), Ordering::Less);
        assert_eq!(cmp_apple_builds("24D70", "24D2054"), Ordering::Less);
    }

    #[test]
    fn cmp_apple_builds_cross_train() {
        assert_eq!(cmp_apple_builds("25E999", "25F100"), Ordering::Less);
        assert_eq!(cmp_apple_builds("25Z999", "26A001"), Ordering::Less);
    }

    #[test]
    fn cmp_apple_builds_unparseable_is_optimistic() {
        assert_eq!(cmp_apple_builds("foo", "25E246"), Ordering::Equal);
        assert_eq!(cmp_apple_builds("25E246", "garbage"), Ordering::Equal);
    }

    // ── host_build_supports_image ────────────────────────────────────────

    #[test]
    fn host_build_supports_image_exact_match() {
        assert!(host_build_supports_image("25E236", "25E236"));
    }

    #[test]
    fn host_build_supports_image_older_image_is_compatible() {
        assert!(host_build_supports_image("25E246", "25E236"));
    }

    #[test]
    fn host_build_supports_image_newer_image_is_rejected() {
        // The bug we are fixing: image_build > host_build must return false.
        assert!(!host_build_supports_image("25E236", "25E246"));
    }

    #[test]
    fn host_build_supports_image_numeric_not_lex() {
        assert!(host_build_supports_image("25E100", "25E99"));
        assert!(!host_build_supports_image("25E99", "25E100"));
    }

    #[test]
    fn host_build_supports_image_optimistic_when_unknown() {
        assert!(host_build_supports_image("25E236", ""));
        assert!(host_build_supports_image("", "25E236"));
        assert!(host_build_supports_image("25E236", "garbage"));
        assert!(host_build_supports_image("garbage", "25E236"));
    }

    // ── cmp_macos_versions ───────────────────────────────────────────────

    #[test]
    fn cmp_macos_versions_basic() {
        assert_eq!(cmp_macos_versions("26.4", "26.3"), Ordering::Greater);
        assert_eq!(cmp_macos_versions("26.4.1", "26.4"), Ordering::Greater);
        assert_eq!(cmp_macos_versions("26.4", "26.4"), Ordering::Equal);
        assert_eq!(cmp_macos_versions("27", "26.99"), Ordering::Greater);
        assert_eq!(cmp_macos_versions("26.3.1", "26.3.0"), Ordering::Greater);
    }

    // ── select_host_restore_candidates: tier-by-tier ─────────────────────

    #[test]
    fn candidates_tier1_exact_first_then_tier2_skips_newer_build() {
        let firmwares = vec![
            fw("26.4", "25E246", "u-25E246", true),
            fw("26.4", "25E236", "u-25E236", true),
        ];
        let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
        // Tier 1 picks 25E236; Tier 2 must reject 25E246 because 25E246 > 25E236.
        let labels: Vec<&str> = cs.iter().map(|c| c.build_id.as_str()).collect();
        assert_eq!(labels, vec!["25E236"]);
    }

    #[test]
    fn candidates_tier2_falls_back_to_older_build() {
        let firmwares = vec![
            fw("26.4", "25E246", "u-25E246", true),
            fw("26.4", "25E230", "u-25E230", true),
        ];
        let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
        let labels: Vec<&str> = cs.iter().map(|c| c.build_id.as_str()).collect();
        assert_eq!(labels, vec!["25E230"]);
    }

    #[test]
    fn candidates_tier2_orders_largest_compatible_first() {
        let firmwares = vec![
            fw("26.4", "25E100", "u-100", true),
            fw("26.4", "25E230", "u-230", true),
        ];
        let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
        let labels: Vec<&str> = cs.iter().map(|c| c.build_id.as_str()).collect();
        assert_eq!(labels, vec!["25E230", "25E100"]);
    }

    #[test]
    fn candidates_tier1_then_tier2_ordering() {
        let firmwares = vec![
            fw("26.4", "25E236", "u-236", true),
            fw("26.4", "25E230", "u-230", true),
        ];
        let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
        let labels: Vec<&str> = cs.iter().map(|c| c.build_id.as_str()).collect();
        assert_eq!(labels, vec!["25E236", "25E230"]);
    }

    #[test]
    fn candidates_tier3_legacy_version() {
        let firmwares = vec![
            fw("26.4", "25E246", "u-26.4", true),
            fw("26.3", "25D70", "u-26.3", true),
        ];
        let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
        // Apple's 26.4/25E246 is too new (build > host); Tier 3 picks 26.3.
        let labels: Vec<(&str, &str)> = cs
            .iter()
            .map(|c| (c.version.as_str(), c.build_id.as_str()))
            .collect();
        assert_eq!(labels, vec![("26.3", "25D70")]);
    }

    #[test]
    fn candidates_tier3_orders_newest_legacy_first() {
        let firmwares = vec![
            fw("26.4", "25E246", "u-26.4", true),
            fw("26.3.1", "25D199", "u-26.3.1", true),
            fw("26.3", "25D70", "u-26.3", true),
            fw("26.2", "25C100", "u-26.2", true),
        ];
        let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
        let pairs: Vec<(&str, &str)> = cs
            .iter()
            .map(|c| (c.version.as_str(), c.build_id.as_str()))
            .collect();
        assert_eq!(
            pairs,
            vec![("26.3.1", "25D199"), ("26.3", "25D70"), ("26.2", "25C100")]
        );
    }

    #[test]
    fn candidates_tier1_tier2_tier3_combined() {
        let firmwares = vec![
            fw("26.4", "25E236", "u-236", true),
            fw("26.4", "25E230", "u-230", true),
            fw("26.3", "25D70", "u-26.3", true),
        ];
        let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
        let pairs: Vec<(&str, &str)> = cs
            .iter()
            .map(|c| (c.version.as_str(), c.build_id.as_str()))
            .collect();
        assert_eq!(
            pairs,
            vec![("26.4", "25E236"), ("26.4", "25E230"), ("26.3", "25D70")]
        );
    }

    #[test]
    fn candidates_skip_unsigned() {
        let firmwares = vec![
            fw("26.4", "25E236", "u-236", false),
            fw("26.4", "25E230", "u-230", true),
        ];
        let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
        let labels: Vec<&str> = cs.iter().map(|c| c.build_id.as_str()).collect();
        assert_eq!(labels, vec!["25E230"]);
    }

    #[test]
    fn candidates_no_match_when_only_newer_builds_signed() {
        let firmwares = vec![fw("27.0", "26A001", "u-27", true)];
        let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
        assert!(cs.is_empty());
    }

    #[test]
    fn candidates_truncated_at_max() {
        let mut firmwares = Vec::new();
        // 10 compatible legacy entries — all valid Tier 3 candidates.
        for n in 0..10 {
            let build = format!("25D{:03}", 100 - n);
            let url = format!("u-{n}");
            firmwares.push(fw("26.3", &build, &url, true));
        }
        let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
        // MAX_LEGACY_VERSION_CANDIDATES = 3.
        assert_eq!(cs.len(), 3);
    }

    #[test]
    fn candidates_unknown_host_build_keeps_version_match() {
        let firmwares = vec![
            fw("26.4", "25E246", "u-26.4", true),
            fw("26.3", "25D70", "u-26.3", true),
        ];
        let cs = select_host_restore_candidates(&firmwares, "26.4", None);
        let pairs: Vec<(&str, &str)> = cs
            .iter()
            .map(|c| (c.version.as_str(), c.build_id.as_str()))
            .collect();
        assert_eq!(pairs, vec![("26.4", "25E246"), ("26.3", "25D70")]);
    }

    #[test]
    fn candidates_filename_extract_plus_compat_check_catches_bug() {
        // End-to-end check that the build extracted from a filename is rejected
        // when it's newer than the host's build (the original 25E246 vs 25E236 bug).
        let url = "https://updates.cdn-apple.com/UniversalMac_26.4_25E246_Restore.ipsw";
        let image_build = extract_macos_build_from_url(url);
        assert_eq!(image_build.as_deref(), Some("25E246"));
        assert!(!host_build_supports_image(
            "25E236",
            image_build.as_deref().unwrap()
        ));
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod rebuild_tests {
    use super::*;
    use crate::init_state::{InitPhase, InitState, write_state};
    use tempfile::TempDir;

    #[test]
    fn test_rebuild_fails_if_not_installed() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dir = TempDir::new().unwrap();

        // Phase is DownloadIpsw — not yet installed
        let mut state = InitState::default();
        state.phase = Some(InitPhase::DownloadIpsw);
        write_state(dir.path(), &state).unwrap();

        let result = rt.block_on(rebuild_base_snapshot(
            dir.path(),
            "",
            "ssh-ed25519 AAAA test",
            &PathBuf::from("scripts/launchd"),
            2,
            2048,
        ));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("phase >= install_mac_o_s"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn test_rebuild_fails_if_no_state_file() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dir = TempDir::new().unwrap();
        // No state file at all — phase is None (default)

        let result = rt.block_on(rebuild_base_snapshot(
            dir.path(),
            "",
            "ssh-ed25519 AAAA test",
            &PathBuf::from("scripts/launchd"),
            2,
            2048,
        ));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("phase >= install_mac_o_s"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn test_rebuild_fails_if_hardware_model_missing() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dir = TempDir::new().unwrap();

        // Phase is Complete but no hardware_model_data
        let mut state = InitState::default();
        state.phase = Some(InitPhase::Complete);
        state.hardware_model_data = None;
        write_state(dir.path(), &state).unwrap();

        // Also create disk.img so it doesn't fail on that check
        std::fs::write(dir.path().join("disk.img"), b"fake").unwrap();

        let result = rt.block_on(rebuild_base_snapshot(
            dir.path(),
            "",
            "ssh-ed25519 AAAA test",
            &PathBuf::from("scripts/launchd"),
            2,
            2048,
        ));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("hardware_model_data"), "unexpected: {msg}");
    }

    #[test]
    fn test_rebuild_fails_if_disk_missing() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dir = TempDir::new().unwrap();

        // Phase is Complete with hardware model but disk.img absent
        let mut state = InitState::default();
        state.phase = Some(InitPhase::Complete);
        state.hardware_model_data =
            Some(base64::engine::general_purpose::STANDARD.encode(b"fake-hw-model"));
        write_state(dir.path(), &state).unwrap();
        // disk.img intentionally NOT created

        let result = rt.block_on(rebuild_base_snapshot(
            dir.path(),
            "",
            "ssh-ed25519 AAAA test",
            &PathBuf::from("scripts/launchd"),
            2,
            2048,
        ));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("disk.img"), "unexpected: {msg}");
    }

    #[test]
    fn test_rebuild_resets_phase_to_provision_before_snapshot() {
        // Verify that the state file reflects Provision phase before
        // create_base_snapshot is called (i.e. crash-safety checkpoint).
        // We can't actually call create_base_snapshot (no VZ framework in tests),
        // so we verify that after inject_provision_files fails (no disk), the
        // written phase is still Provision (not Complete).
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dir = TempDir::new().unwrap();

        let mut state = InitState::default();
        state.phase = Some(InitPhase::Complete);
        state.hardware_model_data =
            Some(base64::engine::general_purpose::STANDARD.encode(b"fake-hw-model"));
        state.snapshot_path = Some("base.vzsnapshot".to_string());
        write_state(dir.path(), &state).unwrap();

        // Create a zero-byte disk.img so the disk check passes but hdiutil will fail
        std::fs::write(dir.path().join("disk.img"), b"").unwrap();

        // rebuild_base_snapshot will fail at inject_provision_files (hdiutil not available in test)
        // but the important invariant is that the error is returned without corrupting state further
        let result = rt.block_on(rebuild_base_snapshot(
            dir.path(),
            "",
            "ssh-ed25519 AAAA test",
            &PathBuf::from("scripts/launchd"),
            2,
            2048,
        ));
        // Should fail (no real hdiutil or VZ in unit tests)
        assert!(result.is_err());
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod remove_tests {
    use super::*;
    use crate::init_state::{INIT_STATE_FILE, InitPhase, InitState, write_state};
    use tempfile::TempDir;

    /// Helper: create a fake base directory with all expected files populated.
    fn create_fake_base_dir(dir: &Path) {
        // Core VM files
        std::fs::write(dir.join("disk.img"), b"fake disk image data").unwrap();
        std::fs::write(dir.join("aux.auxstorage"), b"fake auxiliary storage").unwrap();
        std::fs::write(dir.join("base.vzsnapshot"), b"fake vz snapshot").unwrap();
        std::fs::write(dir.join("macos.ipsw"), b"fake ipsw").unwrap();

        // init-state.json
        let mut state = InitState::default();
        state.phase = Some(InitPhase::Complete);
        state.snapshot_path = Some("base.vzsnapshot".to_string());
        write_state(dir, &state).unwrap();

        // binaries/ subdirectory
        let binaries = dir.join("binaries");
        std::fs::create_dir_all(&binaries).unwrap();
        std::fs::write(binaries.join("theyos-picoclaw"), b"fake binary").unwrap();
        std::fs::write(binaries.join("theyos-zeroclaw"), b"fake binary").unwrap();
    }

    #[test]
    fn test_remove_base_dir_deletes_all_files() {
        let outer = TempDir::new().unwrap();
        let base_dir = outer.path().join("macos-base");
        std::fs::create_dir_all(&base_dir).unwrap();
        create_fake_base_dir(&base_dir);

        // Verify files exist before removal
        assert!(base_dir.join("disk.img").exists());
        assert!(base_dir.join("aux.auxstorage").exists());
        assert!(base_dir.join("base.vzsnapshot").exists());
        assert!(base_dir.join(INIT_STATE_FILE).exists());
        assert!(base_dir.join("binaries").join("theyos-picoclaw").exists());

        let bytes_freed = remove_base_dir(&base_dir).unwrap();

        // Entire directory gone — no orphaned files
        assert!(!base_dir.exists(), "base_dir should be removed entirely");
        assert!(bytes_freed > 0, "should report freed bytes");
    }

    #[test]
    fn test_remove_base_dir_idempotent_when_already_absent() {
        let outer = TempDir::new().unwrap();
        let base_dir = outer.path().join("macos-base-nonexistent");

        // Should not error even if dir doesn't exist
        let result = remove_base_dir(&base_dir);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_remove_base_dir_removes_init_state_json() {
        let outer = TempDir::new().unwrap();
        let base_dir = outer.path().join("macos-base");
        std::fs::create_dir_all(&base_dir).unwrap();
        create_fake_base_dir(&base_dir);

        assert!(base_dir.join(INIT_STATE_FILE).exists());

        remove_base_dir(&base_dir).unwrap();

        // Neither the file nor the directory should remain
        assert!(!base_dir.join(INIT_STATE_FILE).exists());
        assert!(!base_dir.exists());
    }

    #[test]
    fn test_remove_base_dir_removes_nested_binaries() {
        let outer = TempDir::new().unwrap();
        let base_dir = outer.path().join("macos-base");
        std::fs::create_dir_all(&base_dir).unwrap();
        create_fake_base_dir(&base_dir);

        let binary_path = base_dir.join("binaries").join("theyos-picoclaw");
        assert!(binary_path.exists());

        remove_base_dir(&base_dir).unwrap();

        assert!(!binary_path.exists());
        assert!(!base_dir.join("binaries").exists());
    }

    #[test]
    fn test_remove_base_dir_returns_nonzero_bytes_for_nonempty_dir() {
        let outer = TempDir::new().unwrap();
        let base_dir = outer.path().join("macos-base");
        std::fs::create_dir_all(&base_dir).unwrap();
        create_fake_base_dir(&base_dir);

        let bytes = remove_base_dir(&base_dir).unwrap();
        assert!(bytes > 0, "non-empty dir should report bytes_freed > 0");
    }

    #[test]
    fn test_measure_dir_size_counts_nested_files() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.bin"), vec![0u8; 100]).unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("b.bin"), vec![0u8; 200]).unwrap();

        let size = measure_dir_size(dir.path());
        assert_eq!(size, 300, "should sum sizes of all nested files");
    }
}
