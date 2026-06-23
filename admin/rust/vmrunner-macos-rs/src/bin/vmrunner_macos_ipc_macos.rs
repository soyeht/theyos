use core_rs::ipc::harness::run_ipc_loop;
use core_rs::ipc::wire::Response;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use vmrunner_common_rs::{
    DEFAULT_CREATE_CPU_CORES, DEFAULT_CREATE_RAM_MB, MacOsBaseInstallRequest, MacOsPrepareRequest,
    MacOsProvisionAndSnapshotRequest, VmCreateResourceSpec,
};
use vmrunner_macos_rs::{
    AdmissionError, ManagedMacOSVm, VZMacOSVmConfigurationBuilder, VZVirtualMachine,
    VZVirtualMachineConfigurationBuilder, VmAdmission, VmKind, VmLease, VmState, build_cidata_iso,
    clone_base_image, ensure_ssh_key,
    init_state::{InitState, read_state},
    macos_guest, resolve_dhcp_ip,
    slot_manager::{MACOS_VM_LIMIT, MACOS_VM_LIMIT_REACHED},
    snapshot::SnapshotManager,
    warm_pool::{WarmPoolConfig, WarmPoolManager},
};

fn cleanup_failed_macos_install_artifacts(disk_path: &Path, aux_path: &Path) {
    for path in [disk_path, aux_path] {
        match std::fs::remove_file(path) {
            Ok(()) => {
                tracing::info!(path = %path.display(), "removed failed macOS install artifact");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to remove macOS install artifact"
                );
            }
        }
    }
}

/// Centralized string fallback for detecting the VZ host active-VM limit from an
/// error message. Preferred path is the typed [`vmrunner_macos_rs::VZError::HostVmLimitReached`]
/// (set from `NSError.domain == VZErrorDomain && code == 6` in `vz`); this string
/// match is the single fallback for errors that arrive only as text.
fn macos_vm_limit_exceeded(error: &str) -> bool {
    error.contains("\"code\": 6")
        || error.contains("Code=6")
        || error.contains("VZErrorVirtualMachineLimitExceeded")
        || error.contains("maximum supported number of active virtual machines")
        || error.contains("Host VM limit reached")
}

/// True if a [`VZError`](vmrunner_macos_rs::VZError) is the host active-VM limit —
/// typed variant first, centralized string match as fallback.
fn is_macos_vm_limit_error(err: &vmrunner_macos_rs::VZError) -> bool {
    matches!(err, vmrunner_macos_rs::VZError::HostVmLimitReached(_))
        || macos_vm_limit_exceeded(&err.to_string())
}

fn macos_vm_limit_message(source: &str, error: &str) -> String {
    format!(
        "macOS VM startup hit the host active-VM limit while installing from {source}.\n\
         This is not an IPSW compatibility failure, so theyOS did not mark the restore image as bad.\n\
         Stop other Apple Virtualization macOS guests or booted Xcode Simulator devices, then retry \
         `soyeht start -y --force`.\n\
         underlying error: {error}"
    )
}

fn snapshots_dir_from_env_or_home() -> PathBuf {
    match std::env::var("THEYOS_SNAPSHOTS_DIR") {
        Ok(path) if !path.is_empty() => PathBuf::from(path),
        _ => {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join("Library/Application Support/theyos/snapshots")
        }
    }
}

/// Directory that holds VM state, including the admission lease registry.
/// Mirrors the env precedence used elsewhere (state dir, then assets dir, then HOME).
fn vm_state_dir() -> PathBuf {
    for key in ["THEYOS_VM_STATE_DIR", "THEYOS_VM_ASSETS_DIR"] {
        if let Ok(p) = std::env::var(key) {
            if !p.is_empty() {
                return PathBuf::from(p);
            }
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join("Library/Application Support/theyos/vms")
}

/// Map an [`AdmissionError`] to an IPC [`Response`]. Host-limit refusals carry the
/// established machine code so `server-rs` can surface `host_vm_limit_reached`
/// without re-parsing the message. **No VM was started** when this is returned.
fn admission_err_response(err: &AdmissionError) -> Response {
    if err.is_host_vm_limit() {
        Response::err_code(MACOS_VM_LIMIT_REACHED, err)
    } else {
        Response::err(err)
    }
}

/// The single macOS install flow: `DownloadIpsw` → `CreateDisk` → `InstallMacOS`
/// over ranked restore-image candidates. This is the **only** caller of
/// [`macos_guest::install_macos`] and the only place an install VM may start —
/// it reserves and holds one `Install` admission lease across the whole flow
/// (Invariant I-1), shared by both `handle_macos_prepare` (remote) and
/// `handle_macos_base_install` (legacy local CLI).
///
/// On success, `state` is updated with the install result and `phase = Provision`
/// and persisted; returns `Ok(())`. On failure returns a ready error [`Response`]
/// with the lease already released. A VZ host-limit error (`Code=6`) even with a
/// free registry flags the host blocked for this boot, returns the typed limit
/// code, and does **not** retry into another VM.
fn run_macos_install_flow(
    params: &Value,
    base_dir: &Path,
    state: &mut InitState,
    admission: &VmAdmission,
) -> Result<(), Response> {
    use vmrunner_macos_rs::init_state::{InitPhase, read_state, write_state};

    let requested_ipsw = params["ipsw"].as_str();
    tracing::info!(requested_ipsw = ?requested_ipsw, "Resolving restore image source...");
    let candidates = match macos_guest::resolve_restore_image(requested_ipsw, base_dir) {
        Ok(v) => v,
        Err(e) => return Err(Response::err(format!("resolve_restore_image: {e}"))),
    };
    if candidates.is_empty() {
        return Err(Response::err(
            "resolve_restore_image: no compatible candidates returned",
        ));
    }

    let max_attempts = std::env::var("THEYOS_IPSW_MAX_CANDIDATES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(3)
        .min(candidates.len());

    let ipsw_path = base_dir.join("macos.ipsw");
    let disk_path = base_dir.join("disk.img");
    let aux_path = base_dir.join("aux.auxstorage");

    // Invariant I-1: reserve the install slot via the single admission authority
    // BEFORE downloading or starting anything. On HostVmLimitReached we fail fast
    // — no download, no VM start — and (reactive host-blocked case) do not retry.
    if let Err(e) = vmrunner_macos_rs::vz::preflight_vz_supportability() {
        tracing::warn!(error = %e, "guest-image install: VZ supportability preflight refused");
        return Err(Response::err(&e));
    }
    let install_lease = match admission.reserve(VmKind::Install, None) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "guest-image install admission refused");
            return Err(admission_err_response(&e));
        }
    };

    let mut last_err: Option<String> = None;

    for (idx, candidate) in candidates.iter().take(max_attempts).enumerate() {
        let label = candidate.source_label.clone();
        tracing::info!(
            attempt = idx + 1,
            total = max_attempts,
            source = %label,
            "trying restore image candidate"
        );

        if state.ipsw_source.is_some() && state.ipsw_source.as_deref() != Some(label.as_str()) {
            tracing::info!(prev = ?state.ipsw_source, new = %label,
                "switching restore-image candidate; clearing previous download progress");
            std::fs::remove_file(&ipsw_path).ok();
            let _ = macos_guest::clear_download_progress(base_dir);
            *state = read_state(base_dir).unwrap_or_default();
        }

        state.phase = Some(InitPhase::DownloadIpsw);
        state.macos_version = Some(candidate.macos_version.clone());
        state
            .host_macos_version
            .clone_from(&candidate.host_macos_version);
        state
            .host_macos_build
            .clone_from(&candidate.host_macos_build);
        state.ipsw_build.clone_from(&candidate.ipsw_build);
        state.ipsw_source = Some(label.clone());
        let _ = write_state(base_dir, state);

        let candidate_ipsw_path = match &candidate.source {
            macos_guest::RestoreImageSource::DownloadUrl(_) => ipsw_path.clone(),
            macos_guest::RestoreImageSource::LocalFile(local_path) => local_path.clone(),
        };

        let download_result = match &candidate.source {
            macos_guest::RestoreImageSource::DownloadUrl(url) => {
                tracing::info!(url, "Downloading restore image...");
                macos_guest::download_ipsw(url, &ipsw_path, state, base_dir, |downloaded, total| {
                    if total > 0 {
                        let pct = downloaded * 100 / total;
                        tracing::debug!(pct, downloaded, total, "IPSW download progress");
                    }
                })
            }
            macos_guest::RestoreImageSource::LocalFile(local_path) => {
                let local_bytes = std::fs::metadata(local_path).map(|m| m.len()).ok();
                state.ipsw_total_bytes = local_bytes;
                state.ipsw_bytes_downloaded = local_bytes.unwrap_or(0);
                let _ = write_state(base_dir, state);
                tracing::info!(path = %local_path.display(), "Using local restore image");
                Ok(())
            }
        };

        if let Err(e) = download_result {
            tracing::warn!(error = %e, source = %label, "candidate download failed; trying next");
            if !state.failed_ipsw_sources.iter().any(|s| s == &label) {
                state.failed_ipsw_sources.push(label.clone());
            }
            let _ = write_state(base_dir, state);
            std::fs::remove_file(&ipsw_path).ok();
            let _ = macos_guest::clear_download_progress(base_dir);
            *state = read_state(base_dir).unwrap_or_default();
            last_err = Some(format!("{label} (download): {e}"));
            continue;
        }

        if let Err(e) = macos_guest::inspect_restore_image(&candidate_ipsw_path) {
            tracing::warn!(error = %e, source = %label,
                "candidate failed VZ pre-install validation; trying next");
            if !state.failed_ipsw_sources.iter().any(|s| s == &label) {
                state.failed_ipsw_sources.push(label.clone());
            }
            let _ = write_state(base_dir, state);
            std::fs::remove_file(&ipsw_path).ok();
            let _ = macos_guest::clear_download_progress(base_dir);
            *state = read_state(base_dir).unwrap_or_default();
            last_err = Some(format!("{label} (inspect): {e}"));
            continue;
        }

        cleanup_failed_macos_install_artifacts(&disk_path, &aux_path);
        tracing::info!("Creating 64 GB sparse disk...");
        if let Err(e) = macos_guest::create_disk(&disk_path, 64) {
            install_lease.release_clean();
            return Err(Response::err(format!("create_disk: {e}")));
        }
        state.phase = Some(InitPhase::InstallMacOS);
        // Pre-mark this candidate as failed BEFORE install_macos runs so that a
        // subprocess crash (not a returned Err) does not re-try the same candidate.
        if !state.failed_ipsw_sources.iter().any(|s| s == &label) {
            state.failed_ipsw_sources.push(label.clone());
        }
        let _ = write_state(base_dir, state);

        tracing::info!("Installing macOS from IPSW (~20 min)...");
        // install_macos requires the lease proof token — it cannot start a VM
        // without admission.
        match macos_guest::install_macos(
            &candidate_ipsw_path,
            &disk_path,
            &aux_path,
            &install_lease,
            |frac| {
                tracing::info!("macOS install progress: {:.0}%", frac * 100.0);
            },
        ) {
            Ok(result) => {
                tracing::info!(source = %label, "candidate installed successfully");
                state.failed_ipsw_sources.retain(|s| s != &label);
                // The install VM is stopped inside install_macos; release the lease.
                install_lease.release_clean();
                state.hardware_model_data = Some(result.hardware_model_data_b64);
                state.machine_identifier_data_b64 = Some(result.machine_identifier_data_b64);
                state.install_cpu_count = Some(result.install_cpu_count);
                state.install_memory_mb = Some(result.install_memory_mb);
                state.phase = Some(InitPhase::Provision);
                let _ = write_state(base_dir, state);
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(error = %e, source = %label,
                    "install_macos failed; trying next candidate");
                std::fs::remove_file(&ipsw_path).ok();
                cleanup_failed_macos_install_artifacts(&disk_path, &aux_path);
                let _ = macos_guest::clear_download_progress(base_dir);
                *state = read_state(base_dir).unwrap_or_default();
                if is_macos_vm_limit_error(&e) {
                    // Reactive backstop (Invariant I-4): the registry showed free
                    // capacity but VZ still hit the host limit (a prior leak we
                    // cannot see). Flag the host blocked for this boot so we stop
                    // retrying, release this lease (the install VM never started).
                    state.failed_ipsw_sources.retain(|s| s != &label);
                    let _ = write_state(base_dir, state);
                    if let Err(be) = admission.mark_host_blocked() {
                        tracing::warn!(error = %be, "failed to set host-blocked flag");
                    }
                    install_lease.release_clean();
                    return Err(Response::err_code(
                        MACOS_VM_LIMIT_REACHED,
                        macos_vm_limit_message(&label, &e.to_string()),
                    ));
                }
                last_err = Some(format!("{label} (install): {e}"));
            }
        }
    }

    // All candidates failed without hitting the host limit.
    install_lease.release_clean();
    Err(Response::err(format!(
        "all {max_attempts} restore image candidate(s) failed; last error: {}\n\
         hint: if these failures look stale (e.g., a prior run was killed mid-install), \
         retry with `soyeht start --force` to clear the cached failure list.",
        last_err.unwrap_or_else(|| "unknown".into())
    )))
}

// ── Shared state ──────────────────────────────────────────────────────────────

/// A running VM entry that keeps the VZ machine and (for macOS guests) the
/// Apple 2-VM slot permit alive for the entire lifetime of the VM.
///
/// Dropping this entry releases the slot permit so a new macOS VM can start.
struct VmEntry {
    vm: Arc<VZVirtualMachine>,
    /// Admission lease for macOS guest VMs; `None` for Linux guests.
    ///
    /// Release discipline (Invariant I-2): the lease is released by an explicit
    /// `stop_and_release` after the VM is confirmed stopped — never by `VmEntry`'s
    /// own `Drop`, which retains the registry record fail-closed.
    lease: Option<VmLease>,
    /// Holds the `ObjcDelegate` object alive for the lifetime of this VM entry.
    _delegate: Option<ObjcDelegate>,
}

impl VmEntry {
    /// Stop the VM, then release its admission lease. On stop failure the lease is
    /// retained as a suspected orphan (the slot stays held until reboot).
    async fn stop_and_release(mut self, graceful: bool) {
        let lease = self.lease.take();
        if let Some(l) = &lease {
            l.mark_stopping();
        }
        let result = self.vm.stop(graceful).await;
        match (result, lease) {
            (Ok(()), Some(l)) => l.release_clean(),
            (Ok(()), None) => {}
            (Err(e), Some(l)) => {
                tracing::error!(error = %e, "stop_and_release: VM stop failed — retaining lease");
                l.retain_as_orphan();
            }
            (Err(e), None) => {
                tracing::warn!(error = %e, "stop_and_release: Linux VM stop failed");
            }
        }
    }
}

impl Drop for VmEntry {
    fn drop(&mut self) {
        if self.lease.is_some() {
            tracing::warn!(
                "VmEntry dropped without stop_and_release — admission lease retained \
                 fail-closed (use stop_and_release to free the slot)"
            );
        }
    }
}

type VmMap = HashMap<String, VmEntry>;

struct IpcState {
    vms: Mutex<VmMap>,
    warm_pool: WarmPoolManager,
    /// Single admission authority for every macOS VM start — enforces Apple's
    /// 2-VM concurrent limit across processes via the persisted lease registry.
    admission: VmAdmission,
    /// Snapshot manager — holds the registered macOS base snapshot path (no TTL).
    snapshot_manager: Mutex<SnapshotManager>,
    /// Container IDs of pre-booted macOS warm-pool VMs ready for instant assignment (FIFO).
    macos_warm_pool: Mutex<VecDeque<String>>,
    /// Target number of pre-booted macOS warm-pool VMs (≤1 due to Apple 2-VM limit).
    macos_warm_pool_size: usize,
    /// When true, warm pool boot threads must stop their VM instead of registering it.
    /// Set by `drain_warm_pool_vms()` before base snapshot creation.
    warm_pool_inhibited: std::sync::atomic::AtomicBool,
    /// Number of warm pool boot threads currently in flight.
    /// `drain_warm_pool_vms()` waits for this to reach 0 before proceeding.
    warm_pool_booting: std::sync::atomic::AtomicUsize,
}

impl IpcState {
    fn new() -> Result<Self, String> {
        let snapshots_dir = snapshots_dir_from_env_or_home();
        std::fs::create_dir_all(&snapshots_dir)
            .map_err(|e| format!("create snapshots dir: {e}"))?;

        // macOS warm pool is opt-in. Pre-booting a VZ macOS VM at daemon startup
        // can abort the IPC subprocess on some Apple Silicon hosts before Rust can
        // observe an NSError, so keep the default start path free of speculative VMs.
        let pool_size = std::env::var("THEYOS_MACOS_WARM_POOL_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0)
            .min(1); // Apple limit: max 1 warm pool slot

        let pool_cfg = WarmPoolConfig {
            pool_size,
            ..WarmPoolConfig::default()
        };

        let warm_pool = WarmPoolManager::new(snapshots_dir.clone(), pool_cfg)
            .map_err(|e| format!("warm pool init: {e}"))?;

        let admission = VmAdmission::new(&vm_state_dir());

        // T025/T026: Register the macOS base snapshot (created by init-macos-guest) so the
        // warm pool can call restore_from_base_snapshot() at startup and after refills.
        let assets_dir = std::env::var("THEYOS_VM_ASSETS_DIR").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            format!("{home}/Library/Application Support/theyos/vms")
        });
        let base_snapshot = PathBuf::from(&assets_dir).join("macos-base/base.vzsnapshot");
        let mut snapshot_mgr = SnapshotManager::new(
            snapshots_dir.clone(),
            24, // TTL hours (unused for base snapshots)
        );
        if base_snapshot.exists() {
            snapshot_mgr.register("macos-base", base_snapshot);
            tracing::info!("Registered macOS base snapshot for warm pool");
        } else {
            tracing::debug!(
                "macOS base snapshot not found — run 'theyos init-macos-guest' to create it"
            );
        }

        Ok(Self {
            vms: Mutex::new(HashMap::new()),
            warm_pool,
            admission,
            snapshot_manager: Mutex::new(snapshot_mgr),
            macos_warm_pool: Mutex::new(VecDeque::new()),
            macos_warm_pool_size: pool_size,
            warm_pool_inhibited: std::sync::atomic::AtomicBool::new(false),
            warm_pool_booting: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Recover VMs that were running before a restart.
    ///
    /// Scans instance dirs for `vm_ip` files; logs that they need to be recreated
    /// on next `create` call. This is a best-effort recovery — we cannot restore
    /// `VZVirtualMachine` state across process restarts, so instances will be marked
    /// as needing restart by the orchestrator.
    fn recover_running_instances() -> usize {
        let assets_dir = std::env::var("THEYOS_VM_ASSETS_DIR").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            format!("{home}/Library/Application Support/theyos/vms")
        });
        let vms_dir = PathBuf::from(&assets_dir);

        let mut stale_warm_pool_dirs = 0;
        if let Ok(entries) = std::fs::read_dir(&vms_dir) {
            for entry in entries.flatten() {
                let dir = entry.path();
                if dir.is_dir() {
                    let container = entry.file_name().to_string_lossy().into_owned();
                    if container.starts_with("warmpool-") {
                        stale_warm_pool_dirs += 1;
                        match std::fs::remove_dir_all(&dir) {
                            Ok(()) => tracing::warn!(
                                container,
                                "Removed stale macOS warm-pool container from previous vmrunner"
                            ),
                            Err(e) => tracing::warn!(
                                container,
                                path = %dir.display(),
                                error = %e,
                                "Failed to remove stale macOS warm-pool container"
                            ),
                        }
                        continue;
                    }

                    let ip_file = dir.join("vm_ip");
                    if ip_file.exists() {
                        tracing::warn!(
                            container,
                            "Instance had active VM before restart — \
                             will require `create` to restore"
                        );
                        // Remove stale vm_ip so the orchestrator sees it as stopped
                        let _ = std::fs::remove_file(&ip_file);
                    }
                }
            }
        }
        stale_warm_pool_dirs
    }
}

// ── Resource param parsing ────────────────────────────────────────────────────

/// Parse `cpu_cores`, `ram_mb`, `disk_gb` from IPC params with defaults.
fn parse_resource_params(params: &Value, default_cpu: u32, default_ram: u32) -> (u32, u32, u64) {
    let resources = serde_json::from_value::<VmCreateResourceSpec>(params.clone())
        .unwrap_or_default()
        .resolve_with_cpu_ram(default_cpu, default_ram);
    (
        resources.cpu_cores,
        resources.ram_mb,
        u64::from(resources.disk_gb),
    )
}

/// Apply macOS restore-image minimums recorded during base-image install.
fn effective_macos_resources(
    init_st: &InitState,
    requested_cpus: u32,
    requested_memory_mb: u32,
) -> (u32, u32) {
    let min_cpus = init_st
        .install_cpu_count
        .or(init_st.snapshot_cpus)
        .unwrap_or(requested_cpus);
    let min_memory_mb = init_st
        .install_memory_mb
        .or(init_st.snapshot_memory_mb)
        .unwrap_or(requested_memory_mb);
    (
        requested_cpus.max(min_cpus),
        requested_memory_mb.max(min_memory_mb),
    )
}

/// Resolve the provision/snapshot boot sizing for `MacOsProvisionAndSnapshot`.
///
/// Callers serialize `MacOsProvisionAndSnapshotRequest`, whose sizing fields are
/// `cpus`/`memory_mb`. The pre-existing `parse_resource_params` decoded the *create*
/// contract's `cpu_cores`/`ram_mb` instead — fields these params never carry — so it
/// always fell back to the macOS defaults (4/4096) and the caller's `cpus`/`memory_mb`
/// were silently dropped (the drift the typed contract exposed). This honors the typed
/// `cpus`/`memory_mb` when present, falling back to the `VmCreateResourceSpec` parse
/// otherwise.
///
/// Behavior delta: the HTTP guest-image path sends `Some(4)`/`Some(4096)` (== the old
/// effective defaults) so it is unchanged, and `init-macos-guest` defaults its
/// `--cpus`/`--memory-mb` to 4/4096 so default runs are unchanged — but an explicit
/// non-default `--cpus`/`--memory-mb`, previously a dead flag, is now honored.
fn resolve_provision_resources(
    req: &MacOsProvisionAndSnapshotRequest,
    params: &Value,
) -> (u32, u32) {
    let (parsed_cpus, parsed_memory_mb, _disk_gb) = parse_resource_params(params, 4, 4096);
    (
        req.cpus.unwrap_or(parsed_cpus),
        req.memory_mb.unwrap_or(parsed_memory_mb),
    )
}

// ── Main ──────────────────────────────────────────────────────────────────────

pub fn main_impl() {
    // Initialize tracing so warm-pool and VM lifecycle messages appear in server logs.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    // On macOS 26+, Virtualization.framework's ObjC classes are not automatically
    // registered in the runtime class table even when the framework is linked.
    // dlopen forces full framework initialization so class!() / objc_getClass() work.
    unsafe {
        let path = b"/System/Library/Frameworks/Virtualization.framework/Virtualization\0";
        let handle = libc::dlopen(
            path.as_ptr().cast::<libc::c_char>(),
            libc::RTLD_NOW | libc::RTLD_GLOBAL,
        );
        if handle.is_null() {
            let err = libc::dlerror();
            let msg = if err.is_null() {
                "(unknown)"
            } else {
                std::ffi::CStr::from_ptr(err)
                    .to_str()
                    .unwrap_or("(invalid utf8)")
            };
            eprintln!("[vmrunner-macos-ipc] dlopen Virtualization.framework failed: {msg}");
        }
    }

    let state = match IpcState::new() {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("[vmrunner-macos-ipc] init failed: {e}");
            std::process::exit(1);
        }
    };

    // T037: Startup recovery — scan for stale vm_ip files from previous run.
    let stale_warm_pool_dirs = IpcState::recover_running_instances();

    // Reconcile the admission lease registry: drop leases from prior boots (a
    // reboot clears leaked VZ sessions) and surface same-boot suspected orphans.
    match state.admission.reconcile_now() {
        Ok(cap) => {
            if cap.suspected_orphans > 0 || cap.host_blocked {
                tracing::warn!(
                    live = cap.live,
                    suspected_orphans = cap.suspected_orphans,
                    available = cap.available,
                    host_blocked = cap.host_blocked,
                    "admission: macOS VM capacity at startup (suspected orphans persist until reboot)"
                );
            } else {
                tracing::info!(
                    live = cap.live,
                    available = cap.available,
                    "admission: macOS VM capacity reconciled at startup"
                );
            }
        }
        Err(e) => tracing::warn!(error = %e, "admission: startup reconcile failed"),
    }

    // T026: Boot warm pool VMs from base snapshot in the background.
    // Only boots if base snapshot is registered and Apple VM slots are available.
    if stale_warm_pool_dirs > 0 {
        tracing::warn!(
            count = stale_warm_pool_dirs,
            "Skipping macOS warm-pool preboot on this startup after stale warm-pool recovery"
        );
    } else {
        init_macos_warm_pool(&state);
    }

    run_ipc_loop("vmrunner-macos-ipc", move |method, params| {
        dispatch(method, params, &state)
    });
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

fn dispatch(method: &str, params: &Value, state: &Arc<IpcState>) -> Response {
    match method {
        "Create" => handle_create(params, state),
        "Stop" => handle_stop(params, state),
        "Delete" => handle_delete(params, state),
        "Restart" | "Rebuild" => handle_restart(params, state),
        "Status" => handle_status(params, state),
        "WarmPoolInit" => handle_warm_pool_init(params, state.as_ref()),
        "WarmPoolRefill" => handle_warm_pool_refill(params, state.as_ref()),
        "WarmPoolStatus" => handle_warm_pool_status(state.as_ref()),
        "WarmPoolDrain" => handle_warm_pool_drain(state.as_ref()),
        "TakeBaseSnapshot" => handle_take_base_snapshot(params, state),
        "FetchLogs" => handle_fetch_logs(params),
        // Delete-flow cleanup steps. The shared orchestrator emits cleanup_systemd
        // and cleanup_fs unconditionally for every host; on macOS these must
        // succeed so the executor releases the storage lease (a missing CleanupFs
        // leaves the disk lease allocated forever — a silent storage-lease leak).
        "CleanupSystemd" => handle_cleanup_systemd(params),
        "CleanupFs" => handle_cleanup_fs(params),
        // macOS guest init methods (T015, T016)
        "MacOsBaseInstall" => handle_macos_base_install(params, state),
        "MacOsPrepare" => handle_macos_prepare(params, state),
        "MacOsProvisionAndSnapshot" => handle_macos_provision_and_snapshot(params, state),
        "RemoveMacOsBase" => handle_remove_macos_base(params),
        "MacOsSlotStatus" => handle_macos_slot_status(state.as_ref()),
        // Linux guest init methods
        "LinuxBaseInstall" => handle_linux_base_install(params),
        "RemoveLinuxBase" => handle_remove_linux_base(params),
        "LinuxBaseStatus" => handle_linux_base_status(),
        other => Response::err(format!("unknown method: {other}")),
    }
}

// ── Tokio runtime helper ──────────────────────────────────────────────────────

fn block_on<F, T>(f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(f)
}

// ── Instance directory ────────────────────────────────────────────────────────

fn instance_dir(container: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join("Library/Application Support/theyos/vms")
        .join(container)
}

// ── handle_create ─────────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn handle_create(params: &Value, state: &Arc<IpcState>) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };
    let claw_type = match params["claw_type"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("claw_type is required"),
    };
    let port = match params["port"].as_u64() {
        Some(v) => match u16::try_from(v) {
            Ok(p) => p,
            Err(_) => return Response::err("port value out of range"),
        },
        _ => return Response::err("port is required"),
    };

    let (cpus, memory_mb, _disk_gb) =
        parse_resource_params(params, DEFAULT_CREATE_CPU_CORES, DEFAULT_CREATE_RAM_MB);
    let guest_os = params["guest_os"]
        .as_str()
        .unwrap_or(if cfg!(target_os = "macos") {
            "macos"
        } else {
            "linux"
        });

    let customer = params["customer"].as_str().unwrap_or("").to_string();

    tracing::info!(container, claw_type, port, guest_os, "Creating VM");

    let inst_dir = instance_dir(&container);

    // T019 / Invariant I-1: macOS guests go through the single admission authority,
    // which gates on the cross-process lease registry (live + suspected orphans),
    // not just an in-process semaphore. On refusal, no VM is started.
    let mut user_lease: Option<VmLease> = if guest_os == "macos" {
        if let Err(e) = vmrunner_macos_rs::vz::preflight_vz_supportability() {
            tracing::warn!(error = %e, "macOS create: VZ supportability preflight refused");
            return Response::err(&e);
        }
        match state
            .admission
            .reserve(VmKind::UserClaw, Some(container.clone()))
        {
            Ok(lease) => Some(lease),
            Err(e) => {
                tracing::warn!(error = %e, "macOS VM admission refused");
                return admission_err_response(&e);
            }
        }
    } else {
        None
    };

    // T026: For macOS guests, try to take a pre-booted warm-pool VM first.
    // If a warm VM is available it is assigned directly to the user; the warm VM's
    // pre-acquired slot permit is inherited (the slot_permit acquired above is released).
    // A background refill is then triggered if a slot is still free.
    if guest_os == "macos" {
        let warm_container = state.macos_warm_pool.lock().unwrap().pop_front();
        if let Some(ref wc) = warm_container {
            let warm_entry = state.vms.lock().unwrap().remove(wc);
            if let Some(mut warm) = warm_entry {
                let warm_dir = instance_dir(wc);
                let ip = std::fs::read_to_string(warm_dir.join("vm_ip"))
                    .unwrap_or_else(|_| "192.168.64.100".to_string());
                let mac = std::fs::read_to_string(warm_dir.join("vm_mac")).unwrap_or_default();
                std::fs::create_dir_all(&inst_dir).ok();
                let _ = std::fs::write(inst_dir.join("vm_ip"), &ip);
                let _ = std::fs::write(inst_dir.join("vm_mac"), &mac);
                tracing::info!(
                    container,
                    warm_container = wc.as_str(),
                    "macOS warm pool: VM assigned from pool (warm boot)"
                );
                // The warm VM's lease was pre-acquired — the user inherits it.
                // Release the lease we just reserved to avoid double-counting.
                if let Some(l) = user_lease.take() {
                    l.release_clean();
                }
                if let Some(l) = &warm.lease {
                    l.mark_running();
                }
                // T038: Update delegate to use the user's container ID (not the warm pool ID).
                // This ensures crash cleanup targets the correct VmMap entry.
                let user_delegate = create_vm_delegate(&container, Arc::clone(state));
                warm.vm.set_delegate(user_delegate.0);
                let user_entry = VmEntry {
                    vm: Arc::clone(&warm.vm),
                    lease: warm.lease.take(),
                    _delegate: Some(user_delegate),
                };
                state
                    .vms
                    .lock()
                    .unwrap()
                    .insert(container.clone(), user_entry);
                if state.admission.semaphore_available() > 0 {
                    spawn_macos_warm_refill(Arc::clone(state));
                }
                // Install claw in the warm VM (SSH must be ready first).
                if !claw_type.is_empty() {
                    let ip_clone = ip.clone();
                    let ct = claw_type.clone();
                    let cu = customer.clone();
                    std::thread::spawn(move || {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .expect("warm claw install rt");
                        rt.block_on(async {
                            if let Err(e) = macos_guest::wait_for_ssh(&ip_clone, 120).await {
                                tracing::warn!(error = %e, "Warm path: SSH not ready for claw install");
                                return;
                            }
                            match vmrunner_macos_rs::installer_plan_macos::install_claw_and_start(
                                &ip_clone, &ct, &cu,
                            ).await {
                                Ok(()) => tracing::info!("Warm path: claw installed"),
                                Err(e) => tracing::warn!(error = %e, "Warm path: claw install failed"),
                            }
                        });
                    });
                }
                return Response::ok(serde_json::json!({
                    "container": container,
                    "state": "running",
                    "port": port,
                    "vm_ip": ip,
                    "vm_mac": mac,
                    "guest_os": guest_os,
                    "warm_pool": true,
                }));
            }
            // Warm entry vanished between pop_front and remove — fall through to cold boot.
        }
    }

    let result = if guest_os == "macos" {
        handle_create_macos(
            &container, &claw_type, cpus, memory_mb, &inst_dir, &customer,
        )
    } else {
        handle_create_linux(&container, &claw_type, cpus, memory_mb, &inst_dir)
    };

    match result {
        Ok((vm, ip, mac, response_extra)) => {
            // T038: Attach delegate to macOS VMs so crashes are detected and handled.
            let delegate = if guest_os == "macos" {
                let d = create_vm_delegate(&container, Arc::clone(state));
                vm.set_delegate(d.0);
                Some(d)
            } else {
                None
            };
            if let Some(l) = &user_lease {
                l.mark_running();
            }
            // Store lease and delegate in VmEntry — lease released via stop_and_release.
            let entry = VmEntry {
                vm: Arc::new(vm),
                lease: user_lease.take(),
                _delegate: delegate,
            };
            state.vms.lock().unwrap().insert(container.clone(), entry);
            // T026: After cold-boot macOS create, trigger warm pool refill if a slot is free.
            if guest_os == "macos" && state.admission.semaphore_available() > 0 {
                spawn_macos_warm_refill(Arc::clone(state));
            }
            let mut resp = serde_json::json!({
                "container": container,
                "state": "running",
                "port": port,
                "vm_ip": ip,
                "vm_mac": mac,
                "guest_os": guest_os,
            });
            if let Some(extra) = response_extra {
                if let (Some(obj), Some(extra_obj)) = (resp.as_object_mut(), extra.as_object()) {
                    obj.extend(extra_obj.clone());
                }
            }
            Response::ok(resp)
        }
        Err(e) => {
            tracing::error!(container, error = %e, "VM create failed");
            // handle_create_macos stops the VM on its failure paths (or never
            // started one), so the lease is safe to release cleanly.
            if let Some(l) = user_lease.take() {
                l.release_clean();
            }
            Response::err(e.to_string())
        }
    }
}

fn handle_create_linux(
    container: &str,
    claw_type: &str,
    cpus: u32,
    memory_mb: u32,
    inst_dir: &PathBuf,
) -> Result<(VZVirtualMachine, String, String, Option<serde_json::Value>), vmrunner_macos_rs::VZError>
{
    block_on(async {
        let pubkey = ensure_ssh_key().await?;
        let (disk_path, efi_path, cidata_path) =
            clone_base_image(claw_type, container, inst_dir).await?;
        build_cidata_iso(container, &pubkey, &cidata_path).await?;
        let mac = generate_mac();
        // Snapshot existing leases BEFORE starting the VM for delta-based IP detection.
        let existing_ips = vmrunner_macos_rs::snapshot_leased_ips().await;
        let config = VZVirtualMachineConfigurationBuilder::new()
            .cpus(cpus)
            .memory_mb(memory_mb)
            .disk_path(disk_path.clone())
            .efi_store_path(efi_path.clone())
            .cidata_iso_path(cidata_path.clone())
            .mac_address(mac.clone())
            .build()?;
        let vm = VZVirtualMachine::new(&config, container)?;
        vm.start().await?;
        let ip = resolve_dhcp_ip(&mac, 90, &existing_ips).await?;
        let _ = std::fs::create_dir_all(inst_dir);
        let _ = std::fs::write(inst_dir.join("vm_ip"), &ip);
        let _ = std::fs::write(inst_dir.join("vm_mac"), &mac);
        let extra = serde_json::json!({
            "disk_path": disk_path.display().to_string(),
            "efi_store_path": efi_path.display().to_string(),
            "cidata_iso_path": cidata_path.display().to_string(),
        });
        Ok((vm, ip, mac, Some(extra)))
    })
}

#[allow(clippy::too_many_arguments)]
fn handle_create_macos(
    container: &str,
    claw_type: &str,
    cpus: u32,
    memory_mb: u32,
    inst_dir: &PathBuf,
    customer: &str,
) -> Result<(VZVirtualMachine, String, String, Option<serde_json::Value>), vmrunner_macos_rs::VZError>
{
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    // Load the macOS base image init state to get hardware_model_data
    let base_dir = macos_guest::base_dir()
        .map_err(|e| vmrunner_macos_rs::VZError::Internal(format!("base_dir: {e}")))?;

    let init_st = read_state(&base_dir)?;
    let hw_data_b64 = init_st.hardware_model_data.as_deref().ok_or_else(|| {
        vmrunner_macos_rs::VZError::InvalidConfig(
            "macOS base image not initialized — run `theyos init-macos-guest` first".into(),
        )
    })?;
    let hw_data = BASE64
        .decode(hw_data_b64)
        .map_err(|e| vmrunner_macos_rs::VZError::Internal(format!("decode hw_model: {e}")))?;
    // Load stored ECID for reuse — prevents macOS from treating each boot as "new hardware"
    // and triggering Setup Assistant. When None (old init-state.json), a fresh ECID is used.
    let machine_id_data: Option<Vec<u8>> = init_st
        .machine_identifier_data_b64
        .as_deref()
        .and_then(|b| BASE64.decode(b).ok());
    let (macos_cpus, macos_memory_mb) = effective_macos_resources(&init_st, cpus, memory_mb);

    // Clone the macOS base disk (APFS CoW cp -c)
    let base_disk = base_dir.join("disk.img");
    let inst_disk = inst_dir.join("disk.img");
    let base_aux = base_dir.join("aux.auxstorage");
    let inst_aux = inst_dir.join("aux.auxstorage");

    std::fs::create_dir_all(inst_dir).map_err(vmrunner_macos_rs::VZError::Io)?;

    // Use APFS CoW clone (cp -c = clonefile on APFS)
    block_on(async {
        use std::process::Command;
        let out = Command::new("cp")
            .args(["-c", "--"])
            .arg(&base_disk)
            .arg(&inst_disk)
            .output()
            .map_err(|e| vmrunner_macos_rs::VZError::Internal(format!("cp -c disk: {e}")))?;
        if !out.status.success() {
            return Err(vmrunner_macos_rs::VZError::Internal(format!(
                "cp -c failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        let out = Command::new("cp")
            .args(["-c", "--"])
            .arg(&base_aux)
            .arg(&inst_aux)
            .output()
            .map_err(|e| vmrunner_macos_rs::VZError::Internal(format!("cp -c aux: {e}")))?;
        if !out.status.success() {
            return Err(vmrunner_macos_rs::VZError::Internal(format!(
                "cp -c aux failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok::<(), vmrunner_macos_rs::VZError>(())
    })?;

    // Build VZMacOSVmConfiguration — reuse the stored ECID so macOS boots as the same
    // "machine" it was provisioned as, avoiding Setup Assistant on every cold boot.
    let mut macos_builder = VZMacOSVmConfigurationBuilder::new()
        .cpus(macos_cpus)
        .memory_mb(macos_memory_mb)
        .disk_path(inst_disk.clone())
        .aux_storage_path(inst_aux.clone())
        .hardware_model_data(hw_data);
    if let Some(mid) = machine_id_data {
        macos_builder = macos_builder.machine_identifier_data(mid);
    }
    let config = macos_builder.build()?;

    // Capture the MAC from config before moving it into block_on.
    // VZVirtualMachine property access requires the VM's dispatch queue (macOS 26+);
    // reading it from the config at build time avoids the queue restriction entirely.
    let mac = config.mac_address.clone();

    block_on(async {
        // Snapshot existing DHCP leases BEFORE starting the VM for delta-based IP detection.
        let existing_ips = vmrunner_macos_rs::snapshot_leased_ips().await;
        let vm = VZVirtualMachine::new(&config, container)?;

        vm.start().await?;

        let _ = std::fs::write(inst_dir.join("vm_mac"), &mac);

        // Wait up to 600s for DHCP lease (macOS cold boot via snapshot: continues from 5s
        // into first-boot, so networking comes up within normal macOS boot time ~3-5 min).
        let ip = match resolve_dhcp_ip(&mac, 600, &existing_ips).await {
            Ok(ip) => ip,
            Err(e) => {
                // Explicitly stop the VM before returning — dropping a running VZVirtualMachine
                // without stopping it leaves a ghost session in AppleVirtualPlatformSystemService
                // that counts toward the system-wide macOS VM limit (macOS 26 Tahoe behavior).
                let _ = vm.stop(false).await;
                return Err(e);
            }
        };
        let _ = std::fs::write(inst_dir.join("vm_ip"), &ip);

        // Wait for SSH then install claw binary + start service (best-effort).
        if let Err(e) = macos_guest::wait_for_ssh(&ip, 120).await {
            tracing::warn!(container, error = %e, "SSH not available — skipping claw install");
        } else if !claw_type.is_empty() {
            match vmrunner_macos_rs::installer_plan_macos::install_claw_and_start(
                &ip, claw_type, customer,
            )
            .await
            {
                Ok(()) => tracing::info!(container, claw_type, "Claw installed and started"),
                Err(e) => {
                    tracing::warn!(
                        container,
                        claw_type,
                        error = %e,
                        "Claw install failed (non-fatal)"
                    );
                }
            }
        }

        let extra = serde_json::json!({
            "disk_path": inst_disk.display().to_string(),
            "aux_storage_path": inst_aux.display().to_string(),
        });
        Ok((vm, ip, mac, Some(extra)))
    })
}

// ── handle_stop ───────────────────────────────────────────────────────────────

fn handle_stop(params: &Value, state: &Arc<IpcState>) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };
    let graceful = params["graceful"].as_bool().unwrap_or(true);
    tracing::info!(container, graceful, "Stopping VM");

    let entry = state.vms.lock().unwrap().remove(&container);
    let Some(entry) = entry else {
        return Response::ok(serde_json::json!({
            "container": container,
            "state": "stopped",
            "note": "VM not in memory (may already be stopped)",
        }));
    };

    // stop_and_release stops the VM, then releases the lease (or retains it as a
    // suspected orphan if the stop fails — never freeing a slot for a VM we could
    // not confirm stopped).
    block_on(entry.stop_and_release(graceful));
    Response::ok(serde_json::json!({ "container": container, "state": "stopped" }))
}

// ── handle_delete ─────────────────────────────────────────────────────────────

fn handle_delete(params: &Value, state: &Arc<IpcState>) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };
    tracing::info!(container, "Deleting VM");

    // Stop if running, then release the admission lease (T028).
    let entry = state.vms.lock().unwrap().remove(&container);
    if let Some(e) = entry {
        block_on(e.stop_and_release(true));
    }

    // Remove instance files.
    let inst_dir = instance_dir(&container);
    if inst_dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&inst_dir) {
            tracing::warn!(container, error = %e, "Failed to remove instance dir");
        }
    }

    Response::ok(serde_json::json!({ "container": container, "deleted": true }))
}

/// macOS hosts do not run systemd; the shared delete orchestrator still emits a
/// `cleanup_systemd` step for every host. Accept it as a validated no-op so the
/// macOS method surface stays in parity with the Linux runner and the executor
/// does not see a spurious `unknown method` on every delete.
fn handle_cleanup_systemd(params: &Value) -> Response {
    let container = params["container"].as_str().unwrap_or("");
    if container.is_empty() {
        return Response::err("container is required");
    }
    Response::ok(serde_json::json!({ "container": container, "cleaned": true, "noop": true }))
}

/// Remove a macOS guest's per-instance filesystem state, keyed on the instance
/// `container` id (the same key `Delete` uses). Idempotent: returns success when
/// the directory is already gone — `Delete` removes it first — so the executor's
/// storage-lease release runs on macOS hosts. Without this, `CleanupFs` returned
/// `unknown method`, the lease release was skipped, and the disk lease leaked on
/// every macOS instance delete.
fn handle_cleanup_fs(params: &Value) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };

    let dir = instance_dir(&container);
    if dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&dir) {
            return Response::err(format!(
                "cleanup_fs failed to remove {}: {e}",
                dir.display()
            ));
        }
    }
    Response::ok(serde_json::json!({ "container": container, "cleaned": true }))
}

// ── handle_restart ────────────────────────────────────────────────────────────

fn handle_restart(params: &Value, state: &Arc<IpcState>) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };
    tracing::info!(container, "Restarting VM");

    // Stop current instance if running (drops slot permit so create can re-acquire).
    // Use force stop (false) to ensure VZ releases disk/aux locks immediately.
    // Graceful stop can leave locks held, causing "foreign exception" on re-create.
    let entry = state.vms.lock().unwrap().remove(&container);
    if let Some(e) = entry {
        // Stop and release the old lease so the re-create below can reserve a slot.
        block_on(e.stop_and_release(false));
        // Give VZ time to fully release disk locks after force stop.
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    let inst_dir = instance_dir(&container);
    if !inst_dir.exists() {
        return Response::err(format!(
            "Instance directory not found: {}",
            inst_dir.display()
        ));
    }

    // Detect guest type from existing files:
    // - macOS guest: inst_dir/aux.auxstorage exists
    // - Linux guest: inst_dir/<container>.raw exists
    let is_macos_guest = inst_dir.join("aux.auxstorage").exists();

    if is_macos_guest {
        restart_macos_vm(&container, &inst_dir, state)
    } else {
        restart_linux_vm(&container, &inst_dir, state)
    }
}

/// Restart a macOS guest VM from its existing disk files.
fn restart_macos_vm(
    container: &str,
    inst_dir: &std::path::Path,
    state: &Arc<IpcState>,
) -> Response {
    let inst_disk = inst_dir.join("disk.img");
    let inst_aux = inst_dir.join("aux.auxstorage");

    if !inst_disk.exists() {
        return Response::err(format!("Disk not found: {}", inst_disk.display()));
    }
    if !inst_aux.exists() {
        return Response::err(format!("Aux storage not found: {}", inst_aux.display()));
    }

    // Read hardware_model_data from the macOS base init state.
    let base_dir = match macos_guest::base_dir() {
        Ok(d) => d,
        Err(e) => return Response::err(format!("base_dir: {e}")),
    };
    let init_st = match read_state(&base_dir) {
        Ok(s) => s,
        Err(e) => return Response::err(format!("read init state: {e}")),
    };
    let Some(hw_data_b64) = init_st.hardware_model_data.as_deref() else {
        return Response::err(
            "macOS base image not initialized — run `theyos init-macos-guest` first".to_string(),
        );
    };
    let hw_data =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, hw_data_b64) {
            Ok(d) => d,
            Err(e) => return Response::err(format!("decode hw_model: {e}")),
        };

    if let Err(e) = vmrunner_macos_rs::vz::preflight_vz_supportability() {
        tracing::warn!(error = %e, "macOS restart: VZ supportability preflight refused");
        return Response::err(&e);
    }
    // Reserve a macOS VM slot via the single admission authority (Apple 2-VM limit).
    let lease = match state
        .admission
        .reserve(VmKind::UserClaw, Some(container.to_string()))
    {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "macOS VM restart admission refused");
            return admission_err_response(&e);
        }
    };

    let machine_id_data: Option<Vec<u8>> = init_st
        .machine_identifier_data_b64
        .as_deref()
        .and_then(|b| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b).ok());

    // Use stored snapshot config or fallback defaults, without going below the
    // restore-image minimums recorded during install.
    let requested_cpus = init_st.snapshot_cpus.unwrap_or(4);
    let requested_mem = init_st.snapshot_memory_mb.unwrap_or(4096);
    let (restart_cpus, restart_mem) =
        effective_macos_resources(&init_st, requested_cpus, requested_mem);
    let mut restart_builder = VZMacOSVmConfigurationBuilder::new()
        .cpus(restart_cpus)
        .memory_mb(restart_mem)
        .disk_path(inst_disk)
        .aux_storage_path(inst_aux)
        .hardware_model_data(hw_data);
    if let Some(mid) = machine_id_data {
        restart_builder = restart_builder.machine_identifier_data(mid);
    }
    let config = match restart_builder.build() {
        Ok(c) => c,
        Err(e) => return Response::err(format!("build VZ config: {e}")),
    };
    let mac = config.mac_address.clone();

    let result = block_on(async {
        let existing_ips = vmrunner_macos_rs::snapshot_leased_ips().await;
        let vm = VZVirtualMachine::new(&config, container)?;
        vm.start().await?;

        let _ = std::fs::write(inst_dir.join("vm_mac"), &mac);

        let ip = match resolve_dhcp_ip(&mac, 120, &existing_ips).await {
            Ok(ip) => ip,
            Err(e) => {
                // Stop the VM before returning — dropping a running VZVirtualMachine
                // without stopping it leaks an OS-level active-VM slot.
                let _ = vm.stop(false).await;
                return Err(e);
            }
        };
        let _ = std::fs::write(inst_dir.join("vm_ip"), &ip);

        Ok::<(VZVirtualMachine, String, String), vmrunner_macos_rs::VZError>((vm, ip, mac))
    });

    match result {
        Ok((vm, ip, mac)) => {
            lease.mark_running();
            let entry = VmEntry {
                vm: Arc::new(vm),
                lease: Some(lease),
                _delegate: None,
            };
            state
                .vms
                .lock()
                .unwrap()
                .insert(container.to_string(), entry);
            Response::ok(serde_json::json!({
                "container": container,
                "state": "running",
                "vm_ip": ip,
                "vm_mac": mac,
                "guest_os": "macos",
            }))
        }
        Err(e) => {
            tracing::error!(container, error = %e, "macOS VM restart failed");
            // The VM was stopped on the failure path (or never started), so the
            // lease can be released cleanly.
            lease.release_clean();
            Response::err(e.to_string())
        }
    }
}

/// Restart a Linux guest VM from its existing disk files.
fn restart_linux_vm(
    container: &str,
    inst_dir: &std::path::Path,
    state: &Arc<IpcState>,
) -> Response {
    let disk_path = inst_dir.join(format!("{container}.raw"));
    let efi_path = inst_dir.join(format!("{container}.nvram"));
    let cidata_path = inst_dir.join(format!("{container}-cidata.iso"));

    if !disk_path.exists() {
        return Response::err(format!("Disk not found: {}", disk_path.display()));
    }

    let mac = std::fs::read_to_string(inst_dir.join("vm_mac"))
        .unwrap_or_default()
        .trim()
        .to_string();

    let result = block_on(async {
        let existing_ips = vmrunner_macos_rs::snapshot_leased_ips().await;

        let mut builder = VZVirtualMachineConfigurationBuilder::new()
            .cpus(4)
            .memory_mb(4096)
            .disk_path(disk_path)
            .efi_store_path(efi_path)
            .mac_address(mac.clone());

        if cidata_path.exists() {
            builder = builder.cidata_iso_path(cidata_path);
        }

        let config = builder.build()?;
        let vm = VZVirtualMachine::new(&config, container)?;
        vm.start().await?;

        let resolved_mac = if mac.is_empty() {
            vm.get_mac_address().unwrap_or_default()
        } else {
            mac.clone()
        };
        let ip = resolve_dhcp_ip(&resolved_mac, 90, &existing_ips).await?;
        let _ = std::fs::write(inst_dir.join("vm_ip"), &ip);

        Ok::<(VZVirtualMachine, String, String), vmrunner_macos_rs::VZError>((vm, ip, resolved_mac))
    });

    match result {
        Ok((vm, ip, mac)) => {
            let entry = VmEntry {
                vm: Arc::new(vm),
                lease: None, // Linux guest — no macOS admission lease
                _delegate: None,
            };
            state
                .vms
                .lock()
                .unwrap()
                .insert(container.to_string(), entry);
            Response::ok(serde_json::json!({
                "container": container,
                "state": "running",
                "vm_ip": ip,
                "vm_mac": mac,
                "guest_os": "linux",
            }))
        }
        Err(e) => {
            tracing::error!(container, error = %e, "Linux VM restart failed");
            Response::err(e.to_string())
        }
    }
}

// ── handle_status ─────────────────────────────────────────────────────────────

fn handle_status(params: &Value, state: &Arc<IpcState>) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };

    let vm = state
        .vms
        .lock()
        .unwrap()
        .get(&container)
        .map(|e| Arc::clone(&e.vm));
    let state_str = if let Some(vm) = vm {
        match vm.get_state().unwrap_or(VmState::Unknown) {
            VmState::Running => "running",
            VmState::Starting => "starting",
            VmState::Stopped => "stopped",
            VmState::Paused => "paused",
            VmState::Error => "error",
            _ => "unknown",
        }
    } else {
        "stopped"
    };

    let vm_ip = std::fs::read_to_string(instance_dir(&container).join("vm_ip"))
        .ok()
        .map(|s| s.trim().to_string());

    Response::ok(serde_json::json!({
        "container": container,
        "state": state_str,
        "vm_ip": vm_ip,
    }))
}

// ── handle_warm_pool_init ─────────────────────────────────────────────────────

fn handle_warm_pool_init(_params: &Value, state: &IpcState) -> Response {
    tracing::info!("WarmPoolInit");
    let status = state.warm_pool.status();
    Response::ok(serde_json::json!({
        "initialized": true,
        "slots": status.iter().map(|(k, v)| serde_json::json!({
            "claw_type": k,
            "state": format!("{:?}", v.state),
        })).collect::<Vec<_>>(),
    }))
}

// ── handle_warm_pool_refill ───────────────────────────────────────────────────

fn handle_warm_pool_refill(params: &Value, state: &IpcState) -> Response {
    let claw_type = match params["claw_type"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("claw_type is required"),
    };
    tracing::info!(claw_type, "WarmPoolRefill");

    let pool = state.warm_pool.clone();
    let ct = claw_type.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async {
            if let Err(e) = pool.refill(&ct).await {
                tracing::error!(claw_type = ct, error = %e, "Warm pool refill failed");
            }
        });
    });

    Response::ok(serde_json::json!({ "claw_type": claw_type, "refilling": true }))
}

// ── handle_warm_pool_status ───────────────────────────────────────────────────

fn handle_warm_pool_status(state: &IpcState) -> Response {
    let status = state.warm_pool.status();
    let slots: Vec<_> = status
        .iter()
        .map(|(k, v)| {
            serde_json::json!({
                "claw_type": k,
                "state": format!("{:?}", v.state),
                "snapshot_path": v.snapshot.as_ref().map(|s| s.path.display().to_string()),
            })
        })
        .collect();

    Response::ok(serde_json::json!({
        "slots": slots,
        "filling": slots.iter()
            .filter(|s| s["state"].as_str() == Some("Filling"))
            .map(|s| s["claw_type"].clone())
            .collect::<Vec<_>>(),
    }))
}

// ── handle_warm_pool_drain ────────────────────────────────────────────────────

fn handle_warm_pool_drain(state: &IpcState) -> Response {
    drain_warm_pool_vms(state);
    Response::ok(serde_json::json!({ "drained": true }))
}

// ── handle_take_base_snapshot ─────────────────────────────────────────────────

fn handle_take_base_snapshot(params: &Value, state: &Arc<IpcState>) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };
    let claw_type = match params["claw_type"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("claw_type is required"),
    };
    tracing::info!(container, claw_type, "TakeBaseSnapshot");

    let vm = state
        .vms
        .lock()
        .unwrap()
        .get(&container)
        .map(|e| Arc::clone(&e.vm));
    let Some(vm) = vm else {
        return Response::err(format!("VM {container} not running"));
    };

    let snapshot_path = state.warm_pool.snapshot_path_for(&claw_type);
    let result = block_on(async {
        vm.pause().await?;
        vm.save_snapshot(&snapshot_path).await?;
        Ok::<_, vmrunner_macos_rs::VZError>(snapshot_path.clone())
    });

    match result {
        Ok(path) => {
            state.warm_pool.mark_ready(&claw_type, path.clone());
            Response::ok(serde_json::json!({
                "container": container,
                "claw_type": claw_type,
                "snapshot_path": path.display().to_string(),
            }))
        }
        Err(e) => {
            tracing::error!(container, error = %e, "TakeBaseSnapshot failed");
            Response::err(e.to_string())
        }
    }
}

// ── handle_fetch_logs ─────────────────────────────────────────────────────────

fn handle_fetch_logs(params: &Value) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };

    let log_path = instance_dir(&container).join("console.log");
    let logs = std::fs::read_to_string(&log_path).unwrap_or_default();

    Response::ok(serde_json::json!({ "container": container, "logs": logs }))
}

// ── handle_macos_base_install (T015/T016) ─────────────────────────────────────

/// Run (or resume) the macOS guest base image initialization.
///
/// Phases: `DownloadIpsw` → `CreateDisk` → `InstallMacOS` → `Provision` → `CreateSnapshot` → `Complete`
///
/// This handler is long-running (~20 min on first run). The caller (`init_macos_guest` CLI)
/// should invoke it and wait. Subsequent calls resume from the last persisted phase.
#[allow(clippy::too_many_lines)]
fn handle_macos_base_install(params: &Value, state_ipc: &Arc<IpcState>) -> Response {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use vmrunner_macos_rs::init_state::{InitPhase, is_complete, read_state, write_state};

    // Optional params, typed via the shared MacOsBaseInstall contract.
    let req = MacOsBaseInstallRequest::from_params(params);
    let force = req.force;
    let force_provision = req.force_provision;
    // Resource sizing stays on the shared VmCreateResourceSpec contract.
    let (cpus, memory_mb, _disk_gb) = parse_resource_params(params, 4, 4096);
    let registry_url = req.registry_url;
    let ssh_pubkey = req.ssh_pubkey;
    let plist_dir_str = req
        .plist_dir
        .unwrap_or_else(|| "scripts/launchd".to_string());

    let base_dir = match macos_guest::base_dir() {
        Ok(d) => d,
        Err(e) => return Response::err(format!("base_dir: {e}")),
    };

    // Check disk space before starting
    if let Err(e) = macos_guest::check_init_disk_space(&base_dir) {
        return Response::err(e.to_string());
    }

    // Check if already complete (idempotent unless --force or --force-provision)
    if !force && !force_provision && is_complete(&base_dir) {
        return Response::ok(serde_json::json!({
            "status": "already_complete",
            "base_dir": base_dir.display().to_string(),
        }));
    }

    // Determine start phase
    let start_phase: InitPhase = if force_provision {
        InitPhase::Provision
    } else if force {
        InitPhase::DownloadIpsw
    } else {
        // Resume from last persisted phase (or start from beginning)
        read_state(&base_dir)
            .ok()
            .and_then(|s| s.phase)
            .unwrap_or(InitPhase::DownloadIpsw)
    };

    tracing::info!(?start_phase, "Starting macOS base install");

    let mut state = read_state(&base_dir).unwrap_or_default();

    // --force: also clear failed_ipsw_sources so a stuck pre-mark from a prior
    // crashed run can be recovered without editing init-state.json by hand.
    // (force_provision skips the install loop entirely, so it doesn't apply here.)
    if force && !state.failed_ipsw_sources.is_empty() {
        tracing::info!(
            cleared = ?state.failed_ipsw_sources,
            count = state.failed_ipsw_sources.len(),
            "--force: clearing failed_ipsw_sources to allow full retry"
        );
        state.failed_ipsw_sources.clear();
        let _ = write_state(&base_dir, &state);
    }

    // ── Combined phases: DownloadIpsw → CreateDisk → InstallMacOS ────────────
    // Iterates ranked restore-image candidates, retrying with the next one if
    // VZ rejects the current candidate's download or install. Failed candidates
    // are persisted in `state.failed_ipsw_sources` so process restarts skip them.
    let should_run_install_loop = matches!(
        start_phase,
        InitPhase::DownloadIpsw | InitPhase::CreateDisk | InitPhase::InstallMacOS
    ) || state.phase.is_none();

    if should_run_install_loop {
        // Single shared install flow (Invariant I-1: install VM only starts with
        // an admission lease, reserved inside the helper).
        if let Err(resp) =
            run_macos_install_flow(params, &base_dir, &mut state, &state_ipc.admission)
        {
            return resp;
        }
    }

    // ── Phase: Provision ─────────────────────────────────────────────────────
    let should_provision = matches!(state.phase, Some(InitPhase::Provision))
        || matches!(start_phase, InitPhase::Provision);

    if should_provision {
        // Download claw binaries (best-effort)
        if !registry_url.is_empty() {
            let binaries_dir = base_dir.join("binaries");
            tracing::info!("Downloading darwin/arm64 claw binaries...");
            match macos_guest::download_claw_binaries(&registry_url, &binaries_dir, |ct| {
                tracing::info!(claw_type = ct, "Downloading binary");
            }) {
                Ok(downloaded) => tracing::info!(count = downloaded.len(), "Binaries downloaded"),
                Err(e) => tracing::warn!("Binary download failed (non-fatal): {e}"),
            }
        }

        // Inject provision files into the disk
        let disk_path = base_dir.join("disk.img");
        let plist_dir = PathBuf::from(&plist_dir_str);
        let pubkey = if ssh_pubkey.is_empty() {
            match block_on(vmrunner_macos_rs::ensure_ssh_key()) {
                Ok(k) => k,
                Err(e) => return Response::err(format!("ensure_ssh_key: {e}")),
            }
        } else {
            ssh_pubkey.clone()
        };

        tracing::info!("Injecting provisioning files into APFS volume...");
        if let Err(e) = macos_guest::inject_provision_files(&disk_path, &pubkey, &plist_dir) {
            return Response::err(format!("inject_provision_files: {e}"));
        }

        state.phase = Some(InitPhase::CreateSnapshot);
        let _ = write_state(&base_dir, &state);
    }

    // ── Phase: CreateSnapshot ─────────────────────────────────────────────────
    if matches!(state.phase, Some(InitPhase::CreateSnapshot)) {
        let disk_path = base_dir.join("disk.img");
        let aux_path = base_dir.join("aux.auxstorage");

        let Some(hw_data) = state
            .hardware_model_data
            .as_deref()
            .and_then(|b| BASE64.decode(b).ok())
        else {
            return Response::err("hardware_model_data missing from InitState");
        };

        tracing::info!("Creating base VZ snapshot...");
        let install_machine_id = state
            .machine_identifier_data_b64
            .as_deref()
            .and_then(|b| BASE64.decode(b).ok());
        let (snapshot_cpus, snapshot_memory_mb) =
            effective_macos_resources(&state, cpus, memory_mb);
        let (snapshot_path, machine_id_data) = match run_base_snapshot_with_admission(
            &state_ipc.admission,
            &disk_path,
            &aux_path,
            &hw_data,
            install_machine_id.as_deref(),
            &base_dir,
            snapshot_cpus,
            snapshot_memory_mb,
        ) {
            Ok(p) => p,
            Err(resp) => return resp,
        };

        state.snapshot_path = Some(snapshot_path.display().to_string());
        state.machine_identifier_data_b64 = if machine_id_data.is_empty() {
            None
        } else {
            Some(BASE64.encode(&machine_id_data))
        };
        state.snapshot_cpus = Some(snapshot_cpus);
        state.snapshot_memory_mb = Some(snapshot_memory_mb);
        state.begin_phase(InitPhase::Complete);
        state.complete_phase();
        let _ = write_state(&base_dir, &state);
    }

    Response::ok(serde_json::json!({
        "status": "complete",
        "base_dir": base_dir.display().to_string(),
        "snapshot_path": state.snapshot_path,
        "macos_version": state.macos_version,
    }))
}

// ── handle_macos_prepare ─────────────────────────────────────────────────────

/// Download IPSW + create disk + install macOS. No sudo needed.
/// Returns `hardware_model_data` and `base_dir` for the caller to continue.
#[allow(clippy::too_many_lines)]
fn handle_macos_prepare(params: &Value, state_ipc: &Arc<IpcState>) -> Response {
    use vmrunner_macos_rs::init_state::{InitPhase, is_complete, read_state, write_state};

    let req = MacOsPrepareRequest::from_params(params);
    let force = req.force;
    let force_provision = req.force_provision;
    let registry_url = req.registry_url;

    let base_dir = match macos_guest::base_dir() {
        Ok(d) => d,
        Err(e) => return Response::err(format!("base_dir: {e}")),
    };

    if let Err(e) = macos_guest::check_init_disk_space(&base_dir) {
        return Response::err(e.to_string());
    }

    // If already past provision, nothing to prepare
    if !force && !force_provision && is_complete(&base_dir) {
        return Response::ok(serde_json::json!({
            "status": "already_complete",
            "base_dir": base_dir.display().to_string(),
        }));
    }

    // If --force-provision, skip to provision (prepare already done)
    if force_provision {
        let state = read_state(&base_dir).unwrap_or_default();
        return Response::ok(serde_json::json!({
            "status": "ready_for_provision",
            "base_dir": base_dir.display().to_string(),
            "hardware_model_data": state.hardware_model_data,
        }));
    }

    let start_phase = if force {
        InitPhase::DownloadIpsw
    } else {
        read_state(&base_dir)
            .ok()
            .and_then(|s| s.phase)
            .unwrap_or(InitPhase::DownloadIpsw)
    };

    // If already past install, prepare is done
    if matches!(
        start_phase,
        InitPhase::Provision | InitPhase::CreateSnapshot | InitPhase::Complete
    ) {
        let state = read_state(&base_dir).unwrap_or_default();
        return Response::ok(serde_json::json!({
            "status": "ready_for_provision",
            "base_dir": base_dir.display().to_string(),
            "hardware_model_data": state.hardware_model_data,
        }));
    }

    let mut state = read_state(&base_dir).unwrap_or_default();

    // --force: also clear failed_ipsw_sources so a stuck pre-mark from a prior
    // crashed run can be recovered without editing init-state.json by hand.
    // (force_provision returns earlier without touching the install loop.)
    if force && !state.failed_ipsw_sources.is_empty() {
        tracing::info!(
            cleared = ?state.failed_ipsw_sources,
            count = state.failed_ipsw_sources.len(),
            "--force: clearing failed_ipsw_sources to allow full retry"
        );
        state.failed_ipsw_sources.clear();
        let _ = write_state(&base_dir, &state);
    }

    // ── Combined phases: DownloadIpsw → CreateDisk → InstallMacOS (iterative) ──
    let should_run_install_loop = matches!(
        start_phase,
        InitPhase::DownloadIpsw | InitPhase::CreateDisk | InitPhase::InstallMacOS
    ) || state.phase.is_none();

    if should_run_install_loop {
        // Single shared install flow (Invariant I-1: install VM only starts with
        // an admission lease, reserved inside the helper).
        if let Err(resp) =
            run_macos_install_flow(params, &base_dir, &mut state, &state_ipc.admission)
        {
            return resp;
        }
    }

    // Download claw binaries (best-effort, part of prepare)
    if !registry_url.is_empty() {
        let binaries_dir = base_dir.join("binaries");
        tracing::info!("Downloading darwin/arm64 claw binaries...");
        match macos_guest::download_claw_binaries(&registry_url, &binaries_dir, |ct| {
            tracing::info!(claw_type = ct, "Downloading binary");
        }) {
            Ok(downloaded) => tracing::info!(count = downloaded.len(), "Binaries downloaded"),
            Err(e) => tracing::warn!("Binary download failed (non-fatal): {e}"),
        }
    }

    Response::ok(serde_json::json!({
        "status": "ready_for_provision",
        "base_dir": base_dir.display().to_string(),
        "hardware_model_data": state.hardware_model_data,
        "macos_version": state.macos_version,
    }))
}

/// Reserve a `Snapshot` slot, run [`macos_guest::create_base_snapshot`] under it,
/// then release the lease. The only place a snapshot boot VM may start (Invariant
/// I-1). On a VZ host-limit error, flags the host blocked for this boot and returns
/// the typed limit code. `create_base_snapshot` stops its VM on every path, so the
/// lease is released cleanly here.
#[allow(clippy::too_many_arguments)]
fn run_base_snapshot_with_admission(
    admission: &VmAdmission,
    disk_path: &Path,
    aux_path: &Path,
    hw_data: &[u8],
    install_machine_id: Option<&[u8]>,
    base_dir: &Path,
    cpus: u32,
    memory_mb: u32,
) -> Result<(PathBuf, Vec<u8>), Response> {
    if let Err(e) = vmrunner_macos_rs::vz::preflight_vz_supportability() {
        tracing::warn!(error = %e, "snapshot: VZ supportability preflight refused");
        return Err(Response::err(&e));
    }
    let lease = match admission.reserve(VmKind::Snapshot, None) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "snapshot admission refused");
            return Err(admission_err_response(&e));
        }
    };
    let result = block_on(macos_guest::create_base_snapshot(
        disk_path,
        aux_path,
        hw_data,
        install_machine_id,
        base_dir,
        cpus,
        memory_mb,
        &lease,
    ));
    match result {
        Ok(v) => {
            lease.release_clean();
            Ok(v)
        }
        Err(e) => {
            lease.release_clean();
            if is_macos_vm_limit_error(&e) {
                if let Err(be) = admission.mark_host_blocked() {
                    tracing::warn!(error = %be, "failed to set host-blocked flag");
                }
                return Err(Response::err_code(
                    MACOS_VM_LIMIT_REACHED,
                    format!("create_base_snapshot: {e}"),
                ));
            }
            Err(Response::err(format!("create_base_snapshot: {e}")))
        }
    }
}

// ── handle_macos_provision_and_snapshot ──────────────────────────────────────

/// Inject provision files + single-boot + snapshot.
/// Caller must have run provision-inject (via sudo) before calling this
/// if starting from the Provision phase.
fn handle_macos_provision_and_snapshot(params: &Value, ipc_state: &Arc<IpcState>) -> Response {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use vmrunner_macos_rs::init_state::{InitPhase, read_state, write_state};

    // Resource sizing: honor the typed request's cpus/memory_mb (what callers actually
    // serialize), falling back to the VmCreateResourceSpec parse. See
    // `resolve_provision_resources` for the exact delta — default/HTTP paths unchanged;
    // the previously-ignored `init-macos-guest --cpus/--memory-mb` is now honored.
    let req = MacOsProvisionAndSnapshotRequest::from_params(params);
    let (cpus, memory_mb) = resolve_provision_resources(&req, params);
    let ssh_pubkey = req.ssh_pubkey;
    let plist_dir_str = req
        .plist_dir
        .unwrap_or_else(|| "scripts/launchd".to_string());
    let skip_provision_inject = req.skip_provision_inject;
    let force_provision = req.force_provision;

    let base_dir = match macos_guest::base_dir() {
        Ok(d) => d,
        Err(e) => return Response::err(format!("base_dir: {e}")),
    };

    let mut state = read_state(&base_dir).unwrap_or_default();

    // Drain warm pool VMs immediately to free Apple VM slots and avoid DHCP
    // IP collision between warm pool VM and the base-boot VM.
    drain_warm_pool_vms(ipc_state);

    // --force-provision: reset state to Provision to re-inject + re-snapshot
    if force_provision {
        state.phase = Some(InitPhase::Provision);
        let _ = write_state(&base_dir, &state);
    }

    // ── Provision (inject files via helper) ──────────────────────────────────
    let should_provision =
        matches!(state.phase, Some(InitPhase::Provision)) && !skip_provision_inject;

    if should_provision {
        let disk_path = base_dir.join("disk.img");
        let plist_dir = PathBuf::from(&plist_dir_str);
        let pubkey = if ssh_pubkey.is_empty() {
            match block_on(vmrunner_macos_rs::ensure_ssh_key()) {
                Ok(k) => k,
                Err(e) => return Response::err(format!("ensure_ssh_key: {e}")),
            }
        } else {
            ssh_pubkey.clone()
        };

        tracing::info!("Injecting provisioning files into APFS volume...");
        if let Err(e) = macos_guest::inject_provision_files(&disk_path, &pubkey, &plist_dir) {
            return Response::err(format!("inject_provision_files: {e}"));
        }

        state.phase = Some(InitPhase::CreateSnapshot);
        let _ = write_state(&base_dir, &state);
    }

    // ── CreateSnapshot (single boot) ─────────────────────────────────────────
    if matches!(state.phase, Some(InitPhase::CreateSnapshot)) {
        let disk_path = base_dir.join("disk.img");
        let aux_path = base_dir.join("aux.auxstorage");

        let Some(hw_data) = state
            .hardware_model_data
            .as_deref()
            .and_then(|b| BASE64.decode(b).ok())
        else {
            return Response::err("hardware_model_data missing from InitState");
        };

        tracing::info!("Creating base VZ snapshot (single boot)...");

        let install_machine_id = state
            .machine_identifier_data_b64
            .as_deref()
            .and_then(|b| BASE64.decode(b).ok());
        let (snapshot_cpus, snapshot_memory_mb) =
            effective_macos_resources(&state, cpus, memory_mb);
        let (snapshot_path, machine_id_data) = match run_base_snapshot_with_admission(
            &ipc_state.admission,
            &disk_path,
            &aux_path,
            &hw_data,
            install_machine_id.as_deref(),
            &base_dir,
            snapshot_cpus,
            snapshot_memory_mb,
        ) {
            Ok(p) => p,
            Err(resp) => return resp,
        };

        state.snapshot_path = Some(snapshot_path.display().to_string());
        state.machine_identifier_data_b64 = if machine_id_data.is_empty() {
            None
        } else {
            Some(BASE64.encode(&machine_id_data))
        };
        state.snapshot_cpus = Some(snapshot_cpus);
        state.snapshot_memory_mb = Some(snapshot_memory_mb);
        state.begin_phase(InitPhase::Complete);
        state.complete_phase();
        let _ = write_state(&base_dir, &state);
    }

    Response::ok(serde_json::json!({
        "status": "complete",
        "base_dir": base_dir.display().to_string(),
        "snapshot_path": state.snapshot_path,
        "macos_version": state.macos_version,
    }))
}

// ── handle_remove_macos_base (T016) ───────────────────────────────────────────

/// Remove all macOS base image files and return bytes freed.
fn handle_remove_macos_base(_params: &Value) -> Response {
    let base_dir = match macos_guest::base_dir() {
        Ok(d) => d,
        Err(e) => return Response::err(format!("base_dir: {e}")),
    };

    if !base_dir.exists() {
        return Response::ok(serde_json::json!({
            "removed": false,
            "note": "macOS base directory does not exist",
            "bytes_freed": 0,
        }));
    }

    match macos_guest::remove_base_dir(&base_dir) {
        Ok(bytes_freed) => Response::ok(serde_json::json!({
            "removed": true,
            "bytes_freed": bytes_freed,
        })),
        Err(e) => Response::err(format!("remove_base_dir: {e}")),
    }
}

// ── handle_macos_slot_status (T024) ───────────────────────────────────────────

/// Return macOS VM slot availability for /healthz and diagnostic use.
/// Reports the cross-process admission view (live + suspected orphans + blocked),
/// not just the in-process semaphore.
fn handle_macos_slot_status(state: &IpcState) -> Response {
    match state.admission.capacity() {
        Ok(cap) => Response::ok(serde_json::json!({
            "available": cap.available,
            "total": MACOS_VM_LIMIT,
            "in_use": MACOS_VM_LIMIT.saturating_sub(cap.available),
            "live": cap.live,
            "suspected_orphans": cap.suspected_orphans,
            "host_blocked": cap.host_blocked,
        })),
        Err(e) => Response::err(format!("admission capacity: {e}")),
    }
}

// ── Linux guest init ─────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn handle_linux_base_install(params: &Value) -> Response {
    use vmrunner_macos_rs::linux_guest;
    use vmrunner_macos_rs::linux_init_state::{
        LinuxInitPhase, is_complete, read_state, write_state,
    };

    let force = params["force"].as_bool().unwrap_or(false);
    let force_provision = params["force_provision"].as_bool().unwrap_or(false);
    let (cpus, memory_mb, _disk_gb) =
        parse_resource_params(params, DEFAULT_CREATE_CPU_CORES, DEFAULT_CREATE_RAM_MB);
    let image_url = params["image_url"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| linux_guest::default_cloud_image_url())
        .to_string();

    let base_dir = match linux_guest::base_dir() {
        Ok(d) => d,
        Err(e) => return Response::err(format!("base_dir: {e}")),
    };

    if let Err(e) = linux_guest::check_init_disk_space(&base_dir) {
        return Response::err(e.to_string());
    }

    if let Err(e) = linux_guest::check_prerequisites() {
        return Response::err(e.to_string());
    }

    if !force && !force_provision && is_complete(&base_dir) {
        return Response::ok(serde_json::json!({
            "status": "already_complete",
            "base_dir": base_dir.display().to_string(),
        }));
    }

    let start_phase = if force_provision {
        LinuxInitPhase::FirstBoot
    } else if force {
        LinuxInitPhase::DownloadImage
    } else {
        read_state(&base_dir)
            .ok()
            .and_then(|s| s.phase)
            .unwrap_or(LinuxInitPhase::DownloadImage)
    };

    tracing::info!(?start_phase, "Starting Linux base install");
    let mut state = read_state(&base_dir).unwrap_or_default();

    // ── Phase: DownloadImage ─────────────────────────────────────────────────
    let should_download =
        matches!(start_phase, LinuxInitPhase::DownloadImage) || state.phase.is_none();

    if should_download {
        state.phase = Some(LinuxInitPhase::DownloadImage);
        state.image_url = Some(image_url.clone());
        state.ubuntu_version = Some("24.04".to_string());
        let _ = write_state(&base_dir, &state);

        let qcow2_path = base_dir.join("ubuntu-cloud.img");
        tracing::info!(url = %image_url, "Downloading Ubuntu cloud image...");
        if let Err(e) = linux_guest::download_cloud_image(
            &image_url,
            &qcow2_path,
            &mut state,
            &base_dir,
            |downloaded, total| {
                if total > 0 {
                    let pct = downloaded * 100 / total;
                    if pct % 10 == 0 {
                        tracing::info!(pct, downloaded, total, "Download progress");
                    }
                }
            },
        ) {
            return Response::err(format!("download: {e}"));
        }

        state.phase = Some(LinuxInitPhase::ConvertImage);
        let _ = write_state(&base_dir, &state);
    }

    // ── Phase: ConvertImage ──────────────────────────────────────────────────
    let should_convert = matches!(state.phase, Some(LinuxInitPhase::ConvertImage))
        || matches!(start_phase, LinuxInitPhase::ConvertImage);

    if should_convert {
        let qcow2_path = base_dir.join("ubuntu-cloud.img");
        let raw_path = base_dir.join("disk.img");
        let target_gb = linux_guest::DEFAULT_DISK_SIZE_GB;

        if let Err(e) = block_on(linux_guest::convert_and_resize_image(
            &qcow2_path,
            &raw_path,
            target_gb,
        )) {
            return Response::err(format!("convert: {e}"));
        }

        state.disk_size_gb = Some(target_gb);
        state.phase = Some(LinuxInitPhase::FirstBoot);
        let _ = write_state(&base_dir, &state);
    }

    // ── Phase: FirstBoot ─────────────────────────────────────────────────────
    let should_first_boot = matches!(state.phase, Some(LinuxInitPhase::FirstBoot))
        || matches!(start_phase, LinuxInitPhase::FirstBoot);

    if should_first_boot {
        let disk_path = base_dir.join("disk.img");
        let nvram_path = base_dir.join("base.nvram");
        let cidata_path = base_dir.join("cidata.iso");

        tracing::info!("First boot: populating NVRAM via EFI/GRUB...");
        let (vm, ip, _mac) = match block_on(linux_guest::first_boot(
            &disk_path,
            &nvram_path,
            &cidata_path,
            cpus,
            memory_mb,
        )) {
            Ok(v) => v,
            Err(e) => return Response::err(format!("first_boot: {e}")),
        };

        // ── Phase: ValidateSsh ───────────────────────────────────────────────
        state.phase = Some(LinuxInitPhase::ValidateSsh);
        let _ = write_state(&base_dir, &state);

        tracing::info!(ip, "Validating SSH access...");
        if let Err(e) = block_on(linux_guest::validate_ssh(&ip)) {
            let _ = block_on(linux_guest::shutdown_vm(&vm));
            return Response::err(format!("validate_ssh: {e}"));
        }

        // ── Phase: SaveBase ──────────────────────────────────────────────────
        state.phase = Some(LinuxInitPhase::SaveBase);
        let _ = write_state(&base_dir, &state);

        tracing::info!("Shutting down VM and saving base image...");
        if let Err(e) = block_on(linux_guest::shutdown_vm(&vm)) {
            tracing::warn!("Graceful shutdown failed (non-fatal): {e}");
        }

        // Create symlinks for all 6 claw types
        let assets_dir = match linux_guest::assets_dir() {
            Ok(d) => d,
            Err(e) => return Response::err(format!("assets_dir: {e}")),
        };
        if let Err(e) = linux_guest::create_claw_symlinks(&base_dir, &assets_dir) {
            return Response::err(format!("symlinks: {e}"));
        }

        state.phase = Some(LinuxInitPhase::Complete);
        let _ = write_state(&base_dir, &state);
    }

    // ── Resume from SaveBase (disk + NVRAM exist, just need symlinks) ────
    if matches!(state.phase, Some(LinuxInitPhase::SaveBase)) {
        tracing::info!("Resuming from SaveBase — creating symlinks...");
        let assets_dir = match linux_guest::assets_dir() {
            Ok(d) => d,
            Err(e) => return Response::err(format!("assets_dir: {e}")),
        };
        if let Err(e) = linux_guest::create_claw_symlinks(&base_dir, &assets_dir) {
            return Response::err(format!("symlinks: {e}"));
        }
        state.phase = Some(LinuxInitPhase::Complete);
        let _ = write_state(&base_dir, &state);
    }

    Response::ok(serde_json::json!({
        "status": "complete",
        "base_dir": base_dir.display().to_string(),
        "ubuntu_version": state.ubuntu_version,
        "disk_size_gb": state.disk_size_gb,
    }))
}

fn handle_remove_linux_base(params: &Value) -> Response {
    use vmrunner_macos_rs::linux_guest;

    let base_dir = match linux_guest::base_dir() {
        Ok(d) => d,
        Err(e) => return Response::err(format!("base_dir: {e}")),
    };
    let _ = params; // unused but matches dispatch signature

    match linux_guest::remove_base_dir(&base_dir) {
        Ok(bytes_freed) => Response::ok(serde_json::json!({
            "removed": true,
            "bytes_freed": bytes_freed,
        })),
        Err(e) => Response::err(format!("remove: {e}")),
    }
}

fn handle_linux_base_status() -> Response {
    use vmrunner_macos_rs::linux_init_state;

    let base_dir = match vmrunner_macos_rs::linux_guest::base_dir() {
        Ok(d) => d,
        Err(e) => return Response::err(format!("base_dir: {e}")),
    };

    let state = linux_init_state::read_state(&base_dir).unwrap_or_default();
    Response::ok(serde_json::json!({
        "base_dir": base_dir.display().to_string(),
        "phase": state.phase,
        "ubuntu_version": state.ubuntu_version,
        "disk_size_gb": state.disk_size_gb,
        "complete": linux_init_state::is_complete(&base_dir),
    }))
}

// ── macOS warm pool (T026) ─────────────────────────────────────────────────────

/// Boot warm-pool VMs from the registered base snapshot at startup.
///
/// Spawns one background thread per warm-pool slot. Each thread:
///   1. Acquires an `OwnedSemaphorePermit` from `state.slots`.
///   2. CoW-clones `macos-base/disk.img` and `macos-base/aux.auxstorage` to a new
///      `warmpool-<uuid>` container directory.
///   3. Calls `SnapshotManager::restore_from_base_snapshot` to boot the VM from
///      `base.vzsnapshot`.
///   4. Stores the running VM in `state.vms` and pushes its container ID onto
///      `state.macos_warm_pool`.
///
/// Stop all warm pool VMs and release their Apple VM slots.
///
/// Called before `create_base_snapshot` to ensure:
/// 1. No DHCP IP collision between warm pool VM and base-boot VM
/// 2. Apple VM slot is free for the base-boot VM (max 2 macOS VMs)
fn drain_warm_pool_vms(state: &IpcState) {
    // Set inhibit flag FIRST — any warm pool boot thread that hasn't finished
    // will see this flag and stop its VM instead of registering it.
    state
        .warm_pool_inhibited
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // Wait for any in-flight warm pool boot threads to finish (they will self-cancel
    // due to the inhibit flag, but we need them to fully stop their VM first).
    let mut waited = 0u32;
    while state
        .warm_pool_booting
        .load(std::sync::atomic::Ordering::SeqCst)
        > 0
    {
        std::thread::sleep(std::time::Duration::from_millis(200));
        waited += 1;
        if waited % 25 == 0 {
            tracing::info!("Waiting for warm pool boot to finish before base init...");
        }
        if waited > 300 {
            // 60s max wait — something is stuck
            tracing::warn!("Warm pool boot thread stuck — proceeding anyway");
            break;
        }
    }

    // Now drain any containers that were registered before the flag was set.
    let containers: Vec<String> = state.macos_warm_pool.lock().unwrap().drain(..).collect();
    for container in &containers {
        // Remove the entry and stop+release its lease (frees the Apple VM slot).
        let entry = state.vms.lock().unwrap().remove(container);
        if let Some(entry) = entry {
            block_on(entry.stop_and_release(false));
        }
        let dir = instance_dir(container);
        if let Err(e) = std::fs::remove_dir_all(&dir)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                container,
                path = %dir.display(),
                error = %e,
                "Failed to remove drained warm pool container directory"
            );
        }
    }
    state.warm_pool.drain_all();

    if !containers.is_empty() || waited > 0 {
        tracing::info!(
            drained = containers.len(),
            waited_ms = waited * 200,
            "Warm pool drained for base init"
        );
    }
}

/// No-ops silently if the base snapshot is not registered (init-macos-guest not run)
/// or no Apple VM slot is available.
fn init_macos_warm_pool(state: &Arc<IpcState>) {
    for _ in 0..state.macos_warm_pool_size {
        // Only boot if base snapshot is registered and a slot is free.
        let has_base = state
            .snapshot_manager
            .lock()
            .unwrap()
            .base_snapshot_path("macos-base")
            .is_some();
        if !has_base {
            tracing::debug!("macOS warm pool: base snapshot not ready, skipping pre-boot");
            return;
        }
        if state.admission.semaphore_available() == 0 {
            tracing::debug!("macOS warm pool: no slots available for pre-boot");
            return;
        }

        if vmrunner_macos_rs::vz::preflight_vz_supportability().is_err() {
            tracing::debug!(
                "macOS warm pool: VZ supportability preflight refused, skipping pre-boot"
            );
            return;
        }
        // Reserve a WarmPool slot via the single admission authority.
        let lease = match state.admission.reserve(VmKind::WarmPool, None) {
            Ok(l) => l,
            Err(e) => {
                tracing::debug!(error = %e, "macOS warm pool: admission refused for pre-boot");
                return;
            }
        };

        let state_clone = Arc::clone(state);
        state
            .warm_pool_booting
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::thread::spawn(move || {
            let container = format!("warmpool-{}", &uuid::Uuid::new_v4().to_string()[..8]);
            tracing::info!(container, "macOS warm pool: booting pre-warmed VM");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("warm pool tokio runtime");
            if let Err(e) = rt.block_on(boot_warm_pool_vm(
                Arc::clone(&state_clone),
                lease,
                &container,
            )) {
                tracing::warn!(container, error = %e, "macOS warm pool: boot failed");
            } else {
                tracing::info!(container, "macOS warm pool: VM ready");
            }
            state_clone
                .warm_pool_booting
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
    }
}

/// Boot one warm-pool VM from the base snapshot and register it in shared state.
///
/// # Errors
///
/// Returns `VZError` if disk clone, snapshot restore, or VM boot fails.
async fn boot_warm_pool_vm(
    state: Arc<IpcState>,
    lease: VmLease,
    container: &str,
) -> Result<(), vmrunner_macos_rs::VZError> {
    // Pre-start preparation (no VM started yet). Any failure here releases the
    // lease cleanly — nothing was started, so the slot must be returned.
    let prep = (|| -> Result<(vmrunner_macos_rs::VZVirtualMachineConfiguration, PathBuf), vmrunner_macos_rs::VZError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
        use std::process::Command;

        let base_dir = macos_guest::base_dir()?;
        let init_st = read_state(&base_dir)?;
        let hw_data_b64 = init_st.hardware_model_data.as_deref().ok_or_else(|| {
            vmrunner_macos_rs::VZError::InvalidConfig(
                "macOS base image not initialized — run `theyos init-macos-guest` first".into(),
            )
        })?;
        let hw_data = BASE64
            .decode(hw_data_b64)
            .map_err(|e| vmrunner_macos_rs::VZError::Internal(format!("decode hw_model: {e}")))?;
        // ECID is required for snapshot restore — VZ 26 rejects restore if ECID doesn't match.
        let machine_id_data: Option<Vec<u8>> = init_st
            .machine_identifier_data_b64
            .as_deref()
            .and_then(|b| BASE64.decode(b).ok());
        if machine_id_data.is_none() {
            return Err(vmrunner_macos_rs::VZError::SnapshotError(
                "machine_identifier_data not stored — re-run `theyos init-macos-guest --force-provision` to rebuild the base snapshot with ECID tracking".into(),
            ));
        }

        let inst_dir = instance_dir(container);
        std::fs::create_dir_all(&inst_dir).map_err(vmrunner_macos_rs::VZError::Io)?;

        // Fail closed if the target volume can't fit a clone — mirrors
        // `clone_base_image` (lib.rs). APFS CoW makes the copy near-free now, but
        // the cloned VM writes into this space at boot. On insufficient space this
        // returns `Err` (prep fails → lease released cleanly; no VM started).
        vmrunner_macos_rs::vz::check_disk_space(&inst_dir)?;

        // APFS CoW clone the base disk and aux storage.
        let base_disk = base_dir.join("disk.img");
        let inst_disk = inst_dir.join("disk.img");
        let out = Command::new("cp")
            .args(["-c", "--"])
            .arg(&base_disk)
            .arg(&inst_disk)
            .output()
            .map_err(|e| vmrunner_macos_rs::VZError::Internal(format!("cp -c disk: {e}")))?;
        if !out.status.success() {
            return Err(vmrunner_macos_rs::VZError::Internal(format!(
                "cp -c disk failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        let base_aux = base_dir.join("aux.auxstorage");
        let inst_aux = inst_dir.join("aux.auxstorage");
        let out = Command::new("cp")
            .args(["-c", "--"])
            .arg(&base_aux)
            .arg(&inst_aux)
            .output()
            .map_err(|e| vmrunner_macos_rs::VZError::Internal(format!("cp -c aux: {e}")))?;
        if !out.status.success() {
            return Err(vmrunner_macos_rs::VZError::Internal(format!(
                "cp -c aux failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }

        // Cold-boot the VM from the cloned disk (snapshot restore needs identical paths).
        let requested_cpus = init_st.snapshot_cpus.unwrap_or(4);
        let requested_mem = init_st.snapshot_memory_mb.unwrap_or(4096);
        let (snap_cpus, snap_mem) =
            effective_macos_resources(&init_st, requested_cpus, requested_mem);
        let mut warm_builder = VZMacOSVmConfigurationBuilder::new()
            .cpus(snap_cpus)
            .memory_mb(snap_mem)
            .disk_path(inst_disk)
            .aux_storage_path(inst_aux)
            .hardware_model_data(hw_data);
        if let Some(mid) = machine_id_data {
            warm_builder = warm_builder.machine_identifier_data(mid);
        }
        let config = warm_builder.build()?;
        Ok((config, inst_dir))
    })();

    let (config, inst_dir) = match prep {
        Ok(v) => v,
        Err(e) => {
            lease.release_clean();
            return Err(e);
        }
    };

    let existing_ips = vmrunner_macos_rs::snapshot_leased_ips().await;
    let vm = match VZVirtualMachine::new(&config, container) {
        Ok(v) => Arc::new(v),
        Err(e) => {
            lease.release_clean();
            return Err(e);
        }
    };

    // From here the VM may be running — it is owned with its lease by a
    // ManagedMacOSVm so every exit path stops it before releasing (Invariant I-2).
    let managed = ManagedMacOSVm::new(vm, lease);
    if let Err(e) = managed.vm().start().await {
        let _ = managed.stop_then_release(false).await;
        return Err(e);
    }

    let mac = config.mac_address.clone();
    let ip = match vmrunner_macos_rs::resolve_dhcp_ip(&mac, 120, &existing_ips).await {
        Ok(ip) => ip,
        Err(e) => {
            let _ = managed.stop_then_release(false).await;
            return Err(e);
        }
    };
    tracing::info!(container, ip, "Warm-pool VM cold-booted and has DHCP");
    managed.mark_running();

    let _ = std::fs::write(inst_dir.join("vm_ip"), &ip);
    let _ = std::fs::write(inst_dir.join("vm_mac"), &mac);

    // If the warm pool was inhibited (base init in progress), stop+release instead
    // of registering — avoids DHCP IP collision with the base-boot VM.
    if state
        .warm_pool_inhibited
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        tracing::info!(
            container,
            "Warm pool inhibited — stopping VM instead of registering"
        );
        let _ = managed.stop_then_release(false).await;
        let _ = std::fs::remove_dir_all(&inst_dir);
        return Ok(());
    }

    // T038: Attach delegate to warm-pool VMs so crashes are detected.
    let delegate = create_vm_delegate(container, Arc::clone(&state));
    managed.vm().set_delegate(delegate.0);

    // Hand the running VM + its lease into a long-lived VmEntry; the lease is
    // released later via VmEntry::stop_and_release.
    let (vm, lease) = managed.into_parts();
    let entry = VmEntry {
        vm,
        lease: Some(lease),
        _delegate: Some(delegate),
    };
    state
        .vms
        .lock()
        .unwrap()
        .insert(container.to_string(), entry);
    state
        .macos_warm_pool
        .lock()
        .unwrap()
        .push_back(container.to_string());

    Ok(())
}

/// Spawn a background thread to refill the macOS warm pool after a slot is freed.
///
/// Only spawns if the admission authority grants a `WarmPool` slot.
/// Called after a user instance consumes a warm-pool VM.
fn spawn_macos_warm_refill(state: Arc<IpcState>) {
    if state.macos_warm_pool_size == 0 {
        return; // warm pool disabled
    }
    if state
        .warm_pool_inhibited
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        return;
    }
    if state.admission.semaphore_available() == 0 {
        return;
    }
    if vmrunner_macos_rs::vz::preflight_vz_supportability().is_err() {
        return;
    }
    // race / limit — another caller already took the slot
    let Ok(lease) = state.admission.reserve(VmKind::WarmPool, None) else {
        return;
    };
    state
        .warm_pool_booting
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    std::thread::spawn(move || {
        let container = format!("warmpool-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        tracing::info!(container, "macOS warm pool: refilling after slot consumed");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("warm pool refill tokio runtime");
        match rt.block_on(boot_warm_pool_vm(Arc::clone(&state), lease, &container)) {
            Ok(()) => tracing::info!(container, "macOS warm pool: refill complete"),
            Err(e) => tracing::warn!(container, error = %e, "macOS warm pool: refill failed"),
        }
        state
            .warm_pool_booting
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    });
}

// ── VZ state-change delegate (T038) ───────────────────────────────────────────
//
// Implements `VZVirtualMachineDelegate` protocol via `objc::declare::ClassDecl`.
// Two callbacks are handled:
//   - `guestDidStopVirtualMachine:` — normal guest-initiated shutdown
//   - `virtualMachine:didStopWithError:` — crash / kernel panic (EC-005)
//
// On error stop: write `vm_error` file, remove `vm_ip`, drop VmEntry (releases
// MacOSVmSlotManager permit via RAII), trigger warm pool refill in background.

/// Context stored in the `ObjcDelegate`'s `_ctx` ivar.
/// Heap-allocated via `Box::into_raw`; freed in `ObjcDelegate::drop`.
struct VmDelegateContext {
    container_id: String,
    state: Arc<IpcState>,
}

/// RAII wrapper around an `ObjcDelegate` instance.
///
/// Storing this in `VmEntry` ensures:
/// 1. The `ObjcDelegate` is retained for the entire VM lifetime (VZ holds it weakly).
/// 2. `Box<VmDelegateContext>` is freed exactly once when the `VmEntry` is dropped.
struct ObjcDelegate(*mut objc::runtime::Object);

// SAFETY: The `ObjcDelegate` is only accessed through the ObjC dispatch queue and
// through our `Arc<IpcState>`; no data races are introduced.
unsafe impl Send for ObjcDelegate {}
unsafe impl Sync for ObjcDelegate {}

impl Drop for ObjcDelegate {
    fn drop(&mut self) {
        use objc::{msg_send, sel, sel_impl};
        if self.0.is_null() {
            return;
        }
        unsafe {
            // Zero out the ivar before releasing so a late-arriving callback
            // cannot dereference a freed context.
            let ptr: *mut std::ffi::c_void = *(*self.0).get_ivar("_ctx");
            if !ptr.is_null() {
                // Null the ivar first — prevents double-free if delegate fires late.
                (*self.0).set_ivar("_ctx", std::ptr::null_mut::<std::ffi::c_void>());
                // Free the context Box.
                drop(Box::from_raw(ptr.cast::<VmDelegateContext>()));
            }
            let _: () = msg_send![self.0, release];
        }
    }
}

// ── Module-level ObjC callback functions ──────────────────────────────────────
// Defined here (before vz_delegate_class) to avoid `items_after_statements`.

/// Read the `_ctx` ivar of a `TheyOSVmDelegate`; returns null if not set.
///
/// # Safety
///
/// `this` must be a `TheyOSVmDelegate` instance with an initialized `_ctx` ivar.
unsafe fn delegate_ctx(this: &objc::runtime::Object) -> *const VmDelegateContext {
    unsafe {
        let raw: *mut std::ffi::c_void = *this.get_ivar("_ctx");
        raw.cast::<VmDelegateContext>()
    }
}

/// `ObjC` callback: `guestDidStopVirtualMachine:` — normal guest-initiated shutdown.
extern "C" fn guest_did_stop(
    this: &objc::runtime::Object,
    _sel: objc::runtime::Sel,
    _vm: *mut objc::runtime::Object,
) {
    let ctx_ptr = unsafe { delegate_ctx(this) };
    if ctx_ptr.is_null() {
        return;
    }
    let (container_id, state) = unsafe {
        let c = &*ctx_ptr;
        (c.container_id.clone(), Arc::clone(&c.state))
    };
    tracing::info!(container = %container_id, "VZ VM: guest initiated stop");
    std::thread::spawn(move || {
        cleanup_vm_on_stop(&state, &container_id, None);
    });
}

/// `ObjC` callback: `virtualMachine:didStopWithError:` — crash / kernel panic.
extern "C" fn vm_did_stop_with_error(
    this: &objc::runtime::Object,
    _sel: objc::runtime::Sel,
    _vm: *mut objc::runtime::Object,
    error: *mut objc::runtime::Object,
) {
    use objc::{msg_send, sel, sel_impl};

    let ctx_ptr = unsafe { delegate_ctx(this) };
    if ctx_ptr.is_null() {
        return;
    }
    let (container_id, state) = unsafe {
        let c = &*ctx_ptr;
        (c.container_id.clone(), Arc::clone(&c.state))
    };

    // Extract NSError `localizedDescription` string.
    let err_desc: String = if error.is_null() {
        "unknown error".to_string()
    } else {
        // SAFETY: `localizedDescription` returns `NSString`; `UTF8String`
        // returns a C string valid for the `NSString`'s lifetime.
        let ns_str: *mut objc::runtime::Object = unsafe { msg_send![error, localizedDescription] };
        let c_str: *const std::os::raw::c_char = if ns_str.is_null() {
            std::ptr::null()
        } else {
            unsafe { msg_send![ns_str, UTF8String] }
        };
        if c_str.is_null() {
            "nil NSError description".to_string()
        } else {
            // SAFETY: c_str is valid for the NSString's lifetime (stack frame).
            unsafe {
                std::ffi::CStr::from_ptr(c_str)
                    .to_string_lossy()
                    .into_owned()
            }
        }
    };

    tracing::error!(
        container = %container_id,
        error = %err_desc,
        "VZ VM: stopped with error (EC-005 kernel panic or host exhaustion)"
    );

    std::thread::spawn(move || {
        cleanup_vm_on_stop(&state, &container_id, Some(&err_desc));
    });
}

/// Register the `TheyOSVmDelegate` `ObjC` class exactly once.
fn vz_delegate_class() -> &'static objc::runtime::Class {
    use objc::declare::ClassDecl;
    use objc::runtime::{Class, Protocol};
    use objc::{class, sel, sel_impl};
    use std::sync::OnceLock;

    static CLASS: OnceLock<&'static Class> = OnceLock::new();
    CLASS.get_or_init(|| {
        let superclass = class!(NSObject);
        let mut decl = ClassDecl::new("TheyOSVmDelegate", superclass)
            .expect("TheyOSVmDelegate: class name already taken");

        // ivar stores a raw `*mut c_void` (pointer to `Box<VmDelegateContext>`).
        decl.add_ivar::<*mut std::ffi::c_void>("_ctx");

        // Declare conformance to `VZVirtualMachineDelegate` (optional — VZ checks via
        // `respondsToSelector:`, so missing protocol declaration is non-fatal).
        if let Some(proto) = Protocol::get("VZVirtualMachineDelegate") {
            decl.add_protocol(proto);
        }

        unsafe {
            decl.add_method(
                sel!(guestDidStopVirtualMachine:),
                guest_did_stop
                    as extern "C" fn(
                        &objc::runtime::Object,
                        objc::runtime::Sel,
                        *mut objc::runtime::Object,
                    ),
            );
            decl.add_method(
                sel!(virtualMachine:didStopWithError:),
                vm_did_stop_with_error
                    as extern "C" fn(
                        &objc::runtime::Object,
                        objc::runtime::Sel,
                        *mut objc::runtime::Object,
                        *mut objc::runtime::Object,
                    ),
            );
        }

        decl.register()
    })
}

/// Allocate and configure a `TheyOSVmDelegate` instance for the given container.
///
/// The caller must store the returned `ObjcDelegate` in the matching `VmEntry`
/// to keep the `ObjcDelegate` alive (`VZVirtualMachine` holds it weakly).
fn create_vm_delegate(container_id: &str, state: Arc<IpcState>) -> ObjcDelegate {
    use objc::{msg_send, sel, sel_impl};

    let class = vz_delegate_class();
    let ctx = Box::new(VmDelegateContext {
        container_id: container_id.to_string(),
        state,
    });
    let ctx_ptr = Box::into_raw(ctx).cast::<std::ffi::c_void>();
    let delegate: *mut objc::runtime::Object = unsafe {
        let obj: *mut objc::runtime::Object = msg_send![class, new];
        (*obj).set_ivar("_ctx", ctx_ptr);
        obj
    };
    ObjcDelegate(delegate)
}

/// Clean up a VM that stopped (normally or due to error).
///
/// 1. Writes `vm_error` to the container dir if `error` is `Some`.
/// 2. Removes `vm_ip` so the orchestrator sees the VM as stopped.
/// 3. Drops the `VmEntry` (releases `MacOSVmSlotManager` permit via RAII).
/// 4. Triggers warm pool refill if a slot is now available.
fn cleanup_vm_on_stop(state: &Arc<IpcState>, container_id: &str, error: Option<&str>) {
    let dir = instance_dir(container_id);

    // Write vm_error marker for the orchestrator / admin panel.
    if let Some(err_msg) = error {
        let _ = std::fs::write(dir.join("vm_error"), err_msg);
    }

    // Remove vm_ip so the orchestrator detects the VM as stopped.
    let _ = std::fs::remove_file(dir.join("vm_ip"));

    // The VZ delegate fired because the VM already stopped (guest shutdown or
    // crash), so the lease can be released cleanly.
    let removed_entry = state.vms.lock().unwrap().remove(container_id);
    if let Some(mut entry) = removed_entry {
        if let Some(lease) = entry.lease.take() {
            lease.release_clean();
        }
        tracing::info!(
            container = %container_id,
            "VM entry removed; admission lease released (VM already stopped)"
        );
        // Trigger warm pool refill if a slot is now free.
        if !state
            .warm_pool_inhibited
            .load(std::sync::atomic::Ordering::SeqCst)
            && state.admission.semaphore_available() > 0
        {
            spawn_macos_warm_refill(Arc::clone(state));
        }
    }
}

// ── MAC address generation ────────────────────────────────────────────────────

fn generate_mac() -> String {
    use uuid::Uuid;
    let bytes = Uuid::new_v4().into_bytes();
    let b0 = (bytes[0] & 0xFE) | 0x02; // locally-administered, unicast
    format!(
        "{b0:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

#[cfg(test)]
mod resource_param_tests {
    use serde_json::json;
    use vmrunner_common_rs::{
        DEFAULT_CREATE_CPU_CORES, DEFAULT_CREATE_DISK_GB, DEFAULT_CREATE_RAM_MB,
        MacOsProvisionAndSnapshotRequest,
    };
    use vmrunner_macos_rs::init_state::InitState;

    #[test]
    fn parse_resource_params_uses_current_defaults() {
        assert_eq!(
            super::parse_resource_params(
                &json!({}),
                DEFAULT_CREATE_CPU_CORES,
                DEFAULT_CREATE_RAM_MB
            ),
            (
                DEFAULT_CREATE_CPU_CORES,
                DEFAULT_CREATE_RAM_MB,
                u64::from(DEFAULT_CREATE_DISK_GB)
            )
        );
    }

    #[test]
    fn parse_resource_params_preserves_supplied_values() {
        assert_eq!(
            super::parse_resource_params(
                &json!({
                    "cpu_cores": 4,
                    "ram_mb": 4096,
                    "disk_gb": 20
                }),
                DEFAULT_CREATE_CPU_CORES,
                DEFAULT_CREATE_RAM_MB
            ),
            (4, 4096, 20)
        );
    }

    #[test]
    fn parse_resource_params_treats_invalid_values_as_defaults() {
        assert_eq!(
            super::parse_resource_params(
                &json!({
                    "cpu_cores": "4",
                    "ram_mb": 9_999_999_999_u64,
                    "disk_gb": null
                }),
                DEFAULT_CREATE_CPU_CORES,
                DEFAULT_CREATE_RAM_MB
            ),
            (
                DEFAULT_CREATE_CPU_CORES,
                DEFAULT_CREATE_RAM_MB,
                u64::from(DEFAULT_CREATE_DISK_GB)
            )
        );
    }

    // ── MacOsProvisionAndSnapshot resource resolution (typed-contract closure) ────
    //
    // `resolve_provision_resources` honors the typed request's optional cpus/memory_mb
    // as an override while preserving the prior VmCreateResourceSpec parse. These pin
    // the behavior-preserving semantics so the closure can never silently regress into
    // discarding caller-sent sizing.

    #[test]
    fn resolve_provision_resources_falls_back_to_macos_defaults_when_unset() {
        // No VmCreateResourceSpec and no typed override → the macOS provision defaults
        // (4 vCPU / 4096 MB) this path has always used.
        let req = MacOsProvisionAndSnapshotRequest::default();
        assert_eq!(
            super::resolve_provision_resources(&req, &json!({})),
            (4, 4096)
        );
    }

    #[test]
    fn resolve_provision_resources_honors_vmcreate_spec_when_override_absent() {
        // Anti-regression: callers send cpu_cores/ram_mb (VmCreateResourceSpec), not the
        // typed cpus/memory_mb. Those caller values must still win when the typed override
        // is omitted — naively replacing the parse with the typed fields would have
        // silently discarded caller-sent sizing.
        let req = MacOsProvisionAndSnapshotRequest::default();
        assert_eq!(
            super::resolve_provision_resources(&req, &json!({ "cpu_cores": 6, "ram_mb": 8192 })),
            (6, 8192)
        );
    }

    #[test]
    fn resolve_provision_resources_typed_override_wins() {
        // When present, the typed cpus/memory_mb override the VmCreateResourceSpec — the
        // previously-dead contract field is now genuinely consumed end-to-end.
        let req = MacOsProvisionAndSnapshotRequest {
            cpus: Some(8),
            memory_mb: Some(16_384),
            ..MacOsProvisionAndSnapshotRequest::default()
        };
        assert_eq!(
            super::resolve_provision_resources(&req, &json!({ "cpu_cores": 6, "ram_mb": 8192 })),
            (8, 16_384)
        );
    }

    // ── effective_macos_resources (restore-image minimum merge) ──────────────────
    //
    // resolve_provision_resources feeds its (cpus, memory_mb) into
    // effective_macos_resources, which raises them to the install/snapshot minimums
    // recorded during base-image install. These pin that merge so the uplift #1 chain
    // (typed cpus/memory_mb -> snapshot boot sizing) can't regress.

    #[test]
    fn effective_macos_resources_uses_requested_when_no_minimums() {
        let st = InitState::default();
        assert_eq!(super::effective_macos_resources(&st, 4, 4096), (4, 4096));
    }

    #[test]
    fn effective_macos_resources_raises_to_install_minimums_but_keeps_larger_request() {
        let st = InitState {
            install_cpu_count: Some(8),
            install_memory_mb: Some(8192),
            ..InitState::default()
        };
        // A request below the install minimum is raised to it...
        assert_eq!(super::effective_macos_resources(&st, 4, 4096), (8, 8192));
        // ...but a larger request is preserved (max, never clamped down).
        assert_eq!(
            super::effective_macos_resources(&st, 16, 16_384),
            (16, 16_384)
        );
    }

    #[test]
    fn effective_macos_resources_uses_snapshot_minimum_then_prefers_install() {
        // Snapshot minimums apply when the install minimums are absent.
        let snap_only = InitState {
            snapshot_cpus: Some(6),
            snapshot_memory_mb: Some(6144),
            ..InitState::default()
        };
        assert_eq!(
            super::effective_macos_resources(&snap_only, 4, 4096),
            (6, 6144)
        );
        // Install minimums take precedence over snapshot minimums (`.or` ordering).
        let both = InitState {
            install_cpu_count: Some(8),
            install_memory_mb: Some(8192),
            snapshot_cpus: Some(2),
            snapshot_memory_mb: Some(2048),
            ..InitState::default()
        };
        assert_eq!(super::effective_macos_resources(&both, 4, 4096), (8, 8192));
    }
}

// ── VZ host-limit error classifier ────────────────────────────────────────────
//
// macos_vm_limit_exceeded is the string fallback for the VZ active-VM limit when
// the error arrives only as text; is_macos_vm_limit_error prefers the typed
// VZError::HostVmLimitReached and falls back to that string match. These pin the
// match matrix so a VZ message-format change (or an over-broad pattern) is caught.
#[cfg(test)]
mod vz_limit_classifier_tests {
    use super::{is_macos_vm_limit_error, macos_vm_limit_exceeded};
    use vmrunner_macos_rs::VZError;

    #[test]
    fn macos_vm_limit_exceeded_matches_known_vz_limit_strings() {
        for s in [
            r#"{"code": 6}"#,
            "NSError Code=6 domain=VZErrorDomain",
            "VZErrorVirtualMachineLimitExceeded",
            "reached the maximum supported number of active virtual machines",
            "Host VM limit reached: 2 running",
        ] {
            assert!(
                macos_vm_limit_exceeded(s),
                "should classify as limit: {s:?}"
            );
        }
    }

    #[test]
    fn macos_vm_limit_exceeded_rejects_unrelated_strings() {
        for s in [
            "",
            "Code=5 some other error",
            "code: 6", // unquoted — not the `"code": 6` JSON shape
            "disk full",
            "VZErrorVirtualMachineLimit", // truncated — not the `...Exceeded` variant
        ] {
            assert!(
                !macos_vm_limit_exceeded(s),
                "should NOT classify as limit: {s:?}"
            );
        }
    }

    #[test]
    fn is_macos_vm_limit_error_typed_variant_and_string_fallback() {
        // Typed variant → true regardless of message text.
        assert!(is_macos_vm_limit_error(&VZError::HostVmLimitReached(
            "anything".into()
        )));
        // Non-limit variant whose Display carries a known limit string → fallback true.
        assert!(is_macos_vm_limit_error(&VZError::Internal(
            "boot failed Code=6".into()
        )));
        // Non-limit variant with an unrelated message → false.
        assert!(!is_macos_vm_limit_error(&VZError::Internal(
            "unrelated failure".into()
        )));
    }
}

// ── admission wiring regression guards ────────────────────────────────────────
//
// These tests enforce Invariant I-1 structurally: no macOS VM `.start()` path
// exists outside the single admission authority. They read this file's own source
// at compile time and assert the install/snapshot flows are funneled through the
// admission-holding helpers — so a future edit that reintroduces a direct
// `install_macos` / `create_base_snapshot` call (bypassing the lease) fails CI.
#[cfg(test)]
mod admission_wiring_tests {
    use vmrunner_macos_rs::VZError;

    const SRC: &str = include_str!("vmrunner_macos_ipc_macos.rs");

    /// The production source, excluding this test module (whose string literals
    /// would otherwise inflate the counts).
    fn prod_src() -> &'static str {
        SRC.split("mod admission_wiring_tests")
            .next()
            .expect("source split")
    }

    fn count(needle: &str) -> usize {
        prod_src().matches(needle).count()
    }

    #[test]
    fn install_macos_only_called_from_shared_helper() {
        // Exactly one call site for the install VM (inside run_macos_install_flow),
        // which holds the Install lease. Both handlers route through the helper.
        assert_eq!(
            count("macos_guest::install_macos("),
            1,
            "install_macos must be called from exactly one place (run_macos_install_flow)"
        );
        // The shared helper exists and is called by both handlers (1 def + 2 calls).
        assert!(
            count("run_macos_install_flow(") >= 3,
            "both handle_macos_prepare and handle_macos_base_install must use run_macos_install_flow"
        );
    }

    #[test]
    fn create_base_snapshot_only_called_from_admission_helper() {
        assert_eq!(
            count("macos_guest::create_base_snapshot("),
            1,
            "create_base_snapshot must be called only from run_base_snapshot_with_admission"
        );
        assert!(
            count("run_base_snapshot_with_admission(") >= 3,
            "both snapshot call sites must route through run_base_snapshot_with_admission"
        );
    }

    #[test]
    fn warm_to_user_handoff_transfers_lease_without_duplicating() {
        // The warm→user handoff must move the warm lease and release the redundant
        // user reservation — never hold two leases for one VM.
        assert!(
            SRC.contains("warm.lease.take()"),
            "warm→user handoff must transfer the warm lease"
        );
        assert!(
            SRC.contains("user_lease.take()"),
            "the redundant user reservation must be released on warm handoff"
        );
    }

    #[test]
    fn long_lived_macos_leases_are_marked_running() {
        // User VMs, restarted VMs, and warm-pool VMs remain registered after
        // startup. Each path must move the persisted lease from `starting` to
        // `running`, otherwise diagnostics look stuck even after provisioning
        // completed successfully.
        assert!(
            count(".mark_running();") >= 4,
            "every long-lived macOS VM path must mark its lease running"
        );
    }

    #[test]
    fn vz_code6_is_classified_as_host_vm_limit() {
        // Typed variant.
        assert!(is_super_is_limit(&VZError::HostVmLimitReached("x".into())));
        // String fallbacks (errors that arrive only as text).
        assert!(is_super_is_limit(&VZError::VirtualizationError(
            "Error Domain=VZErrorDomain Code=6 ...".into()
        )));
        assert!(is_super_is_limit(&VZError::Internal(
            "the maximum supported number of active virtual machines has been reached".into()
        )));
        // Unrelated errors are not misclassified.
        assert!(!is_super_is_limit(&VZError::Internal("disk full".into())));
    }

    // Bridge to the parent module's private fn.
    fn is_super_is_limit(e: &VZError) -> bool {
        super::is_macos_vm_limit_error(e)
    }
}

#[cfg(test)]
mod cleanup_step_tests {
    use super::{handle_cleanup_fs, handle_cleanup_systemd, instance_dir};
    use serde_json::json;

    #[test]
    fn cleanup_systemd_requires_container() {
        let resp = handle_cleanup_systemd(&json!({}));
        assert!(!resp.ok);
        assert!(
            resp.error.as_deref().unwrap_or("").contains("container"),
            "expected a container-required error, got {:?}",
            resp.error
        );
    }

    #[test]
    fn cleanup_systemd_is_validated_noop_success() {
        // macOS has no systemd; the step must still succeed so the executor does
        // not log a spurious failure (or, worse, treat it as fatal) on delete.
        let resp = handle_cleanup_systemd(&json!({ "container": "picoclaw-demo" }));
        assert!(resp.ok, "error: {:?}", resp.error);
        let result = resp.result.expect("ok response carries a result");
        assert_eq!(result["cleaned"], json!(true));
    }

    #[test]
    fn cleanup_fs_requires_container() {
        let resp = handle_cleanup_fs(&json!({}));
        assert!(!resp.ok);
        assert!(resp.error.as_deref().unwrap_or("").contains("container"));
    }

    #[test]
    fn cleanup_fs_is_idempotent_when_dir_absent() {
        // The Delete step removes the instance dir first; CleanupFs must still
        // report success on an already-clean instance so the executor releases the
        // storage lease. (The bug this fixes: an error here leaked the disk lease.)
        let resp = handle_cleanup_fs(&json!({
            "container": "parity-cleanup-absent-7f3a9c00-does-not-exist"
        }));
        assert!(resp.ok, "error: {:?}", resp.error);
        assert_eq!(resp.result.expect("result")["cleaned"], json!(true));
    }

    #[test]
    fn cleanup_fs_removes_existing_instance_dir() {
        let container = format!("parity-cleanup-real-{}", std::process::id());
        let dir = instance_dir(&container);
        std::fs::create_dir_all(&dir).expect("create test instance dir");
        std::fs::write(dir.join("disk.img"), b"x").expect("write test artifact");
        assert!(dir.exists());

        let resp = handle_cleanup_fs(&json!({ "container": container }));
        assert!(resp.ok, "error: {:?}", resp.error);
        assert_eq!(resp.result.expect("result")["cleaned"], json!(true));
        assert!(!dir.exists(), "CleanupFs must remove the instance dir");
    }
}

/// Error-path / idempotency coverage for the macOS guest-image provision step.
///
/// These exercise `handle_macos_provision_and_snapshot` against a fully sandboxed
/// assets dir (no real `~/Library`, no VM boot). The provision handler is the one
/// guest-image method that does NOT gate on `check_init_disk_space` (100 GB free),
/// so it is deterministic in CI; `MacOsPrepare`/`MacOsBaseInstall` are intentionally
/// not driven here because their disk-space gate is environment-dependent.
///
/// Env is process-global, so a module-local lock serializes these tests. This bin's
/// test binary has no other env-mutating tests (the cleanup tests above key off
/// `$HOME`, not `THEYOS_VM_*`), so the lock is sufficient. The handler response is
/// captured *before* env is torn down, so an assertion panic cannot leak env state.
#[cfg(test)]
mod provision_error_path_tests {
    use super::{IpcState, handle_macos_provision_and_snapshot};
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;
    use vmrunner_macos_rs::init_state::{InitPhase, InitState, write_state};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Run `f` with `THEYOS_VM_*` pointed at a throwaway tempdir and a 0-size warm
    /// pool. Returns whatever `f` produced; env is removed before returning so a
    /// later assertion panic in the caller cannot leave the process env mutated.
    fn with_sandboxed_assets<R>(f: impl FnOnce(&std::path::Path) -> R) -> R {
        let guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().to_path_buf();
        // SAFETY: edition-2024 set_var is unsafe; serialized by ENV_LOCK and only
        // these THEYOS_VM_* keys (untouched by other tests in this binary) are set.
        unsafe {
            std::env::set_var("THEYOS_VM_ASSETS_DIR", &path);
            std::env::set_var("THEYOS_VM_STATE_DIR", &path);
            std::env::set_var("THEYOS_SNAPSHOTS_DIR", path.join("snapshots"));
            std::env::set_var("THEYOS_MACOS_WARM_POOL_SIZE", "0");
        }
        let out = f(&path);
        unsafe {
            std::env::remove_var("THEYOS_VM_ASSETS_DIR");
            std::env::remove_var("THEYOS_VM_STATE_DIR");
            std::env::remove_var("THEYOS_SNAPSHOTS_DIR");
            std::env::remove_var("THEYOS_MACOS_WARM_POOL_SIZE");
        }
        drop(dir);
        drop(guard);
        out
    }

    #[test]
    fn provision_errors_when_hardware_model_data_missing() {
        // State is at CreateSnapshot but the install never recorded the hardware model
        // (a corrupt/interrupted base-install). The snapshot step must fail loudly with
        // a clear operator error rather than panic or attempt a boot with no model.
        let resp = with_sandboxed_assets(|_p| {
            let base = vmrunner_macos_rs::macos_guest::base_dir().expect("base_dir");
            let state = InitState {
                phase: Some(InitPhase::CreateSnapshot),
                hardware_model_data: None,
                ..InitState::default()
            };
            write_state(&base, &state).expect("write init state");
            let ipc = Arc::new(IpcState::new().expect("ipc state"));
            handle_macos_provision_and_snapshot(&json!({}), &ipc)
        });
        assert!(!resp.ok, "expected an error response, got {resp:?}");
        assert!(
            resp.error
                .as_deref()
                .unwrap_or_default()
                .contains("hardware_model_data missing"),
            "expected a hardware_model_data error, got {:?}",
            resp.error
        );
    }

    #[test]
    fn provision_is_idempotent_noop_when_skipping_inject_at_provision_phase() {
        // At the Provision phase with skip_provision_inject=true, neither the inject nor
        // the snapshot block runs: the handler is a safe no-op that reports complete and
        // leaves state untouched. Calling it twice yields the identical result (no VM is
        // ever booted on this path).
        let params = json!({ "skip_provision_inject": true });
        let (resp1, resp2) = with_sandboxed_assets(|_p| {
            let base = vmrunner_macos_rs::macos_guest::base_dir().expect("base_dir");
            let state = InitState {
                phase: Some(InitPhase::Provision),
                ..InitState::default()
            };
            write_state(&base, &state).expect("write init state");
            let ipc = Arc::new(IpcState::new().expect("ipc state"));
            let r1 = handle_macos_provision_and_snapshot(&params, &ipc);
            let r2 = handle_macos_provision_and_snapshot(&params, &ipc);
            (r1, r2)
        });
        for resp in [&resp1, &resp2] {
            assert!(resp.ok, "expected ok, got {resp:?}");
            assert_eq!(
                resp.result.as_ref().expect("result")["status"],
                json!("complete")
            );
        }
    }
}
