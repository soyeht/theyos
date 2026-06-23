//! `VZVirtualMachine` wrapper for Apple Virtualization Framework.
//!
//! All `VZVirtualMachine` Objective-C calls must be dispatched to the VM's
//! dedicated serial GCD queue. Completion handlers are bridged to Rust async
//! via `tokio::task::spawn_blocking` + `std::sync::mpsc::channel`.
//!
//! Decision references (research.md):
//! - Decision 2: spawn_blocking + mpsc completion handler bridge
//! - Decision 6: VZEFIBootLoader (not VZLinuxBootLoader)
//! - Decision 8: console=hvc0 (VirtIO console, not ttyS0)
//! - Decision 9: Snapshots ARM64-only macOS 14+
//! - Decision 10: Serial GCD queue per VM

#![cfg(target_os = "macos")]
// objc 0.2.7 uses the deprecated `cfg(cargo-clippy)` internally in its macros.
#![allow(unexpected_cfgs)]
// VZ Framework ObjC FFI patterns use raw pointer casts; doc comments use ObjC names.
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::ptr_as_ptr)]
#![allow(clippy::ref_as_ptr)]
#![allow(clippy::doc_markdown)]

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use block::ConcreteBlock;
use objc::runtime::Object;
use objc::{class, msg_send, sel, sel_impl};

use crate::{error::VZError, network::NetworkConfig};

// ── Framework Links ──────────────────────────────────────────────────────────

#[link(name = "Virtualization", kind = "framework")]
unsafe extern "C" {}

#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {}

// ── GCD types/functions ──────────────────────────────────────────────────────

type DispatchQueue = *mut Object;

unsafe extern "C" {
    fn dispatch_queue_create(
        label: *const libc::c_char,
        attr: *const libc::c_void,
    ) -> DispatchQueue;
    fn dispatch_async(queue: DispatchQueue, block: *const libc::c_void);
    fn dispatch_release(queue: DispatchQueue);
}

/// Create a serial GCD dispatch queue with the given label.
///
/// # Safety
///
/// The returned pointer must eventually be released with `dispatch_release`.
#[must_use]
pub fn create_serial_queue(label: &str) -> DispatchQueue {
    let c_label = std::ffi::CString::new(label).unwrap_or_default();
    // SAFETY: dispatch_queue_create with NULL attrs creates a serial queue.
    unsafe { dispatch_queue_create(c_label.as_ptr(), std::ptr::null()) }
}

/// Dispatch a block asynchronously on the given GCD queue.
///
/// # Safety
///
/// `queue` must be a valid dispatch queue. `block` must be a valid ObjC block pointer.
pub unsafe fn dispatch_async_on_queue(queue: DispatchQueue, block: *const libc::c_void) {
    // SAFETY: dispatch_async retains the block and dispatches it on the queue.
    unsafe {
        dispatch_async(queue, block);
    }
}

/// Release a GCD dispatch queue created by [`create_serial_queue`].
///
/// # Safety
///
/// `queue` must be a valid queue returned by `dispatch_queue_create`, and callers
/// must not dispatch new work onto it after release.
pub unsafe fn release_dispatch_queue(queue: DispatchQueue) {
    // SAFETY: caller guarantees the queue is valid and no longer needed.
    unsafe {
        dispatch_release(queue);
    }
}

// ── VZ state constants (from VZVirtualMachineState enum) ────────────────────
// 0=stopped, 1=running, 2=paused, 3=error, 4=starting, 5=pausing, 6=resuming,
// 7=stopping, 8=saving, 9=restoring
const VZ_STATE_STOPPED: isize = 0;
const VZ_STATE_RUNNING: isize = 1;
const VZ_STATE_PAUSED: isize = 2;
const VZ_STATE_ERROR: isize = 3;
const VZ_STATE_STARTING: isize = 4;
const VZ_STATE_PAUSING: isize = 5;
const VZ_STATE_RESUMING: isize = 6;
const VZ_STATE_STOPPING: isize = 7;
const VZ_STATE_SAVING: isize = 8;
const VZ_STATE_RESTORING: isize = 9;

/// Minimum free disk space required to create a VM (in bytes).
const MIN_DISK_SPACE_BYTES: u64 = 5 * 1024 * 1024 * 1024;

// ── check_disk_space ─────────────────────────────────────────────────────────

/// Check available disk space before VM creation.
///
/// # Errors
///
/// Returns `VZError::InsufficientDiskSpace` if less than 5 GB is available.
pub fn check_disk_space(path: &PathBuf) -> Result<(), VZError> {
    let _metadata = std::fs::metadata(path).map_err(|e| {
        VZError::InvalidConfig(format!("Cannot access path '{}': {e}", path.display()))
    })?;

    // SAFETY: statfs is a libc function; path_cstr is a valid null-terminated string.
    let available = unsafe {
        let mut stat: libc::statfs = std::mem::zeroed();
        let path_cstr = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| VZError::InvalidConfig(format!("Invalid path: {}", path.display())))?;

        if libc::statfs(path_cstr.as_ptr(), &raw mut stat) != 0 {
            return Err(VZError::InvalidConfig(format!(
                "Cannot get disk space for '{}': {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }
        stat.f_bavail * u64::from(stat.f_bsize)
    };

    if available < MIN_DISK_SPACE_BYTES {
        #[allow(clippy::cast_precision_loss)]
        let available_gb = available as f64 / (1024.0 * 1024.0 * 1024.0);
        #[allow(clippy::cast_precision_loss)]
        let required_gb = MIN_DISK_SPACE_BYTES as f64 / (1024.0 * 1024.0 * 1024.0);

        return Err(VZError::InsufficientDiskSpace {
            available_bytes: available,
            required_bytes: MIN_DISK_SPACE_BYTES,
            message: format!(
                "Insufficient disk space at '{}': {:.2} GB available, {:.2} GB required. \
                Please free up at least {:.2} GB more.",
                path.display(),
                available_gb,
                required_gb,
                required_gb - available_gb
            ),
        });
    }

    Ok(())
}

// ── VZ supportability preflight (P5) ─────────────────────────────────────────

/// Whether the Virtualization framework reports that this process can run
/// virtual machines on this host, via `+[VZVirtualMachine isSupported]`.
///
/// `isSupported` is a class method performing a static capability check — it
/// does NOT allocate, configure, or boot a VM. A `false` result means EITHER the
/// host hardware/OS is unsupportable OR the process lacks virtualization
/// authorization; the probe cannot distinguish the two.
#[must_use]
pub fn vz_is_supported() -> bool {
    // SAFETY: +[VZVirtualMachine isSupported] is a no-argument class method
    // returning BOOL; binding to a Rust bool matches the rest of this file
    // (cf. requestStopWithError:, validateWithError:).
    unsafe { msg_send![class!(VZVirtualMachine), isSupported] }
}

/// Pure, fail-closed supportability gate. `Ok(())` when the injected `probe`
/// reports virtualization is available; otherwise a typed
/// [`VZError::VirtualizationUnsupported`]. The `probe` seam keeps this unit
/// testable without a real Virtualization framework.
///
/// # Errors
///
/// Returns [`VZError::VirtualizationUnsupported`] when `probe()` is `false`.
pub fn evaluate_vz_supportability(probe: impl Fn() -> bool) -> Result<(), VZError> {
    if probe() {
        return Ok(());
    }
    Err(VZError::VirtualizationUnsupported(
        // Worded to classify as `virtualization_unavailable` without claiming
        // whether the root cause is hardware support or signing authorization.
        "the Virtualization framework reports this process cannot run virtual \
         machines on this host (VZVirtualMachine.isSupported() was false) — an \
         unsupportable host or a missing virtualization authorization; no \
         virtual machine can be created"
            .to_string(),
    ))
}

/// Real-framework supportability preflight: [`evaluate_vz_supportability`] over
/// the live [`vz_is_supported`] probe. Fail-closed.
///
/// Not yet wired into the admission path: the single safe chokepoint is
/// `VmAdmission::reserve`, but gating there needs a new `AdmissionError` variant
/// and the guest-image failure-code mapping decision, tracked as a follow-up.
///
/// # Errors
///
/// Propagates [`VZError::VirtualizationUnsupported`] from
/// [`evaluate_vz_supportability`].
pub fn preflight_vz_supportability() -> Result<(), VZError> {
    evaluate_vz_supportability(vz_is_supported)
}

/// Build a typed, honest error for a nil `VZVirtualMachine` initializer given
/// the host's supportability. When the framework can run VMs, a nil init points
/// at an invalid VM configuration; when it cannot, surface the unsupportable
/// host instead of a misleading "bad config" message. Pure for testability.
fn diagnose_vm_init_nil(supported: bool) -> VZError {
    if supported {
        VZError::VirtualizationError(
            "VZVirtualMachine initWithConfiguration:queue: returned nil while \
             virtualization is available — most likely an invalid VM \
             configuration"
                .to_string(),
        )
    } else {
        // Same honest typed error as the supportability seam.
        evaluate_vz_supportability(|| false).expect_err("probe is constant false")
    }
}

// ── async_vz_call ────────────────────────────────────────────────────────────

/// Bridge an `^(NSError *)` ObjC completion handler to a Rust `Result`.
///
/// Pattern (Decision 2 from research.md):
/// 1. `spawn_blocking` keeps the tokio executor unblocked.
/// 2. `mpsc::channel` conveys the result from the GCD callback.
/// 3. `ConcreteBlock` wraps the Rust closure as an Objective-C block.
///
/// # Safety
///
/// The caller is responsible for:
/// - `vm_obj` being a valid, retained `VZVirtualMachine *` for the duration.
/// - `queue` being the serial GCD queue this VM was initialized with.
/// - `dispatch_fn` dispatching only ObjC messages that expect `^(NSError *)`.
///
/// # Errors
///
/// Returns the NSError description on failure, or timeout after `timeout_secs`.
pub(crate) async fn async_vz_call<F>(
    vm_obj: *mut Object,
    queue: DispatchQueue,
    timeout_secs: u64,
    dispatch_fn: F,
) -> Result<(), VZError>
where
    F: FnOnce(*mut Object, DispatchQueue, mpsc::SyncSender<Result<(), String>>) + Send + 'static,
{
    let (tx, rx) = mpsc::sync_channel::<Result<(), String>>(1);

    // Cast raw ObjC pointers to usize to satisfy Send bound for spawn_blocking.
    // SAFETY: The GCD serial queue provides exclusive VM access; the values are
    // valid for the duration of this call since the VM object lives in an Arc.
    let vm_addr: usize = vm_obj as usize;
    let queue_addr: usize = queue as usize;

    tokio::task::spawn_blocking(move || {
        let vm_obj = vm_addr as *mut Object;
        let queue = queue_addr as *mut Object as DispatchQueue;
        dispatch_fn(vm_obj, queue, tx);

        rx.recv_timeout(Duration::from_secs(timeout_secs))
            .map_err(|e| format!("timeout waiting for VZ completion: {e}"))?
    })
    .await
    .map_err(|e| VZError::Internal(format!("spawn_blocking panicked: {e}")))?
    .map_err(VZError::Internal)
}

// ── NSError helper ────────────────────────────────────────────────────────────

/// Extract a human-readable string from an NSError pointer.
///
/// # Safety
///
/// `err_obj` must be either null or a valid `NSError *`.
unsafe fn nserror_message(err_obj: *mut Object) -> String {
    if err_obj.is_null() {
        return String::new();
    }
    // SAFETY: caller guarantees err_obj is NSError*; localizedDescription returns NSString*.
    let desc: *mut Object = unsafe { msg_send![err_obj, localizedDescription] };
    if desc.is_null() {
        return "unknown NSError (nil description)".to_string();
    }
    let cstr: *const libc::c_char = unsafe { msg_send![desc, UTF8String] };
    if cstr.is_null() {
        return "unknown NSError (nil UTF8String)".to_string();
    }
    // SAFETY: cstr points into NSString's internal buffer, valid for the duration of this fn.
    unsafe { std::ffi::CStr::from_ptr(cstr) }
        .to_string_lossy()
        .into_owned()
}

// ── NSURL helper ─────────────────────────────────────────────────────────────

/// Create an `NSURL` from a filesystem path.
///
/// # Safety
///
/// Returns a retained `NSURL *`. Caller must release it.
unsafe fn nsurl_from_path(path: &Path) -> Result<*mut Object, VZError> {
    let path_str = path
        .to_str()
        .ok_or_else(|| VZError::InvalidConfig(format!("non-UTF-8 path: {}", path.display())))?;
    let ns_str = unsafe {
        let cls = class!(NSString);
        let raw: *const libc::c_char = std::ffi::CString::new(path_str)
            .unwrap()
            .into_raw()
            .cast_const();
        let ns: *mut Object = msg_send![cls, stringWithUTF8String: raw];
        ns
    };
    let url: *mut Object =
        unsafe { msg_send![class!(NSURL), fileURLWithPath: ns_str isDirectory: false] };
    if url.is_null() {
        return Err(VZError::InvalidConfig(format!(
            "Could not create NSURL for path: {}",
            path.display()
        )));
    }
    Ok(url)
}

// ── VM state ─────────────────────────────────────────────────────────────────

/// VM state (mirrors VZVirtualMachineState enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Stopped,
    Running,
    Paused,
    Error,
    Starting,
    Pausing,
    Resuming,
    Stopping,
    Saving,
    Restoring,
    Unknown,
}

impl From<isize> for VmState {
    fn from(n: isize) -> Self {
        match n {
            VZ_STATE_STOPPED => Self::Stopped,
            VZ_STATE_RUNNING => Self::Running,
            VZ_STATE_PAUSED => Self::Paused,
            VZ_STATE_ERROR => Self::Error,
            VZ_STATE_STARTING => Self::Starting,
            VZ_STATE_PAUSING => Self::Pausing,
            VZ_STATE_RESUMING => Self::Resuming,
            VZ_STATE_STOPPING => Self::Stopping,
            VZ_STATE_SAVING => Self::Saving,
            VZ_STATE_RESTORING => Self::Restoring,
            _ => Self::Unknown,
        }
    }
}

// ── VZVirtualMachine ─────────────────────────────────────────────────────────

/// Wrapper around `VZVirtualMachine *`.
///
/// # Safety invariants
///
/// - `inner` is a retained `VZVirtualMachine *`, valid for the lifetime of this struct.
/// - `queue` is the serial GCD queue passed to `initWithConfiguration:queue:`.
/// - All ObjC calls on `inner` MUST be dispatched to `queue`.
/// - `Drop` releases both `inner` and `queue`.
pub struct VZVirtualMachine {
    /// Retained `VZVirtualMachine *`.
    inner: *mut Object,
    /// Dedicated serial GCD queue for this VM.
    queue: DispatchQueue,
    /// Container name (used for queue label and logging).
    pub container_id: String,
}

// SAFETY: VZVirtualMachine is Send+Sync: ObjC objects managed by ARC are
// thread-safe when all calls go through the dedicated serial queue.
unsafe impl Send for VZVirtualMachine {}
unsafe impl Sync for VZVirtualMachine {}

impl Drop for VZVirtualMachine {
    fn drop(&mut self) {
        // SAFETY: self.inner is a retained ObjC object; release to balance alloc/init.
        if !self.inner.is_null() {
            unsafe {
                let _: () = msg_send![self.inner, release];
            }
        }
        // SAFETY: self.queue was created with dispatch_queue_create; release it.
        if !self.queue.is_null() {
            unsafe {
                dispatch_release(self.queue);
            }
        }
    }
}

impl VZVirtualMachine {
    /// Create a new `VZVirtualMachine` from a built configuration.
    ///
    /// Calls `[[VZVirtualMachine alloc] initWithConfiguration:queue:]` with a
    /// per-VM serial dispatch queue labelled `theyos.vm.<container_id>`.
    ///
    /// # Errors
    ///
    /// Returns an error if the ObjC initializer returns nil (bad config).
    pub fn new(
        config: &VZVirtualMachineConfiguration,
        container_id: &str,
    ) -> Result<Self, VZError> {
        let label = format!("theyos.vm.{container_id}\0");

        // SAFETY: dispatch_queue_create takes a C string label and NULL attrs → serial queue.
        let queue = unsafe { dispatch_queue_create(label.as_ptr().cast(), std::ptr::null()) };
        if queue.is_null() {
            return Err(VZError::Internal(
                "dispatch_queue_create returned null".into(),
            ));
        }

        // SAFETY: VZVirtualMachine alloc+init with the validated ObjC configuration object.
        let vm_obj: *mut Object = unsafe {
            let alloc: *mut Object = msg_send![class!(VZVirtualMachine), alloc];
            msg_send![alloc, initWithConfiguration: config.inner queue: queue]
        };

        if vm_obj.is_null() {
            // SAFETY: release queue since we own it and the VM creation failed.
            unsafe { dispatch_release(queue) };
            // Typed, honest diagnostic instead of a generic "returned nil": when
            // the host can't run VMs at all, say so (probe consulted only on this
            // failure path; the success path above is unchanged).
            return Err(diagnose_vm_init_nil(vz_is_supported()));
        }

        tracing::debug!(
            container = container_id,
            "VZVirtualMachine created successfully"
        );

        Ok(Self {
            inner: vm_obj,
            queue,
            container_id: container_id.to_string(),
        })
    }

    /// Set the ObjC delegate object on this VM.
    ///
    /// The delegate must implement `VZVirtualMachineDelegate` protocol. Ownership
    /// semantics: VZ holds the delegate weakly (standard Cocoa delegate pattern), so
    /// the caller is responsible for keeping it alive (typically via `VmEntry._delegate`).
    ///
    /// # Safety
    ///
    /// `delegate` must be a valid, retained ObjC object for the duration of this call.
    /// The caller must keep the delegate alive for at least as long as the VM is running.
    pub fn set_delegate(&self, delegate: *mut Object) {
        // SAFETY: setDelegate: is safe from any thread; VZ retains the delegate weakly.
        unsafe {
            let _: () = msg_send![self.inner, setDelegate: delegate];
        }
    }

    /// Get the current VM state.
    ///
    /// # Errors
    ///
    /// Never fails in practice; returns `VmState::Unknown` for unrecognized values.
    pub fn get_state(&self) -> Result<VmState, VZError> {
        // SAFETY: `state` is a property getter on VZVirtualMachine, safe to call from any thread.
        let raw: isize = unsafe { msg_send![self.inner, state] };
        Ok(VmState::from(raw))
    }

    /// Read the MAC address assigned to the VM's first network device.
    ///
    /// Returns the lowercase colon-separated MAC string (e.g. `"aa:bb:cc:dd:ee:ff"`),
    /// or `None` if no network device is configured.
    ///
    /// # Safety invariants
    ///
    /// Reads the `configuration.networkDevices[0].MACAddress.string` property chain.
    /// All properties are read-only getters on VZ objects created at init time — safe
    /// to call from any thread after `VZVirtualMachine::new`.
    #[must_use]
    pub fn get_mac_address(&self) -> Option<String> {
        unsafe {
            // SAFETY: `configuration` is a read-only property returning the VZVirtualMachineConfiguration
            // passed at init. It is retained by the VM and valid for the VM's lifetime.
            let config: *mut Object = msg_send![self.inner, configuration];
            if config.is_null() {
                return None;
            }
            // SAFETY: `networkDevices` returns NSArray<VZNetworkDeviceConfiguration *>.
            let devices: *mut Object = msg_send![config, networkDevices];
            if devices.is_null() {
                return None;
            }
            let count: usize = msg_send![devices, count];
            if count == 0 {
                return None;
            }
            // SAFETY: objectAtIndex:0 is valid since count > 0.
            let dev: *mut Object = msg_send![devices, objectAtIndex: 0usize];
            if dev.is_null() {
                return None;
            }
            // SAFETY: `MACAddress` returns VZMACAddress (non-nil on a configured device).
            let mac_obj: *mut Object = msg_send![dev, MACAddress];
            if mac_obj.is_null() {
                return None;
            }
            // SAFETY: `string` returns NSString with the colon-separated MAC.
            let mac_str: *mut Object = msg_send![mac_obj, string];
            if mac_str.is_null() {
                return None;
            }
            let cstr: *const std::os::raw::c_char = msg_send![mac_str, UTF8String];
            if cstr.is_null() {
                return None;
            }
            Some(
                std::ffi::CStr::from_ptr(cstr)
                    .to_string_lossy()
                    .to_lowercase(),
            )
        }
    }

    /// Start the VM asynchronously, waiting up to 30 seconds.
    ///
    /// Calls `[vm startWithCompletionHandler:^(NSError *)]` via `async_vz_call`.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM fails to start or the timeout elapses.
    pub async fn start(&self) -> Result<(), VZError> {
        let vm = self.inner;
        let queue = self.queue;
        let container = self.container_id.clone();

        tracing::info!(container, "Starting VZVirtualMachine");

        async_vz_call(vm, queue, 30, move |vm_obj, q, tx| {
            let completion = ConcreteBlock::new(move |err: *mut Object| {
                // SAFETY: err is either nil or NSError*.
                let result = if err.is_null() {
                    Ok(())
                } else {
                    Err(unsafe { nserror_message(err) })
                };
                let _ = tx.send(result);
            });
            let completion = completion.copy();

            // SAFETY: dispatch_async schedules the block on the VM's serial queue.
            // The block calls startWithCompletionHandler: on the VM object.
            let start_block = ConcreteBlock::new(move || unsafe {
                let _: () = msg_send![vm_obj, startWithCompletionHandler: &*completion];
            });
            let start_block = start_block.copy();
            unsafe {
                dispatch_async(q, &*start_block as *const _ as *const libc::c_void);
            }
        })
        .await
        .map_err(|e| VZError::VirtualizationError(format!("start: {e}")))?;

        tracing::info!(container, "VZVirtualMachine started");
        Ok(())
    }

    /// Stop the VM.
    ///
    /// If `graceful` is true, first calls `requestStopWithError:` (asks guest to shutdown)
    /// and waits up to 30 seconds. If the guest doesn't stop, falls back to `stopWithCompletionHandler:`.
    ///
    /// # Errors
    ///
    /// Returns an error if force-stop fails.
    pub async fn stop(&self, graceful: bool) -> Result<(), VZError> {
        let vm = self.inner;
        let queue = self.queue;
        let container = self.container_id.clone();

        tracing::info!(container, graceful, "Stopping VZVirtualMachine");

        if graceful {
            // Try graceful shutdown first: requestStopWithError: sends ACPI power-off to guest.
            // SAFETY: requestStopWithError: is safe to call from any thread per VZ docs.
            let mut err_ptr: *mut Object = std::ptr::null_mut();
            let sent: bool = unsafe { msg_send![vm, requestStopWithError: &mut err_ptr] };
            if sent {
                // Poll for stopped state up to 30 seconds.
                for _ in 0..60 {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    if let Ok(VmState::Stopped) = self.get_state() {
                        tracing::info!(container, "VZVirtualMachine stopped gracefully");
                        return Ok(());
                    }
                }
                tracing::warn!(
                    container,
                    "graceful stop timed out after 30s, force-stopping"
                );
            }
        }

        // Force stop via stopWithCompletionHandler:.
        async_vz_call(vm, queue, 30, move |vm_obj, q, tx| {
            let completion = ConcreteBlock::new(move |err: *mut Object| {
                let result = if err.is_null() {
                    Ok(())
                } else {
                    Err(unsafe { nserror_message(err) })
                };
                let _ = tx.send(result);
            });
            let completion = completion.copy();

            let stop_block = ConcreteBlock::new(move || unsafe {
                let _: () = msg_send![vm_obj, stopWithCompletionHandler: &*completion];
            });
            let stop_block = stop_block.copy();
            unsafe {
                dispatch_async(q, &*stop_block as *const _ as *const libc::c_void);
            }
        })
        .await
        .map_err(|e| VZError::VirtualizationError(format!("stop: {e}")))?;

        tracing::info!(container, "VZVirtualMachine force-stopped");
        Ok(())
    }

    /// Pause the VM (prerequisite to saving a snapshot).
    ///
    /// # Errors
    ///
    /// Returns an error if the VM fails to pause.
    pub async fn pause(&self) -> Result<(), VZError> {
        let vm = self.inner;
        let queue = self.queue;
        let container = self.container_id.clone();

        tracing::info!(container, "Pausing VZVirtualMachine");

        async_vz_call(vm, queue, 30, move |vm_obj, q, tx| {
            let completion = ConcreteBlock::new(move |err: *mut Object| {
                let result = if err.is_null() {
                    Ok(())
                } else {
                    Err(unsafe { nserror_message(err) })
                };
                let _ = tx.send(result);
            });
            let completion = completion.copy();

            let block = ConcreteBlock::new(move || unsafe {
                let _: () = msg_send![vm_obj, pauseWithCompletionHandler: &*completion];
            });
            let block = block.copy();
            unsafe {
                dispatch_async(q, &*block as *const _ as *const libc::c_void);
            }
        })
        .await
        .map_err(|e| VZError::VirtualizationError(format!("pause: {e}")))?;

        tracing::info!(container, "VZVirtualMachine paused");
        Ok(())
    }

    /// Save the VM state to a `.vzsnapshot` file.
    ///
    /// VM must be paused before calling this. Guards with `validateSaveRestoreSupportWithError:`.
    ///
    /// # Errors
    ///
    /// Returns an error if snapshot save/restore is not supported or save fails.
    pub async fn save_snapshot(&self, path: &Path) -> Result<(), VZError> {
        let vm = self.inner;
        let queue = self.queue;
        let container = self.container_id.clone();

        // Note: validateSaveRestoreSupportWithError: was removed from VZVirtualMachine on macOS 26.
        // On macOS 26 it lives on VZVirtualMachineConfiguration instead.
        // Skip the explicit check — saveMachineStateToURL:completionHandler: returns an error
        // via the completion handler if save/restore isn't supported.

        let url = unsafe { nsurl_from_path(path)? };
        // Cast NSURL* to usize so the closure satisfies Send.
        // SAFETY: url is a valid retained NSURL* for the duration of this call.
        let url_addr: usize = url as usize;

        tracing::info!(container, path = %path.display(), "Saving VZ snapshot");

        async_vz_call(vm, queue, 120, move |vm_obj, q, tx| {
            let url = url_addr as *mut Object;
            let completion = ConcreteBlock::new(move |err: *mut Object| {
                let result = if err.is_null() {
                    Ok(())
                } else {
                    Err(unsafe { nserror_message(err) })
                };
                let _ = tx.send(result);
            });
            let completion = completion.copy();

            let block = ConcreteBlock::new(move || unsafe {
                let _: () =
                    msg_send![vm_obj, saveMachineStateToURL: url completionHandler: &*completion];
            });
            let block = block.copy();
            unsafe {
                dispatch_async(q, &*block as *const _ as *const libc::c_void);
            }
        })
        .await
        .map_err(|e| VZError::SnapshotError(format!("save: {e}")))?;

        tracing::info!(container, "VZ snapshot saved");
        Ok(())
    }

    /// Restore a VM from a `.vzsnapshot` file, then resume to running state.
    ///
    /// # Errors
    ///
    /// Returns an error if restore or resume fails.
    pub async fn restore_snapshot(&self, path: &Path) -> Result<(), VZError> {
        let vm = self.inner;
        let queue = self.queue;
        let container = self.container_id.clone();

        let url = unsafe { nsurl_from_path(path)? };
        // Cast NSURL* to usize so the closure satisfies Send.
        // SAFETY: url is a valid retained NSURL* for the duration of this call.
        let url_addr: usize = url as usize;

        tracing::info!(container, path = %path.display(), "Restoring VZ snapshot");

        // Step 1: restoreMachineStateFromURL:
        async_vz_call(vm, queue, 60, move |vm_obj, q, tx| {
            let url = url_addr as *mut Object;
            let completion = ConcreteBlock::new(move |err: *mut Object| {
                let result = if err.is_null() {
                    Ok(())
                } else {
                    Err(unsafe { nserror_message(err) })
                };
                let _ = tx.send(result);
            });
            let completion = completion.copy();

            let block = ConcreteBlock::new(move || unsafe {
                let _: () = msg_send![vm_obj,
                    restoreMachineStateFromURL: url
                    completionHandler: &*completion
                ];
            });
            let block = block.copy();
            unsafe {
                dispatch_async(q, &*block as *const _ as *const libc::c_void);
            }
        })
        .await
        .map_err(|e| VZError::SnapshotError(format!("restore: {e}")))?;

        // Step 2: resumeWithCompletionHandler: to go Paused → Running.
        async_vz_call(vm, queue, 30, move |vm_obj, q, tx| {
            let completion = ConcreteBlock::new(move |err: *mut Object| {
                let result = if err.is_null() {
                    Ok(())
                } else {
                    Err(unsafe { nserror_message(err) })
                };
                let _ = tx.send(result);
            });
            let completion = completion.copy();

            let block = ConcreteBlock::new(move || unsafe {
                let _: () = msg_send![vm_obj, resumeWithCompletionHandler: &*completion];
            });
            let block = block.copy();
            unsafe {
                dispatch_async(q, &*block as *const _ as *const libc::c_void);
            }
        })
        .await
        .map_err(|e| VZError::SnapshotError(format!("resume after restore: {e}")))?;

        tracing::info!(container, "VZ snapshot restored and VM running");
        Ok(())
    }
}

// ── VZVirtualMachineConfiguration ────────────────────────────────────────────

/// Holds a built, validated `VZVirtualMachineConfiguration *`.
///
/// The ObjC object is retained and released on Drop.
pub struct VZVirtualMachineConfiguration {
    /// Retained `VZVirtualMachineConfiguration *`.
    pub(crate) inner: *mut Object,
    pub cpus: u32,
    pub memory_mb: u32,
    /// The MAC address assigned to the first network device (colon-separated lowercase).
    /// Captured at build time to avoid reading from the running VM (which requires the VM queue).
    pub mac_address: String,
    /// Raw `VZMacMachineIdentifier` data (ECID bytes) used in this config.
    /// Only populated for macOS guest configs (`VZMacOSVmConfigurationBuilder`).
    /// Persist this to reuse the same ECID for snapshot restore — VZ 26 requires the
    /// restore VM to have the identical ECID as when the snapshot was saved.
    pub machine_identifier_data: Vec<u8>,
}

unsafe impl Send for VZVirtualMachineConfiguration {}
unsafe impl Sync for VZVirtualMachineConfiguration {}

impl Drop for VZVirtualMachineConfiguration {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            unsafe {
                let _: () = msg_send![self.inner, release];
            }
        }
    }
}

// ── VZVirtualMachineConfigurationBuilder ─────────────────────────────────────

/// Assembles a `VZVirtualMachineConfiguration` from component parts.
///
/// Produces an EFI-booted VM (Decision 6) with:
/// - `VZGenericPlatformConfiguration`
/// - `VZEFIBootLoader` + `.nvram` EFI variable store
/// - `VZDiskImageStorageDeviceAttachment` for rootfs disk (read-write)
/// - Second `VZDiskImageStorageDeviceAttachment` for cidata ISO (read-only)
/// - `VZNATNetworkDeviceAttachment` with random MAC
/// - `VZVirtioConsoleDeviceSerialPortConfiguration` → hvc0
/// - `VZVirtioEntropyDeviceConfiguration`
pub struct VZVirtualMachineConfigurationBuilder {
    pub cpus: u32,
    pub memory_mb: u32,
    /// Path to per-instance raw disk image (APFS CoW clone of base).
    pub disk_path: PathBuf,
    /// Path to EFI variable store (.nvram).
    pub efi_store_path: PathBuf,
    /// Path to cloud-init cidata ISO.
    pub cidata_iso_path: PathBuf,
    /// MAC address to assign (hex string, colon-separated).
    pub mac_address: String,
    pub network: NetworkConfig,
}

impl VZVirtualMachineConfigurationBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cpus: 2,
            memory_mb: 2048,
            disk_path: PathBuf::new(),
            efi_store_path: PathBuf::new(),
            cidata_iso_path: PathBuf::new(),
            mac_address: String::new(),
            network: NetworkConfig::default(),
        }
    }

    #[must_use]
    pub fn cpus(mut self, cpus: u32) -> Self {
        self.cpus = cpus;
        self
    }

    #[must_use]
    pub fn memory_mb(mut self, memory_mb: u32) -> Self {
        self.memory_mb = memory_mb;
        self
    }

    #[must_use]
    pub fn disk_path(mut self, path: PathBuf) -> Self {
        self.disk_path = path;
        self
    }

    #[must_use]
    pub fn efi_store_path(mut self, path: PathBuf) -> Self {
        self.efi_store_path = path;
        self
    }

    #[must_use]
    pub fn cidata_iso_path(mut self, path: PathBuf) -> Self {
        self.cidata_iso_path = path;
        self
    }

    #[must_use]
    pub fn mac_address(mut self, mac: String) -> Self {
        self.mac_address = mac;
        self
    }

    #[must_use]
    pub fn network(mut self, network: NetworkConfig) -> Self {
        self.network = network;
        self
    }

    /// Build the `VZVirtualMachineConfiguration` using real ObjC calls.
    ///
    /// # Errors
    ///
    /// Returns an error if any path is missing, values are out of range,
    /// or `validateWithError:` fails.
    pub fn build(self) -> Result<VZVirtualMachineConfiguration, VZError> {
        // Validate ranges.
        if self.cpus < 1 || self.cpus > 4 {
            return Err(VZError::InvalidConfig(format!(
                "CPU count must be between 1 and 4, got {}",
                self.cpus
            )));
        }
        if self.memory_mb < 512 || self.memory_mb > 8192 {
            return Err(VZError::InvalidConfig(format!(
                "Memory must be between 512 and 8192 MB, got {}",
                self.memory_mb
            )));
        }
        if !self.disk_path.exists() {
            return Err(VZError::InvalidConfig(format!(
                "Disk image not found: {}",
                self.disk_path.display()
            )));
        }
        // NOTE: NVRAM not existing is OK — build_inner() will create a blank
        // VZEFIVariableStore when the file is absent (needed for first boot).
        if !self.cidata_iso_path.exists() {
            return Err(VZError::InvalidConfig(format!(
                "Cidata ISO not found: {}",
                self.cidata_iso_path.display()
            )));
        }

        // SAFETY: All ObjC calls below use class! and msg_send! macros. Objects are
        // retained until transferred to VZVirtualMachineConfiguration's arrays.
        unsafe { self.build_inner() }
    }

    /// Internal unsafe build — all real VZ Framework ObjC calls.
    #[allow(clippy::too_many_lines)]
    unsafe fn build_inner(self) -> Result<VZVirtualMachineConfiguration, VZError> {
        let cpus = self.cpus;
        let memory_bytes: u64 = u64::from(self.memory_mb) * 1024 * 1024;

        // ── Platform: VZGenericPlatformConfiguration ──────────────────────────
        // Apple's sample code, Tart, and Lima all set a VZGenericMachineIdentifier
        // on the platform. Without it the EFI firmware may fail to initialise.
        let platform: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZGenericPlatformConfiguration), alloc];
            let p: *mut Object = msg_send![alloc, init];
            let machine_id: *mut Object = {
                let a: *mut Object = msg_send![class!(VZGenericMachineIdentifier), alloc];
                msg_send![a, init]
            };
            let _: () = msg_send![p, setMachineIdentifier: machine_id];
            p
        };

        // ── Boot: VZEFIBootLoader ─────────────────────────────────────────────
        // If a pre-populated NVRAM exists (cloned from base image with GRUB boot
        // entries already configured), reuse it via initWithURL:.  Otherwise create
        // a fresh one — but note that VZ's EFI may not auto-discover BOOTAA64.EFI
        // from a blank NVRAM on all macOS versions.
        let efi_store_url = unsafe { nsurl_from_path(&self.efi_store_path)? };
        let mut efi_create_err: *mut Object = std::ptr::null_mut();
        let efi_var_store: *mut Object = if self.efi_store_path.exists() {
            // Reuse the cloned (pre-populated) NVRAM.
            unsafe {
                let alloc: *mut Object = msg_send![class!(VZEFIVariableStore), alloc];
                msg_send![alloc, initWithURL: efi_store_url]
            }
        } else {
            // No NVRAM present — create a blank one (first-time fallback).
            let store: *mut Object = unsafe {
                let alloc: *mut Object = msg_send![class!(VZEFIVariableStore), alloc];
                msg_send![alloc,
                    initCreatingVariableStoreAtURL: efi_store_url
                    options: 0usize
                    error: &mut efi_create_err
                ]
            };
            if store.is_null() {
                let msg = unsafe { nserror_message(efi_create_err) };
                return Err(VZError::InvalidConfig(format!(
                    "VZEFIVariableStore create failed: {msg}"
                )));
            }
            store
        };

        let boot_loader: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZEFIBootLoader), alloc];
            let loader: *mut Object = msg_send![alloc, init];
            let _: () = msg_send![loader, setVariableStore: efi_var_store];
            loader
        };

        // ── Storage: rootfs disk (read-write) ────────────────────────────────
        // Use the explicit 4-arg initializer (macOS 12+) with cached mode
        // and full sync — matches Tart behaviour for Linux EFI boot.
        let disk_url = unsafe { nsurl_from_path(&self.disk_path)? };
        let mut disk_err: *mut Object = std::ptr::null_mut();
        let disk_attach: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZDiskImageStorageDeviceAttachment), alloc];
            // cachingMode: 1 = VZDiskImageCachingModeCached (Tart uses this for Linux)
            // synchronizationMode: 1 = VZDiskImageSynchronizationModeFull
            msg_send![alloc,
                initWithURL: disk_url
                readOnly: false
                cachingMode: 1i64
                synchronizationMode: 1i64
                error: &mut disk_err
            ]
        };
        if disk_attach.is_null() {
            let msg = unsafe { nserror_message(disk_err) };
            return Err(VZError::InvalidConfig(format!(
                "Cannot attach disk '{}': {msg}",
                self.disk_path.display()
            )));
        }
        let rootfs_storage: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZVirtioBlockDeviceConfiguration), alloc];
            msg_send![alloc, initWithAttachment: disk_attach]
        };

        // ── Storage: cidata ISO (read-only) ───────────────────────────────────
        let cidata_url = unsafe { nsurl_from_path(&self.cidata_iso_path)? };
        let mut cidata_err: *mut Object = std::ptr::null_mut();
        let cidata_attach: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZDiskImageStorageDeviceAttachment), alloc];
            msg_send![alloc,
                initWithURL: cidata_url
                readOnly: true
                error: &mut cidata_err
            ]
        };
        if cidata_attach.is_null() {
            let msg = unsafe { nserror_message(cidata_err) };
            return Err(VZError::InvalidConfig(format!(
                "Cannot attach cidata ISO '{}': {msg}",
                self.cidata_iso_path.display()
            )));
        }
        let cidata_storage: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZVirtioBlockDeviceConfiguration), alloc];
            msg_send![alloc, initWithAttachment: cidata_attach]
        };

        // ── Network: VZNATNetworkDeviceAttachment ─────────────────────────────
        let nat_attach: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZNATNetworkDeviceAttachment), alloc];
            msg_send![alloc, init]
        };
        let net_dev: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZVirtioNetworkDeviceConfiguration), alloc];
            let dev: *mut Object = msg_send![alloc, init];
            let _: () = msg_send![dev, setAttachment: nat_attach];

            // Use the caller-supplied MAC so DHCP lookup (resolve_dhcp_ip) finds
            // the right lease. Fall back to a random MAC only if none was provided.
            let mac_obj: *mut Object = if self.mac_address.is_empty() {
                msg_send![class!(VZMACAddress), randomLocallyAdministeredAddress]
            } else {
                let mac_cstr = std::ffi::CString::new(self.mac_address.as_str()).unwrap();
                let mac_nsstr: *mut Object =
                    msg_send![class!(NSString), stringWithUTF8String: mac_cstr.as_ptr()];
                let alloc_mac: *mut Object = msg_send![class!(VZMACAddress), alloc];
                let parsed: *mut Object = msg_send![alloc_mac, initWithString: mac_nsstr];
                if parsed.is_null() {
                    // Invalid format — fall back to random
                    msg_send![class!(VZMACAddress), randomLocallyAdministeredAddress]
                } else {
                    parsed
                }
            };
            let _: () = msg_send![dev, setMACAddress: mac_obj];
            dev
        };

        // ── Serial console: VZVirtioConsoleDeviceSerialPortConfiguration ─────
        // Provides hvc0 in the guest (Decision 8).
        let serial_attach: *mut Object = {
            use std::os::unix::io::IntoRawFd;
            let alloc: *mut Object = msg_send![class!(VZFileHandleSerialPortAttachment), alloc];
            let dev_null_rd = std::fs::File::open("/dev/null")
                .map_err(|e| VZError::Internal(format!("open /dev/null read: {e}")))?;
            // Write serial output to a log file if THEYOS_LINUX_SERIAL_LOG is set (for debugging).
            let serial_log = std::env::var("THEYOS_LINUX_SERIAL_LOG")
                .ok()
                .filter(|s| !s.is_empty());
            let dev_null_wr = if let Some(ref log_path) = serial_log {
                tracing::info!(path = log_path, "Linux serial console → log file");
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log_path)
                    .map_err(|e| VZError::Internal(format!("open serial log {log_path}: {e}")))?
            } else {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/null")
                    .map_err(|e| VZError::Internal(format!("open /dev/null write: {e}")))?
            };
            let rd_fd = dev_null_rd.into_raw_fd();
            let wr_fd = dev_null_wr.into_raw_fd();
            // Use initWithFileDescriptor:closeOnDealloc: instead of the deprecated
            // fileHandleWithDescriptor: which throws NSInvalidArgumentException on macOS 26+.
            let rd_nsfile: *mut Object = {
                let a: *mut Object = msg_send![class!(NSFileHandle), alloc];
                msg_send![a, initWithFileDescriptor: rd_fd closeOnDealloc: true]
            };
            let wr_nsfile: *mut Object = {
                let a: *mut Object = msg_send![class!(NSFileHandle), alloc];
                msg_send![a, initWithFileDescriptor: wr_fd closeOnDealloc: true]
            };
            msg_send![alloc, initWithFileHandleForReading: rd_nsfile fileHandleForWriting: wr_nsfile]
        };
        let serial_port: *mut Object = {
            let alloc: *mut Object =
                msg_send![class!(VZVirtioConsoleDeviceSerialPortConfiguration), alloc];
            let port: *mut Object = msg_send![alloc, init];
            let _: () = msg_send![port, setAttachment: serial_attach];
            port
        };

        // ── Entropy: VZVirtioEntropyDeviceConfiguration ───────────────────────
        let entropy: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZVirtioEntropyDeviceConfiguration), alloc];
            msg_send![alloc, init]
        };

        // ── Assemble VZVirtualMachineConfiguration ────────────────────────────
        let config_obj: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZVirtualMachineConfiguration), alloc];
            msg_send![alloc, init]
        };

        // CPU + memory
        let _: () = msg_send![config_obj, setCPUCount: cpus as usize];
        let _: () = msg_send![config_obj, setMemorySize: memory_bytes];

        // Platform + bootloader
        let _: () = msg_send![config_obj, setPlatform: platform];
        let _: () = msg_send![config_obj, setBootLoader: boot_loader];

        // Storage devices array
        let storage_array = unsafe { build_ns_array(&[rootfs_storage, cidata_storage]) };
        let _: () = msg_send![config_obj, setStorageDevices: storage_array];

        // Network devices array
        let network_array = unsafe { build_ns_array(&[net_dev]) };
        let _: () = msg_send![config_obj, setNetworkDevices: network_array];

        // Serial ports array
        let serial_array = unsafe { build_ns_array(&[serial_port]) };
        let _: () = msg_send![config_obj, setSerialPorts: serial_array];

        // Entropy devices array
        let entropy_array = unsafe { build_ns_array(&[entropy]) };
        let _: () = msg_send![config_obj, setEntropyDevices: entropy_array];

        // validateWithError:
        let mut val_err: *mut Object = std::ptr::null_mut();
        let valid: bool = msg_send![config_obj, validateWithError: &mut val_err];
        if !valid {
            let msg = unsafe { nserror_message(val_err) };
            let _: () = msg_send![config_obj, release];
            return Err(VZError::InvalidConfig(format!(
                "VZVirtualMachineConfiguration validateWithError: {msg}"
            )));
        }

        Ok(VZVirtualMachineConfiguration {
            inner: config_obj,
            cpus,
            memory_mb: self.memory_mb,
            mac_address: self.mac_address.clone(),
            machine_identifier_data: Vec::new(),
        })
    }
}

impl Default for VZVirtualMachineConfigurationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── NSArray helper ────────────────────────────────────────────────────────────

/// Build an `NSArray` from a slice of ObjC object pointers.
///
/// # Safety
///
/// All pointers in `items` must be valid, retained ObjC objects.
unsafe fn build_ns_array(items: &[*mut Object]) -> *mut Object {
    let count = items.len();
    msg_send![class!(NSArray),
        arrayWithObjects: items.as_ptr()
        count: count
    ]
}

// ── Public nsurl helper (for macos_guest.rs) ──────────────────────────────────

/// Public wrapper around `nsurl_from_path` for use by `macos_guest.rs`.
///
/// # Safety
///
/// Returns a retained `NSURL *`. Caller must release it.
///
/// # Errors
///
/// Returns `VZError::InvalidConfig` if the path is not UTF-8 or empty.
pub unsafe fn nsurl_from_path_pub(path: &Path) -> Result<*mut Object, VZError> {
    unsafe { nsurl_from_path(path) }
}

// ── GuestOs enum ─────────────────────────────────────────────────────────────

/// Discriminant for VM guest OS type — selects the VZ boot path at creation time.
///
/// Decision 1 from research.md:
/// - `Linux`: `VZEFIBootLoader` + `VZGenericPlatformConfiguration`
/// - `MacOS`: `VZMacOSBootLoader` + `VZMacPlatformConfiguration`
#[derive(Debug, Clone)]
pub enum GuestOs {
    /// Linux ARM64 guest (Ubuntu) via `VZEFIBootLoader`.
    Linux {
        /// Path to the EFI variable store (`.nvram`).
        efi_store: PathBuf,
        /// Path to the cloud-init cidata ISO.
        cidata_iso: PathBuf,
    },
    /// macOS guest via `VZMacOSBootLoader` + `VZMacPlatformConfiguration`.
    MacOS {
        /// Path to the `VZMacAuxiliaryStorage` file (~1 MB, acts as NVRAM).
        aux_storage: PathBuf,
        /// Raw bytes of `VZMacHardwareModel.dataRepresentation` from the IPSW install.
        hardware_model_data: Vec<u8>,
    },
}

// ── VZMacOSVmConfigurationBuilder ─────────────────────────────────────────────

/// Assembles a `VZVirtualMachineConfiguration` for a **macOS guest** VM.
///
/// Uses `VZMacOSBootLoader` + `VZMacPlatformConfiguration` (Decision 1 from research.md).
/// Storage and network devices are the same as the Linux path (virtio-blk + VZ NAT).
pub struct VZMacOSVmConfigurationBuilder {
    pub cpus: u32,
    pub memory_mb: u32,
    /// Path to per-instance raw disk image (APFS CoW clone of macOS base).
    pub disk_path: PathBuf,
    /// Path to `VZMacAuxiliaryStorage` file (~1 MB `.auxstorage`).
    pub aux_storage_path: PathBuf,
    /// Raw `VZMacHardwareModel` data (from IPSW install, stored base64 in init-state.json).
    pub hardware_model_data: Vec<u8>,
    /// Optional raw `VZMacMachineIdentifier` data (ECID) to reuse.
    ///
    /// When `Some`, the stored ECID is used via `initWithDataRepresentation:` instead of
    /// generating a fresh random ECID. Required for snapshot restore — VZ 26 enforces that
    /// the VM config ECID must match the ECID embedded in the snapshot state.
    /// When `None`, a fresh ECID is generated (suitable only for first-boot cold path).
    pub machine_identifier_data: Option<Vec<u8>>,
    /// Optional MAC address to reuse (colon-separated hex string).
    ///
    /// When set, the VM is assigned this specific MAC so it gets the same DHCP lease
    /// across reboots (e.g. first boot → fix_sshd → second boot in create_base_snapshot).
    /// When empty, a random locally-administered MAC is generated.
    pub mac_address_override: String,
}

impl VZMacOSVmConfigurationBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cpus: 4,
            memory_mb: 4096,
            disk_path: PathBuf::new(),
            aux_storage_path: PathBuf::new(),
            hardware_model_data: Vec::new(),
            machine_identifier_data: None,
            mac_address_override: String::new(),
        }
    }

    #[must_use]
    pub fn cpus(mut self, cpus: u32) -> Self {
        self.cpus = cpus;
        self
    }

    #[must_use]
    pub fn memory_mb(mut self, memory_mb: u32) -> Self {
        self.memory_mb = memory_mb;
        self
    }

    #[must_use]
    pub fn disk_path(mut self, path: PathBuf) -> Self {
        self.disk_path = path;
        self
    }

    #[must_use]
    pub fn aux_storage_path(mut self, path: PathBuf) -> Self {
        self.aux_storage_path = path;
        self
    }

    #[must_use]
    pub fn hardware_model_data(mut self, data: Vec<u8>) -> Self {
        self.hardware_model_data = data;
        self
    }

    /// Set the `VZMacMachineIdentifier` data (ECID) to reuse.
    ///
    /// Pass the bytes previously stored via `VZVirtualMachineConfiguration::machine_identifier_data`.
    /// Required when restoring a VZ snapshot — the ECID in the config must match the snapshot's ECID.
    #[must_use]
    pub fn machine_identifier_data(mut self, data: Vec<u8>) -> Self {
        self.machine_identifier_data = Some(data);
        self
    }

    /// Set a specific MAC address (colon-separated hex) instead of generating a random one.
    #[must_use]
    pub fn mac_address(mut self, mac: String) -> Self {
        self.mac_address_override = mac;
        self
    }

    /// Build the `VZVirtualMachineConfiguration` for a macOS guest.
    ///
    /// # Errors
    ///
    /// Returns `VZError::InvalidConfig` if paths are missing, values out of range,
    /// or `validateWithError:` fails.
    pub fn build(self) -> Result<VZVirtualMachineConfiguration, VZError> {
        if self.cpus < 1 || self.cpus > 8 {
            return Err(VZError::InvalidConfig(format!(
                "CPU count must be 1–8, got {}",
                self.cpus
            )));
        }
        // macOS guests need at least 2 GB RAM
        if self.memory_mb < 2048 || self.memory_mb > 32768 {
            return Err(VZError::InvalidConfig(format!(
                "Memory must be 2048–32768 MB for macOS guest, got {}",
                self.memory_mb
            )));
        }
        if !self.disk_path.exists() {
            return Err(VZError::InvalidConfig(format!(
                "macOS disk not found: {}",
                self.disk_path.display()
            )));
        }
        if self.hardware_model_data.is_empty() {
            return Err(VZError::InvalidConfig(
                "hardware_model_data is empty — run init-macos-guest first".into(),
            ));
        }
        // SAFETY: all ObjC calls use class!/msg_send! macros; objects retained until
        // transferred to VZVirtualMachineConfiguration.
        unsafe { self.build_inner() }
    }

    #[allow(clippy::too_many_lines)]
    unsafe fn build_inner(self) -> Result<VZVirtualMachineConfiguration, VZError> {
        let cpus = self.cpus;
        let memory_bytes: u64 = u64::from(self.memory_mb) * 1024 * 1024;

        // ── Hardware model from stored data ──────────────────────────────────
        // SAFETY: NSData initWithBytes:length: copies the bytes.
        let hw_data: *mut Object = {
            let cls = class!(NSData);
            let ptr = self.hardware_model_data.as_ptr();
            let len = self.hardware_model_data.len();
            msg_send![cls, dataWithBytes: ptr length: len]
        };
        // macOS 26 changed `initWithDataRepresentation:error:` (throws) to
        // `initWithDataRepresentation:` (failable init, returns nil on failure).
        let hw_model: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZMacHardwareModel), alloc];
            msg_send![alloc, initWithDataRepresentation: hw_data]
        };
        if hw_model.is_null() {
            return Err(VZError::InvalidConfig(
                "VZMacHardwareModel from stored data is nil — base image may be corrupt".into(),
            ));
        }

        // ── VZMacAuxiliaryStorage ────────────────────────────────────────────
        let aux_url = unsafe { nsurl_from_path(&self.aux_storage_path)? };
        let aux_storage: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZMacAuxiliaryStorage), alloc];
            msg_send![alloc, initWithURL: aux_url]
        };

        // ── Platform: VZMacPlatformConfiguration ─────────────────────────────
        // Use the stored ECID when provided (required for snapshot restore — VZ 26 requires
        // the restore VM to have the identical ECID as when the snapshot was saved).
        // When None, generate a fresh ECID (suitable for first-boot cold path only).
        let machine_id: *mut Object = if let Some(ref id_bytes) = self.machine_identifier_data {
            let ns_data: *mut Object = {
                let cls = class!(NSData);
                let ptr = id_bytes.as_ptr();
                let len = id_bytes.len();
                msg_send![cls, dataWithBytes: ptr length: len]
            };
            let alloc: *mut Object = msg_send![class!(VZMacMachineIdentifier), alloc];
            let id_obj: *mut Object = msg_send![alloc, initWithDataRepresentation: ns_data];
            if id_obj.is_null() {
                return Err(VZError::InvalidConfig(
                    "VZMacMachineIdentifier from stored data is nil — init-state.json may be corrupt".into(),
                ));
            }
            id_obj
        } else {
            let alloc: *mut Object = msg_send![class!(VZMacMachineIdentifier), alloc];
            msg_send![alloc, init]
        };
        // Extract the ECID bytes so callers can persist them for later snapshot restores.
        // SAFETY: `dataRepresentation` returns a retained NSData; bytes/length are valid
        // for the lifetime of the NSData object, which outlives this function.
        let machine_id_data: Vec<u8> = {
            let ns_data: *mut Object = msg_send![machine_id, dataRepresentation];
            if ns_data.is_null() {
                Vec::new()
            } else {
                let len: usize = msg_send![ns_data, length];
                let bytes: *const u8 = msg_send![ns_data, bytes];
                // SAFETY: `bytes` and `len` come from a valid NSData object.
                unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec()
            }
        };
        let platform: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZMacPlatformConfiguration), alloc];
            let p: *mut Object = msg_send![alloc, init];
            let _: () = msg_send![p, setHardwareModel: hw_model];
            let _: () = msg_send![p, setAuxiliaryStorage: aux_storage];
            let _: () = msg_send![p, setMachineIdentifier: machine_id];
            p
        };

        // ── Boot: VZMacOSBootLoader ──────────────────────────────────────────
        let boot_loader: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZMacOSBootLoader), alloc];
            msg_send![alloc, init]
        };

        // ── Storage: VirtioBlock disk with OS page-cache enabled ─────────────
        // VZDiskImageCachingModeCached (2) lets the host OS cache disk reads in
        // its page cache.  The default `initWithURL:readOnly:error:` silently
        // uses VZDiskImageCachingModeUncached (1), which bypasses the page
        // cache and causes catastrophically slow small-block random reads during
        // SSV sealing (2–4 h observed).  With cached mode the repeated read
        // passes of the Merkle hash verification are served from RAM, cutting
        // SSV sealing from hours to ~10–20 min.
        //
        // VZDiskImageSynchronizationModeFull (1): writes are still fsync'd so
        // the base image stays durable even if the process is killed mid-init.
        let disk_url = unsafe { nsurl_from_path(&self.disk_path)? };
        let mut disk_err: *mut Object = std::ptr::null_mut();
        let disk_attach: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZDiskImageStorageDeviceAttachment), alloc];
            // VZDiskImageCachingModeCached = 2, VZDiskImageSynchronizationModeFull = 1
            // (confirmed via Swift: VZDiskImageCachingMode.cached.rawValue == 2,
            //  VZDiskImageSynchronizationMode.full.rawValue == 1)
            msg_send![alloc,
                initWithURL: disk_url
                readOnly: false
                cachingMode: 2isize
                synchronizationMode: 1isize
                error: &mut disk_err
            ]
        };
        if disk_attach.is_null() {
            let msg = unsafe { nserror_message(disk_err) };
            return Err(VZError::InvalidConfig(format!(
                "Cannot attach macOS disk '{}': {msg}",
                self.disk_path.display()
            )));
        }
        let disk_storage: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZVirtioBlockDeviceConfiguration), alloc];
            msg_send![alloc, initWithAttachment: disk_attach]
        };

        // ── Network: VZNATNetworkDeviceAttachment ─────────────────────────────
        let nat_attach: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZNATNetworkDeviceAttachment), alloc];
            msg_send![alloc, init]
        };
        // Use override MAC if set, otherwise generate a random one.
        let mac_obj: *mut Object = if self.mac_address_override.is_empty() {
            msg_send![class!(VZMACAddress), randomLocallyAdministeredAddress]
        } else {
            let mac_cstr = std::ffi::CString::new(self.mac_address_override.as_str()).unwrap();
            let nsstr: *mut Object = msg_send![class!(NSString),
                stringWithUTF8String: mac_cstr.as_ptr()];
            let alloc: *mut Object = msg_send![class!(VZMACAddress), alloc];
            msg_send![alloc, initWithString: nsstr]
        };
        let mac_nsstring: *mut Object = msg_send![mac_obj, string];
        let mac_cstr: *const std::os::raw::c_char = msg_send![mac_nsstring, UTF8String];
        let mac_address_str = if mac_cstr.is_null() {
            String::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(mac_cstr) }
                .to_string_lossy()
                .to_lowercase()
        };
        let net_dev: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZVirtioNetworkDeviceConfiguration), alloc];
            let dev: *mut Object = msg_send![alloc, init];
            let _: () = msg_send![dev, setAttachment: nat_attach];
            let _: () = msg_send![dev, setMACAddress: mac_obj];
            dev
        };

        // ── Serial console: /dev/null or log file if THEYOS_MACOS_SERIAL_LOG is set ──
        let serial_attach: *mut Object = {
            use std::os::unix::io::IntoRawFd;
            let alloc: *mut Object = msg_send![class!(VZFileHandleSerialPortAttachment), alloc];
            let dev_null_rd = std::fs::File::open("/dev/null")
                .map_err(|e| VZError::Internal(format!("open /dev/null read: {e}")))?;
            // Write serial output to a log file if THEYOS_MACOS_SERIAL_LOG is set (for debugging).
            let serial_log = std::env::var("THEYOS_MACOS_SERIAL_LOG")
                .ok()
                .filter(|p| !p.is_empty());
            let dev_null_wr = if let Some(ref log_path) = serial_log {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log_path)
                    .map_err(|e| VZError::Internal(format!("open serial log {log_path}: {e}")))?
            } else {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/null")
                    .map_err(|e| VZError::Internal(format!("open /dev/null write: {e}")))?
            };
            // Use initWithFileDescriptor:closeOnDealloc: instead of the deprecated
            // fileHandleWithDescriptor: which throws NSInvalidArgumentException on macOS 26+.
            let rd_nsfile: *mut Object = {
                let a: *mut Object = msg_send![class!(NSFileHandle), alloc];
                msg_send![a, initWithFileDescriptor: dev_null_rd.into_raw_fd() closeOnDealloc: true]
            };
            let wr_nsfile: *mut Object = {
                let a: *mut Object = msg_send![class!(NSFileHandle), alloc];
                msg_send![a, initWithFileDescriptor: dev_null_wr.into_raw_fd() closeOnDealloc: true]
            };
            msg_send![alloc,
                initWithFileHandleForReading: rd_nsfile
                fileHandleForWriting: wr_nsfile
            ]
        };
        let serial_port: *mut Object = {
            let alloc: *mut Object =
                msg_send![class!(VZVirtioConsoleDeviceSerialPortConfiguration), alloc];
            let port: *mut Object = msg_send![alloc, init];
            let _: () = msg_send![port, setAttachment: serial_attach];
            port
        };

        // ── Entropy ──────────────────────────────────────────────────────────
        let entropy: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZVirtioEntropyDeviceConfiguration), alloc];
            msg_send![alloc, init]
        };

        // ── Graphics (virtual display, required even in headless mode) ────────
        // macOS initializes its display subsystem during boot regardless of whether
        // a window is shown to the user. Without a VZMacGraphicsDeviceConfiguration,
        // macOS 13+ hangs at ~100% CPU for hours before networking starts — the OS
        // waits for a display framebuffer that never appears.
        // We configure a minimal virtual display (1920×1080) that is not rendered
        // to any real screen; it satisfies the macOS boot requirement without overhead.
        let display_cfg: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZMacGraphicsDisplayConfiguration), alloc];
            msg_send![alloc,
                initWithWidthInPixels: 1920usize
                heightInPixels: 1080usize
                pixelsPerInch: 80usize
            ]
        };
        let graphics_device: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZMacGraphicsDeviceConfiguration), alloc];
            let dev: *mut Object = msg_send![alloc, init];
            let disp_array = unsafe { build_ns_array(&[display_cfg]) };
            let _: () = msg_send![dev, setDisplays: disp_array];
            dev
        };

        // ── Assemble VZVirtualMachineConfiguration ────────────────────────────
        let config_obj: *mut Object = {
            let alloc: *mut Object = msg_send![class!(VZVirtualMachineConfiguration), alloc];
            msg_send![alloc, init]
        };

        let _: () = msg_send![config_obj, setCPUCount: cpus as usize];
        let _: () = msg_send![config_obj, setMemorySize: memory_bytes];
        let _: () = msg_send![config_obj, setPlatform: platform];
        let _: () = msg_send![config_obj, setBootLoader: boot_loader];

        let storage_array = unsafe { build_ns_array(&[disk_storage]) };
        let _: () = msg_send![config_obj, setStorageDevices: storage_array];

        let network_array = unsafe { build_ns_array(&[net_dev]) };
        let _: () = msg_send![config_obj, setNetworkDevices: network_array];

        let serial_array = unsafe { build_ns_array(&[serial_port]) };
        let _: () = msg_send![config_obj, setSerialPorts: serial_array];

        let entropy_array = unsafe { build_ns_array(&[entropy]) };
        let _: () = msg_send![config_obj, setEntropyDevices: entropy_array];

        let graphics_array = unsafe { build_ns_array(&[graphics_device]) };
        let _: () = msg_send![config_obj, setGraphicsDevices: graphics_array];

        // Note: validateWithError: throws an ObjC exception on macOS 26 from Rust context.
        // Validation is implicitly performed by VZVirtualMachine initWithConfiguration:queue:.

        Ok(VZVirtualMachineConfiguration {
            inner: config_obj,
            cpus,
            memory_mb: self.memory_mb,
            mac_address: mac_address_str,
            machine_identifier_data: machine_id_data,
        })
    }
}

impl Default for VZMacOSVmConfigurationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_disk_space_temp_dir() {
        let temp_dir = std::env::temp_dir();
        assert!(check_disk_space(&temp_dir).is_ok());
    }

    #[test]
    fn test_check_disk_space_nonexistent() {
        let nonexistent = PathBuf::from("/nonexistent/path/that/does/not/exist");
        assert!(check_disk_space(&nonexistent).is_err());
    }

    // ── VZ supportability preflight (P5) ──────────────────────────────────────

    #[test]
    fn evaluate_vz_supportability_ok_when_supported() {
        assert!(evaluate_vz_supportability(|| true).is_ok());
    }

    #[test]
    fn evaluate_vz_supportability_failclosed_when_unsupported() {
        let err = evaluate_vz_supportability(|| false).expect_err("must fail closed");
        assert!(matches!(err, VZError::VirtualizationUnsupported(_)));
    }

    #[test]
    fn diagnose_vm_init_nil_supported_is_config_error() {
        // VZ available + nil init ⇒ an invalid-config diagnostic, not "unsupported".
        assert!(matches!(
            diagnose_vm_init_nil(true),
            VZError::VirtualizationError(_)
        ));
    }

    #[test]
    fn diagnose_vm_init_nil_unsupported_is_unsupported_error() {
        assert!(matches!(
            diagnose_vm_init_nil(false),
            VZError::VirtualizationUnsupported(_)
        ));
    }

    /// The VZ-unsupported diagnostic should use the terminal, honest
    /// virtualization-unavailable code. A nil VM init while VZ is supported
    /// remains a generic config diagnostic and must not become a user-facing
    /// supportability failure.
    #[test]
    fn vz_diagnostics_classify_supportability_without_overclassifying_config() {
        use core_rs::guest_image_failure::GuestImageFailureCode;

        let unsupported = evaluate_vz_supportability(|| false)
            .expect_err("fail closed")
            .to_string();
        assert_eq!(
            GuestImageFailureCode::classify(None, &unsupported),
            GuestImageFailureCode::VirtualizationUnavailable,
            "VZ-unsupported must classify as the terminal supportability code"
        );

        let config = diagnose_vm_init_nil(true).to_string();
        assert_eq!(
            GuestImageFailureCode::classify(None, &config),
            GuestImageFailureCode::Unknown,
            "nil-while-supported config diagnostic must classify as Unknown"
        );
    }

    #[test]
    fn test_vm_state_from_isize() {
        assert_eq!(VmState::from(0), VmState::Stopped);
        assert_eq!(VmState::from(1), VmState::Running);
        assert_eq!(VmState::from(2), VmState::Paused);
        assert_eq!(VmState::from(3), VmState::Error);
        assert_eq!(VmState::from(99), VmState::Unknown);
    }

    #[test]
    fn test_config_builder_new_defaults() {
        let b = VZVirtualMachineConfigurationBuilder::new();
        assert_eq!(b.cpus, 2);
        assert_eq!(b.memory_mb, 2048);
    }

    #[test]
    fn test_config_builder_invalid_cpus() {
        let result = VZVirtualMachineConfigurationBuilder::new()
            .cpus(0)
            .disk_path(PathBuf::from("/tmp/test.raw"))
            .efi_store_path(PathBuf::from("/tmp/test.nvram"))
            .cidata_iso_path(PathBuf::from("/tmp/test.iso"))
            .build();
        let err = result.err().expect("should fail with invalid CPUs");
        assert!(err.to_string().contains("CPU count"));
    }

    #[test]
    fn test_config_builder_invalid_memory() {
        let result = VZVirtualMachineConfigurationBuilder::new()
            .memory_mb(100)
            .disk_path(PathBuf::from("/tmp/test.raw"))
            .efi_store_path(PathBuf::from("/tmp/test.nvram"))
            .cidata_iso_path(PathBuf::from("/tmp/test.iso"))
            .build();
        let err = result.err().expect("should fail with invalid memory");
        assert!(err.to_string().contains("Memory"));
    }

    #[test]
    fn test_config_builder_missing_disk() {
        let result = VZVirtualMachineConfigurationBuilder::new()
            .disk_path(PathBuf::from("/nonexistent/disk.raw"))
            .efi_store_path(PathBuf::from("/tmp/test.nvram"))
            .cidata_iso_path(PathBuf::from("/tmp/test.iso"))
            .build();
        let err = result.err().expect("should fail with missing disk");
        assert!(err.to_string().contains("Disk image not found"));
    }

    /// P4 fail-closed guard: the warm-pool clone path (`boot_warm_pool_vm`) must
    /// run `check_disk_space` BEFORE the `cp -c` clone, so an over-full target
    /// volume is refused before any copy. This is a source-text scan because the
    /// function needs VZ + a real base image to drive (out of scope for unit
    /// tests); `check_disk_space`'s own fail-closed behaviour is covered above.
    #[test]
    fn warm_pool_clone_checks_disk_space_before_cp() {
        let src = include_str!("bin/vmrunner_macos_ipc_macos.rs");
        let start = src
            .find("async fn boot_warm_pool_vm")
            .expect("boot_warm_pool_vm present");
        let after = &src[start..];
        // Bound the scan to the function body (up to the next top-level fn).
        let end = after[1..]
            .find("\nasync fn ")
            .or_else(|| after[1..].find("\nfn "))
            .map_or(after.len(), |i| i + 1);
        let body = &after[..end];

        let check = body
            .find("check_disk_space")
            .expect("warm-pool clone must call check_disk_space");
        let cp = body
            .find("Command::new(\"cp\")")
            .expect("warm-pool clone uses `cp` to copy the base image");
        assert!(
            check < cp,
            "check_disk_space must run BEFORE the cp clone (fail-closed)"
        );
    }

    /// P5b: every macOS-VZ admission `reserve()` MUST be preceded by a
    /// `preflight_vz_supportability()` fail-closed gate, so an unsupportable host
    /// is refused before any lease / VM work. Source-text scan because the IPC
    /// handlers need real VZ to drive (out of scope for unit tests); the seam /
    /// classify behaviour is unit-tested above. A NEW reserve site without a
    /// preflight — or a changed reserve count — fails this guard.
    #[test]
    fn every_macos_vz_reserve_is_gated_by_supportability_preflight() {
        fn preceding(src: &str, idx: usize, lines: usize) -> &str {
            let head = &src[..idx];
            let start = head
                .match_indices('\n')
                .rev()
                .nth(lines)
                .map_or(0, |(i, _)| i);
            &src[start..idx]
        }

        let sources = [
            (
                include_str!("bin/vmrunner_macos_ipc_macos.rs"),
                "vmrunner_macos_ipc_macos.rs",
            ),
            (include_str!("macos_guest.rs"), "macos_guest.rs"),
        ];
        // The admission reserve is macOS-VZ only (Linux paths carry no lease).
        let needles = [
            ".reserve(VmKind::",
            ".reserve(crate::vm_admission::VmKind::",
        ];
        let mut total = 0usize;
        for (src, file) in sources {
            // Production code only — drop the in-file #[cfg(test)] module(s).
            let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
            for needle in needles {
                let mut from = 0usize;
                while let Some(rel) = prod[from..].find(needle) {
                    let idx = from + rel;
                    from = idx + needle.len();
                    assert!(
                        preceding(prod, idx, 20).contains("preflight_vz_supportability"),
                        "{file}: a `{needle}` reserve near byte {idx} is not preceded \
                         (within 20 lines) by preflight_vz_supportability() — every \
                         macOS-VZ start must fail closed on VZ supportability before \
                         reserving a slot"
                    );
                    total += 1;
                }
            }
        }
        assert_eq!(
            total, 7,
            "expected 7 macOS-VZ reserve sites each gated by a supportability \
             preflight; found {total}. A reserve site was added or removed — \
             re-confirm each macOS-VZ path preflights before reserve, then update \
             this count."
        );
    }
}
