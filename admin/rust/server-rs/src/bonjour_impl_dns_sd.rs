//! macOS-native mDNS backend over Apple's `dns_sd.h` system bridge.
//!
//! The pure-Rust `mdns-sd` crate binds UDP 5353 alongside macOS's
//! `mDNSResponder` daemon via `SO_REUSEPORT`; the resulting publisher
//! announces never propagate to the system mDNS cache (T046 hardware
//! walkthrough on 2026-05-08, see
//! `docs/followup-mdns-sd-macos-publisher.md`). This module routes
//! through `mDNSResponder` instead, sharing its socket the way Apple's
//! `NSNetService` and `NWBrowser` do.
//!
//! Public surface mirrors `bonjour_impl_mdns_sd.rs` so the facade in
//! `bonjour_publisher.rs` / `bonjour_browser.rs` can `cfg`-gate between
//! the two impls (B-3) without changing call sites.
//!
//! ## Design
//!
//! Each registration owns a `DNSServiceRef` (an opaque connection to
//! `mDNSResponder`) plus a dedicated pump thread that calls
//! `DNSServiceProcessResult` in a blocking loop. The pump thread keeps
//! the daemon connection alive — without it, `mDNSResponder` will
//! disconnect after its idle timeout. `DNSServiceRefDeallocate` from
//! another thread cancels the in-flight read; the pump thread observes
//! the resulting error and exits cleanly.
//!
//! ## Safety
//!
//! All FFI types are wrapped in RAII handles (`SdRefHandle`,
//! `TxtRecordBuilder`) so the C resources are deterministically freed
//! on drop. Raw pointers never escape this module.
//!
//! Per the dns_sd.h contract a single `DNSServiceRef` is **not** safe
//! for concurrent operations from multiple threads, but
//! `DNSServiceRefDeallocate` IS safe to call from a different thread
//! than the one running `DNSServiceProcessResult` — that's exactly the
//! shutdown pattern this module relies on.

#![allow(
    unsafe_code,
    // FFI wrapper module: the system-header names (`dns_sd.h`,
    // `DNSServiceRef`, etc.) appear in nearly every doc comment as
    // prose; backticking each one repeatedly hurts readability more
    // than it helps and would not be enforced on the matching Linux
    // backend.
    clippy::doc_markdown,
    // Internal helpers panic only on `Mutex` poisoning — by design we
    // would rather propagate that than swallow it, and adding a
    // `# Panics` block to every method that takes a lock is noise.
    clippy::missing_panics_doc
)]

use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tracing::{info, warn};

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    clippy::all,
    clippy::pedantic
)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/dns_sd_bindings.rs"));
}

const KDNS_SERVICE_ERR_NO_ERROR: ffi::DNSServiceErrorType = 0;
const KDNS_SERVICE_FLAGS_NONE: ffi::DNSServiceFlags = 0;
const KDNS_SERVICE_INTERFACE_INDEX_ANY: u32 = 0;
// Re-exported as plain u32/u32 to avoid sprinkling `ffi::` casts at call sites.
const KDNS_SERVICE_FLAG_ADD: ffi::DNSServiceFlags =
    ffi::kDNSServiceFlagsAdd as ffi::DNSServiceFlags;
const KDNS_SERVICE_FLAG_MORE_COMING: ffi::DNSServiceFlags =
    ffi::kDNSServiceFlagsMoreComing as ffi::DNSServiceFlags;
const KDNS_SERVICE_PROTOCOL_IPV4: ffi::DNSServiceProtocol =
    ffi::kDNSServiceProtocol_IPv4 as ffi::DNSServiceProtocol;
const KDNS_SERVICE_PROTOCOL_IPV6: ffi::DNSServiceProtocol =
    ffi::kDNSServiceProtocol_IPv6 as ffi::DNSServiceProtocol;

// ─────────────────────── public API (mirrors mdns-sd backend) ──────────────

/// Backend-specific error type. Mirrors the shape of
/// `bonjour_impl_mdns_sd::BackendError` so the facade compiles
/// identically against either backend.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("dns_sd error code {0}")]
    DnsSd(ffi::DNSServiceErrorType),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("TXT record too large ({size} bytes; max {max})")]
    TxtTooLarge { size: usize, max: usize },
}

impl BackendError {
    fn from_code(code: ffi::DNSServiceErrorType) -> Self {
        Self::DnsSd(code)
    }
}

/// Description of a single service registration. Shape-identical to
/// `bonjour_impl_mdns_sd::ServiceSpec`.
pub struct ServiceSpec<'a> {
    pub service_type: &'a str,
    pub instance: &'a str,
    pub host: &'a str,
    pub ip: IpAddr,
    pub port: u16,
    pub txt: &'a HashMap<String, String>,
}

/// Outcome of `unregister_and_wait`. Same enum as the Linux backend's.
#[derive(Debug)]
pub enum UnregisterOutcome {
    Ok,
    NotFound,
    Failed(String),
    TimedOut,
}

/// Outcome of `shutdown_and_wait`. Same enum as the Linux backend's.
#[derive(Debug)]
pub enum ShutdownOutcome {
    Ok,
    Failed(String),
    Unexpected(String),
    TimedOut,
}

/// Publisher daemon handle. Cheap to clone — internal state is shared
/// behind an `Arc`.
#[derive(Clone)]
pub struct PublisherHandle {
    inner: Arc<PublisherInner>,
}

struct PublisherInner {
    services: Mutex<HashMap<String, RegisteredService>>,
}

/// One live registration — owns its DNSServiceRef and pump thread. The
/// `shutdown_pipe`'s read end is used by the pump to wake out of
/// `select(2)`; the write end is used by `drop_service` to signal exit
/// before joining the pump and (after join) deallocating the ref.
struct RegisteredService {
    sd_ref: SdRefHandle,
    pump: Option<JoinHandle<()>>,
    shutdown_pipe: ShutdownPipe,
}

impl PublisherHandle {
    pub fn new() -> Result<Self, BackendError> {
        Ok(Self {
            inner: Arc::new(PublisherInner {
                services: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// Register `spec` with `mDNSResponder`. The returned fullname is the
    /// pre-computed string assembled from `spec.instance`,
    /// `spec.service_type`, and the local domain — the facade uses it as
    /// the unregister key. mDNSResponder may assign an alternate name on
    /// conflict; we log the actual name from the callback for
    /// observability but the unregister-by-fullname API stays stable.
    pub fn register(&self, spec: &ServiceSpec<'_>) -> Result<String, BackendError> {
        let txt = TxtBuffer::build(spec.txt)?;
        let instance_c = CString::new(spec.instance)
            .map_err(|e| BackendError::InvalidArgument(format!("instance: {e}")))?;
        // dns_sd.h's `regtype` parameter wants `_service._proto` only.
        // The facade hands us the mdns-sd-style `_service._proto.local.`
        // (or `.local`), so strip both trailing dots and the `.local`
        // domain segment.
        let regtype_c = CString::new(normalize_regtype(spec.service_type))
            .map_err(|e| BackendError::InvalidArgument(format!("service_type: {e}")))?;
        // `host` argument: passing NULL lets mDNSResponder use the
        // local hostname, which is what Apple recommends for ordinary
        // services. Our `spec.host` is informational only on this
        // backend; we ignore it here and use NULL.
        let host_c: Option<CString> = None;

        // Predicted fullname. Constructed identically to mdns-sd so a
        // caller that stored a fullname against this backend can unregister
        // against either implementation.
        let fullname = format!(
            "{}.{}",
            spec.instance,
            spec.service_type.trim_start_matches('.')
        );

        // SAFETY: we pass a leaked Box pointer as the C callback context.
        // It's reclaimed when the registration is dropped (see
        // `RegisteredService::drop_pieces` below).
        let context = Box::into_raw(Box::new(RegisterContext {
            requested_fullname: fullname.clone(),
        }));

        let mut sd_ref: ffi::DNSServiceRef = ptr::null_mut();
        let sd_ref_out = ptr::addr_of_mut!(sd_ref);
        // SAFETY: All `*const c_char` pointers are valid until end of fn
        // (CStrings live on the stack here). `txt.as_ptr()` is valid for
        // `txt.len()` bytes. dns_sd.h copies the txt buffer internally
        // before returning, so we can drop `txt` after the call.
        let err = unsafe {
            ffi::DNSServiceRegister(
                sd_ref_out,
                KDNS_SERVICE_FLAGS_NONE,
                KDNS_SERVICE_INTERFACE_INDEX_ANY,
                instance_c.as_ptr(),
                regtype_c.as_ptr(),
                ptr::null(), // domain: NULL => use default ("local.")
                host_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                spec.port.to_be(), // dns_sd.h wants network byte order
                txt.len(),
                txt.as_ptr(),
                Some(register_reply),
                context.cast::<c_void>(),
            )
        };
        if err != KDNS_SERVICE_ERR_NO_ERROR {
            // SAFETY: context was just leaked; reclaim and drop.
            unsafe { drop(Box::from_raw(context)) };
            return Err(BackendError::from_code(err));
        }

        // Spawn the pump thread that drains daemon events for this ref.
        // The pump exits when its shutdown pipe is signalled; the spawning
        // side then joins and only afterwards deallocates the ref. That
        // ordering avoids a libdispatch teardown race that would otherwise
        // crash inside `DNSServiceProcessResult` on shutdown — see
        // `docs/followup-dns-sd-test-teardown-signal.md`.
        let sd_handle = SdRefHandle::new(sd_ref);
        let shutdown_pipe = ShutdownPipe::new().inspect_err(|_| {
            // SAFETY: ref was just successfully created and no other
            // thread holds it.
            unsafe { ffi::DNSServiceRefDeallocate(sd_handle.raw) };
            // SAFETY: context just leaked; reclaim and drop.
            unsafe { drop(Box::from_raw(context)) };
        })?;
        let pump_ref = SendableSdRef(sd_handle.raw);
        let pump_shutdown_fd = shutdown_pipe.read_fd;
        let pump = thread::Builder::new()
            .name(format!("dns_sd_pump_register[{fullname}]"))
            .spawn(move || {
                // Bind the whole `SendableSdRef` into a local so the
                // closure captures the Send wrapper rather than just the
                // raw pointer field (precise captures, edition 2021+).
                let captured = pump_ref;
                pump_events(captured.0, pump_shutdown_fd);
            })
            .map_err(|e| BackendError::InvalidArgument(format!("pump thread: {e}")))?;

        let mut services = self.inner.services.lock().expect("services mutex poisoned");
        services.insert(
            fullname.clone(),
            RegisteredService {
                sd_ref: sd_handle,
                pump: Some(pump),
                shutdown_pipe,
            },
        );
        Ok(fullname)
    }

    /// Fire-and-forget unregister. Drops the underlying `DNSServiceRef`
    /// (deallocating it via the system call) and joins the pump thread.
    pub fn unregister(&self, fullname: &str) -> Result<(), BackendError> {
        let mut services = self.inner.services.lock().expect("services mutex poisoned");
        if let Some(svc) = services.remove(fullname) {
            drop_service(svc);
        }
        Ok(())
    }

    /// Unregister and wait — for the dns_sd.h backend the deallocate is
    /// effectively synchronous (the system call returns once the ref is
    /// released), so we always return `Ok` once the join completes within
    /// the budget, or `TimedOut` if joining exceeds `wait`.
    pub async fn unregister_and_wait(&self, fullname: &str, wait: Duration) -> UnregisterOutcome {
        let services_arc = Arc::clone(&self.inner);
        let fullname_owned = fullname.to_string();
        let join_result = tokio::time::timeout(
            wait,
            tokio::task::spawn_blocking(move || {
                let mut services = services_arc
                    .services
                    .lock()
                    .expect("services mutex poisoned");
                services.remove(&fullname_owned)
            }),
        )
        .await;
        match join_result {
            Ok(Ok(Some(svc))) => {
                let svc_drop = tokio::task::spawn_blocking(move || drop_service(svc));
                match tokio::time::timeout(wait, svc_drop).await {
                    Ok(Ok(())) => UnregisterOutcome::Ok,
                    Ok(Err(e)) => UnregisterOutcome::Failed(format!("join: {e}")),
                    Err(_) => UnregisterOutcome::TimedOut,
                }
            }
            Ok(Ok(None)) => UnregisterOutcome::NotFound,
            Ok(Err(e)) => UnregisterOutcome::Failed(format!("lock task: {e}")),
            Err(_) => UnregisterOutcome::TimedOut,
        }
    }

    /// Tear down all live registrations. The dns_sd.h backend has no
    /// "daemon" concept of its own — each registration is a separate
    /// connection — so this drops every entry from the map.
    pub async fn shutdown_and_wait(&self, wait: Duration) -> ShutdownOutcome {
        let services_arc = Arc::clone(&self.inner);
        let join = tokio::task::spawn_blocking(move || {
            let entries: Vec<RegisteredService> = {
                let mut services = services_arc
                    .services
                    .lock()
                    .expect("services mutex poisoned");
                services.drain().map(|(_, svc)| svc).collect()
            };
            for svc in entries {
                drop_service(svc);
            }
        });
        match tokio::time::timeout(wait, join).await {
            Ok(Ok(())) => ShutdownOutcome::Ok,
            Ok(Err(e)) => ShutdownOutcome::Failed(format!("join: {e}")),
            Err(_) => ShutdownOutcome::TimedOut,
        }
    }
}

// ─────────────────────── browser implementation (B-2b) ─────────────────────

/// Browser daemon handle. Each call to `browse` opens a fresh
/// `DNSServiceBrowse` connection to mDNSResponder and spawns a pump
/// thread that drains add/remove events. Add events trigger
/// `DNSServiceResolve` on a per-instance pump thread, which in turn
/// triggers `DNSServiceGetAddrInfo` on its own pump. The chain ends by
/// emitting a `ResolvedService` to the stream's `mpsc` sender.
pub struct BrowserHandle {
    inner: Arc<BrowserInner>,
}

struct BrowserInner {
    /// Live browse refs by `service_type` — used by `stop_browse` and
    /// `shutdown`. The pump thread for each ref is detached; its
    /// `DNSServiceRef` deallocation in `Drop` unblocks the pump.
    browses: Mutex<HashMap<String, BrowseSession>>,
    /// Live in-flight chain refs (resolve + getaddrinfo). Tracked here
    /// so `shutdown` can tear them down deterministically — without this
    /// the chain pumps keep running past the BrowserHandle's drop and
    /// SIGTRAP when mDNSResponder closes the IPC channel under their
    /// feet during process exit.
    chain: Arc<ChainRegistry>,
}

/// Shared registry for in-flight chain operations (resolve, getaddrinfo).
/// Each entry is tagged with a stable `id` so the chain pump can remove
/// itself on natural exit (callback signalled `done`) without colliding
/// with a concurrent `shutdown` that's draining the registry.
#[derive(Default)]
struct ChainRegistry {
    next_id: Mutex<u64>,
    entries: Mutex<HashMap<u64, ChainEntry>>,
}

struct ChainEntry {
    sd_ref: ffi::DNSServiceRef,
    pump: JoinHandle<()>,
    /// Shutdown notifier: drained on forced exit (signal pipe → join
    /// pump → deallocate ref). On natural exit (callback set `done`),
    /// the pump itself deallocates the ref and the pipe is dropped here
    /// without ever firing.
    shutdown_pipe: ShutdownPipe,
}

// SAFETY: same argument as SendableSdRef — the raw DNSServiceRef is
// not used concurrently from multiple threads. The registry only reads
// it to deallocate on shutdown, which dns_sd.h documents as safe from
// any thread.
unsafe impl Send for ChainEntry {}
unsafe impl Sync for ChainEntry {}

impl ChainRegistry {
    fn allocate_id(&self) -> u64 {
        let mut next = self.next_id.lock().expect("chain.next_id poisoned");
        let id = *next;
        *next = next.wrapping_add(1);
        id
    }

    fn insert(&self, id: u64, entry: ChainEntry) {
        let mut entries = self.entries.lock().expect("chain.entries poisoned");
        entries.insert(id, entry);
    }

    /// Remove an entry on natural completion (chain pump exited because
    /// the callback signalled `done`). Returns `Some` if the entry was
    /// still in the registry, `None` if shutdown drained it first.
    fn take(&self, id: u64) -> Option<ChainEntry> {
        let mut entries = self.entries.lock().expect("chain.entries poisoned");
        entries.remove(&id)
    }

    /// Drain the registry on shutdown. The caller deallocates each
    /// `sd_ref` (unblocking its pump) and then joins each pump.
    fn drain(&self) -> Vec<ChainEntry> {
        let mut entries = self.entries.lock().expect("chain.entries poisoned");
        entries.drain().map(|(_, v)| v).collect()
    }
}

/// One live `DNSServiceBrowse` registration. The `shutdown_pipe`'s
/// read end is used by the pump to wake out of `select(2)`; the write
/// end is used by `drop_browse_session` to signal exit before joining
/// the pump and (after join) deallocating the ref.
struct BrowseSession {
    sd_ref: SdRefHandle,
    pump: Option<JoinHandle<()>>,
    shutdown_pipe: ShutdownPipe,
}

impl BrowserHandle {
    pub fn new() -> Result<Self, BackendError> {
        Ok(Self {
            inner: Arc::new(BrowserInner {
                browses: Mutex::new(HashMap::new()),
                chain: Arc::new(ChainRegistry::default()),
            }),
        })
    }

    /// Start browsing `service_type` (mdns-sd-style, e.g.
    /// `_soyeht-household._tcp.local.`). Returns a stream that yields
    /// `ResolvedService` items as the chain
    /// browse → resolve → getaddrinfo completes for each instance.
    pub fn browse(&self, service_type: &str) -> Result<BrowseStream, BackendError> {
        let regtype_norm = normalize_regtype(service_type).to_string();
        let regtype_c = CString::new(regtype_norm.as_str())
            .map_err(|e| BackendError::InvalidArgument(format!("service_type: {e}")))?;

        // Public service-type label echoed into emitted ResolvedService
        // entries (kept in mdns-sd form for facade compatibility).
        let display_service_type = service_type.to_string();

        let (tx, rx) = mpsc::unbounded_channel::<ResolvedService>();

        // SAFETY: The leaked Box pointer is reclaimed on `BrowserInner`
        // teardown via `drop_browse_session`, after the pump thread has
        // joined and mDNSResponder is guaranteed not to invoke the
        // callback again.
        let context = Box::into_raw(Box::new(BrowseContext {
            display_service_type: display_service_type.clone(),
            regtype_normalized: regtype_norm.clone(),
            sender: tx,
            chain: Arc::clone(&self.inner.chain),
        }));

        let mut sd_ref: ffi::DNSServiceRef = ptr::null_mut();
        // SAFETY: All pointers are valid for the call: regtype_c is owned,
        // domain is NULL (which dns_sd.h interprets as "default").
        let err = unsafe {
            ffi::DNSServiceBrowse(
                ptr::addr_of_mut!(sd_ref),
                KDNS_SERVICE_FLAGS_NONE,
                KDNS_SERVICE_INTERFACE_INDEX_ANY,
                regtype_c.as_ptr(),
                ptr::null(),
                Some(browse_reply),
                context.cast::<c_void>(),
            )
        };
        if err != KDNS_SERVICE_ERR_NO_ERROR {
            // SAFETY: context just leaked; reclaim and drop.
            unsafe { drop(Box::from_raw(context)) };
            return Err(BackendError::from_code(err));
        }

        let sd_handle = SdRefHandle::new(sd_ref);
        let shutdown_pipe = ShutdownPipe::new().inspect_err(|_| {
            // SAFETY: ref was just successfully created and no other
            // thread holds it.
            unsafe { ffi::DNSServiceRefDeallocate(sd_handle.raw) };
            // SAFETY: context just leaked; reclaim and drop.
            unsafe { drop(Box::from_raw(context)) };
        })?;
        let pump_ref = SendableSdRef(sd_handle.raw);
        let pump_shutdown_fd = shutdown_pipe.read_fd;
        let pump = thread::Builder::new()
            .name(format!("dns_sd_pump_browse[{regtype_norm}]"))
            .spawn(move || {
                let captured = pump_ref;
                pump_events(captured.0, pump_shutdown_fd);
            })
            .map_err(|e| BackendError::InvalidArgument(format!("pump thread: {e}")))?;

        {
            let mut browses = self.inner.browses.lock().expect("browses mutex poisoned");
            // Replace any prior session for the same type — caller
            // semantically restarted browsing. Drop the old one now.
            if let Some(prev) = browses.insert(
                regtype_norm.clone(),
                BrowseSession {
                    sd_ref: sd_handle,
                    pump: Some(pump),
                    shutdown_pipe,
                },
            ) {
                drop_browse_session(prev);
            }
        }

        info!(
            stage = "dns_sd.browse_started",
            regtype = %regtype_norm,
        );

        Ok(BrowseStream {
            rx: AsyncMutex::new(rx),
        })
    }

    pub fn stop_browse(&self, service_type: &str) {
        let key = normalize_regtype(service_type).to_string();
        let removed = {
            let mut browses = self.inner.browses.lock().expect("browses mutex poisoned");
            browses.remove(&key)
        };
        if let Some(session) = removed {
            drop_browse_session(session);
        }
    }

    pub fn shutdown(&self) {
        // Stop accepting new chain spawns by tearing down browse refs
        // first — that prevents `browse_reply` from firing again with a
        // fresh resolve. Then drain any in-flight chain pumps.
        let drained: Vec<BrowseSession> = {
            let mut browses = self.inner.browses.lock().expect("browses mutex poisoned");
            browses.drain().map(|(_, v)| v).collect()
        };
        for session in drained {
            drop_browse_session(session);
        }
        // Drain in-flight resolve / getaddrinfo pumps. Order: signal
        // the pump's shutdown pipe (so it exits select(2) without
        // entering another DNSServiceProcessResult call), join the
        // pump, then deallocate the ref. Doing it the other way around
        // reintroduces the libdispatch teardown race fixed in
        // `docs/followup-dns-sd-test-teardown-signal.md`.
        //
        // Loop until the registry is stable: a resolve callback can run
        // *after* the resolve pump exits but before we observe the empty
        // registry, spawning a getaddrinfo that lands in the registry
        // after our first drain. Iterate until a drain returns empty.
        loop {
            let batch = self.inner.chain.drain();
            if batch.is_empty() {
                break;
            }
            // Step 1: wake every pump in the batch so they all exit
            // select(2) concurrently — gives us better wall-clock latency
            // than serialised wake-then-join.
            for entry in &batch {
                entry.shutdown_pipe.signal();
            }
            // Step 2: join + deallocate.
            for entry in batch {
                let ChainEntry {
                    sd_ref,
                    pump,
                    shutdown_pipe,
                } = entry;
                if let Err(e) = pump.join() {
                    warn!(stage = "dns_sd.chain_pump_join_failed", error = ?e);
                }
                // Pump has fully exited — safe to deallocate without
                // racing a libdispatch callback dispatch.
                if !sd_ref.is_null() {
                    // SAFETY: the registry's drain transfers ownership
                    // of `sd_ref` to us; pump joined; no other thread
                    // holds it.
                    unsafe { ffi::DNSServiceRefDeallocate(sd_ref) };
                }
                // Drop the pipe explicitly to make the ordering clear
                // (otherwise it would drop at end of scope anyway).
                drop(shutdown_pipe);
            }
            // After joining, any callback that was mid-flight on a
            // joined pump has finished. Late-arriving entries (e.g.
            // getaddrinfo spawned by a just-completed resolve) are now
            // visible in the registry; loop and drain them.
        }
    }
}

impl Drop for BrowserHandle {
    fn drop(&mut self) {
        // Best-effort shutdown of any still-live browse sessions. Safe to
        // call even if `shutdown()` was already invoked: the map will be
        // empty.
        self.shutdown();
    }
}

/// Async stream of resolved services. Wraps an `mpsc::UnboundedReceiver`
/// behind a `tokio::sync::Mutex` so `next(&self)` matches the Linux
/// backend's signature (the facade calls it from inside `tokio::select!`).
pub struct BrowseStream {
    rx: AsyncMutex<mpsc::UnboundedReceiver<ResolvedService>>,
}

impl BrowseStream {
    /// Yield the next resolved service. Returns `None` when all senders
    /// (browse / resolve / getaddrinfo pumps) have dropped — i.e. the
    /// `BrowserHandle` was shut down.
    pub async fn next(&self) -> Option<ResolvedService> {
        let mut guard = self.rx.lock().await;
        guard.recv().await
    }
}

pub struct ResolvedService {
    service_type: String,
    hostname: String,
    txt: HashMap<String, String>,
    addresses: HashSet<IpAddr>,
    port: u16,
}

impl ResolvedService {
    #[must_use]
    pub fn service_type(&self) -> &str {
        &self.service_type
    }

    #[must_use]
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    #[must_use]
    pub fn txt(&self, key: &str) -> Option<&str> {
        self.txt.get(key).map(String::as_str)
    }

    #[must_use]
    pub fn addresses(&self) -> &HashSet<IpAddr> {
        &self.addresses
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

// ─────────────────────── internal helpers ──────────────────────────────────

/// RAII wrapper around `DNSServiceRef` — `DNSServiceRefDeallocate` on drop.
struct SdRefHandle {
    raw: ffi::DNSServiceRef,
}

impl SdRefHandle {
    fn new(raw: ffi::DNSServiceRef) -> Self {
        Self { raw }
    }
}

impl Drop for SdRefHandle {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: dns_sd.h guarantees `DNSServiceRefDeallocate` is
            // safe to call from any thread, even while another thread is
            // blocked in `DNSServiceProcessResult` on the same ref — the
            // blocked call will unblock with an error.
            unsafe { ffi::DNSServiceRefDeallocate(self.raw) };
            self.raw = ptr::null_mut();
        }
    }
}

// SAFETY: dns_sd.h documents `DNSServiceRef` opaque handles as
// thread-portable as long as concurrent operations on the *same* ref are
// serialised. Our usage uses one pump thread per ref, with deallocation
// on a different thread (allowed). Send/Sync are correct.
unsafe impl Send for SdRefHandle {}
unsafe impl Sync for SdRefHandle {}

/// Send-marker wrapper for moving a `DNSServiceRef` into a spawned thread.
/// Same safety argument as `SdRefHandle`: dns_sd.h documents the ref as
/// safe to read from a single thread, and deallocate-from-another-thread
/// is the canonical shutdown pattern.
struct SendableSdRef(ffi::DNSServiceRef);

// SAFETY: see `SdRefHandle` above.
unsafe impl Send for SendableSdRef {}

/// Heap-allocated context passed to the C callback.
struct RegisterContext {
    requested_fullname: String,
}

/// Clean up a registration. Order matters: signal the pump's shutdown
/// pipe FIRST so the pump exits its `select` and stops calling
/// `DNSServiceProcessResult`, then join, and only afterwards deallocate
/// the ref. Doing it any other way reintroduces the libdispatch
/// teardown race documented in
/// `docs/followup-dns-sd-test-teardown-signal.md`.
///
/// Must run on a worker thread (it joins a thread); avoid calling from
/// async contexts unless wrapped in `spawn_blocking`.
fn drop_service(mut svc: RegisteredService) {
    // Wake the pump so it exits select(2) without entering another
    // DNSServiceProcessResult call.
    svc.shutdown_pipe.signal();
    if let Some(handle) = svc.pump.take() {
        if let Err(e) = handle.join() {
            warn!(
                stage = "dns_sd.pump_join_failed",
                error = ?e,
            );
        }
    }
    // Pump has fully exited — safe to deallocate now without racing a
    // libdispatch callback dispatch.
    drop(std::mem::replace(
        &mut svc.sd_ref,
        SdRefHandle::new(ptr::null_mut()),
    ));
    // Note: the RegisterContext leak is reclaimed in register_reply once
    // the C library has finished invoking the callback for this ref.
    // We do NOT reclaim here because mDNSResponder may still hold the
    // pointer between deallocate and the final no-more-callbacks signal.
    // For the v0 implementation we accept the small per-registration leak
    // — a household has O(1) registrations and they live for the daemon
    // process lifetime. Improved cleanup is a B-2 follow-up.
}

/// C callback for `DNSServiceRegister`. Logs the assigned fullname for
/// observability (informational only — the facade addresses
/// registrations by the requested fullname).
extern "C" fn register_reply(
    _sd_ref: ffi::DNSServiceRef,
    _flags: ffi::DNSServiceFlags,
    error_code: ffi::DNSServiceErrorType,
    name: *const c_char,
    regtype: *const c_char,
    domain: *const c_char,
    context: *mut c_void,
) {
    // SAFETY: `context` was set by `register` to a leaked `Box<RegisterContext>`.
    // mDNSResponder may invoke this callback multiple times (e.g., on
    // re-bind events); we only read, never reclaim, so the leak is safe
    // for the lifetime of the registration.
    let ctx = if context.is_null() {
        None
    } else {
        Some(unsafe { &*(context.cast::<RegisterContext>()) })
    };
    let assigned = unsafe { c_str_to_string(name) };
    let regtype = unsafe { c_str_to_string(regtype) };
    let domain = unsafe { c_str_to_string(domain) };
    let requested = ctx.map_or("?", |c| c.requested_fullname.as_str());
    if error_code == KDNS_SERVICE_ERR_NO_ERROR {
        tracing::info!(
            stage = "dns_sd.register_confirmed",
            requested = %requested,
            assigned_name = %assigned,
            assigned_type = %regtype,
            assigned_domain = %domain,
        );
    } else {
        warn!(
            stage = "dns_sd.register_failed",
            requested = %requested,
            error_code,
        );
    }
}

/// Self-pipe used to interrupt a pump thread blocked in `select(2)`
/// without touching the `DNSServiceRef`. Apple's documentation says
/// `DNSServiceRefDeallocate` is safe to call from another thread while
/// a different thread is inside `DNSServiceProcessResult`, but in
/// practice that path occasionally crashes inside
/// `dispatch_channel_cancel` (libdispatch teardown) when the deallocate
/// races a callback dispatch — see `docs/followup-dns-sd-test-teardown-signal.md`.
///
/// The fix: have the pump only enter `DNSServiceProcessResult` when the
/// underlying socket is readable, exit cleanly when the self-pipe gets
/// a wake byte, and let the spawning side deallocate the ref ONLY after
/// the pump has joined. That guarantees deallocate never races a live
/// `DNSServiceProcessResult` call.
struct ShutdownPipe {
    read_fd: c_int,
    write_fd: c_int,
}

impl ShutdownPipe {
    /// Create a non-blocking, close-on-exec self-pipe. Returns the OS
    /// error code on failure (mapped into a `BackendError::DnsSd` for
    /// caller convenience — the value never collides with a dns_sd code
    /// because it is a positive `errno` and dns_sd codes are negative).
    fn new() -> Result<Self, BackendError> {
        let mut fds: [c_int; 2] = [-1, -1];
        // SAFETY: `pipe(2)` writes two valid file descriptors to `fds`
        // on success. The buffer is uninitialised on failure, but we
        // bail out before reading it.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if rc != 0 {
            return Err(BackendError::DnsSd(-1));
        }
        // Set close-on-exec + nonblocking on both ends.
        for fd in fds {
            // SAFETY: fcntl on a freshly-created fd; the GETFL/SETFL
            // pair is the standard pattern from `man fcntl`.
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL, 0);
                if flags >= 0 {
                    libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
                let cflags = libc::fcntl(fd, libc::F_GETFD, 0);
                if cflags >= 0 {
                    libc::fcntl(fd, libc::F_SETFD, cflags | libc::FD_CLOEXEC);
                }
            }
        }
        Ok(Self {
            read_fd: fds[0],
            write_fd: fds[1],
        })
    }

    /// Wake the reader (pump). Idempotent — if the pipe is already full
    /// (`EAGAIN`), the pending byte is enough to unblock `select`.
    fn signal(&self) {
        let byte: u8 = 1;
        // SAFETY: write to a valid fd we own. Errors (EAGAIN if pipe
        // full, EBADF if already closed) are non-fatal: the reader is
        // either already going to wake or has already exited.
        unsafe {
            let _ = libc::write(self.write_fd, ptr::addr_of!(byte).cast::<c_void>(), 1);
        }
    }
}

impl Drop for ShutdownPipe {
    fn drop(&mut self) {
        if self.read_fd >= 0 {
            // SAFETY: closing an fd we own.
            unsafe { libc::close(self.read_fd) };
            self.read_fd = -1;
        }
        if self.write_fd >= 0 {
            // SAFETY: closing an fd we own.
            unsafe { libc::close(self.write_fd) };
            self.write_fd = -1;
        }
    }
}

// SAFETY: the pipe's two fds are read-only/write-only by separate
// threads (pump reads, shutdown writes). Both file descriptors are
// owned by this struct; concurrent read+write on a pipe is documented
// as thread-safe by POSIX.
unsafe impl Send for ShutdownPipe {}
unsafe impl Sync for ShutdownPipe {}

/// Block in `select(2)` on the dns_sd socket and the shutdown pipe.
/// Returns `Ok(true)` if the dns_sd socket is readable (caller should
/// call `DNSServiceProcessResult`), `Ok(false)` if the shutdown pipe
/// fired (caller should exit the pump), or an error if `select` itself
/// failed in a way other than `EINTR`.
///
/// SAFETY: callers must pass valid file descriptors (an fd returned by
/// `DNSServiceRefSockFD` is valid as long as the ref is alive; the
/// shutdown pipe fd is valid as long as `ShutdownPipe` is alive).
fn select_pump_ready(sd_fd: c_int, shutdown_fd: c_int) -> Result<bool, c_int> {
    loop {
        let mut readset = MaybeUninit::<libc::fd_set>::uninit();
        // SAFETY: `FD_ZERO` writes `sizeof(fd_set)` bytes to the buffer.
        unsafe {
            libc::FD_ZERO(readset.as_mut_ptr());
        }
        // SAFETY: readset is now zeroed by FD_ZERO above.
        let mut readset = unsafe { readset.assume_init() };
        // SAFETY: `FD_SET` requires the fd to be in range [0,
        // FD_SETSIZE). dns_sd fds and pipe fds in a test/server process
        // are well below that limit.
        unsafe {
            libc::FD_SET(sd_fd, &raw mut readset);
            libc::FD_SET(shutdown_fd, &raw mut readset);
        }
        let nfds = sd_fd.max(shutdown_fd) + 1;
        // SAFETY: `select` reads readset and writes back the ready set.
        let rc = unsafe {
            libc::select(
                nfds,
                &raw mut readset,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if rc < 0 {
            // SAFETY: `__error()` (libc errno wrapper) is always valid.
            let err = unsafe { *libc::__error() };
            if err == libc::EINTR {
                continue;
            }
            return Err(err);
        }
        // SAFETY: `FD_ISSET` reads the readset populated by `select`.
        let shutdown_ready = unsafe { libc::FD_ISSET(shutdown_fd, &raw const readset) };
        if shutdown_ready {
            return Ok(false);
        }
        // SAFETY: see above.
        let sd_ready = unsafe { libc::FD_ISSET(sd_fd, &raw const readset) };
        if sd_ready {
            return Ok(true);
        }
        // Spurious wakeup — loop.
    }
}

/// Pump loop: drains events from `DNSServiceProcessResult` for one
/// `DNSServiceRef`. Exits when the shutdown pipe is signalled. The
/// caller is expected to deallocate the ref AFTER joining the pump
/// thread — that ordering is what avoids the libdispatch teardown
/// race documented in `docs/followup-dns-sd-test-teardown-signal.md`.
fn pump_events(sd_ref: ffi::DNSServiceRef, shutdown_fd: c_int) {
    // SAFETY: `DNSServiceRefSockFD` returns a stable fd for the
    // lifetime of the ref (per dns_sd.h).
    let sd_fd = unsafe { ffi::DNSServiceRefSockFD(sd_ref) };
    if sd_fd < 0 {
        tracing::debug!(stage = "dns_sd.pump_no_socket", sd_fd);
        return;
    }
    loop {
        match select_pump_ready(sd_fd, shutdown_fd) {
            Ok(true) => {
                // SAFETY: ref is valid until the spawning side joins
                // this thread (and only deallocates after the join).
                let err = unsafe { ffi::DNSServiceProcessResult(sd_ref) };
                if err != KDNS_SERVICE_ERR_NO_ERROR {
                    tracing::debug!(stage = "dns_sd.pump_exit", error_code = err,);
                    break;
                }
            }
            Ok(false) => {
                tracing::debug!(stage = "dns_sd.pump_shutdown_signal");
                break;
            }
            Err(errno) => {
                tracing::debug!(stage = "dns_sd.pump_select_error", errno);
                break;
            }
        }
    }
}

/// Pump loop variant for chain-step refs (resolve, getaddrinfo). The C
/// callback signals chain completion by setting `done` to `true`; the
/// pump observes the flag after each successful `DNSServiceProcessResult`
/// and tears down the ref itself. This avoids the segfault that would
/// happen if the callback deallocated the ref while still running on
/// the pump's stack — the next loop iteration would then call
/// `DNSServiceProcessResult` on a freed ref.
///
/// On natural exit (callback set `done`) the pump removes its entry
/// from the chain registry and deallocates the ref. On forced exit
/// (shutdown pipe signalled) the entry is left in the registry; the
/// drainer then deallocates the ref after joining this thread.
///
/// SAFETY: the ref is owned by exactly one of (this pump, the chain
/// registry's drain). Only one of them deallocates.
fn pump_chain_events(
    sd_ref: ffi::DNSServiceRef,
    done: &Arc<AtomicBool>,
    chain: &Arc<ChainRegistry>,
    id: u64,
    shutdown_fd: c_int,
) {
    // SAFETY: see `pump_events` above.
    let sd_fd = unsafe { ffi::DNSServiceRefSockFD(sd_ref) };
    if sd_fd < 0 {
        tracing::debug!(stage = "dns_sd.chain_pump_no_socket", sd_fd, id);
        return;
    }
    loop {
        match select_pump_ready(sd_fd, shutdown_fd) {
            Ok(true) => {
                // SAFETY: ref valid until either we deallocate (natural
                // exit) or the drainer deallocates after joining us.
                let err = unsafe { ffi::DNSServiceProcessResult(sd_ref) };
                if err != KDNS_SERVICE_ERR_NO_ERROR {
                    tracing::debug!(stage = "dns_sd.chain_pump_error_exit", error_code = err, id,);
                    // Forced exit: drainer owns deallocation.
                    return;
                }
                if done.load(Ordering::Acquire) {
                    tracing::debug!(stage = "dns_sd.chain_pump_done_exit", id);
                    break;
                }
            }
            Ok(false) => {
                tracing::debug!(stage = "dns_sd.chain_pump_shutdown_signal", id);
                // Forced exit via shutdown pipe: drainer owns deallocation.
                return;
            }
            Err(errno) => {
                tracing::debug!(stage = "dns_sd.chain_pump_select_error", errno, id);
                return;
            }
        }
    }
    // Natural exit: callback signalled completion. Remove ourselves
    // from the registry so a later shutdown doesn't double-deallocate,
    // then deallocate the ref. If `take` returns None, shutdown drained
    // us between the loop break and here — let shutdown handle the
    // deallocate.
    if let Some(_entry) = chain.take(id) {
        // SAFETY: we hold the only reference to `sd_ref` now (we just
        // pulled the entry out of the registry, no other thread can
        // grab it).
        unsafe { ffi::DNSServiceRefDeallocate(sd_ref) };
    }
}

// ─────────────────────── browser internals ────────────────────────────────

/// Heap context for the top-level browse callback. Outlives the browse
/// pump; reclaimed by `drop_browse_session` after the pump joins.
struct BrowseContext {
    display_service_type: String,
    regtype_normalized: String,
    sender: mpsc::UnboundedSender<ResolvedService>,
    chain: Arc<ChainRegistry>,
}

/// Heap context for the per-instance resolve callback. Reclaimed inside
/// `resolve_reply` once the chain hands off to GetAddrInfo (or fails).
/// `done` signals to the dedicated `pump_chain_events` loop that this
/// ref's lifecycle is complete and the pump should tear it down.
struct ResolveContext {
    display_service_type: String,
    sender: mpsc::UnboundedSender<ResolvedService>,
    done: Arc<AtomicBool>,
    chain: Arc<ChainRegistry>,
}

/// Heap context for the per-host getaddrinfo callback. Aggregates
/// addresses across multiple callbacks (kDNSServiceFlagsMoreComing) and
/// emits a `ResolvedService` once the daemon signals completion.
/// Reclaimed inside `getaddrinfo_reply` after emit. `done` is set on the
/// terminal callback so the dedicated pump tears the ref down without
/// the callback racing the next `DNSServiceProcessResult`.
struct GetAddrInfoContext {
    display_service_type: String,
    hostname: String,
    txt: HashMap<String, String>,
    port: u16,
    addresses: HashSet<IpAddr>,
    sender: mpsc::UnboundedSender<ResolvedService>,
    done: Arc<AtomicBool>,
}

// (No chain field on GetAddrInfoContext — getaddrinfo is the terminal
// step of the chain, so it doesn't spawn anything new.)

/// Tear down a browse session. Order: signal the pump's shutdown pipe
/// FIRST so the pump exits its `select(2)` and stops calling
/// `DNSServiceProcessResult`, then join, then deallocate the browse
/// ref. Doing it any other way (e.g. deallocate-then-join) reintroduces
/// the libdispatch teardown race documented in
/// `docs/followup-dns-sd-test-teardown-signal.md`.
///
/// The `BrowseContext` is intentionally leaked for the daemon's
/// lifetime — like `RegisterContext`, mDNSResponder may still hold the
/// pointer transiently and the per-browse leak is O(1).
fn drop_browse_session(mut session: BrowseSession) {
    // Wake the pump out of select(2) without touching the ref.
    session.shutdown_pipe.signal();
    if let Some(handle) = session.pump.take() {
        if let Err(e) = handle.join() {
            warn!(
                stage = "dns_sd.browse_pump_join_failed",
                error = ?e,
            );
        }
    }
    // Pump fully exited; safe to deallocate.
    drop(std::mem::replace(
        &mut session.sd_ref,
        SdRefHandle::new(ptr::null_mut()),
    ));
}

/// C callback for `DNSServiceBrowse`. Each invocation announces an Add
/// or Remove event for one service instance. We only act on Adds —
/// removes are surfaced to the facade today by the freshness window in
/// `bonjour_browser`, not by this callback.
extern "C" fn browse_reply(
    _sd_ref: ffi::DNSServiceRef,
    flags: ffi::DNSServiceFlags,
    interface_index: u32,
    error_code: ffi::DNSServiceErrorType,
    service_name: *const c_char,
    regtype: *const c_char,
    reply_domain: *const c_char,
    context: *mut c_void,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: context was leaked as a Box<BrowseContext> in
    // `BrowserHandle::browse`. We borrow, never reclaim — the registration
    // outlives this callback for the daemon's lifetime.
    let ctx = unsafe { &*(context.cast::<BrowseContext>()) };

    if error_code != KDNS_SERVICE_ERR_NO_ERROR {
        warn!(
            stage = "dns_sd.browse_callback_error",
            regtype = %ctx.regtype_normalized,
            error_code,
        );
        return;
    }
    if flags & KDNS_SERVICE_FLAG_ADD == 0 {
        // Remove event — ignore (handled by facade-side freshness window).
        return;
    }

    // SAFETY: dns_sd.h documents these C strings as NUL-terminated, valid
    // for the duration of the callback. We copy them into owned Rust
    // strings before issuing the next FFI call.
    let service_name_str = unsafe { c_str_to_string(service_name) };
    let regtype_str = unsafe { c_str_to_string(regtype) };
    let reply_domain_str = unsafe { c_str_to_string(reply_domain) };

    info!(
        stage = "dns_sd.browse_add",
        regtype = %ctx.regtype_normalized,
        instance = %service_name_str,
        domain = %reply_domain_str,
        interface_index,
    );

    if let Err(err) = start_resolve(
        &service_name_str,
        &regtype_str,
        &reply_domain_str,
        interface_index,
        ctx.display_service_type.clone(),
        ctx.sender.clone(),
        &ctx.chain,
    ) {
        warn!(
            stage = "dns_sd.resolve_start_failed",
            instance = %service_name_str,
            error = ?err,
        );
    }
}

/// Kick off a `DNSServiceResolve` for one browsed instance. Spawns its
/// own pump thread; the resolve ref is deallocated in the resolve
/// callback once the chain hands off to GetAddrInfo.
fn start_resolve(
    service_name: &str,
    regtype: &str,
    reply_domain: &str,
    interface_index: u32,
    display_service_type: String,
    sender: mpsc::UnboundedSender<ResolvedService>,
    chain: &Arc<ChainRegistry>,
) -> Result<(), BackendError> {
    let name_c = CString::new(service_name)
        .map_err(|e| BackendError::InvalidArgument(format!("name: {e}")))?;
    let regtype_c = CString::new(regtype)
        .map_err(|e| BackendError::InvalidArgument(format!("regtype: {e}")))?;
    let domain_c = CString::new(reply_domain)
        .map_err(|e| BackendError::InvalidArgument(format!("domain: {e}")))?;

    let done = Arc::new(AtomicBool::new(false));
    // SAFETY: leaked Box pointer reclaimed inside `resolve_reply`.
    let context = Box::into_raw(Box::new(ResolveContext {
        display_service_type,
        sender,
        done: Arc::clone(&done),
        chain: Arc::clone(chain),
    }));

    let mut sd_ref: ffi::DNSServiceRef = ptr::null_mut();
    // SAFETY: name_c, regtype_c, domain_c are valid CStrings for the
    // duration of the call; dns_sd.h copies what it needs internally.
    let err = unsafe {
        ffi::DNSServiceResolve(
            ptr::addr_of_mut!(sd_ref),
            KDNS_SERVICE_FLAGS_NONE,
            interface_index,
            name_c.as_ptr(),
            regtype_c.as_ptr(),
            domain_c.as_ptr(),
            Some(resolve_reply),
            context.cast::<c_void>(),
        )
    };
    if err != KDNS_SERVICE_ERR_NO_ERROR {
        // SAFETY: context just leaked; reclaim and drop.
        unsafe { drop(Box::from_raw(context)) };
        return Err(BackendError::from_code(err));
    }

    let id = chain.allocate_id();
    let shutdown_pipe = ShutdownPipe::new().inspect_err(|_| {
        // SAFETY: sd_ref was just successfully created and no other
        // thread holds it.
        unsafe { ffi::DNSServiceRefDeallocate(sd_ref) };
        // SAFETY: context still leaked; reclaim and drop.
        unsafe { drop(Box::from_raw(context)) };
    })?;
    let pump_shutdown_fd = shutdown_pipe.read_fd;
    let pump_ref = SendableSdRef(sd_ref);
    let chain_for_pump = Arc::clone(chain);
    let pump = thread::Builder::new()
        .name(format!("dns_sd_pump_resolve[{service_name}]"))
        .spawn(move || {
            let captured = pump_ref;
            // The pump owns the ref and tears it down on natural exit.
            // The callback signals completion via `done` rather than
            // deallocating the ref itself — that would race the pump's
            // next `DNSServiceProcessResult` call.
            pump_chain_events(captured.0, &done, &chain_for_pump, id, pump_shutdown_fd);
        })
        .map_err(|e| {
            // Best-effort cleanup on spawn failure.
            // SAFETY: sd_ref was just successfully created and no other
            // thread holds it.
            unsafe { ffi::DNSServiceRefDeallocate(sd_ref) };
            // SAFETY: context still leaked; reclaim and drop.
            unsafe { drop(Box::from_raw(context)) };
            BackendError::InvalidArgument(format!("resolve pump thread: {e}"))
        })?;

    chain.insert(
        id,
        ChainEntry {
            sd_ref,
            pump,
            shutdown_pipe,
        },
    );
    Ok(())
}

/// C callback for `DNSServiceResolve`. Receives the service's host
/// target, port, and TXT bytes. We then chain into `DNSServiceGetAddrInfo`
/// to materialise the host into IP addresses.
extern "C" fn resolve_reply(
    _sd_ref: ffi::DNSServiceRef,
    _flags: ffi::DNSServiceFlags,
    interface_index: u32,
    error_code: ffi::DNSServiceErrorType,
    fullname: *const c_char,
    host_target: *const c_char,
    port_be: u16,
    txt_len: u16,
    txt_record: *const u8,
    context: *mut c_void,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: context was leaked as Box<ResolveContext> in `start_resolve`.
    // We reclaim it here (before any early return) so the box drops once
    // we've extracted what we need. Setting `done` after this borrow
    // exits tells the pump thread to break out of its loop and
    // deallocate the ref.
    let ctx_box: Box<ResolveContext> = unsafe { Box::from_raw(context.cast::<ResolveContext>()) };
    let ctx = *ctx_box;

    // Tell the pump thread to break out of its loop after this callback
    // returns. The pump will then deallocate the ref itself — we can't
    // do it here because we're still inside `DNSServiceProcessResult`'s
    // call frame and freeing the ref would be a use-after-free on the
    // next pump iteration.
    ctx.done.store(true, Ordering::Release);

    if error_code != KDNS_SERVICE_ERR_NO_ERROR {
        warn!(stage = "dns_sd.resolve_callback_error", error_code,);
        return;
    }

    // SAFETY: fullname, host_target are dns_sd.h-owned NUL-terminated
    // C strings valid for the duration of this callback.
    let fullname_str = unsafe { c_str_to_string(fullname) };
    let host_target_str_owned = unsafe { c_str_to_string(host_target) };

    // dns_sd.h emits port in network byte order.
    let port = u16::from_be(port_be);

    // SAFETY: txt_record is valid for `txt_len` bytes per dns_sd.h.
    // A null txt_record only appears when txt_len == 0; guard for that.
    let txt = if txt_record.is_null() || txt_len == 0 {
        HashMap::new()
    } else {
        let slice = unsafe { std::slice::from_raw_parts(txt_record, txt_len as usize) };
        parse_txt_record(slice)
    };

    info!(
        stage = "dns_sd.resolve_done",
        fullname = %fullname_str,
        host = %host_target_str_owned,
        port,
        txt_keys = txt.len(),
    );

    if let Err(err) = start_get_addr_info(
        &host_target_str_owned,
        interface_index,
        ctx.display_service_type.clone(),
        txt,
        port,
        ctx.sender.clone(),
        &ctx.chain,
    ) {
        warn!(
            stage = "dns_sd.getaddrinfo_start_failed",
            host = %host_target_str_owned,
            error = ?err,
        );
    }
}

/// Kick off a `DNSServiceGetAddrInfo` for one resolved host. Spawns its
/// own pump thread; the ref is deallocated by the callback once the
/// daemon signals completion (no `kDNSServiceFlagsMoreComing`).
fn start_get_addr_info(
    host_target: &str,
    interface_index: u32,
    display_service_type: String,
    txt: HashMap<String, String>,
    port: u16,
    sender: mpsc::UnboundedSender<ResolvedService>,
    chain: &Arc<ChainRegistry>,
) -> Result<(), BackendError> {
    let host_c = CString::new(host_target)
        .map_err(|e| BackendError::InvalidArgument(format!("host: {e}")))?;

    let done = Arc::new(AtomicBool::new(false));
    // SAFETY: leaked Box reclaimed inside `getaddrinfo_reply` on the
    // terminal callback (no `kDNSServiceFlagsMoreComing`).
    let context = Box::into_raw(Box::new(GetAddrInfoContext {
        display_service_type,
        hostname: host_target.to_string(),
        txt,
        port,
        addresses: HashSet::new(),
        sender,
        done: Arc::clone(&done),
    }));

    let mut sd_ref: ffi::DNSServiceRef = ptr::null_mut();
    // SAFETY: host_c is a valid CString for the duration of the call.
    let err = unsafe {
        ffi::DNSServiceGetAddrInfo(
            ptr::addr_of_mut!(sd_ref),
            KDNS_SERVICE_FLAGS_NONE,
            interface_index,
            KDNS_SERVICE_PROTOCOL_IPV4 | KDNS_SERVICE_PROTOCOL_IPV6,
            host_c.as_ptr(),
            Some(getaddrinfo_reply),
            context.cast::<c_void>(),
        )
    };
    if err != KDNS_SERVICE_ERR_NO_ERROR {
        // SAFETY: context just leaked; reclaim and drop.
        unsafe { drop(Box::from_raw(context)) };
        return Err(BackendError::from_code(err));
    }

    let id = chain.allocate_id();
    let shutdown_pipe = ShutdownPipe::new().inspect_err(|_| {
        // SAFETY: ref was just successfully created and no other thread
        // holds it.
        unsafe { ffi::DNSServiceRefDeallocate(sd_ref) };
        // SAFETY: context still leaked; reclaim and drop.
        unsafe { drop(Box::from_raw(context)) };
    })?;
    let pump_shutdown_fd = shutdown_pipe.read_fd;
    let pump_ref = SendableSdRef(sd_ref);
    let chain_for_pump = Arc::clone(chain);
    let pump = thread::Builder::new()
        .name(format!("dns_sd_pump_getaddrinfo[{host_target}]"))
        .spawn(move || {
            let captured = pump_ref;
            pump_chain_events(captured.0, &done, &chain_for_pump, id, pump_shutdown_fd);
        })
        .map_err(|e| {
            // SAFETY: we created the ref above and no thread is using it.
            unsafe { ffi::DNSServiceRefDeallocate(sd_ref) };
            // SAFETY: context still leaked; reclaim and drop.
            unsafe { drop(Box::from_raw(context)) };
            BackendError::InvalidArgument(format!("getaddrinfo pump thread: {e}"))
        })?;

    chain.insert(
        id,
        ChainEntry {
            sd_ref,
            pump,
            shutdown_pipe,
        },
    );
    Ok(())
}

/// C callback for `DNSServiceGetAddrInfo`. The daemon may invoke this
/// multiple times for one query (one address per call) with
/// `kDNSServiceFlagsMoreComing` set on all but the last. We accumulate
/// addresses on the heap context, then emit a single `ResolvedService`
/// when the terminal callback arrives.
extern "C" fn getaddrinfo_reply(
    _sd_ref: ffi::DNSServiceRef,
    flags: ffi::DNSServiceFlags,
    _interface_index: u32,
    error_code: ffi::DNSServiceErrorType,
    hostname: *const c_char,
    address: *const ffi::sockaddr,
    _ttl: u32,
    context: *mut c_void,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: context is the leaked Box<GetAddrInfoContext>. We borrow
    // mutably here — only one thread at a time invokes the callback
    // (mDNSResponder serialises callbacks per ref and pump_events calls
    // them inline from DNSServiceProcessResult).
    let ctx = unsafe { &mut *(context.cast::<GetAddrInfoContext>()) };

    if error_code == KDNS_SERVICE_ERR_NO_ERROR && !address.is_null() {
        // SAFETY: address is a valid sockaddr per dns_sd.h. We cast
        // through libc::sockaddr (the FFI types `ffi::sockaddr` and
        // `libc::sockaddr` are layout-compatible: both `#[repr(C)]`,
        // both opaque structs with the leading `sa_family_t`).
        if let Some(ip) = unsafe { sockaddr_to_ipaddr(address.cast::<libc::sockaddr>()) } {
            // SAFETY (logging): hostname is dns_sd.h-owned C string.
            let hostname_str = unsafe { c_str_to_string(hostname) };
            info!(
                stage = "dns_sd.getaddrinfo_address",
                host = %hostname_str,
                ip = %ip,
            );
            ctx.addresses.insert(ip);
        }
    } else if error_code != KDNS_SERVICE_ERR_NO_ERROR {
        warn!(stage = "dns_sd.getaddrinfo_callback_error", error_code,);
    }

    // Terminal callback (no MoreComing flag): emit and clean up.
    if flags & KDNS_SERVICE_FLAG_MORE_COMING == 0 {
        // SAFETY: reclaim the leaked Box. We then set `done` so the
        // pump thread exits its `DNSServiceProcessResult` loop after
        // this callback returns and deallocates the ref itself —
        // doing the deallocate from inside the callback would race the
        // pump's next iteration.
        let ctx_box: Box<GetAddrInfoContext> =
            unsafe { Box::from_raw(context.cast::<GetAddrInfoContext>()) };
        let GetAddrInfoContext {
            display_service_type,
            hostname,
            txt,
            port,
            addresses,
            sender,
            done,
        } = *ctx_box;

        // Signal pump to exit and tear down the ref.
        done.store(true, Ordering::Release);

        if addresses.is_empty() {
            info!(stage = "dns_sd.resolved_no_addresses");
        } else {
            let resolved = ResolvedService {
                service_type: display_service_type,
                hostname,
                txt,
                addresses,
                port,
            };
            // Channel may be closed if the BrowserHandle was dropped;
            // log and ignore — there's nothing to deliver to.
            if sender.send(resolved).is_err() {
                info!(stage = "dns_sd.resolved_dropped_no_receiver");
            }
        }
    }
}

/// Convert a dns_sd.h-supplied `sockaddr*` into an `IpAddr`. Returns
/// `None` for unsupported address families.
///
/// SAFETY: caller must ensure `addr` points to a valid `sockaddr` whose
/// `sa_family` field is initialised. dns_sd.h documents the pointer as
/// valid for the duration of the callback.
unsafe fn sockaddr_to_ipaddr(addr: *const libc::sockaddr) -> Option<IpAddr> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: caller guarantees `addr` references at least an initialised
    // sa_family. We dispatch on family before reading further.
    let family = unsafe { (*addr).sa_family };
    match i32::from(family) {
        libc::AF_INET => {
            // SAFETY: dns_sd.h documents the buffer as at least
            // sizeof(sockaddr_in) when family == AF_INET. We use
            // `read_unaligned` to side-step `clippy::cast_ptr_alignment`
            // — kernel-supplied sockaddrs are in fact properly aligned,
            // but proving that to clippy without `#[allow]` requires the
            // unaligned read.
            let sa_in: libc::sockaddr_in =
                unsafe { ptr::read_unaligned(addr.cast::<libc::sockaddr_in>()) };
            // sin_addr.s_addr is in network byte order; Ipv4Addr::from
            // on a [u8; 4] of the raw bytes preserves dotted-quad ordering.
            let octets = sa_in.sin_addr.s_addr.to_ne_bytes();
            Some(IpAddr::V4(std::net::Ipv4Addr::from(octets)))
        }
        libc::AF_INET6 => {
            // SAFETY: ditto for sockaddr_in6.
            let sa_in6: libc::sockaddr_in6 =
                unsafe { ptr::read_unaligned(addr.cast::<libc::sockaddr_in6>()) };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(
                sa_in6.sin6_addr.s6_addr,
            )))
        }
        _ => None,
    }
}

/// Parse an RFC 6763 §6.4 TXT-record byte buffer into a key/value map.
/// Each record is `<u8 length><length bytes of "key=value">`. Records
/// without an `=` are treated as a key with empty value (per RFC).
/// Invalid UTF-8 in keys or values is replaced with U+FFFD.
fn parse_txt_record(buf: &[u8]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut i = 0usize;
    while i < buf.len() {
        let len = buf[i] as usize;
        i += 1;
        if i + len > buf.len() {
            // Malformed — bail out with what we have.
            break;
        }
        let record = &buf[i..i + len];
        i += len;
        if record.is_empty() {
            continue;
        }
        let (key_bytes, value_bytes) = match record.iter().position(|&b| b == b'=') {
            Some(eq) => (&record[..eq], &record[eq + 1..]),
            None => (record, &[][..]),
        };
        let key = String::from_utf8_lossy(key_bytes).into_owned();
        let value = String::from_utf8_lossy(value_bytes).into_owned();
        out.insert(key, value);
    }
    out
}

/// Convert a possibly-null C string to an owned Rust String, replacing
/// invalid UTF-8 with U+FFFD. Returns `"<null>"` for null pointers.
unsafe fn c_str_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return "<null>".to_string();
    }
    // SAFETY: caller asserts `ptr` is a NUL-terminated C string.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

// ─────────────────────── TXT record builder ────────────────────────────────

/// Normalize a service type string into the form dns_sd.h's `regtype`
/// parameter requires (`_service._proto`, no domain, no trailing dot).
/// The facade hands us the mdns-sd-style form (`_service._proto.local.`)
/// so we have to strip both the trailing dot(s) and the `.local` suffix.
fn normalize_regtype(s: &str) -> &str {
    let s = s.trim_end_matches('.');
    s.strip_suffix(".local")
        .or_else(|| s.strip_suffix(".local."))
        .unwrap_or(s)
}

/// dns_sd.h passes TXT records as a flat byte buffer following RFC 6763
/// §6.4: one or more `<length><key=value>` records, each prefixed by a
/// single byte length (0–255). We build it manually rather than use
/// `TXTRecordSetValue` to avoid the lifetime gymnastics of a separate
/// `TXTRecordRef` resource.
#[derive(Debug)]
struct TxtBuffer {
    bytes: Vec<u8>,
}

impl TxtBuffer {
    fn build(txt: &HashMap<String, String>) -> Result<Self, BackendError> {
        let mut bytes = Vec::new();
        // Sort keys for deterministic output (helps regression tests on
        // both backends produce comparable on-the-wire bytes).
        let mut keys: Vec<&String> = txt.keys().collect();
        keys.sort();
        for key in keys {
            let value = &txt[key];
            // Per RFC 6763 §6.4: keys must be 1–9 octets typical, the
            // combined `key=value` record can be up to 255 octets. We
            // reject longer entries because the protocol can't represent
            // them.
            let mut record = Vec::with_capacity(key.len() + 1 + value.len());
            record.extend_from_slice(key.as_bytes());
            record.push(b'=');
            record.extend_from_slice(value.as_bytes());
            if record.len() > 255 {
                return Err(BackendError::TxtTooLarge {
                    size: record.len(),
                    max: 255,
                });
            }
            // u8 cast is safe — we just bounded above.
            #[allow(clippy::cast_possible_truncation)]
            bytes.push(record.len() as u8);
            bytes.extend_from_slice(&record);
        }
        // dns_sd.h limits the entire txtRecord to 65535 bytes (u16 length
        // field on the wire).
        if bytes.len() > u16::MAX as usize {
            return Err(BackendError::TxtTooLarge {
                size: bytes.len(),
                max: u16::MAX as usize,
            });
        }
        Ok(Self { bytes })
    }

    fn as_ptr(&self) -> *const c_void {
        self.bytes.as_ptr().cast::<c_void>()
    }

    #[allow(clippy::cast_possible_truncation)]
    fn len(&self) -> u16 {
        self.bytes.len() as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn txt_buffer_builds_rfc_6763_format() {
        let mut txt = HashMap::new();
        txt.insert("hh_id".to_string(), "abc".to_string());
        txt.insert("proto".to_string(), "1".to_string());
        let buf = TxtBuffer::build(&txt).unwrap();
        // `hh_id=abc` = 9 bytes; `proto=1` = 7 bytes
        // Sorted keys → hh_id first, then proto
        // Expected: [9, "hh_id=abc", 7, "proto=1"]
        let expected: Vec<u8> = [&[9u8][..], b"hh_id=abc", &[7u8][..], b"proto=1"].concat();
        assert_eq!(buf.bytes, expected);
        assert_eq!(buf.len() as usize, expected.len());
    }

    #[test]
    fn normalize_regtype_strips_local_and_dots() {
        assert_eq!(
            normalize_regtype("_soyeht-household._tcp.local."),
            "_soyeht-household._tcp"
        );
        assert_eq!(
            normalize_regtype("_soyeht-household._tcp.local"),
            "_soyeht-household._tcp"
        );
        assert_eq!(
            normalize_regtype("_soyeht-household._tcp."),
            "_soyeht-household._tcp"
        );
        assert_eq!(
            normalize_regtype("_soyeht-household._tcp"),
            "_soyeht-household._tcp"
        );
    }

    #[test]
    fn txt_buffer_rejects_overlong_record() {
        let mut txt = HashMap::new();
        let big = "x".repeat(300);
        txt.insert("k".to_string(), big);
        let err = TxtBuffer::build(&txt).unwrap_err();
        match err {
            BackendError::TxtTooLarge { size, max } => {
                assert!(size > 255);
                assert_eq!(max, 255);
            }
            other => panic!("expected TxtTooLarge, got {other:?}"),
        }
    }

    /// Smoke test: registers a service via the dns_sd.h backend and gives
    /// the developer a 4-second window to verify with
    /// `dns-sd -B _soyeht-spike-b2a._tcp local.` from another terminal.
    /// Ignored by default — run with:
    ///
    /// ```ignore
    /// cargo test -p server-rs --lib bonjour_impl_dns_sd::tests::register_smoke -- --ignored --nocapture
    /// ```
    ///
    /// Promoted to an unconditional test in B-4 once the regression-lock
    /// `bonjour_macos_smoke.rs` integration test is in place.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "macOS-only smoke test; relies on mDNSResponder running"]
    async fn register_smoke() {
        let publisher = PublisherHandle::new().expect("PublisherHandle::new");

        let mut txt = HashMap::new();
        txt.insert("hh_id".to_string(), "spike-b2a-hh".to_string());
        txt.insert("pair_nonce".to_string(), "spike-b2a-nonce".to_string());

        let spec = ServiceSpec {
            service_type: "_soyeht-spike-b2a._tcp.local.",
            instance: "spike-b2a",
            host: "spike-b2a.local.",
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8443,
            txt: &txt,
        };

        let fullname = publisher.register(&spec).expect("register");
        eprintln!("[register_smoke] registered fullname={fullname}");
        eprintln!(
            "[register_smoke] you have 4s — run in another terminal:\n  dns-sd -B _soyeht-spike-b2a._tcp local."
        );

        tokio::time::sleep(Duration::from_secs(4)).await;

        let outcome = publisher.shutdown_and_wait(Duration::from_secs(2)).await;
        eprintln!("[register_smoke] shutdown outcome: {outcome:?}");
        assert!(matches!(outcome, ShutdownOutcome::Ok));
    }

    #[test]
    fn parse_txt_record_round_trips_with_txt_buffer() {
        let mut txt = HashMap::new();
        txt.insert("hh_id".to_string(), "abc".to_string());
        txt.insert("pair_nonce".to_string(), "xyz".to_string());
        let buf = TxtBuffer::build(&txt).unwrap();
        let parsed = parse_txt_record(&buf.bytes);
        assert_eq!(parsed.get("hh_id").map(String::as_str), Some("abc"));
        assert_eq!(parsed.get("pair_nonce").map(String::as_str), Some("xyz"));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn parse_txt_record_handles_keys_without_equals() {
        // RFC 6763 §6.4 allows boolean attributes (no `=`).
        let buf = vec![6u8, b'b', b'o', b'o', b'l', b'k', b'y'];
        let parsed = parse_txt_record(&buf);
        assert_eq!(parsed.get("boolky").map(String::as_str), Some(""));
    }

    #[test]
    fn parse_txt_record_truncates_on_malformed_length() {
        // Length byte says 99 but only 3 bytes follow — must not panic.
        let buf = vec![99u8, b'a', b'b', b'c'];
        let parsed = parse_txt_record(&buf);
        assert!(parsed.is_empty());
    }

    /// Browser smoke test: spawns a publisher in the same process,
    /// registers a service over the dns_sd.h backend, then opens a
    /// `BrowserHandle` against the same regtype and asserts the chain
    /// browse → resolve → getaddrinfo materialises the registration.
    /// Ignored by default — run with:
    ///
    /// ```ignore
    /// cargo test -p server-rs --lib bonjour_impl_dns_sd::tests::browse_smoke -- --ignored --nocapture
    /// ```
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "macOS-only smoke test; relies on mDNSResponder running"]
    async fn browse_smoke() {
        const REGTYPE: &str = "_soyeht-spike-b2b._tcp.local.";

        let publisher = PublisherHandle::new().expect("PublisherHandle::new");

        let mut txt = HashMap::new();
        txt.insert("hh_id".to_string(), "spike-b2b-hh".to_string());
        txt.insert("pair_nonce".to_string(), "spike-b2b-nonce".to_string());

        let spec = ServiceSpec {
            service_type: REGTYPE,
            instance: "spike-b2b",
            host: "spike-b2b.local.",
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8443,
            txt: &txt,
        };

        let fullname = publisher.register(&spec).expect("register");
        eprintln!("[browse_smoke] registered fullname={fullname}");

        // Give mDNSResponder a moment to commit the registration before
        // we start browsing — without this the browser sometimes opens
        // its socket before the registration is visible.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let browser = BrowserHandle::new().expect("BrowserHandle::new");
        let stream = browser.browse(REGTYPE).expect("browse");

        let resolved = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("did not receive a ResolvedService within 5s")
            .expect("stream closed without yielding a ResolvedService");

        eprintln!(
            "[browse_smoke] resolved: type={} port={} txt_keys={:?} addresses={:?}",
            resolved.service_type(),
            resolved.port(),
            resolved.txt.keys().collect::<Vec<_>>(),
            resolved.addresses()
        );

        assert_eq!(resolved.service_type(), REGTYPE);
        assert_eq!(resolved.txt("hh_id"), Some("spike-b2b-hh"));
        assert_eq!(resolved.txt("pair_nonce"), Some("spike-b2b-nonce"));
        assert!(
            !resolved.addresses().is_empty(),
            "expected at least one address in the resolved set"
        );
        assert_eq!(resolved.port(), 8443);

        // Clean shutdown of both ends.
        browser.shutdown();
        let outcome = publisher.shutdown_and_wait(Duration::from_secs(2)).await;
        eprintln!("[browse_smoke] publisher shutdown outcome: {outcome:?}");
        assert!(matches!(outcome, ShutdownOutcome::Ok));
    }
}
