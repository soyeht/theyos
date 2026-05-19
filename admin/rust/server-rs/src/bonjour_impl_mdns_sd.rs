//! Pure-Rust mDNS backend wrapping the `mdns-sd` crate.
//!
//! This module is the I/O layer the `bonjour_publisher` and `bonjour_browser`
//! facades call into. It exists so a parallel `bonjour_impl_dns_sd.rs` can
//! provide a macOS-native backend (Apple's `dns_sd.h` system bridge) without
//! the facades knowing which is wired in. See
//! `docs/followup-mdns-sd-macos-publisher.md` for context.
//!
//! On `mdns-sd` 0.10 the publisher does not propagate to macOS's
//! `mDNSResponder` daemon when `mDNSResponder` already binds 5353 — the
//! parallel macOS backend (B-2) replaces this for `target_os = "macos"`.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use mdns_sd::{DaemonStatus, Receiver, ServiceDaemon, ServiceEvent, ServiceInfo, UnregisterStatus};
use tokio::time::timeout;

/// Backend-specific error type. Re-exported so the facade signatures don't
/// hardcode the underlying crate.
pub type BackendError = mdns_sd::Error;

/// Description of a single service registration. Built by the facade,
/// consumed by the backend.
pub struct ServiceSpec<'a> {
    pub service_type: &'a str,
    pub instance: &'a str,
    pub host: &'a str,
    pub ip: IpAddr,
    pub port: u16,
    pub txt: &'a HashMap<String, String>,
}

/// Outcome of `unregister_and_wait`.
#[derive(Debug)]
pub enum UnregisterOutcome {
    Ok,
    NotFound,
    Failed(String),
    TimedOut,
}

/// Outcome of `shutdown_and_wait`.
#[derive(Debug)]
pub enum ShutdownOutcome {
    Ok,
    Failed(String),
    Unexpected(String),
    TimedOut,
}

/// Publisher daemon handle. Cheap to clone — the underlying `ServiceDaemon`
/// is itself a clone-able multi-handle to one daemon thread.
#[derive(Clone)]
pub struct PublisherHandle {
    daemon: ServiceDaemon,
}

impl PublisherHandle {
    pub fn new() -> Result<Self, BackendError> {
        Ok(Self {
            daemon: ServiceDaemon::new()?,
        })
    }

    /// Register `spec` with the daemon. Returns the fullname assigned by
    /// the daemon — the caller stores it to `unregister` later.
    pub fn register(&self, spec: &ServiceSpec<'_>) -> Result<String, BackendError> {
        let info = ServiceInfo::new(
            spec.service_type,
            spec.instance,
            spec.host,
            spec.ip,
            spec.port,
            Some(spec.txt.clone()),
        )?;
        let fullname = info.get_fullname().to_string();
        self.daemon.register(info)?;
        Ok(fullname)
    }

    /// Fire-and-forget unregister. Caller does not await ack — used in
    /// the TXT-update path where a re-register follows immediately.
    pub fn unregister(&self, fullname: &str) -> Result<(), BackendError> {
        self.daemon.unregister(fullname).map(|_| ())
    }

    /// Unregister and await completion with `wait` budget.
    pub async fn unregister_and_wait(&self, fullname: &str, wait: Duration) -> UnregisterOutcome {
        let rx: Receiver<UnregisterStatus> = match self.daemon.unregister(fullname) {
            Ok(rx) => rx,
            Err(e) => return UnregisterOutcome::Failed(e.to_string()),
        };
        match timeout(wait, rx.recv_async()).await {
            Ok(Ok(UnregisterStatus::OK)) => UnregisterOutcome::Ok,
            Ok(Ok(UnregisterStatus::NotFound)) => UnregisterOutcome::NotFound,
            Ok(Err(e)) => UnregisterOutcome::Failed(e.to_string()),
            Err(_) => UnregisterOutcome::TimedOut,
        }
    }

    /// Shut down the daemon and await completion with `wait` budget.
    pub async fn shutdown_and_wait(&self, wait: Duration) -> ShutdownOutcome {
        let rx: Receiver<DaemonStatus> = match self.daemon.shutdown() {
            Ok(rx) => rx,
            Err(e) => return ShutdownOutcome::Failed(e.to_string()),
        };
        match timeout(wait, rx.recv_async()).await {
            Ok(Ok(DaemonStatus::Shutdown)) => ShutdownOutcome::Ok,
            Ok(Ok(other)) => ShutdownOutcome::Unexpected(format!("{other:?}")),
            Ok(Err(e)) => ShutdownOutcome::Failed(e.to_string()),
            Err(_) => ShutdownOutcome::TimedOut,
        }
    }
}

/// Browser daemon handle.
pub struct BrowserHandle {
    daemon: ServiceDaemon,
}

impl BrowserHandle {
    pub fn new() -> Result<Self, BackendError> {
        Ok(Self {
            daemon: ServiceDaemon::new()?,
        })
    }

    /// Start browsing `service_type`. The returned stream yields
    /// `ResolvedService` items.
    pub fn browse(&self, service_type: &str) -> Result<BrowseStream, BackendError> {
        let receiver = self.daemon.browse(service_type)?;
        Ok(BrowseStream { receiver })
    }

    pub fn stop_browse(&self, service_type: &str) {
        let _ = self.daemon.stop_browse(service_type);
    }

    pub fn shutdown(&self) {
        let _ = self.daemon.shutdown();
    }
}

/// Async stream of resolved services. Skips intermediate `ServiceEvent`
/// variants internally so the facade only ever sees resolutions.
pub struct BrowseStream {
    receiver: Receiver<ServiceEvent>,
}

impl BrowseStream {
    /// Yield the next resolved service. Returns `None` when the underlying
    /// daemon channel closes.
    pub async fn next(&self) -> Option<ResolvedService> {
        loop {
            let event = self.receiver.recv_async().await.ok()?;
            if let ServiceEvent::ServiceResolved(info) = event {
                return Some(ResolvedService::from_service_info(&info));
            }
        }
    }
}

/// Backend-agnostic snapshot of one resolved mDNS service. The macOS
/// backend will produce the same shape from `dns_sd.h` callbacks.
pub struct ResolvedService {
    service_type: String,
    hostname: String,
    txt: HashMap<String, String>,
    addresses: HashSet<IpAddr>,
    port: u16,
}

impl ResolvedService {
    fn from_service_info(info: &ServiceInfo) -> Self {
        let mut txt = HashMap::new();
        for prop in info.get_properties().iter() {
            txt.insert(prop.key().to_string(), prop.val_str().to_string());
        }
        Self {
            service_type: info.get_type().to_string(),
            hostname: info.get_hostname().to_string(),
            txt,
            addresses: info.get_addresses().clone(),
            port: info.get_port(),
        }
    }

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
