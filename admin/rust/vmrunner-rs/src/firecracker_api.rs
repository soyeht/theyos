//! `firecracker_api.rs` — Firecracker REST API client via hyper + hyperlocal (Unix socket).
// NOTE: VmError is large by design (rich diagnostic context); boxing would require
// pervasive API changes across all callers.
#![allow(clippy::result_large_err)]
//!
//! The Firecracker microVM exposes a REST API on a Unix domain socket.
//! This module uses `hyper` with `hyperlocal::UnixConnector` for proper
//! HTTP/1.1 framing over Unix sockets, replacing the previous hand-rolled
//! HTTP implementation.
//!
//! # Firecracker API contract
//! - All requests: `Content-Type: application/json`
//! - All successful PUTs: HTTP 204 No Content
//! - Base URL is `http://localhost` (the socket provides routing)

use std::path::{Path, PathBuf};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyperlocal::{UnixClientExt, UnixConnector, Uri as UnixUri};

use crate::error::VmError;

/// Default timeout for normal API requests (seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Timeout for snapshot operations (seconds).
const SNAPSHOT_TIMEOUT_SECS: u64 = 120;

/// Short initial timeout for snapshot create (seconds).
///
/// Firecracker (notably with nanobot) sometimes writes the snapshot files to
/// disk but never sends an HTTP response.  Rather than waiting the full 120 s
/// before falling back to the files-on-disk check, we first try with this
/// shorter timeout.  If it expires but the files landed, we treat it as
/// success immediately.  If the files are missing we retry with the full
/// timeout in case Firecracker is simply slow.
const SNAPSHOT_SHORT_TIMEOUT_SECS: u64 = 10;

/// Maximum number of retries when the socket is not yet ready.
const MAX_CONNECT_RETRIES: u32 = 10;

/// Low-level Firecracker REST API client.
///
/// Communicates over a Unix domain socket using `hyper` + `hyperlocal`
/// for correct HTTP/1.1 framing. All methods are async.
pub struct FirecrackerClient {
    sock_path: PathBuf,
}

impl FirecrackerClient {
    /// Create a client for the given socket path.
    #[must_use]
    pub fn new(sock_path: PathBuf) -> Self {
        FirecrackerClient { sock_path }
    }

    // ── Public API methods ─────────────────────────────────────────────────

    /// PUT /machine-config — set vCPU count and RAM.
    ///
    /// # Errors
    ///
    /// Returns an error if the Firecracker API request fails.
    pub async fn set_machine_config(
        &self,
        vcpu_count: u32,
        mem_size_mib: u32,
    ) -> Result<(), VmError> {
        let body = serde_json::json!({
            "vcpu_count": vcpu_count,
            "mem_size_mib": mem_size_mib,
        });
        self.put("/machine-config", &body, DEFAULT_TIMEOUT_SECS)
            .await
    }

    /// PUT /boot-source — set kernel image path and boot arguments.
    ///
    /// # Errors
    ///
    /// Returns an error if the Firecracker API request fails.
    pub async fn set_boot_source(
        &self,
        kernel_image_path: &str,
        boot_args: &str,
    ) -> Result<(), VmError> {
        let body = serde_json::json!({
            "kernel_image_path": kernel_image_path,
            "boot_args": boot_args,
        });
        self.put("/boot-source", &body, DEFAULT_TIMEOUT_SECS).await
    }

    /// PUT /drives/rootfs — attach root block device.
    ///
    /// # Errors
    ///
    /// Returns an error if the Firecracker API request fails.
    pub async fn set_rootfs(&self, path_on_host: &str, is_read_only: bool) -> Result<(), VmError> {
        let body = serde_json::json!({
            "drive_id": "rootfs",
            "path_on_host": path_on_host,
            "is_root_device": true,
            "is_read_only": is_read_only,
        });
        self.put("/drives/rootfs", &body, DEFAULT_TIMEOUT_SECS)
            .await
    }

    /// PUT /network-interfaces/{iface_id} — attach TAP network interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the Firecracker API request fails.
    pub async fn set_network_interface(
        &self,
        iface_id: &str,
        host_dev_name: &str,
        mac: &str,
    ) -> Result<(), VmError> {
        let body = serde_json::json!({
            "iface_id": iface_id,
            "host_dev_name": host_dev_name,
            "guest_mac": mac,
        });
        self.put(
            &format!("/network-interfaces/{iface_id}"),
            &body,
            DEFAULT_TIMEOUT_SECS,
        )
        .await
    }

    /// PUT /actions — send `InstanceStart` to boot the VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the Firecracker API request fails.
    pub async fn start_instance(&self) -> Result<(), VmError> {
        let body = serde_json::json!({ "action_type": "InstanceStart" });
        self.put("/actions", &body, DEFAULT_TIMEOUT_SECS).await
    }

    /// PATCH /vm — transition the VM to `Paused` state (required before snapshot).
    ///
    /// # Errors
    ///
    /// Returns an error if the Firecracker API request fails.
    pub async fn pause_vm(&self) -> Result<(), VmError> {
        let body = serde_json::json!({ "state": "Paused" });
        self.patch("/vm", &body, DEFAULT_TIMEOUT_SECS).await
    }

    /// PATCH /vm — resume a paused VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the Firecracker API request fails.
    pub async fn resume_vm(&self) -> Result<(), VmError> {
        let body = serde_json::json!({ "state": "Resumed" });
        self.patch("/vm", &body, DEFAULT_TIMEOUT_SECS).await
    }

    /// PUT /snapshot/create — create a full snapshot of a paused VM.
    ///
    /// Both `snapshot_path` and `mem_file_path` are host-side absolute paths.
    /// The VM **must** be paused before calling this.
    ///
    /// Firecracker (notably with nanobot) sometimes writes the snapshot files
    /// to disk but never sends an HTTP response.  To avoid waiting the full
    /// 120 s timeout we use a two-phase strategy:
    ///
    /// 1. Try the request with a short (10 s) timeout.
    /// 2. On **any** error, check if both files landed on disk with non-zero
    ///    size → treat as success.
    /// 3. If the files are missing, retry with the full 120 s timeout (maybe
    ///    Firecracker is just slow).
    /// 4. If the retry also fails, check the files one more time.
    ///
    /// This reduces the nanobot worst-case from ~120 s to ~10 s while keeping
    /// correctness for legitimately slow snapshot creates.
    ///
    /// # Errors
    ///
    /// Returns an error if the Firecracker API request fails and the snapshot
    /// files are not present on disk.
    pub async fn create_snapshot(
        &self,
        snapshot_path: &str,
        mem_file_path: &str,
    ) -> Result<(), VmError> {
        let body = serde_json::json!({
            "snapshot_path": snapshot_path,
            "mem_file_path": mem_file_path,
            "snapshot_type": "Full",
        });

        // ── Phase 1: short timeout ─────────────────────────────────────────
        match self
            .put("/snapshot/create", &body, SNAPSHOT_SHORT_TIMEOUT_SECS)
            .await
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                // Check files-on-disk before potentially waiting another 120 s.
                if Self::snapshot_files_exist(snapshot_path, mem_file_path) {
                    tracing::warn!(
                        "[vmrunner] snapshot API timed out (short) but files exist on disk \
                         — treating as success: {e}"
                    );
                    return Ok(());
                }
                tracing::info!(
                    "[vmrunner] snapshot short timeout ({SNAPSHOT_SHORT_TIMEOUT_SECS}s) \
                     expired and files not yet on disk — retrying with full timeout: {e}"
                );
            }
        }

        // ── Phase 2: full timeout ──────────────────────────────────────────
        match self
            .put("/snapshot/create", &body, SNAPSHOT_TIMEOUT_SECS)
            .await
        {
            Ok(()) => Ok(()),
            Err(e) => {
                if Self::snapshot_files_exist(snapshot_path, mem_file_path) {
                    tracing::warn!(
                        "[vmrunner] snapshot API returned error but files exist on disk \
                         — treating as success: {e}"
                    );
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Check whether both snapshot files exist on disk with non-zero size.
    fn snapshot_files_exist(snapshot_path: &str, mem_file_path: &str) -> bool {
        let vmstate_ok = std::path::Path::new(snapshot_path)
            .metadata()
            .is_ok_and(|m| m.len() > 0);
        let mem_ok = std::path::Path::new(mem_file_path)
            .metadata()
            .is_ok_and(|m| m.len() > 0);
        vmstate_ok && mem_ok
    }

    /// PUT /snapshot/load — restore a VM from a full snapshot.
    ///
    /// `enable_diff_snapshots` enables copy-on-write diff snapshots after restore.
    /// Set to `false` for the common "boot from base snapshot" case.
    ///
    /// # Errors
    ///
    /// Returns an error if the Firecracker API request fails.
    pub async fn load_snapshot(
        &self,
        snapshot_path: &str,
        mem_file_path: &str,
        enable_diff_snapshots: bool,
    ) -> Result<(), VmError> {
        let body = serde_json::json!({
            "snapshot_path": snapshot_path,
            "mem_file_path": mem_file_path,
            "enable_diff_snapshots": enable_diff_snapshots,
            "resume_vm": true,
        });
        self.put("/snapshot/load", &body, SNAPSHOT_TIMEOUT_SECS)
            .await
    }

    /// Wait for the Unix socket file to appear (poll every 25 ms).
    ///
    /// # Errors
    ///
    /// Returns a timeout error if the socket does not appear within `max_wait`.
    pub async fn wait_for_socket(sock_path: &Path, max_wait: Duration) -> Result<(), VmError> {
        core_rs::poll::poll_until_exists_async(sock_path, max_wait, Duration::from_millis(25))
            .await
            .map_err(|_elapsed| {
                VmError::timeout_plain(format!(
                    "firecracker API socket did not appear within {:?}: {}",
                    max_wait,
                    sock_path.display()
                ))
            })
    }

    // ── Private helpers ────────────────────────────────────────────────────

    /// Send a PUT request with a JSON body over the Unix socket.
    async fn put(
        &self,
        path: &str,
        body: &serde_json::Value,
        timeout_secs: u64,
    ) -> Result<(), VmError> {
        self.call("PUT", path, body, timeout_secs).await
    }

    /// Send a PATCH request with a JSON body over the Unix socket.
    async fn patch(
        &self,
        path: &str,
        body: &serde_json::Value,
        timeout_secs: u64,
    ) -> Result<(), VmError> {
        self.call("PATCH", path, body, timeout_secs).await
    }

    /// Execute an HTTP request against the Firecracker API via the Unix socket.
    ///
    /// Retries with exponential backoff if the socket is not yet accepting
    /// connections (`NotFound` / `ConnectionRefused`).
    async fn call(
        &self,
        method: &str,
        path: &str,
        body: &serde_json::Value,
        timeout_secs: u64,
    ) -> Result<(), VmError> {
        let body_str = body.to_string();

        let hyper_method: hyper::Method = method
            .parse()
            .map_err(|e| VmError::FirecrackerApi(format!("invalid HTTP method {method}: {e}")))?;

        let uri: hyper::Uri = UnixUri::new(&self.sock_path, path).into();

        let request_fn = || {
            hyper::Request::builder()
                .method(hyper_method.clone())
                .uri(uri.clone())
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .body(Full::new(Bytes::from(body_str.clone())))
                .map_err(|e| VmError::FirecrackerApi(format!("build request {method} {path}: {e}")))
        };

        // Retry loop with exponential backoff for socket-not-ready errors.
        let mut last_err: Option<VmError> = None;
        for attempt in 0..=MAX_CONNECT_RETRIES {
            // Build a fresh client per attempt — hyperlocal opens a new
            // connection on each request anyway, and this avoids stale
            // connection pool state after a retry.
            let client: Client<UnixConnector, Full<Bytes>> = Client::unix();

            let request = request_fn()?;

            let result =
                tokio::time::timeout(Duration::from_secs(timeout_secs), client.request(request))
                    .await;

            match result {
                Ok(Ok(response)) => {
                    let status = response.status();
                    if status.is_success() {
                        return Ok(());
                    }
                    // Non-2xx: collect the body for diagnostics.
                    let body_bytes = response
                        .into_body()
                        .collect()
                        .await
                        .map(http_body_util::Collected::to_bytes)
                        .unwrap_or_default();
                    let body_text = String::from_utf8_lossy(&body_bytes);
                    return Err(VmError::FirecrackerApi(format!(
                        "{method} {path} returned HTTP {}: {}",
                        status.as_u16(),
                        body_text.trim()
                    )));
                }
                Ok(Err(e)) => {
                    // Connection-level error — check if retryable.
                    let err_str = e.to_string();
                    let retryable = err_str.contains("No such file or directory")
                        || err_str.contains("Connection refused")
                        || err_str.contains("connect error");
                    if retryable && attempt < MAX_CONNECT_RETRIES {
                        let wait_ms = 50u64 * (1u64 << attempt.min(4)); // 50, 100, 200, 400, 800
                        last_err = Some(VmError::FirecrackerApi(format!(
                            "connect to {}: {e}",
                            self.sock_path.display()
                        )));
                        tokio::time::sleep(Duration::from_millis(wait_ms)).await;
                        continue;
                    }
                    return Err(VmError::FirecrackerApi(format!(
                        "{method} {path} via {}: {e}",
                        self.sock_path.display()
                    )));
                }
                Err(_elapsed) => {
                    return Err(VmError::timeout_plain(format!(
                        "{method} {path} timed out after {timeout_secs}s",
                    )));
                }
            }
        }

        // All retries exhausted.
        Err(last_err.unwrap_or_else(|| {
            VmError::FirecrackerApi(format!(
                "connect to {}: max retries exceeded",
                self.sock_path.display()
            ))
        }))
    }
}

#[cfg(test)]
mod tests;
