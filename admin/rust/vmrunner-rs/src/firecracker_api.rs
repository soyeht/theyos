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
mod tests {
    use super::*;

    #[tokio::test]
    async fn wait_for_socket_missing_times_out() {
        let path = PathBuf::from("/tmp/vmrunner-test-nonexistent-fc-sock-12345.sock");
        let result = FirecrackerClient::wait_for_socket(&path, Duration::from_millis(100)).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("socket") || msg.contains("timeout") || msg.contains("Timeout"));
    }

    #[tokio::test]
    async fn wait_for_socket_existing_file_succeeds() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let result = FirecrackerClient::wait_for_socket(&path, Duration::from_millis(100)).await;
        assert!(result.is_ok());
    }

    // ── Mock Firecracker server + contract tests ───────────────────────

    use std::sync::Arc as StdArc;
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    /// A recorded HTTP request from the `FirecrackerClient`.
    #[derive(Debug, Clone)]
    struct RecordedRequest {
        method: String,
        path: String,
        content_type: Option<String>,
        body: serde_json::Value,
    }

    /// Spawn a mock HTTP server on a Unix socket that records requests
    /// and responds with a configurable status code.
    ///
    /// Returns the recorded requests after the server is dropped.
    struct MockFcServer {
        sock_path: PathBuf,
        requests: StdArc<Mutex<Vec<RecordedRequest>>>,
        _tmpdir: tempfile::TempDir,
    }

    impl MockFcServer {
        async fn start() -> Self {
            Self::start_with(204, String::new()).await
        }

        async fn start_with(status: u16, body: String) -> Self {
            let tmpdir = tempfile::tempdir().expect("create tmpdir");
            let sock_path = tmpdir.path().join("fc.sock");
            let requests: StdArc<Mutex<Vec<RecordedRequest>>> = StdArc::new(Mutex::new(Vec::new()));

            let listener = UnixListener::bind(&sock_path).expect("bind unix socket");

            let reqs = requests.clone();
            let resp_status = status;
            let resp_body = body.clone();

            tokio::spawn(async move {
                // Accept connections in a loop until the task is dropped.
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let reqs = reqs.clone();
                    let resp_body = resp_body.clone();

                    tokio::spawn(async move {
                        let io = hyper_util::rt::TokioIo::new(stream);

                        let service = hyper::service::service_fn(
                            move |req: hyper::Request<hyper::body::Incoming>| {
                                let reqs = reqs.clone();
                                let resp_body = resp_body.clone();

                                async move {
                                    let method = req.method().to_string();
                                    let path = req.uri().path().to_string();
                                    let content_type = req
                                        .headers()
                                        .get("content-type")
                                        .and_then(|v| v.to_str().ok())
                                        .map(String::from);

                                    let body_bytes = req
                                        .into_body()
                                        .collect()
                                        .await
                                        .map(http_body_util::Collected::to_bytes)
                                        .unwrap_or_default();
                                    let body: serde_json::Value =
                                        serde_json::from_slice(&body_bytes)
                                            .unwrap_or(serde_json::Value::Null);

                                    reqs.lock().await.push(RecordedRequest {
                                        method,
                                        path,
                                        content_type,
                                        body,
                                    });

                                    let response = hyper::Response::builder()
                                        .status(resp_status)
                                        .body(Full::new(Bytes::from(resp_body)))
                                        .unwrap();
                                    Ok::<_, hyper::Error>(response)
                                }
                            },
                        );

                        let conn = hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        );
                        let _ = conn.serve_connection(io, service).await;
                    });
                }
            });

            // Wait for socket to be ready
            for _ in 0..50 {
                if tokio::net::UnixStream::connect(&sock_path).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            MockFcServer {
                sock_path,
                requests,
                _tmpdir: tmpdir,
            }
        }

        async fn recorded(&self) -> Vec<RecordedRequest> {
            self.requests.lock().await.clone()
        }
    }

    #[tokio::test]
    async fn contract_set_machine_config() {
        let server = MockFcServer::start().await;
        let client = FirecrackerClient::new(server.sock_path.clone());

        client
            .set_machine_config(2, 512)
            .await
            .expect("should succeed");

        let reqs = server.recorded().await;
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "PUT");
        assert_eq!(reqs[0].path, "/machine-config");
        assert_eq!(reqs[0].content_type.as_deref(), Some("application/json"));
        assert_eq!(reqs[0].body["vcpu_count"], 2);
        assert_eq!(reqs[0].body["mem_size_mib"], 512);
    }

    #[tokio::test]
    async fn contract_set_boot_source() {
        let server = MockFcServer::start().await;
        let client = FirecrackerClient::new(server.sock_path.clone());

        client
            .set_boot_source("/path/to/vmlinux", "console=ttyS0")
            .await
            .expect("should succeed");

        let reqs = server.recorded().await;
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "PUT");
        assert_eq!(reqs[0].path, "/boot-source");
        assert_eq!(reqs[0].body["kernel_image_path"], "/path/to/vmlinux");
        assert_eq!(reqs[0].body["boot_args"], "console=ttyS0");
    }

    #[tokio::test]
    async fn contract_set_rootfs() {
        let server = MockFcServer::start().await;
        let client = FirecrackerClient::new(server.sock_path.clone());

        client
            .set_rootfs("/path/to/rootfs.ext4", false)
            .await
            .expect("should succeed");

        let reqs = server.recorded().await;
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "PUT");
        assert_eq!(reqs[0].path, "/drives/rootfs");
        assert_eq!(reqs[0].body["drive_id"], "rootfs");
        assert_eq!(reqs[0].body["path_on_host"], "/path/to/rootfs.ext4");
        assert_eq!(reqs[0].body["is_root_device"], true);
        assert_eq!(reqs[0].body["is_read_only"], false);
    }

    #[tokio::test]
    async fn contract_set_network_interface() {
        let server = MockFcServer::start().await;
        let client = FirecrackerClient::new(server.sock_path.clone());

        client
            .set_network_interface("eth0", "tap1", "AA:BB:CC:DD:EE:FF")
            .await
            .expect("should succeed");

        let reqs = server.recorded().await;
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "PUT");
        assert_eq!(reqs[0].path, "/network-interfaces/eth0");
        assert_eq!(reqs[0].body["iface_id"], "eth0");
        assert_eq!(reqs[0].body["host_dev_name"], "tap1");
        assert_eq!(reqs[0].body["guest_mac"], "AA:BB:CC:DD:EE:FF");
    }

    #[tokio::test]
    async fn contract_start_instance() {
        let server = MockFcServer::start().await;
        let client = FirecrackerClient::new(server.sock_path.clone());

        client.start_instance().await.expect("should succeed");

        let reqs = server.recorded().await;
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "PUT");
        assert_eq!(reqs[0].path, "/actions");
        assert_eq!(reqs[0].body["action_type"], "InstanceStart");
    }

    #[tokio::test]
    async fn contract_pause_vm() {
        let server = MockFcServer::start().await;
        let client = FirecrackerClient::new(server.sock_path.clone());

        client.pause_vm().await.expect("should succeed");

        let reqs = server.recorded().await;
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "PATCH");
        assert_eq!(reqs[0].path, "/vm");
        assert_eq!(reqs[0].body["state"], "Paused");
    }

    #[tokio::test]
    async fn contract_resume_vm() {
        let server = MockFcServer::start().await;
        let client = FirecrackerClient::new(server.sock_path.clone());

        client.resume_vm().await.expect("should succeed");

        let reqs = server.recorded().await;
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "PATCH");
        assert_eq!(reqs[0].path, "/vm");
        assert_eq!(reqs[0].body["state"], "Resumed");
    }

    #[tokio::test]
    async fn contract_load_snapshot() {
        let server = MockFcServer::start().await;
        let client = FirecrackerClient::new(server.sock_path.clone());

        client
            .load_snapshot("/snap/vmstate", "/snap/mem", false)
            .await
            .expect("should succeed");

        let reqs = server.recorded().await;
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "PUT");
        assert_eq!(reqs[0].path, "/snapshot/load");
        assert_eq!(reqs[0].body["snapshot_path"], "/snap/vmstate");
        assert_eq!(reqs[0].body["mem_file_path"], "/snap/mem");
        assert_eq!(reqs[0].body["enable_diff_snapshots"], false);
        assert_eq!(reqs[0].body["resume_vm"], true);
    }

    #[tokio::test]
    async fn contract_non_2xx_returns_error() {
        let server =
            MockFcServer::start_with(400, r#"{"fault_message": "Invalid request"}"#.to_string())
                .await;
        let client = FirecrackerClient::new(server.sock_path.clone());

        let result = client.start_instance().await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("400"),
            "should include HTTP status: {err_msg}"
        );
        assert!(
            err_msg.contains("Invalid request"),
            "should include error body: {err_msg}"
        );
    }

    #[tokio::test]
    async fn contract_socket_not_found_returns_error() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let bogus = tmpdir.path().join("nonexistent.sock");
        let client = FirecrackerClient::new(bogus.clone());

        let result = client.start_instance().await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        // Error should reference the socket path or connection failure.
        assert!(
            err_msg.contains("nonexistent.sock")
                || err_msg.contains("connect")
                || err_msg.contains("No such file"),
            "error should mention socket path: {err_msg}"
        );
    }
}
