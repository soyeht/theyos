#![cfg(test)]

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
                                let body: serde_json::Value = serde_json::from_slice(&body_bytes)
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
        MockFcServer::start_with(400, r#"{"fault_message": "Invalid request"}"#.to_string()).await;
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
