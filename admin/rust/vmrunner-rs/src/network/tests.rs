#![cfg(test)]

use super::*;

// ── Mock slirp server ─────────────────────────────────────────────────
//
// A minimal Unix-socket server that speaks the slirp4netns JSON protocol.
// Used to test retry and cleanup_partial behavior without a real slirp.
//
// Each connection handles exactly one JSON command (slirp4netns behavior).
// The fixture wakes and joins its blocking listener before releasing the
// socket's tempdir, so no worker or request outlives the fixture.

use std::io::{Read, Write as _};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
enum MockResponse {
    Text(String),
    Raw(Vec<u8>),
}

/// A mock slirp4netns server that records all received commands.
struct MockSlirp {
    sock_path: PathBuf,
    messages: Arc<Mutex<Vec<String>>>,
    add_responses: Arc<Mutex<Vec<MockResponse>>>,
    list_responses: Arc<Mutex<Vec<String>>>,
    remove_responses: Arc<Mutex<Vec<String>>>,
    active_hostfwds: Arc<Mutex<Vec<(i64, u16, u16)>>>,
    shutdown: Arc<AtomicBool>,
    worker_exited: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl MockSlirp {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("slirp-api.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind mock slirp socket");

        let messages: Arc<Mutex<Vec<String>>> = Arc::default();
        let add_responses: Arc<Mutex<Vec<MockResponse>>> = Arc::default();
        let list_responses: Arc<Mutex<Vec<String>>> = Arc::default();
        let remove_responses: Arc<Mutex<Vec<String>>> = Arc::default();
        let active_hostfwds: Arc<Mutex<Vec<(i64, u16, u16)>>> = Arc::default();
        let shutdown: Arc<AtomicBool> = Arc::default();
        let worker_exited: Arc<AtomicBool> = Arc::default();

        let msgs = messages.clone();
        let add_resps = add_responses.clone();
        let list_resps = list_responses.clone();
        let remove_resps = remove_responses.clone();
        let active = active_hostfwds.clone();
        let stop = shutdown.clone();
        let exited = worker_exited.clone();

        let worker = std::thread::spawn(move || {
            let mut next_id = 1i64;
            while !stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                        stream.set_write_timeout(Some(Duration::from_secs(2))).ok();

                        let mut buf = Vec::new();
                        let _ = stream.read_to_end(&mut buf);
                        let request = String::from_utf8_lossy(&buf).trim().to_string();
                        if request.is_empty() {
                            continue;
                        }

                        let request_json = serde_json::from_str::<serde_json::Value>(&request).ok();
                        let execute = request_json
                            .as_ref()
                            .and_then(|v| v["execute"].as_str().map(String::from))
                            .unwrap_or_default();

                        msgs.lock().unwrap().push(execute.clone());

                        let response = match execute.as_str() {
                            "add_hostfwd" => {
                                let host_port = request_json
                                    .as_ref()
                                    .and_then(|v| v["arguments"]["host_port"].as_u64())
                                    .unwrap_or_default()
                                    as u16;
                                let guest_port = request_json
                                    .as_ref()
                                    .and_then(|v| v["arguments"]["guest_port"].as_u64())
                                    .unwrap_or_default()
                                    as u16;
                                let id = next_id;
                                next_id += 1;
                                active.lock().unwrap().push((id, host_port, guest_port));
                                let mut q = add_resps.lock().unwrap();
                                if let Some(r) = q.first().cloned() {
                                    q.remove(0);
                                    r
                                } else {
                                    MockResponse::Text(format!(r#"{{"return":{{"id":{id}}}}}"#))
                                }
                            }
                            "remove_hostfwd" => {
                                let mut q = remove_resps.lock().unwrap();
                                let response = if q.is_empty() {
                                    r#"{"return":{}}"#.to_string()
                                } else {
                                    q.remove(0)
                                };
                                let removal_succeeded =
                                    serde_json::from_str::<serde_json::Value>(&response)
                                        .ok()
                                        .is_some_and(|value| {
                                            value.get("error").is_none()
                                                && value
                                                    .get("return")
                                                    .is_some_and(serde_json::Value::is_object)
                                        });
                                if removal_succeeded {
                                    if let Some(id) = request_json
                                        .as_ref()
                                        .and_then(|v| v["arguments"]["id"].as_i64())
                                    {
                                        active
                                            .lock()
                                            .unwrap()
                                            .retain(|(entry_id, _, _)| *entry_id != id);
                                    }
                                }
                                MockResponse::Text(response)
                            }
                            "list_hostfwd" => {
                                let mut q = list_resps.lock().unwrap();
                                if let Some(r) = q.first().cloned() {
                                    q.remove(0);
                                    MockResponse::Text(r)
                                } else {
                                    let entries: Vec<serde_json::Value> = active
                                        .lock()
                                        .unwrap()
                                        .iter()
                                        .map(|(id, host_port, guest_port)| {
                                            serde_json::json!({
                                                "id": id,
                                                "host_port": host_port,
                                                "guest_port": guest_port,
                                            })
                                        })
                                        .collect();
                                    MockResponse::Text(
                                        serde_json::json!({"entries": entries}).to_string(),
                                    )
                                }
                            }
                            _ => MockResponse::Text(r#"{"error":{"desc":"unknown"}}"#.to_string()),
                        };

                        match response {
                            MockResponse::Text(response) => {
                                let _ = stream.write_all(response.as_bytes());
                            }
                            MockResponse::Raw(response) => {
                                let _ = stream.write_all(&response);
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            exited.store(true, Ordering::Release);
        });

        MockSlirp {
            sock_path,
            messages,
            add_responses,
            list_responses,
            remove_responses,
            active_hostfwds,
            shutdown,
            worker_exited,
            worker: Some(worker),
            _dir: dir,
        }
    }

    fn queue_add_response(&self, response: &str) {
        self.add_responses
            .lock()
            .unwrap()
            .push(MockResponse::Text(response.to_string()));
    }

    fn queue_add_raw_response(&self, response: &[u8]) {
        self.add_responses
            .lock()
            .unwrap()
            .push(MockResponse::Raw(response.to_vec()));
    }

    fn queue_list_response(&self, response: &str) {
        self.list_responses
            .lock()
            .unwrap()
            .push(response.to_string());
    }

    fn queue_remove_response(&self, response: &str) {
        self.remove_responses
            .lock()
            .unwrap()
            .push(response.to_string());
    }

    fn active_hostfwd_count(&self) -> usize {
        self.active_hostfwds.lock().unwrap().len()
    }

    fn received_commands(&self) -> Vec<String> {
        self.messages.lock().unwrap().clone()
    }
}

impl Drop for MockSlirp {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        // Wake the blocking accept. The server treats this empty
        // connection as a no-op, observes shutdown on its next loop, and
        // exits before the TempDir unlinks the socket path.
        drop(std::os::unix::net::UnixStream::connect(&self.sock_path));
        if let Some(worker) = self.worker.take() {
            worker.join().expect("mock slirp server thread panicked");
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[test]
fn quick_variant_cleans_partial_on_retry() {
    // Verify that slirp_add_hostfwd_quick (cleanup_partial=true) calls
    // list_hostfwd (part of remove_hostfwd) between retries when
    // add_hostfwd fails with the phantom-binding error.
    let mock = MockSlirp::new();

    // First add_hostfwd → fail with the phantom error
    mock.queue_add_response(
        r#"{"error":{"desc":"bad request: add_hostfwd: slirp_add_hostfwd failed"}}"#,
    );
    // After cleanup (list+remove), the retry succeeds
    // (no more queued responses → default success)

    let result = slirp_add_hostfwd_quick(&mock.sock_path, 22999, 22);
    assert!(result.is_ok(), "should succeed after retry: {result:?}");

    let cmds = mock.received_commands();
    // Expected: add_hostfwd → list_hostfwd (cleanup) → add_hostfwd (retry)
    assert!(
        cmds.contains(&"list_hostfwd".to_string()),
        "cleanup_partial should call list_hostfwd between retries; got: {cmds:?}"
    );
    assert!(
        cmds.iter().filter(|c| *c == "add_hostfwd").count() >= 2,
        "should retry add_hostfwd at least once; got: {cmds:?}"
    );
    assert!(
        cmds.contains(&"remove_hostfwd".to_string()),
        "retry must remove the applied partial mapping before adding again; got: {cmds:?}"
    );
}

#[test]
fn full_variant_cleans_partial_on_retry() {
    // Verify slirp_add_hostfwd (the non-quick variant) also cleans up.
    let mock = MockSlirp::new();
    mock.queue_add_response(
        r#"{"error":{"desc":"bad request: add_hostfwd: slirp_add_hostfwd failed"}}"#,
    );

    let result = slirp_add_hostfwd(&mock.sock_path, 22998, 22);
    assert!(result.is_ok(), "should succeed after retry: {result:?}");

    let cmds = mock.received_commands();
    assert!(
        cmds.contains(&"list_hostfwd".to_string()),
        "cleanup_partial should call list_hostfwd; got: {cmds:?}"
    );
    assert!(
        cmds.contains(&"remove_hostfwd".to_string()),
        "cleanup_partial should remove the applied partial mapping; got: {cmds:?}"
    );
}

#[test]
fn add_hostfwd_retries_empty_response() {
    let mock = MockSlirp::new();
    mock.queue_add_response("");

    let result = slirp_add_hostfwd_quick(&mock.sock_path, 22995, 22);
    assert_eq!(result.unwrap(), 2, "empty response must not be success");

    let cmds = mock.received_commands();
    assert!(
        cmds.iter().filter(|c| *c == "add_hostfwd").count() >= 2,
        "empty response should trigger an add_hostfwd retry; got: {cmds:?}"
    );
    assert!(
        cmds.contains(&"remove_hostfwd".to_string()),
        "empty response must be reconciled before retry; got: {cmds:?}"
    );
    assert_eq!(
        mock.active_hostfwd_count(),
        1,
        "cleanup must leave only the successful retry binding"
    );
}

#[test]
fn add_hostfwd_retries_read_error_after_verified_cleanup() {
    let mock = MockSlirp::new();
    mock.queue_add_raw_response(&[0xff]);

    let result = slirp_add_hostfwd_quick(&mock.sock_path, 22994, 22);
    assert_eq!(
        result.unwrap(),
        2,
        "read error must retry only after cleanup"
    );

    let cmds = mock.received_commands();
    assert_eq!(
        cmds.iter().filter(|c| *c == "add_hostfwd").count(),
        2,
        "read error should cause exactly one retry; got: {cmds:?}"
    );
    assert!(
        cmds.contains(&"remove_hostfwd".to_string()),
        "read error must be reconciled before retry; got: {cmds:?}"
    );
}

#[test]
fn add_hostfwd_retries_malformed_response_after_verified_cleanup() {
    let mock = MockSlirp::new();
    mock.queue_add_response(r#"{"return":{"id":"not-an-id"}}"#);

    let result = slirp_add_hostfwd_quick(&mock.sock_path, 22993, 22);
    assert_eq!(
        result.unwrap(),
        2,
        "malformed response must retry after cleanup"
    );

    let cmds = mock.received_commands();
    assert_eq!(
        cmds.iter().filter(|c| *c == "add_hostfwd").count(),
        2,
        "malformed response should cause exactly one retry; got: {cmds:?}"
    );
    assert!(
        cmds.contains(&"remove_hostfwd".to_string()),
        "malformed response must be reconciled before retry; got: {cmds:?}"
    );
}

#[test]
fn add_hostfwd_refuses_retry_when_cleanup_list_fails() {
    let mock = MockSlirp::new();
    mock.queue_add_response("");
    for _ in 0..6 {
        mock.queue_list_response("not json");
    }

    let result = slirp_add_hostfwd_quick(&mock.sock_path, 22992, 22);
    assert!(
        result.is_err(),
        "ambiguous add must fail when cleanup cannot be verified"
    );
    assert!(
        matches!(&result, Err(VmError::HostfwdUncertain(_))),
        "unverified cleanup must be a typed uncertain-hostfwd outcome: {result:?}"
    );

    let cmds = mock.received_commands();
    assert_eq!(
        cmds.iter().filter(|c| *c == "add_hostfwd").count(),
        1,
        "cleanup failure must prevent a second add; got: {cmds:?}"
    );
    assert_eq!(
        mock.active_hostfwd_count(),
        1,
        "unverified cleanup must be handed to the VM teardown path, not treated as an empty state"
    );
}

#[test]
fn add_hostfwd_refuses_retry_when_cleanup_remove_fails() {
    let mock = MockSlirp::new();
    mock.queue_add_response("");
    for _ in 0..3 {
        mock.queue_remove_response(r#"{"error":{"desc":"remove failed"}}"#);
    }

    let result = slirp_add_hostfwd_quick(&mock.sock_path, 22991, 22);
    assert!(
        result.is_err(),
        "ambiguous add must fail when removal cannot be verified"
    );
    assert!(
        matches!(&result, Err(VmError::HostfwdUncertain(_))),
        "unverified removal must be a typed uncertain-hostfwd outcome: {result:?}"
    );

    let cmds = mock.received_commands();
    assert_eq!(
        cmds.iter().filter(|c| *c == "add_hostfwd").count(),
        1,
        "removal failure must prevent a second add; got: {cmds:?}"
    );
    assert_eq!(
        mock.active_hostfwd_count(),
        1,
        "unverified removal must be handed to the VM teardown path, not treated as an empty state"
    );
}

#[test]
fn add_hostfwd_refuses_retry_when_direct_list_error_has_entries() {
    let mock = MockSlirp::new();
    mock.queue_add_response("");
    for _ in 0..6 {
        mock.queue_list_response(r#"{"error":{"desc":"list failed"},"entries":[]}"#);
    }

    let result = slirp_add_hostfwd_quick(&mock.sock_path, 22990, 22);
    assert!(
        result.is_err(),
        "ambiguous direct list error must not permit a retry"
    );
    let cmds = mock.received_commands();
    assert_eq!(
        cmds.iter().filter(|c| *c == "add_hostfwd").count(),
        1,
        "direct list error must prevent a second add; got: {cmds:?}"
    );
}

#[test]
fn add_hostfwd_refuses_retry_when_wrapped_list_error_has_entries() {
    let mock = MockSlirp::new();
    mock.queue_add_response("");
    for _ in 0..6 {
        mock.queue_list_response(r#"{"return":{"error":{"desc":"list failed"},"entries":[]}}"#);
    }

    let result = slirp_add_hostfwd_quick(&mock.sock_path, 22989, 22);
    assert!(
        result.is_err(),
        "ambiguous wrapped list error must not permit a retry"
    );
    let cmds = mock.received_commands();
    assert_eq!(
        cmds.iter().filter(|c| *c == "add_hostfwd").count(),
        1,
        "wrapped list error must prevent a second add; got: {cmds:?}"
    );
}

#[test]
fn add_hostfwd_refuses_retry_when_list_formats_are_combined() {
    let mock = MockSlirp::new();
    mock.queue_add_response("");
    for _ in 0..6 {
        mock.queue_list_response(
            r#"{"entries":[],"return":{"entries":[{"id":1,"host_port":22999,"guest_port":22}]}}"#,
        );
    }

    let result = slirp_add_hostfwd_quick(&mock.sock_path, 22988, 22);
    assert!(
        result.is_err(),
        "combined list formats must not permit a retry"
    );
    let cmds = mock.received_commands();
    assert_eq!(
        cmds.iter().filter(|c| *c == "add_hostfwd").count(),
        1,
        "combined list formats must prevent a second add; got: {cmds:?}"
    );
}

#[test]
fn add_hostfwd_succeeds_on_first_try() {
    // Happy path: no retries needed.
    let mock = MockSlirp::new();
    let result = slirp_add_hostfwd_quick(&mock.sock_path, 22997, 22);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1); // first auto-assigned ID

    let cmds = mock.received_commands();
    assert_eq!(cmds, vec!["add_hostfwd"]);
}

#[test]
fn mock_slirp_drop_waits_for_server_exit() {
    let mock = MockSlirp::new();
    let worker_exited = mock.worker_exited.clone();

    assert!(
        !worker_exited.load(Ordering::Acquire),
        "new mock server must still be running"
    );
    drop(mock);
    assert!(
        worker_exited.load(Ordering::Acquire),
        "fixture teardown must join its mock server before returning"
    );
}

#[test]
fn mock_slirp_waits_for_request_bytes_after_accept() {
    let mock = MockSlirp::new();
    let mut stream =
        std::os::unix::net::UnixStream::connect(&mock.sock_path).expect("connect to mock slirp");

    // A listener configured non-blocking can pass that mode to accepted
    // streams. The mock must wait for this write rather than treating the
    // transient WouldBlock as an empty request and forcing a retry.
    std::thread::sleep(Duration::from_millis(30));
    stream
        .write_all(br#"{"execute":"add_hostfwd","arguments":{"host_port":22997,"guest_port":22}}"#)
        .expect("write request");
    stream.shutdown(Shutdown::Write).expect("finish request");

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read mock response");
    assert_eq!(response, r#"{"return":{"id":1}}"#);
    assert_eq!(mock.received_commands(), vec!["add_hostfwd"]);
}

#[test]
fn add_hostfwd_returns_error_on_non_transient_failure() {
    // A non-transient error (not "slirp_add_hostfwd failed") should
    // return immediately without retries, but only after proving that the
    // request did not leave a mapping behind.
    let mock = MockSlirp::new();
    mock.queue_add_response(r#"{"error":{"desc":"some permanent error"}}"#);

    let result = slirp_add_hostfwd_quick(&mock.sock_path, 22996, 22);
    assert!(result.is_err(), "should fail on non-transient error");

    let cmds = mock.received_commands();
    assert_eq!(
        cmds.iter().filter(|c| *c == "add_hostfwd").count(),
        1,
        "should not retry on non-transient error: {cmds:?}"
    );
    assert!(
        cmds.contains(&"remove_hostfwd".to_string()),
        "must reconcile a non-transient error before returning: {cmds:?}"
    );
    assert_eq!(
        mock.active_hostfwd_count(),
        0,
        "permanent add error must reconcile the mapping before returning"
    );
}

#[test]
fn add_hostfwd_non_transient_error_without_verified_cleanup_is_uncertain() {
    let mock = MockSlirp::new();
    mock.queue_add_response(r#"{"error":{"desc":"some permanent error"}}"#);
    for _ in 0..6 {
        mock.queue_list_response("not json");
    }

    let result = slirp_add_hostfwd_quick(&mock.sock_path, 22985, 22);
    assert!(
        matches!(result, Err(VmError::HostfwdUncertain(_))),
        "unverified permanent error must be handed to teardown: {result:?}"
    );
    assert_eq!(
        mock.active_hostfwd_count(),
        1,
        "unverified cleanup must not be represented as an ordinary permanent error"
    );
}

#[test]
fn add_hostfwd_rejects_duplicate_return_members() {
    let mock = MockSlirp::new();
    mock.queue_add_response(r#"{"return":{"error":{"desc":"failed"}},"return":{"id":1}}"#);
    mock.queue_add_response(r#"{"error":{"desc":"some permanent error"}}"#);

    let result = slirp_add_hostfwd_quick(&mock.sock_path, 22984, 22);
    assert!(
        result.is_err(),
        "duplicate response members must not be accepted"
    );
    let cmds = mock.received_commands();
    assert!(
        cmds.contains(&"remove_hostfwd".to_string()),
        "duplicate response must be reconciled before retry or failure: {cmds:?}"
    );
    assert_eq!(
        mock.active_hostfwd_count(),
        0,
        "duplicate response must be reconciled before the final error"
    );
}

#[test]
fn add_hostfwd_rejects_error_with_return_id() {
    for response in [
        r#"{"error":{"desc":"failed"},"return":{"id":1}}"#,
        r#"{"\u0065rror":{"desc":"failed"},"return":{"id":1}}"#,
    ] {
        let mock = MockSlirp::new();
        mock.queue_add_response(response);

        let result = slirp_add_hostfwd_quick(&mock.sock_path, 22987, 22);
        assert!(result.is_err(), "error response must not become success");
        let cmds = mock.received_commands();
        assert_eq!(
            cmds.iter().filter(|c| *c == "add_hostfwd").count(),
            1,
            "error response must not trigger a second add; got: {cmds:?}"
        );
        assert!(
            cmds.contains(&"remove_hostfwd".to_string()),
            "error response with an id must be reconciled; got: {cmds:?}"
        );
        assert_eq!(
            mock.active_hostfwd_count(),
            0,
            "error response with an id must not leave a hostfwd active"
        );
    }
}

#[test]
fn parse_hostfwd_id_from_return() {
    assert_eq!(parse_hostfwd_id(r#"{"return":{"id": 42}}"#), 42);
}

#[test]
fn parse_hostfwd_id_missing() {
    assert_eq!(parse_hostfwd_id("{}"), -1);
    assert_eq!(parse_hostfwd_id("garbage"), -1);
    assert_eq!(parse_hostfwd_id(""), -1);
}

#[test]
fn parse_hostfwd_id_rejects_error_with_return() {
    assert_eq!(
        parse_hostfwd_id(r#"{"error":{"desc":"failed"},"return":{"id":1}}"#),
        -1
    );
    assert_eq!(
        parse_hostfwd_id(r#"{"\u0065rror":{"desc":"failed"},"return":{"id":1}}"#),
        -1
    );
}

#[test]
fn parse_list_direct_format() {
    // slirp4netns actual format: {"entries":[...]}
    let response = r#"{"entries":[
            {"id":0,"proto":"tcp","host_addr":"127.0.0.1","host_port":22003,"guest_addr":"10.0.2.100","guest_port":22},
            {"id":1,"proto":"tcp","host_addr":"127.0.0.1","host_port":18800,"guest_addr":"10.0.2.100","guest_port":18800}
        ]}"#;
    let result = parse_list_hostfwd_response(response).expect("valid direct list response");
    assert_eq!(result.len(), 2);
    assert_eq!(result[0], (0, 22003, 22));
    assert_eq!(result[1], (1, 18800, 18800));
}

#[test]
fn parse_list_wrapped_format() {
    // Alternative format: {"return":{"entries":[...]}}
    let response = r#"{"return":{"entries":[{"id":5,"proto":"tcp","host_addr":"127.0.0.1","host_port":22006,"guest_addr":"10.0.2.100","guest_port":22}]}}"#;
    let result = parse_list_hostfwd_response(response).expect("valid wrapped list response");
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], (5, 22006, 22));
}

#[test]
fn parse_list_empty_entries() {
    let response = r#"{"entries":[]}"#;
    assert!(
        parse_list_hostfwd_response(response)
            .expect("valid empty list response")
            .is_empty()
    );
}

#[test]
fn parse_list_invalid_json() {
    assert!(parse_list_hostfwd_response("not json").is_err());
    assert!(parse_list_hostfwd_response("").is_err());
    assert!(parse_list_hostfwd_response("{}").is_err());
}

#[test]
fn parse_list_error_with_entries_is_rejected() {
    assert!(
        parse_list_hostfwd_response(r#"{"error":{"desc":"list failed"},"entries":[]}"#).is_err()
    );
    assert!(
        parse_list_hostfwd_response(r#"{"return":{"error":{"desc":"list failed"},"entries":[]}}"#)
            .is_err()
    );
}

#[test]
fn parse_list_combined_formats_are_rejected() {
    assert!(parse_list_hostfwd_response(r#"{"entries":[],"return":{"entries":[]}}"#).is_err());
}
