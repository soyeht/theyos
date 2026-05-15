//! Slirp4netns API helpers and OS process/path utilities.
// NOTE: VmError is large by design (rich diagnostic context); boxing would require
// pervasive API changes across all callers.
#![allow(clippy::result_large_err)]

use std::net::Shutdown;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::VmError;

// ── Slirp API helpers ──────────────────────────────────────────────────────

/// Add a TCP port-forward via the slirp4netns API socket.
///
/// Matches: `slirp_api_exec` in `fc-agent-runtime.sh`.
///
/// Retries on transient transport errors (broken pipe, connection refused) and
/// on early slirp initialization errors (`slirp_add_hostfwd failed`) with
/// exponential back-off. slirp4netns occasionally has a brief unavailability
/// window after the API socket appears but before TAP is fully ready.
///
/// Returns the hostfwd ID assigned by slirp4netns (or -1 if the response
/// couldn't be parsed).
pub(crate) fn slirp_add_hostfwd(
    api_sock: &Path,
    host_port: u16,
    guest_port: u16,
) -> Result<i64, VmError> {
    // App-port mappings (host_port == guest_port) have shown longer
    // stabilization windows than the SSH forward in heavily loaded runs.
    let max_retries = if host_port == guest_port { 40 } else { 20 };
    // Always attempt cleanup between retries. If a previous add_hostfwd
    // partially created the mapping, subsequent retries will hit "duplicate"
    // errors from libslirp. The remove is best-effort (ignored on error).
    slirp_add_hostfwd_with_retry(
        api_sock,
        host_port,
        guest_port,
        max_retries,
        200,
        2000,
        true,
    )
}

/// Add a TCP port-forward via slirp API with a short retry window.
///
/// Used for optional/background operations where we prefer to fail fast and
/// continue without blocking the whole refill pipeline.
///
/// `cleanup_partial_on_retry` is `true` because slirp4netns processes the
/// `add_hostfwd` request **before** the client reads the response. If the
/// transport fails (broken pipe) after the slirp has already bound the port,
/// the client sees an error but the binding exists internally. Without
/// cleanup, every subsequent retry fails with `slirp_add_hostfwd failed`
/// (port already bound), and the phantom binding leaks into the warm-pool
/// entry — poisoning SSH port allocation for future claims.
#[cfg(test)]
pub(crate) fn slirp_add_hostfwd_quick(
    api_sock: &Path,
    host_port: u16,
    guest_port: u16,
) -> Result<i64, VmError> {
    slirp_add_hostfwd_with_retry(api_sock, host_port, guest_port, 8, 100, 1000, true)
}

fn slirp_add_hostfwd_with_retry(
    api_sock: &Path,
    host_port: u16,
    guest_port: u16,
    max_retries: u32,
    initial_backoff_ms: u64,
    max_backoff_ms: u64,
    cleanup_partial_on_retry: bool,
) -> Result<i64, VmError> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::thread::sleep;

    let payload = format!(
        r#"{{"execute":"add_hostfwd","arguments":{{"proto":"tcp","host_addr":"127.0.0.1","host_port":{host_port},"guest_addr":"10.0.2.100","guest_port":{guest_port}}}}}"#
    );

    let mut last_err = String::new();

    for attempt in 0..=max_retries {
        if attempt > 0 {
            let wait_ms = (initial_backoff_ms * (1u64 << (attempt - 1).min(4))).min(max_backoff_ms);
            tracing::warn!(
                "[vmrunner] slirp hostfwd attempt {attempt}/{max_retries} after {wait_ms}ms (last: {last_err})"
            );
            sleep(Duration::from_millis(wait_ms));
        }

        let mut stream = match UnixStream::connect(api_sock) {
            Ok(s) => s,
            Err(e) => {
                last_err = format!("connect: {e}");
                continue;
            }
        };

        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        // slirp4netns API uses newline-delimited JSON; the server requires
        // shutdown(SHUT_WR) after sending the request before it sends a response.
        if let Err(e) = writeln!(stream, "{payload}") {
            last_err = format!("write: {e}");
            continue;
        }
        stream.shutdown(Shutdown::Write).ok();

        let mut response = String::new();
        stream.read_to_string(&mut response).ok();

        if response.contains("\"error\"") {
            // slirp4netns can briefly report this while TAP setup is still
            // completing; treat it as transient and retry with backoff.
            if response.contains("slirp_add_hostfwd failed") {
                last_err = format!("api: {response}");
                if cleanup_partial_on_retry {
                    // Best-effort cleanup in case the previous attempt partially
                    // created this mapping and subsequent retries hit a duplicate.
                    let _ = slirp_remove_hostfwd(api_sock, host_port, guest_port);
                }
                continue;
            }
            return Err(VmError::Other(format!(
                "slirp API add_hostfwd error: {response}"
            )));
        }

        // Parse the ID from {"return":{"id": N}}
        let fwd_id = parse_hostfwd_id(&response);
        if fwd_id < 0 {
            tracing::warn!(
                "[vmrunner] slirp add_hostfwd succeeded but could not parse id from: {response}"
            );
        }
        return Ok(fwd_id);
    }

    Err(VmError::Other(format!(
        "slirp API write: failed after {max_retries} retries (last: {last_err})"
    )))
}

/// Parse `{"return":{"id": N}}` → N, or -1 on failure.
fn parse_hostfwd_id(response: &str) -> i64 {
    serde_json::from_str::<serde_json::Value>(response)
        .ok()
        .and_then(|v| v["return"]["id"].as_i64())
        .unwrap_or(-1)
}

/// Remove a TCP port-forward via the slirp4netns API socket.
///
/// Lists current hostfwd entries, finds those matching `host_port` + `guest_port`,
/// and removes each by ID (the correct API format). Best-effort: errors are
/// logged but not propagated (slirp cleans up on exit).
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn slirp_remove_hostfwd(
    api_sock: &Path,
    host_port: u16,
    guest_port: u16,
) -> Result<(), VmError> {
    let entries = slirp_list_hostfwd(api_sock);
    let matching: Vec<i64> = entries
        .iter()
        .filter(|(_, hp, gp)| *hp == host_port && *gp == guest_port)
        .map(|(id, _, _)| *id)
        .collect();

    if matching.is_empty() {
        tracing::info!(
            "[vmrunner] slirp remove_hostfwd: no entries match host_port={host_port} guest_port={guest_port}"
        );
        return Ok(());
    }

    for id in matching {
        let _ = slirp_remove_hostfwd_by_id(api_sock, id);
    }
    Ok(())
}

/// Remove a TCP port-forward and verify it was actually removed.
///
/// Unlike the best-effort `slirp_remove_hostfwd`, this function confirms
/// removal by re-listing entries after each attempt. Retries up to 3 times
/// if the entry persists. This is critical for temporary hostfwds in pool
/// fill, where a leaked port poisons subsequent `pick_ssh_port` calls.
///
/// The slirp4netns API is synchronous — `remove_hostfwd` unbinds the port
/// before returning `{"return":{}}`. The verification step guards against
/// transport-level failures (broken pipe, partial write) where we can't
/// trust the response.
pub(crate) fn slirp_remove_hostfwd_verified(
    api_sock: &Path,
    host_port: u16,
    guest_port: u16,
    fwd_id: i64,
) -> bool {
    for attempt in 0..3 {
        // Try removal by ID first (preferred), fall back to port-match.
        if fwd_id >= 0 {
            let _ = slirp_remove_hostfwd_by_id(api_sock, fwd_id);
        } else {
            let _ = slirp_remove_hostfwd(api_sock, host_port, guest_port);
        }

        // Verify: list entries and check if the port is gone.
        // The API is synchronous so no sleep is needed between remove and list.
        let remaining = slirp_list_hostfwd(api_sock);
        let still_present = remaining
            .iter()
            .any(|(_, hp, gp)| *hp == host_port && *gp == guest_port);

        if !still_present {
            if attempt > 0 {
                tracing::info!(
                    "[vmrunner] slirp remove_hostfwd_verified: port {host_port} removed after {attempt} retries"
                );
            }
            return true;
        }

        tracing::warn!(
            "[vmrunner] slirp remove_hostfwd_verified: port {host_port} still present after attempt {attempt}, retrying"
        );
        // Brief pause before retry to let any transient state settle.
        std::thread::sleep(Duration::from_millis(100));
    }

    tracing::error!(
        "[vmrunner] slirp remove_hostfwd_verified: FAILED to remove port {host_port} after 3 attempts"
    );
    false
}

/// Remove a TCP port-forward by its slirp4netns-assigned ID.
///
/// Sends `{"execute":"remove_hostfwd","arguments":{"id": N}}` — the correct
/// format expected by the slirp4netns API.
pub(crate) fn slirp_remove_hostfwd_by_id(api_sock: &Path, id: i64) -> Result<(), VmError> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let payload = format!(r#"{{"execute":"remove_hostfwd","arguments":{{"id":{id}}}}}"#);

    let mut stream = UnixStream::connect(api_sock)
        .map_err(|e| VmError::Other(format!("slirp remove_hostfwd(id={id}) connect: {e}")))?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    writeln!(stream, "{payload}")
        .map_err(|e| VmError::Other(format!("slirp remove_hostfwd(id={id}) write: {e}")))?;
    stream.shutdown(Shutdown::Write).ok();

    let mut response = String::new();
    stream.read_to_string(&mut response).ok();
    tracing::info!("[vmrunner] slirp remove_hostfwd(id={id}) response: {response}");

    if response.contains("\"error\"") {
        tracing::warn!("[vmrunner] slirp remove_hostfwd(id={id}) error: {response}");
    }
    Ok(())
}

/// List current hostfwd entries via the slirp4netns API.
///
/// Returns `Vec<(id, host_port, guest_port)>`. Returns empty vec on any error
/// (infallible — used internally by `slirp_remove_hostfwd`).
pub(crate) fn slirp_list_hostfwd(api_sock: &Path) -> Vec<(i64, u16, u16)> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let payload = r#"{"execute":"list_hostfwd"}"#;

    let Ok(mut stream) = UnixStream::connect(api_sock) else {
        return Vec::new();
    };
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    if writeln!(stream, "{payload}").is_err() {
        return Vec::new();
    }
    stream.shutdown(Shutdown::Write).ok();

    let mut response = String::new();
    stream.read_to_string(&mut response).ok();

    // Parse {"return":{"entries":[{"id":N,"proto":"tcp","host_addr":"...","host_port":N,"guest_addr":"...","guest_port":N}, ...]}}
    // Minimal parsing without serde_json: split on each "id" occurrence.
    parse_list_hostfwd_response(&response)
}

/// Parse the `list_hostfwd` response into (id, `host_port`, `guest_port`) tuples.
///
/// slirp4netns returns `{"entries":[...]}` (no `"return"` wrapper).
/// For robustness, we also accept the `{"return":{"entries":[...]}}` format
/// in case future versions change the response shape.
fn parse_list_hostfwd_response(response: &str) -> Vec<(i64, u16, u16)> {
    #[derive(serde::Deserialize)]
    struct HostfwdEntry {
        id: i64,
        host_port: u16,
        guest_port: u16,
    }

    #[derive(serde::Deserialize)]
    struct DirectResponse {
        entries: Vec<HostfwdEntry>,
    }

    #[derive(serde::Deserialize)]
    struct ReturnBody {
        entries: Vec<HostfwdEntry>,
    }

    #[derive(serde::Deserialize)]
    struct WrappedResponse {
        #[serde(rename = "return")]
        ret: ReturnBody,
    }

    let to_tuples = |entries: Vec<HostfwdEntry>| -> Vec<(i64, u16, u16)> {
        entries
            .into_iter()
            .map(|e| (e.id, e.host_port, e.guest_port))
            .collect()
    };

    // Try the actual slirp4netns format first: {"entries":[...]}
    if let Ok(r) = serde_json::from_str::<DirectResponse>(response) {
        return to_tuples(r.entries);
    }
    // Fall back to wrapped format: {"return":{"entries":[...]}}
    if let Ok(r) = serde_json::from_str::<WrappedResponse>(response) {
        return to_tuples(r.ret.entries);
    }

    Vec::new()
}

/// Wait until the slirp4netns API socket is actually ready to accept commands.
///
/// The socket file can appear before the API is ready to process requests.
/// This sends `list_hostfwd` probes every 100ms until a valid `"return"`
/// response is received.
pub(crate) fn slirp_wait_ready(api_sock: &Path, timeout: Duration) -> Result<(), VmError> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let deadline = std::time::Instant::now() + timeout;
    let payload = r#"{"execute":"list_hostfwd"}"#;
    let mut probes = 0u32;

    loop {
        probes += 1;

        if let Ok(mut stream) = UnixStream::connect(api_sock) {
            stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
            if writeln!(stream, "{payload}").is_ok() {
                stream.shutdown(Shutdown::Write).ok();
                let mut buf = [0u8; 4096];
                if let Ok(n) = stream.read(&mut buf) {
                    let response = String::from_utf8_lossy(&buf[..n]);
                    if response.contains("\"return\"") || response.contains("\"entries\"") {
                        tracing::info!(
                            "[vmrunner] slirp_wait_ready: API ready after {probes} probes"
                        );
                        return Ok(());
                    }
                }
            }
        }

        if std::time::Instant::now() >= deadline {
            return Err(VmError::Other(format!(
                "slirp API not ready after {}s ({probes} probes): {}",
                timeout.as_secs(),
                api_sock.display()
            )));
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}

// ── OS helpers ─────────────────────────────────────────────────────────────

pub(crate) fn is_pid_running(pid: u32) -> bool {
    core_rs::os::is_pid_running(pid)
}

pub(crate) fn kill_pid(pid: u32) {
    core_rs::os::kill_pid(pid);
}

pub(crate) fn kill_pgrp(pid: u32) {
    core_rs::os::kill_pgrp(pid);
}

pub(crate) fn kill_pid_force(pid: u32) {
    core_rs::os::kill_pid_force(pid);
}

pub(crate) fn reap_pid(pid: u32) {
    core_rs::os::reap_pid(pid);
}

pub(crate) fn kill_pgrp_force(pid: u32) {
    core_rs::os::kill_pgrp_force(pid);
}

pub(crate) fn resolve_slirp4netns() -> Result<String, VmError> {
    core_rs::os::resolve_slirp4netns()
        .map(|p| p.to_string_lossy().into_owned())
        .ok_or_else(|| {
            VmError::MissingBinary("slirp4netns not found (set SLIRP4NETNS_BIN)".to_string())
        })
}

pub(crate) fn which_systemctl() -> Option<String> {
    if let Ok(v) = std::env::var("SYSTEMCTL_BIN") {
        if !v.is_empty() {
            return Some(v);
        }
    }
    let candidates = [
        "/run/current-system/sw/bin/systemctl",
        "/usr/bin/systemctl",
        "/usr/local/bin/systemctl",
    ];
    for c in &candidates {
        if Path::new(c).exists() {
            return Some(c.to_string());
        }
    }
    None
}

/// Enable IP forwarding inside the network namespace of the given PID.
///
/// Required for the dual-TAP model: iptables FORWARD/MASQUERADE between
/// tap0 (slirp) and tap1 (Firecracker) need `ip_forward=1`.
///
/// Must be done from host as real root via `sudo`+`nsenter`. Writing to
/// `/proc/sys/net/ipv4/ip_forward` inside a user namespace silently fails
/// (kernel ignores writes from mapped-root in user namespaces for this sysctl).
///
/// # Errors
///
/// Returns an error if the `sudo nsenter` command cannot be spawned.
/// A non-zero exit is logged as a warning but does not return an error.
pub fn enable_ip_forward(unshare_pid: u32) -> Result<(), VmError> {
    use std::process::Command;

    let pid_str = unshare_pid.to_string();
    // Use full paths: the systemd service PATH doesn't include /run/wrappers/bin
    // (sudo) or procps (sysctl). After nsenter enters the network namespace, the
    // child process inherits nsenter's PATH which may not include sysctl. Write
    // directly via /bin/sh instead.
    let output = Command::new("/run/wrappers/bin/sudo")
        .args([
            "nsenter",
            "-t",
            &pid_str,
            "-n",
            "/bin/sh",
            "-c",
            "echo 1 > /proc/sys/net/ipv4/ip_forward",
        ])
        .output()
        .map_err(|e| {
            VmError::Other(format!(
                "enable_ip_forward: failed to run sudo nsenter: {e}"
            ))
        })?;

    if output.status.success() {
        tracing::info!("[vmrunner] ip_forward enabled for netns of pid {unshare_pid}");
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!(
            "[vmrunner] enable_ip_forward for pid {unshare_pid} failed (non-fatal): {stderr}"
        );
    }
    Ok(())
}

pub(crate) fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

pub(crate) fn claw_data_base_dir(claw_type: &str, state_dir: &Path) -> Option<PathBuf> {
    // Convention: <state_dir>/../<claw_type>-data/
    let parent = state_dir.parent()?;
    let candidate = parent.join(format!("{claw_type}-data"));
    if candidate.is_dir() {
        Some(candidate)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mock slirp server ─────────────────────────────────────────────────
    //
    // A minimal Unix-socket server that speaks the slirp4netns JSON protocol.
    // Used to test retry and cleanup_partial behavior without a real slirp.
    //
    // Each connection handles exactly one JSON command (slirp4netns behavior).
    // The server thread runs until the socket file is deleted (Drop).

    use std::io::{Read, Write as _};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    /// A mock slirp4netns server that records all received commands.
    struct MockSlirp {
        sock_path: PathBuf,
        messages: Arc<Mutex<Vec<String>>>,
        add_responses: Arc<Mutex<Vec<String>>>,
        shutdown: Arc<AtomicBool>,
        _dir: tempfile::TempDir,
    }

    impl MockSlirp {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let sock_path = dir.path().join("slirp-api.sock");
            let listener = UnixListener::bind(&sock_path).expect("bind mock slirp socket");
            // Non-blocking accept with short poll so the thread can check shutdown.
            listener.set_nonblocking(true).expect("set_nonblocking");

            let messages: Arc<Mutex<Vec<String>>> = Arc::default();
            let add_responses: Arc<Mutex<Vec<String>>> = Arc::default();
            let shutdown: Arc<AtomicBool> = Arc::default();

            let msgs = messages.clone();
            let resps = add_responses.clone();
            let stop = shutdown.clone();

            std::thread::spawn(move || {
                let mut next_id = 1i64;
                while !stop.load(Ordering::Relaxed) {
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

                            let execute = serde_json::from_str::<serde_json::Value>(&request)
                                .ok()
                                .and_then(|v| v["execute"].as_str().map(String::from))
                                .unwrap_or_default();

                            msgs.lock().unwrap().push(execute.clone());

                            let response = match execute.as_str() {
                                "add_hostfwd" => {
                                    let mut q = resps.lock().unwrap();
                                    if let Some(r) = q.first().cloned() {
                                        q.remove(0);
                                        r
                                    } else {
                                        let id = next_id;
                                        next_id += 1;
                                        format!(r#"{{"return":{{"id":{id}}}}}"#)
                                    }
                                }
                                "remove_hostfwd" => r#"{"return":{}}"#.to_string(),
                                "list_hostfwd" => r#"{"entries":[]}"#.to_string(),
                                _ => r#"{"error":{"desc":"unknown"}}"#.to_string(),
                            };

                            let _ = write!(stream, "{response}");
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            });

            MockSlirp {
                sock_path,
                messages,
                add_responses,
                shutdown,
                _dir: dir,
            }
        }

        fn queue_add_response(&self, response: &str) {
            self.add_responses
                .lock()
                .unwrap()
                .push(response.to_string());
        }

        fn received_commands(&self) -> Vec<String> {
            self.messages.lock().unwrap().clone()
        }
    }

    impl Drop for MockSlirp {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
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
    fn add_hostfwd_returns_error_on_non_transient_failure() {
        // A non-transient error (not "slirp_add_hostfwd failed") should
        // return immediately without retries.
        let mock = MockSlirp::new();
        mock.queue_add_response(r#"{"error":{"desc":"some permanent error"}}"#);

        let result = slirp_add_hostfwd_quick(&mock.sock_path, 22996, 22);
        assert!(result.is_err(), "should fail on non-transient error");

        let cmds = mock.received_commands();
        assert_eq!(
            cmds,
            vec!["add_hostfwd"],
            "should not retry on non-transient error"
        );
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
    fn parse_list_direct_format() {
        // slirp4netns actual format: {"entries":[...]}
        let response = r#"{"entries":[
            {"id":0,"proto":"tcp","host_addr":"127.0.0.1","host_port":22003,"guest_addr":"10.0.2.100","guest_port":22},
            {"id":1,"proto":"tcp","host_addr":"127.0.0.1","host_port":18800,"guest_addr":"10.0.2.100","guest_port":18800}
        ]}"#;
        let result = parse_list_hostfwd_response(response);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], (0, 22003, 22));
        assert_eq!(result[1], (1, 18800, 18800));
    }

    #[test]
    fn parse_list_wrapped_format() {
        // Alternative format: {"return":{"entries":[...]}}
        let response = r#"{"return":{"entries":[{"id":5,"proto":"tcp","host_addr":"127.0.0.1","host_port":22006,"guest_addr":"10.0.2.100","guest_port":22}]}}"#;
        let result = parse_list_hostfwd_response(response);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], (5, 22006, 22));
    }

    #[test]
    fn parse_list_empty_entries() {
        let response = r#"{"entries":[]}"#;
        assert!(parse_list_hostfwd_response(response).is_empty());
    }

    #[test]
    fn parse_list_invalid_json() {
        assert!(parse_list_hostfwd_response("not json").is_empty());
        assert!(parse_list_hostfwd_response("").is_empty());
        assert!(parse_list_hostfwd_response("{}").is_empty());
    }
}
