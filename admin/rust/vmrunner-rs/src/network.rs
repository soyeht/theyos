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
/// Returns the hostfwd ID assigned by slirp4netns. Empty, malformed, or
/// unreadable responses are retried and eventually returned as errors.
pub(crate) fn slirp_add_hostfwd(
    api_sock: &Path,
    host_port: u16,
    guest_port: u16,
) -> Result<i64, VmError> {
    // App-port mappings (host_port == guest_port) have shown longer
    // stabilization windows than the SSH forward in heavily loaded runs.
    let max_retries = if host_port == guest_port { 40 } else { 20 };
    // Always attempt verified cleanup between retries. If a previous
    // add_hostfwd partially created the mapping, subsequent retries will hit
    // "duplicate" errors from libslirp; an unverified cleanup aborts instead.
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

    let payload = core_rs::guest_net::slirp_add_hostfwd_payload(host_port, guest_port);

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
            if cleanup_partial_on_retry {
                ensure_hostfwd_reconciled_before_retry(api_sock, host_port, guest_port)?;
            }
            continue;
        }
        stream.shutdown(Shutdown::Write).ok();

        let mut response = String::new();
        if let Err(e) = stream.read_to_string(&mut response) {
            last_err = format!("read: {e}");
            if cleanup_partial_on_retry {
                ensure_hostfwd_reconciled_before_retry(api_sock, host_port, guest_port)?;
            }
            continue;
        }

        if response.trim().is_empty() {
            last_err = "read: empty response".to_string();
            if cleanup_partial_on_retry {
                ensure_hostfwd_reconciled_before_retry(api_sock, host_port, guest_port)?;
            }
            continue;
        }

        let value = match serde_json::from_str::<serde_json::Value>(&response) {
            Ok(value) => value,
            Err(error) => {
                last_err = format!("api: invalid JSON response: {error}");
                if cleanup_partial_on_retry {
                    ensure_hostfwd_reconciled_before_retry(api_sock, host_port, guest_port)?;
                }
                continue;
            }
        };

        if let Some(error) = json_error_value(&value) {
            let error_text = error.to_string();
            // slirp4netns can briefly report this while TAP setup is still
            // completing; treat it as transient and retry with backoff.
            if error_text.contains("slirp_add_hostfwd failed") {
                last_err = format!("api: {response}");
                if cleanup_partial_on_retry {
                    ensure_hostfwd_reconciled_before_retry(api_sock, host_port, guest_port)?;
                }
                continue;
            }
            return Err(VmError::Other(format!(
                "slirp API add_hostfwd error: {response}"
            )));
        }

        // Parse the ID from {"return":{"id": N}} using the decoded JSON
        // value so escaped error keys cannot bypass the success check.
        match parse_hostfwd_id_value(&value) {
            Ok(fwd_id) => return Ok(fwd_id),
            Err(reason) => {
                last_err = format!("api: invalid add_hostfwd response: {reason}: {response}");
                tracing::warn!(
                    "[vmrunner] slirp add_hostfwd returned an invalid response: {response}"
                );
                if cleanup_partial_on_retry {
                    ensure_hostfwd_reconciled_before_retry(api_sock, host_port, guest_port)?;
                }
                continue;
            }
        }
    }

    Err(VmError::Other(format!(
        "slirp API write: failed after {max_retries} retries (last: {last_err})"
    )))
}

/// Reconcile a possibly-applied add before retrying it.
///
/// An add request may be applied by slirp4netns before the client observes an
/// empty, malformed, or failed response. Retrying without a valid list/remove
/// cycle can leave the old binding in place or create a duplicate. Refuse to
/// retry unless the matching mapping is absent from a successful list response.
fn ensure_hostfwd_reconciled_before_retry(
    api_sock: &Path,
    host_port: u16,
    guest_port: u16,
) -> Result<(), VmError> {
    if slirp_remove_hostfwd_verified(api_sock, host_port, guest_port, -1) {
        Ok(())
    } else {
        Err(VmError::Other(format!(
            "slirp API add_hostfwd: refusing retry because cleanup of host_port={host_port} guest_port={guest_port} could not be verified"
        )))
    }
}

fn json_error_value(value: &serde_json::Value) -> Option<&serde_json::Value> {
    value.get("error").or_else(|| {
        value
            .get("return")
            .and_then(serde_json::Value::as_object)
            .and_then(|return_body| return_body.get("error"))
    })
}

fn parse_hostfwd_id_value(value: &serde_json::Value) -> Result<i64, &'static str> {
    let return_body = value
        .get("return")
        .and_then(serde_json::Value::as_object)
        .ok_or("missing return object")?;
    if return_body.contains_key("error") {
        return Err("return object contains an error");
    }
    let id = return_body
        .get("id")
        .and_then(serde_json::Value::as_i64)
        .ok_or("missing integer return id")?;
    if id < 0 {
        return Err("return id is negative");
    }
    Ok(id)
}

/// Parse `{"return":{"id": N}}` → N, or -1 on failure.
fn parse_hostfwd_id(response: &str) -> i64 {
    serde_json::from_str::<serde_json::Value>(response)
        .ok()
        .and_then(|value| {
            if json_error_value(&value).is_some() {
                None
            } else {
                parse_hostfwd_id_value(&value).ok()
            }
        })
        .unwrap_or(-1)
}

/// Remove a TCP port-forward via the slirp4netns API socket.
///
/// Lists current hostfwd entries, finds those matching `host_port` + `guest_port`,
/// removes each by ID (the correct API format), and verifies a valid follow-up
/// list response contains no matching entry. Transport and response errors are
/// propagated so callers cannot mistake an unverified cleanup for success.
pub(crate) fn slirp_remove_hostfwd(
    api_sock: &Path,
    host_port: u16,
    guest_port: u16,
) -> Result<(), VmError> {
    let entries = slirp_list_hostfwd(api_sock)?;
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
        slirp_remove_hostfwd_by_id(api_sock, id)?;
    }

    let remaining = slirp_list_hostfwd(api_sock)?;
    if remaining
        .iter()
        .any(|(_, hp, gp)| *hp == host_port && *gp == guest_port)
    {
        return Err(VmError::Other(format!(
            "slirp remove_hostfwd: matching host_port={host_port} guest_port={guest_port} remains after removal"
        )));
    }
    Ok(())
}

/// Remove a TCP port-forward and verify it was actually removed.
///
/// This function confirms
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
        let remove_result = if fwd_id >= 0 {
            slirp_remove_hostfwd_by_id(api_sock, fwd_id)
        } else {
            slirp_remove_hostfwd(api_sock, host_port, guest_port)
        };
        let remove_succeeded = remove_result.is_ok();
        if let Err(e) = remove_result {
            tracing::warn!(
                "[vmrunner] slirp remove_hostfwd_verified: cleanup attempt {attempt} failed: {e}"
            );
        }

        // Verify: list entries and check if the port is gone.
        // The API is synchronous so no sleep is needed between remove and list.
        let remaining = match slirp_list_hostfwd(api_sock) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(
                    "[vmrunner] slirp remove_hostfwd_verified: list verification failed on attempt {attempt}: {e}"
                );
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        let still_present = remaining
            .iter()
            .any(|(_, hp, gp)| *hp == host_port && *gp == guest_port);

        if remove_succeeded && !still_present {
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
    stream
        .read_to_string(&mut response)
        .map_err(|e| VmError::Other(format!("slirp remove_hostfwd(id={id}) read: {e}")))?;
    tracing::info!("[vmrunner] slirp remove_hostfwd(id={id}) response: {response}");

    let value = serde_json::from_str::<serde_json::Value>(&response).map_err(|e| {
        VmError::Other(format!(
            "slirp remove_hostfwd(id={id}) invalid response: {e}"
        ))
    })?;
    if value.get("error").is_some() {
        return Err(VmError::Other(format!(
            "slirp remove_hostfwd(id={id}) API error: {response}"
        )));
    }
    if !value
        .get("return")
        .is_some_and(serde_json::Value::is_object)
    {
        return Err(VmError::Other(format!(
            "slirp remove_hostfwd(id={id}) missing return object"
        )));
    }
    Ok(())
}

/// List current hostfwd entries via the slirp4netns API.
///
/// Returns `Vec<(id, host_port, guest_port)>` or an error for any transport or
/// response-shape failure. Cleanup must distinguish a valid empty list from a
/// failed list request; treating both as empty can falsely claim a binding was
/// removed.
pub(crate) fn slirp_list_hostfwd(api_sock: &Path) -> Result<Vec<(i64, u16, u16)>, VmError> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let payload = r#"{"execute":"list_hostfwd"}"#;

    let mut stream = UnixStream::connect(api_sock)
        .map_err(|e| VmError::Other(format!("slirp list_hostfwd connect: {e}")))?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    writeln!(stream, "{payload}")
        .map_err(|e| VmError::Other(format!("slirp list_hostfwd write: {e}")))?;
    stream.shutdown(Shutdown::Write).ok();

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| VmError::Other(format!("slirp list_hostfwd read: {e}")))?;

    parse_list_hostfwd_response(&response)
        .map_err(|e| VmError::Other(format!("slirp list_hostfwd invalid response: {e}")))
}

/// Parse the `list_hostfwd` response into (id, `host_port`, `guest_port`) tuples.
///
/// slirp4netns returns `{"entries":[...]}` (no `"return"` wrapper).
/// For robustness, we also accept the `{"return":{"entries":[...]}}` format
/// in case future versions change the response shape.
fn parse_list_hostfwd_response(response: &str) -> Result<Vec<(i64, u16, u16)>, &'static str> {
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

    let value = serde_json::from_str::<serde_json::Value>(response)
        .map_err(|_| "list_hostfwd response is not valid JSON")?;
    let top_level_error = value
        .as_object()
        .is_some_and(|object| object.contains_key("error"));
    let wrapped_error = value
        .get("return")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|object| object.contains_key("error"));
    if top_level_error || wrapped_error {
        return Err("list_hostfwd response contains an error");
    }
    let object = value
        .as_object()
        .ok_or("list_hostfwd response must be an object")?;
    let has_direct_entries = object.contains_key("entries");
    let has_wrapped_response = object.contains_key("return");
    if has_direct_entries == has_wrapped_response {
        return Err("list_hostfwd response must use exactly one format");
    }
    if has_wrapped_response
        && value
            .get("return")
            .and_then(serde_json::Value::as_object)
            .and_then(|return_body| return_body.get("entries"))
            .is_none()
    {
        return Err("wrapped list_hostfwd response is missing entries");
    }

    // Try the actual slirp4netns format first: {"entries":[...]}
    if let Ok(r) = serde_json::from_str::<DirectResponse>(response) {
        return Ok(to_tuples(r.entries));
    }
    // Fall back to wrapped format: {"return":{"entries":[...]}}
    if let Ok(r) = serde_json::from_str::<WrappedResponse>(response) {
        return Ok(to_tuples(r.ret.entries));
    }

    Err("expected direct or wrapped entries response")
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
            let add_responses: Arc<Mutex<Vec<MockResponse>>> = Arc::default();
            let list_responses: Arc<Mutex<Vec<String>>> = Arc::default();
            let remove_responses: Arc<Mutex<Vec<String>>> = Arc::default();
            let active_hostfwds: Arc<Mutex<Vec<(i64, u16, u16)>>> = Arc::default();
            let shutdown: Arc<AtomicBool> = Arc::default();

            let msgs = messages.clone();
            let add_resps = add_responses.clone();
            let list_resps = list_responses.clone();
            let remove_resps = remove_responses.clone();
            let active = active_hostfwds.clone();
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

                            let request_json =
                                serde_json::from_str::<serde_json::Value>(&request).ok();
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
                                _ => MockResponse::Text(
                                    r#"{"error":{"desc":"unknown"}}"#.to_string(),
                                ),
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
                list_responses,
                remove_responses,
                active_hostfwds,
                shutdown,
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

        let cmds = mock.received_commands();
        assert_eq!(
            cmds.iter().filter(|c| *c == "add_hostfwd").count(),
            1,
            "cleanup failure must prevent a second add; got: {cmds:?}"
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

        let cmds = mock.received_commands();
        assert_eq!(
            cmds.iter().filter(|c| *c == "add_hostfwd").count(),
            1,
            "removal failure must prevent a second add; got: {cmds:?}"
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
            parse_list_hostfwd_response(r#"{"error":{"desc":"list failed"},"entries":[]}"#)
                .is_err()
        );
        assert!(
            parse_list_hostfwd_response(
                r#"{"return":{"error":{"desc":"list failed"},"entries":[]}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn parse_list_combined_formats_are_rejected() {
        assert!(parse_list_hostfwd_response(r#"{"entries":[],"return":{"entries":[]}}"#).is_err());
    }
}
