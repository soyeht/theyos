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
/// unreadable responses are retried and eventually returned as errors. If a
/// cleanup cannot be verified after an ambiguous response, the error is
/// `VmError::HostfwdUncertain`; the owning VM must not be reused.
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

        let value = match parse_json_without_duplicate_keys(&response) {
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
            let reported_id = hostfwd_id_for_cleanup(&value);
            let cleanup_verified = if cleanup_partial_on_retry {
                if let Some(fwd_id) = reported_id {
                    slirp_remove_hostfwd_verified(api_sock, host_port, guest_port, fwd_id)
                } else {
                    ensure_hostfwd_reconciled_before_retry(api_sock, host_port, guest_port).is_ok()
                }
            } else {
                false
            };
            if !cleanup_verified {
                let id_context = reported_id
                    .map(|id| format!(" with id={id}"))
                    .unwrap_or_default();
                return Err(VmError::HostfwdUncertain(format!(
                    "slirp API add_hostfwd error{id_context}; cleanup could not be verified: {response}"
                )));
            }
            // slirp4netns can briefly report this while TAP setup is still
            // completing; treat it as transient and retry with backoff.
            if error_text.contains("slirp_add_hostfwd failed") {
                last_err = format!("api: {response}");
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
        Err(VmError::HostfwdUncertain(format!(
            "slirp API add_hostfwd: refusing retry because cleanup of host_port={host_port} guest_port={guest_port} could not be verified"
        )))
    }
}

/// Deserialize a JSON response while rejecting duplicate object members.
///
/// `serde_json::Value` otherwise uses last-member-wins semantics. That would
/// let a response such as `{"return":{"error":...},"return":{"id":1}}`
/// hide an earlier error and turn an ambiguous slirp response into success.
fn parse_json_without_duplicate_keys(response: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str::<StrictJsonValue>(response)
        .map(|value| value.0)
        .map_err(|error| error.to_string())
}

struct StrictJsonValue(serde_json::Value);

impl<'de> serde::Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, SeqAccess, Visitor};

        struct StrictJsonVisitor;

        impl<'de> Visitor<'de> for StrictJsonVisitor {
            type Value = serde_json::Value;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value without duplicate object members")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(serde_json::Value::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(serde_json::Value::Number(value.into()))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(serde_json::Value::Number(value.into()))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(serde_json::Value::Number)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(serde_json::Value::String(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(serde_json::Value::String(value))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(serde_json::Value::Null)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(serde_json::Value::Null)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
                    values.push(value.0);
                }
                Ok(serde_json::Value::Array(values))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut object = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    let value = map.next_value::<StrictJsonValue>()?.0;
                    if object.insert(key.clone(), value).is_some() {
                        return Err(de::Error::custom(format!(
                            "duplicate JSON object key: {key}"
                        )));
                    }
                }
                Ok(serde_json::Value::Object(object))
            }
        }

        deserializer
            .deserialize_any(StrictJsonVisitor)
            .map(StrictJsonValue)
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

fn hostfwd_id_for_cleanup(value: &serde_json::Value) -> Option<i64> {
    value
        .get("return")
        .and_then(serde_json::Value::as_object)
        .and_then(|return_body| return_body.get("id"))
        .and_then(serde_json::Value::as_i64)
        .filter(|id| *id >= 0)
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
#[cfg(test)]
fn parse_hostfwd_id(response: &str) -> i64 {
    parse_json_without_duplicate_keys(response)
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

    let value = parse_json_without_duplicate_keys(&response).map_err(|e| {
        VmError::Other(format!(
            "slirp remove_hostfwd(id={id}) invalid response: {e}"
        ))
    })?;
    if json_error_value(&value).is_some() {
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

    let value = parse_json_without_duplicate_keys(response)
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
mod tests;
