//! IPC client — extracted from executor-rs/src/ipc_client.rs.
//!
//! Manages a subprocess communicating over stdin/stdout JSON-RPC.
//! Includes transparent auto-respawn when the subprocess crashes.

use crate::error::{AppError, ErrorCode};
use crate::ipc::wire::{ERROR_CONTEXT_FIELD, Request};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

/// Error type for IPC client operations.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("subprocess start failed: {0}")]
    SubprocessStart(String),
    #[error("ipc error: {0}")]
    Io(String),
    #[error("call failed: {0}")]
    CallFailed(String),
    #[error("not found: {0}")]
    NotFound(String),
}

impl AppError for IpcError {
    fn code(&self) -> ErrorCode {
        match self {
            IpcError::NotFound(_) => ErrorCode::NotFound,
            _ => ErrorCode::Internal,
        }
    }
}

/// A synchronous IPC client that manages a subprocess communicating over
/// stdin/stdout JSON-RPC (one request line -> one response line).
///
/// If the subprocess crashes mid-session, the client automatically respawns
/// it with the same binary and arguments, then retries the failed call once.
pub struct IpcClient {
    child: Mutex<Child>,
    stdin: Mutex<ChildStdin>,
    stdout: Mutex<BufReader<ChildStdout>>,
    bin_path: String,
    args: Vec<String>,
    respawn_count: AtomicU32,
}

impl IpcClient {
    /// Spawn a subprocess and capture its stdin/stdout pipes.
    fn spawn_process(
        bin_path: &str,
        args: &[String],
    ) -> Result<(Child, ChildStdin, BufReader<ChildStdout>), IpcError> {
        let mut cmd = Command::new(bin_path);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd
            .spawn()
            .map_err(|e| IpcError::SubprocessStart(format!("{bin_path}: {e}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| IpcError::SubprocessStart(format!("{bin_path}: no stdin")))?;
        let stdout = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| IpcError::SubprocessStart(format!("{bin_path}: no stdout")))?,
        );
        Ok((child, stdin, stdout))
    }

    /// Spawn `bin_path` with the given `args`, wire up stdin/stdout pipes,
    /// and return an `IpcClient` ready for `call()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the subprocess cannot be spawned or its stdin/stdout
    /// pipes cannot be captured.
    pub fn start(bin_path: &str, args: &[&str]) -> Result<Self, IpcError> {
        let owned_args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (child, stdin, stdout) = Self::spawn_process(bin_path, &owned_args)?;
        Ok(Self {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(stdout),
            bin_path: bin_path.to_string(),
            args: owned_args,
            respawn_count: AtomicU32::new(0),
        })
    }

    /// Check whether an error indicates the subprocess has crashed.
    fn is_crash_error(e: &IpcError) -> bool {
        match e {
            IpcError::Io(msg) => {
                msg == "subprocess closed stdout"
                    || msg.starts_with("write:")
                    || msg.starts_with("flush:")
            }
            _ => false,
        }
    }

    /// Kill the old subprocess, spawn a fresh one, and replace the pipes.
    fn respawn(&self) -> Result<(), IpcError> {
        let mut child = self
            .child
            .lock()
            .map_err(|e| IpcError::Io(format!("child lock: {e}")))?;
        let _ = child.kill();
        let _ = child.wait();

        let (new_child, new_stdin, new_stdout) = Self::spawn_process(&self.bin_path, &self.args)?;

        {
            let mut stdin = self
                .stdin
                .lock()
                .map_err(|e| IpcError::Io(format!("stdin lock: {e}")))?;
            *stdin = new_stdin;
        }
        {
            let mut stdout = self
                .stdout
                .lock()
                .map_err(|e| IpcError::Io(format!("stdout lock: {e}")))?;
            *stdout = new_stdout;
        }

        *child = new_child;
        let count = self.respawn_count.fetch_add(1, Ordering::SeqCst) + 1;
        drop(child);

        eprintln!(
            "[ipc] subprocess crashed, respawning: {} (respawn #{})",
            self.bin_path, count
        );

        Ok(())
    }

    /// The number of times this client has respawned its subprocess.
    pub fn respawn_count(&self) -> u32 {
        self.respawn_count.load(Ordering::SeqCst)
    }

    /// Send a single JSON-RPC request (no retry).
    #[allow(clippy::needless_pass_by_value)] // consumed by Request::new
    fn call_once(&self, method: &str, params: Value) -> Result<Value, (IpcError, Option<Value>)> {
        // P2 plumb-only: build the typed envelope. `version` is left `None`, so
        // serialization is byte-identical to the legacy `{"method","params"}`.
        let req = Request::new(method, params);
        let mut line = serde_json::to_string(&req)
            .map_err(|e| (IpcError::Io(format!("serialize: {e}")), None))?;
        line.push('\n');

        {
            let mut stdin = self
                .stdin
                .lock()
                .map_err(|e| (IpcError::Io(format!("stdin lock: {e}")), None))?;
            stdin
                .write_all(line.as_bytes())
                .map_err(|e| (IpcError::Io(format!("write: {e}")), None))?;
            stdin
                .flush()
                .map_err(|e| (IpcError::Io(format!("flush: {e}")), None))?;
        }

        let mut response_line = String::new();
        {
            let mut stdout = self
                .stdout
                .lock()
                .map_err(|e| (IpcError::Io(format!("stdout lock: {e}")), None))?;
            stdout
                .read_line(&mut response_line)
                .map_err(|e| (IpcError::Io(format!("read: {e}")), None))?;
        }

        if response_line.is_empty() {
            return Err((IpcError::Io("subprocess closed stdout".to_string()), None));
        }

        let mut resp: Value = serde_json::from_str(response_line.trim())
            .map_err(|e| (IpcError::Io(format!("parse response: {e}")), None))?;

        if resp["ok"].as_bool() == Some(false) {
            let err_msg = resp["error"]
                .as_str()
                .unwrap_or("unknown error")
                .to_string();
            let ctx = resp
                .as_object_mut()
                .and_then(|m| m.remove(ERROR_CONTEXT_FIELD))
                .filter(serde_json::Value::is_object);
            let lower = err_msg.to_lowercase();
            let ipc_err = if lower.contains("not found") || lower.contains("instance not found") {
                IpcError::NotFound(err_msg)
            } else {
                IpcError::CallFailed(err_msg)
            };
            return Err((ipc_err, ctx));
        }

        // Take ownership of "result" without cloning the entire JSON tree.
        Ok(resp
            .as_object_mut()
            .and_then(|m| m.remove("result"))
            .unwrap_or(Value::Null))
    }

    /// Send a JSON-RPC request and return the `result` field of the response.
    ///
    /// Delegates to `call_with_context`, discarding the error context on failure.
    ///
    /// # Errors
    ///
    /// Returns an error if the IPC subprocess fails, returns an error response,
    /// or the communication pipe is broken.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, IpcError> {
        self.call_with_context(method, params).map_err(|(e, ctx)| {
            if let Some(ctx) = ctx {
                eprintln!("[ipc] {method}: error context discarded: {ctx}");
            }
            e
        })
    }

    /// Like `call`, but on failure also returns any `error_context` JSON
    /// attached to the response (structured diagnostic payload).
    ///
    /// If the subprocess has crashed, automatically respawns it and retries once.
    ///
    /// Returns `Ok(result)` on success.
    /// Returns `Err((IpcError, Option<error_context>))` on failure.
    ///
    /// # Errors
    ///
    /// Returns an error tuple if the IPC subprocess returns an error response,
    /// if respawn fails, or if serialization, I/O, or pipe communication fails.
    #[allow(clippy::needless_pass_by_value)] // NOTE: public API — callers pass owned Value
    pub fn call_with_context(
        &self,
        method: &str,
        params: Value,
    ) -> Result<Value, (IpcError, Option<Value>)> {
        let count_before = self.respawn_count.load(Ordering::SeqCst);
        let retry_params = params.clone();
        let result = self.call_once(method, params);

        let is_crash = matches!(&result, Err((e, _)) if Self::is_crash_error(e));
        if is_crash {
            let count_now = self.respawn_count.load(Ordering::SeqCst);
            if count_now == count_before {
                self.respawn()
                    .map_err(|re| (IpcError::Io(format!("respawn failed: {re}")), None))?;
            }
            self.call_once(method, retry_params)
        } else {
            result
        }
    }

    /// Send a Ping to verify the subprocess is alive and responsive.
    ///
    /// # Errors
    ///
    /// Returns an error if the subprocess does not respond to the ping request.
    pub fn ping(&self) -> Result<(), IpcError> {
        self.call("Ping", json!({}))?;
        Ok(())
    }
}

impl Drop for IpcClient {
    fn drop(&mut self) {
        if let Ok(child) = self.child.get_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

    /// Create a `#!/bin/sh` script that responds OK to `n` requests then exits.
    fn write_crash_after_n_ipc(dir: &Path, n: u32) -> std::path::PathBuf {
        let path = dir.join(format!("crash-after-{n}.sh"));
        let script = format!(
            "#!/bin/sh\ncount=0\nwhile IFS= read -r _l; do\n  count=$((count + 1))\n  printf '{{\"ok\":true,\"result\":{{\"pong\":true}}}}\\n'\n  if [ \"$count\" -ge {n} ]; then exit 0; fi\ndone\n"
        );
        std::fs::write(&path, script).expect("write crash script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    #[test]
    fn respawn_on_crash_recovers() {
        let dir = TempDir::new().unwrap();
        let script = write_crash_after_n_ipc(dir.path(), 1);
        let client = IpcClient::start(script.to_str().unwrap(), &[]).unwrap();

        // First call succeeds (process handles 1 request, then exits)
        client.ping().unwrap();

        // Second call triggers respawn + retry
        client.ping().unwrap();
        assert_eq!(client.respawn_count(), 1);
    }

    #[test]
    fn respawn_count_increments() {
        let dir = TempDir::new().unwrap();
        let script = write_crash_after_n_ipc(dir.path(), 2);
        let client = IpcClient::start(script.to_str().unwrap(), &[]).unwrap();

        // 6 calls with crash-after-2: respawns at calls 3 and 5
        for _ in 0..6 {
            client.ping().unwrap();
        }
        assert_eq!(client.respawn_count(), 2);
    }

    #[test]
    fn respawn_failure_returns_error() {
        let dir = TempDir::new().unwrap();
        let script = write_crash_after_n_ipc(dir.path(), 1);
        let client = IpcClient::start(script.to_str().unwrap(), &[]).unwrap();

        // First call succeeds
        client.ping().unwrap();

        // Delete the script so respawn fails
        std::fs::remove_file(&script).unwrap();

        // Second call triggers crash → respawn fails (binary gone)
        let err = client.ping().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("respawn failed"),
            "expected 'respawn failed', got: {msg}"
        );
    }

    #[test]
    fn respawn_preserves_args() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("echo-args-crash.sh");
        std::fs::write(
            &path,
            "#!/bin/sh\nARGS=\"$*\"\nIFS= read -r _l\nprintf '{\"ok\":true,\"result\":{\"args\":\"%s\"}}\\n' \"$ARGS\"\nexit 0\n",
        )
        .expect("write script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let client = IpcClient::start(path.to_str().unwrap(), &["--foo", "bar"]).unwrap();

        // First call — process responds with args then exits
        let v = client.call("Test", json!({})).unwrap();
        assert_eq!(v["args"].as_str().unwrap(), "--foo bar");

        // Second call — respawn, new process has same args
        let v = client.call("Test", json!({})).unwrap();
        assert_eq!(v["args"].as_str().unwrap(), "--foo bar");
        assert_eq!(client.respawn_count(), 1);
    }

    #[test]
    fn broken_pipe_triggers_respawn() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("broken-pipe.sh");

        // Initial script exits immediately (never reads stdin)
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let client = IpcClient::start(path.to_str().unwrap(), &[]).unwrap();

        // Wait until the child process has definitely exited (no timing guesses)
        loop {
            if client.child.lock().unwrap().try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Replace with a working script
        std::fs::write(
            &path,
            "#!/bin/sh\nwhile IFS= read -r _l; do printf '{\"ok\":true,\"result\":{\"pong\":true}}\\n'; done\n",
        )
        .unwrap();

        // Call should detect crash (broken pipe or closed stdout), respawn, retry
        client.ping().unwrap();
        assert_eq!(client.respawn_count(), 1);
    }
}
