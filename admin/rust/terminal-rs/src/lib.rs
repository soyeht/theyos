//! terminal-rs — Rust implementation of the theyOS terminal manager.
//!
//! Provides two independent subsystems:
//!
//! 1. **Session manager** (`Manager`) — pure in-memory session/history management
//!    with a 400-line cap. Used for `RunCommand` / `GetSessionHistory` etc.
//!
//! 2. **PTY manager** (`pty` module) — real OS PTY via `pty-process`. Owns
//!    the master fd, a 200 KB ring buffer, and a broadcast channel for subscribers.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TerminalError {
    #[error("container not found")]
    ContainerNotFound,
    #[error("{0}")]
    Other(String),
}

impl core_rs::error::AppError for TerminalError {
    fn code(&self) -> core_rs::error::ErrorCode {
        match self {
            TerminalError::ContainerNotFound => core_rs::error::ErrorCode::NotFound,
            TerminalError::Other(_) => core_rs::error::ErrorCode::Internal,
        }
    }
}

// ─── Executor trait ──────────────────────────────────────────────────────────

/// Result of executing a command inside a container.
pub struct ExecResult {
    pub output: String,
    pub exit_code: i32,
}

/// Trait for executing commands inside containers.
/// The IPC binary provides a real implementation; tests use a mock.
pub trait Executor: Send + Sync {
    /// Execute a command inside the given container.
    ///
    /// # Errors
    ///
    /// Returns an error if the container is not found or the command fails.
    fn exec(&self, container: &str, command: &str) -> Result<ExecResult, TerminalError>;
}

/// No-op executor that always returns an error. Used when no real executor is
/// configured (e.g. library-only usage without the IPC binary).
pub struct NoopExecutor;

impl Executor for NoopExecutor {
    fn exec(&self, _container: &str, _command: &str) -> Result<ExecResult, TerminalError> {
        Err(TerminalError::Other("no executor configured".to_string()))
    }
}

/// Mock executor for testing — returns a fixed output and exit code.
pub struct MockExecutor {
    pub output: Mutex<String>,
    pub exit_code: Mutex<i32>,
}

impl MockExecutor {
    #[must_use]
    pub fn new(output: &str, exit_code: i32) -> Self {
        MockExecutor {
            output: Mutex::new(output.to_string()),
            exit_code: Mutex::new(exit_code),
        }
    }

    /// Update the mock output and exit code.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn set(&self, output: &str, exit_code: i32) {
        *self.output.lock().expect("MockExecutor mutex") = output.to_string();
        *self.exit_code.lock().expect("MockExecutor mutex") = exit_code;
    }
}

impl Executor for MockExecutor {
    fn exec(&self, _container: &str, _command: &str) -> Result<ExecResult, TerminalError> {
        Ok(ExecResult {
            output: self.output.lock().expect("MockExecutor mutex").clone(),
            exit_code: *self.exit_code.lock().expect("MockExecutor mutex"),
        })
    }
}

// ─── Session ─────────────────────────────────────────────────────────────────

const HISTORY_CAP: usize = 400;

struct Session {
    history: Vec<String>,
}

impl Session {
    fn new() -> Self {
        Session {
            history: Vec::with_capacity(128),
        }
    }

    fn append_line(&mut self, line: &str) {
        let line = line.trim_end_matches('\n');
        self.history.push(line.to_string());
        if self.history.len() > HISTORY_CAP {
            let excess = self.history.len() - HISTORY_CAP;
            self.history.drain(..excess);
        }
    }

    fn reset_history(&mut self) {
        self.history.clear();
    }
}

// ─── Manager ─────────────────────────────────────────────────────────────────

struct Inner {
    containers: BTreeSet<String>,
    sessions: HashMap<String, Session>,
}

pub struct Manager {
    inner: Mutex<Inner>,
    executor: Box<dyn Executor>,
}

fn session_key(container: &str, session_id: &str) -> String {
    if session_id.is_empty() {
        container.to_string()
    } else {
        format!("{container}::{session_id}")
    }
}

impl Manager {
    /// Lock the inner state, converting a `PoisonError` to `TerminalError::Other`.
    fn lock_inner(&self) -> Result<std::sync::MutexGuard<'_, Inner>, TerminalError> {
        self.inner
            .lock()
            .map_err(|_| TerminalError::Other("mutex poisoned".into()))
    }

    /// Create a new Manager with the given executor and initial containers.
    #[must_use]
    pub fn new(executor: Box<dyn Executor>, containers: &[&str]) -> Self {
        let mut inner = Inner {
            containers: BTreeSet::new(),
            sessions: HashMap::new(),
        };
        for &c in containers {
            let c = c.trim();
            if c.is_empty() {
                continue;
            }
            inner.containers.insert(c.to_string());
            ensure_session_inner(&mut inner, c, "");
        }
        Manager {
            inner: Mutex::new(inner),
            executor,
        }
    }

    /// Create a new Manager with no executor and no initial containers.
    #[must_use]
    pub fn new_empty() -> Self {
        Manager::new(Box::new(NoopExecutor), &[])
    }

    /// Create a new Manager with a mock executor and no initial containers.
    #[must_use]
    pub fn new_with_mock(output: &str, exit_code: i32) -> Self {
        Manager::new(Box::new(MockExecutor::new(output, exit_code)), &[])
    }

    pub fn ensure_container(&self, container: &str) {
        let container = container.trim();
        if container.is_empty() {
            return;
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.containers.insert(container.to_string());
        ensure_session_inner(&mut inner, container, "");
    }

    pub fn remove_container(&self, container: &str) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.containers.remove(container);
        // Remove all sessions for this container
        let keys_to_remove: Vec<String> = inner
            .sessions
            .keys()
            .filter(|k| *k == container || k.starts_with(&format!("{container}::")))
            .cloned()
            .collect();
        for key in keys_to_remove {
            inner.sessions.remove(&key);
        }
    }

    pub fn list_containers(&self) -> Vec<String> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.containers.iter().cloned().collect()
    }

    pub fn has_container(&self, container: &str) -> bool {
        let container = container.trim();
        if container.is_empty() {
            return false;
        }
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.containers.contains(container)
    }

    /// Run a command in a terminal session.
    ///
    /// # Errors
    ///
    /// Returns an error if the container is not found, the mutex is poisoned,
    /// or command execution fails.
    pub fn run_command(
        &self,
        container: &str,
        session_id: &str,
        user: &str,
        command: &str,
    ) -> Result<(), TerminalError> {
        let command = command.trim();
        if command.is_empty() {
            // Ensure session exists (validates container) but do nothing else
            let mut inner = self.lock_inner()?;
            ensure_session_checked(&mut inner, container, session_id)?;
            return Ok(());
        }

        // Append the command echo line
        {
            let mut inner = self.lock_inner()?;
            let session = ensure_session_checked(&mut inner, container, session_id)?;
            session.append_line(&format!("{user}@{container}:~$ {command}"));
        }

        if command == "clear" {
            let mut inner = self.lock_inner()?;
            let key = session_key(container, session_id);
            if let Some(session) = inner.sessions.get_mut(&key) {
                session.reset_history();
                session.append_line(&format!("[ok] cleared terminal {container}"));
                session.append_line("soyeht@local:~$ ");
            }
            return Ok(());
        }

        // Execute the command via the injected executor
        let result = self.executor.exec(container, command)?;

        let mut inner = self.lock_inner()?;
        let key = session_key(container, session_id);
        if let Some(session) = inner.sessions.get_mut(&key) {
            append_output_lines(session, &result.output);
            if result.exit_code != 0 {
                session.append_line(&format!("[exit {}]", result.exit_code));
            }
            session.append_line("soyeht@local:~$ ");
        }

        Ok(())
    }

    /// Restart a terminal session, appending a restart marker to the history.
    ///
    /// # Errors
    ///
    /// Returns an error if the container is not found or the mutex is poisoned.
    pub fn restart(&self, container: &str, session_id: &str) -> Result<(), TerminalError> {
        let mut inner = self.lock_inner()?;
        let session = ensure_session_checked(&mut inner, container, session_id)?;
        session.append_line(&format!("[restart] {container} terminal session reset"));
        session.append_line("soyeht@local:~$ ");
        Ok(())
    }

    /// Get history for a container's session. Used in tests.
    pub fn get_session_history(&self, container: &str, session_id: &str) -> Vec<String> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = session_key(container, session_id);
        match inner.sessions.get(&key) {
            Some(s) => s.history.clone(),
            None => vec![],
        }
    }

    /// Returns true if the given container/session currently exists.
    pub fn has_session(&self, container: &str, session_id: &str) -> bool {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = session_key(container, session_id);
        inner.sessions.contains_key(&key)
    }

    /// Closes a specific session by removing it from in-memory state.
    ///
    /// Returns `ContainerNotFound` only when the container itself does not exist.
    /// Missing sessions are treated as idempotent success.
    ///
    /// # Errors
    ///
    /// Returns an error if the container does not exist or the mutex is poisoned.
    pub fn close_session(&self, container: &str, session_id: &str) -> Result<(), TerminalError> {
        let container = container.trim();
        let mut inner = self.lock_inner()?;
        if container.is_empty() || !inner.containers.contains(container) {
            return Err(TerminalError::ContainerNotFound);
        }
        let key = session_key(container, session_id);
        inner.sessions.remove(&key);
        Ok(())
    }

    /// Set the executor (for IPC binary to inject a real executor after construction).
    pub fn set_executor(&mut self, executor: Box<dyn Executor>) {
        self.executor = executor;
    }

    /// Run a command with pre-computed output and exit code (for IPC mock mode).
    /// Behaves identically to `run_command` but skips the executor call.
    ///
    /// # Errors
    ///
    /// Returns an error if the container is not found or the mutex is poisoned.
    pub fn run_command_mock(
        &self,
        container: &str,
        session_id: &str,
        user: &str,
        command: &str,
        mock_output: &str,
        mock_exit_code: i32,
    ) -> Result<(), TerminalError> {
        let command = command.trim();
        if command.is_empty() {
            let mut inner = self.lock_inner()?;
            ensure_session_checked(&mut inner, container, session_id)?;
            return Ok(());
        }

        // Append command echo
        {
            let mut inner = self.lock_inner()?;
            let session = ensure_session_checked(&mut inner, container, session_id)?;
            session.append_line(&format!("{user}@{container}:~$ {command}"));
        }

        if command == "clear" {
            let mut inner = self.lock_inner()?;
            let key = session_key(container, session_id);
            if let Some(session) = inner.sessions.get_mut(&key) {
                session.reset_history();
                session.append_line(&format!("[ok] cleared terminal {container}"));
                session.append_line("soyeht@local:~$ ");
            }
            return Ok(());
        }

        // Use mock output instead of executor
        let mut inner = self.lock_inner()?;
        let key = session_key(container, session_id);
        if let Some(session) = inner.sessions.get_mut(&key) {
            append_output_lines(session, mock_output);
            if mock_exit_code != 0 {
                session.append_line(&format!("[exit {mock_exit_code}]"));
            }
            session.append_line("soyeht@local:~$ ");
        }

        Ok(())
    }
}

/// Ensure a session exists, returning a mutable reference to it.
/// Returns `ContainerNotFound` if the container doesn't exist.
fn ensure_session_checked<'a>(
    inner: &'a mut Inner,
    container: &str,
    session_id: &str,
) -> Result<&'a mut Session, TerminalError> {
    let container = container.trim();
    if container.is_empty() || !inner.containers.contains(container) {
        return Err(TerminalError::ContainerNotFound);
    }
    ensure_session_inner(inner, container, session_id);
    let key = session_key(container, session_id);
    Ok(inner
        .sessions
        .get_mut(&key)
        .expect("session just inserted by ensure_session_inner"))
}

/// Ensure a session exists (unconditionally — caller already validated container).
fn ensure_session_inner(inner: &mut Inner, container: &str, session_id: &str) {
    let key = session_key(container, session_id);
    if inner.sessions.contains_key(&key) {
        return;
    }
    let mut session = Session::new();
    session.append_line(&format!("[boot] terminal ready :: {container}"));
    session.append_line("soyeht@local:~$ ");
    inner.sessions.insert(key, session);
}

fn append_output_lines(session: &mut Session, output: &str) {
    let output = output.replace("\r\n", "\n").replace('\r', "\n");
    for line in output.split('\n') {
        let line = line.trim_end_matches('\n');
        if line.is_empty() {
            continue;
        }
        session.append_line(line);
    }
}

// ─── PTY subsystem ───────────────────────────────────────────────────────────

pub mod pty;

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn new_empty_has_no_containers() {
        let m = Manager::new_empty();
        assert_eq!(m.list_containers().len(), 0);
    }

    #[test]
    fn new_with_containers_sorted() {
        let m = Manager::new(Box::new(NoopExecutor), &["zeta", "alpha", "mid"]);
        assert_eq!(m.list_containers(), vec!["alpha", "mid", "zeta"]);
    }

    #[test]
    fn ensure_container_creates_boot_session() {
        let m = Manager::new_empty();
        m.ensure_container("box1");
        let hist = m.get_session_history("box1", "");
        assert_eq!(hist.len(), 2);
        assert_eq!(hist[0], "[boot] terminal ready :: box1");
        assert_eq!(hist[1], "soyeht@local:~$ ");
    }

    #[test]
    fn ensure_container_idempotent() {
        let m = Manager::new_empty();
        m.ensure_container("box1");
        m.ensure_container("box1");
        assert_eq!(m.list_containers(), vec!["box1"]);
        // Session history should still be just the 2 boot lines
        let hist = m.get_session_history("box1", "");
        assert_eq!(hist.len(), 2);
    }

    #[test]
    fn ensure_container_empty_ignored() {
        let m = Manager::new_empty();
        m.ensure_container("");
        m.ensure_container("  ");
        assert_eq!(m.list_containers().len(), 0);
    }

    #[test]
    fn remove_container_removes_from_list() {
        let m = Manager::new_empty();
        m.ensure_container("keep");
        m.ensure_container("remove_me");
        m.remove_container("remove_me");
        assert_eq!(m.list_containers(), vec!["keep"]);
    }

    #[test]
    fn remove_container_cleans_sessions() {
        let m = Manager::new_empty();
        m.ensure_container("temp");
        m.remove_container("temp");
        let err = m.run_command("temp", "", "user", "ls").unwrap_err();
        assert_eq!(err, TerminalError::ContainerNotFound);
    }

    #[test]
    fn has_container_true() {
        let m = Manager::new_empty();
        m.ensure_container("mybox");
        assert!(m.has_container("mybox"));
    }

    #[test]
    fn has_container_false() {
        let m = Manager::new_empty();
        assert!(!m.has_container("ghost"));
    }

    #[test]
    fn has_container_whitespace_false() {
        let m = Manager::new_empty();
        m.ensure_container("real");
        assert!(!m.has_container("  "));
    }

    #[test]
    fn run_command_empty_noop() {
        let m = Manager::new_empty();
        m.ensure_container("box1");
        m.run_command("box1", "", "soyeht", "").unwrap();
        let hist = m.get_session_history("box1", "");
        assert_eq!(hist.len(), 2); // just boot lines
    }

    #[test]
    fn run_command_clear_resets() {
        let m = Manager::new_empty();
        m.ensure_container("box2");
        m.run_command("box2", "", "soyeht", "clear").unwrap();
        let hist = m.get_session_history("box2", "");
        assert_eq!(hist.len(), 2);
        assert_eq!(hist[0], "[ok] cleared terminal box2");
        assert_eq!(hist[1], "soyeht@local:~$ ");
    }

    #[test]
    fn run_command_success() {
        let m = Manager::new_with_mock("hello", 0);
        m.ensure_container("box3");
        m.run_command("box3", "", "admin", "echo hello").unwrap();
        let hist = m.get_session_history("box3", "");
        assert_eq!(hist.len(), 5);
        assert_eq!(hist[2], "admin@box3:~$ echo hello");
        assert_eq!(hist[3], "hello");
        assert_eq!(hist[4], "soyeht@local:~$ ");
    }

    #[test]
    fn run_command_nonzero_exit() {
        let m = Manager::new_with_mock("error occurred", 1);
        m.ensure_container("box4");
        m.run_command("box4", "", "admin", "false").unwrap();
        let hist = m.get_session_history("box4", "");
        assert_eq!(hist.len(), 6);
        assert_eq!(hist[2], "admin@box4:~$ false");
        assert_eq!(hist[3], "error occurred");
        assert_eq!(hist[4], "[exit 1]");
        assert_eq!(hist[5], "soyeht@local:~$ ");
    }

    #[test]
    fn run_command_missing_container() {
        let m = Manager::new_empty();
        let err = m
            .run_command("no-such-box", "", "soyeht", "ls")
            .unwrap_err();
        assert_eq!(err, TerminalError::ContainerNotFound);
    }

    #[test]
    fn restart_appends_lines() {
        let m = Manager::new_empty();
        m.ensure_container("box5");
        m.restart("box5", "").unwrap();
        let hist = m.get_session_history("box5", "");
        assert_eq!(hist.len(), 4);
        assert_eq!(hist[2], "[restart] box5 terminal session reset");
        assert_eq!(hist[3], "soyeht@local:~$ ");
    }

    #[test]
    fn restart_missing_container() {
        let m = Manager::new_empty();
        let err = m.restart("no-such-box", "").unwrap_err();
        assert_eq!(err, TerminalError::ContainerNotFound);
    }

    #[test]
    fn history_cap_400() {
        let m = Manager::new_with_mock("line1\nline2", 0);
        m.ensure_container("capbox");
        for i in 0..200 {
            m.run_command("capbox", "", "soyeht", &format!("cmd-{i}"))
                .unwrap();
        }
        let hist = m.get_session_history("capbox", "");
        assert!(
            hist.len() <= 400,
            "history length {} exceeds cap 400",
            hist.len()
        );
    }

    #[test]
    fn session_key_empty_session_id() {
        assert_eq!(session_key("box", ""), "box");
    }

    #[test]
    fn session_key_with_session_id() {
        assert_eq!(session_key("box", "s1"), "box::s1");
    }

    #[test]
    fn append_output_lines_normalizes_crlf() {
        let mut session = Session::new();
        append_output_lines(&mut session, "a\r\nb\rc\n");
        // "a", "b", "c" — empty trailing line skipped
        assert_eq!(session.history, vec!["a", "b", "c"]);
    }

    #[test]
    fn append_output_lines_skips_empty() {
        let mut session = Session::new();
        append_output_lines(&mut session, "\n\nhello\n\n");
        assert_eq!(session.history, vec!["hello"]);
    }

    #[test]
    fn concurrent_run_command_single_session() {
        let m = Arc::new(Manager::new_with_mock("ok", 0));
        m.ensure_container("box");

        let workers = 20;
        let mut handles = Vec::with_capacity(workers);
        for i in 0..workers {
            let mm = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                mm.run_command("box", "", "u", &format!("cmd-{i}")).unwrap();
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let hist = m.get_session_history("box", "");
        // boot + prompt + 20 * (echo + output + prompt)
        assert_eq!(hist.len(), 2 + workers * 3);
        for i in 0..workers {
            assert!(hist.iter().any(|l| l == &format!("u@box:~$ cmd-{i}")));
        }
    }

    #[test]
    fn concurrent_run_command_multiple_sessions() {
        let m = Arc::new(Manager::new_with_mock("ok", 0));
        m.ensure_container("box");

        let mut handles = Vec::new();
        for sid in ["s1", "s2", "s3", "s4"] {
            let mm = Arc::clone(&m);
            let sid = sid.to_string();
            handles.push(thread::spawn(move || {
                for i in 0..10 {
                    mm.run_command("box", &sid, "u", &format!("{sid}-cmd-{i}"))
                        .unwrap();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        for sid in ["s1", "s2", "s3", "s4"] {
            let hist = m.get_session_history("box", sid);
            assert_eq!(hist.len(), 2 + 10 * 3);
            for i in 0..10 {
                assert!(hist.iter().any(|l| l == &format!("u@box:~$ {sid}-cmd-{i}")));
            }
        }
    }

    #[test]
    fn remove_container_during_writes_becomes_not_found() {
        let m = Arc::new(Manager::new_with_mock("ok", 0));
        m.ensure_container("box");

        let mm = Arc::clone(&m);
        let writer = thread::spawn(move || {
            for _ in 0..200 {
                let _ = mm.run_command("box", "", "u", "echo");
            }
        });

        m.remove_container("box");
        writer.join().unwrap();

        assert!(!m.has_container("box"));
        let err = m.run_command("box", "", "u", "echo").unwrap_err();
        assert_eq!(err, TerminalError::ContainerNotFound);
    }

    #[test]
    fn close_session_removes_session() {
        let m = Manager::new_with_mock("ok", 0);
        m.ensure_container("box");
        m.run_command("box", "s1", "u", "echo hi").unwrap();
        assert!(m.has_session("box", "s1"));
        m.close_session("box", "s1").unwrap();
        assert!(!m.has_session("box", "s1"));
    }

    #[test]
    fn close_session_missing_is_idempotent() {
        let m = Manager::new_empty();
        m.ensure_container("box");
        m.close_session("box", "ghost").unwrap();
    }
}
