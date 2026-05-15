//! PTY session with on-disk conversation log (v2).
//!
//! # Architecture
//!
//! `PtySession` owns:
//! - A `pty_process::blocking::Pty` fd (shared with the read thread).
//! - A `std::process::Child` handle.
//! - An `Arc<ConversationLog>` that persists every byte produced by the shell
//!   to `<conv_dir>/<conv_id>.log` — this is the canonical source for replay
//!   on WS attach. Logs persist across backend restarts; the file is opened
//!   in append mode and the size counter is initialized from disk. Growth is
//!   capped per conversation by `THEYOS_CONV_LOG_MAX_BYTES` — when the cap is
//!   hit, `append` returns `io::Error(FileTooLarge)` and the session closes
//!   cleanly with a `CTL:log_full` marker.
//! - A `tokio::sync::broadcast::Sender<(u64, Arc<[u8]>)>` where `u64` is the
//!   monotonic end-offset of the chunk in the log (used by subscribers to
//!   de-duplicate replay vs live).
//! - A `tokio::sync::Mutex<()>` `write_lock` that serializes PTY writes from
//!   multiple concurrent WS clients — POSIX does not guarantee atomicity on
//!   PTY writes larger than `PIPE_BUF` (512 bytes), so without serialization
//!   two clients pasting text would interleave bytes.
//!
//! A background thread reads from the PTY fd in a loop, appends each chunk
//! to the `ConversationLog` (which also bumps the atomic size counter), and
//! broadcasts `(end_offset, Arc<[u8]>)` to subscribers.
//!
//! `PtyManager` owns a flat `HashMap<String, Arc<PtySession>>` keyed by
//! `{container}::{conversation_id}`. PTYs are created lazily on the first WS
//! attach for a conversation and live until explicit `close` (by `DELETE`).

use crate::TerminalError;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Broadcast channel capacity (number of in-flight chunks per session).
const BROADCAST_CAP: usize = 256;

/// Read chunk size pumped from the PTY master fd.
const READ_CHUNK: usize = 4096;

/// Default per-conversation log size cap when `THEYOS_CONV_LOG_MAX_BYTES`
/// is unset or unparseable: 500 MiB.
pub const DEFAULT_CONV_LOG_MAX_BYTES: u64 = 500 * 1024 * 1024;

/// Control marker emitted on the broadcast channel when a conversation log
/// hits its size cap. The `\x00\x01CTL:` prefix is the protocol shared with
/// the WS handler (`server-rs::handlers_terminal`).
const CTL_LOG_FULL_MARKER: &[u8] = b"\x00\x01CTL:log_full";

// ── ConversationLog ───────────────────────────────────────────────────────

/// Append-only on-disk record of every byte produced by a conversation's PTY.
///
/// Invariants:
/// - Only **one writer** (the PTY background read thread). Writes are
///   serialized by the internal `Mutex<File>`. The file is opened with
///   `O_APPEND` so `write(2)` is atomic for the written range.
/// - `size` is the **source of truth** for "how many bytes are committed".
///   Never read `file.metadata().len()` — it races with the append.
/// - Readers (WS replay handlers) open a fresh FD via `open_reader()` and
///   read up to `current_size()` bytes — never `.read_to_end()`.
/// - On write error: truncate the file back to `size`, leaving the invariant
///   "bytes up to `size` are valid" intact. Caller kills the PTY.
/// - Total log size is capped by `max_bytes`; `append` rejects writes that
///   would push `size` past the cap (returns `io::Error(FileTooLarge)`).
pub struct ConversationLog {
    path: PathBuf,
    writer: Mutex<File>,
    size: AtomicU64,
    max_bytes: u64,
}

impl ConversationLog {
    /// Opens (or reopens) the log for `conv_id` under `conv_dir`. Creates the
    /// file if it does not exist; **preserves existing content** otherwise.
    /// The file is opened with `O_APPEND`; `size` is initialized from the
    /// current on-disk length so subsequent appends correctly extend it.
    ///
    /// `max_bytes` is the total byte cap for this log — once `size` reaches
    /// that value, `append` returns `io::Error(FileTooLarge)`. Pass
    /// `u64::MAX` to effectively disable the cap (tests only).
    ///
    /// Path-traversal defense: rejects `conv_id` that doesn't match
    /// `[A-Za-z0-9_-]{1,64}`.
    ///
    /// # Errors
    ///
    /// Returns `TerminalError::Other` if the id is invalid or the file
    /// cannot be created.
    pub fn open(
        conv_dir: &Path,
        conv_id: &str,
        max_bytes: u64,
    ) -> Result<Arc<Self>, TerminalError> {
        validate_conv_id(conv_id)?;
        let path = conv_dir.join(format!("{conv_id}.log"));
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let writer = opts
            .open(&path)
            .map_err(|e| TerminalError::Other(format!("open log {}: {e}", path.display())))?;
        // Initialize size from disk so appends extend rather than overwrite
        // after a backend restart.
        let initial_size = writer
            .metadata()
            .map_err(|e| TerminalError::Other(format!("stat log {}: {e}", path.display())))?
            .len();
        Ok(Arc::new(Self {
            path,
            writer: Mutex::new(writer),
            size: AtomicU64::new(initial_size),
            max_bytes,
        }))
    }

    /// Append `bytes` to the log and bump the size counter. Returns the new
    /// end-offset (total bytes in the log including `bytes`).
    ///
    /// On partial write failure, truncates the file back to the pre-write
    /// size so the log stays consistent.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the write fails.
    pub fn append(&self, bytes: &[u8]) -> std::io::Result<u64> {
        if bytes.is_empty() {
            return Ok(self.size.load(Ordering::Acquire));
        }
        let mut f = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = self.size.load(Ordering::Acquire);
        // Size cap: reject writes that would push the log past `max_bytes`.
        // Nothing is written, size is not bumped — caller (reader thread)
        // treats `FileTooLarge` as the cap-hit signal.
        if prev.saturating_add(bytes.len() as u64) > self.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "conversation log full",
            ));
        }
        match f.write_all(bytes) {
            Ok(()) => {
                // Size is source of truth; bump AFTER write_all returns Ok.
                let end =
                    self.size.fetch_add(bytes.len() as u64, Ordering::Release) + bytes.len() as u64;
                Ok(end)
            }
            Err(e) => {
                // Roll back partial bytes: truncate to the size we know is valid.
                let _ = f.set_len(prev);
                Err(e)
            }
        }
    }

    /// Current committed size (source of truth).
    #[must_use]
    pub fn current_size(&self) -> u64 {
        self.size.load(Ordering::Acquire)
    }

    /// Open a fresh read FD. Caller should read up to `current_size()` bytes.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the file cannot be opened.
    pub fn open_reader(&self) -> std::io::Result<File> {
        File::open(&self.path)
    }

    /// Path on disk.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Unlink the file on disk. Safe to call even if the file is already gone.
    pub fn remove(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn validate_conv_id(conv_id: &str) -> Result<(), TerminalError> {
    if conv_id.is_empty() || conv_id.len() > 64 {
        return Err(TerminalError::Other(format!(
            "invalid conversation id length: {}",
            conv_id.len()
        )));
    }
    if !conv_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(TerminalError::Other(
            "invalid conversation id: only [A-Za-z0-9_-] allowed".to_string(),
        ));
    }
    Ok(())
}

// ── PtySession ────────────────────────────────────────────────────────────

pub struct PtySession {
    /// PTY master fd — shared between writer (tokio tasks) and reader thread.
    pty: Arc<pty_process::blocking::Pty>,
    /// Child process handle.
    child: Mutex<std::process::Child>,
    /// Append-only conversation log + size counter (source of truth).
    log: Arc<ConversationLog>,
    /// Serializes PTY writes from multiple WS clients. POSIX write atomicity
    /// is only guaranteed up to `PIPE_BUF` (512 bytes) on pipes and is NOT
    /// guaranteed on PTYs — so two clients pasting simultaneously would
    /// interleave bytes at the kernel boundary without this lock.
    write_lock: tokio::sync::Mutex<()>,
    /// Broadcast of `(end_offset, chunk)` — subscribers use the offset to
    /// de-duplicate against the replay they already streamed from the log.
    tx: tokio::sync::broadcast::Sender<(u64, Arc<[u8]>)>,
    /// Set once the process exits or `close()` is called.
    closed: AtomicBool,
    /// Tracked PTY dimensions (cols, rows).
    size: Mutex<(u16, u16)>,
}

impl PtySession {
    /// Write raw bytes to the PTY master (client input → shell stdin).
    ///
    /// Acquires `write_lock` to serialize concurrent writers.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is closed or the write fails.
    pub async fn write(&self, data: &[u8]) -> Result<(), TerminalError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(TerminalError::Other("pty session is closed".to_string()));
        }
        let _guard = self.write_lock.lock().await;
        (&*self.pty)
            .write_all(data)
            .map_err(|e| TerminalError::Other(e.to_string()))
    }

    /// Resize the PTY window and update tracked dimensions.
    ///
    /// # Errors
    ///
    /// Returns an error if the PTY resize call fails.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), TerminalError> {
        self.pty
            .resize(pty_process::Size::new(rows, cols))
            .map_err(|e| TerminalError::Other(e.to_string()))?;
        *self
            .size
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = (cols, rows);
        Ok(())
    }

    /// Current tracked dimensions `(cols, rows)`.
    #[must_use]
    pub fn current_size(&self) -> (u16, u16) {
        *self
            .size
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Reference to the conversation log. Used by WS attach handler to
    /// stream replay bytes before entering the live broadcast forward loop.
    #[must_use]
    pub fn log(&self) -> Arc<ConversationLog> {
        Arc::clone(&self.log)
    }

    /// Subscribe to the live broadcast. Each message is `(end_offset, bytes)`
    /// where `end_offset` is the post-write size of the log at the moment
    /// the chunk was broadcast.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<(u64, Arc<[u8]>)> {
        self.tx.subscribe()
    }

    /// Is the session closed?
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Kill the child (SIGHUP), reap it, and mark the session closed.
    /// Idempotent.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut child = self
            .child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = child.kill();
        let _ = child.wait();
    }
}

// ── start_pty_session ─────────────────────────────────────────────────────

/// Start a PTY session by spawning `<ctl_path> pty <container> <conv_id>`.
///
/// The spawned subprocess is `fc-ssh` (Linux) or `theyos-ssh` (macOS). v2 of
/// those binaries ignores `conv_id` and just execs a direct login shell on
/// the guest — no tmux.
///
/// A background thread pumps bytes from the PTY fd into the
/// `ConversationLog` and broadcasts `(end_offset, chunk)` to subscribers.
/// If a log write fails, the PTY is killed and subscribers get a Closed
/// broadcast.
///
/// # Errors
///
/// Returns an error if the PTY cannot be opened or the child process
/// cannot be spawned.
pub fn start_pty_session(
    ctl_path: &str,
    container: &str,
    conv_id: &str,
    log: &Arc<ConversationLog>,
    cols: u16,
    rows: u16,
) -> Result<Arc<PtySession>, TerminalError> {
    let conv_id_owned = conv_id.to_string();
    let (pty, pts) =
        pty_process::blocking::open().map_err(|e| TerminalError::Other(format!("openpty: {e}")))?;

    pty.resize(pty_process::Size::new(rows, cols))
        .map_err(|e| TerminalError::Other(format!("resize: {e}")))?;

    let child = pty_process::blocking::Command::new(ctl_path)
        .arg("pty")
        .arg(container)
        .arg(conv_id)
        .env("TERM", "xterm-256color")
        .spawn(pts)
        .map_err(|e| TerminalError::Other(format!("spawn: {e}")))?;

    let pty = Arc::new(pty);
    let (tx, _) = tokio::sync::broadcast::channel::<(u64, Arc<[u8]>)>(BROADCAST_CAP);

    let session = Arc::new(PtySession {
        pty: Arc::clone(&pty),
        child: Mutex::new(child),
        log: Arc::clone(log),
        write_lock: tokio::sync::Mutex::new(()),
        tx,
        closed: AtomicBool::new(false),
        size: Mutex::new((cols, rows)),
    });

    // Background read thread: PTY fd → log file → broadcast.
    let session_weak = Arc::downgrade(&session);
    std::thread::spawn(move || {
        let mut buf = [0u8; READ_CHUNK];
        loop {
            match (&*pty).read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let Some(sess) = session_weak.upgrade() else {
                        break;
                    };
                    match sess.log.append(&buf[..n]) {
                        Ok(end) => {
                            let chunk: Arc<[u8]> = Arc::from(&buf[..n]);
                            let _ = sess.tx.send((end, chunk));
                        }
                        Err(e) if e.kind() == io::ErrorKind::FileTooLarge => {
                            tracing::warn!(
                                conv_id = %conv_id_owned,
                                "conversation log full, closing session"
                            );
                            // Emit CTL:log_full with sentinel offset u64::MAX
                            // so WS replay-dedupe (`end_offset <= cursor`) can
                            // never discard it for late-subscribing clients.
                            let marker: Arc<[u8]> = Arc::from(CTL_LOG_FULL_MARKER);
                            let _ = sess.tx.send((u64::MAX, marker));
                            sess.close();
                            break;
                        }
                        Err(e) => {
                            tracing::error!("conversation log append failed, killing session: {e}");
                            // Kill the child and mark closed; subscribers will
                            // see the broadcast Sender drop.
                            sess.close();
                            break;
                        }
                    }
                }
            }
        }
        // Normal exit path: reap + mark closed.
        if let Some(sess) = session_weak.upgrade() {
            let _ = sess
                .child
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .wait();
            sess.closed.store(true, Ordering::SeqCst);
        }
    });

    Ok(session)
}

// ── PtyManager ────────────────────────────────────────────────────────────

/// Manages a flat map of active PTY sessions keyed by
/// `{container}::{conversation_id}`.
pub struct PtyManager {
    sessions: Mutex<HashMap<String, Arc<PtySession>>>,
    /// Path to the fc-ssh / theyos-ssh binary.
    ctl_path: String,
    /// Directory where conversation log files live (one per session).
    conv_dir: PathBuf,
    /// Per-conversation log size cap (bytes). Read from
    /// `THEYOS_CONV_LOG_MAX_BYTES` once at construction.
    conv_log_max_bytes: u64,
}

impl PtyManager {
    /// Create a manager with the given ssh control binary and conversation
    /// log directory. The directory is created on demand; conversation logs
    /// persist across restarts and are only removed by explicit close.
    ///
    /// Reads `THEYOS_CONV_LOG_MAX_BYTES` once here. Unparseable values fall
    /// back to `DEFAULT_CONV_LOG_MAX_BYTES` with a `tracing::warn!`.
    #[must_use]
    pub fn new(ctl_path: &str, conv_dir: PathBuf) -> Self {
        let conv_log_max_bytes = Self::read_max_bytes_env();
        Self::with_max_bytes(ctl_path, conv_dir, conv_log_max_bytes)
    }

    /// Construct a manager with an explicit cap. Primarily for tests.
    #[must_use]
    pub fn with_max_bytes(ctl_path: &str, conv_dir: PathBuf, conv_log_max_bytes: u64) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            ctl_path: ctl_path.to_string(),
            conv_dir,
            conv_log_max_bytes,
        }
    }

    fn read_max_bytes_env() -> u64 {
        Self::parse_max_bytes(std::env::var("THEYOS_CONV_LOG_MAX_BYTES").ok().as_deref())
    }

    /// Pure parser for the cap env var. Returns the default for `None`,
    /// empty strings, or unparseable values (with a warn in the unparseable
    /// case). Extracted for testability without mutating process env.
    fn parse_max_bytes(raw: Option<&str>) -> u64 {
        match raw {
            Some(s) if !s.is_empty() => match s.parse::<u64>() {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        value = %s,
                        error = %e,
                        "THEYOS_CONV_LOG_MAX_BYTES is not a valid u64; falling back to default"
                    );
                    DEFAULT_CONV_LOG_MAX_BYTES
                }
            },
            _ => DEFAULT_CONV_LOG_MAX_BYTES,
        }
    }

    /// Per-conversation log size cap (bytes).
    #[must_use]
    pub fn conv_log_max_bytes(&self) -> u64 {
        self.conv_log_max_bytes
    }

    /// Path to the ssh control binary.
    #[must_use]
    pub fn ctl_path(&self) -> &str {
        &self.ctl_path
    }

    /// Conversation log directory.
    #[must_use]
    pub fn conv_dir(&self) -> &Path {
        &self.conv_dir
    }

    fn session_key(container: &str, conv_id: &str) -> String {
        format!("{container}::{conv_id}")
    }

    /// Lazily start a PTY for `conv_id`, or return the existing live session.
    /// Creates the conversation log file on first open; reopens (preserving
    /// content) if a log for `conv_id` already exists on disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the session cannot be started.
    pub fn start(
        &self,
        container: &str,
        conv_id: &str,
        cols: u16,
        rows: u16,
    ) -> Result<Arc<PtySession>, TerminalError> {
        if conv_id.is_empty() {
            return Err(TerminalError::Other(
                "conversation_id is required".to_string(),
            ));
        }
        validate_conv_id(conv_id)?;

        let key = Self::session_key(container, conv_id);
        let mut map = self
            .sessions
            .lock()
            .map_err(|_| TerminalError::Other("mutex poisoned".to_string()))?;

        if let Some(sess) = map.get(&key) {
            if !sess.is_closed() {
                return Ok(Arc::clone(sess));
            }
            map.remove(&key);
        }

        // Ensure conv_dir exists (best-effort; startup should have created it).
        let _ = std::fs::create_dir_all(&self.conv_dir);
        let log = ConversationLog::open(&self.conv_dir, conv_id, self.conv_log_max_bytes)?;
        let sess = start_pty_session(&self.ctl_path, container, conv_id, &log, cols, rows)?;
        map.insert(key, Arc::clone(&sess));
        Ok(sess)
    }

    /// Get an existing session without starting a new one.
    pub fn get(&self, container: &str, conv_id: &str) -> Option<Arc<PtySession>> {
        let key = Self::session_key(container, conv_id);
        let map = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.get(&key).map(Arc::clone)
    }

    /// Close and remove a specific PTY session. Also unlinks its log file.
    ///
    /// # Errors
    ///
    /// Returns an error if the mutex is poisoned.
    pub fn close(&self, container: &str, conv_id: &str) -> Result<(), TerminalError> {
        let key = Self::session_key(container, conv_id);
        let removed = {
            let mut map = self
                .sessions
                .lock()
                .map_err(|_| TerminalError::Other("mutex poisoned".to_string()))?;
            map.remove(&key)
        };
        if let Some(sess) = removed {
            sess.close();
            sess.log.remove();
        } else {
            // Session never started but a stale log file may still exist.
            if validate_conv_id(conv_id).is_ok() {
                let path = self.conv_dir.join(format!("{conv_id}.log"));
                let _ = std::fs::remove_file(&path);
            }
        }
        Ok(())
    }

    /// Close and remove all sessions for a given container.
    pub fn remove_container(&self, container: &str) {
        let prefix = format!("{container}::");
        let mut map = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let keys: Vec<String> = map
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();
        for key in keys {
            if let Some(sess) = map.remove(&key) {
                sess.close();
                sess.log.remove();
            }
        }
    }

    /// Remove sessions whose child process has exited.
    pub fn cleanup_stale(&self) -> usize {
        let mut map = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stale: Vec<String> = map
            .iter()
            .filter(|(_, sess)| sess.is_closed())
            .map(|(key, _)| key.clone())
            .collect();
        let count = stale.len();
        for key in stale {
            if let Some(sess) = map.remove(&key) {
                sess.log.remove();
            }
        }
        count
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn mock_log() -> (tempfile::TempDir, Arc<ConversationLog>) {
        let dir = tempdir().expect("tempdir");
        let log = ConversationLog::open(dir.path(), "test_conv_id", u64::MAX).expect("open log");
        (dir, log)
    }

    #[test]
    fn conv_id_validation() {
        assert!(validate_conv_id("abc123_-DEF").is_ok());
        assert!(validate_conv_id("").is_err());
        assert!(validate_conv_id("../etc/passwd").is_err());
        assert!(validate_conv_id("has space").is_err());
        assert!(validate_conv_id(&"x".repeat(65)).is_err());
    }

    #[test]
    fn log_append_bumps_size_and_writes() {
        let (_dir, log) = mock_log();
        assert_eq!(log.current_size(), 0);
        let end1 = log.append(b"hello ").unwrap();
        assert_eq!(end1, 6);
        let end2 = log.append(b"world").unwrap();
        assert_eq!(end2, 11);
        assert_eq!(log.current_size(), 11);

        let mut f = log.open_reader().unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hello world");
    }

    #[test]
    fn log_append_empty_is_noop() {
        let (_dir, log) = mock_log();
        let end = log.append(&[]).unwrap();
        assert_eq!(end, 0);
        assert_eq!(log.current_size(), 0);
    }

    #[test]
    fn log_remove_unlinks_file() {
        let (dir, log) = mock_log();
        log.append(b"data").unwrap();
        let path = log.path().to_path_buf();
        assert!(path.exists());
        log.remove();
        assert!(!path.exists());
        // remove is idempotent
        log.remove();
        // dir still exists
        assert!(dir.path().exists());
    }

    #[test]
    fn log_size_is_source_of_truth_not_file_len() {
        // After append, size == bytes written. Even though we don't fsync,
        // the buffered file might have different page-cache state — size is
        // the counter we trust.
        let (_dir, log) = mock_log();
        log.append(b"abcdef").unwrap();
        assert_eq!(log.current_size(), 6);
    }

    #[test]
    fn pty_manager_session_key() {
        assert_eq!(PtyManager::session_key("box", "c1"), "box::c1");
    }

    #[test]
    fn pty_manager_empty_conv_id_errors() {
        let dir = tempdir().unwrap();
        let mgr = PtyManager::new("/nonexistent", dir.path().to_path_buf());
        let res = mgr.start("box", "", 80, 24);
        assert!(res.is_err());
    }

    #[test]
    fn pty_manager_invalid_conv_id_errors() {
        let dir = tempdir().unwrap();
        let mgr = PtyManager::new("/nonexistent", dir.path().to_path_buf());
        let res = mgr.start("box", "../etc", 80, 24);
        assert!(res.is_err());
    }

    #[test]
    fn pty_manager_close_missing_is_ok() {
        let dir = tempdir().unwrap();
        let mgr = PtyManager::new("/nonexistent", dir.path().to_path_buf());
        assert!(mgr.close("box", "nope").is_ok());
    }

    #[test]
    fn pty_manager_cleanup_stale_empty() {
        let dir = tempdir().unwrap();
        let mgr = PtyManager::new("/nonexistent", dir.path().to_path_buf());
        assert_eq!(mgr.cleanup_stale(), 0);
    }

    #[test]
    fn log_persists_across_recreation() {
        // Simulates a backend restart: create log, drop it, reopen the same
        // conv_id in the same directory — size and content must survive.
        let dir = tempdir().unwrap();
        let path = {
            let log = ConversationLog::open(dir.path(), "conv_persist", u64::MAX).unwrap();
            log.append(b"hello world").unwrap();
            assert_eq!(log.current_size(), 11);
            log.path().to_path_buf()
            // log Arc dropped here
        };
        assert!(path.exists());

        let reopened = ConversationLog::open(dir.path(), "conv_persist", u64::MAX).unwrap();
        assert_eq!(reopened.current_size(), 11);

        let mut f = reopened.open_reader().unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hello world");

        // A further append extends, not overwrites.
        let end = reopened.append(b"!").unwrap();
        assert_eq!(end, 12);
        let mut f2 = reopened.open_reader().unwrap();
        let mut buf2 = Vec::new();
        f2.read_to_end(&mut buf2).unwrap();
        assert_eq!(buf2, b"hello world!");
    }

    #[test]
    fn log_size_initializes_from_existing_file() {
        let dir = tempdir().unwrap();
        let payload: &[u8] = b"preexisting content written directly";
        let path = dir.path().join("conv_pre.log");
        std::fs::write(&path, payload).unwrap();

        let log = ConversationLog::open(dir.path(), "conv_pre", u64::MAX).unwrap();
        assert_eq!(log.current_size(), payload.len() as u64);
    }

    #[test]
    fn append_fails_at_cap() {
        let dir = tempdir().unwrap();
        let log = ConversationLog::open(dir.path(), "conv_cap", 10).unwrap();
        // 5 bytes fit.
        let end = log.append(b"hello").unwrap();
        assert_eq!(end, 5);
        assert_eq!(log.current_size(), 5);

        // 6 more bytes would push to 11 > 10 — must fail, untouched.
        let err = log.append(b"world!").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::FileTooLarge);
        assert_eq!(log.current_size(), 5);

        // File on disk is still exactly 5 bytes.
        let disk_len = std::fs::metadata(log.path()).unwrap().len();
        assert_eq!(disk_len, 5);

        // Even a single extra byte past the cap fails.
        let end = log.append(b"abcde").unwrap();
        assert_eq!(end, 10);
        let err = log.append(b"x").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::FileTooLarge);
        assert_eq!(log.current_size(), 10);
    }

    #[test]
    fn delete_after_restart_unlinks_file() {
        // Simulates: conversation was created under manager A (which exited),
        // then a new manager B attaches to the same dir and is asked to
        // delete it. The stale file on disk must be unlinked even though B
        // never had a live session for that conv_id.
        let dir = tempdir().unwrap();
        let conv_id = "conv_stale";
        let log_path = {
            let mgr_a =
                PtyManager::with_max_bytes("/nonexistent", dir.path().to_path_buf(), u64::MAX);
            let log = ConversationLog::open(mgr_a.conv_dir(), conv_id, u64::MAX).unwrap();
            log.append(b"some bytes").unwrap();
            log.path().to_path_buf()
        };
        assert!(log_path.exists(), "precondition: stale file exists");

        let mgr_b = PtyManager::with_max_bytes("/nonexistent", dir.path().to_path_buf(), u64::MAX);
        mgr_b.close("any_container", conv_id).unwrap();
        assert!(
            !log_path.exists(),
            "close() must unlink stale log even without an active session"
        );
    }

    #[test]
    fn parse_max_bytes_valid() {
        assert_eq!(PtyManager::parse_max_bytes(Some("12345")), 12345);
        assert_eq!(PtyManager::parse_max_bytes(Some("0")), 0);
    }

    #[test]
    fn parse_max_bytes_falls_back_on_invalid() {
        assert_eq!(
            PtyManager::parse_max_bytes(Some("not-a-number")),
            DEFAULT_CONV_LOG_MAX_BYTES
        );
        assert_eq!(
            PtyManager::parse_max_bytes(Some("-5")),
            DEFAULT_CONV_LOG_MAX_BYTES
        );
        assert_eq!(
            PtyManager::parse_max_bytes(Some("")),
            DEFAULT_CONV_LOG_MAX_BYTES
        );
        assert_eq!(
            PtyManager::parse_max_bytes(None),
            DEFAULT_CONV_LOG_MAX_BYTES
        );
    }
}
