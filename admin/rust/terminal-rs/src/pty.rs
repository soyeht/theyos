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
//!   in append mode and the size counter is initialized from disk. On-disk
//!   growth is capped per conversation by `THEYOS_CONV_LOG_MAX_BYTES` — when
//!   an append would push the physical file past the cap, the log ROTATES
//!   (drops the oldest half, keeps the newest half) instead of rejecting the
//!   write or closing the session. `ConversationLog::base_offset()` tracks
//!   how many logical bytes have been rotated away, so callers translating
//!   logical offsets (the broadcast/replay cursor) to physical file
//!   positions can subtract it out.
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
//! Closing a session (`PtySession::close`) kills every terminal-facing
//! process attached to its TTY — not just the tracked direct child — via an
//! escalation ported from `soyeht-ios` PR #317's `NativePTY` technique:
//! `SIGHUP` immediately, `SIGTERM` after 2s if anything survived, `SIGKILL`
//! after another 2s if still surviving. Pipe/socket-backed helpers are
//! excluded: MCP servers inherit the controlling TTY but communicate with
//! their client over private stdio, and die naturally when that client
//! closes those streams. This runs on a detached background thread, so
//! `close` itself returns immediately.
//!
//! `PtyManager` owns a flat `HashMap<String, Arc<PtySession>>` keyed by
//! `{container}::{conversation_id}`. PTYs are created lazily on the first WS
//! attach for a conversation and live until explicit `close` (by `DELETE`).

use crate::TerminalError;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
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

/// Floor for `THEYOS_CONV_LOG_MAX_BYTES`: at least 2x `READ_CHUNK`. Below
/// this, a single PTY read chunk can be bigger than the entire cap, and
/// `rotate_file` cannot shrink a 0-or-1-byte file any further — `append`
/// then always accepts the oversized write without ever making rotation
/// progress, which is fine ONCE, but a cap this tiny defeats the point of
/// rotation (every single append would need to accept an oversized write).
/// A raw value below this floor is clamped up to it, with a warning.
const MIN_CONV_LOG_MAX_BYTES: u64 = 64 * 1024;

/// Rotation shift buffer size — chunk size used when compacting the log file
/// in place (copying the retained tail down to the start of the file).
const ROTATE_SHIFT_CHUNK: usize = 64 * 1024;

/// Default cap on concurrently LIVE broker-owned local sessions when
/// `THEYOS_MAX_LOCAL_SESSIONS` is unset or unparseable. Every live session
/// holds a real PTY, a real child process, and a broadcast channel;
/// unbounded creation (a buggy or hostile client hammering the create
/// endpoint with fresh `conversation_id`s) exhausts OS process/fd limits
/// for the whole engine, not just that one client. Already-exited sessions
/// don't count against this — they hold no live resource, and are reaped
/// opportunistically by `cleanup_stale`.
const DEFAULT_MAX_LOCAL_SESSIONS: usize = 64;

/// Default minimum age (seconds) before an orphaned conversation log
/// becomes eligible for GC, when `THEYOS_ORPHAN_LOG_MAX_AGE_SECS` is unset
/// or unparseable: 30 days. Conversation logs persist across restarts BY
/// DESIGN — this must stay generous, since it only reclaims logs from
/// `conversation_id`s nobody has reattached to, or explicitly closed, in a
/// long time.
const DEFAULT_ORPHAN_LOG_MAX_AGE_SECS: u64 = 30 * 24 * 60 * 60;

// ── ConversationLog ───────────────────────────────────────────────────────

/// Append-only on-disk record of every byte produced by a conversation's PTY.
///
/// Invariants:
/// - Only **one writer** (the PTY background read thread). Writes are
///   serialized by the internal `Mutex<File>`. The file is opened with
///   `O_APPEND` so `write(2)` is atomic for the written range.
/// - `size` is the **source of truth** for "how many logical bytes have ever
///   been committed" — it counts monotonically and is never reduced by
///   rotation. Never read `file.metadata().len()` for this — it races with
///   the append AND excludes rotated-away history.
/// - `base_offset` is the logical offset of physical file position 0. It
///   starts at 0 and only ever increases, when `rotate()` truncates the
///   oldest half of the on-disk file to make room. Physical file position =
///   logical offset − `base_offset`. Resets to 0 on process restart (there
///   is no side file recording it — the on-disk file is the sole record).
/// - Readers (WS replay handlers) open a fresh FD via `open_reader()` and
///   read up to `current_size() - base_offset()` physical bytes — never
///   `.read_to_end()` — translating any logical offset by subtracting
///   `base_offset()` first.
/// - On write error: truncate the file back to its pre-write physical
///   length, leaving the invariant "bytes up to `size` are valid" intact.
///   Caller kills the PTY.
/// - On-disk size is capped by `max_bytes`; `append` never fails or rejects
///   a write because of the cap — when a write would push the PHYSICAL file
///   past `max_bytes`, it rotates first (drops the oldest half, bumps
///   `base_offset`), then always performs the write. The session is never
///   killed by hitting the cap.
pub struct ConversationLog {
    path: PathBuf,
    writer: Mutex<File>,
    size: AtomicU64,
    max_bytes: u64,
    /// Logical offset of physical file position 0 (see struct docs).
    base_offset: AtomicU64,
    /// Guards a physical byte range against a concurrent rotation
    /// truncating/shifting it out from under an in-flight reader. `append`
    /// (a plain OS thread, via `blocking_write`) takes the write side only
    /// around `rotate_file` itself — never for a plain non-rotating append,
    /// which only extends the file at EOF and never disturbs already-
    /// committed bytes. WS replay (async) takes a read guard via
    /// [`Self::replay_guard`], scoped to one bounded disk read at a time —
    /// never held across a network send, which could stall arbitrarily
    /// long on a slow peer and, for that whole span, block rotation (and
    /// therefore `append`) too.
    rotate_lock: tokio::sync::RwLock<()>,
}

impl ConversationLog {
    /// Opens (or reopens) the log for `conv_id` under `conv_dir`. Creates the
    /// file if it does not exist; **preserves existing content** otherwise.
    /// The file is opened with `O_APPEND`; `size` is initialized from the
    /// current on-disk length so subsequent appends correctly extend it.
    ///
    /// `max_bytes` is the on-disk byte cap for this log — once the physical
    /// file would grow past that value, `append` rotates (drops the oldest
    /// half) before writing, instead of failing. Pass `u64::MAX` to
    /// effectively disable rotation (tests only).
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
            base_offset: AtomicU64::new(0),
            rotate_lock: tokio::sync::RwLock::new(()),
        }))
    }

    /// Append `bytes` to the log and bump the size counter. Returns the new
    /// logical end-offset (total bytes ever written, including `bytes` —
    /// never reduced by rotation).
    ///
    /// If the physical file would grow past `max_bytes`, rotates first
    /// (dropping the oldest half of on-disk content and bumping
    /// `base_offset`) so the on-disk size stays bounded — the session is
    /// never killed by hitting the cap. Rotation loops (bounded — each
    /// round roughly halves the physical length) in the pathological case
    /// where a single `bytes` is itself larger than `max_bytes`; once the
    /// file is empty there is nothing left to drop, so an oversized single
    /// write is accepted rather than looping forever.
    ///
    /// On partial write failure, truncates the file back to the pre-write
    /// physical length so the log stays consistent.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the write or a rotation's file I/O fails.
    pub fn append(&self, bytes: &[u8]) -> std::io::Result<u64> {
        if bytes.is_empty() {
            return Ok(self.size.load(Ordering::Acquire));
        }
        let mut f = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = self.size.load(Ordering::Acquire);
        let mut base = self.base_offset.load(Ordering::Acquire);

        loop {
            let phys_len = prev - base;
            if phys_len == 0 || phys_len.saturating_add(bytes.len() as u64) <= self.max_bytes {
                break;
            }
            // Blocks this OS thread (the PTY background read thread — never
            // an async runtime thread) until any in-flight replay read
            // finishes, so rotation can never truncate/shift bytes a reader
            // is mid-way through streaming.
            let _rotate_guard = self.rotate_lock.blocking_write();
            let dropped = rotate_file(&self.path, phys_len)?;
            if dropped == 0 {
                // `phys_len` is down to 0 or 1 — rotation can no longer make
                // progress (nothing left to halve). Without this break the
                // loop would spin here forever at 100% CPU, holding `f`
                // (the writer mutex) for good and wedging every future
                // append on this session. Accept the oversized write
                // instead — this is the "single write bigger than the whole
                // cap" case `append`'s doc comment already says is handled
                // this way.
                break;
            }
            base = base.saturating_add(dropped);
            self.base_offset.store(base, Ordering::Release);
        }

        match f.write_all(bytes) {
            Ok(()) => {
                // Size is source of truth; bump AFTER write_all returns Ok.
                let end =
                    self.size.fetch_add(bytes.len() as u64, Ordering::Release) + bytes.len() as u64;
                Ok(end)
            }
            Err(e) => {
                // Roll back partial bytes: truncate to the physical length we
                // know is valid (relative to the possibly-just-rotated base).
                let _ = f.set_len(prev - base);
                Err(e)
            }
        }
    }

    /// Current committed size (source of truth) — total logical bytes ever
    /// appended, monotonically increasing and unaffected by rotation.
    #[must_use]
    pub fn current_size(&self) -> u64 {
        self.size.load(Ordering::Acquire)
    }

    /// Logical offset of physical file position 0. Bytes before this offset
    /// have been rotated away and no longer exist on disk. `0` until the log
    /// rotates for the first time.
    #[must_use]
    pub fn base_offset(&self) -> u64 {
        self.base_offset.load(Ordering::Acquire)
    }

    /// Acquire a read guard that blocks any concurrent rotation for as long
    /// as it is held. WS replay should hold this only around a single
    /// bounded disk read (computing a fresh `base_offset`, seeking, and
    /// reading one chunk) — never across the network send that follows —
    /// so a rotation can never truncate/shift the file out from under an
    /// in-flight read, while a slow/stalled peer still cannot hold up
    /// rotation (and therefore `append`) for a whole replay's duration.
    pub async fn replay_guard(&self) -> tokio::sync::RwLockReadGuard<'_, ()> {
        self.rotate_lock.read().await
    }

    /// Open a fresh read FD. The file holds `current_size() - base_offset()`
    /// physical bytes, representing logical offsets `base_offset()..current_size()`.
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

/// Compact `path` in place by dropping its oldest `phys_len / 2` bytes,
/// shifting the retained (newest) half down to the start of the file, then
/// truncating. Returns the number of bytes dropped.
///
/// Uses a separate read-write handle rather than `ConversationLog`'s
/// append-mode writer — `O_APPEND` forces every write to the current EOF
/// regardless of seek position, which makes it unusable for writing into the
/// middle of the file. The shift copies forward (increasing offsets) with
/// the write cursor permanently `dropped` bytes behind the read cursor; for
/// a leftward shift that direction is always safe against self-clobbering
/// (the classic safe `memmove` direction when dest < src), regardless of the
/// chunk size used.
fn rotate_file(path: &Path, phys_len: u64) -> io::Result<u64> {
    let dropped = phys_len / 2;
    if dropped == 0 {
        return Ok(0);
    }
    let kept = phys_len - dropped;
    let mut rw = OpenOptions::new().read(true).write(true).open(path)?;

    let mut buf = vec![0u8; ROTATE_SHIFT_CHUNK];
    let mut src = dropped;
    let mut dst = 0u64;
    while src < phys_len {
        let want = usize::try_from(phys_len - src)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        rw.seek(SeekFrom::Start(src))?;
        let n = rw.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        rw.seek(SeekFrom::Start(dst))?;
        rw.write_all(&buf[..n])?;
        src += n as u64;
        dst += n as u64;
    }
    rw.set_len(kept)?;
    Ok(dropped)
}

/// Reads from `reader` into `buf`, transparently retrying on
/// `ErrorKind::Interrupted` (EINTR) — a signal delivered mid-syscall is not
/// EOF and must not be treated as "the child hung up". Returns `Ok(0)` on
/// genuine EOF, `Ok(n)` for a successful read of `n` bytes, or `Err` for any
/// other I/O error.
fn read_retrying_eintr<R: Read>(mut reader: R, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            other => return other,
        }
    }
}

// ── PtySession ────────────────────────────────────────────────────────────

pub struct PtySession {
    /// PTY master fd — shared between writer (tokio tasks) and reader thread.
    pty: Arc<pty_process::blocking::Pty>,
    /// Child process handle. Taken (`Option::take`) by whichever of
    /// [`Self::close`] or the read thread's normal-exit path gets there
    /// first, so exactly one of them reaps it — never both.
    child: Mutex<Option<std::process::Child>>,
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
    /// Path to the PTY slave device (e.g. `/dev/ttys003` on macOS,
    /// `/dev/pts/3` on Linux). `soyeht-mcp` maps TTY -> pane via this path
    /// to infer the sender of a message.
    slave_tty_path: String,
    /// Process group id of the child, queried via `getpgid()` right after
    /// spawn. `pty-process` makes the child a session leader (`setsid` +
    /// `TIOCSCTTY`) as part of `spawn`, so this is normally equal to the
    /// child's own pid — verified via syscall here rather than assumed, so
    /// it stays correct if that ever changes upstream.
    pgid: i32,
    /// Working directory the child was spawned with. Resolves to the
    /// engine's own cwd at spawn time when the caller didn't specify one
    /// (guest sessions never do; local sessions do via `LocalSpawnSpec::cwd`).
    cwd: PathBuf,
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

    /// Path to the PTY slave device.
    #[must_use]
    pub fn slave_tty_path(&self) -> &str {
        &self.slave_tty_path
    }

    /// Process group id of the child.
    #[must_use]
    pub fn pgid(&self) -> i32 {
        self.pgid
    }

    /// Working directory the child was spawned with.
    #[must_use]
    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    /// Kill every terminal-facing process attached to this session's TTY —
    /// not just the tracked direct child — escalating SIGHUP (now) → SIGTERM
    /// (after 2s, if anything survived) → SIGKILL (after another 2s, if still
    /// surviving). Pipe/socket-backed helpers are left to their parent/EOF
    /// lifecycle so an MCP transport cannot be severed independently of its
    /// live agent client.
    /// Idempotent; returns immediately — the escalation and final reap run
    /// on a detached background thread, so neither an async caller
    /// (`spawn_blocking`) nor the plain OS PTY-read thread ever blocks on
    /// the multi-second timeline.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        // Snapshot BEFORE any teardown: once the PTY's fds are gone the tty
        // association is revoked and survivors become unfindable via
        // `proc_listpids`/`/proc` — same ordering requirement as the
        // reference implementation. Each pid's identity (start time) is
        // captured alongside it, so LATER escalation stages can verify a
        // pid is still the SAME process before re-signaling it — see
        // `TrackedPid` and `signal_survivors`.
        let mut tty_pids: Vec<TrackedPid> = core_rs::os::list_tty_pids(&self.slave_tty_path)
            .into_iter()
            // Exclude only a positive non-terminal classification. Inspection
            // failures preserve the historical fail-closed cleanup behavior.
            .filter(|pid| {
                core_rs::os::process_has_terminal_stdio(*pid, &self.slave_tty_path) != Some(false)
            })
            .filter_map(|p| i32::try_from(p).ok())
            .map(TrackedPid::snapshot)
            .collect();
        // Always include the session leader. `proc_listpids` can race with
        // teardown or fail transiently, but close must still terminate and
        // reap the direct child.
        if !tty_pids.iter().any(|tracked| tracked.pid == self.pgid) {
            tty_pids.push(TrackedPid::snapshot(self.pgid));
        }
        // Immediate — no time has passed for a snapshotted pid to have
        // died and been recycled yet, so no re-verification is needed
        // (unlike the later stages — see spawn_kill_escalation).
        signal_survivors(&tty_pids, KillStage::Hup, false);

        let child = self
            .child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(child) = child {
            spawn_kill_escalation(tty_pids, child);
        }
    }
}

/// Which signal a [`signal_survivors`] round sends.
#[derive(Clone, Copy)]
enum KillStage {
    Hup,
    Term,
    Kill,
}

/// A pid snapshotted from the session's TTY, paired with its process
/// identity (start time) at snapshot time — see `signal_survivors`'s
/// `reverify` parameter for why this is needed instead of just re-checking
/// TTY membership.
struct TrackedPid {
    pid: i32,
    identity: Option<(u64, u64)>,
}

impl TrackedPid {
    fn snapshot(pid: i32) -> Self {
        let identity = u32::try_from(pid).ok().and_then(core_rs::os::process_identity);
        Self { pid, identity }
    }
}

/// Sends `stage`'s signal to every pid in `tty_pids` still alive. Returns
/// whether anything was found alive, so callers can skip later escalation
/// stages once nothing survived.
///
/// This deliberately signals individual terminal-facing jobs instead of the
/// session's process group. An MCP helper can share its owning agent's process
/// group while replacing stdin/stdout with private pipes; a group-wide signal
/// would bypass the classifier that excluded it from `tty_pids`.
///
/// `reverify`: for the LATER escalation stages (SIGTERM, SIGKILL — seconds
/// after the initial snapshot), a snapshotted individual pid can have
/// already exited and been assigned to an unrelated process in the
/// meantime; `is_pid_running` alone can't tell the difference, so
/// signaling it would hit the wrong process. When `true`, re-fetches each
/// candidate's current `process_identity` and skips it unless it still
/// matches the identity captured at snapshot time.
///
/// This deliberately does NOT re-check TTY membership (e.g. re-running
/// `list_tty_pids`) to verify a pid — once a session's controlling process
/// has been signaled, still-alive OTHER members of that session can stop being
/// reported as attached to the tty at all (the same reason they show up as
/// `??` in `ps` afterward), making a TTY-membership re-check unreliable exactly
/// when it matters. Process identity has nothing to do with tty/session state,
/// so it doesn't share that failure mode. Pass `false` for the immediate
/// initial signal (no time has passed since the snapshot for reuse to occur).
fn signal_survivors(tty_pids: &[TrackedPid], stage: KillStage, reverify: bool) -> bool {
    let mut any_alive = false;

    for tracked in tty_pids {
        let member = tracked.pid;
        let Ok(member_u32) = u32::try_from(member) else {
            continue;
        };
        if reverify && core_rs::os::process_identity(member_u32) != tracked.identity {
            continue; // exited (and possibly recycled) since the snapshot — skip it
        }
        if core_rs::os::is_pid_running(member_u32) {
            any_alive = true;
            match stage {
                KillStage::Hup => core_rs::os::kill_pid_hup(member_u32),
                KillStage::Term => core_rs::os::kill_pid(member_u32),
                KillStage::Kill => core_rs::os::kill_pid_force(member_u32),
            }
        }
    }

    any_alive
}

/// Runs the SIGTERM/SIGKILL escalation stages (2s apart) on a detached
/// thread, then reaps `child`. `child` is only reaped here — never
/// unconditionally — because [`PtySession::close`] already took it out of
/// the session before calling this, so the read thread's normal-exit path
/// (which also reaps via the same `Mutex<Option<Child>>` slot) can never
/// double-wait on it.
///
/// `signal_survivors` is called with `reverify = true` for both the Term
/// and Kill stages (never the immediate Hup, which `close()` already sent
/// before spawning this) — seconds have passed by then, long enough for a
/// snapshotted individual pid to have exited and been assigned to an
/// unrelated process.
fn spawn_kill_escalation(tty_pids: Vec<TrackedPid>, mut child: std::process::Child) {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(2));
        if signal_survivors(&tty_pids, KillStage::Term, true) {
            std::thread::sleep(std::time::Duration::from_secs(2));
            signal_survivors(&tty_pids, KillStage::Kill, true);
        }
        // SIGKILL cannot be ignored, so by now the child — if it was ever
        // going to die from these signals — has already exited; `wait()`
        // reaps it (or returns promptly if it exited earlier on its own).
        let _ = child.wait();
    });
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
    let (pty, pts) =
        pty_process::blocking::open().map_err(|e| TerminalError::Other(format!("openpty: {e}")))?;

    pty.resize(pty_process::Size::new(rows, cols))
        .map_err(|e| TerminalError::Other(format!("resize: {e}")))?;

    let tty_path = slave_tty_path(&pty)?;

    let child = pty_process::blocking::Command::new(ctl_path)
        .arg("pty")
        .arg(container)
        .arg(conv_id)
        .env("TERM", "xterm-256color")
        .spawn(pts)
        .map_err(|e| TerminalError::Other(format!("spawn: {e}")))?;

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    Ok(wire_pty_session(
        pty,
        child,
        conv_id,
        log,
        SpawnMeta {
            cols,
            rows,
            tty_path,
            cwd,
        },
    ))
}

/// Resolves the PTY slave device path (e.g. `/dev/ttys003`, `/dev/pts/3`)
/// for the master fd `pty`, so it can be recorded as session metadata.
fn slave_tty_path(pty: &pty_process::blocking::Pty) -> Result<String, TerminalError> {
    rustix::pty::ptsname(pty, Vec::new())
        .map_err(|e| TerminalError::Other(format!("ptsname: {e}")))?
        .into_string()
        .map_err(|_| TerminalError::Other("ptsname returned a non-UTF8 path".to_string()))
}

/// Process group id of `pid`, queried via `getpgid()`. Falls back to `pid`
/// itself (the expected value once `pty-process`'s `session_leader` setup
/// makes the child a session/process-group leader) if the syscall fails —
/// this is best-effort metadata, not a security or correctness boundary.
#[allow(unsafe_code)]
fn child_pgid(pid: u32) -> i32 {
    let raw = libc::pid_t::try_from(pid).unwrap_or(libc::pid_t::MAX);
    // SAFETY: `getpgid` is a plain syscall wrapper; passing any pid value
    // (including one for a process we don't own) is memory-safe — it can
    // only fail (`ESRCH`/`EPERM`), never cause undefined behavior.
    let group = unsafe { libc::getpgid(raw) };
    if group > 0 { group } else { raw }
}

/// Spawn specification for a broker-owned local PTY session (persistent
/// panes). The client resolves everything — argv, working directory, and
/// environment (login PATH, TERM, per-pane identity vars) — and the engine
/// only executes, so pane processes survive app restarts without the engine
/// needing any knowledge of shells or agents.
#[derive(Debug, Clone)]
pub struct LocalSpawnSpec {
    /// Program + arguments. Must be non-empty.
    pub argv: Vec<String>,
    /// Working directory for the child. Inherits the engine's cwd when `None`.
    pub cwd: Option<PathBuf>,
    /// The child's COMPLETE environment — the engine's own process
    /// environment (the daemon's env) is cleared before this is applied, so
    /// nothing is inherited or leaked. The caller (the macOS app's
    /// `resolveSpawnPlan`) is responsible for sending everything the child
    /// needs, matching the app's local (non-broker) spawn path byte-for-byte.
    pub env: Vec<(String, String)>,
}

/// Session metadata surfaced by [`PtyManager::list_local`] (E5). `pgid` and
/// `slave_tty_path` let external tools (`soyeht-mcp`) map a TTY back to the
/// pane that owns it, e.g. to infer which pane a message came from.
#[derive(Debug, Clone)]
pub struct LocalSessionInfo {
    pub conversation_id: String,
    pub slave_tty_path: String,
    pub pgid: i32,
    pub cwd: PathBuf,
    pub is_connected: bool,
}

/// Start a PTY session running a local command described by `spec`, instead
/// of the guest `<ctl> pty` bridge. Same log/broadcast wiring as
/// [`start_pty_session`].
///
/// The child's environment is cleared before `spec.env` is applied — the
/// engine (daemon) process environment is never inherited or leaked into a
/// broker-owned local pane. This gives byte-for-byte parity with the macOS
/// app's own local (non-broker) spawn path, which sends its own complete
/// environment rather than layering on top of whatever the engine happens
/// to be running with. `TERM` is defaulted for callers that omit it;
/// `spec.env` can still override it.
///
/// # Errors
///
/// Returns an error if `argv` is empty, the PTY cannot be opened, or the
/// child cannot be spawned.
pub fn start_pty_session_local(
    spec: &LocalSpawnSpec,
    conv_id: &str,
    log: &Arc<ConversationLog>,
    cols: u16,
    rows: u16,
) -> Result<Arc<PtySession>, TerminalError> {
    let (program, args) = spec
        .argv
        .split_first()
        .ok_or_else(|| TerminalError::Other("argv must not be empty".to_string()))?;

    let (pty, pts) =
        pty_process::blocking::open().map_err(|e| TerminalError::Other(format!("openpty: {e}")))?;

    pty.resize(pty_process::Size::new(rows, cols))
        .map_err(|e| TerminalError::Other(format!("resize: {e}")))?;

    let tty_path = slave_tty_path(&pty)?;

    let mut cmd = pty_process::blocking::Command::new(program)
        .args(args)
        .env_clear()
        .env("TERM", "xterm-256color");
    for (key, value) in &spec.env {
        cmd = cmd.env(key, value);
    }
    if let Some(cwd) = &spec.cwd {
        cmd = cmd.current_dir(cwd);
    }
    let child = cmd
        .spawn(pts)
        .map_err(|e| TerminalError::Other(format!("spawn: {e}")))?;

    let cwd = spec
        .cwd
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    Ok(wire_pty_session(
        pty,
        child,
        conv_id,
        log,
        SpawnMeta {
            cols,
            rows,
            tty_path,
            cwd,
        },
    ))
}

/// Bundled spawn-time session metadata (E5), to keep [`wire_pty_session`]
/// under the clippy arg-count limit.
struct SpawnMeta {
    cols: u16,
    rows: u16,
    tty_path: String,
    cwd: PathBuf,
}

/// Shared post-spawn wiring: read thread (PTY fd → log → broadcast),
/// session construction, and reap-on-exit. Used by both the guest and the
/// local spawn paths. `meta.tty_path`/`meta.cwd` are session metadata (E5)
/// already resolved by the caller; `pgid` is queried here from `child`'s pid.
fn wire_pty_session(
    pty: pty_process::blocking::Pty,
    child: std::process::Child,
    conv_id: &str,
    log: &Arc<ConversationLog>,
    meta: SpawnMeta,
) -> Arc<PtySession> {
    let conv_id_owned = conv_id.to_string();
    let pty = Arc::new(pty);
    let pgid = child_pgid(child.id());
    let (tx, _) = tokio::sync::broadcast::channel::<(u64, Arc<[u8]>)>(BROADCAST_CAP);

    let session = Arc::new(PtySession {
        pty: Arc::clone(&pty),
        child: Mutex::new(Some(child)),
        log: Arc::clone(log),
        write_lock: tokio::sync::Mutex::new(()),
        tx,
        closed: AtomicBool::new(false),
        size: Mutex::new((meta.cols, meta.rows)),
        slave_tty_path: meta.tty_path,
        pgid,
        cwd: meta.cwd,
    });

    // Background read thread: PTY fd → log file → broadcast.
    let session_weak = Arc::downgrade(&session);
    std::thread::spawn(move || {
        let mut buf = [0u8; READ_CHUNK];
        loop {
            // `read_retrying_eintr` absorbs EINTR internally, so any `Err`
            // observed here is a genuine fatal I/O error (never a signal
            // that merely interrupted the syscall).
            match read_retrying_eintr(&*pty, &mut buf) {
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
                        Err(e) => {
                            // `append` rotates instead of ever returning a
                            // cap-hit error (see `ConversationLog::append`),
                            // so this is a genuine disk/IO failure — the
                            // session cannot make progress.
                            tracing::error!(
                                conv_id = %conv_id_owned,
                                "conversation log append failed, killing session: {e}"
                            );
                            sess.close();
                            break;
                        }
                    }
                }
            }
        }
        // Normal exit path: reap (if `close()` didn't already take the
        // child first — see its doc comment) + mark closed. EOF here means
        // the kernel has confirmed no process still holds the PTY slave
        // open, so there is nothing left to kill-escalate.
        if let Some(sess) = session_weak.upgrade() {
            let child = sess
                .child
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(mut child) = child {
                let _ = child.wait();
            }
            sess.closed.store(true, Ordering::SeqCst);
        }
    });

    session
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
    /// Cap on concurrently live local sessions. Read from
    /// `THEYOS_MAX_LOCAL_SESSIONS` once at construction.
    max_local_sessions: usize,
    /// Minimum age (seconds) before an orphaned conversation log becomes
    /// eligible for GC. Read from `THEYOS_ORPHAN_LOG_MAX_AGE_SECS` once at
    /// construction.
    orphan_log_max_age_secs: u64,
}

impl PtyManager {
    /// Create a manager with the given ssh control binary and conversation
    /// log directory. The directory is created on demand; conversation logs
    /// persist across restarts and are only removed by explicit close.
    ///
    /// Reads `THEYOS_CONV_LOG_MAX_BYTES`, `THEYOS_MAX_LOCAL_SESSIONS`, and
    /// `THEYOS_ORPHAN_LOG_MAX_AGE_SECS` once here. Unparseable values fall
    /// back to their defaults with a `tracing::warn!`.
    #[must_use]
    pub fn new(ctl_path: &str, conv_dir: PathBuf) -> Self {
        let conv_log_max_bytes = Self::read_max_bytes_env();
        let max_local_sessions = Self::read_max_local_sessions_env();
        let orphan_log_max_age_secs = Self::read_orphan_log_max_age_env();
        Self::with_limits(
            ctl_path,
            conv_dir,
            conv_log_max_bytes,
            max_local_sessions,
            orphan_log_max_age_secs,
        )
    }

    /// Construct a manager with an explicit byte cap; the local-session
    /// count cap and orphaned-log GC age use their defaults. Primarily for
    /// tests that only care about exercising rotation.
    #[must_use]
    pub fn with_max_bytes(ctl_path: &str, conv_dir: PathBuf, conv_log_max_bytes: u64) -> Self {
        Self::with_limits(
            ctl_path,
            conv_dir,
            conv_log_max_bytes,
            DEFAULT_MAX_LOCAL_SESSIONS,
            DEFAULT_ORPHAN_LOG_MAX_AGE_SECS,
        )
    }

    /// Construct a manager with every limit explicit. Primarily for tests
    /// that need a small `max_local_sessions` (to exercise the cap without
    /// actually spawning that many real processes) or a near-zero
    /// `orphan_log_max_age_secs` (to exercise GC without waiting real days).
    #[must_use]
    pub fn with_limits(
        ctl_path: &str,
        conv_dir: PathBuf,
        conv_log_max_bytes: u64,
        max_local_sessions: usize,
        orphan_log_max_age_secs: u64,
    ) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            ctl_path: ctl_path.to_string(),
            conv_dir,
            conv_log_max_bytes,
            max_local_sessions,
            orphan_log_max_age_secs,
        }
    }

    fn read_max_bytes_env() -> u64 {
        Self::parse_max_bytes(std::env::var("THEYOS_CONV_LOG_MAX_BYTES").ok().as_deref())
    }

    /// Pure parser for the cap env var. Returns the default for `None`,
    /// empty strings, or unparseable values (with a warn in the unparseable
    /// case). Extracted for testability without mutating process env.
    fn parse_max_bytes(raw: Option<&str>) -> u64 {
        let parsed = match raw {
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
        };
        if parsed < MIN_CONV_LOG_MAX_BYTES {
            tracing::warn!(
                value = parsed,
                floor = MIN_CONV_LOG_MAX_BYTES,
                "THEYOS_CONV_LOG_MAX_BYTES is below the sane floor; clamping up"
            );
            MIN_CONV_LOG_MAX_BYTES
        } else {
            parsed
        }
    }

    fn read_max_local_sessions_env() -> usize {
        Self::parse_max_local_sessions(
            std::env::var("THEYOS_MAX_LOCAL_SESSIONS").ok().as_deref(),
        )
    }

    /// Pure parser for the local-session-count cap env var. Returns the
    /// default for `None`, empty strings, zero, or unparseable values (with
    /// a warn in the zero/unparseable case — zero would reject every local
    /// session outright, which is never what an operator setting this
    /// env var actually wants).
    fn parse_max_local_sessions(raw: Option<&str>) -> usize {
        match raw {
            Some(s) if !s.is_empty() => match s.parse::<usize>() {
                Ok(0) => {
                    tracing::warn!(
                        "THEYOS_MAX_LOCAL_SESSIONS is 0, which would reject every local \
                         session; falling back to default"
                    );
                    DEFAULT_MAX_LOCAL_SESSIONS
                }
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        value = %s,
                        error = %e,
                        "THEYOS_MAX_LOCAL_SESSIONS is not a valid usize; falling back to default"
                    );
                    DEFAULT_MAX_LOCAL_SESSIONS
                }
            },
            _ => DEFAULT_MAX_LOCAL_SESSIONS,
        }
    }

    fn read_orphan_log_max_age_env() -> u64 {
        Self::parse_orphan_log_max_age(
            std::env::var("THEYOS_ORPHAN_LOG_MAX_AGE_SECS").ok().as_deref(),
        )
    }

    /// Pure parser for the orphaned-log GC age env var. Returns the default
    /// for `None`, empty strings, or unparseable values (with a warn in the
    /// unparseable case). `0` is accepted as-is (an operator explicitly
    /// asking for the most aggressive GC), unlike the session cap, where 0
    /// would be a foot-gun rather than a usable setting.
    fn parse_orphan_log_max_age(raw: Option<&str>) -> u64 {
        match raw {
            Some(s) if !s.is_empty() => match s.parse::<u64>() {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        value = %s,
                        error = %e,
                        "THEYOS_ORPHAN_LOG_MAX_AGE_SECS is not a valid u64; falling back to default"
                    );
                    DEFAULT_ORPHAN_LOG_MAX_AGE_SECS
                }
            },
            _ => DEFAULT_ORPHAN_LOG_MAX_AGE_SECS,
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

    /// Whether any currently-tracked session — local or guest-container,
    /// regardless of which container — is live for `conv_id`. Both key
    /// formats (`\0local::{conv_id}` and `{container}::{conv_id}`) end in
    /// `::{conv_id}`, so a single suffix check covers both without special-
    /// casing either flow. Safe against a false match from an unrelated
    /// `conv_id`: `validate_conv_id` restricts every id that ever produced a
    /// real key to `[A-Za-z0-9_-]`, so a `conv_id` value can never itself
    /// contain the `::` separator.
    fn is_conv_id_live(map: &HashMap<String, Arc<PtySession>>, conv_id: &str) -> bool {
        let suffix = format!("::{conv_id}");
        map.iter()
            .any(|(key, sess)| key.ends_with(&suffix) && !sess.is_closed())
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

    /// Lazily start a broker-owned local PTY (persistent panes), or return
    /// the existing live session for `conv_id`. Same reuse/log semantics as
    /// [`Self::start`], but the child is a local command described by `spec`
    /// instead of the guest ssh bridge.
    ///
    /// Returns `(session, reconnected)` — `reconnected` is `true` when an
    /// existing live session was returned as-is, `false` when a new process
    /// had to be spawned. Callers (the create endpoint) surface this so the
    /// app can tell "conversation restored" apart from "fresh shell".
    ///
    /// # Errors
    ///
    /// Returns an error if the session cannot be started, or if starting a
    /// genuinely new session would exceed `max_local_sessions` (reattaching
    /// to an existing live session is always allowed, even at the cap).
    pub fn start_local(
        &self,
        conv_id: &str,
        spec: &LocalSpawnSpec,
        cols: u16,
        rows: u16,
    ) -> Result<(Arc<PtySession>, bool), TerminalError> {
        if conv_id.is_empty() {
            return Err(TerminalError::Other(
                "conversation_id is required".to_string(),
            ));
        }
        validate_conv_id(conv_id)?;

        let key = Self::local_session_key(conv_id);
        let mut map = self
            .sessions
            .lock()
            .map_err(|_| TerminalError::Other("mutex poisoned".to_string()))?;

        if let Some(sess) = map.get(&key) {
            if !sess.is_closed() {
                return Ok((Arc::clone(sess), true));
            }
            map.remove(&key);
        }

        // Cap concurrently LIVE local sessions: each one holds a real PTY,
        // child process, and broadcast channel, so unbounded creation
        // exhausts OS process/fd limits for the whole engine. Only live
        // (`!is_closed()`) entries count — already-exited ones hold no live
        // resource and are reaped opportunistically by `cleanup_stale`, so
        // they shouldn't permanently eat into a client's cap headroom just
        // because nobody's run that sweep yet. This only gates spawning a
        // NEW process: the reuse check above already returned early for an
        // existing live session, and reattaching must keep working even
        // when the engine is at the cap.
        let local_prefix = Self::local_session_key("");
        let live_local_count = map
            .iter()
            .filter(|(k, sess)| k.starts_with(&local_prefix) && !sess.is_closed())
            .count();
        if live_local_count >= self.max_local_sessions {
            return Err(TerminalError::Other(format!(
                "local session limit reached ({live_local_count}/{}); close an existing pane \
                 before starting another",
                self.max_local_sessions
            )));
        }

        let _ = std::fs::create_dir_all(&self.conv_dir);
        let log = ConversationLog::open(&self.conv_dir, conv_id, self.conv_log_max_bytes)?;
        let sess = start_pty_session_local(spec, conv_id, &log, cols, rows)?;
        map.insert(key, Arc::clone(&sess));
        Ok((sess, false))
    }

    /// Get an existing local session without starting a new one.
    pub fn get_local(&self, conv_id: &str) -> Option<Arc<PtySession>> {
        let key = Self::local_session_key(conv_id);
        let map = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.get(&key).map(Arc::clone)
    }

    /// List every broker-owned local session (live or not-yet-reaped),
    /// keyed by `conversation_id`, for the session-metadata list endpoint.
    #[must_use]
    pub fn list_local(&self) -> Vec<LocalSessionInfo> {
        let prefix = Self::local_session_key("");
        let map = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.iter()
            .filter_map(|(key, sess)| {
                let conversation_id = key.strip_prefix(&prefix)?.to_string();
                Some(LocalSessionInfo {
                    conversation_id,
                    slave_tty_path: sess.slave_tty_path().to_string(),
                    pgid: sess.pgid(),
                    cwd: sess.cwd().to_path_buf(),
                    is_connected: !sess.is_closed(),
                })
            })
            .collect()
    }

    /// Close and remove a local session; unlinks its log file.
    ///
    /// # Errors
    ///
    /// Returns an error if the session map lock is poisoned.
    pub fn close_local(&self, conv_id: &str) -> Result<(), TerminalError> {
        let key = Self::local_session_key(conv_id);
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
        } else if validate_conv_id(conv_id).is_ok() {
            let path = self.conv_dir.join(format!("{conv_id}.log"));
            let _ = std::fs::remove_file(&path);
        }
        Ok(())
    }

    /// Map key for local (broker-owned) sessions. The `\0` prefix can never
    /// collide with guest keys: NUL never survives container validation.
    fn local_session_key(conv_id: &str) -> String {
        format!("\u{0}local::{conv_id}")
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

    /// Sweeps `conv_dir` for `.log` files with no live in-memory session
    /// (see [`Self::is_conv_id_live`]) whose mtime is older than
    /// `orphan_log_max_age_secs`. Conversation logs persist across restarts
    /// BY DESIGN — this only reclaims logs from `conversation_id`s nobody
    /// has reattached to (or explicitly closed) in a long time.
    ///
    /// This covers a gap `cleanup_stale` structurally cannot: that method
    /// only reaps sessions tracked in the in-memory map THIS run, but a
    /// `conversation_id` nobody has asked for since the last restart never
    /// gets an in-memory entry at all, so its log sits on disk forever
    /// without this sweep. `conv_dir` is shared between local and
    /// guest-container sessions (both use the same `{conv_id}.log` naming),
    /// so this sweeps both — `is_conv_id_live` already protects a live
    /// entry from either flow.
    ///
    /// Returns the number of files removed. I/O errors reading the
    /// directory or a given file's metadata are logged and skipped rather
    /// than treated as fatal — this is best-effort maintenance, not a
    /// correctness-critical path.
    pub fn gc_orphaned_conversation_logs(&self) -> usize {
        let entries = match std::fs::read_dir(&self.conv_dir) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!("[pty-gc] read conv_dir: {e}");
                return 0;
            }
        };

        let now = std::time::SystemTime::now();
        let max_age = std::time::Duration::from_secs(self.orphan_log_max_age_secs);
        let map = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let mut removed = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(conv_id) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".log"))
            else {
                continue;
            };
            if validate_conv_id(conv_id).is_err() {
                continue;
            }
            if Self::is_conv_id_live(&map, conv_id) {
                continue;
            }
            let age = match entry.metadata().and_then(|m| m.modified()) {
                Ok(modified) => now.duration_since(modified).unwrap_or_default(),
                Err(e) => {
                    tracing::warn!(conv_id = %conv_id, "[pty-gc] stat log file: {e}");
                    continue;
                }
            };
            if age < max_age {
                continue;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(e) => {
                    tracing::warn!(conv_id = %conv_id, "[pty-gc] remove orphaned log: {e}");
                }
            }
        }
        removed
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use tempfile::tempdir;

    enum FlakyStep {
        Interrupted,
        Data(Vec<u8>),
    }

    /// A `Read` impl that plays back a scripted sequence of steps, then
    /// reports EOF (`Ok(0)`) forever once the script is exhausted.
    struct FlakyReader(VecDeque<FlakyStep>);

    impl Read for FlakyReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.pop_front() {
                Some(FlakyStep::Interrupted) => {
                    Err(io::Error::from(io::ErrorKind::Interrupted))
                }
                Some(FlakyStep::Data(data)) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    Ok(n)
                }
                None => Ok(0),
            }
        }
    }

    struct AlwaysErrors;

    impl Read for AlwaysErrors {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "gone"))
        }
    }

    #[test]
    fn read_retrying_eintr_retries_past_interrupted() {
        let mut reader = FlakyReader(VecDeque::from([
            FlakyStep::Interrupted,
            FlakyStep::Interrupted,
            FlakyStep::Data(b"hello".to_vec()),
        ]));
        let mut buf = [0u8; 16];
        let n = read_retrying_eintr(&mut reader, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn read_retrying_eintr_propagates_non_interrupted_errors() {
        let mut buf = [0u8; 16];
        let err = read_retrying_eintr(AlwaysErrors, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn read_retrying_eintr_returns_ok_zero_on_eof() {
        let mut reader = FlakyReader(VecDeque::new());
        let mut buf = [0u8; 16];
        let n = read_retrying_eintr(&mut reader, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn signal_survivors_skips_a_tracked_pid_that_has_exited_since_snapshot() {
        // Regression (jovian review, fix C): a snapshotted individual pid
        // can exit and be assigned to an unrelated process before a LATER
        // escalation stage re-signals it; `is_pid_running` alone can't
        // tell the difference. Spawn a short-lived real child, capture its
        // identity while alive, wait for it to exit and be reaped, then
        // prove `signal_survivors` with `reverify = true` refuses to
        // signal it: `process_identity` for an exited pid returns `None`,
        // which never matches the `Some(..)` recorded at snapshot time —
        // exactly the "already gone, possibly recycled" case this guards
        // against.
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = i32::try_from(child.id()).expect("pid fits i32");
        let tracked = TrackedPid::snapshot(pid);
        assert!(
            tracked.identity.is_some(),
            "a live process must have a determinable identity"
        );
        child.wait().expect("reap true");

        let any_alive = signal_survivors(&[tracked], KillStage::Term, true);
        assert!(!any_alive, "an exited pid must never be (re-)signaled");
    }

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
    fn append_rotates_oldest_half_instead_of_failing() {
        // E3: hitting the cap used to fail the write (`FileTooLarge`) and the
        // caller (wire_pty_session) killed the session. Now it rotates —
        // drops the oldest half on disk — and the write always succeeds.
        let dir = tempdir().unwrap();
        let log = ConversationLog::open(dir.path(), "conv_cap", 10).unwrap();

        let end = log.append(b"0123456789").unwrap(); // exactly at the cap
        assert_eq!(end, 10);
        assert_eq!(log.current_size(), 10);
        assert_eq!(log.base_offset(), 0);
        assert_eq!(std::fs::metadata(log.path()).unwrap().len(), 10);

        // One more byte would push physical length to 11 > 10 → rotate first
        // (drop the oldest 5 bytes, keep "56789"), then append "A".
        let end = log.append(b"A").unwrap();
        assert_eq!(
            end, 11,
            "logical size keeps counting monotonically, unaffected by rotation"
        );
        assert_eq!(log.base_offset(), 5, "oldest 5 bytes were dropped");

        let mut f = log.open_reader().unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"56789A");
        assert!(std::fs::metadata(log.path()).unwrap().len() <= 10);
    }

    #[test]
    fn append_never_fails_at_cap_session_stays_alive_indefinitely() {
        // Regression for the E1 follow-up: a small cap used to kill the
        // session after ~2x max_bytes of output. Rotation keeps it alive for
        // arbitrarily large total output, bounded on-disk.
        let dir = tempdir().unwrap();
        let log = ConversationLog::open(dir.path(), "conv_cap_small", 1024).unwrap();
        for _ in 0..2000 {
            log.append(b"0123456789").unwrap();
        }
        assert_eq!(log.current_size(), 20_000);
        let disk_len = std::fs::metadata(log.path()).unwrap().len();
        assert!(
            disk_len <= 1024,
            "on-disk size must stay bounded by the cap, got {disk_len}"
        );
    }

    #[test]
    fn rotation_never_corrupts_retained_tail_across_many_rounds() {
        // Append a distinguishable, non-repeating byte per call so any
        // off-by-one in the shift-copy would show up as corrupted content
        // rather than an innocuous repeated pattern.
        let dir = tempdir().unwrap();
        let log = ConversationLog::open(dir.path(), "conv_cap_seq", 64).unwrap();
        let mut sent = Vec::new();
        for i in 0..500u32 {
            let chunk = format!("{i:04}|").into_bytes();
            sent.extend_from_slice(&chunk);
            log.append(&chunk).unwrap();
        }
        let disk_len = std::fs::metadata(log.path()).unwrap().len();
        assert!(disk_len <= 64);

        let mut f = log.open_reader().unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        // Whatever is on disk must be an exact suffix of everything ever sent.
        assert!(sent.ends_with(&buf));
        assert_eq!(buf.len() as u64, disk_len);
        assert_eq!(log.current_size() - log.base_offset(), disk_len);
    }

    #[test]
    fn append_terminates_even_when_single_chunk_exceeds_a_tiny_cap() {
        // Regression (jovian review, fix A): before the `dropped == 0`
        // break, a cap smaller than a single write (e.g. below READ_CHUNK)
        // made phys_len settle at 0 or 1 and rotate_file() return
        // dropped=0 forever — the append loop spun at 100% CPU while
        // holding the writer mutex, freezing the session's PTY drain
        // permanently. Explicit tiny cap via `ConversationLog::open`
        // directly bypasses the production-only floor in
        // `PtyManager::parse_max_bytes` — this is exactly the
        // pathological case that floor exists to keep out of production,
        // but `append` itself must still terminate even if it's ever
        // reached (e.g. via `with_max_bytes` in a future caller).
        let dir = tempdir().unwrap();
        let log = ConversationLog::open(dir.path(), "conv_tiny_cap", 2).unwrap();
        let burst = vec![b'x'; READ_CHUNK]; // far bigger than the cap

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = log.append(&burst);
            let _ = tx.send(result.is_ok());
        });

        match rx.recv_timeout(std::time::Duration::from_secs(2)) {
            Ok(ok) => assert!(
                ok,
                "append must succeed (accepting the oversized write), not error"
            ),
            Err(_) => panic!("append() did not return within 2s — infinite loop regression"),
        }
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
        assert_eq!(
            PtyManager::parse_max_bytes(Some("104857600")),
            104_857_600,
            "a value above the floor must pass through unchanged"
        );
    }

    #[test]
    fn parse_max_bytes_clamps_up_to_the_floor() {
        assert_eq!(PtyManager::parse_max_bytes(Some("0")), MIN_CONV_LOG_MAX_BYTES);
        assert_eq!(PtyManager::parse_max_bytes(Some("12345")), MIN_CONV_LOG_MAX_BYTES);
        assert_eq!(
            PtyManager::parse_max_bytes(Some(&(MIN_CONV_LOG_MAX_BYTES - 1).to_string())),
            MIN_CONV_LOG_MAX_BYTES
        );
        assert_eq!(
            PtyManager::parse_max_bytes(Some(&MIN_CONV_LOG_MAX_BYTES.to_string())),
            MIN_CONV_LOG_MAX_BYTES,
            "exactly at the floor must not be altered further"
        );
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

    #[test]
    fn parse_max_local_sessions_valid() {
        assert_eq!(PtyManager::parse_max_local_sessions(Some("8")), 8);
    }

    #[test]
    fn parse_max_local_sessions_falls_back_on_zero_or_invalid() {
        assert_eq!(
            PtyManager::parse_max_local_sessions(Some("0")),
            DEFAULT_MAX_LOCAL_SESSIONS,
            "zero would reject every local session outright"
        );
        assert_eq!(
            PtyManager::parse_max_local_sessions(Some("not-a-number")),
            DEFAULT_MAX_LOCAL_SESSIONS
        );
        assert_eq!(
            PtyManager::parse_max_local_sessions(Some("-5")),
            DEFAULT_MAX_LOCAL_SESSIONS
        );
        assert_eq!(
            PtyManager::parse_max_local_sessions(Some("")),
            DEFAULT_MAX_LOCAL_SESSIONS
        );
        assert_eq!(
            PtyManager::parse_max_local_sessions(None),
            DEFAULT_MAX_LOCAL_SESSIONS
        );
    }

    #[test]
    fn parse_orphan_log_max_age_valid_including_zero() {
        assert_eq!(PtyManager::parse_orphan_log_max_age(Some("3600")), 3600);
        assert_eq!(
            PtyManager::parse_orphan_log_max_age(Some("0")),
            0,
            "unlike the session cap, 0 is a real setting here (GC immediately), not a foot-gun"
        );
    }

    #[test]
    fn parse_orphan_log_max_age_falls_back_on_invalid() {
        assert_eq!(
            PtyManager::parse_orphan_log_max_age(Some("not-a-number")),
            DEFAULT_ORPHAN_LOG_MAX_AGE_SECS
        );
        assert_eq!(
            PtyManager::parse_orphan_log_max_age(Some("-5")),
            DEFAULT_ORPHAN_LOG_MAX_AGE_SECS
        );
        assert_eq!(
            PtyManager::parse_orphan_log_max_age(Some("")),
            DEFAULT_ORPHAN_LOG_MAX_AGE_SECS
        );
        assert_eq!(
            PtyManager::parse_orphan_log_max_age(None),
            DEFAULT_ORPHAN_LOG_MAX_AGE_SECS
        );
    }

    /// Long-lived but well-behaved (dies on default SIGHUP disposition, so
    /// `close_local` reaps it near-instantly instead of leaving it to sleep
    /// out its full duration).
    fn sleep_spec(secs: &str) -> LocalSpawnSpec {
        let sleep_bin =
            core_rs::os::which_binary("sleep").expect("sleep must exist for this test");
        LocalSpawnSpec {
            argv: vec![sleep_bin.to_string_lossy().into_owned(), secs.to_string()],
            cwd: None,
            env: vec![],
        }
    }

    #[test]
    fn start_local_rejects_a_new_session_beyond_the_cap_but_reattach_still_works() {
        let dir = tempdir().unwrap();
        let mgr = PtyManager::with_limits(
            "/nonexistent",
            dir.path().to_path_buf(),
            DEFAULT_CONV_LOG_MAX_BYTES,
            2,
            DEFAULT_ORPHAN_LOG_MAX_AGE_SECS,
        );
        let spec = sleep_spec("30");

        let (_s1, reconnected1) = mgr.start_local("cap-conv-a", &spec, 80, 24).unwrap();
        assert!(!reconnected1);
        let (_s2, reconnected2) = mgr.start_local("cap-conv-b", &spec, 80, 24).unwrap();
        assert!(!reconnected2);

        let result = mgr.start_local("cap-conv-c", &spec, 80, 24);
        assert!(
            result.is_err(),
            "a third distinct live session must be rejected at cap 2"
        );
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("session limit"),
            "expected a clear session-limit error, got: {msg}"
        );

        // Reattaching to an EXISTING live session must keep working even at
        // the cap — only spawning a genuinely new process is gated.
        let (_s1_again, reconnected_again) = mgr.start_local("cap-conv-a", &spec, 80, 24).unwrap();
        assert!(reconnected_again);

        mgr.close_local("cap-conv-a").unwrap();
        mgr.close_local("cap-conv-b").unwrap();
    }

    #[test]
    fn start_local_allows_a_new_session_once_a_capped_slot_is_closed() {
        let dir = tempdir().unwrap();
        let mgr = PtyManager::with_limits(
            "/nonexistent",
            dir.path().to_path_buf(),
            DEFAULT_CONV_LOG_MAX_BYTES,
            1,
            DEFAULT_ORPHAN_LOG_MAX_AGE_SECS,
        );
        let spec = sleep_spec("30");

        mgr.start_local("solo-conv-a", &spec, 80, 24).unwrap();
        assert!(mgr.start_local("solo-conv-b", &spec, 80, 24).is_err());

        mgr.close_local("solo-conv-a").unwrap();
        let (_s, reconnected) = mgr
            .start_local("solo-conv-b", &spec, 80, 24)
            .expect("closing the only live slot must free the cap for a new session");
        assert!(!reconnected);

        mgr.close_local("solo-conv-b").unwrap();
    }

    #[test]
    fn gc_orphaned_conversation_logs_removes_old_untracked_logs_but_spares_live_ones() {
        let dir = tempdir().unwrap();
        let mgr = PtyManager::with_limits(
            "/nonexistent",
            dir.path().to_path_buf(),
            DEFAULT_CONV_LOG_MAX_BYTES,
            DEFAULT_MAX_LOCAL_SESSIONS,
            0, // anything not live is immediately eligible
        );

        // A genuinely orphaned log: on disk, but no in-memory session was
        // ever created for it this run — simulates a conversation_id
        // nobody has reattached to since a prior restart.
        let orphan_path = dir.path().join("orphan-conv.log");
        std::fs::write(&orphan_path, b"stale history").unwrap();

        // A live session's log must survive GC regardless of age (age is 0
        // here, so only liveness is protecting it).
        let spec = sleep_spec("30");
        mgr.start_local("live-conv", &spec, 80, 24).unwrap();
        let live_log_path = dir.path().join("live-conv.log");
        assert!(live_log_path.exists());

        let removed = mgr.gc_orphaned_conversation_logs();

        assert_eq!(
            removed, 1,
            "must remove exactly the orphaned log, not the live one"
        );
        assert!(!orphan_path.exists(), "orphaned log must be removed");
        assert!(
            live_log_path.exists(),
            "live session's log must survive GC"
        );

        mgr.close_local("live-conv").unwrap();
    }

    #[test]
    fn gc_orphaned_conversation_logs_spares_recently_modified_orphans() {
        let dir = tempdir().unwrap();
        let mgr = PtyManager::with_limits(
            "/nonexistent",
            dir.path().to_path_buf(),
            DEFAULT_CONV_LOG_MAX_BYTES,
            DEFAULT_MAX_LOCAL_SESSIONS,
            DEFAULT_ORPHAN_LOG_MAX_AGE_SECS, // real default: 30 days
        );
        let recent_path = dir.path().join("recent-conv.log");
        std::fs::write(&recent_path, b"just happened").unwrap(); // mtime = now

        let removed = mgr.gc_orphaned_conversation_logs();

        assert_eq!(removed, 0);
        assert!(
            recent_path.exists(),
            "a recently-touched orphan must not be GC'd yet"
        );
    }

    #[test]
    fn gc_orphaned_conversation_logs_ignores_non_log_and_invalid_names() {
        let dir = tempdir().unwrap();
        let mgr = PtyManager::with_limits(
            "/nonexistent",
            dir.path().to_path_buf(),
            DEFAULT_CONV_LOG_MAX_BYTES,
            DEFAULT_MAX_LOCAL_SESSIONS,
            0,
        );
        std::fs::write(dir.path().join("not-a-log.txt"), b"ignore me").unwrap();
        std::fs::write(dir.path().join("bad id!.log"), b"ignore me too").unwrap();

        let removed = mgr.gc_orphaned_conversation_logs();

        assert_eq!(removed, 0);
        assert!(dir.path().join("not-a-log.txt").exists());
        assert!(dir.path().join("bad id!.log").exists());
    }
}
