#![cfg(test)]

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
            Some(FlakyStep::Interrupted) => Err(io::Error::from(io::ErrorKind::Interrupted)),
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
        Err(error) => {
            panic!("append() did not return within 2s — infinite loop regression: {error}")
        }
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
        let mgr_a = PtyManager::with_max_bytes("/nonexistent", dir.path().to_path_buf(), u64::MAX);
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
    assert_eq!(
        PtyManager::parse_max_bytes(Some("0")),
        MIN_CONV_LOG_MAX_BYTES
    );
    assert_eq!(
        PtyManager::parse_max_bytes(Some("12345")),
        MIN_CONV_LOG_MAX_BYTES
    );
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
    let sleep_bin = core_rs::os::which_binary("sleep").expect("sleep must exist for this test");
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
    assert!(live_log_path.exists(), "live session's log must survive GC");

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
