#![cfg(test)]

use super::*;
use std::fs;
#[cfg(unix)]
use std::process::{Child, Command};
#[cfg(unix)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
static FORCE_KILL_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

#[cfg(unix)]
struct TestChild {
    child: Child,
}

#[cfg(unix)]
impl TestChild {
    fn pid(&self) -> u32 {
        self.child.id()
    }
}

#[cfg(unix)]
impl Drop for TestChild {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(unix)]
fn spawn_test_child(ignore_term: bool) -> TestChild {
    use std::os::unix::process::CommandExt;

    let mut command = Command::new("/bin/sh");
    if ignore_term {
        command.args(["-c", "trap '' TERM; exec /bin/sleep 30"]);
    } else {
        command.args(["-c", "exec /bin/sleep 30"]);
    }
    // Give the child its own process group so the cleanup path may safely
    // exercise its real process-group signals without affecting this test.
    command.process_group(0);

    TestChild {
        child: command.spawn().expect("spawn controlled sleep child"),
    }
}

#[cfg(unix)]
fn pid_exists(pid: u32) -> bool {
    let pid = i32::try_from(pid).expect("child PID must fit i32");
    // SAFETY: kill(pid, 0) only probes existence; pid came from Child::id.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[cfg(unix)]
fn wait_until_pid_exists(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if pid_exists(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("controlled child PID {pid} never became observable");
}

#[cfg(unix)]
fn wait_until_pid_is_esrch(pid: u32) {
    let pid = i32::try_from(pid).expect("child PID must fit i32");
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        // SAFETY: kill(pid, 0) only probes existence; pid came from Child::id.
        let result = unsafe { libc::kill(pid, 0) };
        if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("controlled child PID {pid} did not reach ESRCH before timeout");
}

#[cfg(unix)]
fn count_force_kill(_: u32) {
    FORCE_KILL_ATTEMPTS.fetch_add(1, Ordering::SeqCst);
}

// ── CreateGuard ────────────────────────────────────────────────────────

#[test]
fn create_guard_without_commit_removes_directory() {
    let dir = tempfile::tempdir().unwrap();
    let instance_dir = dir.path().join("test-instance");
    fs::create_dir(&instance_dir).unwrap();
    assert!(instance_dir.exists());

    {
        let _guard = CreateGuard::new(instance_dir.clone());
        // Drop without commit
    }

    assert!(
        !instance_dir.exists(),
        "instance dir should be removed after drop without commit"
    );
}

#[test]
fn create_guard_with_commit_preserves_directory() {
    let dir = tempfile::tempdir().unwrap();
    let instance_dir = dir.path().join("test-instance");
    fs::create_dir(&instance_dir).unwrap();

    {
        let mut guard = CreateGuard::new(instance_dir.clone());
        guard.commit();
    }

    assert!(
        instance_dir.exists(),
        "instance dir should survive drop after commit"
    );
}

#[test]
fn create_guard_removes_socket_files_on_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let instance_dir = dir.path().join("test-instance");
    fs::create_dir(&instance_dir).unwrap();

    let fc_sock = instance_dir.join("firecracker.sock");
    let slirp_sock = instance_dir.join("slirp-api.sock");
    fs::write(&fc_sock, "").unwrap();
    fs::write(&slirp_sock, "").unwrap();
    assert!(fc_sock.exists());
    assert!(slirp_sock.exists());

    {
        let _guard = CreateGuard::new(instance_dir.clone());
    }

    // Both sockets and the directory should be gone
    assert!(!fc_sock.exists());
    assert!(!slirp_sock.exists());
    assert!(!instance_dir.exists());
}

#[test]
fn create_guard_with_bogus_pids_still_cleans_up_directory() {
    // PIDs 999_999_999 won't exist — kill calls are best-effort.
    // The important thing is the directory still gets removed.
    let dir = tempfile::tempdir().unwrap();
    let instance_dir = dir.path().join("test-instance");
    fs::create_dir(&instance_dir).unwrap();
    fs::write(instance_dir.join("rootfs.ext4"), "fake").unwrap();

    {
        let mut guard = CreateGuard::new(instance_dir.clone());
        guard.set_fc_pid(999_999_999);
        guard.set_slirp_pid(999_999_998);
        // Drop without commit — cleanup runs with nonexistent PIDs
    }

    assert!(
        !instance_dir.exists(),
        "directory should be removed even with bogus PIDs"
    );
}

#[cfg(unix)]
#[test]
fn cleanup_kills_real_child_and_rechecks_until_esrch() {
    let dir = tempfile::tempdir().unwrap();
    let instance_dir = dir.path().join("test-instance");
    fs::create_dir(&instance_dir).unwrap();
    let child = spawn_test_child(false);
    let pid = child.pid();
    wait_until_pid_exists(pid);

    assert!(
        do_cleanup(&instance_dir, Some(pid), None),
        "verified cleanup must remove the instance directory"
    );
    wait_until_pid_is_esrch(pid);
    assert!(
        !instance_dir.exists(),
        "the directory must be removed only after the real child is gone"
    );
}

// QUARANTINED 2026-08-07 — flaky on a required CI check; cause not isolated.
// Tracking issue: https://github.com/soyeht/theyos/issues/438
//
// Failed 4× in 4 days on required checks, on both OS, always here at
// `assert!(!removed)` (the survivor did NOT survive, so cleanup removed the
// directory). The denominator is a loaded runner, not a platform (3 of 4 on
// Linux, 1 on macOS):
//   - macOS  run 30909529385  @aa3f4caa       2026-08-04
//   - Linux  run 31073232986  @e60bad85       2026-08-06
//   - Linux  PR #434          @51a06355       2026-08-07
//   - Linux  run 31205432352  @f1c1a153 (#435) 2026-08-07
//
// Leading hypothesis is a readiness race: the helper that gates cleanup on
// the child *existing* (`pid_exists`) returns true within ~µs of spawn,
// while the shell only runs `trap '' TERM` some milliseconds later. A
// SIGTERM landing in that window kills a child this test assumes ignores
// TERM. The mechanism reproduces in a scratch harness (pre-trap child +
// SIGTERM -> child killed 100/100; PID is observable ~3–16 ms before the
// trap marker) but NOT on this test locally — it passes on an idle host and
// even with the pre-trap window forced wide open, matching the plan's "só
// abre em runner lento". That is short of the plan's honest criterion (RED
// reproduced on the test, or cause isolated from a real CI stack with the
// fix proven by a negative control), so this is quarantined, not fixed.
//
// Quarantined rather than left flaking: a required check that fails at
// random destroys the meaning of every green and teaches re-run-to-green;
// with `enforce_admins` now on, it blocks correct merges outright.
//
// To lift: reproduce the red ON THIS TEST under CI load (or pin the exact
// timing), then fix WITHOUT removing any assert, then 200 passes both OS.
#[cfg(unix)]
#[test]
#[ignore = "flaky on a required CI check; cause not isolated — see the note above and issue #438"]
fn cleanup_quarantines_real_term_ignoring_survivor_after_force_attempts() {
    let dir = tempfile::tempdir().unwrap();
    let instance_dir = dir.path().join("_warm-picoclaw-0");
    fs::create_dir(&instance_dir).unwrap();
    let child = spawn_test_child(true);
    let pid = child.pid();
    wait_until_pid_exists(pid);
    let force_before = FORCE_KILL_ATTEMPTS.load(Ordering::SeqCst);

    let removed = do_cleanup_with_ops(
        &instance_dir,
        Some(pid),
        None,
        CleanupOps {
            is_pid_running,
            persist_marker: persist_hostfwd_uncertain_marker,
            kill_pid,
            kill_pgrp,
            kill_pid_force: count_force_kill,
            kill_pgrp_force: count_force_kill,
            reap_pid,
            sleep: simulated_sleep,
        },
    );

    assert!(!removed, "a real survivor must block directory removal");
    assert!(
        FORCE_KILL_ATTEMPTS.load(Ordering::SeqCst) >= force_before + 2,
        "the force-kill hooks must be reached after TERM is ignored"
    );
    assert!(
        pid_exists(pid),
        "the real child must still be observed alive"
    );
    assert!(instance_dir.exists(), "survivor evidence must be preserved");
    assert!(
        instance_dir
            .join(crate::instance_env::HOSTFWD_UNCERTAIN_MARKER)
            .exists(),
        "the survivor path must retain its quarantine marker"
    );
}

#[test]
fn create_guard_capture_diagnostic_logs_before_drop() {
    let dir = tempfile::tempdir().unwrap();
    let instance_dir = dir.path().join("test-instance");
    fs::create_dir(&instance_dir).unwrap();
    fs::write(instance_dir.join("serial.log"), "kernel: boot ok\n").unwrap();
    fs::write(instance_dir.join("slirp.log"), "slirp: started\n").unwrap();

    let logs;
    {
        let guard = CreateGuard::new(instance_dir.clone());
        logs = guard.capture_diagnostic_logs();
        // Guard drops here — directory is deleted
    }

    assert!(!instance_dir.exists(), "directory should be removed");
    assert!(
        logs.serial_log_tail.as_deref().unwrap().contains("boot ok"),
        "serial log should have been captured before deletion"
    );
    assert!(
        logs.slirp_log_tail
            .as_deref()
            .unwrap()
            .contains("slirp: started"),
        "slirp log should have been captured before deletion"
    );
}

// ── ClaimGuard ─────────────────────────────────────────────────────────

#[test]
fn claim_guard_without_commit_removes_directory() {
    let dir = tempfile::tempdir().unwrap();
    let instance_dir = dir.path().join("claimed-instance");
    fs::create_dir(&instance_dir).unwrap();

    {
        let _guard = ClaimGuard::new(instance_dir.clone(), None, None);
    }

    assert!(
        !instance_dir.exists(),
        "claimed dir should be removed after rollback"
    );
}

#[test]
fn claim_guard_with_commit_preserves_directory() {
    let dir = tempfile::tempdir().unwrap();
    let instance_dir = dir.path().join("claimed-instance");
    fs::create_dir(&instance_dir).unwrap();

    {
        let mut guard = ClaimGuard::new(instance_dir.clone(), None, None);
        guard.commit();
    }

    assert!(
        instance_dir.exists(),
        "claimed dir should survive after commit"
    );
}

// ── PoolFillGuard ──────────────────────────────────────────────────────

#[test]
fn pool_fill_guard_without_commit_removes_directory() {
    let dir = tempfile::tempdir().unwrap();
    let pool_dir = dir.path().join("_warm-picoclaw-0");
    fs::create_dir(&pool_dir).unwrap();

    {
        let _guard = PoolFillGuard::new(pool_dir.clone());
    }

    assert!(
        !pool_dir.exists(),
        "pool dir should be removed after fill rollback"
    );
}

#[test]
fn pool_fill_guard_with_commit_preserves_directory() {
    let dir = tempfile::tempdir().unwrap();
    let pool_dir = dir.path().join("_warm-picoclaw-0");
    fs::create_dir(&pool_dir).unwrap();

    {
        let mut guard = PoolFillGuard::new(pool_dir.clone());
        guard.commit();
    }

    assert!(
        pool_dir.exists(),
        "pool dir should survive after successful fill"
    );
}

#[test]
fn pool_fill_guard_with_bogus_pids_cleans_up_directory() {
    let dir = tempfile::tempdir().unwrap();
    let pool_dir = dir.path().join("_warm-picoclaw-0");
    fs::create_dir(&pool_dir).unwrap();
    fs::write(pool_dir.join("firecracker.sock"), "").unwrap();

    {
        let mut guard = PoolFillGuard::new(pool_dir.clone());
        guard.set_fc_pid(999_999_997);
        guard.set_slirp_pid(999_999_996);
    }

    assert!(
        !pool_dir.exists(),
        "pool dir should be removed even with bogus PIDs"
    );
}

fn simulated_survivor(_: u32) -> bool {
    true
}

fn simulated_stopped(_: u32) -> bool {
    false
}

fn simulated_noop(_: u32) {}

fn simulated_sleep(_: std::time::Duration) {}

fn simulated_marker_failure(_: &Path, _: &str) -> Result<(), crate::error::VmError> {
    Err(crate::error::VmError::Io("simulated marker failure".into()))
}

#[test]
fn cleanup_preserves_quarantine_evidence_when_process_survives() {
    let dir = tempfile::tempdir().unwrap();
    let instance_dir = dir.path().join("_warm-picoclaw-0");
    fs::create_dir(&instance_dir).unwrap();

    let removed = do_cleanup_with_ops(
        &instance_dir,
        Some(4242),
        None,
        CleanupOps {
            is_pid_running: simulated_survivor,
            persist_marker: persist_hostfwd_uncertain_marker,
            kill_pid: simulated_noop,
            kill_pgrp: simulated_noop,
            kill_pid_force: simulated_noop,
            kill_pgrp_force: simulated_noop,
            reap_pid: simulated_noop,
            sleep: simulated_sleep,
        },
    );

    assert!(
        !removed,
        "a surviving process must prevent directory removal"
    );
    assert!(instance_dir.exists(), "survivor evidence must be preserved");
    assert!(
        instance_dir
            .join(crate::instance_env::HOSTFWD_UNCERTAIN_MARKER)
            .exists(),
        "cleanup must quarantine before attempting teardown"
    );
}

#[test]
fn cleanup_still_tears_down_when_marker_persistence_fails() {
    let dir = tempfile::tempdir().unwrap();
    let instance_dir = dir.path().join("_warm-picoclaw-0");
    fs::create_dir(&instance_dir).unwrap();

    let removed = do_cleanup_with_ops(
        &instance_dir,
        Some(4243),
        None,
        CleanupOps {
            is_pid_running: simulated_stopped,
            persist_marker: simulated_marker_failure,
            kill_pid: simulated_noop,
            kill_pgrp: simulated_noop,
            kill_pid_force: simulated_noop,
            kill_pgrp_force: simulated_noop,
            reap_pid: simulated_noop,
            sleep: simulated_sleep,
        },
    );

    assert!(
        removed,
        "marker failure must not suppress teardown when all processes are dead"
    );
    assert!(
        !instance_dir.exists(),
        "verified teardown may remove evidence after marker failure"
    );
}

#[test]
fn cleanup_preserves_unparseable_state_instead_of_dropping_pids() {
    let dir = tempfile::tempdir().unwrap();
    let instance_dir = dir.path().join("_warm-picoclaw-0");
    fs::create_dir(&instance_dir).unwrap();
    fs::write(
        instance_dir.join("instance.env"),
        "CONTAINER_NAME=picoclaw-test\n\
             CUSTOMER_NAME=test\n\
             CLAW_TYPE=picoclaw\n\
             PORT=35000\n\
             SSH_PORT=22002\n\
             FIRECRACKER_PID=not-a-pid\n\
             SLIRP_PID=\n",
    )
    .unwrap();

    let removed = do_cleanup_with_ops(
        &instance_dir,
        None,
        None,
        CleanupOps {
            is_pid_running: simulated_stopped,
            persist_marker: persist_hostfwd_uncertain_marker,
            kill_pid: simulated_noop,
            kill_pgrp: simulated_noop,
            kill_pid_force: simulated_noop,
            kill_pgrp_force: simulated_noop,
            reap_pid: simulated_noop,
            sleep: simulated_sleep,
        },
    );

    assert!(!removed, "unparseable state must never be treated as empty");
    assert!(instance_dir.exists(), "unparseable state must be preserved");
    assert!(
        instance_dir
            .join(crate::instance_env::HOSTFWD_UNCERTAIN_MARKER)
            .exists(),
        "unparseable state must be quarantined before recovery"
    );
}
