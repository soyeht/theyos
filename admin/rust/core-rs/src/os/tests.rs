#![cfg(test)]

use super::*;

#[test]
fn current_pid_is_running() {
    let pid = std::process::id();
    assert!(is_pid_running(pid));
}

#[test]
fn nonexistent_pid_is_not_running() {
    // PID 4294967 is almost certainly not running
    assert!(!is_pid_running(4_294_967));
}

#[test]
fn pid_zero_is_never_running() {
    assert!(!is_pid_running(0));
}

#[test]
fn kill_pid_noop_for_zero() {
    // Should not panic or kill own process group
    kill_pid_hup(0);
    kill_pid(0);
    kill_pid_force(0);
    kill_pgrp_hup(0);
    kill_pgrp(0);
    kill_pgrp_force(0);
}

#[test]
fn getuid_returns_nonzero_in_ci() {
    // In non-root environments, UID should be > 0.
    // Don't assert specific value — just ensure it doesn't panic.
    let _ = getuid();
}

#[test]
fn getgid_returns_value() {
    let _ = getgid();
}

#[test]
fn own_pgrp_returns_nonzero() {
    assert!(
        own_pgrp() > 0,
        "a running process always has a process group"
    );
}

#[test]
fn format_bytes_human_ranges() {
    assert_eq!(format_bytes_human(0), "0B");
    assert_eq!(format_bytes_human(512), "512B");
    assert_eq!(format_bytes_human(1024), "1.0K");
    assert_eq!(format_bytes_human(1_048_576), "1.0M");
    assert_eq!(format_bytes_human(1_073_741_824), "1.0G");
    assert_eq!(format_bytes_human(1_610_612_736), "1.5G");
}

#[test]
fn is_executable_on_self() {
    // The test binary itself should be executable
    let exe = std::env::current_exe().unwrap();
    assert!(is_executable(&exe));
}

#[test]
fn is_executable_on_nonexistent() {
    assert!(!is_executable(Path::new("/nonexistent/path")));
}

#[test]
fn which_binary_finds_sh() {
    // /bin/sh should always exist on Linux
    let result = which_binary("sh");
    assert!(result.is_some());
}

#[test]
fn which_binary_returns_none_for_missing() {
    assert!(which_binary("__nonexistent_binary_core_rs_test__").is_none());
}

#[test]
fn resolve_binary_finds_sh() {
    // /bin/sh should always exist on Linux
    let result = resolve_binary("sh", &[]);
    assert!(result.is_some(), "resolve_binary should find sh");
}

#[test]
fn resolve_binary_returns_none_for_missing() {
    assert!(resolve_binary("__nonexistent_binary_resolve_test__", &[]).is_none());
}

#[test]
fn resolve_binary_checks_extra_paths() {
    // The test binary itself is a valid file — use it as an extra path.
    let exe = std::env::current_exe().unwrap();
    let exe_str = exe.to_str().unwrap();
    let result = resolve_binary("__will_not_be_in_path__", &[exe_str]);
    assert_eq!(result, Some(exe));
}

// ── is_pid_running: zombie detection ───────────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn is_pid_running_returns_false_for_zombie() {
    // Fork a child that exits immediately. Don't call waitpid — the child
    // becomes a zombie. is_pid_running must detect state Z and return false.
    //
    // SAFETY: fork() + _exit() are async-signal-safe POSIX calls.
    // The child does nothing except _exit(0). The parent reaps after the assert.
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork() failed");
        if pid == 0 {
            // Child: exit immediately → becomes zombie until parent waits.
            libc::_exit(0);
        }
        let child_pid = u32::try_from(pid).expect("fork returned a positive child PID");
        // Parent: give child time to exit and become zombie.
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Core assertion: zombie should NOT be considered "running".
        assert!(
            !is_pid_running(child_pid),
            "is_pid_running should return false for zombie PID {pid}"
        );

        // Cleanup: reap the zombie so we don't leak it.
        let mut status: i32 = 0;
        libc::waitpid(pid, std::ptr::addr_of_mut!(status), 0);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn parse_proc_stat_state_for_self() {
    // /proc/self/stat must exist and have state R or S (never Z).
    let state = proc_stat_state(std::process::id());
    assert!(
        state == Some('R') || state == Some('S'),
        "expected R or S for self, got {state:?}"
    );
}

#[test]
fn parse_proc_stat_state_nonexistent_pid() {
    // A non-existent PID should return None.
    assert_eq!(proc_stat_state(4_294_967), None);
}

// ── reap_pid ───────────────────────────────────────────────────────────

#[test]
fn reap_pid_noop_for_zero() {
    // Should not panic.
    reap_pid(0);
}

#[test]
fn reap_pid_noop_for_non_child() {
    // PID 1 (init) is not our child — waitpid returns ECHILD, which is fine.
    reap_pid(1);
}

// ── find_pids_referencing_path / kill_processes_referencing_path ───────

/// Unique marker per test to avoid collisions with parallel `cargo test`.
fn unique_marker(test_name: &str) -> String {
    format!(
        "__core_rs_proc_scan_{test_name}_{}_{}__",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}

#[test]
fn find_pids_referencing_path_empty_when_no_match() {
    let marker = unique_marker("no_match");
    let pids = find_pids_referencing_path(&marker);
    assert!(pids.is_empty(), "expected no matches for unique marker");
}

#[test]
fn find_pids_referencing_path_excludes_self() {
    // Our own process's cmdline contains the test binary path, but
    // find_pids_referencing_path must exclude our own PID.
    let exe = std::env::current_exe().unwrap();
    let exe_str = exe.to_string_lossy();
    let pids = find_pids_referencing_path(&exe_str);
    let my_pid = std::process::id();
    assert!(
        !pids.contains(&my_pid),
        "should exclude current process (PID {my_pid})"
    );
}

/// Spawn a helper process whose cmdline contains the given marker.
/// Creates a temp script at `/tmp/<marker>` that traps signals and sleeps.
/// Returns the `Child` handle. The caller must `kill()+wait()` and remove
/// the temp file.
#[cfg(target_os = "linux")]
fn spawn_with_marker(marker: &str) -> std::process::Child {
    let script_path = format!("/tmp/{marker}");
    // Write a script that does NOT exec — so the shebang interpreter
    // (/bin/sh) stays as the process with our script path in argv[1].
    std::fs::write(
        &script_path,
        "#!/bin/sh\ntrap : INT TERM\nwhile true; do sleep 60; done\n",
    )
    .expect("failed to write temp script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
            .expect("failed to chmod temp script");
    }
    std::process::Command::new(&script_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to spawn marker process")
}

#[cfg(target_os = "linux")]
fn cleanup_marker(marker: &str, child: &mut std::process::Child) {
    child.kill().ok();
    child.wait().ok();
    let _ = std::fs::remove_file(format!("/tmp/{marker}"));
}

#[cfg(target_os = "linux")]
#[test]
fn find_pids_referencing_path_finds_subprocess() {
    let marker = unique_marker("find_sub");
    let mut child = spawn_with_marker(&marker);
    let child_pid = child.id();

    // Give the process time to appear in /proc
    std::thread::sleep(std::time::Duration::from_millis(100));

    let pids = find_pids_referencing_path(&marker);
    assert!(
        pids.contains(&child_pid),
        "should find child PID {child_pid} in results: {pids:?}"
    );

    cleanup_marker(&marker, &mut child);
}

#[cfg(target_os = "linux")]
#[test]
fn kill_processes_referencing_path_kills_match() {
    let marker = unique_marker("kill_match");
    let mut child = spawn_with_marker(&marker);
    let child_pid = child.id();

    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(
        is_pid_running(child_pid),
        "child should be alive before kill"
    );

    let killed = kill_processes_referencing_path(&marker);
    assert!(killed >= 1, "should have killed at least 1 process");

    // Give time for SIGTERM/SIGKILL to take effect + reap
    std::thread::sleep(std::time::Duration::from_millis(300));
    child.wait().ok(); // reap
    assert!(
        !is_pid_running(child_pid),
        "child should be dead after kill"
    );

    let _ = std::fs::remove_file(format!("/tmp/{marker}"));
}

#[test]
fn kill_processes_referencing_path_noop_when_no_match() {
    let marker = unique_marker("kill_noop");
    let killed = kill_processes_referencing_path(&marker);
    assert_eq!(killed, 0, "should not kill anything for unique marker");
}

#[test]
fn find_pids_referencing_path_handles_unreadable_proc() {
    // PID 0 and non-existent PIDs should not cause panics.
    // This test just ensures the function doesn't crash on a normal system.
    let pids = find_pids_referencing_path("/some/path/that/is/used/nowhere");
    // We don't assert the contents, just that it returns without panic.
    let _ = pids;
}

#[cfg(target_os = "linux")]
#[test]
fn reap_pid_collects_zombie() {
    // Fork a child, let it become zombie, reap it, confirm it's gone.
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork() failed");
        if pid == 0 {
            libc::_exit(0);
        }
        let child_pid = u32::try_from(pid).expect("fork returned a positive child PID");
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Before reap: /proc/<pid>/stat should show state Z.
        assert_eq!(
            proc_stat_state(child_pid),
            Some('Z'),
            "child should be zombie before reap"
        );

        reap_pid(child_pid);

        // After reap: the PID should no longer exist (kill probe fails).
        let ret = libc::kill(pid, 0);
        assert_eq!(ret, -1, "PID should be gone after reap");
    }
}

#[test]
fn list_tty_pids_empty_for_nonexistent_path() {
    assert!(list_tty_pids("/dev/definitely-not-a-real-tty-path").is_empty());
}

#[test]
fn list_tty_pids_empty_for_non_tty_device() {
    // /dev/null is a real character device but no process has it as a
    // controlling terminal — proves the call completes and correctly
    // finds zero matches for a device nothing is attached to as a tty.
    assert!(list_tty_pids("/dev/null").is_empty());
}

#[test]
fn process_identity_is_stable_and_present_for_the_current_process() {
    let pid = std::process::id();
    let first = process_identity(pid);
    assert!(
        first.is_some(),
        "a running process must have a determinable identity"
    );
    let second = process_identity(pid);
    assert_eq!(
        first, second,
        "identity must be stable across repeated calls"
    );
}

#[test]
fn process_identity_none_for_nonexistent_pid() {
    assert_eq!(process_identity(4_294_967), None);
}

#[test]
fn process_identity_differs_across_distinct_processes() {
    // Not a proof against pid reuse (that's the whole point — a reused
    // pid number is indistinguishable from the original by definition
    // unless you compare identity), but a sanity check that two
    // DIFFERENT, concurrently-running processes get different
    // identities rather than this always returning some constant.
    let mine = process_identity(std::process::id());
    let init = process_identity(1);
    assert_ne!(
        mine, init,
        "distinct concurrently-running processes must not collide"
    );
}

// ── F1 macOS per-fd rdev classifier — red-first behavioural matrix ──
//
// Safia rubric A1–A5 / C2–C3 (rubric anchor
// safia-ios-pr329-reap-fix-security-lens-2026-07-23.md; readiness
// 18b19245…). Each fixture builds a live child whose CONTROLLING tty is
// PTY A (so `list_tty_pids(A)` lists it — asserted before classification,
// exercising the two-stage reap predicate), then points the child's
// stdin/stdout at a chosen backing. The classifier must key on the
// per-fd device, not the coarse vnode type.
//
// RED on the pre-fix classifier (which ignores `tty_path` and returns
// `Some(true)` for any vnode fd0/fd1): the regular-file, `/dev/null`, and
// different-PTY rows expect `Some(false)` and therefore FAIL until the fix
// lands (A4 non-vacuity). Pipe/socket/real-slave rows stay green (C2 / A5).
#[cfg(target_os = "macos")]
mod macos_f1_per_fd_rdev {
    use super::super::{list_tty_pids, process_has_terminal_stdio};
    use std::os::fd::AsRawFd;

    /// Allocate a PTY master/slave pair, returning `(master, slave, slave_path)`.
    fn open_pty() -> (i32, i32, String) {
        // SAFETY: standard POSIX pty allocation; every returned fd is
        // checked `>= 0`. `ptsname` is single-threaded-only, which holds:
        // the value is consumed immediately on the calling thread.
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(master >= 0, "posix_openpt failed");
            assert_eq!(libc::grantpt(master), 0, "grantpt failed");
            assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");
            let name = libc::ptsname(master);
            assert!(!name.is_null(), "ptsname returned null");
            let path = std::ffi::CStr::from_ptr(name)
                .to_string_lossy()
                .into_owned();
            let cpath = std::ffi::CString::new(path.clone()).unwrap();
            let slave = libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
            assert!(slave >= 0, "open slave failed");
            (master, slave, path)
        }
    }

    /// Fork a `sleep 600` whose controlling tty is `ctty_slave`'s device
    /// and whose stdin/stdout are `fd0`/`fd1`. Returns the child pid.
    fn spawn_sleeper(ctty_slave: i32, fd0: i32, fd1: i32) -> i32 {
        // SAFETY: the child path executes only async-signal-safe libc
        // calls (setsid/ioctl/dup2/execv/_exit) before exec — no Rust
        // allocation or std runtime — which is sound to run post-`fork`
        // in a multi-threaded harness.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                libc::setsid();
                libc::ioctl(ctty_slave, libc::c_ulong::from(libc::TIOCSCTTY), 0);
                libc::dup2(fd0, 0);
                libc::dup2(fd1, 1);
                let prog = c"/bin/sleep";
                let a0 = c"sleep";
                let a1 = c"600";
                let argv = [a0.as_ptr(), a1.as_ptr(), std::ptr::null()];
                libc::execv(prog.as_ptr(), argv.as_ptr());
                libc::_exit(127);
            }
            pid
        }
    }

    /// Poll until `pid` is a member of `slave_path`'s tty (controlling-tty
    /// set), then a short settle so the post-exec fd table is stable.
    fn wait_member(slave_path: &str, pid: i32) {
        for _ in 0..300 {
            if list_tty_pids(slave_path).contains(&u32::try_from(pid).unwrap()) {
                std::thread::sleep(std::time::Duration::from_millis(40));
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("timeout: pid {pid} never joined tty {slave_path}");
    }

    fn reap(pid: i32) {
        // SAFETY: best-effort teardown of our own child.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(pid, &raw mut status, 0);
        }
    }

    fn close_fd(fd: i32) {
        // SAFETY: closing a fd this test owns.
        unsafe {
            libc::close(fd);
        }
    }

    #[test]
    fn regular_file_stdio_is_excluded() {
        let (m_a, s_a, path_a) = open_pty();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let f = tmp.as_raw_fd();
        let pid = spawn_sleeper(s_a, f, f);
        wait_member(&path_a, pid);
        let verdict = process_has_terminal_stdio(u32::try_from(pid).unwrap(), &path_a);
        reap(pid);
        close_fd(s_a);
        close_fd(m_a);
        assert_eq!(
            verdict,
            Some(false),
            "regular-file stdin/stdout is not terminal-facing"
        );
    }

    #[test]
    fn dev_null_stdio_is_excluded() {
        let (m_a, s_a, path_a) = open_pty();
        // SAFETY: opening /dev/null.
        let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
        assert!(devnull >= 0);
        let pid = spawn_sleeper(s_a, devnull, devnull);
        wait_member(&path_a, pid);
        let verdict = process_has_terminal_stdio(u32::try_from(pid).unwrap(), &path_a);
        reap(pid);
        close_fd(devnull);
        close_fd(s_a);
        close_fd(m_a);
        // /dev/null IS a char device — proves char-type alone is insufficient.
        assert_eq!(
            verdict,
            Some(false),
            "/dev/null (char, rdev != slave) is not terminal-facing"
        );
    }

    #[test]
    fn different_pty_is_excluded_for_a_and_included_for_b() {
        let (m_a, s_a, path_a) = open_pty();
        let (m_b, s_b, path_b) = open_pty();
        // controlling tty is A; stdin/stdout point at B's slave.
        let pid = spawn_sleeper(s_a, s_b, s_b);
        wait_member(&path_a, pid);
        let verdict_a = process_has_terminal_stdio(u32::try_from(pid).unwrap(), &path_a);
        let verdict_b = process_has_terminal_stdio(u32::try_from(pid).unwrap(), &path_b);
        reap(pid);
        for fd in [s_a, m_a, s_b, m_b] {
            close_fd(fd);
        }
        assert_eq!(
            verdict_a,
            Some(false),
            "cross-session PTY B on fd0/1 is not terminal-facing for A"
        );
        assert_eq!(
            verdict_b,
            Some(true),
            "fd0/1 bound to B's slave IS terminal-facing for B"
        );
    }

    #[test]
    fn pipe_stdio_is_excluded() {
        let (m_a, s_a, path_a) = open_pty();
        let mut fds = [0i32; 2];
        // SAFETY: `fds` has room for the two pipe ends.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let pid = spawn_sleeper(s_a, fds[0], fds[1]);
        wait_member(&path_a, pid);
        let verdict = process_has_terminal_stdio(u32::try_from(pid).unwrap(), &path_a);
        reap(pid);
        for fd in [fds[0], fds[1], s_a, m_a] {
            close_fd(fd);
        }
        assert_eq!(
            verdict,
            Some(false),
            "pipe stdio (MCP-helper shape) must stay excluded"
        );
    }

    #[test]
    fn socketpair_stdio_is_excluded() {
        let (m_a, s_a, path_a) = open_pty();
        let mut sv = [0i32; 2];
        // SAFETY: `sv` has room for the two socket ends.
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) },
            0
        );
        let pid = spawn_sleeper(s_a, sv[0], sv[1]);
        wait_member(&path_a, pid);
        let verdict = process_has_terminal_stdio(u32::try_from(pid).unwrap(), &path_a);
        reap(pid);
        for fd in [sv[0], sv[1], s_a, m_a] {
            close_fd(fd);
        }
        assert_eq!(verdict, Some(false), "socketpair stdio must stay excluded");
    }

    #[test]
    fn real_slave_tty_stdio_is_included() {
        let (m_a, s_a, path_a) = open_pty();
        // stdin/stdout ARE A's own slave: the genuine terminal job.
        let pid = spawn_sleeper(s_a, s_a, s_a);
        wait_member(&path_a, pid);
        let verdict = process_has_terminal_stdio(u32::try_from(pid).unwrap(), &path_a);
        reap(pid);
        close_fd(s_a);
        close_fd(m_a);
        assert_eq!(
            verdict,
            Some(true),
            "a real slave-TTY job stays terminal-classified (A5)"
        );
    }
}

// ── F1 pure classifier matrix (deterministic; no syscalls) ──
// Exhaustive over Safia A3's rows, including the metadata-unavailable row
// (VnodeUnreadable → None) that has no deterministic syscall fixture.
#[cfg(target_os = "macos")]
mod macos_f1_classify_pure {
    use super::super::{StdioFd, classify_terminal_stdio};

    const SLAVE: u32 = 0x0123_4567;
    const S_IFCHR: u16 = 0o02_0000;
    const S_IFREG: u16 = 0o10_0000;

    fn chr(rdev: u32) -> StdioFd {
        StdioFd::Vnode {
            mode: S_IFCHR | 0o620,
            rdev,
        }
    }

    #[test]
    fn exact_slave_char_included() {
        assert_eq!(classify_terminal_stdio(&[chr(SLAVE)], SLAVE), Some(true));
    }

    #[test]
    fn char_device_with_other_rdev_excluded() {
        // /dev/null shape: a char device, but a different rdev.
        assert_eq!(
            classify_terminal_stdio(&[chr(SLAVE ^ 1)], SLAVE),
            Some(false)
        );
    }

    #[test]
    fn regular_file_excluded_even_if_rdev_collides() {
        // Not a char device → excluded regardless of rdev.
        assert_eq!(
            classify_terminal_stdio(
                &[StdioFd::Vnode {
                    mode: S_IFREG | 0o644,
                    rdev: SLAVE
                }],
                SLAVE
            ),
            Some(false)
        );
    }

    #[test]
    fn pipe_or_socket_excluded() {
        assert_eq!(
            classify_terminal_stdio(&[StdioFd::Other, StdioFd::Other], SLAVE),
            Some(false)
        );
    }

    #[test]
    fn nothing_inspectable_is_none_include() {
        assert_eq!(classify_terminal_stdio(&[], SLAVE), None);
    }

    #[test]
    fn unreadable_vnode_is_none_include() {
        assert_eq!(
            classify_terminal_stdio(&[StdioFd::VnodeUnreadable], SLAVE),
            None
        );
        assert_eq!(
            classify_terminal_stdio(&[StdioFd::Other, StdioFd::VnodeUnreadable], SLAVE),
            None
        );
    }

    #[test]
    fn exact_match_wins_over_unreadable_sibling() {
        assert_eq!(
            classify_terminal_stdio(&[StdioFd::VnodeUnreadable, chr(SLAVE)], SLAVE),
            Some(true)
        );
    }

    #[test]
    fn or_across_two_fds_second_matches() {
        assert_eq!(
            classify_terminal_stdio(&[chr(SLAVE ^ 2), chr(SLAVE)], SLAVE),
            Some(true)
        );
    }
}
