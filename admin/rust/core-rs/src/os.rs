//! OS-level utilities — consolidated from vmrunner-rs, imagebuilder-rs, soyeht-rs,
//! launcher-rs, and rootfsbuilder-rs.

// This module wraps POSIX FFI syscalls (kill, getuid, getgid) — unsafe is required.
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn proc_pidinfo(
        pid: i32,
        flavor: i32,
        arg: u64,
        buffer: *mut std::ffi::c_void,
        buffersize: i32,
    ) -> i32;
}

/// Resolve the path to `slirp4netns`.
///
/// Strategy (in order):
///   1. `SLIRP4NETNS_BIN` env var (if set, non-empty, and file exists)
///   2. `which slirp4netns` on PATH
///   3. Shallow `/nix/store` scan for `bin/slirp4netns`
///   4. `None` if not found
#[must_use]
pub fn resolve_slirp4netns() -> Option<PathBuf> {
    // 1. Env var
    if let Ok(v) = std::env::var("SLIRP4NETNS_BIN")
        && !v.is_empty()
    {
        let p = PathBuf::from(&v);
        if p.exists() {
            return Some(p);
        }
    }
    // 2. PATH lookup
    if let Some(p) = which_binary("slirp4netns") {
        return Some(p);
    }
    // 3. Nix store scan
    let nix_store = Path::new("/nix/store");
    if nix_store.is_dir()
        && let Ok(rd) = std::fs::read_dir(nix_store)
    {
        let mut candidates: Vec<PathBuf> = rd
            .flatten()
            .filter_map(|entry| {
                let candidate = entry.path().join("bin/slirp4netns");
                candidate.is_file().then_some(candidate)
            })
            .collect();
        // Sort descending by name so newest Nix store path wins
        candidates.sort();
        candidates.reverse();
        if let Some(c) = candidates.into_iter().next() {
            return Some(c);
        }
    }
    None
}

/// Check whether a process with the given PID is **alive** (not zombie, not dead).
///
/// Uses `kill(pid, 0)` as a fast existence probe, then reads `/proc/<pid>/stat`
/// to detect zombie (state `Z`) processes. A zombie is a process that has exited
/// but whose parent has not yet called `waitpid` — `kill(pid, 0)` succeeds for
/// zombies, but they are functionally dead.
///
/// Returns `false` for zombies, non-existent PIDs, and PID 0.
#[must_use]
pub fn is_pid_running(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: `kill(pid, 0)` is a POSIX existence probe — no signal is delivered.
    // Integer arguments only; no Rust-managed memory is accessed.
    #[allow(clippy::cast_possible_wrap)] // NOTE: PIDs > i32::MAX are not valid on Linux
    let ret = unsafe { libc_kill(pid as i32, 0) };
    if ret == 0 {
        // Process exists in the kernel — but it might be a zombie.
        // Check /proc/<pid>/stat to distinguish alive from Z state.
        return proc_stat_state(pid) != Some('Z');
    }
    // ret == -1: check errno. EPERM means the process exists but we lack
    // permission to signal it. ESRCH means the process does not exist.
    let err = std::io::Error::last_os_error();
    err.raw_os_error() == Some(libc::EPERM)
}

/// Read the process state character from `/proc/<pid>/stat`.
///
/// The state field is the 3rd field in `/proc/<pid>/stat` (after the PID and
/// the command name in parentheses). Common values:
///   - `R` = running
///   - `S` = sleeping (interruptible)
///   - `D` = sleeping (uninterruptible / disk)
///   - `T` = stopped
///   - `Z` = zombie
///
/// Returns `None` if the file cannot be read or parsed (e.g. PID doesn't exist).
#[must_use]
pub fn proc_stat_state(pid: u32) -> Option<char> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Format: "<pid> (<comm>) <state> ..."
    // The comm field can contain spaces and parentheses, so we find the LAST ')'.
    let after_comm = content.rfind(')')? + 1;
    // The state char is the first non-space character after the closing paren.
    content[after_comm..].trim_start().chars().next()
}

/// Reap a zombie child process without blocking.
///
/// Calls `waitpid(pid, WNOHANG)` to collect the exit status of a terminated
/// child process. This is a no-op if:
///   - `pid == 0` (would wait for any child in the same process group)
///   - The PID is not a child of the current process (`ECHILD`)
///   - The child hasn't exited yet (`WNOHANG` returns immediately)
///
/// This function is safe to call unconditionally after killing a process.
pub fn reap_pid(pid: u32) {
    if pid == 0 {
        return;
    }
    // SAFETY: `waitpid(pid, &mut status, WNOHANG)` is a POSIX syscall.
    // We pass a valid mutable pointer to a stack-allocated i32.
    // WNOHANG ensures we never block. pid == 0 is guarded above.
    #[allow(clippy::cast_possible_wrap)]
    unsafe {
        let mut status: i32 = 0;
        libc::waitpid(pid as i32, &raw mut status, libc::WNOHANG);
    }
}

/// Send SIGHUP to a process. No-op if pid == 0 (would kill own process group).
pub fn kill_pid_hup(pid: u32) {
    if pid == 0 {
        return;
    }
    // SAFETY: `kill(pid, SIGHUP)` is a POSIX syscall. Integer arguments only;
    // no Rust-managed memory is accessed. pid == 0 is guarded above.
    #[allow(clippy::cast_possible_wrap)] // NOTE: PIDs > i32::MAX are not valid on Linux
    unsafe {
        libc_kill(pid as i32, 1);
    }
}

/// Send SIGTERM to a process. No-op if pid == 0 (would kill own process group).
pub fn kill_pid(pid: u32) {
    if pid == 0 {
        return;
    }
    // SAFETY: `kill(pid, SIGTERM)` is a POSIX syscall. Integer arguments only;
    // no Rust-managed memory is accessed. pid == 0 is guarded above.
    #[allow(clippy::cast_possible_wrap)] // NOTE: PIDs > i32::MAX are not valid on Linux
    unsafe {
        libc_kill(pid as i32, 15);
    }
}

/// Send SIGKILL to a process. No-op if pid == 0.
pub fn kill_pid_force(pid: u32) {
    if pid == 0 {
        return;
    }
    // SAFETY: `kill(pid, SIGKILL)` is a POSIX syscall. Integer arguments only;
    // no Rust-managed memory is accessed. pid == 0 is guarded above.
    #[allow(clippy::cast_possible_wrap)] // NOTE: PIDs > i32::MAX are not valid on Linux
    unsafe {
        libc_kill(pid as i32, 9);
    }
}

/// Send SIGHUP to a process group (negative PID). No-op if pid == 0.
pub fn kill_pgrp_hup(pid: u32) {
    if pid == 0 {
        return;
    }
    // SAFETY: `kill(-pid, SIGHUP)` targets the process group. Integer arguments
    // only; no Rust-managed memory is accessed. pid == 0 is guarded above.
    #[allow(clippy::cast_possible_wrap)] // NOTE: PIDs > i32::MAX are not valid on Linux
    unsafe {
        libc_kill(-(pid as i32), 1);
    }
}

/// Send SIGTERM to a process group (negative PID). No-op if pid == 0.
pub fn kill_pgrp(pid: u32) {
    if pid == 0 {
        return;
    }
    // SAFETY: `kill(-pid, SIGTERM)` targets the process group. Integer arguments
    // only; no Rust-managed memory is accessed. pid == 0 is guarded above.
    #[allow(clippy::cast_possible_wrap)] // NOTE: PIDs > i32::MAX are not valid on Linux
    unsafe {
        libc_kill(-(pid as i32), 15);
    }
}

/// Send SIGKILL to a process group (negative PID). No-op if pid == 0.
pub fn kill_pgrp_force(pid: u32) {
    if pid == 0 {
        return;
    }
    // SAFETY: `kill(-pid, SIGKILL)` targets the process group. Integer arguments
    // only; no Rust-managed memory is accessed. pid == 0 is guarded above.
    #[allow(clippy::cast_possible_wrap)] // NOTE: PIDs > i32::MAX are not valid on Linux
    unsafe {
        libc_kill(-(pid as i32), 9);
    }
}

/// Get the current user's UID.
#[must_use]
pub fn getuid() -> u32 {
    unsafe extern "C" {
        fn getuid() -> u32;
    }
    // SAFETY: getuid() is a POSIX syscall that takes no arguments and returns
    // a simple integer. No memory safety concerns.
    unsafe { getuid() }
}

/// Get the current process's effective UID.
///
/// Distinct from [`getuid`]: the *effective* UID is what the kernel checks for
/// file-access permissions, so this is the right test for "do I have the
/// privilege to read a root/service-account-owned file" and, by extension,
/// "should I attempt to re-exec under sudo".
#[must_use]
pub fn geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid() is a POSIX syscall that takes no arguments and returns
    // a simple integer. No memory safety concerns.
    unsafe { geteuid() }
}

/// Get the current user's GID.
#[must_use]
pub fn getgid() -> u32 {
    unsafe extern "C" {
        fn getgid() -> u32;
    }
    // SAFETY: getgid() is a POSIX syscall that takes no arguments and returns
    // a simple integer. No memory safety concerns.
    unsafe { getgid() }
}

/// Get the calling process's own process group id, via `getpgrp()`.
///
/// Used to guard against ever sending a process-group-wide signal
/// (`kill(-pgid, ...)`) to the CALLER's own process group — e.g. a kill
/// escalation must refuse to treat a tracked child's `pgid` as
/// group-signalable if it ever turned out to equal the caller's own pgrp
/// (which would turn "kill one child's process group" into "kill the
/// caller and everything else sharing its group").
#[must_use]
pub fn own_pgrp() -> u32 {
    unsafe extern "C" {
        fn getpgrp() -> i32;
    }
    // SAFETY: getpgrp() is a POSIX syscall that takes no arguments and
    // returns a simple integer. No memory safety concerns.
    let pgrp = unsafe { getpgrp() };
    u32::try_from(pgrp).unwrap_or(0)
}

/// Return a human-readable file/directory size string (e.g. `"42.0M"`, `"1.2G"`).
///
/// For regular files, uses `metadata().len()` (pure Rust, no subprocess).
/// For directories, shells out to `du -sb` to get the total size.
/// Falls back to `"?"` on any error.
#[must_use]
#[allow(clippy::cast_precision_loss)] // acceptable for display purposes
pub fn file_size_human(path: &Path) -> String {
    let bytes = if path.is_dir() {
        // For directories, use `du -sb` to get total byte count
        Command::new("du")
            .args(["-sb", path.to_str().unwrap_or(".")])
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
            })
    } else {
        path.metadata().ok().map(|m| m.len())
    };
    match bytes {
        Some(b) => format_bytes_human(b),
        None => "?".to_string(),
    }
}

/// Format a byte count as a human-readable string.
#[must_use]
#[allow(clippy::cast_precision_loss)] // acceptable for display purposes
pub fn format_bytes_human(bytes: u64) -> String {
    if bytes >= 1 << 30 {
        format!("{:.1}G", bytes as f64 / (1u64 << 30) as f64)
    } else if bytes >= 1 << 20 {
        format!("{:.1}M", bytes as f64 / (1u64 << 20) as f64)
    } else if bytes >= 1 << 10 {
        format!("{:.1}K", bytes as f64 / (1u64 << 10) as f64)
    } else {
        format!("{bytes}B")
    }
}

// ── Binary / executable helpers ──────────────────────────────────────────────

/// Returns `true` if the path points to a file with any execute bit set.
#[must_use]
pub fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

/// Locate a binary on `PATH` by scanning directories directly.
///
/// Returns the resolved path if found. Does not depend on an external
/// `which` utility (which may not exist on NixOS).
#[must_use]
pub fn which_binary(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|dir| PathBuf::from(dir).join(name))
        .find(|p| p.is_file())
}

/// Resolve a binary by name, checking `PATH` and common platform fallback locations.
///
/// On NixOS, systemd services have a minimal `PATH` that excludes
/// `/run/current-system/sw/bin/`. This helper checks multiple well-known
/// locations so callers don't need to handle platform quirks.
///
/// Search order:
///   1. `$PATH` (via [`which_binary`])
///   2. `/run/current-system/sw/bin/{name}` (NixOS)
///   3. `/usr/bin/{name}`
///   4. `/usr/local/bin/{name}`
///   5. `/opt/homebrew/bin/{name}` (Homebrew on Apple Silicon)
///   6. Each path in `extra_paths` (caller-provided, e.g. macOS `.app` bundles)
///
/// Returns the first path where `is_file()` is true.
#[must_use]
pub fn resolve_binary(name: &str, extra_paths: &[&str]) -> Option<PathBuf> {
    // 1. PATH lookup
    if let Some(p) = which_binary(name) {
        return Some(p);
    }
    // 2–4. Platform fallback paths
    let candidates = [
        format!("/run/current-system/sw/bin/{name}"),
        format!("/usr/bin/{name}"),
        format!("/usr/local/bin/{name}"),
        format!("/opt/homebrew/bin/{name}"),
    ];
    for c in &candidates {
        let p = PathBuf::from(c);
        if p.is_file() {
            return Some(p);
        }
    }
    // 5. Caller-provided extra paths
    for c in extra_paths {
        let p = PathBuf::from(c);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

// ── Process cmdline scanning ──────────────────────────────────────────────

/// Find PIDs of processes whose `/proc/<pid>/cmdline` contains the given
/// path fragment. Excludes the current process.
///
/// This is used to detect orphan `firecracker`, `slirp4netns`, or `unshare`
/// processes that still reference a warm-pool directory path (e.g.
/// `_warm-picoclaw-0`) even though the directory has been recreated for a
/// new pool fill cycle.
///
/// # How it works
///
/// Iterates `/proc/*/cmdline` (Linux-specific). Each cmdline file contains
/// NUL-separated argv entries. We check whether **any** argv entry contains
/// `path_fragment` as a substring.
///
/// Returns an unsorted list of matching PIDs (may be empty).
#[must_use]
pub fn find_pids_referencing_path(path_fragment: &str) -> Vec<u32> {
    let my_pid = std::process::id();
    let mut pids = Vec::new();

    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return pids;
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // Only numeric directories are PIDs.
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };
        if pid == my_pid || pid == 0 {
            continue;
        }

        let cmdline_path = format!("/proc/{pid}/cmdline");
        let Ok(raw) = std::fs::read(&cmdline_path) else {
            continue; // process may have exited between readdir and read
        };

        // cmdline is NUL-separated argv. Check if any arg contains the fragment.
        let has_match = raw.split(|&b| b == 0).any(|arg| {
            let s = String::from_utf8_lossy(arg);
            s.contains(path_fragment)
        });

        if has_match {
            pids.push(pid);
        }
    }

    pids
}

/// Kill all processes whose `/proc/<pid>/cmdline` references the given path
/// fragment. Sends `SIGTERM`, waits 200 ms, then `SIGKILL` for survivors.
///
/// Returns the number of processes killed (SIGTERM sent, regardless of
/// whether SIGKILL was needed).
#[must_use]
pub fn kill_processes_referencing_path(path_fragment: &str) -> usize {
    let pids = find_pids_referencing_path(path_fragment);
    if pids.is_empty() {
        return 0;
    }

    // Phase 1: SIGTERM all.
    for &pid in &pids {
        kill_pid(pid);
    }

    // Give processes time to exit gracefully.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Phase 2: SIGKILL survivors.
    for &pid in &pids {
        if is_pid_running(pid) {
            kill_pid_force(pid);
        }
        reap_pid(pid);
    }

    pids.len()
}

/// List every pid whose controlling terminal is `tty_path` (e.g.
/// `/dev/ttys003` on macOS, `/dev/pts/3` on Linux).
///
/// Used to snapshot every process attached to a PTY session's slave device
/// — not just a single tracked child — before a kill escalation, so
/// grandchildren the caller never directly spawned (e.g. a shell's own
/// subprocesses) are not left running after the session closes.
///
/// Best-effort: returns an empty `Vec` on any failure (bad path, permission,
/// unsupported platform) rather than erroring. Callers should treat an empty
/// result as "fall back to whatever pids you already know about", not as
/// proof nothing is attached.
#[must_use]
pub fn list_tty_pids(tty_path: &str) -> Vec<u32> {
    #[cfg(target_os = "macos")]
    {
        macos_list_tty_pids(tty_path)
    }
    #[cfg(target_os = "linux")]
    {
        linux_list_tty_pids(tty_path)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = tty_path;
        Vec::new()
    }
}

/// Report whether standard input or standard output is terminal-facing.
///
/// This is intentionally separate from [`list_tty_pids`]: a subprocess can
/// inherit its parent's controlling terminal while replacing stdin/stdout
/// with private pipes or sockets. MCP servers have exactly that shape and
/// must not be treated as terminal jobs by TTY-wide cleanup.
///
/// Returns `None` when the process cannot be inspected. Kill/reap callers
/// should preserve their historical behavior on `None` and exclude a process
/// only after a positive `Some(false)` classification.
#[must_use]
pub fn process_has_terminal_stdio(pid: u32, tty_path: &str) -> Option<bool> {
    #[cfg(target_os = "macos")]
    {
        macos_process_has_terminal_stdio(pid, tty_path)
    }
    #[cfg(target_os = "linux")]
    {
        linux_process_has_terminal_stdio(pid, tty_path)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (pid, tty_path);
        None
    }
}

/// One inspected standard descriptor's shape for F1 classification.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StdioFd {
    /// A vnode whose device metadata was read: `(vst_mode, vst_rdev)`.
    Vnode { mode: u16, rdev: u32 },
    /// A vnode fd whose per-fd metadata could not be read → fail-open.
    VnodeUnreadable,
    /// A non-vnode fd (pipe, socket, …): inspectable, never a terminal.
    Other,
}

/// Pure F1 verdict over the observed fd 0 / fd 1 descriptors of one process.
///
/// - `Some(true)`  — at least one fd is a character device whose `rdev` equals
///   `slave_rdev` (terminal-facing on THIS session's slave TTY).
/// - `Some(false)` — descriptors were inspected and none matched the slave TTY
///   (regular file, `/dev/null`, a different pty, pipe, or socket).
/// - `None`        — nothing inspectable, or a vnode fd's metadata was
///   unreadable: fail-open. `PtySession::close` excludes only `Some(false)`,
///   so `None` keeps the historical over-kill (include) direction — a real
///   terminal job is never allowed to evade the reap by a lookup failure.
#[cfg(target_os = "macos")]
fn classify_terminal_stdio(observed: &[StdioFd], slave_rdev: u32) -> Option<bool> {
    const S_IFMT: u16 = 0o17_0000;
    const S_IFCHR: u16 = 0o02_0000;

    let mut inspected = false;
    let mut fail_open = false;
    for fd in observed {
        match *fd {
            StdioFd::Vnode { mode, rdev } => {
                inspected = true;
                if (mode & S_IFMT) == S_IFCHR && rdev == slave_rdev {
                    return Some(true);
                }
            }
            StdioFd::VnodeUnreadable => fail_open = true,
            StdioFd::Other => inspected = true,
        }
    }
    if fail_open {
        None
    } else if inspected {
        Some(false)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn proc_pidfdinfo(
        pid: i32,
        fd: i32,
        flavor: i32,
        buffer: *mut std::ffi::c_void,
        buffersize: i32,
    ) -> i32;
}

// ABI-faithful mirrors of <sys/proc_info.h>, enough to read
// `pvi.vi_stat.vst_mode`/`vst_rdev` from a `PROC_PIDFDVNODEINFO` reply. The
// layout is pinned by the `offset_of!`/`size_of` assertions below — a mismatch
// is a compile error, so `vst_rdev` can never be read from the wrong offset.
// Only `vst_mode`/`vst_rdev` are read; the other fields exist for layout.
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code, clippy::struct_field_names)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code, clippy::struct_field_names)]
struct VinfoStat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: u32,
    vst_gid: u32,
    vst_atime: i64,
    vst_atimensec: i64,
    vst_mtime: i64,
    vst_mtimensec: i64,
    vst_ctime: i64,
    vst_ctimensec: i64,
    vst_birthtime: i64,
    vst_birthtimensec: i64,
    vst_size: i64,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct Fsid {
    val: [i32; 2],
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code, clippy::struct_field_names)]
struct VnodeInfo {
    vi_stat: VinfoStat,
    vi_type: i32,
    vi_pad: i32,
    vi_fsid: Fsid,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct VnodeFdInfo {
    pfi: ProcFileInfo,
    pvi: VnodeInfo,
}

#[cfg(target_os = "macos")]
const _: () = {
    assert!(std::mem::size_of::<ProcFileInfo>() == 24);
    assert!(std::mem::size_of::<VinfoStat>() == 136);
    assert!(std::mem::size_of::<VnodeFdInfo>() == 176);
    assert!(std::mem::offset_of!(VnodeFdInfo, pvi.vi_stat.vst_mode) == 28);
    assert!(std::mem::offset_of!(VnodeFdInfo, pvi.vi_stat.vst_rdev) == 140);
};

/// Read `(vst_mode, vst_rdev)` for one vnode-backed descriptor via
/// `proc_pidfdinfo(PROC_PIDFDVNODEINFO)`. `None` on any failure (error or short
/// read) so the caller fails open rather than excluding a real terminal.
#[cfg(target_os = "macos")]
fn macos_fd_vnode_stat(pid: i32, fd: i32) -> Option<(u16, u32)> {
    const PROC_PIDFDVNODEINFO: i32 = 1;
    // SAFETY: `VnodeFdInfo` is an all-integer `#[repr(C)]` POD; the all-zero
    // bit pattern is a valid inhabitant.
    let mut info: VnodeFdInfo = unsafe { std::mem::zeroed() };
    let size = i32::try_from(std::mem::size_of::<VnodeFdInfo>()).ok()?;
    // SAFETY: `info` owns exactly `size` writable bytes and outlives the call;
    // the kernel writes at most `size` bytes and returns the count written.
    let written =
        unsafe { proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEINFO, (&raw mut info).cast(), size) };
    if written < size {
        return None;
    }
    Some((info.pvi.vi_stat.vst_mode, info.pvi.vi_stat.vst_rdev))
}

/// macOS F1 classifier. A standard descriptor (fd 0 / fd 1) is terminal-facing
/// only when it is a character device whose `rdev` equals the slave TTY's — the
/// per-fd device identity, not the coarse "is a vnode" type. `proc_pidinfo(
/// PROC_PIDLISTFDS)` finds the candidate fds; `proc_pidfdinfo(PROC_PIDFDVNODEINFO)`
/// reads each vnode fd's device. Regular files, `/dev/null`, and a DIFFERENT pty
/// are all vnodes but carry a different `rdev`, so they are excluded. Enumeration
/// failure or unreadable per-fd metadata returns `None` (fail-open include).
#[cfg(target_os = "macos")]
fn macos_process_has_terminal_stdio(pid: u32, tty_path: &str) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct ProcFdInfo {
        proc_fd: i32,
        proc_fdtype: u32,
    }

    const PROC_PIDLISTFDS: i32 = 1;
    const PROX_FDTYPE_VNODE: u32 = 1;

    // The slave TTY's device number is the identity every candidate fd is
    // compared against. If we cannot stat it we cannot decide → fail-open.
    let slave_rdev = u32::try_from(std::fs::metadata(tty_path).ok()?.rdev()).ok()?;

    let pid = i32::try_from(pid).ok()?;
    // SAFETY: a null/zero buffer is the documented size-query form. No
    // Rust-managed memory is exposed to libproc.
    let required = unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    let required = usize::try_from(required).ok()?;
    if required == 0 {
        return None;
    }

    let entry_size = std::mem::size_of::<ProcFdInfo>();
    let capacity = required.div_ceil(entry_size).saturating_add(8);
    let mut descriptors = vec![ProcFdInfo::default(); capacity];
    let byte_capacity = i32::try_from(std::mem::size_of_val(descriptors.as_slice())).ok()?;
    // SAFETY: `descriptors` owns `byte_capacity` writable bytes and remains
    // alive for the duration of the call. libproc returns the byte count
    // actually initialized.
    let written = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            descriptors.as_mut_ptr().cast(),
            byte_capacity,
        )
    };
    let written = usize::try_from(written).ok()?;
    if written == 0 {
        return None;
    }
    let count = (written / entry_size).min(descriptors.len());

    // Observe fd 0 / fd 1 only; the verdict is pure (`classify_terminal_stdio`).
    let mut observed: Vec<StdioFd> = Vec::with_capacity(2);
    for descriptor in &descriptors[..count] {
        if !matches!(descriptor.proc_fd, libc::STDIN_FILENO | libc::STDOUT_FILENO) {
            continue;
        }
        if descriptor.proc_fdtype != PROX_FDTYPE_VNODE {
            observed.push(StdioFd::Other);
            continue;
        }
        observed.push(match macos_fd_vnode_stat(pid, descriptor.proc_fd) {
            Some((mode, rdev)) => StdioFd::Vnode { mode, rdev },
            None => StdioFd::VnodeUnreadable,
        });
    }
    classify_terminal_stdio(&observed, slave_rdev)
}

/// Linux exposes each descriptor as a `/proc/<pid>/fd/<n>` symlink.
/// Dereferencing it and comparing `st_rdev` with the PTY slave distinguishes
/// the terminal itself from pipes, sockets, and regular-file redirections.
#[cfg(target_os = "linux")]
fn linux_process_has_terminal_stdio(pid: u32, tty_path: &str) -> Option<bool> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let tty = std::fs::metadata(tty_path).ok()?;
    let tty_dev = tty.rdev();
    let mut inspected = false;
    for descriptor in [libc::STDIN_FILENO, libc::STDOUT_FILENO] {
        let Ok(metadata) = std::fs::metadata(format!("/proc/{pid}/fd/{descriptor}")) else {
            continue;
        };
        inspected = true;
        if metadata.file_type().is_char_device() && metadata.rdev() == tty_dev {
            return Some(true);
        }
    }
    inspected.then_some(false)
}

/// macOS: `proc_listpids(PROC_TTY_ONLY, <tty rdev>, ...)` — the same
/// libproc call `lsof`/`ps` use internally to resolve "which processes are
/// on this tty".
#[cfg(target_os = "macos")]
fn macos_list_tty_pids(tty_path: &str) -> Vec<u32> {
    use std::os::unix::fs::MetadataExt;

    unsafe extern "C" {
        fn proc_listpids(kind: u32, typeinfo: u32, buffer: *mut i32, buffersize: i32) -> i32;
    }

    // From <sys/proc_info.h>: PROC_TTY_ONLY selects processes by
    // controlling-terminal device number (passed as `typeinfo`).
    const PROC_TTY_ONLY: u32 = 3;
    // Generous fixed buffer: a terminal session realistically never has
    // more than a handful of attached processes: simpler than the
    // call-twice-for-exact-size dance, at the cost of (harmlessly) missing
    // entries in a pathological case far outside normal use.
    const MAX_PIDS: usize = 4096;

    let Ok(meta) = std::fs::metadata(tty_path) else {
        return Vec::new();
    };
    let Ok(dev) = u32::try_from(meta.rdev()) else {
        return Vec::new();
    };

    let mut buf = vec![0i32; MAX_PIDS];
    let Ok(buffersize) = i32::try_from(std::mem::size_of_val(buf.as_slice())) else {
        return Vec::new();
    };
    // SAFETY: `buf` has exactly `MAX_PIDS` valid `i32` slots and
    // `buffersize` is exactly that many bytes, so the kernel can never
    // write past the end of the allocation. `dev` is a plain device-number
    // integer, not a pointer — no aliasing/lifetime concerns.
    let written = unsafe { proc_listpids(PROC_TTY_ONLY, dev, buf.as_mut_ptr(), buffersize) };
    if written <= 0 {
        return Vec::new();
    }
    // The return value is a BYTE count, not a pid count.
    let Ok(written) = usize::try_from(written) else {
        return Vec::new();
    };
    let count = (written / std::mem::size_of::<i32>()).min(MAX_PIDS);
    buf.truncate(count);
    buf.into_iter()
        .filter(|&p| p > 0)
        .filter_map(|p| u32::try_from(p).ok())
        .collect()
}

/// Linux: scan `/proc/*/stat` and compare each process's `tty_nr` field
/// (documented to use the same major/minor packing as a device's `st_rdev`)
/// against the target tty's device number.
#[cfg(target_os = "linux")]
fn linux_list_tty_pids(tty_path: &str) -> Vec<u32> {
    use std::os::unix::fs::MetadataExt;

    let Ok(meta) = std::fs::metadata(tty_path) else {
        return Vec::new();
    };
    let target_dev = meta.rdev();

    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut pids = Vec::new();
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(content) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue; // process may have exited between readdir and read
        };
        // Format: "<pid> (<comm>) <state> <ppid> <pgrp> <session> <tty_nr> ..."
        // `comm` can contain spaces/parens, so find the LAST ')' first.
        let Some(after_comm) = content.rfind(')').map(|i| i + 1) else {
            continue;
        };
        // tty_nr is the 5th whitespace-separated field after the comm field
        // (state=0, ppid=1, pgrp=2, session=3, tty_nr=4).
        let Some(tty_nr_str) = content[after_comm..].split_whitespace().nth(4) else {
            continue;
        };
        let Ok(tty_nr) = tty_nr_str.parse::<i64>() else {
            continue;
        };
        let Ok(tty_nr) = u64::try_from(tty_nr) else {
            continue; // negative/absent tty_nr — no controlling terminal
        };
        if tty_nr == target_dev {
            pids.push(pid);
        }
    }
    pids
}

/// Opaque identity token for a live process, derived from its start time.
/// As long as two calls for the SAME pid number return equal `Some`
/// values, it is guaranteed to be the SAME process — not a different one
/// that happens to have been assigned that pid number after the original
/// exited. Returns `None` if the pid doesn't exist or its start time
/// can't be determined.
///
/// Deliberately independent of TTY/session state — unlike re-checking
/// `list_tty_pids` membership. Once a session's controlling process
/// exits, the OS's tty-attachment query (`proc_listpids`/`/proc`'s
/// `tty_nr`) can stop reporting OTHER, still-alive members of that
/// session as attached to the tty at all (they show up as `??` in `ps`),
/// so re-verifying "is this pid still on our tty" partway through a kill
/// escalation is unreliable exactly when it matters most — right after
/// the first signal round has already started killing session members.
/// A process's start time has nothing to do with tty/session state, so it
/// doesn't share that failure mode: it stays queryable for as long as the
/// process itself is alive, regardless of what happens to its session
/// leader or controlling terminal.
#[must_use]
pub fn process_identity(pid: u32) -> Option<(u64, u64)> {
    #[cfg(target_os = "macos")]
    {
        macos_process_start_time(pid)
    }
    #[cfg(target_os = "linux")]
    {
        linux_process_start_time(pid)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

/// macOS: `proc_pidinfo(pid, PROC_PIDTBSDINFO, ...)` — reads
/// `pbi_start_tvsec`/`pbi_start_tvusec` (process start time, wall clock)
/// from `struct proc_bsdinfo`.
#[cfg(target_os = "macos")]
fn macos_process_start_time(pid: u32) -> Option<(u64, u64)> {
    // Mirrors <sys/proc_info.h>'s `struct proc_bsdinfo` field-for-field (in
    // order, same primitive types) so `#[repr(C)]` gives it an identical
    // layout — we only ever READ `pbi_start_tvsec`/`pbi_start_tvusec` at
    // the end, but every preceding field must still be present for the
    // compiler to place them at the same offsets the kernel writes to.
    #[repr(C)]
    struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        rfu_1: u32,
        pbi_comm: [u8; 16],
        pbi_name: [u8; 32],
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    const PROC_PIDTBSDINFO: i32 = 3;

    let pid_i32 = i32::try_from(pid).ok()?;
    let size = i32::try_from(std::mem::size_of::<ProcBsdInfo>()).ok()?;
    let mut info = std::mem::MaybeUninit::<ProcBsdInfo>::uninit();
    // SAFETY: `info` has exactly `size_of::<ProcBsdInfo>()` bytes available
    // and `size` is exactly that many bytes, so the kernel can never write
    // past the end of the allocation. We only treat the buffer as
    // initialized (`assume_init`) when the kernel reports it wrote the
    // FULL struct (`written == size`).
    let written =
        unsafe { proc_pidinfo(pid_i32, PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast(), size) };
    if written != size {
        return None;
    }
    // SAFETY: `written == size` confirms the kernel filled the entire
    // struct before returning.
    let info = unsafe { info.assume_init() };
    Some((info.pbi_start_tvsec, info.pbi_start_tvusec))
}

/// Linux: `starttime` field (22nd field, in clock ticks since boot) from
/// `/proc/<pid>/stat` — same parsing style as `linux_list_tty_pids`.
#[cfg(target_os = "linux")]
fn linux_process_start_time(pid: u32) -> Option<(u64, u64)> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = content.rfind(')')? + 1;
    // Fields after "(comm) ": state=0 ppid=1 pgrp=2 session=3 tty_nr=4
    // tpgid=5 flags=6 minflt=7 cminflt=8 majflt=9 cmajflt=10 utime=11
    // stime=12 cutime=13 cstime=14 priority=15 nice=16 num_threads=17
    // itrealvalue=18 starttime=19.
    let starttime_str = content[after_comm..].split_whitespace().nth(19)?;
    let starttime: u64 = starttime_str.parse().ok()?;
    Some((starttime, 0))
}

// ── Internal FFI ──────────────────────────────────────────────────────────

unsafe fn libc_kill(pid: i32, sig: i32) -> i32 {
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    // SAFETY: `kill()` is a POSIX syscall. Integer arguments only; no
    // Rust-managed memory is accessed.
    unsafe { kill(pid, sig) }
}

#[cfg(test)]
mod tests;
