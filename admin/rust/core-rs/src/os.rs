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
    if let Ok(v) = std::env::var("SLIRP4NETNS_BIN") {
        if !v.is_empty() {
            let p = PathBuf::from(&v);
            if p.exists() {
                return Some(p);
            }
        }
    }
    // 2. PATH lookup
    if let Some(p) = which_binary("slirp4netns") {
        return Some(p);
    }
    // 3. Nix store scan
    let nix_store = Path::new("/nix/store");
    if nix_store.is_dir() {
        if let Ok(rd) = std::fs::read_dir(nix_store) {
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
        let _ = tty_path;
        macos_process_has_terminal_stdio(pid)
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

/// macOS `proc_pidinfo(PROC_PIDLISTFDS)` reports the kernel type of every
/// open descriptor. PTYs are vnode-backed; MCP stdio is pipe/socket-backed.
#[cfg(target_os = "macos")]
fn macos_process_has_terminal_stdio(pid: u32) -> Option<bool> {
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct ProcFdInfo {
        proc_fd: i32,
        proc_fdtype: u32,
    }

    const PROC_PIDLISTFDS: i32 = 1;
    const PROX_FDTYPE_VNODE: u32 = 1;

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
    Some(descriptors[..count].iter().any(|descriptor| {
        matches!(descriptor.proc_fd, libc::STDIN_FILENO | libc::STDOUT_FILENO)
            && descriptor.proc_fdtype == PROX_FDTYPE_VNODE
    }))
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
mod tests {
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
        assert!(own_pgrp() > 0, "a running process always has a process group");
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
        assert!(first.is_some(), "a running process must have a determinable identity");
        let second = process_identity(pid);
        assert_eq!(first, second, "identity must be stable across repeated calls");
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
        assert_ne!(mine, init, "distinct concurrently-running processes must not collide");
    }
}
