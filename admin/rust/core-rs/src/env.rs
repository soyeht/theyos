//! Environment variable helpers — extracted from server-rs, vmrunner-rs, executor-rs.

// set_var/remove_var are unsafe in edition 2024; this module owns those wrappers.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::mem;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::Duration;

/// Read an env var, returning the default if missing or empty.
#[must_use]
pub fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Read an env var, returning an empty string if missing.
#[must_use]
pub fn env_string(key: &str) -> String {
    std::env::var(key).unwrap_or_default()
}

/// Read an env var as a `PathBuf`, returning `None` if missing or empty.
pub fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Parse a duration string (e.g. `"5m"`, `"10h"`, `"30s"`) into `Duration`.
pub fn parse_duration_str(s: &str) -> Option<Duration> {
    if let Some(mins) = s.strip_suffix('m') {
        mins.parse::<u64>()
            .ok()
            .map(|m| Duration::from_secs(m * 60))
    } else if let Some(hours) = s.strip_suffix('h') {
        hours
            .parse::<u64>()
            .ok()
            .map(|h| Duration::from_secs(h * 3600))
    } else if let Some(secs) = s.strip_suffix('s') {
        secs.parse::<u64>().ok().map(Duration::from_secs)
    } else {
        None
    }
}

// ── Boolean env ───────────────────────────────────────────────────────────────

/// Parse a boolean environment variable with a fallback default.
///
/// Recognises `"0"`, `"false"`, `"no"` as `false` and `"1"`, `"true"`, `"yes"`
/// as `true` (case-sensitive). Any other value or missing variable returns
/// `default`.
#[must_use]
pub fn env_bool(var: &str, default: bool) -> bool {
    match std::env::var(var).as_deref() {
        Ok("0" | "false" | "no") => false,
        Ok("1" | "true" | "yes") => true,
        _ => default,
    }
}

// ── Home directory ────────────────────────────────────────────────────────────

/// Return the current user's home directory.
///
/// Reads `HOME` from the environment, falling back to `"/root"` if unset.
///
/// **Warning**: Under `sudo`, `$HOME` is typically `/root`.  For code that
/// needs the *real user's* home directory under sudo (e.g. to resolve
/// `~/firecracker/assets/`), use [`theyos_home`] instead.
#[must_use]
pub fn home_dir() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".into()))
}

/// Resolve the real user's home directory, safe under `sudo`.
///
/// Reads `THEYOS_HOME` from `{repo_root}/.env` which is always the
/// original user's home (e.g. `/home/youruser`), regardless of
/// whether the current process runs under `sudo`.
///
/// Fallback chain: `THEYOS_HOME` from `.env` → `$HOME` → `/root`.
#[must_use]
pub fn theyos_home(repo_root: &Path) -> String {
    read_env_field(&repo_root.join(".env"), "THEYOS_HOME")
        .unwrap_or_else(|| std::env::var("HOME").unwrap_or_else(|_| "/root".into()))
}

/// Resolve the invoking sudo user's username.
///
/// Prefers `SUDO_USER`, falling back to resolving `SUDO_UID` via the passwd
/// database. Returns `None` when the process is not running under sudo or the
/// invoker cannot be resolved.
#[must_use]
pub fn sudo_invoker_user() -> Option<String> {
    pick_sudo_invoker_user(
        std::env::var("SUDO_USER").ok().as_deref(),
        parse_env_u32("SUDO_UID"),
    )
}

/// Resolve the invoking sudo user's home directory.
///
/// Fallback chain:
/// 1. passwd entry for `SUDO_USER`
/// 2. passwd entry for `SUDO_UID`
/// 3. `SUDO_HOME` as a last-resort compatibility fallback
#[must_use]
pub fn sudo_invoker_home() -> Option<PathBuf> {
    pick_sudo_invoker_home(
        std::env::var("SUDO_USER").ok().as_deref(),
        parse_env_u32("SUDO_UID"),
        std::env::var("SUDO_HOME").ok().as_deref(),
    )
}

fn pick_sudo_invoker_user(sudo_user: Option<&str>, sudo_uid: Option<u32>) -> Option<String> {
    sudo_user
        .filter(|user| !user.is_empty() && *user != "root")
        .map(str::to_owned)
        .or_else(|| sudo_uid.and_then(username_from_uid))
}

fn pick_sudo_invoker_home(
    sudo_user: Option<&str>,
    sudo_uid: Option<u32>,
    sudo_home: Option<&str>,
) -> Option<PathBuf> {
    if let Some(user) = sudo_user.filter(|user| !user.is_empty() && *user != "root")
        && let Some(home) = home_of_user(user)
    {
        return Some(home);
    }
    if let Some(uid) = sudo_uid
        && let Some(home) = home_of_uid(uid)
    {
        return Some(home);
    }
    sudo_home.filter(|home| !home.is_empty()).map(PathBuf::from)
}

fn parse_env_u32(key: &str) -> Option<u32> {
    std::env::var(key).ok()?.trim().parse::<u32>().ok()
}

fn username_from_uid(uid: u32) -> Option<String> {
    passwd_entry_by_uid(uid).map(|entry| entry.username)
}

fn home_of_uid(uid: u32) -> Option<PathBuf> {
    passwd_entry_by_uid(uid).map(|entry| entry.home)
}

fn home_of_user(user: &str) -> Option<PathBuf> {
    passwd_entry_by_name(user).map(|entry| entry.home)
}

#[derive(Debug)]
struct PasswdEntry {
    username: String,
    home: PathBuf,
}

fn passwd_entry_by_name(user: &str) -> Option<PasswdEntry> {
    let user = CString::new(user).ok()?;
    passwd_lookup(|pwd, buf, len, result| {
        // SAFETY: `user` is a valid NUL-terminated C string for the lifetime
        // of this call; the other pointers are provided by `passwd_lookup`.
        unsafe { libc::getpwnam_r(user.as_ptr(), pwd, buf, len, result) }
    })
}

fn passwd_entry_by_uid(uid: u32) -> Option<PasswdEntry> {
    passwd_lookup(|pwd, buf, len, result| {
        // SAFETY: `pwd`, `buf`, and `result` are owned by `passwd_lookup`;
        // `uid` is copied by value into the closure.
        unsafe { libc::getpwuid_r(uid, pwd, buf, len, result) }
    })
}

fn passwd_lookup(
    mut f: impl FnMut(
        *mut libc::passwd,
        *mut libc::c_char,
        usize,
        *mut *mut libc::passwd,
    ) -> libc::c_int,
) -> Option<PasswdEntry> {
    let mut buf_len = passwd_buf_len();
    loop {
        // SAFETY: `passwd` is a plain old data libc struct and the re-entrant
        // lookup APIs fully initialize it before we read any field.
        let mut pwd: libc::passwd = unsafe { mem::zeroed() };
        let mut result = ptr::null_mut();
        let mut buf = vec![0u8; buf_len];
        let rc = f(
            &raw mut pwd,
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            &raw mut result,
        );
        if rc == libc::ERANGE {
            buf_len *= 2;
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        return passwd_entry_from_raw(&pwd);
    }
}

fn passwd_buf_len() -> usize {
    // SAFETY: `sysconf` is a read-only libc call with no aliasing.
    let len = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    // `sysconf` returns `c_long` (i64 on 64-bit, i32 on 32-bit). Non-positive
    // values mean "unknown/unsupported" → fall back to 1024. Positive values
    // always fit in `usize` on every platform we compile for; `try_from`
    // handles both the negative-sign case and the 32-bit truncation case.
    match usize::try_from(len) {
        Ok(n) if n > 0 => n,
        _ => 1024,
    }
}

fn passwd_entry_from_raw(pwd: &libc::passwd) -> Option<PasswdEntry> {
    if pwd.pw_name.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pwd` was populated by `getpwnam_r`/`getpwuid_r`; the pointers
    // remain valid while the backing buffer is alive inside `passwd_lookup`.
    let username = unsafe { CStr::from_ptr(pwd.pw_name) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: same guarantee as above for `pw_dir`.
    let home = PathBuf::from(
        unsafe { CStr::from_ptr(pwd.pw_dir) }
            .to_string_lossy()
            .into_owned(),
    );
    Some(PasswdEntry { username, home })
}

// ── KEY=VALUE file helpers ────────────────────────────────────────────────────

/// Read a single field from a KEY=VALUE file (e.g. `instance.env`, `.env`).
///
/// Skips blank lines and `#`-comments. Returns the first value whose key
/// matches exactly. No quote stripping — values are returned verbatim.
#[must_use]
pub fn read_env_field(path: &Path, key: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    read_env_field_from_str(&content, key)
}

/// Same as [`read_env_field`] but operates on an already-loaded string.
#[must_use]
pub fn read_env_field_from_str(content: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(val) = line.strip_prefix(&prefix) {
            return Some(val.to_string());
        }
    }
    None
}

/// Parse a `.env` / KEY=VALUE file into a `HashMap`.
///
/// Skips blank lines and `#`-comments. Strips surrounding single or double
/// quotes from values.
#[must_use]
pub fn load_dotenv(path: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Ok(content) = std::fs::read_to_string(path) else {
        return map;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            let key = key.trim().to_string();
            let val = val.trim();
            // Strip surrounding single or double quotes
            let val = if (val.starts_with('"') && val.ends_with('"'))
                || (val.starts_with('\'') && val.ends_with('\''))
            {
                val[1..val.len() - 1].to_string()
            } else {
                val.to_string()
            };
            map.insert(key, val);
        }
    }
    map
}

// ── Test helpers (edition 2024: set_var/remove_var are unsafe) ─────────────────

/// Set an environment variable in tests.
///
/// In Rust edition 2024 `std::env::set_var` is `unsafe` because mutating the
/// process environment is not thread-safe. This wrapper encapsulates the
/// `unsafe` call with documented safety rationale so every test site does not
/// need its own `unsafe` block.
///
/// # Safety contract
///
/// Callers must ensure no other thread reads or writes the environment
/// concurrently (e.g. use a `Mutex` guard or `#[serial]`).
/// **Test-only** — do not call from production code paths.
pub fn set_test_env(key: &str, value: &str) {
    // SAFETY: The caller guarantees single-threaded access to the environment
    // (typically via a test-level Mutex or serial execution).
    unsafe { std::env::set_var(key, value) };
}

/// Remove an environment variable in tests.
///
/// **Test-only** — do not call from production code paths.
///
/// See [`set_test_env`] for the safety rationale.
pub fn remove_test_env(key: &str) {
    // SAFETY: The caller guarantees single-threaded access to the environment.
    unsafe { std::env::remove_var(key) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os;

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration_str("5m"), Some(Duration::from_secs(300)));
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration_str("2h"), Some(Duration::from_secs(7200)));
    }

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration_str("30s"), Some(Duration::from_secs(30)));
    }

    #[test]
    fn parse_duration_invalid() {
        assert_eq!(parse_duration_str("abc"), None);
        assert_eq!(parse_duration_str(""), None);
    }

    #[test]
    fn env_or_missing() {
        // Use a key unlikely to exist
        let val = env_or("__CORE_RS_TEST_MISSING_KEY__", "fallback");
        assert_eq!(val, "fallback");
    }

    #[test]
    fn env_bool_true_variants() {
        // Use unique key to avoid test-parallelism races
        set_test_env("__CORE_RS_TEST_BOOL_T__", "1");
        assert!(env_bool("__CORE_RS_TEST_BOOL_T__", false));
        set_test_env("__CORE_RS_TEST_BOOL_T__", "true");
        assert!(env_bool("__CORE_RS_TEST_BOOL_T__", false));
        set_test_env("__CORE_RS_TEST_BOOL_T__", "yes");
        assert!(env_bool("__CORE_RS_TEST_BOOL_T__", false));
        remove_test_env("__CORE_RS_TEST_BOOL_T__");
    }

    #[test]
    fn env_bool_false_variants() {
        set_test_env("__CORE_RS_TEST_BOOL_F__", "0");
        assert!(!env_bool("__CORE_RS_TEST_BOOL_F__", true));
        set_test_env("__CORE_RS_TEST_BOOL_F__", "false");
        assert!(!env_bool("__CORE_RS_TEST_BOOL_F__", true));
        set_test_env("__CORE_RS_TEST_BOOL_F__", "no");
        assert!(!env_bool("__CORE_RS_TEST_BOOL_F__", true));
        remove_test_env("__CORE_RS_TEST_BOOL_F__");
    }

    #[test]
    fn env_bool_default() {
        assert!(env_bool("__CORE_RS_TEST_MISSING_BOOL__", true));
        assert!(!env_bool("__CORE_RS_TEST_MISSING_BOOL__", false));
    }

    #[test]
    fn home_dir_not_empty() {
        let h = home_dir();
        assert!(!h.as_os_str().is_empty());
    }

    #[test]
    fn sudo_invoker_user_can_resolve_current_uid() {
        let uid = os::getuid();
        let username = username_from_uid(uid).expect("current uid should resolve");
        let picked = pick_sudo_invoker_user(None, Some(uid));
        assert_eq!(picked, Some(username));
    }

    #[test]
    fn sudo_invoker_home_prefers_passwd_resolution_over_sudo_home() {
        let uid = os::getuid();
        let username = username_from_uid(uid).expect("current uid should resolve");
        let expected_home = home_of_uid(uid).expect("current uid should have a home");
        let picked = pick_sudo_invoker_home(Some(&username), Some(uid), Some("/wrong/home"));
        assert_eq!(picked, Some(expected_home));
    }

    #[test]
    fn read_env_field_from_str_basic() {
        let content = "# comment\nFOO=bar\nBAZ=qux\n";
        assert_eq!(
            read_env_field_from_str(content, "FOO"),
            Some("bar".to_string())
        );
        assert_eq!(
            read_env_field_from_str(content, "BAZ"),
            Some("qux".to_string())
        );
        assert_eq!(read_env_field_from_str(content, "MISSING"), None);
    }

    #[test]
    fn read_env_field_from_str_skips_comments() {
        let content = "# FOO=hidden\nFOO=visible\n";
        assert_eq!(
            read_env_field_from_str(content, "FOO"),
            Some("visible".to_string())
        );
    }

    #[test]
    fn load_dotenv_strips_quotes() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let tmp = dir.path().join("dotenv_test");
        std::fs::write(&tmp, "# comment\nA=\"quoted\"\nB='single'\nC=plain\n").unwrap();
        let map = load_dotenv(&tmp);
        assert_eq!(map.get("A").map(String::as_str), Some("quoted"));
        assert_eq!(map.get("B").map(String::as_str), Some("single"));
        assert_eq!(map.get("C").map(String::as_str), Some("plain"));
    }

    #[test]
    fn theyos_home_reads_dotenv() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(&dotenv, "THEYOS_HOME=/home/testuser\n").unwrap();

        let result = theyos_home(dir.path());
        assert_eq!(result, "/home/testuser");
    }

    #[test]
    fn theyos_home_falls_back_to_env_home() {
        // Use a non-existent directory so .env won't be found.
        let result = theyos_home(std::path::Path::new("/nonexistent/repo/root"));
        // Should fall back to $HOME (which is set in CI and locally).
        assert!(!result.is_empty());
    }
}
