//! theyos-update — Self-update for theyOS.
//!
//! Replaces `scripts/update-theyos.sh`. Runs automatically via systemd timer.
//!
//! # What it does
//!
//! 1. `git fetch --prune origin`
//! 2. Compare HEAD vs origin/main — exit 0 (already up to date) or continue
//! 3. `git pull --ff-only origin main`
//! 4. `soyeht rebuild`
//! 5. Log updated version
//!
//! # Usage
//!
//! ```text
//! theyos-update              # normal update
//! theyos-update --dry-run    # fetch + check, no pull/rebuild
//! ```
//!
//! # Environment
//!
//! | Variable      | Default                        |
//! |---------------|--------------------------------|
//! | `THEYOS_DIR`  | auto-detected from exe path    |

use std::fs;
use std::path::Path;
use std::process::Command;

// ── CLI (manual, no clap dep) ─────────────────────────────────────────────────

struct Args {
    dry_run: bool,
}

impl Args {
    fn parse() -> Self {
        let mut dry_run = false;
        for arg in std::env::args().skip(1) {
            match arg.as_str() {
                "--dry-run" | "-n" => dry_run = true,
                "--help" | "-h" => {
                    println!("Usage: theyos-update [--dry-run]");
                    println!();
                    println!("Options:");
                    println!("  --dry-run    Fetch and check only; do not pull or rebuild");
                    std::process::exit(0);
                }
                other => {
                    eprintln!("[theyos-update] unknown argument: {other}");
                    std::process::exit(2);
                }
            }
        }
        Self { dry_run }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let args = Args::parse();
    let repo = core_rs::path::resolve_repo_root().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    log(&format!("repo: {}", repo.display()));

    // 1. Fetch
    log("fetching updates...");
    let fetch_ok = run_git(&repo, &["fetch", "--prune", "origin"]);
    if !fetch_ok {
        log("error: git fetch failed");
        std::process::exit(1);
    }

    // 2. Compare HEAD vs origin/main
    let local_rev = git_rev(&repo, "HEAD");
    let remote_rev = git_rev(&repo, "origin/main");

    if remote_rev.is_empty() {
        log("error: could not resolve origin/main");
        std::process::exit(1);
    }

    if local_rev == remote_rev {
        log(&format!("already up to date ({})", short_rev(&local_rev)));
        std::process::exit(0);
    }

    log(&format!(
        "update available: {} → {}",
        short_rev(&local_rev),
        short_rev(&remote_rev)
    ));

    if args.dry_run {
        log("dry-run: skipping pull and rebuild");
        std::process::exit(0);
    }

    // 3. Pull
    log("pulling origin/main (ff-only)...");
    if !run_git(&repo, &["pull", "--ff-only", "origin", "main"]) {
        log("error: git pull failed (non-fast-forward or conflict)");
        std::process::exit(1);
    }

    // 4. Rebuild stack
    log("rebuilding stack...");
    if !rebuild_stack(&repo) {
        log("error: stack rebuild failed");
        std::process::exit(1);
    }

    // 5. Log final version
    let new_rev = git_rev(&repo, "HEAD");
    let version = read_version_file(&repo);
    log(&format!("updated to {} ({})", version, short_rev(&new_rev)));
}

// ── Step implementations ──────────────────────────────────────────────────────

/// Run `soyeht rebuild`.
fn rebuild_stack(repo: &Path) -> bool {
    let soyeht = repo.join("admin/rust/target/debug/soyeht");
    if soyeht.is_file() {
        log("using soyeht rebuild");
        return Command::new(&soyeht)
            .arg("rebuild")
            .current_dir(repo)
            .status()
            .is_ok_and(|s| s.success());
    }

    log("error: soyeht binary not found");
    false
}

// ── Git helpers ───────────────────────────────────────────────────────────────

fn run_git(repo: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .current_dir(repo)
        .status()
        .is_ok_and(|s| s.success())
}

fn git_rev(repo: &Path, refspec: &str) -> String {
    let out = Command::new("git")
        .args(["rev-parse", refspec])
        .current_dir(repo)
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => String::new(),
    }
}

fn short_rev(rev: &str) -> &str {
    &rev[..rev.len().min(8)]
}

fn read_version_file(repo: &Path) -> String {
    let vf = repo.join("VERSION");
    fs::read_to_string(&vf)
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}

// ── Logging ───────────────────────────────────────────────────────────────────

fn log(msg: &str) {
    let ts = utc_timestamp();
    eprintln!("[{ts}] [theyos-update] {msg}");
}

fn utc_timestamp() -> String {
    core_rs::time::now_iso_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core_rs::env::{remove_test_env, set_test_env};
    use std::time::SystemTime;

    #[test]
    fn short_rev_truncates() {
        assert_eq!(short_rev("abcdef1234567890"), "abcdef12");
    }

    #[test]
    fn short_rev_shorter_than_8() {
        assert_eq!(short_rev("abc"), "abc");
    }

    #[test]
    fn utc_timestamp_non_empty() {
        let ts = utc_timestamp();
        assert!(ts.contains('T'), "expected ISO8601, got: {ts}");
        assert!(ts.ends_with('Z'), "expected UTC, got: {ts}");
    }

    #[test]
    fn civil_from_days_epoch() {
        assert_eq!(core_rs::time::civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn civil_from_days_today_in_range() {
        let secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        #[allow(clippy::cast_possible_wrap)]
        let (y, m, d) = core_rs::time::civil_from_days((secs / 86400) as i64);
        assert!((2025..=2030).contains(&y));
        assert!((1..=12).contains(&m));
        assert!((1..=31).contains(&d));
    }

    #[test]
    fn resolve_repo_root_with_env() {
        set_test_env("THEYOS_DIR", "/tmp/test-theyos");
        let root = core_rs::path::resolve_repo_root().unwrap();
        assert_eq!(root, std::path::PathBuf::from("/tmp/test-theyos"));
        remove_test_env("THEYOS_DIR");
    }

    #[test]
    fn read_version_file_missing_returns_unknown() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let v = read_version_file(dir.path());
        assert_eq!(v, "unknown");
    }

    #[test]
    fn read_version_file_reads_content() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("VERSION"), "1.2.3\n").unwrap();
        let v = read_version_file(dir.path());
        assert_eq!(v, "1.2.3");
    }
}
