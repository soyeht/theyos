//! claw-autoupdate — Per-claw upstream git pull.
//!
//! Replaces `scripts/claw-autoupdate.sh` and `claws/scripts/autoupdate.sh`
//! (they were near-identical; this is the unified Rust version).
//!
//! # What it does
//!
//! For each claw type found under `claws/src/`:
//!   1. Check if any customer has `autoupdate.json` with `"enabled": true`.
//!   2. Fetch upstream git remote.
//!   3. If new commits: pull (ff-only).
//!
//! # Usage
//!
//! ```text
//! claw-autoupdate                  # run for all claws
//! claw-autoupdate --dry-run        # check only, no pull
//! claw-autoupdate picoclaw nanobot  # target specific claw types only
//! ```
//!
//! # autoupdate.json schema
//!
//! `claws/data/<type>/customers/<name>/autoupdate.json`:
//! ```json
//! { "enabled": true }
//! ```
//!
//! # Environment
//!
//! | Variable              | Default                         |
//! |-----------------------|---------------------------------|
//! | `THEYOS_DIR`          | auto-detected from exe path     |
//! | `AUTOUPDATE_DRY_RUN`  | `0`  (set to `1` for dry-run)   |

mod config;
mod discovery;
mod logging;
mod update;

use config::Config;
use discovery::discover_claws;
use logging::log;
use update::process_claw;

fn main() {
    let cfg = Config::from_env_and_args();
    std::fs::create_dir_all(cfg.log_file.parent().unwrap()).ok();

    log(&cfg, "start autoupdate");

    // Discover claw dirs (from src_dir/*/  OR from the explicit targets list)
    let claw_dirs = discover_claws(&cfg);

    if claw_dirs.is_empty() {
        log(&cfg, "no claw repos found — nothing to do");
        std::process::exit(0);
    }

    for (claw, repo) in &claw_dirs {
        process_claw(&cfg, claw, repo);
    }

    log(&cfg, "done autoupdate");
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use tempfile::TempDir;

    use core_rs::env::{remove_test_env, set_test_env};

    use crate::config::Config;
    use crate::discovery::{discover_claws, list_enabled_customers};
    use crate::logging::{env_bool, utc_timestamp};

    fn make_customer_with_autoupdate(dir: &Path, customer: &str, enabled: bool) {
        let customer_dir = dir.join("customers").join(customer);
        fs::create_dir_all(&customer_dir).unwrap();
        let content = format!(r#"{{"enabled":{enabled}}}"#);
        fs::write(customer_dir.join("autoupdate.json"), content).unwrap();
    }

    #[test]
    fn list_enabled_customers_empty_dir() {
        let d = TempDir::new().unwrap();
        let result = list_enabled_customers(d.path());
        assert!(result.is_empty());
    }

    #[test]
    fn list_enabled_customers_enabled_true() {
        let d = TempDir::new().unwrap();
        make_customer_with_autoupdate(d.path(), "alice", true);
        make_customer_with_autoupdate(d.path(), "bob", false);
        let result = list_enabled_customers(d.path());
        assert_eq!(result, vec!["alice"]);
    }

    #[test]
    fn list_enabled_customers_multiple_enabled() {
        let d = TempDir::new().unwrap();
        make_customer_with_autoupdate(d.path(), "alice", true);
        make_customer_with_autoupdate(d.path(), "bob", true);
        make_customer_with_autoupdate(d.path(), "carol", false);
        let mut result = list_enabled_customers(d.path());
        result.sort();
        assert_eq!(result, vec!["alice", "bob"]);
    }

    #[test]
    fn list_enabled_customers_no_json_file() {
        let d = TempDir::new().unwrap();
        fs::create_dir_all(d.path().join("customers/alice")).unwrap();
        let result = list_enabled_customers(d.path());
        assert!(result.is_empty());
    }

    #[test]
    fn is_autoupdate_enabled_true() {
        let d = TempDir::new().unwrap();
        let f = d.path().join("autoupdate.json");
        fs::write(&f, r#"{"enabled":true}"#).unwrap();
        assert!(crate::discovery::is_autoupdate_enabled(&f));
    }

    #[test]
    fn is_autoupdate_enabled_false() {
        let d = TempDir::new().unwrap();
        let f = d.path().join("autoupdate.json");
        fs::write(&f, r#"{"enabled":false}"#).unwrap();
        assert!(!crate::discovery::is_autoupdate_enabled(&f));
    }

    #[test]
    fn is_autoupdate_enabled_missing_file() {
        let d = TempDir::new().unwrap();
        let f = d.path().join("nonexistent.json");
        assert!(!crate::discovery::is_autoupdate_enabled(&f));
    }

    #[test]
    fn discover_claws_empty_src() {
        let d = TempDir::new().unwrap();
        fs::create_dir_all(d.path().join("claws/src")).unwrap();
        fs::create_dir_all(d.path().join("admin")).unwrap();
        fs::write(d.path().join("flake.nix"), "# fake").unwrap();

        set_test_env("THEYOS_DIR", d.path().to_str().unwrap());
        let cfg = Config {
            src_dir: d.path().join("claws/src"),
            data_dir: d.path().join("claws/data"),
            log_file: d.path().join("logs/claw-autoupdate.log"),
            dry_run: false,
            targets: vec![],
        };
        remove_test_env("THEYOS_DIR");

        let claws = discover_claws(&cfg);
        assert!(claws.is_empty());
    }

    #[test]
    fn discover_claws_finds_git_repos() {
        let d = TempDir::new().unwrap();
        let src = d.path().join("claws/src");
        let picoclaw_dir = src.join("picoclaw");
        fs::create_dir_all(picoclaw_dir.join(".git")).unwrap();

        let cfg = Config {
            src_dir: src,
            data_dir: d.path().join("claws/data"),
            log_file: d.path().join("logs/autoupdate.log"),
            dry_run: false,
            targets: vec![],
        };

        let claws = discover_claws(&cfg);
        assert_eq!(claws.len(), 1);
        assert_eq!(claws[0].0, "picoclaw");
    }

    #[test]
    fn env_bool_defaults() {
        // Use a unique var name to avoid TOCTOU races with parallel tests.
        remove_test_env("TEST_BOOL_DEFAULTS");
        assert!(env_bool("TEST_BOOL_DEFAULTS", true));
        assert!(!env_bool("TEST_BOOL_DEFAULTS", false));
    }

    #[test]
    fn env_bool_overrides() {
        // Use a unique var name to avoid TOCTOU races with parallel tests.
        set_test_env("TEST_BOOL_OVERRIDES", "0");
        assert!(!env_bool("TEST_BOOL_OVERRIDES", true));
        set_test_env("TEST_BOOL_OVERRIDES", "1");
        assert!(env_bool("TEST_BOOL_OVERRIDES", false));
        remove_test_env("TEST_BOOL_OVERRIDES");
    }

    #[test]
    fn utc_timestamp_format() {
        let ts = utc_timestamp();
        assert!(ts.contains('T'));
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20); // "YYYY-MM-DDTHH:MM:SSZ"
    }
}
