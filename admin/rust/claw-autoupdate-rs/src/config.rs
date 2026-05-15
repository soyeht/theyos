//! Configuration for claw-autoupdate.

use std::path::PathBuf;

use crate::logging;

/// Top-level configuration built from env vars + CLI args.
#[derive(Debug, Clone)]
pub struct Config {
    pub src_dir: PathBuf,
    pub data_dir: PathBuf,
    pub log_file: PathBuf,
    pub dry_run: bool,
    pub targets: Vec<String>,
}

impl Config {
    pub fn from_env_and_args() -> Self {
        let repo_root = core_rs::path::resolve_repo_root().unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        });
        let src_dir = repo_root.join("claws/src");
        let data_dir = repo_root.join("claws/data");
        let log_file = repo_root.join("logs/claw-autoupdate.log");

        let mut dry_run = logging::env_bool("AUTOUPDATE_DRY_RUN", false);
        let mut targets: Vec<String> = Vec::new();

        for arg in std::env::args().skip(1) {
            match arg.as_str() {
                "--dry-run" | "-n" => dry_run = true,
                "--help" | "-h" => {
                    println!("Usage: claw-autoupdate [--dry-run] [claw...]");
                    println!();
                    println!("Options:");
                    println!("  --dry-run      Fetch and check only, no pull");
                    println!("  [claw...]      Target specific claw types (default: all)");
                    std::process::exit(0);
                }
                other if !other.starts_with('-') => targets.push(other.to_string()),
                other => {
                    eprintln!("[claw-autoupdate] unknown argument: {other}");
                    std::process::exit(2);
                }
            }
        }

        Self {
            src_dir,
            data_dir,
            log_file,
            dry_run,
            targets,
        }
    }
}
