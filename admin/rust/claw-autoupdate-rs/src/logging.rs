//! Logging and environment helpers.

use crate::config::Config;
use std::fs;
use std::io::Write;

/// Log a message to stderr and the log file.
pub fn log(cfg: &Config, msg: &str) {
    let ts = utc_timestamp();
    let line = format!("[{ts}] {msg}\n");
    // Print to stderr
    eprint!("{line}");
    // Append to log file (best-effort)
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cfg.log_file)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

pub fn utc_timestamp() -> String {
    core_rs::time::now_iso_secs()
}

/// Parse a boolean env var with fallback.
pub fn env_bool(var: &str, default: bool) -> bool {
    core_rs::env::env_bool(var, default)
}
