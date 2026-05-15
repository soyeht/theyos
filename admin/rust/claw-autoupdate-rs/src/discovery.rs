//! Claw and customer discovery.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::config::Config;

// ── autoupdate.json ──────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
struct AutoupdateJson {
    #[serde(default)]
    enabled: bool,
}

// ── Customer discovery ───────────────────────────────────────────────────────

/// Returns list of customer names with `autoupdate.json { "enabled": true }`.
pub fn list_enabled_customers(data_dir: &Path) -> Vec<String> {
    let customers_dir = data_dir.join("customers");
    if !customers_dir.is_dir() {
        return Vec::new();
    }

    let Ok(entries) = fs::read_dir(&customers_dir) else {
        return Vec::new();
    };

    let mut enabled: Vec<String> = entries
        .flatten()
        .filter(|e| {
            let flag = e.path().join("autoupdate.json");
            flag.is_file() && is_autoupdate_enabled(&flag)
        })
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    enabled.sort();
    enabled
}

pub(crate) fn is_autoupdate_enabled(path: &Path) -> bool {
    let Ok(content) = fs::read_to_string(path) else {
        return false;
    };
    // Fast path: serde_json parse
    if let Ok(v) = serde_json::from_str::<AutoupdateJson>(&content) {
        return v.enabled;
    }
    // Fallback: naive string search (same as the original grep -qi)
    let lower = content.to_lowercase();
    lower.contains("\"enabled\"") && lower.contains("true")
}

// ── Claw discovery ───────────────────────────────────────────────────────────

pub fn discover_claws(cfg: &Config) -> Vec<(String, PathBuf)> {
    if !cfg.targets.is_empty() {
        return cfg
            .targets
            .iter()
            .map(|t| {
                let path = cfg.src_dir.join(t);
                (t.clone(), path)
            })
            .collect();
    }

    // Auto-discover: iterate claws/src/*/
    let Ok(rd) = fs::read_dir(&cfg.src_dir) else {
        return Vec::new();
    };

    let mut result: Vec<(String, PathBuf)> = rd
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter(|e| {
            let p = e.path();
            // Must have .git OR scripts/ to be considered a claw repo
            p.join(".git").is_dir() || p.join("scripts").is_dir()
        })
        .map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let path = e.path();
            (name, path)
        })
        .collect();

    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}
