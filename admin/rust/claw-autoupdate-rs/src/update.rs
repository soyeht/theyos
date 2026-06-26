//! Git update logic for upstream claw repos.

use std::path::Path;
use std::process::{Command, Stdio};

use crate::config::Config;
use crate::discovery::list_enabled_customers;
use crate::logging::log;

// ── Git update result ────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub enum UpdateResult {
    Updated,       // new commits pulled
    AlreadyLatest, // up to date
    Skipped,       // dirty / no branch / dry-run
    Failed,        // fetch or pull error
}

// ── Claw processing ──────────────────────────────────────────────────────────

pub fn process_claw(cfg: &Config, claw: &str, repo: &Path) {
    // 1. Check for enabled customers
    let data_dir = cfg.data_dir.join(claw);
    let enabled_customers = list_enabled_customers(&data_dir);
    if enabled_customers.is_empty() {
        log(cfg, &format!("skip {claw}: no autoupdate enabled"));
        return;
    }

    // 2. Git update
    let update = update_repo(cfg, claw, repo);
    let did_update = match update {
        UpdateResult::Updated => true,
        UpdateResult::Skipped if cfg.dry_run => true, // dry-run: pretend updated
        UpdateResult::AlreadyLatest | UpdateResult::Skipped => false,
        UpdateResult::Failed => {
            log(cfg, &format!("skip {claw}: update failed"));
            return;
        }
    };

    if !did_update {
        log(cfg, &format!("skip {claw}: no updates"));
        return;
    }

    log(cfg, &format!("updated {claw}: new commits pulled"));
}

// ── Git helpers ──────────────────────────────────────────────────────────────

fn update_repo(cfg: &Config, name: &str, repo: &Path) -> UpdateResult {
    // Must be a git repo
    if !repo.join(".git").is_dir() {
        log(cfg, &format!("skip {name}: not a git repo"));
        return UpdateResult::Skipped;
    }

    // Must have clean working tree
    let clean = Command::new("git")
        .args(["-C", repo.to_str().unwrap_or("."), "diff", "--quiet"])
        .status()
        .is_ok_and(|s| s.success());
    let clean_staged = Command::new("git")
        .args([
            "-C",
            repo.to_str().unwrap_or("."),
            "diff",
            "--cached",
            "--quiet",
        ])
        .status()
        .is_ok_and(|s| s.success());
    if !clean || !clean_staged {
        log(cfg, &format!("skip {name}: working tree dirty"));
        return UpdateResult::Skipped;
    }

    if cfg.dry_run {
        log(cfg, &format!("dry-run {name}: would fetch/pull"));
        return UpdateResult::Skipped;
    }

    // Fetch
    log(cfg, &format!("check {name}: fetching updates"));
    let fetch_ok = Command::new("git")
        .args([
            "-C",
            repo.to_str().unwrap_or("."),
            "fetch",
            "--prune",
            "origin",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !fetch_ok {
        log(cfg, &format!("error {name}: fetch failed"));
        return UpdateResult::Failed;
    }

    // Resolve branch
    let Some(branch) = resolve_git_branch(repo) else {
        log(
            cfg,
            &format!("skip {name}: could not resolve upstream branch"),
        );
        return UpdateResult::Skipped;
    };

    // Compare revs
    let local_rev = git_rev(repo, "HEAD");
    let remote_rev = git_rev(repo, &format!("origin/{branch}"));

    if local_rev.is_empty() || remote_rev.is_empty() {
        log(cfg, &format!("skip {name}: could not read revs"));
        return UpdateResult::Skipped;
    }

    if local_rev == remote_rev {
        log(cfg, &format!("ok {name}: already up to date"));
        return UpdateResult::AlreadyLatest;
    }

    // Pull
    log(cfg, &format!("update {name}: pulling {branch}"));
    let pull_ok = Command::new("git")
        .args([
            "-C",
            repo.to_str().unwrap_or("."),
            "pull",
            "--ff-only",
            "origin",
            &branch,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    if pull_ok {
        let new_rev = git_rev(repo, "HEAD");
        log(
            cfg,
            &format!("updated {name}: {}", &new_rev[..new_rev.len().min(8)]),
        );
        UpdateResult::Updated
    } else {
        log(
            cfg,
            &format!("error {name}: pull failed (non fast-forward?)"),
        );
        UpdateResult::Failed
    }
}

fn resolve_git_branch(repo: &Path) -> Option<String> {
    // Try symbolic-ref origin/HEAD
    let out = Command::new("git")
        .args([
            "-C",
            repo.to_str().unwrap_or("."),
            "symbolic-ref",
            "-q",
            "--short",
            "refs/remotes/origin/HEAD",
        ])
        .output()
        .ok()?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if let Some(branch) = s.strip_prefix("origin/") {
            return Some(branch.to_string());
        }
        return Some(s);
    }

    // Try origin/main
    if git_ref_exists(repo, "refs/remotes/origin/main") {
        return Some("main".to_string());
    }
    // Try origin/master
    if git_ref_exists(repo, "refs/remotes/origin/master") {
        return Some("master".to_string());
    }
    None
}

fn git_ref_exists(repo: &Path, refspec: &str) -> bool {
    Command::new("git")
        .args([
            "-C",
            repo.to_str().unwrap_or("."),
            "show-ref",
            "--verify",
            "--quiet",
            refspec,
        ])
        .status()
        .is_ok_and(|s| s.success())
}

fn git_rev(repo: &Path, refspec: &str) -> String {
    let out = Command::new("git")
        .args(["-C", repo.to_str().unwrap_or("."), "rev-parse", refspec])
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => String::new(),
    }
}
