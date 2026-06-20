//! `soyeht claws-scan` — drift tracker for upstream claw repos.
//!
//! For every entry in `claws/manifest.yml` that has a `source:` pointing at a
//! GitHub repo, compare the reviewed commit vs the current HEAD and surface
//! drift. Never promotes `reviewed_upstream_commit` — that is explicitly
//! reserved for a future `claws-detect --rerun`.
//!
//! Reads the manifest YAML directly (instead of going through
//! `core_rs::manifest::catalog`) so this command works even before Phase A
//! fields have been merged into the compiled manifest.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::github_cache;
use crate::github_client::{self, GitHubApi, GitHubClient};
use crate::manifest_yaml;

/// CLI arguments for `soyeht claws-scan`.
#[derive(Debug, Default)]
pub struct ClawsScanArgs {
    pub apply: bool,
    pub json: bool,
    pub no_cache: bool,
}

/// TTL for scan mode (5min — we want fresh data).
const SCAN_TTL: Duration = Duration::from_secs(300);

/// One row of the scan report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRow {
    pub claw: String,
    pub source: String,
    pub reviewed: String,
    pub latest: String,
    pub stale: bool,
    pub reviewed_at: String,
    pub latest_checked_at: String,
}

/// Raw YAML-backed manifest entry (scan-only view).
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // `latest_upstream_commit` is carried for future JSON output.
struct RawEntry {
    #[serde(default)]
    source: String,
    #[serde(default)]
    reviewed_upstream_commit: String,
    #[serde(default)]
    reviewed_at: String,
    #[serde(default)]
    latest_upstream_commit: String,
    #[serde(default)]
    latest_checked_at: String,
    /// Fallback to the git ref field if present (picoclaw/zeroclaw use `ref`).
    #[serde(default, rename = "ref")]
    git_ref: String,
}

#[derive(Debug, Deserialize)]
struct RawManifest {
    #[serde(default)]
    claws: std::collections::BTreeMap<String, RawEntry>,
}

/// Top-level entry point.
pub fn cmd_claws_scan(root: &Path, args: &ClawsScanArgs) {
    let manifest_path = root.join("claws/manifest.yml");
    let manifest = match load_manifest(&manifest_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[scan] cannot load manifest: {e}");
            std::process::exit(1);
        }
    };
    let client = GitHubClient::new();
    let cache_dir = github_cache::default_cache_dir();
    let rows = collect_rows(&client, &cache_dir, &manifest, args.no_cache);

    if args.json {
        let json = serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string());
        println!("{json}");
    } else {
        print_human(&rows);
    }

    if args.apply {
        if let Err(e) = apply_latest_updates(&manifest_path, &rows) {
            eprintln!("[scan] apply failed: {e}");
            std::process::exit(1);
        }
    }
}

fn load_manifest(path: &Path) -> Result<RawManifest, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_yaml::from_str(&content).map_err(|e| format!("parse {}: {e}", path.display()))
}

fn collect_rows<C: GitHubApi>(
    client: &C,
    cache_dir: &Path,
    manifest: &RawManifest,
    no_cache: bool,
) -> Vec<ScanRow> {
    let ttl = if no_cache {
        Duration::from_secs(0)
    } else {
        SCAN_TTL
    };
    let mut rows = Vec::new();
    for (name, entry) in &manifest.claws {
        if entry.source.is_empty() {
            continue;
        }
        let (owner, repo) = match github_client::parse_repo_url(&entry.source) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[scan] skip {name}: {e}");
                continue;
            }
        };
        let branch = if entry.git_ref.is_empty() {
            None
        } else {
            Some(entry.git_ref.as_str())
        };
        let head =
            match github_cache::cached_head_sha(client, cache_dir, &owner, &repo, branch, ttl) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[scan] skip {name}: {e}");
                    continue;
                }
            };
        let stale =
            !entry.reviewed_upstream_commit.is_empty() && entry.reviewed_upstream_commit != head;
        rows.push(ScanRow {
            claw: name.clone(),
            source: entry.source.clone(),
            reviewed: entry.reviewed_upstream_commit.clone(),
            latest: head,
            stale,
            reviewed_at: entry.reviewed_at.clone(),
            latest_checked_at: entry.latest_checked_at.clone(),
        });
    }
    rows
}

fn print_human(rows: &[ScanRow]) {
    let stale_count = rows.iter().filter(|r| r.stale).count();
    if rows.is_empty() {
        println!("[scan] no claws with GitHub upstream");
        return;
    }
    for row in rows {
        if row.stale {
            println!(
                "[stale] {claw}: {rev} → {lat} (reviewed {ra}, latest {la})",
                claw = row.claw,
                rev = short_sha(&row.reviewed),
                lat = short_sha(&row.latest),
                ra = if row.reviewed_at.is_empty() {
                    "?"
                } else {
                    &row.reviewed_at
                },
                la = if row.latest_checked_at.is_empty() {
                    "?"
                } else {
                    &row.latest_checked_at
                },
            );
        } else if row.reviewed.is_empty() {
            println!(
                "[unknown] {claw}: reviewed commit not recorded (latest {lat})",
                claw = row.claw,
                lat = short_sha(&row.latest),
            );
        } else {
            println!(
                "[ok] {claw}: {lat}",
                claw = row.claw,
                lat = short_sha(&row.latest)
            );
        }
    }
    println!(
        "[scan] {stale_count} stale / {total} checked",
        total = rows.len()
    );
}

fn short_sha(sha: &str) -> String {
    if sha.len() >= 7 {
        sha[..7].to_string()
    } else {
        sha.to_string()
    }
}

/// Textual patch in-place: only updates `latest_upstream_commit` and
/// `latest_checked_at` fields for each claw where a latest HEAD was resolved.
/// Never touches `reviewed_upstream_commit`.
fn apply_latest_updates(manifest_path: &Path, rows: &[ScanRow]) -> Result<(), String> {
    let content = std::fs::read_to_string(manifest_path)
        .map_err(|e| format!("read {}: {e}", manifest_path.display()))?;
    let today = core_rs::time::format_date(core_rs::time::unix_now_secs());

    let mut updated = content;
    for row in rows {
        if row.latest.is_empty() {
            continue;
        }
        updated = manifest_yaml::patch_quoted_field_noop_unknown(
            &updated,
            &row.claw,
            "latest_upstream_commit",
            &row.latest,
        );
        updated = manifest_yaml::patch_quoted_field_noop_unknown(
            &updated,
            &row.claw,
            "latest_checked_at",
            &today,
        );
    }

    // Write via a tempfile in the same dir to make it atomic-ish.
    let tmp_path = manifest_yaml::tmp_sibling(manifest_path);
    std::fs::write(&tmp_path, &updated)
        .map_err(|e| format!("write {}: {e}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, manifest_path)
        .map_err(|e| format!("rename to {}: {e}", manifest_path.display()))?;
    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github_client::{FileContent, GitHubError, Release, RepoMeta};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::path::PathBuf;

    struct MockApi {
        heads: HashMap<(String, String, Option<String>), String>,
        calls: RefCell<u32>,
    }

    impl MockApi {
        fn new(entries: Vec<(&str, &str, Option<&str>, &str)>) -> Self {
            let mut heads = HashMap::new();
            for (o, r, b, sha) in entries {
                heads.insert(
                    (o.to_string(), r.to_string(), b.map(String::from)),
                    sha.to_string(),
                );
            }
            Self {
                heads,
                calls: RefCell::new(0),
            }
        }
    }

    impl GitHubApi for MockApi {
        fn get_repo(&self, _o: &str, _r: &str) -> Result<RepoMeta, GitHubError> {
            Err(GitHubError::BadInput("unused".into()))
        }
        fn latest_release(&self, _o: &str, _r: &str) -> Result<Option<Release>, GitHubError> {
            Ok(None)
        }
        fn get_contents(
            &self,
            _o: &str,
            _r: &str,
            _p: &str,
        ) -> Result<Option<FileContent>, GitHubError> {
            Ok(None)
        }
        fn head_sha(
            &self,
            owner: &str,
            repo: &str,
            branch: Option<&str>,
        ) -> Result<String, GitHubError> {
            *self.calls.borrow_mut() += 1;
            let key = (
                owner.to_string(),
                repo.to_string(),
                branch.map(String::from),
            );
            self.heads
                .get(&key)
                .cloned()
                .ok_or_else(|| GitHubError::BadInput(format!("no mock for {owner}/{repo}")))
        }
    }

    fn write_manifest(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("manifest.yml");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn scan_reports_stale_when_commits_differ() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = write_manifest(
            tmp.path(),
            "claws:\n  picoclaw:\n    source: https://github.com/sipeed/picoclaw\n    reviewed_upstream_commit: oldsha0000000000\n    reviewed_at: \"2026-04-01\"\n    ref: main\n",
        );
        let manifest = load_manifest(&manifest).unwrap();
        let mock = MockApi::new(vec![(
            "sipeed",
            "picoclaw",
            Some("main"),
            "newsha9999999999",
        )]);
        let rows = collect_rows(&mock, tmp.path(), &manifest, true);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].stale);
        assert_eq!(rows[0].reviewed, "oldsha0000000000");
        assert_eq!(rows[0].latest, "newsha9999999999");
    }

    #[test]
    fn scan_skips_entries_without_source() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = write_manifest(
            tmp.path(),
            "claws:\n  noclaw:\n    description: no upstream\n",
        );
        let manifest = load_manifest(&manifest).unwrap();
        let mock = MockApi::new(vec![]);
        let rows = collect_rows(&mock, tmp.path(), &manifest, true);
        assert!(rows.is_empty());
    }

    #[test]
    fn scan_reports_ok_when_commits_match() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = write_manifest(
            tmp.path(),
            "claws:\n  nullclaw:\n    source: https://github.com/nullclaw/nullclaw\n    reviewed_upstream_commit: abc123\n    ref: main\n",
        );
        let manifest = load_manifest(&manifest).unwrap();
        let mock = MockApi::new(vec![("nullclaw", "nullclaw", Some("main"), "abc123")]);
        let rows = collect_rows(&mock, tmp.path(), &manifest, true);
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].stale);
    }

    #[test]
    fn scan_uses_default_branch_when_no_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = write_manifest(
            tmp.path(),
            "claws:\n  foo:\n    source: https://github.com/foo/foo\n    reviewed_upstream_commit: abc\n",
        );
        let manifest = load_manifest(&manifest).unwrap();
        let mock = MockApi::new(vec![("foo", "foo", None, "xyz")]);
        let rows = collect_rows(&mock, tmp.path(), &manifest, true);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].stale);
    }

    #[test]
    fn scan_handles_non_github_source() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = write_manifest(
            tmp.path(),
            "claws:\n  a:\n    source: https://gitlab.com/foo/bar\n",
        );
        let manifest = load_manifest(&manifest).unwrap();
        let mock = MockApi::new(vec![]);
        let rows = collect_rows(&mock, tmp.path(), &manifest, true);
        assert!(rows.is_empty(), "gitlab url should be skipped");
    }

    #[test]
    fn patch_field_replaces_existing_value() {
        let src = "claws:\n  picoclaw:\n    source: https://x\n    latest_upstream_commit: old\n    other: keep\n";
        let out = manifest_yaml::patch_quoted_field_noop_unknown(
            src,
            "picoclaw",
            "latest_upstream_commit",
            "new",
        );
        assert!(out.contains("latest_upstream_commit: \"new\""));
        assert!(out.contains("other: keep"));
        // old value is gone
        assert!(!out.contains(": old"));
    }

    #[test]
    fn patch_field_appends_when_key_missing() {
        let src = "claws:\n  foo:\n    source: https://x\n    other: keep\n";
        let out = manifest_yaml::patch_quoted_field_noop_unknown(
            src,
            "foo",
            "latest_upstream_commit",
            "abc",
        );
        assert!(out.contains("latest_upstream_commit: \"abc\""));
        assert!(out.contains("other: keep"));
        assert!(out.contains("source: https://x"));
    }

    #[test]
    fn patch_field_no_op_for_unknown_claw() {
        let src = "claws:\n  foo:\n    other: keep\n";
        let out = manifest_yaml::patch_quoted_field_noop_unknown(
            src,
            "bar",
            "latest_upstream_commit",
            "abc",
        );
        assert_eq!(out, src);
    }

    #[test]
    fn patch_field_does_not_touch_reviewed_commit() {
        let src = "claws:\n  foo:\n    reviewed_upstream_commit: reviewed-sha\n    latest_upstream_commit: old\n";
        let out = manifest_yaml::patch_quoted_field_noop_unknown(
            src,
            "foo",
            "latest_upstream_commit",
            "new",
        );
        assert!(out.contains("reviewed_upstream_commit: reviewed-sha"));
        assert!(out.contains("latest_upstream_commit: \"new\""));
    }

    #[test]
    fn apply_latest_updates_writes_today_and_sha() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_manifest(
            tmp.path(),
            "claws:\n  foo:\n    source: https://github.com/a/b\n    reviewed_upstream_commit: r1\n",
        );
        let rows = vec![ScanRow {
            claw: "foo".into(),
            source: "https://github.com/a/b".into(),
            reviewed: "r1".into(),
            latest: "deadbeef".into(),
            stale: true,
            reviewed_at: "2026-04-01".into(),
            latest_checked_at: String::new(),
        }];
        apply_latest_updates(&path, &rows).unwrap();
        let updated = std::fs::read_to_string(&path).unwrap();
        assert!(updated.contains("reviewed_upstream_commit: r1"));
        assert!(updated.contains("latest_upstream_commit: \"deadbeef\""));
        assert!(updated.contains("latest_checked_at:"));
    }

    #[test]
    fn short_sha_trims_long() {
        assert_eq!(short_sha("abcdefgh1234"), "abcdefg");
        assert_eq!(short_sha("abc"), "abc");
    }

    #[test]
    fn find_claw_block_locates_header() {
        let src = "claws:\n  foo:\n    a: 1\n  bar:\n    b: 2";
        let block = manifest_yaml::find_claw_block(src, "bar").unwrap();
        assert_eq!(block.start, 3);
        assert_eq!(block.indent, "  ");
    }

    #[test]
    fn find_block_end_stops_at_next_sibling() {
        let src = "claws:\n  foo:\n    a: 1\n  bar:\n    b: 2";
        let block = manifest_yaml::find_claw_block(src, "foo").unwrap();
        assert_eq!(block.end, 3);
    }

    #[test]
    fn parse_manifest_reads_phase_a_fields_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_manifest(
            tmp.path(),
            "claws:\n  x:\n    source: https://github.com/a/b\n    reviewed_upstream_commit: r1\n    reviewed_at: \"2026-04-01\"\n    latest_upstream_commit: l1\n    latest_checked_at: \"2026-04-10\"\n",
        );
        let m = load_manifest(&path).unwrap();
        let e = &m.claws["x"];
        assert_eq!(e.source, "https://github.com/a/b");
        assert_eq!(e.reviewed_upstream_commit, "r1");
        assert_eq!(e.latest_upstream_commit, "l1");
        assert_eq!(e.latest_checked_at, "2026-04-10");
    }

    #[test]
    fn parse_manifest_handles_missing_phase_a_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_manifest(
            tmp.path(),
            "claws:\n  x:\n    source: https://github.com/a/b\n    ref: main\n",
        );
        let m = load_manifest(&path).unwrap();
        let e = &m.claws["x"];
        assert_eq!(e.reviewed_upstream_commit, "");
        assert_eq!(e.git_ref, "main");
    }
}
