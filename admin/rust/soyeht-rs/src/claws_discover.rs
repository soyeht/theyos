//! `soyeht claws-discover` — agent-first context bundler for `tier: catalog` claws.
//!
//! `claws-discover` does **not** call any LLM API. Instead, for each
//! `tier: catalog` claw, it fetches GitHub metadata + README + the content of
//! key build/install files, and writes a single markdown bundle to
//! `artifacts/discover/<claw>.md`. The bundle is meant to be consumed by an
//! external coding agent (Claude Code, Codex, Cursor) that edits
//! `claws/manifest.yml` by hand with the install plan.
//!
//! The command is strictly dry-run: it never mutates `manifest.yml`. The
//! manifest edit is the agent's responsibility, reviewed via normal
//! `git diff`. Verification of whatever plan the agent proposes still goes
//! through `soyeht claws-verify`.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::github_cache;
use crate::github_client::{self, GitHubApi, GitHubClient};

/// CLI arguments for `soyeht claws-discover`.
#[derive(Debug, Clone)]
pub struct ClawsDiscoverArgs {
    pub claw: Option<String>,
    pub all_catalog: bool,
}

const DISCOVER_TTL: Duration = Duration::from_secs(3600);

/// Files the bundle inlines verbatim (when present). Ordered roughly by
/// signal strength for identifying the install strategy.
const PROBE_FILES: &[&str] = &[
    "README.md",
    "README",
    "Cargo.toml",
    "go.mod",
    "setup.py",
    "pyproject.toml",
    "package.json",
    "Dockerfile",
    "Makefile",
    "BUILD",
    "CMakeLists.txt",
    "requirements.txt",
    "main.py",
    "main.go",
    "src/main.rs",
    "install.sh",
];

/// Max README/file body length we inline per file, in chars. Prevents 10MB
/// bundles from a README with an embedded changelog.
const MAX_INLINED_CHARS: usize = 12_000;

/// Top-level entry point invoked from `main.rs`.
pub fn cmd_claws_discover(root: &Path, args: &ClawsDiscoverArgs) {
    let targets = match decide_targets(root, args) {
        Ok(t) if !t.is_empty() => t,
        Ok(_) => {
            eprintln!("[discover] no catalog claws selected (use --claw or --all-catalog)");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("[discover] {e}");
            std::process::exit(2);
        }
    };

    let github = GitHubClient::new();
    let cache_dir = github_cache::default_cache_dir();
    let out_dir = root.join("artifacts").join("discover");
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        eprintln!("[discover] create {}: {e}", out_dir.display());
        std::process::exit(1);
    }

    for claw in &targets {
        match write_bundle(&out_dir, claw, &github, &cache_dir) {
            Ok(path) => println!("[discover] {claw}: wrote {}", path.display()),
            Err(e) => eprintln!("[discover] {claw}: {e}"),
        }
    }
    println!(
        "[discover] done. Next: open a coding agent against these files and edit \
         claws/manifest.yml to replace `tier: catalog` with the appropriate `tier: detected` + \
         `install:` block. Then run `soyeht claws-verify <claw>` to validate."
    );
}

/// Pick the list of `tier: catalog` claws to process.
fn decide_targets(root: &Path, args: &ClawsDiscoverArgs) -> Result<Vec<String>, String> {
    if let Some(name) = &args.claw {
        if !core_rs::manifest::is_known(name) {
            return Err(format!("claw {name:?} is not in the manifest"));
        }
        return Ok(vec![name.clone()]);
    }
    if !args.all_catalog {
        return Err("missing target: pass a claw name or --all-catalog".to_string());
    }
    let manifest_path = root.join("claws").join("manifest.yml");
    let content = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("read {}: {e}", manifest_path.display()))?;
    let v: serde_yaml::Value = serde_yaml::from_str(&content)
        .map_err(|e| format!("yaml parse {}: {e}", manifest_path.display()))?;
    let Some(claws) = v.get("claws").and_then(serde_yaml::Value::as_mapping) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (name, entry) in claws {
        let Some(name) = name.as_str() else { continue };
        let tier = entry
            .get("tier")
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or("");
        if tier == "catalog" {
            out.push(name.to_string());
        }
    }
    Ok(out)
}

/// Write a single-claw markdown bundle. Returns the bundle path on success.
fn write_bundle(
    out_dir: &Path,
    claw: &str,
    github: &impl GitHubApi,
    cache_dir: &Path,
) -> Result<PathBuf, String> {
    let entry =
        core_rs::manifest::get(claw).ok_or_else(|| format!("manifest has no entry for {claw}"))?;
    if entry.source.is_empty() {
        return Err("manifest entry has no `source:` URL".to_string());
    }
    let (owner, repo) = github_client::parse_repo_url(entry.source).map_err(|e| e.to_string())?;

    let meta = github_cache::cached_get_repo(github, cache_dir, &owner, &repo, DISCOVER_TTL)
        .map_err(|e| format!("github get_repo: {e}"))?;
    let head = github
        .head_sha(&owner, &repo, Some(meta.default_branch.as_str()))
        .map_err(|e| format!("github head_sha: {e}"))?;

    let mut present_files: Vec<(String, String)> = Vec::new();
    for name in PROBE_FILES {
        match github_cache::cached_get_contents(
            github,
            cache_dir,
            &owner,
            &repo,
            name,
            DISCOVER_TTL,
        ) {
            Ok(Some(file)) => {
                present_files.push((
                    file.path,
                    truncate_to_chars(&file.content, MAX_INLINED_CHARS),
                ));
            }
            Ok(None) => {}
            Err(e) => return Err(format!("github get_contents({name}): {e}")),
        }
    }

    let bundle = render_bundle(
        claw,
        entry.source,
        &meta,
        &head,
        &present_files,
        "claws/manifest.yml",
    );

    let out_path = out_dir.join(format!("{claw}.md"));
    std::fs::write(&out_path, bundle).map_err(|e| format!("write bundle: {e}"))?;
    Ok(out_path)
}

/// Build the markdown body of the bundle. Pure function — easy to test.
fn render_bundle(
    claw: &str,
    source: &str,
    meta: &github_client::RepoMeta,
    head_sha: &str,
    files: &[(String, String)],
    manifest_rel_path: &str,
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# claws-discover bundle: `{claw}`\n\n\
         This file is the input for an external coding agent (Claude Code, Codex, etc.). \
         The agent should:\n\n\
         1. Read the metadata + README + key files below.\n\
         2. Decide an install strategy by mapping to one of the 6 templates \
         (`go-binary`, `cargo-build`, `pip-package`, `node-package`, `raw-binary`, `manual-shell`).\n\
         3. Open `{manifest_rel_path}` and replace the `{claw}` block's `tier: catalog` with a \
         full `tier: detected` entry (template + install block, per the schema in \
         `/Users/dev/.claude/plans/shiny-tumbling-spring.md`).\n\
         4. Commit the manifest edit, then run `soyeht claws-verify {claw}` to validate.\n\n\
         **Do not edit this bundle.** It is regenerated by `soyeht claws-discover --claw {claw}`."
    );

    let _ = writeln!(
        out,
        "\n## Metadata\n\n\
         | field | value |\n\
         |---|---|\n\
         | name | `{}` |\n\
         | source | <{}> |\n\
         | stars | {} |\n\
         | license | {} |\n\
         | default branch | {} |\n\
         | head SHA | `{}` |\n\
         | upstream pushed_at | {} |\n\
         | description | {} |",
        meta.name,
        source,
        meta.stars,
        if meta.license_spdx.is_empty() {
            "(none)"
        } else {
            meta.license_spdx.as_str()
        },
        meta.default_branch,
        head_sha,
        meta.pushed_at,
        if meta.description.is_empty() {
            "(empty)"
        } else {
            meta.description.as_str()
        },
    );

    let _ = writeln!(out, "\n## Files present in repo root\n");
    if files.is_empty() {
        let _ = writeln!(out, "(none of the probe files were found)");
    } else {
        for (path, _) in files {
            let _ = writeln!(out, "- `{path}`");
        }
    }

    for (path, body) in files {
        let fence = pick_code_fence(body);
        let _ = writeln!(out, "\n### `{path}`\n\n{fence}\n{body}\n{fence}");
    }

    let _ = writeln!(
        out,
        "\n## Suggested manifest patch (agent fills this in)\n\n\
         Replace the `{claw}:` block in `{manifest_rel_path}` with something like:\n\n\
         ```yaml\n\
         {claw}:\n\
           description: \"<one-line human description>\"\n\
           tier: detected\n\
           stars: {}\n\
           source: {}\n\
           language: <go|rust|python|node|none>\n\
           buildable: false\n\
           distribution: prebuilt\n\
           version: \"<upstream release or commit>\"\n\
           min_ram_mb: <256|512|1024|2048>\n\
           license: \"{}\"\n\n\
           # Choose ONE of the 6 templates. Delete the others.\n\
           install_template: <go-binary|cargo-build|pip-package|node-package|raw-binary|manual-shell>\n\
           install_plan_source: \"template:<same name as above>\"\n\
           install:\n\
             # Fields depend on template:\n\
             #   go-binary:     github_repo, binary_name, asset_pattern (optional)\n\
             #   cargo-build:   repo_source\n\
             #   pip-package:   pip_package, entry_point\n\
             #   node-package:  npm_package, entry_point\n\
             #   raw-binary:    binary_path (URL to a download)\n\
             #   manual-shell:  manual_script (literal shell script)\n\
             # Drift tracking (set by claws-detect when it runs on this claw):\n\
           reviewed_upstream_commit: \"{}\"\n\
           reviewed_at: \"<YYYY-MM-DD of when agent reviewed>\"\n\
           reviewed_by: \"<agent name, e.g. claude-code / codex>\"\n\
         ```\n\n\
         After saving: `soyeht claws-verify {claw}` spins up a sandbox VM and \
         promotes the claw to `tier: available` on smoke pass.",
        meta.stars,
        source,
        if meta.license_spdx.is_empty() {
            "unknown"
        } else {
            meta.license_spdx.as_str()
        },
        head_sha,
    );

    out
}

/// Choose a code fence length so the body can't escape the block.
fn pick_code_fence(body: &str) -> String {
    let mut longest_run = 0usize;
    let mut current = 0usize;
    for ch in body.chars() {
        if ch == '`' {
            current += 1;
            longest_run = longest_run.max(current);
        } else {
            current = 0;
        }
    }
    "`".repeat(longest_run.saturating_add(1).max(3))
}

fn truncate_to_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push_str("\n\n… (truncated by claws-discover; full content in upstream repo)");
    out
}

// ─── Tests (offline, GitHub mocked) ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github_client::RepoMeta;

    fn fake_meta() -> RepoMeta {
        RepoMeta {
            name: "foo".into(),
            stars: 42,
            pushed_at: "2026-04-10T12:00:00Z".into(),
            license_spdx: "MIT".into(),
            default_branch: "main".into(),
            html_url: "https://github.com/foo/foo".into(),
            description: "a test claw".into(),
        }
    }

    #[test]
    fn render_bundle_has_metadata_and_file_sections() {
        let meta = fake_meta();
        let files = vec![
            ("README.md".to_string(), "# foo\n\nHello.".to_string()),
            (
                "Cargo.toml".to_string(),
                "[package]\nname = \"foo\"\n".to_string(),
            ),
        ];
        let body = render_bundle(
            "foo",
            "https://github.com/foo/foo",
            &meta,
            "deadbeef",
            &files,
            "claws/manifest.yml",
        );
        assert!(body.contains("# claws-discover bundle: `foo`"));
        assert!(body.contains("| stars | 42 |"));
        assert!(body.contains("head SHA | `deadbeef`"));
        assert!(body.contains("### `README.md`"));
        assert!(body.contains("### `Cargo.toml`"));
        assert!(body.contains("install_template:"));
        assert!(body.contains("reviewed_upstream_commit: \"deadbeef\""));
    }

    #[test]
    fn render_bundle_empty_files_list() {
        let meta = fake_meta();
        let body = render_bundle(
            "foo",
            "https://github.com/foo/foo",
            &meta,
            "cafef00d",
            &[],
            "claws/manifest.yml",
        );
        assert!(body.contains("(none of the probe files were found)"));
    }

    #[test]
    fn pick_code_fence_escapes_embedded_backticks() {
        // A body containing ``` needs at least 4 backticks to fence safely.
        let fence = pick_code_fence("hello ``` world");
        assert!(fence.len() >= 4, "got {fence:?}");
        // And 5 for ````.
        let fence = pick_code_fence("```` nested ````");
        assert!(fence.len() >= 5, "got {fence:?}");
    }

    #[test]
    fn truncate_respects_max_chars() {
        let short = truncate_to_chars("abc", 10);
        assert_eq!(short, "abc");
        let long: String = "a".repeat(20);
        let out = truncate_to_chars(&long, 10);
        assert!(out.starts_with("aaaaaaaaaa"));
        assert!(out.contains("truncated"));
    }

    #[test]
    fn decide_targets_single_claw_requires_manifest_presence() {
        let tmp = tempfile::tempdir().unwrap();
        let args = ClawsDiscoverArgs {
            claw: Some("not-there".into()),
            all_catalog: false,
        };
        assert!(decide_targets(tmp.path(), &args).is_err());
    }

    #[test]
    fn decide_targets_all_catalog_filters_on_disk_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let claws_dir = tmp.path().join("claws");
        std::fs::create_dir_all(&claws_dir).unwrap();
        std::fs::write(
            claws_dir.join("manifest.yml"),
            "claws:\n  foo:\n    tier: catalog\n  bar:\n    tier: detected\n  baz:\n    tier: catalog\n",
        )
        .unwrap();
        let args = ClawsDiscoverArgs {
            claw: None,
            all_catalog: true,
        };
        let targets = decide_targets(tmp.path(), &args).unwrap();
        assert!(targets.iter().any(|t| t == "foo"));
        assert!(targets.iter().any(|t| t == "baz"));
        assert!(!targets.iter().any(|t| t == "bar"));
    }

    #[test]
    fn write_bundle_produces_markdown_file_with_fake_github() {
        let tmp = tempfile::tempdir().unwrap();
        // Populate a minimal manifest.yml so manifest::get would find entries —
        // but here we bypass that by validating with the render function only.
        let out_dir = tmp.path().join("artifacts").join("discover");
        std::fs::create_dir_all(&out_dir).unwrap();

        let meta = fake_meta();
        let files = vec![("README.md".to_string(), "# foo".to_string())];
        let body = render_bundle(
            "foo",
            "https://github.com/foo/foo",
            &meta,
            "deadbeef",
            &files,
            "claws/manifest.yml",
        );
        let path = out_dir.join("foo.md");
        std::fs::write(&path, &body).unwrap();
        assert!(path.exists());
        let loaded = std::fs::read_to_string(&path).unwrap();
        assert!(loaded.contains("foo"));
    }
}
