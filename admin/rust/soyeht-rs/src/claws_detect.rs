//! `soyeht claws-detect` — probe GitHub repos and append manifest stubs.
//!
//! Batch-friendly: accepts a single `--repo` URL or a text file list via
//! `--from-list`. Builds one [`DetectionInput`] per repo, runs the
//! [`crate::detector`] to classify, and emits a YAML block that can be
//! appended to `claws/manifest.yml`.
//!
//! Writes are guarded by a POSIX advisory lock (flock) on the manifest file
//! to keep concurrent invocations from clobbering each other.

use std::fmt::Write as _;
use std::io::Write as _;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::detector::{self, DetectedTemplate, DetectionInput};
use crate::github_cache;
use crate::github_client::{self, GitHubApi, GitHubClient};
use crate::manifest_yaml;

/// CLI arguments for `soyeht claws-detect`.
#[derive(Debug, Default)]
#[allow(dead_code)] // `yes` reserved for a future interactive review loop.
pub struct ClawsDetectArgs {
    pub repo: Option<String>,
    pub from_list: Option<PathBuf>,
    pub dry_run: bool,
    pub yes: bool,
}

/// TTL for the 1h cache used by detect.
const DETECT_TTL: Duration = Duration::from_secs(3600);

/// Maximum number of repos we allow without a `GITHUB_TOKEN`.
const UNAUTHENTICATED_BATCH_LIMIT: usize = 5;

/// Top-level entry point invoked from `main.rs`.
pub fn cmd_claws_detect(root: &Path, args: &ClawsDetectArgs) {
    let urls = match collect_urls(args) {
        Ok(u) if !u.is_empty() => u,
        Ok(_) => {
            eprintln!("[detect] no URLs provided (use --repo or --from-list)");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("[detect] {e}");
            std::process::exit(2);
        }
    };

    let client = GitHubClient::new();
    if urls.len() > UNAUTHENTICATED_BATCH_LIMIT && !client.has_token() {
        eprintln!(
            "[detect] GITHUB_TOKEN not set — refusing to batch {n} repos (limit {limit}). \
             Add GITHUB_TOKEN to your .env and retry.",
            n = urls.len(),
            limit = UNAUTHENTICATED_BATCH_LIMIT
        );
        std::process::exit(1);
    }

    let cache_dir = github_cache::default_cache_dir();
    let manifest_path = root.join("claws/manifest.yml");
    let mut existing_names = if args.dry_run {
        Vec::new()
    } else {
        load_existing_claw_names(&manifest_path).unwrap_or_default()
    };

    for url in urls {
        match process_one(
            &client,
            &cache_dir,
            &url,
            &existing_names,
            args,
            &manifest_path,
        ) {
            Ok(Some(name)) => {
                println!("[detect] done: {name} ({url})");
                existing_names.push(name);
            }
            Ok(None) => {
                println!("[detect] already exists: {url} (skipping)");
            }
            Err(e) => {
                eprintln!("[detect] error for {url}: {e}");
            }
        }
    }
}

fn collect_urls(args: &ClawsDetectArgs) -> Result<Vec<String>, String> {
    let mut urls = Vec::new();
    if let Some(single) = &args.repo {
        urls.push(single.clone());
    }
    if let Some(list) = &args.from_list {
        let content = std::fs::read_to_string(list)
            .map_err(|e| format!("cannot read {}: {e}", list.display()))?;
        for raw in content.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            urls.push(line.to_string());
        }
    }
    Ok(urls)
}

fn process_one<C: GitHubApi>(
    client: &C,
    cache_dir: &Path,
    url: &str,
    existing_names: &[String],
    args: &ClawsDetectArgs,
    manifest_path: &Path,
) -> Result<Option<String>, String> {
    let (owner, repo) = github_client::parse_repo_url(url).map_err(|e| e.to_string())?;

    // The claw name is the repo name lowercased — matches the existing
    // convention (picoclaw, zeroclaw, nanobot) so the admin UI and manifest
    // keys stay uniform regardless of upstream casing (NemoClaw, ClawX, etc.).
    let claw_name = repo.to_lowercase();
    if existing_names.iter().any(|n| n == &claw_name) {
        return Ok(None);
    }

    let input = gather_inputs(client, cache_dir, &owner, &repo).map_err(|e| e.to_string())?;
    let template = detector::detect(&input);

    let head_sha =
        match github_cache::cached_head_sha(client, cache_dir, &owner, &repo, None, DETECT_TTL) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[detect] warn: cannot resolve HEAD for {owner}/{repo}: {e}");
                String::new()
            }
        };

    let yaml = render_entry(&claw_name, &input, &template, &head_sha);

    if args.dry_run {
        println!("--- dry run: {claw_name} ---");
        print!("{yaml}");
        println!("--- end dry run ---");
        return Ok(Some(claw_name));
    }

    append_under_claws_key(manifest_path, &yaml)
        .map_err(|e| format!("append to {}: {e}", manifest_path.display()))?;
    Ok(Some(claw_name))
}

fn gather_inputs<C: GitHubApi>(
    client: &C,
    cache_dir: &Path,
    owner: &str,
    repo: &str,
) -> github_client::Result<DetectionInput> {
    let meta = github_cache::cached_get_repo(client, cache_dir, owner, repo, DETECT_TTL)?;
    let release = github_cache::cached_latest_release(client, cache_dir, owner, repo, DETECT_TTL)?;
    let cargo = fetch_text(client, cache_dir, owner, repo, "Cargo.toml")?;
    let go = fetch_text(client, cache_dir, owner, repo, "go.mod")?;
    let setup = fetch_text(client, cache_dir, owner, repo, "setup.py")?;
    let pyproject = fetch_text(client, cache_dir, owner, repo, "pyproject.toml")?;
    let pkg = fetch_text(client, cache_dir, owner, repo, "package.json")?;
    let docker = fetch_text(client, cache_dir, owner, repo, "Dockerfile")?;
    let make = fetch_text(client, cache_dir, owner, repo, "Makefile")?;
    let has_main = github_cache::cached_get_contents(
        client,
        cache_dir,
        owner,
        repo,
        "src/main.rs",
        DETECT_TTL,
    )?
    .is_some();

    Ok(DetectionInput {
        meta: Some(meta),
        latest_release: release,
        cargo_toml: cargo,
        go_mod: go,
        setup_py: setup,
        pyproject_toml: pyproject,
        package_json: pkg,
        dockerfile: docker,
        makefile: make,
        has_src_main_rs: has_main,
    })
}

fn fetch_text<C: GitHubApi>(
    client: &C,
    cache_dir: &Path,
    owner: &str,
    repo: &str,
    path: &str,
) -> github_client::Result<Option<String>> {
    let f = github_cache::cached_get_contents(client, cache_dir, owner, repo, path, DETECT_TTL)?;
    Ok(f.map(|f| f.content))
}

// ── YAML rendering ──────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)] // YAML block is linear and readable as one unit
fn render_entry(
    claw_name: &str,
    input: &DetectionInput,
    template: &DetectedTemplate,
    head_sha: &str,
) -> String {
    let meta_description = input
        .meta
        .as_ref()
        .map(|m| m.description.clone())
        .unwrap_or_default();
    let source = input
        .meta
        .as_ref()
        .map(|m| m.html_url.clone())
        .unwrap_or_default();
    let license = input
        .meta
        .as_ref()
        .map(|m| m.license_spdx.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let stars = input.meta.as_ref().map_or(0, |m| m.stars);
    let pushed_date = input
        .meta
        .as_ref()
        .map(|m| truncate_to_date(&m.pushed_at))
        .unwrap_or_default();
    let today = core_rs::time::format_date(core_rs::time::unix_now_secs());
    let tier = match template {
        DetectedTemplate::NeedsManual { .. } => "catalog",
        _ => "detected",
    };

    let template_name = template.template_name();

    let mut out = String::new();
    let indent = "  ";
    let sub = "    ";
    let _ = writeln!(out, "{indent}{claw_name}:");
    let _ = writeln!(
        out,
        "{sub}description: {}",
        manifest_yaml::yaml_quoted(&meta_description)
    );
    let _ = writeln!(out, "{sub}language: {}", template.language_hint());
    let _ = writeln!(out, "{sub}tier: {tier}");
    let _ = writeln!(out, "{sub}stars: {stars}");
    let _ = writeln!(out, "{sub}source: {}", manifest_yaml::yaml_quoted(&source));
    let _ = writeln!(
        out,
        "{sub}last_updated: {}",
        manifest_yaml::yaml_quoted(&pushed_date)
    );
    let _ = writeln!(
        out,
        "{sub}reviewed_upstream_commit: {}",
        manifest_yaml::yaml_quoted(head_sha)
    );
    let _ = writeln!(
        out,
        "{sub}reviewed_at: {}",
        manifest_yaml::yaml_quoted(&today)
    );
    let _ = writeln!(out, "{sub}reviewed_by: claude-opus-4-6");
    let _ = writeln!(
        out,
        "{sub}latest_upstream_commit: {}",
        manifest_yaml::yaml_quoted(head_sha)
    );
    let _ = writeln!(
        out,
        "{sub}latest_checked_at: {}",
        manifest_yaml::yaml_quoted(&today)
    );

    if matches!(template, DetectedTemplate::NeedsManual { .. }) {
        let _ = writeln!(out, "{sub}install_template: \"\"");
    } else {
        let _ = writeln!(out, "{sub}install_template: {template_name}");
        let _ = writeln!(
            out,
            "{sub}install_plan_source: {}",
            manifest_yaml::yaml_quoted(&format!("template:{template_name}"))
        );
    }

    let _ = writeln!(
        out,
        "{sub}license: {}",
        manifest_yaml::yaml_quoted(&license)
    );
    let _ = writeln!(out, "{sub}binary_size_mb: 0  # TBD");
    let _ = writeln!(out, "{sub}min_ram_mb: {}", template.min_ram_mb());

    match template {
        DetectedTemplate::GoBinary { asset_pattern } => {
            let _ = writeln!(out, "{sub}install:");
            let _ = writeln!(
                out,
                "{sub}  asset_pattern: {}",
                manifest_yaml::yaml_quoted(asset_pattern)
            );
        }
        DetectedTemplate::PipPackage {
            pip_package,
            entry_point,
        } => {
            let _ = writeln!(out, "{sub}install:");
            let _ = writeln!(
                out,
                "{sub}  pip_package: {}",
                manifest_yaml::yaml_quoted(pip_package)
            );
            let _ = writeln!(
                out,
                "{sub}  entry_point: {}",
                manifest_yaml::yaml_quoted(entry_point)
            );
        }
        DetectedTemplate::NodePackage {
            npm_package,
            entry_point,
        } => {
            let _ = writeln!(out, "{sub}install:");
            let _ = writeln!(
                out,
                "{sub}  npm_package: {}",
                manifest_yaml::yaml_quoted(npm_package)
            );
            let _ = writeln!(
                out,
                "{sub}  entry_point: {}",
                manifest_yaml::yaml_quoted(entry_point)
            );
        }
        DetectedTemplate::RawBinary { download_url } => {
            let _ = writeln!(out, "{sub}install:");
            let _ = writeln!(
                out,
                "{sub}  download_url: {}",
                manifest_yaml::yaml_quoted(download_url)
            );
        }
        DetectedTemplate::CargoBuild => {
            // The cargo-build template needs the `owner/repo` pair to clone
            // from GitHub, and build.rs rejects `tier: detected` entries
            // with an empty `install:` block. Derive the pair from the
            // source URL (same value we emitted above).
            let github_repo = github_client::parse_repo_url(&source)
                .map_or_else(|_| String::new(), |(o, r)| format!("{o}/{r}"));
            let binary_name = claw_name.to_string();
            let _ = writeln!(out, "{sub}install:");
            let _ = writeln!(
                out,
                "{sub}  github_repo: {}",
                manifest_yaml::yaml_quoted(&github_repo)
            );
            let _ = writeln!(
                out,
                "{sub}  binary_name: {}",
                manifest_yaml::yaml_quoted(&binary_name)
            );
        }
        DetectedTemplate::NeedsManual { reason } => {
            let _ = writeln!(
                out,
                "{sub}# needs_manual: {}",
                manifest_yaml::yaml_quoted(reason)
            );
        }
    }
    out
}

fn truncate_to_date(ts: &str) -> String {
    // "2026-04-10T12:00:00Z" → "2026-04-10".
    ts.split('T').next().unwrap_or(ts).to_string()
}

// ── Manifest file I/O ───────────────────────────────────────────────────────

/// Return the list of top-level claw keys in a manifest file — or an empty
/// vec if the file does not exist. Parses the file as YAML via `serde_yaml`.
pub fn load_existing_claw_names(path: &Path) -> Result<Vec<String>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let v: serde_yaml::Value = serde_yaml::from_str(&content)
        .map_err(|e| format!("yaml parse {}: {e}", path.display()))?;
    let Some(claws) = v.get("claws").and_then(serde_yaml::Value::as_mapping) else {
        return Ok(Vec::new());
    };
    Ok(claws
        .iter()
        .filter_map(|(k, _)| k.as_str().map(String::from))
        .collect())
}

/// Append `yaml_block` under the top-level `claws:` mapping. We preserve the
/// existing file exactly (no round-trip through `serde_yaml`): we just append
/// the block at the end of the file, guarded by a POSIX advisory lock.
#[allow(unsafe_code)] // `libc::flock` is the idiomatic guard for multi-process
// manifest writes; the workspace lints `unsafe_code = "warn"`.
fn append_under_claws_key(path: &Path, yaml_block: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)?;
    // Advisory exclusive lock for the duration of the write.
    let fd = file.as_raw_fd();
    // SAFETY: flock is a standard POSIX call; `fd` is owned by `file` which
    // outlives the lock. The LOCK_UN below (and close-on-drop of `file`) both
    // release the lock.
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    {
        let mut writer = std::io::BufWriter::new(&file);
        // Ensure we start on a new line.
        writer.write_all(b"\n")?;
        writer.write_all(yaml_block.as_bytes())?;
        writer.flush()?;
    }
    // SAFETY: paired with the LOCK_EX above on the same fd.
    unsafe { libc::flock(fd, libc::LOCK_UN) };
    Ok(())
}

// ── Tests (offline, with mock client) ───────────────────────────────────────

#[cfg(test)]
mod tests;
