//! Deterministic install-template detector.
//!
//! Given GitHub metadata plus a handful of probe files, classify the repo into
//! one of the [`DetectedTemplate`] variants. No network calls here — callers
//! pre-fetch the probes (`Cargo.toml`, `go.mod`, `setup.py`, `pyproject.toml`,
//! `package.json`, `Dockerfile`, `Makefile`) and hand them over through
//! [`DetectionInput`].

use crate::github_client::{Release, RepoMeta};

/// Possible install templates detected from a repo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectedTemplate {
    GoBinary {
        asset_pattern: String,
    },
    CargoBuild,
    PipPackage {
        pip_package: String,
        entry_point: String,
    },
    NodePackage {
        npm_package: String,
        entry_point: String,
    },
    RawBinary {
        download_url: String,
    },
    NeedsManual {
        reason: String,
    },
}

impl DetectedTemplate {
    /// Stable slug used in generated manifest entries.
    #[must_use]
    pub fn template_name(&self) -> &'static str {
        match self {
            Self::GoBinary { .. } => "go-binary-release",
            Self::CargoBuild => "cargo-build",
            Self::PipPackage { .. } => "pip-package",
            Self::NodePackage { .. } => "node-package",
            Self::RawBinary { .. } => "raw-binary",
            Self::NeedsManual { .. } => "",
        }
    }

    /// Conservative language hint for the YAML `language:` field.
    #[must_use]
    pub fn language_hint(&self) -> &'static str {
        match self {
            Self::GoBinary { .. } => "go",
            Self::CargoBuild => "rust",
            Self::PipPackage { .. } => "python",
            Self::NodePackage { .. } => "node",
            Self::RawBinary { .. } | Self::NeedsManual { .. } => "none",
        }
    }

    /// Default minimum RAM (MB) for each template.
    #[must_use]
    pub fn min_ram_mb(&self) -> u32 {
        match self {
            Self::CargoBuild => 2048,
            _ => 512,
        }
    }
}

/// Collected input for [`detect`].
#[derive(Debug, Default, Clone)]
pub struct DetectionInput {
    pub meta: Option<RepoMeta>,
    pub latest_release: Option<Release>,
    pub cargo_toml: Option<String>,
    pub go_mod: Option<String>,
    pub setup_py: Option<String>,
    pub pyproject_toml: Option<String>,
    pub package_json: Option<String>,
    pub dockerfile: Option<String>,
    pub makefile: Option<String>,
    /// Present when `src/main.rs` exists (used to disambiguate binary crates).
    pub has_src_main_rs: bool,
}

/// Classify the repo into a [`DetectedTemplate`] by walking the rules in
/// priority order. See the Fase D plan for rule numbering.
#[must_use]
pub fn detect(input: &DetectionInput) -> DetectedTemplate {
    // Rule 1 — Cargo.toml + [[bin]] or src/main.rs → CargoBuild.
    if let Some(cargo) = &input.cargo_toml {
        if has_bin_target(cargo) || input.has_src_main_rs {
            return DetectedTemplate::CargoBuild;
        }
    }

    // Rule 2 — go.mod + linux release asset → GoBinary.
    if input.go_mod.is_some() {
        if let Some(rel) = &input.latest_release {
            if let Some(pattern) = detect_go_asset_pattern(rel) {
                return DetectedTemplate::GoBinary {
                    asset_pattern: pattern,
                };
            }
        }
    }

    // Rule 3 — setup.py entry_points / pyproject.toml [project.scripts] → PipPackage.
    if let Some((pkg, entry)) = detect_pip_package(input) {
        return DetectedTemplate::PipPackage {
            pip_package: pkg,
            entry_point: entry,
        };
    }

    // Rule 4 — package.json with `bin` → NodePackage.
    if let Some(pj) = &input.package_json {
        if let Some((name, entry)) = detect_node_bin(pj) {
            return DetectedTemplate::NodePackage {
                npm_package: name,
                entry_point: entry,
            };
        }
    }

    // Rule 5 — Release with a tarball/zip asset but no build hints → RawBinary.
    if let Some(rel) = &input.latest_release {
        if let Some(url) = detect_raw_linux_archive(rel) {
            return DetectedTemplate::RawBinary { download_url: url };
        }
    }

    // Rule 7 — Makefile with `install:` target → NeedsManual (reason known).
    if let Some(mk) = &input.makefile {
        if has_install_target(mk) {
            return DetectedTemplate::NeedsManual {
                reason: "Makefile install target detected".to_string(),
            };
        }
    }

    // Rule 6 is used only as a tie-breaker for Rules 1–4 above — we already
    // picked the strongest signal so Dockerfile hints are absorbed there.
    // If we end up here with only a Dockerfile, surface it in the reason.
    if input.dockerfile.is_some() {
        return DetectedTemplate::NeedsManual {
            reason: "Dockerfile-only repo — needs manual install template".to_string(),
        };
    }

    DetectedTemplate::NeedsManual {
        reason: "no recognizable build system".to_string(),
    }
}

// ── Rule helpers ─────────────────────────────────────────────────────────────

fn has_bin_target(cargo_toml: &str) -> bool {
    // Quick token scan — anything matching `[[bin]]` at line start counts.
    cargo_toml.lines().any(|line| {
        let t = line.trim();
        t == "[[bin]]" || t.starts_with("[[bin.")
    })
}

fn detect_go_asset_pattern(release: &Release) -> Option<String> {
    // Look for a linux/amd64 asset with a recognised archive extension.
    // Clippy flags `.ends_with(".tgz")` as case-sensitive even though we
    // already lowercased the string, so the comparisons are intentionally safe.
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    let asset = release.assets.iter().find(|a| {
        let name = a.name.to_ascii_lowercase();
        (name.contains("linux-amd64") || name.contains("linux-x86_64"))
            && (name.ends_with(".tar.gz")
                || name.ends_with(".tgz")
                || name.ends_with(".zip")
                || name.ends_with(".tar.xz"))
    })?;
    Some(generalise_asset_pattern(&asset.name, &release.tag_name))
}

/// Replace the concrete version/arch in an asset name with templated
/// placeholders. Best effort — we never fail.
fn generalise_asset_pattern(asset_name: &str, tag: &str) -> String {
    let mut out = asset_name.to_string();

    // Replace the tag literally, then strip a leading `v` if the asset omitted it.
    if !tag.is_empty() {
        out = out.replace(tag, "{version}");
        if let Some(bare) = tag.strip_prefix('v') {
            if !bare.is_empty() {
                out = out.replace(bare, "{version}");
            }
        }
    }

    // Architecture placeholders.
    out = out.replace("linux-amd64", "linux-{arch}");
    out = out.replace("linux-x86_64", "linux-{arch}");

    out
}

fn detect_pip_package(input: &DetectionInput) -> Option<(String, String)> {
    if let Some(py) = &input.pyproject_toml {
        if let Some(pair) = scan_pyproject_scripts(py) {
            return Some(pair);
        }
    }
    if let Some(setup) = &input.setup_py {
        if let Some(pair) = scan_setup_py(setup) {
            return Some(pair);
        }
    }
    None
}

/// Find `[project.scripts]` in pyproject.toml and extract the first pair.
fn scan_pyproject_scripts(pyproject: &str) -> Option<(String, String)> {
    let pkg_name = scan_pyproject_project_name(pyproject)?;
    let mut in_scripts = false;
    for raw in pyproject.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_scripts = line == "[project.scripts]";
            continue;
        }
        if in_scripts && !line.is_empty() && !line.starts_with('#') {
            // Shape: `<script> = "module:func"` → we only need the script.
            if let Some(eq) = line.find('=') {
                let name = line[..eq].trim().trim_matches('"');
                if !name.is_empty() {
                    return Some((pkg_name, name.to_string()));
                }
            }
        }
    }
    None
}

fn scan_pyproject_project_name(pyproject: &str) -> Option<String> {
    // Look for `name = "foo"` inside the `[project]` section.
    let mut in_project = false;
    for raw in pyproject.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_project = line == "[project]";
            continue;
        }
        if in_project && line.starts_with("name") {
            if let Some(v) = line.split('=').nth(1) {
                let name = v.trim().trim_matches('"').trim_matches('\'');
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// Parse `setup.py` for `entry_points={...}` and a `name=` field in the
/// call to `setup()`.
fn scan_setup_py(setup_py: &str) -> Option<(String, String)> {
    if !setup_py.contains("entry_points") {
        return None;
    }
    let pkg_name = scan_setup_py_name(setup_py)?;
    // Locate the `console_scripts` key, then look for any quoted item that
    // contains `=` in the remaining text. This is intentionally simple —
    // we don't try to balance brackets; we just scan every `"..."` or
    // `'...'` literal that follows and pick the first one shaped like
    // `<name>=<module:func>`.
    let idx = setup_py.find("console_scripts")?;
    let tail = &setup_py[idx + "console_scripts".len()..];

    for (quote, open_char) in [('"', '"'), ('\'', '\'')] {
        if let Some(entry) = find_entry_in_quotes(tail, quote, open_char) {
            return Some((pkg_name.clone(), entry));
        }
    }
    None
}

/// Walk `text` pairing up runs of `quote` characters and return the first
/// run that contains `=`. Tries both alignments (start at index 0 or 1) so we
/// correctly handle the case where `text` starts in the middle of a quoted
/// literal.
fn find_entry_in_quotes(text: &str, quote: char, _open_char: char) -> Option<String> {
    let positions: Vec<usize> = text
        .char_indices()
        .filter(|(_, c)| *c == quote)
        .map(|(i, _)| i)
        .collect();
    if positions.len() < 2 {
        return None;
    }
    for offset in [0usize, 1usize] {
        if let Some(found) = try_pair(text, &positions[offset..]) {
            return Some(found);
        }
    }
    None
}

fn try_pair(text: &str, positions: &[usize]) -> Option<String> {
    let mut i = 0;
    while i + 1 < positions.len() {
        let start = positions[i];
        let end = positions[i + 1];
        let inner = &text[start + 1..end];
        if let Some(eq) = inner.find('=') {
            let name = inner[..eq].trim();
            if !name.is_empty() && !name.contains(char::is_whitespace) {
                return Some(name.to_string());
            }
        }
        i += 2;
    }
    None
}

fn scan_setup_py_name(setup_py: &str) -> Option<String> {
    // Match `name='foo'` or `name="foo"` anywhere in the file. We look for
    // each candidate `name` occurrence and verify the following character is
    // `=` (with optional whitespace).
    let mut search_from = 0;
    while let Some(rel) = setup_py[search_from..].find("name") {
        let pos = search_from + rel;
        search_from = pos + 4;
        // Require that the next non-whitespace char is `=` — skips matches
        // like `setuptools` or arbitrary words ending in `name`.
        let after = setup_py[pos + 4..].trim_start();
        if !after.starts_with('=') {
            continue;
        }
        let after_eq = after[1..].trim_start();
        let bytes = after_eq.as_bytes();
        let quote = match bytes.first() {
            Some(q) if *q == b'"' || *q == b'\'' => *q,
            _ => continue,
        };
        let rest = &after_eq[1..];
        let Some(end) = rest.find(quote as char) else {
            continue;
        };
        let name = &rest[..end];
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    None
}

fn detect_node_bin(package_json: &str) -> Option<(String, String)> {
    let parsed: serde_json::Value = serde_json::from_str(package_json).ok()?;
    let name = parsed.get("name")?.as_str()?.to_string();
    match parsed.get("bin") {
        Some(serde_json::Value::String(_)) => Some((name.clone(), name)),
        Some(serde_json::Value::Object(map)) => {
            let first = map.keys().next()?.clone();
            Some((name, first))
        }
        _ => None,
    }
}

fn detect_raw_linux_archive(release: &Release) -> Option<String> {
    // Clippy's case-sensitive-extension lint flags these even though `n` is
    // already lowercased via `to_ascii_lowercase`.
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    {
        for asset in &release.assets {
            let n = asset.name.to_ascii_lowercase();
            if (n.ends_with(".tar.gz") || n.ends_with(".tgz") || n.ends_with(".zip"))
                && (n.contains("linux") || n.contains("amd64") || n.contains("x86_64"))
            {
                return Some(asset.browser_download_url.clone());
            }
        }
        None
    }
}

fn has_install_target(makefile: &str) -> bool {
    makefile.lines().any(|line| {
        let t = line.trim_start();
        t.starts_with("install:") || t.starts_with("install ")
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github_client::Asset;

    fn mk_release(tag: &str, assets: Vec<(&str, &str)>) -> Release {
        Release {
            tag_name: tag.to_string(),
            assets: assets
                .into_iter()
                .map(|(n, u)| Asset {
                    name: n.to_string(),
                    browser_download_url: u.to_string(),
                    size: 100,
                })
                .collect(),
            published_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn rule1_cargo_bin() {
        let input = DetectionInput {
            cargo_toml: Some("[package]\nname = \"x\"\n[[bin]]\nname = \"x\"\n".into()),
            ..Default::default()
        };
        assert_eq!(detect(&input), DetectedTemplate::CargoBuild);
    }

    #[test]
    fn rule1_cargo_main_rs() {
        let input = DetectionInput {
            cargo_toml: Some("[package]\nname = \"x\"\n".into()),
            has_src_main_rs: true,
            ..Default::default()
        };
        assert_eq!(detect(&input), DetectedTemplate::CargoBuild);
    }

    #[test]
    fn rule2_go_binary_amd64() {
        let input = DetectionInput {
            go_mod: Some("module x\n".into()),
            latest_release: Some(mk_release(
                "v1.2.3",
                vec![("foo-1.2.3-linux-amd64.tar.gz", "https://a/b")],
            )),
            ..Default::default()
        };
        match detect(&input) {
            DetectedTemplate::GoBinary { asset_pattern } => {
                assert!(asset_pattern.contains("linux-{arch}"));
                assert!(asset_pattern.contains("{version}"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rule2_go_binary_x86_64_tag_without_v() {
        let input = DetectionInput {
            go_mod: Some("module x\n".into()),
            latest_release: Some(mk_release(
                "1.0.0",
                vec![("foo-1.0.0-linux-x86_64.tar.xz", "https://a/b")],
            )),
            ..Default::default()
        };
        match detect(&input) {
            DetectedTemplate::GoBinary { asset_pattern } => {
                assert!(asset_pattern.contains("{version}"));
                assert!(asset_pattern.contains("linux-{arch}"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rule2_go_without_release_falls_through() {
        let input = DetectionInput {
            go_mod: Some("module x\n".into()),
            ..Default::default()
        };
        // No release → cannot build go-binary-release pattern.
        assert!(matches!(
            detect(&input),
            DetectedTemplate::NeedsManual { .. }
        ));
    }

    #[test]
    fn rule3_pyproject_scripts() {
        let input = DetectionInput {
            pyproject_toml: Some(
                "[project]\nname = \"nanobot\"\nversion = \"0.1.5\"\n\n[project.scripts]\nnanobot = \"nanobot.cli:main\"\n"
                    .into(),
            ),
            ..Default::default()
        };
        match detect(&input) {
            DetectedTemplate::PipPackage {
                pip_package,
                entry_point,
            } => {
                assert_eq!(pip_package, "nanobot");
                assert_eq!(entry_point, "nanobot");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rule3_setup_py_entry_points() {
        let input = DetectionInput {
            setup_py: Some(
                "from setuptools import setup\nsetup(name='mytool', entry_points={'console_scripts': ['mycmd=mytool.cli:main']})"
                    .into(),
            ),
            ..Default::default()
        };
        match detect(&input) {
            DetectedTemplate::PipPackage {
                pip_package,
                entry_point,
            } => {
                assert_eq!(pip_package, "mytool");
                assert_eq!(entry_point, "mycmd");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rule4_node_bin_string() {
        let input = DetectionInput {
            package_json: Some(r#"{"name": "openclaw", "bin": "openclaw.mjs"}"#.into()),
            ..Default::default()
        };
        match detect(&input) {
            DetectedTemplate::NodePackage {
                npm_package,
                entry_point,
            } => {
                assert_eq!(npm_package, "openclaw");
                assert_eq!(entry_point, "openclaw");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rule4_node_bin_object() {
        let input = DetectionInput {
            package_json: Some(r#"{"name": "foo", "bin": {"foo-cli": "bin/cli.js"}}"#.into()),
            ..Default::default()
        };
        match detect(&input) {
            DetectedTemplate::NodePackage { entry_point, .. } => {
                assert_eq!(entry_point, "foo-cli");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rule5_raw_binary_when_only_release() {
        let input = DetectionInput {
            latest_release: Some(mk_release(
                "v1",
                vec![("app-linux-x86_64.tar.gz", "https://download/x")],
            )),
            ..Default::default()
        };
        match detect(&input) {
            DetectedTemplate::RawBinary { download_url } => {
                assert_eq!(download_url, "https://download/x");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rule7_makefile_install_is_manual() {
        let input = DetectionInput {
            makefile: Some("install:\n\tcp foo /usr/bin\n".into()),
            ..Default::default()
        };
        match detect(&input) {
            DetectedTemplate::NeedsManual { reason } => {
                assert!(reason.contains("Makefile"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rule8_nothing_is_manual() {
        let input = DetectionInput::default();
        match detect(&input) {
            DetectedTemplate::NeedsManual { reason } => {
                assert!(reason.contains("no recognizable"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn dockerfile_only_yields_manual() {
        let input = DetectionInput {
            dockerfile: Some("FROM alpine\nRUN true\n".into()),
            ..Default::default()
        };
        match detect(&input) {
            DetectedTemplate::NeedsManual { reason } => assert!(reason.contains("Dockerfile")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn cargo_beats_go_when_both_present() {
        // Weird repo with both go.mod and Cargo.toml [[bin]] — Rule 1 wins.
        let input = DetectionInput {
            cargo_toml: Some("[[bin]]\nname = \"x\"\n".into()),
            go_mod: Some("module x".into()),
            latest_release: Some(mk_release("v1", vec![("x-v1-linux-amd64.tar.gz", "u")])),
            ..Default::default()
        };
        assert_eq!(detect(&input), DetectedTemplate::CargoBuild);
    }

    #[test]
    fn template_name_and_min_ram() {
        assert_eq!(DetectedTemplate::CargoBuild.template_name(), "cargo-build");
        assert_eq!(DetectedTemplate::CargoBuild.min_ram_mb(), 2048);
        assert_eq!(
            DetectedTemplate::GoBinary {
                asset_pattern: "p".into()
            }
            .min_ram_mb(),
            512
        );
        assert_eq!(
            DetectedTemplate::NeedsManual { reason: "r".into() }.template_name(),
            ""
        );
    }

    #[test]
    fn generalise_asset_pattern_strips_tag_and_arch() {
        let out = generalise_asset_pattern("picoclaw-v0.2.5-linux-amd64.tar.gz", "v0.2.5");
        assert_eq!(out, "picoclaw-{version}-linux-{arch}.tar.gz");
    }

    #[test]
    fn generalise_asset_pattern_bare_version_without_v() {
        let out = generalise_asset_pattern("foo-1.0.0-linux-x86_64.zip", "1.0.0");
        assert_eq!(out, "foo-{version}-linux-{arch}.zip");
    }
}
