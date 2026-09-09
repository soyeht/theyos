#![cfg(test)]

use super::*;
use crate::github_client::{Asset, FileContent, GitHubError, Release, RepoMeta};
use std::cell::RefCell;
use std::collections::HashMap;

struct MockApi {
    meta: RepoMeta,
    release: Option<Release>,
    files: HashMap<String, Option<FileContent>>,
    head: String,
    calls: RefCell<u32>,
}

impl MockApi {
    fn with_cargo(head: &str) -> Self {
        let mut files: HashMap<String, Option<FileContent>> = HashMap::new();
        files.insert(
            "Cargo.toml".into(),
            Some(FileContent {
                path: "Cargo.toml".into(),
                content: "[package]\nname = \"widget\"\n[[bin]]\nname = \"widget\"\n".into(),
            }),
        );
        Self {
            meta: RepoMeta {
                name: "widget".into(),
                stars: 17,
                pushed_at: "2026-04-10T12:00:00Z".into(),
                license_spdx: "MIT".into(),
                default_branch: "main".into(),
                html_url: "https://github.com/foo/widget".into(),
                description: "a widget".into(),
            },
            release: None,
            files,
            head: head.into(),
            calls: RefCell::new(0),
        }
    }
}

impl GitHubApi for MockApi {
    fn get_repo(&self, _o: &str, _r: &str) -> Result<RepoMeta, GitHubError> {
        *self.calls.borrow_mut() += 1;
        Ok(self.meta.clone())
    }
    fn latest_release(&self, _o: &str, _r: &str) -> Result<Option<Release>, GitHubError> {
        Ok(self.release.clone())
    }
    fn get_contents(
        &self,
        _o: &str,
        _r: &str,
        path: &str,
    ) -> Result<Option<FileContent>, GitHubError> {
        Ok(self.files.get(path).cloned().unwrap_or(None))
    }
    fn head_sha(&self, _o: &str, _r: &str, _b: Option<&str>) -> Result<String, GitHubError> {
        Ok(self.head.clone())
    }
}

#[test]
fn render_entry_cargo_build() {
    let input = DetectionInput {
        meta: Some(RepoMeta {
            name: "widget".into(),
            stars: 17,
            pushed_at: "2026-04-10T12:00:00Z".into(),
            license_spdx: "MIT".into(),
            default_branch: "main".into(),
            html_url: "https://github.com/foo/widget".into(),
            description: "a widget".into(),
        }),
        latest_release: None,
        cargo_toml: Some("[[bin]]\nname=\"x\"\n".into()),
        ..Default::default()
    };
    let out = render_entry(
        "widget",
        &input,
        &DetectedTemplate::CargoBuild,
        "a".repeat(40).as_str(),
    );
    assert!(out.contains("widget:"));
    assert!(out.contains("tier: detected"));
    assert!(out.contains("install_template: cargo-build"));
    assert!(out.contains("install_plan_source: \"template:cargo-build\""));
    assert!(out.contains("min_ram_mb: 2048"));
    assert!(out.contains("reviewed_upstream_commit: \""));
    // H1 fix: cargo-build now emits an install block with the repo + binary
    // so build.rs::validate_invariants accepts `tier: detected`.
    assert!(out.contains("install:\n"));
    assert!(out.contains("github_repo: \"foo/widget\""));
    assert!(out.contains("binary_name: \"widget\""));
}

#[test]
fn render_entry_go_binary_block() {
    let input = DetectionInput {
        meta: Some(RepoMeta {
            name: "goapp".into(),
            stars: 2,
            pushed_at: "2026-04-01T00:00:00Z".into(),
            license_spdx: "Apache-2.0".into(),
            default_branch: "main".into(),
            html_url: "https://github.com/foo/goapp".into(),
            description: String::new(),
        }),
        latest_release: Some(Release {
            tag_name: "v1.0.0".into(),
            assets: vec![Asset {
                name: "goapp-v1.0.0-linux-amd64.tar.gz".into(),
                browser_download_url: "https://d".into(),
                size: 10,
            }],
            published_at: String::new(),
        }),
        go_mod: Some("module goapp\n".into()),
        ..Default::default()
    };
    let template = detector::detect(&input);
    let out = render_entry("goapp", &input, &template, "dead");
    assert!(out.contains("install_template: go-binary-release"));
    assert!(out.contains("install:"));
    assert!(out.contains("asset_pattern:"));
}

#[test]
fn render_entry_needs_manual() {
    let input = DetectionInput {
        meta: Some(RepoMeta {
            name: "x".into(),
            stars: 0,
            pushed_at: "2026-04-01T00:00:00Z".into(),
            license_spdx: String::new(),
            default_branch: "main".into(),
            html_url: "https://github.com/foo/x".into(),
            description: String::new(),
        }),
        ..Default::default()
    };
    let out = render_entry(
        "x",
        &input,
        &DetectedTemplate::NeedsManual {
            reason: "no build".into(),
        },
        "",
    );
    assert!(out.contains("tier: catalog"));
    assert!(out.contains("install_template: \"\""));
    assert!(!out.contains("install_plan_source"));
    assert!(out.contains("license: \"unknown\""));
}

#[test]
fn collect_urls_reads_from_list_ignoring_comments() {
    let tmp = tempfile::tempdir().unwrap();
    let list = tmp.path().join("urls.txt");
    std::fs::write(
        &list,
        "# a comment\n\nhttps://github.com/a/b\nhttps://github.com/c/d\n",
    )
    .unwrap();
    let args = ClawsDetectArgs {
        repo: None,
        from_list: Some(list),
        dry_run: true,
        yes: false,
    };
    let urls = collect_urls(&args).unwrap();
    assert_eq!(urls.len(), 2);
}

#[test]
fn collect_urls_combines_single_and_list() {
    let tmp = tempfile::tempdir().unwrap();
    let list = tmp.path().join("urls.txt");
    std::fs::write(&list, "https://github.com/c/d\n").unwrap();
    let args = ClawsDetectArgs {
        repo: Some("https://github.com/a/b".into()),
        from_list: Some(list),
        dry_run: true,
        yes: false,
    };
    let urls = collect_urls(&args).unwrap();
    assert_eq!(urls.len(), 2);
}

#[test]
fn load_existing_claw_names_returns_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("manifest.yml");
    std::fs::write(
        &path,
        "claws:\n  picoclaw:\n    description: x\n  nullclaw:\n    description: y\n",
    )
    .unwrap();
    let names = load_existing_claw_names(&path).unwrap();
    assert!(names.iter().any(|n| n == "picoclaw"));
    assert!(names.iter().any(|n| n == "nullclaw"));
}

#[test]
fn load_existing_claw_names_handles_missing_file() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("nope.yml");
    let names = load_existing_claw_names(&path).unwrap();
    assert!(names.is_empty());
}

#[test]
fn append_under_claws_key_preserves_original() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("manifest.yml");
    let original = "claws:\n  picoclaw:\n    description: x\n";
    std::fs::write(&path, original).unwrap();
    append_under_claws_key(&path, "  newclaw:\n    description: y\n").unwrap();
    let updated = std::fs::read_to_string(&path).unwrap();
    assert!(updated.starts_with(original));
    assert!(updated.contains("newclaw"));
}

#[test]
fn process_one_skips_when_name_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("manifest.yml");
    std::fs::write(&manifest, "claws:\n  widget:\n    description: x\n").unwrap();
    let mock = MockApi::with_cargo("deadbeef");
    let existing = vec!["widget".to_string()];
    let args = ClawsDetectArgs {
        repo: Some("https://github.com/foo/widget".into()),
        from_list: None,
        dry_run: false,
        yes: true,
    };
    let result = process_one(
        &mock,
        tmp.path(),
        "https://github.com/foo/widget",
        &existing,
        &args,
        &manifest,
    )
    .unwrap();
    assert!(result.is_none(), "existing claw should skip");
    // Manifest untouched.
    let after = std::fs::read_to_string(&manifest).unwrap();
    assert!(after.contains("widget:"));
    assert_eq!(after.matches("widget:").count(), 1);
}

#[test]
fn process_one_dry_run_does_not_write() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("manifest.yml");
    std::fs::write(&manifest, "claws:\n").unwrap();
    let mock = MockApi::with_cargo("deadbeef");
    let args = ClawsDetectArgs {
        repo: Some("https://github.com/foo/widget".into()),
        from_list: None,
        dry_run: true,
        yes: true,
    };
    let result = process_one(
        &mock,
        tmp.path(),
        "https://github.com/foo/widget",
        &[],
        &args,
        &manifest,
    )
    .unwrap();
    assert_eq!(result, Some("widget".to_string()));
    let after = std::fs::read_to_string(&manifest).unwrap();
    assert_eq!(after, "claws:\n", "dry run must not mutate manifest");
}

#[test]
fn process_one_writes_and_persists_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("manifest.yml");
    std::fs::write(&manifest, "claws:\n  pico:\n    description: keep-me\n").unwrap();
    let mock = MockApi::with_cargo("cafef00d");
    let args = ClawsDetectArgs {
        repo: Some("https://github.com/foo/widget".into()),
        from_list: None,
        dry_run: false,
        yes: true,
    };
    let result = process_one(
        &mock,
        tmp.path(),
        "https://github.com/foo/widget",
        &[],
        &args,
        &manifest,
    )
    .unwrap();
    assert_eq!(result, Some("widget".to_string()));
    let after = std::fs::read_to_string(&manifest).unwrap();
    assert!(after.contains("pico:"));
    assert!(after.contains("widget:"));
    assert!(after.contains("install_template: cargo-build"));
    assert!(after.contains("reviewed_upstream_commit: \"cafef00d\""));
}

#[test]
fn truncate_to_date_keeps_head() {
    assert_eq!(truncate_to_date("2026-04-10T12:00:00Z"), "2026-04-10");
    assert_eq!(truncate_to_date(""), "");
    assert_eq!(truncate_to_date("bad"), "bad");
}

#[test]
fn yaml_quoted_escapes_quotes() {
    assert_eq!(manifest_yaml::yaml_quoted("a \"b\" c"), "\"a \\\"b\\\" c\"");
}
