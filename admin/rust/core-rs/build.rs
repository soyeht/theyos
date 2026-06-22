//! build.rs — reads `claws/manifest.yml` and generates:
//!   1. `src/generated_manifest.rs` — compiled-in Rust const array
//!   2. `../../../claws/catalog.json` — JSON for frontend runtime
//!
//! This is the single-source-of-truth pipeline: manifest.yml → Rust code + JSON.
//!
//! P-46 additions: `Tier` enum, drift tracking fields, `InstallConfig` block for
//! template-driven claws, and compile-time invariant validation (panics if a
//! claw's tier declaration contradicts its install plan source).

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Claws with a compile-time `InstallerPlan` in vmrunner-rs (match arm at
/// `installer_plan.rs:872`). Must stay in sync — a `tier: supported` entry
/// whose name isn't here panics at build time, pointing to the two files that
/// need updating together.
const BUILTIN_PLANS: &[&str] = &[
    "hermes-agent",
    "ironclaw",
    "nanobot",
    "noclaw",
    "nullclaw",
    "openclaw",
    "picoclaw",
    "zeroclaw",
];

#[derive(Deserialize)]
struct Manifest {
    claws: BTreeMap<String, ClawEntry>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Tier {
    Catalog,
    Detected,
    Available,
    Supported,
}

impl Tier {
    fn as_rust_literal(self) -> &'static str {
        match self {
            Tier::Catalog => "Tier::Catalog",
            Tier::Detected => "Tier::Detected",
            Tier::Available => "Tier::Available",
            Tier::Supported => "Tier::Supported",
        }
    }

    fn as_json_str(self) -> &'static str {
        match self {
            Tier::Catalog => "catalog",
            Tier::Detected => "detected",
            Tier::Available => "available",
            Tier::Supported => "supported",
        }
    }
}

#[derive(Deserialize, Default)]
struct InstallBlock {
    #[serde(default)]
    github_repo: String,
    #[serde(default)]
    git_ref: String,
    #[serde(default)]
    binary_name: String,
    #[serde(default)]
    binary_path: String,
    #[serde(default)]
    asset_pattern: String,
    #[serde(default)]
    pip_package: String,
    #[serde(default)]
    npm_package: String,
    #[serde(default)]
    entry_point: String,
    #[serde(default)]
    config_dir: String,
    #[serde(default)]
    system_deps: Vec<String>,
    #[serde(default)]
    manual_script: String,
}

#[derive(Deserialize)]
struct ClawEntry {
    description: String,
    #[serde(default)]
    language: String,
    #[serde(default)]
    buildable: bool,
    #[serde(default)]
    version: String,
    #[serde(default)]
    binary_size_mb: u32,
    #[serde(default)]
    min_ram_mb: u32,
    #[serde(default)]
    license: String,
    /// How the claw is distributed: "prebuilt" (download artifact) or "local" (build on host).
    #[serde(default)]
    distribution: String,

    // ─── P-46 catalog fields ────────────────────────────────────────────
    /// Required. Every claw must declare its tier explicitly.
    tier: Tier,
    #[serde(default)]
    stars: u32,
    #[serde(default)]
    source: String,
    #[serde(default)]
    last_updated: String,

    // Drift tracking.
    #[serde(default)]
    reviewed_upstream_commit: String,
    #[serde(default)]
    reviewed_at: String,
    #[serde(default)]
    reviewed_by: String,
    #[serde(default)]
    latest_upstream_commit: String,
    #[serde(default)]
    latest_checked_at: String,

    // Install plan origin.
    #[serde(default)]
    install_template: String,
    #[serde(default)]
    install_plan_source: String,
    #[serde(default)]
    install: Option<InstallBlock>,

    // Daemon startup command used by `imagebuilder build --verify-only` to
    // soak the claw for 60s. Empty ⇒ the soak is skipped (install-only verify).
    #[serde(default)]
    run_cmd: String,

    // Operator-visible reason a claw is intentionally not installable
    // (`tier: catalog` entries that exist for discovery only — Electron
    // apps, ESP firmware, Claude Code plugins like claude-claw, etc.).
    // Surfaced to clients via `ClawCatalogResponse.unavailable_reason`
    // when the entry's tier is not user-installable.
    #[serde(default)]
    skip_install_reason: String,
}

/// Escape `\` and `"` for inclusion inside a short, single-line Rust `"..."` literal.
/// For multi-line content (notably `manual_script` from the LLM path) use
/// [`emit_str_literal`] which prefers raw strings with auto-sized delimiters.
fn escape_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Count the longest run of `#` that follows a `"` in `s`. Used to pick a raw
/// string delimiter (`r#"…"#`, `r##"…"##`, …) that cannot appear inside `s`.
fn count_max_consecutive_quote_hashes(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut max = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'"' {
            let mut n = 0usize;
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] == b'#' {
                n += 1;
                j += 1;
            }
            if n > max {
                max = n;
            }
        }
    }
    max
}

/// Escape a potentially multi-line string so it can be embedded as a regular
/// (non-raw) `"…"` literal — handles `\\`, `"`, `\n`, `\r`, `\t`, `\0`.
fn escape_str_full(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
        .replace('\0', "\\0")
}

/// Emit a Rust string literal for `s`.
///
/// Prefers a raw string (`r#"…"#`) with automatically-chosen hash count so that
/// multi-line scripts (with embedded `"`, backslashes, newlines) round-trip
/// without escaping. Falls back to a fully-escaped regular literal if the
/// content would need an impractically long delimiter (>254 hashes).
///
/// Used for `manual_script` (from the manual-shell template, populated by the
/// LLM discover path in Phase H). Single-line fields keep using [`escape_str`].
fn emit_str_literal(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".to_string();
    }
    // Raw strings ignore `\` but must pick enough `#`s so the closing
    // delimiter can't appear inside the content. If the content has no `"`
    // at all, zero hashes suffice (`r"..."`) — this keeps clippy's
    // `needless_raw_string_hashes` happy for single-line scripts.
    if !s.contains('"') {
        return format!("r\"{s}\"");
    }
    let max_hashes = count_max_consecutive_quote_hashes(s);
    if max_hashes < 255 {
        let hashes = "#".repeat(max_hashes + 1);
        format!("r{hashes}\"{s}\"{hashes}")
    } else {
        format!("\"{}\"", escape_str_full(s))
    }
}

/// Sanity-check the `emit_str_literal` pipeline. Runs inside `main()` at build
/// time because `cargo test` does not execute build scripts.
fn check_emit_str_literal_invariants() {
    assert_eq!(emit_str_literal(""), "\"\"");

    // Content without any `"` uses zero-hash raw string.
    let simple = emit_str_literal("hello world");
    assert_eq!(simple, "r\"hello world\"");

    // Content with `"` but no `"#` uses r#"..."#.
    let multi = "echo \"hi\"\npath=/tmp\\foo\n";
    let lit = emit_str_literal(multi);
    assert!(
        lit.starts_with("r#\""),
        "multiline with quotes should use r#, got: {lit}"
    );
    assert!(lit.contains(multi), "content must round-trip verbatim");

    let with_quote_hash = "echo \"#end\"";
    let lit = emit_str_literal(with_quote_hash);
    assert!(
        lit.starts_with("r##\"") && lit.ends_with("\"##"),
        "r## delimiter expected, got: {lit}"
    );

    let with_two = "echo \"##done\"";
    let lit = emit_str_literal(with_two);
    assert!(
        lit.starts_with("r###\"") && lit.ends_with("\"###"),
        "r### delimiter expected, got: {lit}"
    );

    let weird = "tab:\there\nnull:\0end";
    let lit = emit_str_literal(weird);
    assert!(lit.contains(weird), "raw string preserves control bytes");

    assert_eq!(count_max_consecutive_quote_hashes(""), 0);
    assert_eq!(count_max_consecutive_quote_hashes("abc"), 0);
    assert_eq!(count_max_consecutive_quote_hashes("###"), 0);
    assert_eq!(count_max_consecutive_quote_hashes("\"#"), 1);
    assert_eq!(count_max_consecutive_quote_hashes("\"##"), 2);
    assert_eq!(count_max_consecutive_quote_hashes("\"###"), 3);
    assert_eq!(count_max_consecutive_quote_hashes("a\"#b\"##c"), 2);

    assert_eq!(escape_str_full("a\\b"), "a\\\\b");
    assert_eq!(escape_str_full("a\"b"), "a\\\"b");
    assert_eq!(escape_str_full("a\nb"), "a\\nb");
    assert_eq!(escape_str_full("a\tb"), "a\\tb");
}

/// `nemoclaw` → `NEMOCLAW`, `hermes-agent` → `HERMES_AGENT`.
fn ident_upper(name: &str) -> String {
    name.to_ascii_uppercase().replace('-', "_")
}

/// Abort build with a descriptive error if tier/install invariants are violated.
fn validate_invariants(entries: &[(String, ClawEntry)]) {
    for (name, entry) in entries {
        match entry.tier {
            Tier::Supported => {
                assert!(
                    BUILTIN_PLANS.contains(&name.as_str()),
                    "build.rs: claw '{name}' has tier: supported but is not in \
                     BUILTIN_PLANS. Add a builtin plan to \
                     vmrunner-rs/src/installer_plan.rs::get_plan() and add the name \
                     to BUILTIN_PLANS in core-rs/build.rs."
                );
                assert!(
                    entry.install_plan_source == "builtin",
                    "build.rs: claw '{name}' has tier: supported so \
                     install_plan_source must be \"builtin\" (got \"{}\").",
                    entry.install_plan_source
                );
                assert!(
                    entry.install.is_none(),
                    "build.rs: claw '{name}' has tier: supported so install: block \
                     must be absent (supported claws use the compiled-in plan)."
                );
            }
            Tier::Available | Tier::Detected => {
                let src = &entry.install_plan_source;
                assert!(
                    src.starts_with("template:") || src == "llm",
                    "build.rs: claw '{name}' has tier: {} so install_plan_source \
                     must be \"template:<name>\" or \"llm\" (got \"{}\").",
                    entry.tier.as_json_str(),
                    src
                );
                assert!(
                    entry.install.is_some(),
                    "build.rs: claw '{name}' has tier: {} but install: block is \
                     missing.",
                    entry.tier.as_json_str()
                );
            }
            Tier::Catalog => {
                assert!(
                    entry.install.is_none(),
                    "build.rs: claw '{name}' has tier: catalog so install: block \
                     must be absent (catalog claws are metadata-only)."
                );
            }
        }
        if entry.install_template == "manual-shell" {
            let has_script = entry
                .install
                .as_ref()
                .is_some_and(|i| !i.manual_script.is_empty());
            assert!(
                has_script,
                "build.rs: claw '{name}' uses install_template: manual-shell but \
                 install.manual_script is empty."
            );
        }
    }
}

#[allow(clippy::too_many_lines)] // codegen is inherently linear; splitting hurts readability
fn main() {
    // Sanity-check the string-literal emitter before we depend on it for
    // manual_script escaping. Runs every build; fails loudly if regressed.
    check_emit_str_literal_invariants();

    // CLAWS_MANIFEST_YML is set by the Nix build (sandbox doesn't have the repo layout).
    // Falls back to the relative path for normal `cargo build` in the repo.
    let manifest_path = if let Some(path) = std::env::var_os("CLAWS_MANIFEST_YML") {
        PathBuf::from(path)
    } else {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        [
            manifest_dir.join("../../../claws/manifest.yml"),
            // cross-rs mounts the workflow working-directory (`admin/rust`) as
            // the project root, so the repo-level `claws/` directory is copied
            // beside the crates for release builds.
            manifest_dir.join("../claws/manifest.yml"),
            PathBuf::from("/project/claws/manifest.yml"),
        ]
        .into_iter()
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| manifest_dir.join("../../../claws/manifest.yml"))
    };
    println!("cargo:rerun-if-changed={}", manifest_path.to_string_lossy());

    let content = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("build.rs: cannot read {}: {e}", manifest_path.display()));

    let manifest: Manifest = serde_yaml::from_str(&content)
        .unwrap_or_else(|e| panic!("build.rs: cannot parse manifest.yml: {e}"));

    // Collect entries sorted alphabetically by name (BTreeMap already sorted)
    let mut entries: Vec<(String, ClawEntry)> = manifest.claws.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    // ── Invariant validation (panic on violation) ───────────────────────
    validate_invariants(&entries);

    // ── Generate src/generated_manifest.rs ──────────────────────────────
    // `InstallConfig` is only used when at least one claw has an `install:` block
    // (i.e. any tier: detected/available claw). While the catalog is 100% Supported,
    // the import would be dead. Emit it conditionally.
    let any_install = entries.iter().any(|(_, e)| e.install.is_some());
    let install_import = if any_install { "InstallConfig, " } else { "" };

    let mut rs = format!(
        "// AUTO-GENERATED by build.rs from claws/manifest.yml — do not edit.\n\
         #![allow(clippy::unreadable_literal, dead_code)]\n\
         use super::{{ManifestEntry, {install_import}Tier}};\n\n",
    );

    // Emit one static `INSTALL_<CLAWNAME>_DEPS` + `INSTALL_<CLAWNAME>`
    // per claw that has an install: block.
    {
        use std::fmt::Write;
        for (name, entry) in &entries {
            let Some(install) = &entry.install else {
                continue;
            };
            let ident = format!("INSTALL_{}", ident_upper(name));
            let deps_ident = format!("{ident}_DEPS");

            let deps_joined: String = install
                .system_deps
                .iter()
                .map(|d| format!("\"{}\"", escape_str(d)))
                .collect::<Vec<_>>()
                .join(", ");

            writeln!(rs, "static {deps_ident}: &[&str] = &[{deps_joined}];")
                .expect("write to String");

            writeln!(
                rs,
                "static {ident}: InstallConfig = InstallConfig {{ \
                  github_repo: \"{}\", \
                  git_ref: \"{}\", \
                  binary_name: \"{}\", \
                  binary_path: \"{}\", \
                  asset_pattern: \"{}\", \
                  pip_package: \"{}\", \
                  npm_package: \"{}\", \
                  entry_point: \"{}\", \
                  config_dir: \"{}\", \
                  system_deps: {deps_ident}, \
                  manual_script: {} \
                  }};",
                escape_str(&install.github_repo),
                escape_str(&install.git_ref),
                escape_str(&install.binary_name),
                escape_str(&install.binary_path),
                escape_str(&install.asset_pattern),
                escape_str(&install.pip_package),
                escape_str(&install.npm_package),
                escape_str(&install.entry_point),
                escape_str(&install.config_dir),
                // manual_script may be multi-line (from LLM discover) — use
                // the raw-string-preferring emitter to handle embedded quotes
                // and control chars safely.
                emit_str_literal(&install.manual_script),
            )
            .expect("write to String");
        }
    }

    rs.push_str("\npub const CATALOG: &[ManifestEntry] = &[\n");
    {
        use std::fmt::Write;
        for (name, entry) in &entries {
            let install_ref = if entry.install.is_some() {
                format!("Some(&INSTALL_{})", ident_upper(name))
            } else {
                String::from("None")
            };

            writeln!(
                rs,
                "    ManifestEntry {{ \
                  name: \"{name}\", \
                  description: \"{}\", \
                  language: \"{}\", \
                  buildable: {}, \
                  version: \"{}\", \
                  binary_size_mb: {}, \
                  min_ram_mb: {}, \
                  license: \"{}\", \
                  distribution: \"{}\", \
                  tier: {}, \
                  stars: {}, \
                  source: \"{}\", \
                  last_updated: \"{}\", \
                  reviewed_upstream_commit: \"{}\", \
                  reviewed_at: \"{}\", \
                  reviewed_by: \"{}\", \
                  latest_upstream_commit: \"{}\", \
                  latest_checked_at: \"{}\", \
                  install_template: \"{}\", \
                  install_plan_source: \"{}\", \
                  install: {install_ref}, \
                  run_cmd: \"{}\", \
                  skip_install_reason: \"{}\" \
                  }},",
                escape_str(&entry.description),
                escape_str(&entry.language),
                entry.buildable,
                escape_str(&entry.version),
                entry.binary_size_mb,
                entry.min_ram_mb,
                escape_str(&entry.license),
                escape_str(&entry.distribution),
                entry.tier.as_rust_literal(),
                entry.stars,
                escape_str(&entry.source),
                escape_str(&entry.last_updated),
                escape_str(&entry.reviewed_upstream_commit),
                escape_str(&entry.reviewed_at),
                escape_str(&entry.reviewed_by),
                escape_str(&entry.latest_upstream_commit),
                escape_str(&entry.latest_checked_at),
                escape_str(&entry.install_template),
                escape_str(&entry.install_plan_source),
                escape_str(&entry.run_cmd),
                escape_str(&entry.skip_install_reason),
            )
            .expect("write to String");
        }
    }
    rs.push_str("];\n");

    let generated_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/generated_manifest.rs");
    fs::write(&generated_path, &rs)
        .unwrap_or_else(|e| panic!("build.rs: cannot write {}: {e}", generated_path.display()));

    // ── Generate claws/catalog.json ─────────────────────────────────────────
    let catalog: Vec<serde_json::Value> = entries
        .iter()
        .map(|(name, entry)| {
            serde_json::json!({
                "name": name,
                "description": entry.description,
                "language": entry.language,
                "buildable": entry.buildable,
                "version": entry.version,
                "binary_size_mb": entry.binary_size_mb,
                "min_ram_mb": entry.min_ram_mb,
                "license": entry.license,
                "distribution": entry.distribution,
                "tier": entry.tier.as_json_str(),
                "stars": entry.stars,
                "source": entry.source,
                "last_updated": entry.last_updated,
                "reviewed_upstream_commit": entry.reviewed_upstream_commit,
                "latest_upstream_commit": entry.latest_upstream_commit,
                "install_template": entry.install_template,
                "install_plan_source": entry.install_plan_source,
                "run_cmd": entry.run_cmd,
                "skip_install_reason": entry.skip_install_reason,
            })
        })
        .collect();

    let catalog_json = serde_json::to_string_pretty(&catalog).expect("serialize catalog.json");
    let catalog_path = std::env::var_os("CLAWS_CATALOG_JSON").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../claws/catalog.json"),
        PathBuf::from,
    );

    // In the Nix sandbox the target directory doesn't exist — skip the write.
    // catalog.json is a runtime artifact, not needed for compilation.
    if catalog_path.parent().is_some_and(Path::exists) {
        fs::write(&catalog_path, format!("{catalog_json}\n"))
            .unwrap_or_else(|e| panic!("build.rs: cannot write {}: {e}", catalog_path.display()));
    }
}
