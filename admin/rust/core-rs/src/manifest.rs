//! Claw manifest — compiled-in catalog generated from `claws/manifest.yml`.
//!
//! The `build.rs` in core-rs reads the YAML manifest at compile time and
//! generates `generated_manifest.rs` with a `CATALOG` const array. This module
//! wraps that generated code with a clean public API.
//!
//! This is the single source of truth for "what claws does theyOS know about?"
//! All other claw lists in the workspace should use these functions instead of
//! maintaining their own hardcoded arrays.

use serde::{Deserialize, Serialize};

#[path = "generated_manifest.rs"]
mod generated_manifest;

/// Install pipeline progression tier.
///
/// Claws advance through tiers as they gain coverage:
///   - `Catalog`   — only metadata, not installable
///   - `Detected`  — detector assigned a template, not yet verified
///   - `Available` — `claws-verify` passed smoke in disposable VM
///   - `Supported` — builtin plan + E2E + warm pool slot (full first-class)
///
/// The enum is `Copy` and has a `const` gate `can_user_install()` used by
/// install handlers (HTTP + mobile) and the install worker to decide whether
/// an install request should proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Catalog,
    Detected,
    Available,
    Supported,
}

impl Tier {
    /// Gate used by install handlers (`handlers_claws.rs`, `handlers_mobile.rs`)
    /// and the install worker. Only `Available` and `Supported` tiers can be
    /// installed by user action.
    ///
    /// Prefer [`ManifestEntry::installability`] in new code — it additionally
    /// catches "tier ok but no install path" manifest inconsistencies and
    /// surfaces a structured reason. This helper is kept as a lower-level
    /// tier-only check; the catalog API and install handlers MUST go through
    /// the entry-level method.
    #[must_use]
    pub const fn can_user_install(self) -> bool {
        matches!(self, Tier::Available | Tier::Supported)
    }
}

/// Structured reason a claw cannot be installed right now. Serialised as
/// snake-case strings (`"catalog_only"`, `"detected_unverified"`,
/// `"no_install_plan"`) for the wire format consumed by the iPhone/Mac UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReasonCode {
    /// `tier: catalog` — entry exists for discovery only. Common case for
    /// Claude Code plugins (claude-claw), Electron desktop apps, ESP
    /// microcontroller firmware, jailbreak tweaks.
    CatalogOnly,
    /// `tier: detected` — the detector assigned a template but
    /// `claws-verify` has not run a smoke install in a sandbox VM yet.
    DetectedUnverified,
    /// Manifest inconsistency: the entry's tier qualifies for install
    /// (`Available` / `Supported`) but it has neither a `buildable: true`
    /// flag, a `distribution: "prebuilt"` artifact, nor an `install:`
    /// template block. Asserted absent in tests; if this is ever observed
    /// in the wild it is a manifest bug, not a user-facing condition.
    NoInstallPlan,
}

/// Result of asking "can a user install this claw right now?".
///
/// Returned from [`ManifestEntry::installability`]. The HTTP catalog
/// response, the install handlers (`handlers_claws`/`handlers_mobile`),
/// the background install worker, the vmrunner installer factory, and
/// the imagebuilder filter all consult this single API — there is no
/// other predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClawInstallability {
    /// Cleared for user action: handler accepts the install request,
    /// catalog response advertises `installable: true`.
    Installable,
    /// Blocked. `code` carries a stable machine-readable category;
    /// `message` is operator-facing text (uses
    /// `ManifestEntry::skip_install_reason` when present, otherwise a
    /// generic default keyed off `code`).
    Unavailable {
        code: UnavailableReasonCode,
        message: String,
    },
}

impl ManifestEntry {
    /// Single source of truth for installability. **All** install gates —
    /// HTTP handlers, install worker, vmrunner installer factory,
    /// imagebuilder filter, catalog response — delegate to this method.
    /// Adding another parallel predicate is a regression.
    ///
    /// Categorisation:
    ///   - `Supported`/`Available` tier + an install path
    ///     (`buildable` | `prebuilt` | `install:` block) → `Installable`.
    ///   - `Supported`/`Available` tier with NO install path → `Unavailable
    ///     { code: NoInstallPlan, .. }` (asserted absent in tests).
    ///   - `Catalog` tier → `Unavailable { code: CatalogOnly, .. }`.
    ///   - `Detected` tier → `Unavailable { code: DetectedUnverified, .. }`.
    #[must_use]
    pub fn installability(&self) -> ClawInstallability {
        match self.tier {
            Tier::Supported | Tier::Available => {
                let has_install_path =
                    self.buildable || self.distribution == "prebuilt" || self.install.is_some();
                if has_install_path {
                    ClawInstallability::Installable
                } else {
                    ClawInstallability::Unavailable {
                        code: UnavailableReasonCode::NoInstallPlan,
                        message: format!(
                            "{} qualifies by tier {:?} but has no install path \
                             (buildable=false, distribution!=prebuilt, install: absent) \
                             — manifest invariant violated",
                            self.name, self.tier,
                        ),
                    }
                }
            }
            Tier::Catalog => ClawInstallability::Unavailable {
                code: UnavailableReasonCode::CatalogOnly,
                message: if self.skip_install_reason.is_empty() {
                    String::from(
                        "this claw is exposed for discovery only \
                         and not yet installable",
                    )
                } else {
                    self.skip_install_reason.to_string()
                },
            },
            Tier::Detected => ClawInstallability::Unavailable {
                code: UnavailableReasonCode::DetectedUnverified,
                message: if self.skip_install_reason.is_empty() {
                    String::from(
                        "claws-verify has not confirmed this claw runs in a sandbox VM yet",
                    )
                } else {
                    self.skip_install_reason.to_string()
                },
            },
        }
    }
}

/// Install configuration emitted by build.rs for every claw with an `install:`
/// block in the manifest.
///
/// For `Tier::Supported` claws (which use builtin plans), the `install` field
/// of [`ManifestEntry`] is `None` — supported plans are defined directly in
/// `vmrunner-rs/src/installer_plan.rs::get_plan()` and don't need config.
///
/// Empty `&'static str` means "not set". `system_deps: &[]` means "no extras".
///
/// `manual_script` is used only when `install_template == "manual-shell"` (LLM
/// discovered plans that don't fit an existing template).
///
/// Derives `Default` so templates can build fixtures via `..Default::default()`
/// in tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct InstallConfig {
    pub github_repo: &'static str,
    pub binary_name: &'static str,
    pub binary_path: &'static str,
    pub asset_pattern: &'static str,
    pub pip_package: &'static str,
    pub npm_package: &'static str,
    pub entry_point: &'static str,
    pub config_dir: &'static str,
    pub system_deps: &'static [&'static str],
    pub manual_script: &'static str,
}

/// A single entry in the claw manifest.
///
/// Field name conventions (easy to confuse):
///   - `last_updated`             = upstream GitHub `pushed_at` (when the
///     upstream repo was last updated by its maintainer).
///   - `reviewed_upstream_commit` = SHA validated at the last `claws-detect`
///     or `claws-discover` run. `claws-scan` does NOT touch this field.
///   - `latest_upstream_commit`   = SHA seen at the last `claws-scan` run.
///     `claws-scan --apply` updates this field (and `latest_checked_at`) only,
///     preserving `reviewed_upstream_commit` as the baseline.
///   - `reviewed_at` / `reviewed_by` — when/who ran detect or discover.
///   - `latest_checked_at`        — when `claws-scan` last looked at upstream.
#[derive(Debug, Clone, Copy)]
pub struct ManifestEntry {
    pub name: &'static str,
    pub description: &'static str,
    pub language: &'static str,
    /// Whether the Rust codebase has a `get_plan()` entry for this claw,
    /// meaning it can be installed via the claw store (golden build + snapshot).
    pub buildable: bool,
    /// Semver of the build currently shipped in the golden image.
    pub version: &'static str,
    /// Disk footprint in MB (binary for compiled claws, install size for interpreted).
    pub binary_size_mb: u32,
    /// Minimum RAM in MB for the VM to boot and run the claw idle.
    pub min_ram_mb: u32,
    /// SPDX license identifier (e.g. "MIT", "Apache-2.0", "proprietary").
    pub license: &'static str,
    /// Distribution method: `"prebuilt"` = download artifact, `"local"` = build on host.
    pub distribution: &'static str,

    // ─── Catalog fields (added in P-46) ─────────────────────────────────
    /// Install pipeline tier.
    pub tier: Tier,
    /// GitHub stars (0 if unknown or not applicable).
    pub stars: u32,
    /// Upstream repo URL (empty string if not applicable).
    pub source: &'static str,
    /// GitHub `pushed_at` of the upstream (empty if never checked).
    pub last_updated: &'static str,

    // ─── Drift tracking ──────────────────────────────────────────────────
    /// Baseline SHA validated at last detect/discover — immutable by scan.
    pub reviewed_upstream_commit: &'static str,
    pub reviewed_at: &'static str,
    pub reviewed_by: &'static str,
    /// Latest SHA seen by `claws-scan` — scan-updated, can drift from baseline.
    pub latest_upstream_commit: &'static str,
    pub latest_checked_at: &'static str,

    // ─── Install plan origin ─────────────────────────────────────────────
    /// Template name (e.g. "pip-package") if plan came from a template;
    /// empty for builtin plans.
    pub install_template: &'static str,
    /// `"builtin"` | `"template:<name>"` | `"llm"` | `"manual"`.
    pub install_plan_source: &'static str,
    /// `None` for `Tier::Supported` (uses builtin plan in vmrunner-rs).
    /// `Some(&CONFIG)` for `Tier::Detected` / `Tier::Available` (template-driven).
    pub install: Option<&'static InstallConfig>,

    /// Shell command that daemonizes the claw. Used by
    /// `imagebuilder build --verify-only` to boot the claw in the verify VM
    /// and soak it for 60s.
    ///
    /// Empty string ⇒ skip the soak (install-only verify). Non-empty ⇒
    /// `verify_golden_image` runs `nohup <run_cmd> &`, waits 60s, then
    /// checks the pid is still alive.
    ///
    /// Examples: `"picoclaw gateway"`, `"node openclaw.mjs gateway"`,
    /// `"cd /opt/claws/foo && pnpm start"`. Most claws expose a CLI whose
    /// bare invocation prints help and exits — that's why this is a
    /// dedicated field instead of reusing `install.entry_point`.
    pub run_cmd: &'static str,

    /// Operator-visible reason a claw entry is intentionally not
    /// installable. Populated for `tier: catalog` entries that exist
    /// purely for discovery (Claude Code plugins, Electron desktop apps,
    /// ESP microcontroller firmware, etc.). Empty for installable claws.
    ///
    /// Surfaced to clients via
    /// `ClawCatalogResponse.unavailable_reason` (claw-rs/store.rs) and
    /// inside [`ClawInstallability::Unavailable`].
    pub skip_install_reason: &'static str,
}

/// Returns the full compiled-in catalog, sorted alphabetically by name.
#[must_use]
pub fn catalog() -> &'static [ManifestEntry] {
    generated_manifest::CATALOG
}

/// Returns all claw names from the manifest, sorted alphabetically.
///
/// **Returns the full catalog** (every tier). Most legacy callers — server
/// bootstrap, imagebuilder artifact iteration, launcher, availability
/// projection — depend on this "everything" semantic.
///
/// For tier-specific semantics use:
///   - [`supported_names`]   — claws with builtin plans + goldens (warm pool, E2E, deploy).
///   - [`installable_names`] — claws a user can install (Supported + Available).
#[must_use]
pub fn all_names() -> Vec<&'static str> {
    catalog().iter().map(|e| e.name).collect()
}

/// Returns names of claws in `Tier::Supported` only — the first-class set
/// with builtin plans, E2E coverage, and warm pool slots.
///
/// Use in: warm pool preheat, E2E test runner, deploy flow — anything that
/// requires full pipeline support to be meaningful.
#[must_use]
pub fn supported_names() -> Vec<&'static str> {
    catalog()
        .iter()
        .filter(|e| e.tier == Tier::Supported)
        .map(|e| e.name)
        .collect()
}

/// Returns names of claws that a user can install — the single source of
/// truth, delegating to [`ManifestEntry::installability`].
#[must_use]
pub fn installable_names() -> Vec<&'static str> {
    catalog()
        .iter()
        .filter(|e| matches!(e.installability(), ClawInstallability::Installable))
        .map(|e| e.name)
        .collect()
}

/// Returns true if the name appears in the manifest.
#[must_use]
pub fn is_known(name: &str) -> bool {
    catalog().iter().any(|e| e.name == name)
}

/// Returns true if the claw is in the manifest AND marked as buildable.
#[must_use]
pub fn is_buildable(name: &str) -> bool {
    catalog().iter().any(|e| e.name == name && e.buildable)
}

/// Look up a claw's installability by name. Returns `None` for entries that
/// are not in the manifest (so callers can distinguish "unknown claw" from
/// "known but unavailable").
#[must_use]
pub fn installability_of(name: &str) -> Option<ClawInstallability> {
    catalog()
        .iter()
        .find(|e| e.name == name)
        .map(ManifestEntry::installability)
}

/// Returns true if the claw uses pre-built artifact distribution.
#[must_use]
pub fn is_prebuilt(name: &str) -> bool {
    catalog()
        .iter()
        .any(|e| e.name == name && e.distribution == "prebuilt")
}

/// Returns true if the claw is in `Tier::Supported`.
#[must_use]
pub fn is_supported(name: &str) -> bool {
    catalog()
        .iter()
        .any(|e| e.name == name && e.tier == Tier::Supported)
}

/// Looks up a manifest entry by name.
#[must_use]
pub fn get(name: &str) -> Option<&'static ManifestEntry> {
    catalog().iter().find(|e| e.name == name)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_loads_all_entries() {
        let c = catalog();
        assert!(c.len() >= 6, "expected at least 6 claws, got {}", c.len());
    }

    #[test]
    fn manifest_all_names_sorted() {
        let names = all_names();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(
            names, sorted,
            "catalog entries must be alphabetically sorted"
        );
    }

    #[test]
    fn manifest_is_known_works() {
        assert!(is_known("picoclaw"));
        assert!(is_known("ironclaw"));
        assert!(!is_known("fakeclaw"));
        assert!(!is_known(""));
    }

    #[test]
    fn manifest_is_buildable_works() {
        assert!(is_buildable("picoclaw"));
        assert!(!is_buildable("fakeclaw"));
    }

    #[test]
    fn manifest_get_returns_entry() {
        let entry = get("picoclaw").expect("picoclaw should exist");
        assert_eq!(entry.name, "picoclaw");
        assert!(!entry.description.is_empty());
        assert_eq!(entry.language, "go");
        assert!(entry.buildable);
        assert!(!entry.version.is_empty());
        assert!(entry.binary_size_mb > 0);
        assert!(entry.min_ram_mb > 0);
        assert!(!entry.license.is_empty());
    }

    #[test]
    fn manifest_get_returns_none_for_unknown() {
        assert!(get("nonexistent").is_none());
    }

    #[test]
    fn installability_of_buildable_claw_is_installable() {
        assert_eq!(
            installability_of("picoclaw"),
            Some(ClawInstallability::Installable),
        );
    }

    #[test]
    fn installability_of_unknown_claw_is_none() {
        assert!(installability_of("fakeclaw").is_none());
    }

    #[test]
    fn manifest_all_supported_claws_are_prebuilt() {
        for entry in catalog().iter().filter(|e| e.tier == Tier::Supported) {
            assert!(
                is_prebuilt(entry.name),
                "{} is Supported so it should be prebuilt after the runtime migration",
                entry.name
            );
        }
    }

    #[test]
    fn manifest_hermes_agent_is_prebuilt() {
        assert!(is_prebuilt("hermes-agent"));
        assert_eq!(
            installability_of("hermes-agent"),
            Some(ClawInstallability::Installable),
        );
    }

    #[test]
    fn manifest_distribution_field_exists() {
        let entry = get("picoclaw").expect("picoclaw should exist");
        // distribution is always an explicit value in the manifest.
        assert!(
            entry.distribution == "local" || entry.distribution == "prebuilt",
            "unexpected distribution value: {}",
            entry.distribution
        );
    }

    #[test]
    fn all_prebuilt_claws_are_consistent() {
        for entry in catalog() {
            if entry.distribution == "prebuilt" {
                assert!(
                    is_prebuilt(entry.name),
                    "{} has distribution=prebuilt but is_prebuilt() returns false",
                    entry.name
                );
                assert_eq!(
                    entry.installability(),
                    ClawInstallability::Installable,
                    "{} has distribution=prebuilt but is not Installable",
                    entry.name
                );
            } else {
                assert!(
                    !is_prebuilt(entry.name),
                    "{} has distribution={} but is_prebuilt() returns true",
                    entry.name,
                    entry.distribution
                );
            }
        }
    }

    #[test]
    fn all_distribution_values_are_valid() {
        // `distribution` is a Supported-tier concept (prebuilt artifact vs
        // locally built). Detected/catalog entries don't have a distribution
        // value assigned yet — they'll get one when they're promoted.
        for entry in catalog() {
            if entry.tier != Tier::Supported {
                continue;
            }
            assert!(
                entry.distribution == "local" || entry.distribution == "prebuilt",
                "{} has unexpected distribution value: '{}'",
                entry.name,
                entry.distribution
            );
        }
    }

    #[test]
    fn manual_install_scripts_do_not_default_daemons_to_all_interfaces() {
        let offenders: Vec<_> = catalog()
            .iter()
            .filter_map(|entry| {
                let script = entry.install?.manual_script;
                if script.contains("HOST:-0.0.0.0")
                    || script.contains("HOST=\"${HOST:-0.0.0.0}\"")
                    || script.contains("HOST='${HOST:-0.0.0.0}'")
                {
                    Some(entry.name)
                } else {
                    None
                }
            })
            .collect();

        assert!(
            offenders.is_empty(),
            "manual install scripts must not default daemon binds to every \
             interface; use loopback by default and require explicit exposure: \
             {offenders:?}"
        );
    }

    #[test]
    fn root_version_matches_workspace_crate_version() {
        let root_version_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../VERSION");
        let root_version = std::fs::read_to_string(&root_version_path)
            .unwrap_or_else(|err| panic!("failed to read {root_version_path:?}: {err}"));

        assert_eq!(
            root_version.trim(),
            env!("CARGO_PKG_VERSION"),
            "repo root VERSION must stay aligned with the workspace crates \
             because release tooling and humans use it as metadata"
        );
    }

    // ─── P-46: tier model tests ─────────────────────────────────────────

    #[test]
    fn tier_can_user_install_gates_correctly() {
        assert!(!Tier::Catalog.can_user_install());
        assert!(!Tier::Detected.can_user_install());
        assert!(Tier::Available.can_user_install());
        assert!(Tier::Supported.can_user_install());
    }

    #[test]
    fn tier_serde_roundtrip_snake_case() {
        let cases = [
            (Tier::Catalog, "\"catalog\""),
            (Tier::Detected, "\"detected\""),
            (Tier::Available, "\"available\""),
            (Tier::Supported, "\"supported\""),
        ];
        for (tier, expected_json) in cases {
            let json = serde_json::to_string(&tier).unwrap();
            assert_eq!(json, expected_json);
            let parsed: Tier = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, tier);
        }
    }

    #[test]
    fn picoclaw_run_cmd_declares_daemon_subcommand() {
        // Regression: running `nohup picoclaw &` (bare) just prints help and
        // exits, so `imagebuilder build --verify-only` fails its 60s soak.
        // The build.rs codegen must surface the manifest's `run_cmd` field on
        // ManifestEntry so verify knows to launch the daemon subcommand.
        let entry = get("picoclaw").expect("picoclaw should exist");
        assert_eq!(
            entry.run_cmd, "picoclaw gateway",
            "picoclaw.run_cmd should carry the daemon subcommand, got {:?}",
            entry.run_cmd,
        );
    }

    #[test]
    fn noclaw_run_cmd_empty_documents_install_only_verify() {
        // Corollary: noclaw is a meta-claw with no single daemon — the empty
        // run_cmd tells verify to skip the 60s soak.
        let entry = get("noclaw").expect("noclaw should exist");
        assert_eq!(entry.run_cmd, "");
    }

    #[test]
    fn all_builtin_claws_are_supported_tier() {
        // The 8 builtin claws (from the pre-P-46 manifest) all carry builtin
        // plans → Tier::Supported. P-46 adds detected/catalog entries that
        // intentionally sit at lower tiers, so we pin this check to the known
        // builtin set by name rather than iterating the whole catalog.
        const BUILTINS: &[&str] = &[
            "picoclaw",
            "zeroclaw",
            "nanobot",
            "openclaw",
            "noclaw",
            "nullclaw",
            "hermes-agent",
            "ironclaw",
        ];
        for name in BUILTINS {
            let entry = get(name).unwrap_or_else(|| panic!("{name} missing from manifest"));
            assert_eq!(
                entry.tier,
                Tier::Supported,
                "{name} should be Tier::Supported",
            );
        }
    }

    #[test]
    fn supported_claws_have_builtin_plan_source() {
        for entry in catalog().iter().filter(|e| e.tier == Tier::Supported) {
            assert_eq!(
                entry.install_plan_source, "builtin",
                "{} is Supported so install_plan_source must be \"builtin\"",
                entry.name
            );
            assert!(
                entry.install.is_none(),
                "{} is Supported so install: block must be absent",
                entry.name
            );
        }
    }

    #[test]
    fn supported_names_matches_tier_filter() {
        let supported = supported_names();
        let via_filter: Vec<_> = catalog()
            .iter()
            .filter(|e| e.tier == Tier::Supported)
            .map(|e| e.name)
            .collect();
        assert_eq!(supported, via_filter);
    }

    #[test]
    fn installable_names_delegates_to_installability_api() {
        let installable = installable_names();
        let via_method: Vec<_> = catalog()
            .iter()
            .filter(|e| matches!(e.installability(), ClawInstallability::Installable))
            .map(|e| e.name)
            .collect();
        assert_eq!(installable, via_method);
    }

    #[test]
    fn is_supported_works() {
        assert!(is_supported("picoclaw"));
        assert!(is_supported("zeroclaw"));
        assert!(!is_supported("fakeclaw"));
    }

    // ─── Installability single-source-of-truth tests ──────────────────────

    #[test]
    fn installability_categorises_each_tier_correctly() {
        for entry in catalog() {
            let result = entry.installability();
            match entry.tier {
                Tier::Supported | Tier::Available => {
                    assert_eq!(
                        result,
                        ClawInstallability::Installable,
                        "{} has tier {:?} but installability() returned {result:?} \
                         — Supported/Available with a real install path must be Installable",
                        entry.name,
                        entry.tier,
                    );
                }
                Tier::Catalog => {
                    let ClawInstallability::Unavailable { code, .. } = result else {
                        panic!(
                            "{} has tier: catalog but installability() returned \
                             Installable — expected Unavailable {{ code: CatalogOnly }}",
                            entry.name
                        );
                    };
                    assert_eq!(code, UnavailableReasonCode::CatalogOnly);
                }
                Tier::Detected => {
                    let ClawInstallability::Unavailable { code, .. } = result else {
                        panic!(
                            "{} has tier: detected but installability() returned \
                             Installable — expected Unavailable {{ code: DetectedUnverified }}",
                            entry.name
                        );
                    };
                    assert_eq!(code, UnavailableReasonCode::DetectedUnverified);
                }
            }
        }
    }

    #[test]
    fn installability_no_install_plan_is_absent_in_current_manifest() {
        // Invariant: a `Supported` or `Available` entry must declare an
        // install path (buildable, prebuilt, or template install: block).
        // Any `NoInstallPlan` observation here is a manifest bug, not a
        // user-facing condition — fix the manifest entry rather than the
        // test. See the comment on UnavailableReasonCode::NoInstallPlan.
        let offenders: Vec<&str> = catalog()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.installability(),
                    ClawInstallability::Unavailable {
                        code: UnavailableReasonCode::NoInstallPlan,
                        ..
                    }
                )
            })
            .map(|entry| entry.name)
            .collect();
        assert!(
            offenders.is_empty(),
            "manifest invariant violated — these claws have an installable \
             tier but no install path (buildable=false, distribution!=prebuilt, \
             install: absent): {offenders:?}"
        );
    }

    #[test]
    fn installability_claude_claw_is_catalog_only_with_human_message() {
        let entry = get("claude-claw").expect("claude-claw must exist in manifest");
        match entry.installability() {
            ClawInstallability::Unavailable {
                code: UnavailableReasonCode::CatalogOnly,
                message,
            } => {
                assert!(
                    message.contains("Claude Code plugin"),
                    "expected skip_install_reason text, got: {message}"
                );
            }
            other => panic!("expected CatalogOnly Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn installability_catalog_entry_without_skip_reason_uses_default_message() {
        // Synthesise an entry inline rather than depending on an absent
        // skip_install_reason in the live manifest (every catalog entry
        // happens to set one today).
        let entry = ManifestEntry {
            name: "ghostclaw",
            description: "",
            language: "",
            buildable: false,
            version: "",
            binary_size_mb: 0,
            min_ram_mb: 0,
            license: "",
            distribution: "",
            tier: Tier::Catalog,
            stars: 0,
            source: "",
            last_updated: "",
            reviewed_upstream_commit: "",
            reviewed_at: "",
            reviewed_by: "",
            latest_upstream_commit: "",
            latest_checked_at: "",
            install_template: "",
            install_plan_source: "",
            install: None,
            run_cmd: "",
            skip_install_reason: "",
        };
        match entry.installability() {
            ClawInstallability::Unavailable {
                code: UnavailableReasonCode::CatalogOnly,
                message,
            } => {
                assert!(
                    message.contains("discovery only"),
                    "expected default catalog message, got: {message}"
                );
            }
            other => panic!("expected CatalogOnly Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn unavailable_reason_code_serialises_snake_case() {
        let cases = [
            (UnavailableReasonCode::CatalogOnly, "\"catalog_only\""),
            (
                UnavailableReasonCode::DetectedUnverified,
                "\"detected_unverified\"",
            ),
            (UnavailableReasonCode::NoInstallPlan, "\"no_install_plan\""),
        ];
        for (code, expected) in cases {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, expected);
            let back: UnavailableReasonCode = serde_json::from_str(expected).unwrap();
            assert_eq!(back, code);
        }
    }
}
