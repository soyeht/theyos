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
    #[must_use]
    pub const fn can_user_install(self) -> bool {
        matches!(self, Tier::Available | Tier::Supported)
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

/// Returns names of claws that a user can install (`Tier::Supported` or
/// `Tier::Available`). Complement to [`Tier::can_user_install`].
#[must_use]
pub fn installable_names() -> Vec<&'static str> {
    catalog()
        .iter()
        .filter(|e| e.tier.can_user_install())
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

/// Returns true if the claw can be installed by a user.
///
/// Three ways to qualify:
///   1. Tier is `Available` or `Supported` — both pass `Tier::can_user_install`
///      and have either a prebuilt artifact or a template-driven plan.
///   2. Legacy `buildable: true` flag — the claw has a builtin installer plan
///      in `vmrunner-rs/src/installer_plan.rs` (true for every supported claw).
///   3. Legacy `distribution: "prebuilt"` — a prebuilt rootfs is published
///      somewhere the artifact resolver can fetch it.
///
/// The `tier`-based clause is what unblocks P-46 template claws: once
/// `claws-verify` flips a detected claw to `tier: available`, install via the
/// template-driven build-from-plan path is enabled by this function alone —
/// no manual edit to `buildable`/`distribution` required.
#[must_use]
pub fn is_installable(name: &str) -> bool {
    catalog().iter().any(|e| {
        e.name == name && (e.tier.can_user_install() || e.buildable || e.distribution == "prebuilt")
    })
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
    fn manifest_is_installable_for_buildable_claw() {
        assert!(is_installable("picoclaw"));
    }

    #[test]
    fn manifest_is_installable_false_for_unknown() {
        assert!(!is_installable("fakeclaw"));
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
        assert!(is_installable("hermes-agent"));
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
                assert!(
                    is_installable(entry.name),
                    "{} has distribution=prebuilt but is_installable() returns false",
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
    fn installable_names_matches_can_user_install() {
        let installable = installable_names();
        let via_filter: Vec<_> = catalog()
            .iter()
            .filter(|e| e.tier.can_user_install())
            .map(|e| e.name)
            .collect();
        assert_eq!(installable, via_filter);
    }

    #[test]
    fn is_supported_works() {
        assert!(is_supported("picoclaw"));
        assert!(is_supported("zeroclaw"));
        assert!(!is_supported("fakeclaw"));
    }
}
