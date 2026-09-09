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

#[allow(clippy::unreadable_literal, dead_code)]
mod generated_manifest {
    include!(concat!(env!("OUT_DIR"), "/generated_manifest.rs"));
}

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
    pub git_ref: &'static str,
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
mod tests;
