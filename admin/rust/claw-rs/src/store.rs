//! `ClawStore` — dynamic host-state overlay that tracks which claws are installed.
//!
//! The manifest (`core_rs::manifest`) defines ALL claws `theyOS` knows about.
//! The `ClawStore` tracks which of those claws are actually installed on THIS host
//! (golden image + snapshot built and ready).
//!
//! State is persisted as a JSON file at `$THEYOS_DIR/.run/installed_claws.json`.
//! All mutations use atomic write-rename to prevent corruption.

use core_rs::manifest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::verify_results;

// ─── Types ───────────────────────────────────────────────────────────────────

/// Install status for a single claw on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClawStatus {
    NotInstalled,
    Installing,
    Ready,
    Uninstalling,
    Failed,
}

impl std::fmt::Display for ClawStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInstalled => write!(f, "not_installed"),
            Self::Installing => write!(f, "installing"),
            Self::Ready => write!(f, "ready"),
            Self::Uninstalling => write!(f, "uninstalling"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Persisted state for a single installed claw.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledState {
    pub status: ClawStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Response shape for the `/api/v1/claws` endpoint (catalog + status merged).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ClawCatalogResponse {
    pub name: String,
    pub description: String,
    pub language: String,
    pub buildable: bool,
    pub version: String,
    pub binary_size_mb: u32,
    pub min_ram_mb: u32,
    pub license: String,
    pub distribution: String,
    pub status: ClawStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Verify-status recorded by `soyeht claws-verify` (Phase E).
    /// Serialized as the lowercase variant name; absent when no run has been
    /// recorded for this claw.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_status: Option<String>,
    /// Last verify error when `verify_status == "failed"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_error: Option<String>,

    // ─── P-46 Fase F — catalog fields from ManifestEntry ────────────────────
    /// Install pipeline tier (`supported` | `available` | `detected` | `catalog`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tier: String,
    /// GitHub stars (0 means unknown / not applicable).
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub stars: u32,
    /// Upstream source URL (empty if not applicable — e.g. `noclaw`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    /// GitHub `pushed_at` of the upstream (empty until first `claws-scan`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_updated: String,
    /// Baseline SHA validated at last detect/discover (immutable by scan).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reviewed_upstream_commit: String,
    /// Most recent upstream SHA observed by `claws-scan`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub latest_upstream_commit: String,
    /// `"builtin"` | `"template:<name>"` | `"llm"` | `"manual"`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub install_plan_source: String,
}

// `skip_serializing_if` requires an `&T` signature, so we can't take this by
// value even though clippy would prefer it for a `Copy` type.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

// ─── Store error ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("lock poisoned")]
    LockPoisoned,
}

// ─── ClawStore ───────────────────────────────────────────────────────────────

/// Dynamic per-host state for claw installation status.
///
/// Thread-safe via internal `RwLock`. All mutations persist to disk atomically.
pub struct ClawStore {
    state: RwLock<HashMap<String, InstalledState>>,
    state_file: PathBuf,
}

impl ClawStore {
    /// Load or create the state file.
    ///
    /// # Errors
    ///
    /// Returns an error if the state file exists but cannot be parsed.
    pub fn new(state_file: &Path) -> Result<Self, StoreError> {
        let map = if state_file.is_file() {
            let content = std::fs::read_to_string(state_file)?;
            serde_json::from_str(&content)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            state: RwLock::new(map),
            state_file: state_file.to_path_buf(),
        })
    }

    /// Scan existing golden/snapshot assets and auto-mark claws as Ready.
    ///
    /// A claw is marked Ready if ANY of:
    /// - Golden rootfs exists (`goldens/<name>/current/golden.meta.json`)
    ///   — snapshot is optional (VM boots via cold path without it)
    /// - Legacy golden image exists (`ubuntu-24.04-<name>.ext4`)
    ///
    /// Only re-evaluates claws that are `NotInstalled` or `Failed`.
    pub fn seed_from_assets(&self, assets_dir: &Path) {
        let mut state = match self.state.write() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("[claw-store] seed: lock poisoned: {e}");
                return;
            }
        };

        let mut changed = false;
        for entry in manifest::catalog() {
            let name = entry.name;

            // P-46 Fase F: Only Tier::Supported claws have pre-built golden images.
            // Detected/Available/Catalog claws produce their golden via build-from-plan
            // in the install worker — not from assets on disk at boot time.
            if entry.tier != manifest::Tier::Supported {
                continue;
            }

            // Skip claws that are already Ready, Installing, or Uninstalling.
            // Re-evaluate Failed and NotInstalled — assets may exist on disk.
            if let Some(existing) = state.get(name) {
                if matches!(
                    existing.status,
                    ClawStatus::Ready | ClawStatus::Installing | ClawStatus::Uninstalling
                ) {
                    continue;
                }
            }

            // Golden rootfs (sufficient for Ready — snapshot is optional optimization)
            let golden_meta = assets_dir
                .join("goldens")
                .join(name)
                .join("current")
                .join("golden.meta.json");
            let golden_rootfs = assets_dir
                .join("goldens")
                .join(name)
                .join("current")
                .join("rootfs.ext4");

            // Legacy-format golden image (ubuntu-24.04-<name>.ext4)
            let legacy_golden = assets_dir.join(format!("ubuntu-24.04-{name}.ext4"));

            let has_golden = golden_meta.is_file() && golden_rootfs.is_file();
            let has_legacy = legacy_golden.is_file();

            if has_golden || has_legacy {
                let source = if has_golden { "golden" } else { "legacy" };
                tracing::info!(
                    "[claw-store] seed: auto-marking {name} as ready ({source} assets found)"
                );
                state.insert(
                    name.to_string(),
                    InstalledState {
                        status: ClawStatus::Ready,
                        installed_at: Some(core_rs::time::now_iso_secs()),
                        job_id: None,
                        error: None,
                    },
                );
                changed = true;
            }
        }

        if changed {
            if let Err(e) = persist(&self.state_file, &state) {
                tracing::error!("[claw-store] seed: failed to persist: {e}");
            }
        }
    }

    /// Seed claw status from the macOS shared base image.
    ///
    /// On macOS, `init-macos-guest` provisions ALL claw binaries into a single
    /// base image. If the base image is fully initialized (phase == "complete"),
    /// all buildable manifest claws that are currently `NotInstalled` or `Failed`
    /// are automatically marked as `Ready`.
    #[cfg(target_os = "macos")]
    pub fn seed_from_macos_base(&self) {
        let base_dir = {
            let assets = std::env::var("THEYOS_VM_ASSETS_DIR").unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
                format!("{home}/Library/Application Support/theyos/vms")
            });
            std::path::PathBuf::from(assets).join("macos-base")
        };

        let state_path = base_dir.join("init-state.json");
        if !state_path.exists() {
            tracing::info!("[claw-store] seed: macOS base image not initialized yet");
            return;
        }

        let content = match std::fs::read_to_string(&state_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("[claw-store] seed: read init-state.json: {e}");
                return;
            }
        };

        let json: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("[claw-store] seed: parse init-state.json: {e}");
                return;
            }
        };

        if json.get("phase").and_then(|v| v.as_str()) != Some("complete") {
            tracing::info!("[claw-store] seed: macOS base image init not complete, skipping");
            return;
        }

        let mut state = match self.state.write() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("[claw-store] seed: lock poisoned: {e}");
                return;
            }
        };

        let mut changed = false;
        for entry in manifest::catalog() {
            let name = entry.name;

            // Only tier: supported claws are baked into the macOS base image by
            // `init-macos-guest`. Detected/available/catalog claws have no
            // binary inside the base rootfs — marking them Ready would be a
            // lie that breaks install-from-plan later.
            if entry.tier != manifest::Tier::Supported {
                continue;
            }

            // Skip claws that are already Ready, Installing, or Uninstalling.
            if let Some(existing) = state.get(name) {
                if matches!(
                    existing.status,
                    ClawStatus::Ready | ClawStatus::Installing | ClawStatus::Uninstalling
                ) {
                    continue;
                }
            }

            tracing::info!(
                "[claw-store] seed: auto-marking {name} as ready (macOS base image complete)"
            );
            state.insert(
                name.to_string(),
                InstalledState {
                    status: ClawStatus::Ready,
                    installed_at: Some(core_rs::time::now_iso_secs()),
                    job_id: None,
                    error: None,
                },
            );
            changed = true;
        }

        if changed {
            if let Err(e) = persist(&self.state_file, &state) {
                tracing::error!("[claw-store] seed: failed to persist: {e}");
            }
        }
    }

    /// Reset any `Installing` or `Uninstalling` states to `Failed`.
    ///
    /// Called at startup: if the server restarted during an install, the child
    /// process is gone and the claw is in a broken state.
    pub fn reset_stale_installing(&self) {
        let mut state = match self.state.write() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("[claw-store] reset_stale: lock poisoned: {e}");
                return;
            }
        };

        let mut changed = false;
        for (name, entry) in state.iter_mut() {
            if entry.status == ClawStatus::Installing || entry.status == ClawStatus::Uninstalling {
                tracing::warn!(
                    "[claw-store] resetting stale {} status for {name}",
                    entry.status
                );
                entry.status = ClawStatus::Failed;
                entry.error = Some("server restarted during operation".to_string());
                changed = true;
            }
        }

        if changed {
            if let Err(e) = persist(&self.state_file, &state) {
                tracing::error!("[claw-store] reset_stale: failed to persist: {e}");
            }
        }
    }

    // ─── Queries ─────────────────────────────────────────────────────────

    /// Merge manifest catalog with installed state for the API response.
    ///
    /// Equivalent to [`ClawStore::catalog_with_status_merged`] with a `None`
    /// verify-results path — verify fields are always omitted.
    #[must_use]
    pub fn catalog_with_status(&self) -> Vec<ClawCatalogResponse> {
        self.catalog_with_status_merged(None)
    }

    /// Same as [`ClawStore::catalog_with_status`] but additionally merges
    /// `verify-results.json` when `verify_results_path` is `Some`.
    ///
    /// If the file is missing or malformed, verify-related fields are
    /// silently left as `None` — the caller gets a degraded but functional
    /// response.
    #[must_use]
    pub fn catalog_with_status_merged(
        &self,
        verify_results_path: Option<&Path>,
    ) -> Vec<ClawCatalogResponse> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let verify_map = verify_results_path
            .and_then(|p| match verify_results::load(p) {
                Ok(m) => Some(m),
                Err(e) => {
                    tracing::warn!("[claw-store] catalog: verify-results.json load failed: {e}");
                    None
                }
            })
            .unwrap_or_default();

        manifest::catalog()
            .iter()
            .map(|entry| {
                let installed = state.get(entry.name);
                let verify = verify_map.get(entry.name);
                let tier_str = match entry.tier {
                    manifest::Tier::Catalog => "catalog",
                    manifest::Tier::Detected => "detected",
                    manifest::Tier::Available => "available",
                    manifest::Tier::Supported => "supported",
                };
                ClawCatalogResponse {
                    name: entry.name.to_string(),
                    description: entry.description.to_string(),
                    language: entry.language.to_string(),
                    buildable: entry.buildable,
                    version: entry.version.to_string(),
                    binary_size_mb: entry.binary_size_mb,
                    min_ram_mb: entry.min_ram_mb,
                    license: entry.license.to_string(),
                    distribution: entry.distribution.to_string(),
                    status: installed.map_or(ClawStatus::NotInstalled, |s| s.status),
                    installed_at: installed.and_then(|s| s.installed_at.clone()),
                    job_id: installed.and_then(|s| s.job_id.clone()),
                    error: installed.and_then(|s| s.error.clone()),
                    verify_status: verify.map(|v| v.verify_status.to_string()),
                    verify_error: verify.and_then(|v| v.verify_error.clone()),
                    tier: tier_str.to_string(),
                    stars: entry.stars,
                    source: entry.source.to_string(),
                    last_updated: entry.last_updated.to_string(),
                    reviewed_upstream_commit: entry.reviewed_upstream_commit.to_string(),
                    latest_upstream_commit: entry.latest_upstream_commit.to_string(),
                    install_plan_source: entry.install_plan_source.to_string(),
                }
            })
            .collect()
    }

    /// Returns names of claws where status == Ready.
    #[must_use]
    pub fn installed_and_ready(&self) -> Vec<String> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .iter()
            .filter(|(_, v)| v.status == ClawStatus::Ready)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Returns true if the claw is installed and ready.
    #[must_use]
    pub fn is_ready(&self, name: &str) -> bool {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .get(name)
            .is_some_and(|s| s.status == ClawStatus::Ready)
    }

    /// Returns the current status for a claw.
    #[must_use]
    pub fn get_status(&self, name: &str) -> ClawStatus {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .get(name)
            .map_or(ClawStatus::NotInstalled, |s| s.status)
    }

    /// Returns the installed state for a claw (if any).
    #[must_use]
    pub fn get_state(&self, name: &str) -> Option<InstalledState> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.get(name).cloned()
    }

    // ─── Mutations ───────────────────────────────────────────────────────

    /// Mark a claw as installing (background build in progress).
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or persistence fails.
    pub fn mark_installing(&self, name: &str, job_id: &str) -> Result<(), StoreError> {
        self.set_state(
            name,
            InstalledState {
                status: ClawStatus::Installing,
                installed_at: None,
                job_id: Some(job_id.to_string()),
                error: None,
            },
        )
    }

    /// Mark a claw as ready (golden + snapshot built successfully).
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or persistence fails.
    pub fn mark_ready(&self, name: &str) -> Result<(), StoreError> {
        self.set_state(
            name,
            InstalledState {
                status: ClawStatus::Ready,
                installed_at: Some(core_rs::time::now_iso_secs()),
                job_id: None,
                error: None,
            },
        )
    }

    /// Mark a claw as failed (build or uninstall error).
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or persistence fails.
    pub fn mark_failed(&self, name: &str, error: &str) -> Result<(), StoreError> {
        self.set_state(
            name,
            InstalledState {
                status: ClawStatus::Failed,
                installed_at: None,
                job_id: None,
                error: Some(error.to_string()),
            },
        )
    }

    /// Mark a claw as uninstalling (artifact deletion in progress).
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or persistence fails.
    pub fn mark_uninstalling(&self, name: &str) -> Result<(), StoreError> {
        self.set_state(
            name,
            InstalledState {
                status: ClawStatus::Uninstalling,
                installed_at: None,
                job_id: None,
                error: None,
            },
        )
    }

    /// Mark a claw as not installed (remove state entry).
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or persistence fails.
    pub fn mark_not_installed(&self, name: &str) -> Result<(), StoreError> {
        let mut state = self.state.write().map_err(|_| StoreError::LockPoisoned)?;
        state.remove(name);
        persist(&self.state_file, &state)
    }

    // ─── Internal ────────────────────────────────────────────────────────

    fn set_state(&self, name: &str, entry: InstalledState) -> Result<(), StoreError> {
        let mut state = self.state.write().map_err(|_| StoreError::LockPoisoned)?;
        state.insert(name.to_string(), entry);
        persist(&self.state_file, &state)
    }
}

/// Atomic write-rename to prevent corruption.
///
/// Ensures the parent directory exists before writing — on a fresh
/// install the engine's state directory (e.g. `${THEYOS_DIR}/.run/`)
/// has not been created by anything else: `ClawStore::new()` tolerates
/// the state file being absent (returns an empty map), so the first
/// write through this function is the first time anything inside that
/// directory is touched. Without `create_dir_all`, `std::fs::write`
/// returns `ENOENT` and the user sees
/// `"failed to mark installing: IO error: No such file or directory"`
/// on the very first Claw install attempt.
///
/// `create_dir_all` is idempotent — a no-op when the directory already
/// exists from a previous successful run.
fn persist(path: &Path, state: &HashMap<String, InstalledState>) -> Result<(), StoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(state)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, format!("{json}\n"))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, ClawStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_file = dir.path().join("installed_claws.json");
        let store = ClawStore::new(&state_file).expect("ClawStore::new");
        (dir, store)
    }

    #[test]
    fn clawstore_new_creates_state_on_first_mutation() {
        let (_dir, store) = temp_store();
        assert!(!store.state_file.exists());
        store.mark_ready("picoclaw").expect("mark_ready");
        assert!(store.state_file.exists());
    }

    /// Regression test for the fresh-install crash: when the state
    /// file's *parent* directory does not exist yet, `persist()` must
    /// create it instead of returning ENOENT. Reproduces the user-facing
    /// "failed to mark installing: IO error: No such file or directory"
    /// that fired on the very first Claw install attempt against a
    /// brand-new theyos engine on macOS Sequoia.
    #[test]
    fn clawstore_persist_creates_missing_parent_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Path one level deeper than the tempdir — parent doesn't exist.
        let nested = dir.path().join(".run").join("installed_claws.json");
        assert!(!nested.parent().unwrap().exists());

        let store = ClawStore::new(&nested).expect("ClawStore::new tolerates missing path");
        store
            .mark_installing("picoclaw", "job_42")
            .expect("mark_installing must create the missing parent directory");

        assert!(nested.exists(), "state file written");
        assert!(nested.parent().unwrap().exists(), "parent dir created");

        // Round-trip: re-loading sees the persisted state.
        let store2 = ClawStore::new(&nested).expect("reload");
        assert_eq!(store2.get_status("picoclaw"), ClawStatus::Installing);
    }

    #[test]
    fn clawstore_mark_installing_persists() {
        let (dir, store) = temp_store();
        store
            .mark_installing("picoclaw", "job_123")
            .expect("mark_installing");

        // Re-load from disk
        let store2 = ClawStore::new(&dir.path().join("installed_claws.json")).expect("reload");
        assert_eq!(store2.get_status("picoclaw"), ClawStatus::Installing);
        let state = store2.get_state("picoclaw").expect("state exists");
        assert_eq!(state.job_id.as_deref(), Some("job_123"));
    }

    #[test]
    fn clawstore_mark_ready_sets_timestamp() {
        let (_dir, store) = temp_store();
        store.mark_ready("picoclaw").expect("mark_ready");
        let state = store.get_state("picoclaw").expect("state");
        assert_eq!(state.status, ClawStatus::Ready);
        assert!(state.installed_at.is_some());
        assert!(state.error.is_none());
    }

    #[test]
    fn clawstore_mark_failed_stores_error() {
        let (_dir, store) = temp_store();
        store
            .mark_failed("picoclaw", "golden build timed out")
            .expect("mark_failed");
        let state = store.get_state("picoclaw").expect("state");
        assert_eq!(state.status, ClawStatus::Failed);
        assert_eq!(state.error.as_deref(), Some("golden build timed out"));
    }

    #[test]
    fn clawstore_installed_and_ready_filters() {
        let (_dir, store) = temp_store();
        store.mark_ready("picoclaw").unwrap();
        store.mark_installing("zeroclaw", "job_1").unwrap();
        store.mark_failed("nanobot", "oops").unwrap();

        let ready = store.installed_and_ready();
        assert_eq!(ready, vec!["picoclaw"]);
    }

    #[test]
    fn clawstore_is_ready_true_for_ready() {
        let (_dir, store) = temp_store();
        store.mark_ready("picoclaw").unwrap();
        assert!(store.is_ready("picoclaw"));
    }

    #[test]
    fn clawstore_is_ready_false_for_installing() {
        let (_dir, store) = temp_store();
        store.mark_installing("picoclaw", "job_1").unwrap();
        assert!(!store.is_ready("picoclaw"));
    }

    #[test]
    fn clawstore_is_ready_false_for_unknown() {
        let (_dir, store) = temp_store();
        assert!(!store.is_ready("nonexistent"));
    }

    #[test]
    fn clawstore_mark_not_installed_removes_entry() {
        let (_dir, store) = temp_store();
        store.mark_ready("picoclaw").unwrap();
        assert!(store.is_ready("picoclaw"));

        store.mark_not_installed("picoclaw").unwrap();
        assert!(!store.is_ready("picoclaw"));
        assert_eq!(store.get_status("picoclaw"), ClawStatus::NotInstalled);
    }

    #[test]
    fn clawstore_seed_from_assets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let assets = dir.path().join("assets");

        // Create fake golden for picoclaw (no snapshot needed — golden-only is sufficient)
        let golden = assets.join("goldens/picoclaw/current");
        std::fs::create_dir_all(&golden).unwrap();
        std::fs::write(golden.join("golden.meta.json"), "{}").unwrap();
        std::fs::write(golden.join("rootfs.ext4"), b"fake").unwrap();

        let state_file = dir.path().join("state.json");
        let store = ClawStore::new(&state_file).unwrap();
        store.seed_from_assets(&assets);

        assert!(store.is_ready("picoclaw"));
        // zeroclaw has no assets → still not installed
        assert!(!store.is_ready("zeroclaw"));
    }

    #[test]
    fn clawstore_reset_stale_installing() {
        let (_dir, store) = temp_store();
        store.mark_installing("picoclaw", "job_1").unwrap();
        store.mark_ready("zeroclaw").unwrap();

        store.reset_stale_installing();

        assert_eq!(store.get_status("picoclaw"), ClawStatus::Failed);
        assert_eq!(store.get_status("zeroclaw"), ClawStatus::Ready); // unchanged
    }

    #[test]
    fn clawstore_catalog_with_status_merges() {
        let (_dir, store) = temp_store();
        store.mark_ready("picoclaw").unwrap();

        let catalog = store.catalog_with_status();
        assert!(!catalog.is_empty());

        let pico = catalog
            .iter()
            .find(|c| c.name == "picoclaw")
            .expect("picoclaw");
        assert_eq!(pico.status, ClawStatus::Ready);
        assert!(pico.installed_at.is_some());
        // Without a verify-results path, verify fields are never populated.
        assert!(pico.verify_status.is_none());

        let zero = catalog
            .iter()
            .find(|c| c.name == "zeroclaw")
            .expect("zeroclaw");
        assert_eq!(zero.status, ClawStatus::NotInstalled);
    }

    #[test]
    fn clawstore_catalog_with_status_merged_includes_verify_results() {
        let (dir, store) = temp_store();
        store.mark_ready("picoclaw").unwrap();

        let vr_path = dir.path().join("verify-results.json");
        let ok = verify_results::VerifyResult {
            verify_status: verify_results::VerifyStatus::Ok,
            verify_error: None,
            verify_log_path: None,
            verify_attempted_at: Some("2026-04-14T12:00:00Z".into()),
        };
        verify_results::record(&vr_path, "picoclaw", &ok).unwrap();
        let failed = verify_results::VerifyResult {
            verify_status: verify_results::VerifyStatus::Failed,
            verify_error: Some("boom".into()),
            verify_log_path: None,
            verify_attempted_at: Some("2026-04-14T12:00:00Z".into()),
        };
        verify_results::record(&vr_path, "zeroclaw", &failed).unwrap();

        let catalog = store.catalog_with_status_merged(Some(&vr_path));
        let pico = catalog.iter().find(|c| c.name == "picoclaw").unwrap();
        assert_eq!(pico.verify_status.as_deref(), Some("ok"));
        assert!(pico.verify_error.is_none());

        let zero = catalog.iter().find(|c| c.name == "zeroclaw").unwrap();
        assert_eq!(zero.verify_status.as_deref(), Some("failed"));
        assert_eq!(zero.verify_error.as_deref(), Some("boom"));
    }

    #[test]
    fn clawstore_catalog_with_status_merged_tolerates_missing_file() {
        let (_dir, store) = temp_store();
        store.mark_ready("picoclaw").unwrap();
        let missing = std::path::PathBuf::from("/nonexistent/verify-results.json");
        let catalog = store.catalog_with_status_merged(Some(&missing));
        let pico = catalog.iter().find(|c| c.name == "picoclaw").unwrap();
        assert!(pico.verify_status.is_none());
    }
}
