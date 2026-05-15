//! claw-rs — Rust implementation of the theyOS claw type registry.
//!
//! Mirrors the Go `claw.Registry` exactly:
//! - Reads `CLAW_TYPES` env var (default "picoclaw")
//! - For each type reads: `{UPPER}_CODE_DIR`, `{UPPER}_DATA_DIR`,
//!   `{UPPER}_HOST_BASE_DIR`, `{UPPER}_IMAGE`
//! - Validates that `code_dir` exists
//! - `HasCleanup`: checks `{UPPER}_CLEANUP=1` or `true` env var

pub mod store;
pub mod verify_results;

use core_rs::env::env_or;
use core_rs::error::{AppError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

pub use store::{ClawCatalogResponse, ClawStatus, ClawStore, InstalledState};

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ClawError {
    #[error("unsupported claw type: {0}")]
    UnsupportedType(String),
    #[error("code directory not found: {0}")]
    CodeDirNotFound(String),
    #[error("env var not set: {0}")]
    EnvVarMissing(String),
}

impl AppError for ClawError {
    fn code(&self) -> ErrorCode {
        match self {
            ClawError::UnsupportedType(_) => ErrorCode::InvalidInput,
            _ => ErrorCode::Internal,
        }
    }
}

// ─── Types ───────────────────────────────────────────────────────────────────

/// Resolved configuration for a single claw type.
/// Mirrors the Go `claw.ClawType` struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClawType {
    pub name: String,
    pub code_dir: String,
    pub data_dir: String,
    pub host_base_dir: String,
    pub image: String,
}

/// Bootstrap source for the store. Mirrors Go's `store.Source`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub claw_type: String,
    pub base_dir: String,
    pub ports_file: String, // relative to base_dir, default "customers/ports.txt"
}

// ─── Registry ────────────────────────────────────────────────────────────────

/// Discovers and exposes claw types from the `CLAW_TYPES` environment variable.
/// Mirrors the Go `claw.Registry`.
pub struct Registry {
    types: Vec<ClawType>,
    by_name: HashMap<String, ClawType>,
}

impl Registry {
    /// Build a Registry from environment variables.
    ///
    /// Reads `CLAW_TYPES` (comma-separated, default "picoclaw") and for each
    /// type reads:
    /// - `{UPPER}_CODE_DIR`   (fallback: `{UPPER}_BASE_DIR`, then `/services/{name}`)
    /// - `{UPPER}_DATA_DIR`   (fallback: `{UPPER}_BASE_DIR`, then `/services/{name}`)
    /// - `{UPPER}_HOST_BASE_DIR` (fallback: `data_dir`)
    /// - `{UPPER}_IMAGE`      (fallback: `{name}:local`)
    ///
    /// Types whose code directory does not exist are skipped with a warning.
    pub fn from_env() -> Self {
        let raw = std::env::var("CLAW_TYPES").unwrap_or_else(|_| "picoclaw".to_string());
        let raw = raw.trim().to_string();
        let raw = if raw.is_empty() {
            "picoclaw".to_string()
        } else {
            raw
        };

        let mut types: Vec<ClawType> = Vec::new();
        let mut by_name: HashMap<String, ClawType> = HashMap::new();

        for part in raw.split(',') {
            let name = part.trim().to_lowercase();
            if name.is_empty() {
                continue;
            }
            let upper = name.replace('-', "_").to_uppercase();

            let code_dir = env_or(
                &format!("{upper}_CODE_DIR"),
                &env_or(&format!("{upper}_BASE_DIR"), &format!("/services/{name}")),
            );
            let data_dir = env_or(
                &format!("{upper}_DATA_DIR"),
                &env_or(&format!("{upper}_BASE_DIR"), &format!("/services/{name}")),
            );
            let host_base_dir = env_or(&format!("{upper}_HOST_BASE_DIR"), &data_dir);
            let image = env_or(&format!("{upper}_IMAGE"), &format!("{name}:local"));

            // Validate code directory exists (skip with warning if not).
            //
            // On macOS, claw code lives inside the VZ base image — the host
            // doesn't need a code_dir, so skip this check entirely.
            //
            // On Linux, only claws with `distribution: local` need a source
            // checkout on the host (they build from source). Claws with
            // `distribution: prebuilt` download a golden rootfs artifact and
            // never touch `claws/src/<name>`, so requiring the directory to
            // exist would incorrectly drop them from the registry when the
            // clone service hasn't prepared a stub (see
            // nix/module.nix theyos-clone-claws, which only handles a subset
            // of the manifest, and server-rs/main.rs create_dir_all, which
            // silently fails when claws/src is admin-owned). Historical
            // incident: hermes-agent on devs returned HTTP 400
            // "unsupported claw type" from POST /mobile/instances even
            // though the ClawStore had it as Ready.
            #[cfg(not(target_os = "macos"))]
            {
                let needs_code_dir = !core_rs::manifest::is_prebuilt(&name);
                if needs_code_dir {
                    let code_path = PathBuf::from(&code_dir);
                    if !code_path.is_dir() {
                        tracing::warn!(
                            "claw/registry: skipping {:?} — code directory not found at {}",
                            name,
                            code_dir
                        );
                        continue;
                    }
                }
            }

            let ct = ClawType {
                name: name.clone(),
                code_dir,
                data_dir,
                host_base_dir,
                image,
            };
            types.push(ct.clone());
            by_name.insert(name, ct);
        }

        types.sort_by(|a, b| a.name.cmp(&b.name));

        tracing::info!(
            "claw/registry: loaded {} types: {:?}",
            types.len(),
            types.iter().map(|t| &t.name).collect::<Vec<_>>()
        );

        Registry { types, by_name }
    }

    /// Create a Registry directly from a list of `ClawType` values (for testing).
    #[must_use]
    pub fn from_types(types: Vec<ClawType>) -> Self {
        let mut by_name = HashMap::new();
        for ct in &types {
            by_name.insert(ct.name.clone(), ct.clone());
        }
        let mut sorted = types;
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        Registry {
            types: sorted,
            by_name,
        }
    }

    // ─── Public API (mirrors Go Registry methods) ─────────────────────────

    /// Returns a sorted list of registered claw type names.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.types.iter().map(|ct| ct.name.clone()).collect()
    }

    /// Returns a `ClawType` by name (case-insensitive, whitespace-trimmed).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ClawType> {
        let key = name.trim().to_lowercase();
        self.by_name.get(&key)
    }

    /// Checks whether a claw type name is registered.
    #[must_use]
    pub fn is_valid(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Returns the data directory for the given claw type.
    /// Returns `None` if the type is not registered.
    #[must_use]
    pub fn data_base_dir(&self, name: &str) -> Option<String> {
        self.get(name).map(|ct| ct.data_dir.clone())
    }

    /// Returns the host base directory, using `host_base_dir` when `remote` is
    /// true, otherwise `data_dir`. Mirrors Go's `ResolveHostBaseDir(name, remote bool)`.
    #[must_use]
    pub fn resolve_host_base_dir(&self, name: &str, remote: bool) -> Option<String> {
        self.get(name).map(|ct| {
            if remote {
                ct.host_base_dir.clone()
            } else {
                ct.data_dir.clone()
            }
        })
    }

    /// Returns the container image name for the given claw type.
    #[must_use]
    pub fn image_name(&self, name: &str) -> String {
        self.get(name)
            .map_or_else(|| format!("{name}:local"), |ct| ct.image.clone())
    }

    /// Returns paths to all `customers/ports.txt` files.
    #[must_use]
    pub fn ports_paths(&self) -> Vec<String> {
        self.types
            .iter()
            .map(|ct| {
                PathBuf::from(&ct.data_dir)
                    .join("customers")
                    .join("ports.txt")
                    .to_string_lossy()
                    .to_string()
            })
            .collect()
    }

    /// Returns store Source entries for bootstrapping the store.
    /// Mirrors Go's `Sources() []store.Source`.
    #[must_use]
    pub fn sources(&self) -> Vec<Source> {
        self.types
            .iter()
            .map(|ct| Source {
                claw_type: ct.name.clone(),
                base_dir: ct.data_dir.clone(),
                ports_file: "customers/ports.txt".to_string(),
            })
            .collect()
    }

    /// Checks whether a claw type has cleanup enabled via the
    /// `{UPPER}_CLEANUP=1` (or `true` / `yes`) env var.
    #[must_use]
    pub fn has_cleanup(&self, name: &str) -> bool {
        let Some(ct) = self.get(name) else {
            return false;
        };
        let upper = ct.name.replace('-', "_").to_uppercase();
        core_rs::env::env_bool(&format!("{upper}_CLEANUP"), false)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core_rs::env::{remove_test_env, set_test_env};
    use std::sync::Mutex;

    // Serialize env-var-based tests to avoid cross-test pollution.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap();
        for (k, v) in vars {
            set_test_env(k, v);
        }
        f();
        for (k, _) in vars {
            remove_test_env(k);
        }
    }

    #[test]
    fn test_registry_from_env_basic() {
        let tmpdir = tempfile::tempdir().expect("create tempdir");
        let code_dir = tmpdir.path().join("code");
        std::fs::create_dir_all(&code_dir).unwrap();

        with_env(
            &[
                ("CLAW_TYPES", "testclaw"),
                ("TESTCLAW_CODE_DIR", code_dir.to_str().unwrap()),
                ("TESTCLAW_DATA_DIR", tmpdir.path().to_str().unwrap()),
                ("TESTCLAW_HOST_BASE_DIR", tmpdir.path().to_str().unwrap()),
                ("TESTCLAW_IMAGE", "testclaw-image"),
            ],
            || {
                let reg = Registry::from_env();
                assert!(reg.is_valid("testclaw"));
                assert_eq!(reg.names(), vec!["testclaw"]);
                let ct = reg.get("testclaw").unwrap();
                assert_eq!(ct.image, "testclaw-image");
            },
        );
    }

    #[test]
    fn test_invalid_claw_type() {
        let reg = Registry::from_types(vec![]);
        assert!(!reg.is_valid("nonexistent"));
        assert!(reg.get("nonexistent").is_none());
    }

    #[test]
    fn test_sources_mirrors_go() {
        let ct = ClawType {
            name: "picoclaw".to_string(),
            code_dir: "/tmp/code".to_string(),
            data_dir: "/tmp/data".to_string(),
            host_base_dir: "/tmp/host".to_string(),
            image: "picoclaw:local".to_string(),
        };
        let reg = Registry::from_types(vec![ct]);
        let sources = reg.sources();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].claw_type, "picoclaw");
        assert_eq!(sources[0].base_dir, "/tmp/data");
        assert_eq!(sources[0].ports_file, "customers/ports.txt");
    }

    #[test]
    fn test_ports_paths() {
        let ct = ClawType {
            name: "picoclaw".to_string(),
            code_dir: "/tmp".to_string(),
            data_dir: "/tmp/data".to_string(),
            host_base_dir: "/tmp".to_string(),
            image: "picoclaw:local".to_string(),
        };
        let reg = Registry::from_types(vec![ct]);
        let paths = reg.ports_paths();
        assert_eq!(paths, vec!["/tmp/data/customers/ports.txt"]);
    }

    #[test]
    fn test_data_base_dir() {
        let ct = ClawType {
            name: "picoclaw".to_string(),
            code_dir: "/tmp".to_string(),
            data_dir: "/tmp/data".to_string(),
            host_base_dir: "/tmp".to_string(),
            image: "picoclaw:local".to_string(),
        };
        let reg = Registry::from_types(vec![ct]);
        assert_eq!(reg.data_base_dir("picoclaw"), Some("/tmp/data".to_string()));
        assert_eq!(reg.data_base_dir("missing"), None);
    }

    #[test]
    fn test_resolve_host_base_dir() {
        let ct = ClawType {
            name: "picoclaw".to_string(),
            code_dir: "/tmp".to_string(),
            data_dir: "/tmp/data".to_string(),
            host_base_dir: "/host/base".to_string(),
            image: "picoclaw:local".to_string(),
        };
        let reg = Registry::from_types(vec![ct]);
        // remote=true → host_base_dir
        assert_eq!(
            reg.resolve_host_base_dir("picoclaw", true),
            Some("/host/base".to_string())
        );
        // remote=false → data_dir
        assert_eq!(
            reg.resolve_host_base_dir("picoclaw", false),
            Some("/tmp/data".to_string())
        );
        // missing type
        assert_eq!(reg.resolve_host_base_dir("nope", true), None);
    }

    #[test]
    fn test_image_name_fallback() {
        let reg = Registry::from_types(vec![]);
        assert_eq!(reg.image_name("missing"), "missing:local");
    }

    #[test]
    fn test_names_sorted() {
        let reg = Registry::from_types(vec![
            ClawType {
                name: "zeroclaw".to_string(),
                code_dir: "/tmp".to_string(),
                data_dir: "/tmp".to_string(),
                host_base_dir: "/tmp".to_string(),
                image: "z:local".to_string(),
            },
            ClawType {
                name: "alphaclaw".to_string(),
                code_dir: "/tmp".to_string(),
                data_dir: "/tmp".to_string(),
                host_base_dir: "/tmp".to_string(),
                image: "a:local".to_string(),
            },
        ]);
        assert_eq!(reg.names(), vec!["alphaclaw", "zeroclaw"]);
    }

    #[test]
    fn test_has_cleanup_env() {
        let ct = ClawType {
            name: "picoclaw".to_string(),
            code_dir: "/tmp".to_string(),
            data_dir: "/tmp".to_string(),
            host_base_dir: "/tmp".to_string(),
            image: "picoclaw:local".to_string(),
        };
        let reg = Registry::from_types(vec![ct]);

        with_env(&[("PICOCLAW_CLEANUP", "1")], || {
            assert!(reg.has_cleanup("picoclaw"));
        });
        with_env(&[("PICOCLAW_CLEANUP", "true")], || {
            assert!(reg.has_cleanup("picoclaw"));
        });
        with_env(&[("PICOCLAW_CLEANUP", "0")], || {
            assert!(!reg.has_cleanup("picoclaw"));
        });
        // missing type always false
        assert!(!reg.has_cleanup("nope"));
    }

    #[test]
    fn test_skips_missing_code_dir() {
        // ghostclaw is NOT in the manifest, so is_prebuilt("ghostclaw") is false
        // → needs_code_dir=true → must be skipped on Linux when code_dir missing.
        with_env(
            &[
                ("CLAW_TYPES", "ghostclaw"),
                (
                    "GHOSTCLAW_CODE_DIR",
                    "/nonexistent/path/that/does/not/exist",
                ),
                ("GHOSTCLAW_DATA_DIR", "/tmp"),
                ("GHOSTCLAW_IMAGE", "ghost:local"),
            ],
            || {
                let reg = Registry::from_env();
                // On macOS, code_dir check is skipped (code lives in VZ base image),
                // so the claw is registered even with a nonexistent path.
                // On Linux, the claw is skipped because code_dir doesn't exist
                // AND the claw is not prebuilt (not in manifest).
                if cfg!(target_os = "macos") {
                    assert!(reg.is_valid("ghostclaw"));
                    assert_eq!(reg.names(), vec!["ghostclaw"]);
                } else {
                    assert!(!reg.is_valid("ghostclaw"));
                    assert!(reg.names().is_empty());
                }
            },
        );
    }

    #[test]
    fn test_registry_accepts_prebuilt_without_code_dir() {
        // Regression test for the split-brain bug where prebuilt claws
        // (like hermes-agent on devs) were dropped from the Registry because
        // claws/src/<name> didn't exist on the host, causing POST /mobile/instances
        // to return HTTP 400 "unsupported claw type" even though the ClawStore
        // had them marked as Ready.
        //
        // Fix: prebuilt claws (distribution=prebuilt in the manifest) don't need
        // a code_dir — the artifact is downloaded and turned into a golden rootfs
        // via the installer plan, never touching claws/src/<name>. Only claws
        // with distribution=local still require the source tree to exist.
        //
        // Uses picoclaw from the compiled-in manifest (is_prebuilt=true).
        with_env(
            &[
                ("CLAW_TYPES", "picoclaw"),
                (
                    "PICOCLAW_CODE_DIR",
                    "/nonexistent/picoclaw/source/directory",
                ),
                ("PICOCLAW_DATA_DIR", "/tmp"),
                ("PICOCLAW_IMAGE", "picoclaw:local"),
            ],
            || {
                // Sanity: the test only makes sense if picoclaw is actually prebuilt.
                assert!(
                    core_rs::manifest::is_prebuilt("picoclaw"),
                    "manifest invariant: picoclaw must be prebuilt"
                );

                let reg = Registry::from_env();
                // On both macOS and Linux, picoclaw should be registered because
                // it's prebuilt and doesn't need a source checkout.
                assert!(
                    reg.is_valid("picoclaw"),
                    "prebuilt claw must be registered even when code_dir is missing"
                );
                assert_eq!(reg.names(), vec!["picoclaw"]);
            },
        );
    }
}
