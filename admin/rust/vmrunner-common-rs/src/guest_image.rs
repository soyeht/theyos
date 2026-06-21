//! Typed request contracts for the macOS guest-image IPC methods.
//!
//! `MacOsPrepare`, `MacOsBaseInstall`, and `MacOsProvisionAndSnapshot` are each
//! driven from THREE independent sites that previously hand-built and hand-parsed
//! `serde_json::Value` maps with no shared schema:
//!   1. the `init_macos_guest` CLI (`soyeht-rs`),
//!   2. the HTTP guest-image path (`server-rs::handlers_household_guest_image`),
//!   3. the runner that consumes them (`vmrunner-macos-rs`).
//!
//! Hand-built maps drift silently: e.g. the provision/snapshot callers send
//! `cpus`/`memory_mb` that the runner never reads, while the runner reads
//! `ssh_pubkey`/`skip_provision_inject` that the callers never send. These structs
//! make the full field set a single typed contract so every site agrees on one
//! shape. Every field is `#[serde(default)]` so the wire stays backward-compatible
//! and missing fields decode to their previous implicit defaults.

use serde::{Deserialize, Serialize};

/// Request body for the `MacOsPrepare` IPC method (download + stage the base image).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsPrepareRequest {
    /// Re-download/re-stage even if a base image already exists.
    #[serde(default)]
    pub force: bool,
    /// Rebuild the provisioned snapshot even if one exists.
    #[serde(default)]
    pub force_provision: bool,
    /// Optional explicit IPSW path/URL; `None` lets the runner resolve a default.
    #[serde(default)]
    pub ipsw: Option<String>,
    /// Container registry base URL used to pull guest artifacts.
    #[serde(default)]
    pub registry_url: String,
}

/// Request body for the `MacOsBaseInstall` IPC method (prepare + provision in one).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsBaseInstallRequest {
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub force_provision: bool,
    #[serde(default)]
    pub registry_url: String,
    /// SSH public key injected into the guest during provisioning.
    #[serde(default)]
    pub ssh_pubkey: String,
    /// Directory of provisioning plists; `None` lets the runner resolve a default.
    #[serde(default)]
    pub plist_dir: Option<String>,
}

/// Request body for the `MacOsProvisionAndSnapshot` IPC method.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsProvisionAndSnapshotRequest {
    /// CPU cores for the provisioning boot. `None` lets the runner pick a default.
    #[serde(default)]
    pub cpus: Option<u32>,
    /// RAM (MB) for the provisioning boot. `None` lets the runner pick a default.
    #[serde(default)]
    pub memory_mb: Option<u32>,
    /// Rebuild the snapshot even if one exists.
    #[serde(default)]
    pub force_provision: bool,
    /// Directory of provisioning plists; `None` lets the runner resolve a default.
    #[serde(default)]
    pub plist_dir: Option<String>,
    /// SSH public key injected into the guest during provisioning.
    #[serde(default)]
    pub ssh_pubkey: String,
    /// Skip the privileged `theyos-provision-inject` step (test/advanced use).
    #[serde(default)]
    pub skip_provision_inject: bool,
}

macro_rules! impl_value_helpers {
    ($t:ty) => {
        impl $t {
            /// Serialize to a JSON object for an IPC request body. Infallible for
            /// these flat structs.
            #[must_use]
            pub fn to_value(&self) -> serde_json::Value {
                serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}))
            }

            /// Decode from an IPC params object. Unknown fields are ignored and
            /// missing fields fall back to their `#[serde(default)]`; a present
            /// field with the wrong type yields the default (matching the prior
            /// lenient `as_bool()/as_str()` parsing the runner used).
            #[must_use]
            pub fn from_params(params: &serde_json::Value) -> Self {
                serde_json::from_value(params.clone()).unwrap_or_default()
            }
        }
    };
}

impl_value_helpers!(MacOsPrepareRequest);
impl_value_helpers!(MacOsBaseInstallRequest);
impl_value_helpers!(MacOsProvisionAndSnapshotRequest);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn prepare_round_trips_and_ignores_unknown_fields() {
        let req = MacOsPrepareRequest {
            force: true,
            force_provision: false,
            ipsw: None,
            registry_url: "https://registry.example/theyos".to_string(),
        };
        // Round-trip.
        assert_eq!(MacOsPrepareRequest::from_params(&req.to_value()), req);
        // Unknown caller field (e.g. a stray `cpus`) must not break decoding.
        let with_extra = json!({
            "force": true,
            "registry_url": "https://registry.example/theyos",
            "cpus": 4
        });
        assert_eq!(MacOsPrepareRequest::from_params(&with_extra), req);
    }

    #[test]
    fn provision_snapshot_captures_every_field_any_site_uses() {
        // The union of fields the CLI/server callers send and the runner reads.
        let full = json!({
            "cpus": 4u32,
            "memory_mb": 4096u32,
            "force_provision": true,
            "plist_dir": "/var/theyos/plists",
            "ssh_pubkey": "ssh-ed25519 AAAA...",
            "skip_provision_inject": true,
        });
        let req = MacOsProvisionAndSnapshotRequest::from_params(&full);
        assert_eq!(req.cpus, Some(4));
        assert_eq!(req.memory_mb, Some(4096));
        assert!(req.force_provision);
        assert_eq!(req.plist_dir.as_deref(), Some("/var/theyos/plists"));
        assert_eq!(req.ssh_pubkey, "ssh-ed25519 AAAA...");
        assert!(req.skip_provision_inject);
        // And it survives a round-trip unchanged.
        assert_eq!(
            MacOsProvisionAndSnapshotRequest::from_params(&req.to_value()),
            req
        );
    }

    #[test]
    fn missing_fields_decode_to_prior_defaults() {
        let req = MacOsProvisionAndSnapshotRequest::from_params(&json!({}));
        assert_eq!(req, MacOsProvisionAndSnapshotRequest::default());
        assert_eq!(req.cpus, None);
        assert_eq!(req.ssh_pubkey, "");
        assert!(!req.skip_provision_inject);
    }
}
