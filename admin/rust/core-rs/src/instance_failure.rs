//! `InstanceFailureCode` - a stable, machine-readable reason a per-instance
//! create / provisioning operation failed.
//!
//! This mirrors [`crate::guest_image_failure::GuestImageFailureCode`] but for
//! the per-instance VM lifecycle (create / start / snapshot / provisioning),
//! which is a separate surface from guest-image preparation. A small
//! `snake_case` enum paired with the existing human-readable error string:
//! clients key localized copy off the code and treat the raw error as
//! display-only detail. Decoding is fail-soft: any unknown/future code maps to
//! [`InstanceFailureCode::Unknown`] so an older client never breaks on a newer
//! server (and vice versa).
//!
//! This slice defines the vocabulary and classifier only; wiring it onto the
//! instance status (an additive optional field) is a separate change.

use serde::{Deserialize, Serialize};

use crate::guest_image_failure::IPC_CODE_MACOS_VM_LIMIT_REACHED;

/// Machine-readable per-instance failure reason. Serializes to a `snake_case`
/// string; unknown strings decode to [`InstanceFailureCode::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceFailureCode {
    /// Apple's per-host concurrent macOS-VM limit was reached (VZ `Code=6`).
    HostVmLimitReached,
    /// Not enough free disk space to create or start the instance.
    InsufficientDisk,
    /// A VM snapshot save or load failed.
    SnapshotFailed,
    /// The VM failed to start.
    VmStartFailed,
    /// The VM failed to be created or configured.
    VmCreateFailed,
    /// Provisioning did not complete within the allotted time.
    ProvisioningTimeout,
    /// Unrecognized / unclassified failure (fail-soft catch-all).
    #[serde(other)]
    Unknown,
}

impl InstanceFailureCode {
    /// The stable `snake_case` wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostVmLimitReached => "host_vm_limit_reached",
            Self::InsufficientDisk => "insufficient_disk",
            Self::SnapshotFailed => "snapshot_failed",
            Self::VmStartFailed => "vm_start_failed",
            Self::VmCreateFailed => "vm_create_failed",
            Self::ProvisioningTimeout => "provisioning_timeout",
            Self::Unknown => "unknown",
        }
    }

    /// Parse a wire string fail-soft: unrecognized values become [`Self::Unknown`].
    #[must_use]
    pub fn from_wire(s: &str) -> Self {
        match s {
            "host_vm_limit_reached" => Self::HostVmLimitReached,
            "insufficient_disk" => Self::InsufficientDisk,
            "snapshot_failed" => Self::SnapshotFailed,
            "vm_start_failed" => Self::VmStartFailed,
            "vm_create_failed" => Self::VmCreateFailed,
            "provisioning_timeout" => Self::ProvisioningTimeout,
            _ => Self::Unknown,
        }
    }

    /// Classify a per-instance failure from the IPC error code (when known) and
    /// the human-readable message. The numeric code is authoritative when
    /// present; otherwise the message is matched against known signals. Anything
    /// unrecognized is [`Self::Unknown`] (never a misleading specific code).
    #[must_use]
    pub fn classify(ipc_code: Option<u32>, message: &str) -> Self {
        if ipc_code == Some(IPC_CODE_MACOS_VM_LIMIT_REACHED) {
            return Self::HostVmLimitReached;
        }
        let m = message.to_ascii_lowercase();
        // Host VM limit - the admission authority's typed error, the runner's
        // guidance text, and the raw VZ error string.
        if m.contains("vm limit reached")
            || m.contains("active-vm limit")
            || m.contains("maximum supported number of active virtual machines")
            || m.contains("vzerrorvirtualmachinelimitexceeded")
        {
            return Self::HostVmLimitReached;
        }
        if m.contains("insufficient disk")
            || m.contains("not enough space")
            || m.contains("no space")
        {
            return Self::InsufficientDisk;
        }
        // VZError::SnapshotSaveFailed / SnapshotLoadFailed.
        if m.contains("snapshot") {
            return Self::SnapshotFailed;
        }
        // VZError::CreationFailed -> "VM creation failed: ...".
        if m.contains("creation failed") || m.contains("vm creation") {
            return Self::VmCreateFailed;
        }
        // VZError::StartFailed -> "VM start failed: ...".
        if m.contains("start failed") || m.contains("vm start") {
            return Self::VmStartFailed;
        }
        if m.contains("timed out") || m.contains("timeout") {
            return Self::ProvisioningTimeout;
        }
        Self::Unknown
    }

    /// A sanitized, path-free operator-facing summary for this code. The copy is
    /// stable, curated English, and never derived from the raw error string, so
    /// it is safe to store on the instance row and show on any status surface.
    /// Raw error detail may carry local paths, IPs, or stderr; keep it out of
    /// instance rows and status surfaces. Job error records are a separate
    /// surface until the Jobs API sanitization follow-up lands.
    #[must_use]
    pub const fn operator_summary(self) -> &'static str {
        match self {
            Self::HostVmLimitReached => "the host reached its macOS VM limit; retry shortly",
            Self::InsufficientDisk => "the host ran out of disk space",
            Self::SnapshotFailed => "a VM snapshot operation failed",
            Self::VmStartFailed => "the VM failed to start",
            Self::VmCreateFailed => "the VM could not be created",
            Self::ProvisioningTimeout => "provisioning timed out",
            Self::Unknown => "instance creation failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_2001_classifies_as_host_vm_limit() {
        assert_eq!(
            InstanceFailureCode::classify(Some(IPC_CODE_MACOS_VM_LIMIT_REACHED), "anything"),
            InstanceFailureCode::HostVmLimitReached
        );
    }

    #[test]
    fn host_limit_message_classifies_without_code() {
        for msg in [
            "macOS VM startup hit the host active-VM limit",
            "The maximum supported number of active virtual machines has been reached.",
            "host macOS VM limit reached (HostBlocked): 0 running",
        ] {
            assert_eq!(
                InstanceFailureCode::classify(None, msg),
                InstanceFailureCode::HostVmLimitReached,
                "did not classify: {msg}"
            );
        }
    }

    #[test]
    fn insufficient_disk_classifies() {
        assert_eq!(
            InstanceFailureCode::classify(None, "Insufficient disk space: need 4GB"),
            InstanceFailureCode::InsufficientDisk
        );
        assert_eq!(
            InstanceFailureCode::classify(None, "write failed: no space left on device"),
            InstanceFailureCode::InsufficientDisk
        );
    }

    #[test]
    fn snapshot_save_and_load_classify() {
        assert_eq!(
            InstanceFailureCode::classify(None, "Snapshot save failed: disk error"),
            InstanceFailureCode::SnapshotFailed
        );
        assert_eq!(
            InstanceFailureCode::classify(None, "Snapshot load failed: missing file"),
            InstanceFailureCode::SnapshotFailed
        );
    }

    #[test]
    fn vm_create_and_start_classify() {
        assert_eq!(
            InstanceFailureCode::classify(None, "VM creation failed: bad config"),
            InstanceFailureCode::VmCreateFailed
        );
        assert_eq!(
            InstanceFailureCode::classify(None, "VM start failed: boot error"),
            InstanceFailureCode::VmStartFailed
        );
    }

    #[test]
    fn provisioning_timeout_classifies() {
        assert_eq!(
            InstanceFailureCode::classify(None, "provisioning timed out after 300s"),
            InstanceFailureCode::ProvisioningTimeout
        );
    }

    #[test]
    fn unrecognized_is_unknown() {
        assert_eq!(
            InstanceFailureCode::classify(None, "some unexpected failure"),
            InstanceFailureCode::Unknown
        );
        assert_eq!(
            InstanceFailureCode::classify(None, ""),
            InstanceFailureCode::Unknown
        );
    }

    #[test]
    fn as_str_round_trips_via_from_wire() {
        for code in [
            InstanceFailureCode::HostVmLimitReached,
            InstanceFailureCode::InsufficientDisk,
            InstanceFailureCode::SnapshotFailed,
            InstanceFailureCode::VmStartFailed,
            InstanceFailureCode::VmCreateFailed,
            InstanceFailureCode::ProvisioningTimeout,
            InstanceFailureCode::Unknown,
        ] {
            assert_eq!(InstanceFailureCode::from_wire(code.as_str()), code);
        }
    }

    #[test]
    fn from_wire_and_serde_fail_soft_on_unknown() {
        assert_eq!(
            InstanceFailureCode::from_wire("future_code"),
            InstanceFailureCode::Unknown
        );
        let back: InstanceFailureCode = serde_json::from_str("\"future_code\"").unwrap();
        assert_eq!(back, InstanceFailureCode::Unknown);
    }

    #[test]
    fn serde_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&InstanceFailureCode::VmStartFailed).unwrap(),
            "\"vm_start_failed\""
        );
    }

    #[test]
    fn operator_summary_is_non_empty_and_path_free() {
        for code in [
            InstanceFailureCode::HostVmLimitReached,
            InstanceFailureCode::InsufficientDisk,
            InstanceFailureCode::SnapshotFailed,
            InstanceFailureCode::VmStartFailed,
            InstanceFailureCode::VmCreateFailed,
            InstanceFailureCode::ProvisioningTimeout,
            InstanceFailureCode::Unknown,
        ] {
            let s = code.operator_summary();
            assert!(!s.is_empty(), "empty summary for {}", code.as_str());
            // Path-free / no leaked detail: no path separators or format braces.
            for bad in ['/', '\\', '{', '}'] {
                assert!(
                    !s.contains(bad),
                    "summary for {} contains `{bad}`: {s}",
                    code.as_str()
                );
            }
        }
    }

    #[test]
    fn classify_then_summary_strips_raw_path_detail() {
        // A raw VZError-style message carrying a local path classifies to a
        // specific code whose operator_summary is path-free.
        let raw = "Snapshot save failed: /tmp/soyeht-test/snap.vzvmsave: write error";
        let code = InstanceFailureCode::classify(None, raw);
        assert_eq!(code, InstanceFailureCode::SnapshotFailed);
        let summary = code.operator_summary();
        assert!(!summary.contains('/'), "summary leaked a path: {summary}");
        assert!(
            !summary.contains("vzvmsave"),
            "summary leaked raw detail: {summary}"
        );
    }

    #[test]
    fn unknown_summary_is_generic_not_raw() {
        assert_eq!(
            InstanceFailureCode::Unknown.operator_summary(),
            "instance creation failed"
        );
    }
}
