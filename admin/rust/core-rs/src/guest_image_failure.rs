//! `GuestImageFailureCode` — a stable, machine-readable reason a macOS
//! guest-image preparation failed.
//!
//! This mirrors the design of `manifest::UnavailableReasonCode`: a small
//! `snake_case` enum paired with the existing human-readable `error` string.
//! Clients (the iPhone Claw Store) key **localized copy** off the code and
//! treat `error` as display-only detail. Decoding is **fail-soft**: any
//! unknown/future code maps to [`GuestImageFailureCode::Unknown`] so an older
//! client never breaks on a newer server (and vice versa).
//!
//! The code is produced server-side from the prepare outcome (the IPC error
//! code / message) when a failure is stamped into `init-state.json`, surfaced
//! on `GET /bootstrap/status` and the prepare response, and read back from the
//! most-recent failed `phase_history` record.

use serde::{Deserialize, Serialize};

/// The IPC error code returned by `vmrunner_macos_ipc` when the macOS host
/// active-VM limit is reached (`vmrunner_macos_rs::slot_manager::MACOS_VM_LIMIT_REACHED`).
/// Duplicated here as a wire constant so `core-rs` need not depend on the
/// macOS-only runner crate.
pub const IPC_CODE_MACOS_VM_LIMIT_REACHED: u32 = 2001;

/// Machine-readable guest-image failure reason. Serializes to a `snake_case`
/// string; unknown strings decode to [`GuestImageFailureCode::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestImageFailureCode {
    /// Apple's per-host concurrent macOS-VM limit was reached (VZ `Code=6`).
    HostVmLimitReached,
    /// A required helper binary (e.g. `theyos-provision-inject`) was missing.
    HelperMissing,
    /// Not enough free disk space to build the guest image.
    InsufficientDisk,
    /// The virtualization entitlement is missing / not honored.
    EntitlementMissing,
    /// The macOS restore image (IPSW) failed to download.
    IpswDownloadFailed,
    /// The restore image is incompatible with this host.
    IpswIncompatible,
    /// Unrecognized / unclassified failure (fail-soft catch-all).
    #[serde(other)]
    Unknown,
}

impl GuestImageFailureCode {
    /// The stable `snake_case` wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostVmLimitReached => "host_vm_limit_reached",
            Self::HelperMissing => "helper_missing",
            Self::InsufficientDisk => "insufficient_disk",
            Self::EntitlementMissing => "entitlement_missing",
            Self::IpswDownloadFailed => "ipsw_download_failed",
            Self::IpswIncompatible => "ipsw_incompatible",
            Self::Unknown => "unknown",
        }
    }

    /// Parse a wire string fail-soft: unrecognized values become [`Self::Unknown`].
    #[must_use]
    pub fn from_wire(s: &str) -> Self {
        match s {
            "host_vm_limit_reached" => Self::HostVmLimitReached,
            "helper_missing" => Self::HelperMissing,
            "insufficient_disk" => Self::InsufficientDisk,
            "entitlement_missing" => Self::EntitlementMissing,
            "ipsw_download_failed" => Self::IpswDownloadFailed,
            "ipsw_incompatible" => Self::IpswIncompatible,
            _ => Self::Unknown,
        }
    }

    /// Classify a prepare failure from the IPC error code (when known) and the
    /// human-readable message. The numeric code is authoritative when present;
    /// otherwise the message is matched against known signals. Anything
    /// unrecognized is [`Self::Unknown`] (never a misleading specific code).
    #[must_use]
    pub fn classify(ipc_code: Option<u32>, message: &str) -> Self {
        if ipc_code == Some(IPC_CODE_MACOS_VM_LIMIT_REACHED) {
            return Self::HostVmLimitReached;
        }
        let m = message.to_ascii_lowercase();
        // Host VM limit — matches the admission authority's typed error
        // (`VZError::HostVmLimitReached` / `AdmissionError::HostVmLimitReached`,
        // e.g. "host macOS VM limit reached (HostBlocked): ..."), the macOS
        // runner's guidance text ("...host active-VM limit..."), and the raw VZ
        // error ("maximum supported number of active virtual machines").
        if m.contains("vm limit reached")
            || m.contains("active-vm limit")
            || m.contains("maximum supported number of active virtual machines")
            || m.contains("vzerrorvirtualmachinelimitexceeded")
        {
            return Self::HostVmLimitReached;
        }
        if m.contains("entitlement") {
            return Self::EntitlementMissing;
        }
        if m.contains("helper") && m.contains("missing")
            || m.contains("provision-inject")
            || m.contains("helper_missing")
        {
            return Self::HelperMissing;
        }
        if m.contains("insufficient disk")
            || m.contains("not enough space")
            || m.contains("no space")
        {
            return Self::InsufficientDisk;
        }
        if m.contains("download") && (m.contains("ipsw") || m.contains("restore image")) {
            return Self::IpswDownloadFailed;
        }
        if m.contains("incompatible")
            || m.contains("not installable")
            || m.contains("not supported")
        {
            return Self::IpswIncompatible;
        }
        Self::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_2001_classifies_as_host_vm_limit() {
        assert_eq!(
            GuestImageFailureCode::classify(Some(2001), "anything"),
            GuestImageFailureCode::HostVmLimitReached
        );
    }

    #[test]
    fn host_limit_message_classifies_without_code() {
        for msg in [
            "macOS VM startup hit the host active-VM limit while installing",
            "The maximum supported number of active virtual machines has been reached.",
            "Host VM limit reached: ...",
            // The admission authority's typed error, as it reaches the server's
            // failure stamper via the IPC error string (the blocked-preflight path).
            "MacOsPrepare: host macOS VM limit reached (HostBlocked): 0 running, \
             0 suspected orphan(s) this boot (limit 2)",
        ] {
            assert_eq!(
                GuestImageFailureCode::classify(None, msg),
                GuestImageFailureCode::HostVmLimitReached,
                "message did not classify: {msg}"
            );
        }
    }

    #[test]
    fn other_codes_classify_from_message() {
        assert_eq!(
            GuestImageFailureCode::classify(
                None,
                "VZMacOSInstaller failed: hypervisor entitlement missing"
            ),
            GuestImageFailureCode::EntitlementMissing
        );
        assert_eq!(
            GuestImageFailureCode::classify(None, "Insufficient disk space at '/'"),
            GuestImageFailureCode::InsufficientDisk
        );
        assert_eq!(
            GuestImageFailureCode::classify(None, "IPSW download failed: connection reset"),
            GuestImageFailureCode::IpswDownloadFailed
        );
        assert_eq!(
            GuestImageFailureCode::classify(None, "restore image is incompatible with this host"),
            GuestImageFailureCode::IpswIncompatible
        );
    }

    #[test]
    fn unknown_message_is_unknown() {
        assert_eq!(
            GuestImageFailureCode::classify(None, "something totally unexpected"),
            GuestImageFailureCode::Unknown
        );
    }

    #[test]
    fn from_wire_is_fail_soft() {
        assert_eq!(
            GuestImageFailureCode::from_wire("host_vm_limit_reached"),
            GuestImageFailureCode::HostVmLimitReached
        );
        assert_eq!(
            GuestImageFailureCode::from_wire("some_future_code"),
            GuestImageFailureCode::Unknown
        );
    }

    #[test]
    fn serde_round_trips_snake_case_and_fail_soft() {
        // Each known code serializes to its wire string and back.
        for code in [
            GuestImageFailureCode::HostVmLimitReached,
            GuestImageFailureCode::HelperMissing,
            GuestImageFailureCode::InsufficientDisk,
            GuestImageFailureCode::EntitlementMissing,
            GuestImageFailureCode::IpswDownloadFailed,
            GuestImageFailureCode::IpswIncompatible,
            GuestImageFailureCode::Unknown,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            let back: GuestImageFailureCode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, code);
        }
        // Unknown/future string deserializes fail-soft to Unknown.
        let back: GuestImageFailureCode = serde_json::from_str("\"brand_new_code\"").unwrap();
        assert_eq!(back, GuestImageFailureCode::Unknown);
    }
}
