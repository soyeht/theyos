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
/// active-VM limit is reached. This is the single wire owner; the macOS runner
/// re-exports it as `MACOS_VM_LIMIT_REACHED` for compatibility.
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
    /// The Virtualization framework reports this host cannot run virtual machines
    /// (`+[VZVirtualMachine isSupported]` was false) — an unsupportable host/OS or
    /// a missing virtualization authorization. Terminal + ambiguous: neither a
    /// reboot nor a plain retry helps.
    VirtualizationUnavailable,
    /// Unrecognized / unclassified failure (fail-soft catch-all).
    #[serde(other)]
    Unknown,
}

/// The **lifetime scope** of a guest-image failure — how long a stamped failure
/// stays a *current, blocking* condition.
///
/// A failure code says *what* went wrong; the scope says *whether the failure
/// is still in effect*. This distinction is what lets the status reader stop
/// surfacing a transient, boot-scoped failure (e.g. `host_vm_limit_reached`)
/// once the condition that caused it has cleared — without erasing the audit
/// record in `phase_history`.
///
/// Serializes to a `snake_case` string; unknown/future strings decode fail-soft
/// to [`FailureScope::Unknown`], which callers treat as the most conservative
/// scope ([`FailureScope::Persistent`] — keep blocking) so an older client never
/// silently un-blocks on a code it doesn't understand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureScope {
    /// Valid only for the boot it occurred on (recorded in `failure_boot_id`).
    /// On any other boot it is **stale** and no longer blocking — a reboot
    /// cleared the underlying host condition (e.g. a leaked VZ active-VM
    /// session). The canonical example is `host_vm_limit_reached`.
    CurrentBoot,
    /// Sticky until the user fixes the underlying environment and explicitly
    /// retries (e.g. missing entitlement, incompatible restore image, missing
    /// helper). Stays blocking across reboots; reboot does not clear it.
    Persistent,
    /// Transient and worth retrying directly (e.g. a network blip during the
    /// IPSW download). Stays visible as a failure but does not require an
    /// environment change to attempt again.
    Retryable,
    /// Unrecognized / future scope (fail-soft). Callers treat this as
    /// [`Self::Persistent`] (the conservative, keep-blocking choice).
    #[serde(other)]
    Unknown,
}

impl FailureScope {
    /// The stable `snake_case` wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CurrentBoot => "current_boot",
            Self::Persistent => "persistent",
            Self::Retryable => "retryable",
            Self::Unknown => "unknown",
        }
    }

    /// Parse a wire string fail-soft: unrecognized values become [`Self::Unknown`].
    #[must_use]
    pub fn from_wire(s: &str) -> Self {
        match s {
            "current_boot" => Self::CurrentBoot,
            "persistent" => Self::Persistent,
            "retryable" => Self::Retryable,
            _ => Self::Unknown,
        }
    }

    /// Whether a failure with this scope should be treated as **currently
    /// blocking** by the status reader, given whether its recorded boot matches
    /// the live boot.
    ///
    /// - [`Self::CurrentBoot`] blocks **only** when `boot_matches` is true (the
    ///   failure happened on the boot we are still running). On a different boot
    ///   it is stale → not blocking.
    /// - [`Self::Persistent`] and [`Self::Unknown`] always block (conservative).
    /// - [`Self::Retryable`] does not hard-block (the caller may still surface it
    ///   as a non-blocking, retry-able failure).
    ///
    /// `boot_matches` semantics for the compat case (a legacy record with no
    /// recorded boot id) are decided by the caller; see
    /// `guest_image_state::reconcile_failure`.
    #[must_use]
    pub const fn is_blocking(self, boot_matches: bool) -> bool {
        match self {
            Self::CurrentBoot => boot_matches,
            Self::Persistent | Self::Unknown => true,
            Self::Retryable => false,
        }
    }
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
            Self::VirtualizationUnavailable => "virtualization_unavailable",
            Self::Unknown => "unknown",
        }
    }

    /// The scope a failure of this code defaults to when the on-disk record
    /// does not carry an explicit `failure_scope` (older engines stamped the
    /// code but not the scope). This is the authoritative classification table
    /// (item 2 of the failure-scope design):
    ///
    /// - `host_vm_limit_reached` → [`FailureScope::CurrentBoot`] (a reboot
    ///   clears the host active-VM limit / leaked VZ session).
    /// - `ipsw_download_failed`, `insufficient_disk` → [`FailureScope::Retryable`]
    ///   (a network retry, or the user freeing disk, can succeed without a
    ///   reboot or reinstall).
    /// - `helper_missing`, `entitlement_missing`, `ipsw_incompatible`,
    ///   `virtualization_unavailable` → [`FailureScope::Persistent`] (needs a
    ///   reinstall / different host / different image — neither reboot nor a plain
    ///   retry helps).
    /// - `unknown` → [`FailureScope::Persistent`] (conservative: keep blocking).
    #[must_use]
    pub const fn default_scope(self) -> FailureScope {
        match self {
            Self::HostVmLimitReached => FailureScope::CurrentBoot,
            Self::IpswDownloadFailed | Self::InsufficientDisk => FailureScope::Retryable,
            // Persistent: needs a reinstall / different host / different image; and
            // `Unknown` is folded in as the conservative keep-blocking default.
            Self::HelperMissing
            | Self::EntitlementMissing
            | Self::IpswIncompatible
            | Self::VirtualizationUnavailable
            | Self::Unknown => FailureScope::Persistent,
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
            "virtualization_unavailable" => Self::VirtualizationUnavailable,
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
        // Virtualization unavailable — the preflight's typed
        // `VZError::VirtualizationUnsupported` (`+[VZVirtualMachine isSupported]`
        // returned false): an unsupportable host/OS or a missing virtualization
        // authorization. Matched on stable substrings of that message and checked
        // BEFORE the generic "not supported"/"incompatible" branch so it never
        // collapses into `IpswIncompatible`.
        if m.contains("cannot run virtual machines") || m.contains("issupported() was false") {
            return Self::VirtualizationUnavailable;
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
            GuestImageFailureCode::classify(Some(IPC_CODE_MACOS_VM_LIMIT_REACHED), "anything"),
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
    fn virtualization_unavailable_classifies_from_preflight_message() {
        // The exact preflight message (vmrunner-macos-rs `VZError::VirtualizationUnsupported`).
        let preflight = "the Virtualization framework reports this process cannot run virtual \
             machines on this host (VZVirtualMachine.isSupported() was false) — an unsupportable \
             host or a missing virtualization authorization; no virtual machine can be created";
        assert_eq!(
            GuestImageFailureCode::classify(None, preflight),
            GuestImageFailureCode::VirtualizationUnavailable
        );
        // Either stable substring is sufficient.
        assert_eq!(
            GuestImageFailureCode::classify(None, "VZVirtualMachine.isSupported() was false"),
            GuestImageFailureCode::VirtualizationUnavailable
        );
        // Ordering guard: a message carrying BOTH the VZ phrase and the generic
        // "not supported" wording must stay VirtualizationUnavailable, never
        // collapse into IpswIncompatible.
        assert_eq!(
            GuestImageFailureCode::classify(
                None,
                "cannot run virtual machines on this host; configuration not supported"
            ),
            GuestImageFailureCode::VirtualizationUnavailable
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
            GuestImageFailureCode::VirtualizationUnavailable,
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

    // ── FailureScope ──────────────────────────────────────────────────────

    #[test]
    fn default_scope_classifies_each_code() {
        use FailureScope::{CurrentBoot, Persistent, Retryable};
        assert_eq!(
            GuestImageFailureCode::HostVmLimitReached.default_scope(),
            CurrentBoot
        );
        assert_eq!(
            GuestImageFailureCode::IpswDownloadFailed.default_scope(),
            Retryable
        );
        assert_eq!(
            GuestImageFailureCode::InsufficientDisk.default_scope(),
            Retryable
        );
        assert_eq!(
            GuestImageFailureCode::HelperMissing.default_scope(),
            Persistent
        );
        assert_eq!(
            GuestImageFailureCode::EntitlementMissing.default_scope(),
            Persistent
        );
        assert_eq!(
            GuestImageFailureCode::IpswIncompatible.default_scope(),
            Persistent
        );
        assert_eq!(
            GuestImageFailureCode::VirtualizationUnavailable.default_scope(),
            Persistent
        );
        // Unknown is conservative: keep blocking.
        assert_eq!(GuestImageFailureCode::Unknown.default_scope(), Persistent);
    }

    #[test]
    fn scope_is_blocking_rules() {
        // current_boot blocks only when the boot matches.
        assert!(FailureScope::CurrentBoot.is_blocking(true));
        assert!(!FailureScope::CurrentBoot.is_blocking(false));
        // persistent / unknown always block regardless of boot.
        assert!(FailureScope::Persistent.is_blocking(true));
        assert!(FailureScope::Persistent.is_blocking(false));
        assert!(FailureScope::Unknown.is_blocking(true));
        assert!(FailureScope::Unknown.is_blocking(false));
        // retryable never hard-blocks.
        assert!(!FailureScope::Retryable.is_blocking(true));
        assert!(!FailureScope::Retryable.is_blocking(false));
    }

    #[test]
    fn scope_serde_round_trips_and_fail_soft() {
        for scope in [
            FailureScope::CurrentBoot,
            FailureScope::Persistent,
            FailureScope::Retryable,
            FailureScope::Unknown,
        ] {
            let json = serde_json::to_string(&scope).unwrap();
            assert_eq!(json, format!("\"{}\"", scope.as_str()));
            let back: FailureScope = serde_json::from_str(&json).unwrap();
            assert_eq!(back, scope);
        }
        // from_wire fail-soft.
        assert_eq!(
            FailureScope::from_wire("current_boot"),
            FailureScope::CurrentBoot
        );
        assert_eq!(
            FailureScope::from_wire("future_scope"),
            FailureScope::Unknown
        );
        // serde fail-soft on unknown string.
        let back: FailureScope = serde_json::from_str("\"future_scope\"").unwrap();
        assert_eq!(back, FailureScope::Unknown);
    }

    // Compile-time exhaustiveness: adding a variant breaks these matches, a
    // reminder to handle the new value everywhere the wire string appears.
    #[allow(dead_code)]
    fn codes_exhaustive(c: GuestImageFailureCode) {
        match c {
            GuestImageFailureCode::HostVmLimitReached
            | GuestImageFailureCode::HelperMissing
            | GuestImageFailureCode::InsufficientDisk
            | GuestImageFailureCode::EntitlementMissing
            | GuestImageFailureCode::IpswDownloadFailed
            | GuestImageFailureCode::IpswIncompatible
            | GuestImageFailureCode::VirtualizationUnavailable
            | GuestImageFailureCode::Unknown => {}
        }
    }
    #[allow(dead_code)]
    fn scopes_exhaustive(s: FailureScope) {
        match s {
            FailureScope::CurrentBoot
            | FailureScope::Persistent
            | FailureScope::Retryable
            | FailureScope::Unknown => {}
        }
    }
}
