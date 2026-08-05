//! Boot identity — a stable per-boot string that changes only across reboots.
//!
//! This is the **single source of truth** for "which boot are we on", shared by:
//!
//!   - [`vm_admission`](../../vmrunner-macos-rs/src/vm_admission.rs)'s lease
//!     registry (`blocked_boot_id`, per-lease `boot_id`), and
//!   - the guest-image status reader's boot-scoped failure reconciliation
//!     (`server-rs/src/guest_image_state.rs`).
//!
//! Both must agree byte-for-byte on the format, otherwise a `failure_boot_id`
//! stamped by one component would never compare equal to the live boot id read
//! by another. Keeping the derivation here (no FFI, no platform-specific crate)
//! lets `server-rs` reconcile boot-scoped failures **without** depending on the
//! macOS-only `vmrunner-macos-rs` runner crate.
//!
//! ## Format
//!
//! `"boottime:<seconds>"` where `<seconds>` is the integer second field of
//! macOS `kern.boottime`. A reboot changes the boot time, hence the id. On a
//! platform without that sysctl (or any failure to read it) the function
//! degrades to `"boottime:unknown"` — a value that compares unequal to any real
//! boot id, so a boot-scoped failure stamped with a real id is treated as stale
//! (never falsely "current") under that degraded condition.

/// Stable per-boot identity derived from macOS `kern.boottime` seconds.
///
/// Changes only across reboots — which is exactly when leaked VZ sessions are
/// cleared and boot-scoped failures (e.g. `host_vm_limit_reached`) become stale.
///
/// Returns `"boottime:<seconds>"` on success, `"boottime-raw:<sysctl-output>"`
/// if the output was non-empty but unparseable, or `"boottime:unknown"` if the
/// boot time could not be read at all.
#[must_use]
pub fn current_boot_id() -> String {
    if let Ok(out) = std::process::Command::new("sysctl")
        .args(["-n", "kern.boottime"])
        .output()
        && let Ok(s) = String::from_utf8(out.stdout)
    {
        // e.g. "{ sec = 1700000000, usec = 0 } Wed Jan ..."
        if let Some(idx) = s.find("sec = ") {
            let digits: String = s[idx + 6..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            if !digits.is_empty() {
                return format!("boottime:{digits}");
            }
        }
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return format!("boottime-raw:{trimmed}");
        }
    }
    "boottime:unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_id_is_nonempty_and_prefixed() {
        let id = current_boot_id();
        assert!(!id.is_empty());
        assert!(
            id.starts_with("boottime:") || id.starts_with("boottime-raw:"),
            "unexpected boot id format: {id}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn boot_id_on_macos_is_boottime_seconds() {
        // On macOS `kern.boottime` is always available, so we get the parsed
        // `boottime:<digits>` form (never the raw/unknown fallbacks).
        let id = current_boot_id();
        assert!(
            id.starts_with("boottime:") && id != "boottime:unknown",
            "expected boottime:<digits> on macOS, got: {id}"
        );
        let digits = id.strip_prefix("boottime:").unwrap();
        assert!(
            digits.chars().all(|c| c.is_ascii_digit()),
            "boot id seconds must be all digits: {id}"
        );
    }

    #[test]
    fn boot_id_is_stable_within_one_boot() {
        // Two reads in the same process (same boot) must be identical.
        assert_eq!(current_boot_id(), current_boot_id());
    }
}
