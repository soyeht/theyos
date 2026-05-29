//! Guest-image (macOS base VM) initialization state, exposed to the
//! iPhone via `GET /bootstrap/status`.
//!
//! The actual init lifecycle is owned by `init_macos_guest` (the CLI
//! binary in `soyeht-rs`) which persists its progress to
//! `init-state.json` via the schema defined in
//! `vmrunner-macos-rs/src/init_state.rs`. We deliberately do NOT depend
//! on that crate here — reading the JSON as a `serde_json::Value` keeps
//! the dependency graph thin and lets us tolerate older state files
//! that were written before this module existed.
//!
//! Three values are surfaced:
//!
//!   - `phase`  — the top-level phase enum (`download_ipsw`, `create_disk`,
//!     `install_macos`, `provision`, `create_snapshot`, `complete`).
//!   - `status` — overall status (`pending`, `in_progress`, `done`,
//!     `failed`).
//!   - `error`  — last error message from the most recent failed phase
//!     attempt. Only populated when status is `failed`.
//!
//! Linux has no guest VM concept, so this module returns
//! `GuestImageState::not_applicable()` (all three fields `None`) on
//! non-macOS targets. The handler emits Option-typed fields so the
//! iPhone can distinguish "doesn't apply" from "in progress" cleanly.

#[cfg(target_os = "macos")]
use core_rs::guest_image_failure::FailureScope;
use core_rs::guest_image_failure::GuestImageFailureCode;
use serde::Serialize;
#[cfg(target_os = "macos")]
use std::path::PathBuf;

/// Snapshot of guest-image init progress for one Mac engine. All
/// fields are optional: a `None` triple means "no init-state.json
/// exists yet" (fresh install — user hasn't consented to provisioning
/// yet) or "this platform doesn't have a guest image" (Linux).
#[derive(Debug, Clone, Default, Serialize)]
pub struct GuestImageState {
    /// Top-level phase string from `init-state.json::phase`. Snake-case
    /// matches the source enum's `rename_all = "snake_case"`.
    pub phase: Option<String>,

    /// Overall status from `init-state.json::status`. One of:
    /// `pending`, `in_progress`, `done`, `failed`.
    pub status: Option<String>,

    /// Error message extracted from the most recent failed phase
    /// record in `phase_history`. Only set when `status == "failed"`.
    pub error: Option<String>,

    /// Machine-readable failure reason for the most recent failed phase.
    /// Only set when `status == "failed"`; absent on older state files that
    /// predate the field (the iPhone then falls back to generic copy).
    pub failure_code: Option<GuestImageFailureCode>,
}

impl GuestImageState {
    /// Returns the not-applicable triple used on Linux and on any
    /// target where the state file is absent. All three fields are
    /// `None`; the iPhone interprets this as "this server doesn't
    /// need a guest image" (Linux) or "guest image not started yet"
    /// (Mac with fresh install).
    #[must_use]
    pub const fn not_applicable() -> Self {
        Self {
            phase: None,
            status: None,
            error: None,
            failure_code: None,
        }
    }

    /// Reads + parses `init-state.json` from the canonical macOS base
    /// directory. Returns `not_applicable()` if the file is missing,
    /// unreadable, or unparseable — those are all "no signal" states
    /// from the iPhone's perspective and are visually equivalent to
    /// "not started" in the Claw Store UI.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn read_current() -> Self {
        let path = macos_base_dir().join("init-state.json");
        match read_raw(&path) {
            Some(raw) => reconcile_failure(raw, &core_rs::boot_id::current_boot_id()),
            None => Self::not_applicable(),
        }
    }

    /// Linux has no guest VM. Always returns not-applicable.
    #[cfg(not(target_os = "macos"))]
    #[must_use]
    pub fn read_current() -> Self {
        Self::not_applicable()
    }
}

/// Canonical macOS base directory for the guest image
/// (`$THEYOS_VM_ASSETS_DIR/macos-base` if set, otherwise
/// `~/Library/Application Support/theyos/vms/macos-base`). Exposed
/// pub(crate) so the remote-prepare launcher can stamp a `failed`
/// record into `init-state.json` when its background task fails
/// without going through the IPC handler's `fail_phase` path.
#[cfg(target_os = "macos")]
#[must_use]
pub(crate) fn macos_base_dir() -> PathBuf {
    if let Ok(d) = std::env::var("THEYOS_VM_ASSETS_DIR") {
        return PathBuf::from(d).join("macos-base");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join("Library/Application Support/theyos/vms/macos-base")
}

/// Raw parsed guest-image state plus the failure-scope metadata the reader
/// needs to reconcile boot-scoped failures. Internal to this module: callers
/// outside use [`GuestImageState::read_current`], which applies reconciliation.
#[cfg(target_os = "macos")]
struct RawGuestImage {
    /// The state exactly as recorded on disk (raw `failure_code`, unmasked).
    state: GuestImageState,
    /// Failure scope from the failed record, when present. Absent on older
    /// records that predate the field (the reader falls back to
    /// `failure_code.default_scope()`).
    failure_scope: Option<FailureScope>,
    /// Boot id the failure was stamped on, for `current_boot`-scoped failures.
    /// Absent on older records (handled by the compat rule in
    /// [`reconcile_failure`]).
    failure_boot_id: Option<String>,
}

/// Pure parser — reads + parses `init-state.json` into a [`RawGuestImage`]
/// **without** reconciling boot-scoped failures (so the raw, on-disk
/// `failure_code` is preserved). Used by [`GuestImageState::read_current`]
/// (which then reconciles) and by tests that drive it from a tempfile without
/// setting `THEYOS_VM_ASSETS_DIR`.
#[cfg(target_os = "macos")]
fn read_raw(path: &std::path::Path) -> Option<RawGuestImage> {
    if !path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;

    let phase = json.get("phase").and_then(|v| v.as_str()).map(String::from);
    let mut status = json
        .get("status")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Compatibility for 0.1.20 builds that reached the final phase
    // by assigning `phase = "complete"` directly, without also
    // flipping the v2 status field to `done`. The snapshot is already
    // usable at this point, so surface the state the iPhone needs.
    if phase.as_deref() == Some("complete") && status.as_deref() != Some("failed") {
        status = Some("done".to_string());
    }

    // Extract the error from the most recent failed phase in phase_history.
    // Schema: `phase_history` is `BTreeMap<String, PhaseRecord>` where
    // each `PhaseRecord` has `status: PhaseStatus` and `error: Option<String>`.
    // Locate the most recent failed phase record (highest sorted key with
    // status == "failed"), then pull `error`, `failure_code`, `failure_scope`,
    // and `failure_boot_id`.
    let failed_record = if status.as_deref() == Some("failed") {
        json.get("phase_history")
            .and_then(|h| h.as_object())
            .and_then(|history| {
                // Phases run in a fixed sequence (download → disk → install →
                // provision → snapshot → complete), so the latest failed one is
                // the highest sorted key with status == "failed".
                history.iter().rev().find_map(|(_, record)| {
                    let rec_obj = record.as_object()?;
                    if rec_obj.get("status")?.as_str()? == "failed" {
                        Some(rec_obj.clone())
                    } else {
                        None
                    }
                })
            })
    } else {
        None
    };

    let error = failed_record
        .as_ref()
        .and_then(|rec| rec.get("error").and_then(|e| e.as_str()).map(String::from));

    // `failure_code` is fail-soft: an unrecognized/absent code never breaks
    // decoding. Absent → None (older state file); unknown string → Unknown.
    let failure_code = failed_record.as_ref().and_then(|rec| {
        rec.get("failure_code")
            .and_then(|c| c.as_str())
            .map(GuestImageFailureCode::from_wire)
    });

    // `failure_scope` is fail-soft like `failure_code`. Absent → None (older
    // record; the reader falls back to `failure_code.default_scope()`).
    let failure_scope = failed_record.as_ref().and_then(|rec| {
        rec.get("failure_scope")
            .and_then(|s| s.as_str())
            .map(FailureScope::from_wire)
    });

    let failure_boot_id = failed_record.as_ref().and_then(|rec| {
        rec.get("failure_boot_id")
            .and_then(|b| b.as_str())
            .map(String::from)
    });

    Some(RawGuestImage {
        state: GuestImageState {
            phase,
            status,
            error,
            failure_code,
        },
        failure_scope,
        failure_boot_id,
    })
}

/// Reconcile a parsed state against the live boot id (read-time only — never
/// mutates `init-state.json`; `phase_history` is always preserved on disk).
///
/// A **boot-scoped** failure (`failure_scope == current_boot`, the default for
/// `host_vm_limit_reached`) is only a *current, blocking* condition while the
/// boot it was stamped on is still the live boot. Once the boot id differs, a
/// reboot has cleared the underlying host condition (e.g. a leaked VZ active-VM
/// session), so the failure is **stale** and we return a preparable state —
/// `/bootstrap/status` stops surfacing it and the prepare handler (which reads
/// through the same resolver) falls through to spawn without `--force`.
///
/// Compat rule (b): a legacy `current_boot` record stamped *before*
/// `failure_boot_id` existed (so the id is absent) is treated as **stale** too
/// — it cannot prove it belongs to the live boot, and the underlying condition
/// is inherently boot-scoped. This un-blocks Macs already stuck at upgrade
/// time. If the host genuinely is still blocked, the next prepare attempt is
/// refused and re-stamps the failure *with* the current boot id, which then
/// correctly blocks (self-correcting in one cycle, never a permanent stuck
/// state).
///
/// `persistent` and `retryable` failures are left exactly as recorded (a reboot
/// does not clear them); only `current_boot`-stale is masked.
#[cfg(target_os = "macos")]
fn reconcile_failure(raw: RawGuestImage, current_boot_id: &str) -> GuestImageState {
    let RawGuestImage {
        state,
        failure_scope,
        failure_boot_id,
    } = raw;

    // Only a `failed` state with a known code can be a boot-scoped failure.
    if state.status.as_deref() != Some("failed") {
        return state;
    }
    let Some(code) = state.failure_code else {
        return state;
    };

    // Explicit scope wins; otherwise classify from the code (older records).
    let scope = failure_scope.unwrap_or_else(|| code.default_scope());
    if scope != FailureScope::CurrentBoot {
        // persistent / retryable / unknown → surface the failure as recorded.
        return state;
    }

    // current_boot: blocking only while the stamped boot is the live boot.
    // Absent boot id ⇒ compat rule (b) ⇒ treated as a different (stale) boot.
    let is_current_boot = failure_boot_id.as_deref() == Some(current_boot_id);
    if is_current_boot {
        return state; // still this boot → genuinely blocking.
    }

    // Stale boot-scoped failure: no longer the current blocking state. Present a
    // preparable state (history on disk is untouched).
    GuestImageState::not_applicable()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Test shim: parse to the raw on-disk state (no boot reconciliation) — the
    /// historical `read_from_path` shape the parsing tests below assert against.
    fn read_from_path(path: &std::path::Path) -> Option<GuestImageState> {
        read_raw(path).map(|r| r.state)
    }

    /// Parse `json` into a [`RawGuestImage`] via a tempfile (exercises the real
    /// `read_raw` path, including `scope`/`boot_id` extraction).
    fn raw_from_json(json: &str) -> RawGuestImage {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("init-state.json");
        fs::write(&state_file, json).unwrap();
        read_raw(&state_file).expect("parses")
    }

    #[test]
    fn read_returns_not_applicable_when_file_missing() {
        let dir = tempdir().unwrap();
        let result = read_from_path(&dir.path().join("init-state.json"));
        assert!(
            result.is_none(),
            "missing file → None → caller treats as not_applicable"
        );
    }

    #[test]
    fn read_parses_complete_state() {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("init-state.json");
        fs::write(
            &state_file,
            r#"{
                "version": 2,
                "phase": "complete",
                "status": "done",
                "phase_history": {}
            }"#,
        )
        .unwrap();
        let result = read_from_path(&state_file).expect("parses");
        assert_eq!(result.phase.as_deref(), Some("complete"));
        assert_eq!(result.status.as_deref(), Some("done"));
        assert!(result.error.is_none());
    }

    #[test]
    fn read_treats_complete_pending_as_done() {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("init-state.json");
        fs::write(
            &state_file,
            r#"{
                "version": 2,
                "phase": "complete",
                "status": "pending",
                "phase_history": {}
            }"#,
        )
        .unwrap();
        let result = read_from_path(&state_file).expect("parses");
        assert_eq!(result.phase.as_deref(), Some("complete"));
        assert_eq!(result.status.as_deref(), Some("done"));
        assert!(result.error.is_none());
    }

    #[test]
    fn read_parses_in_progress_state() {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("init-state.json");
        fs::write(
            &state_file,
            r#"{
                "phase": "install_macos",
                "status": "in_progress"
            }"#,
        )
        .unwrap();
        let result = read_from_path(&state_file).expect("parses");
        assert_eq!(result.phase.as_deref(), Some("install_macos"));
        assert_eq!(result.status.as_deref(), Some("in_progress"));
        assert!(result.error.is_none());
    }

    #[test]
    fn read_extracts_error_from_failed_phase_history() {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("init-state.json");
        fs::write(
            &state_file,
            r#"{
                "phase": "install_macos",
                "status": "failed",
                "phase_history": {
                    "download_ipsw": {
                        "status": "done",
                        "attempts": 1
                    },
                    "install_macos": {
                        "status": "failed",
                        "attempts": 2,
                        "error": "VZMacOSInstaller failed: hypervisor entitlement missing"
                    }
                }
            }"#,
        )
        .unwrap();
        let result = read_from_path(&state_file).expect("parses");
        assert_eq!(result.phase.as_deref(), Some("install_macos"));
        assert_eq!(result.status.as_deref(), Some("failed"));
        assert_eq!(
            result.error.as_deref(),
            Some("VZMacOSInstaller failed: hypervisor entitlement missing")
        );
    }

    #[test]
    fn read_ignores_error_when_status_is_not_failed() {
        // Defensive: phase_history might contain old failure records
        // from a prior attempt that have since been retried successfully.
        // Don't leak those old errors when current status is in_progress.
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("init-state.json");
        fs::write(
            &state_file,
            r#"{
                "phase": "create_snapshot",
                "status": "in_progress",
                "phase_history": {
                    "install_macos": {
                        "status": "failed",
                        "attempts": 1,
                        "error": "older transient error, retried"
                    }
                }
            }"#,
        )
        .unwrap();
        let result = read_from_path(&state_file).expect("parses");
        assert_eq!(result.status.as_deref(), Some("in_progress"));
        assert!(
            result.error.is_none(),
            "in_progress must not leak historical failed-phase errors"
        );
    }

    #[test]
    fn read_tolerates_corrupted_json() {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("init-state.json");
        fs::write(&state_file, "{ this is not json").unwrap();
        let result = read_from_path(&state_file);
        assert!(result.is_none(), "corrupted JSON → None → not_applicable");
    }

    #[test]
    fn read_extracts_failure_code_from_failed_phase() {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("init-state.json");
        fs::write(
            &state_file,
            r#"{
                "phase": "install_macos",
                "status": "failed",
                "phase_history": {
                    "install_macos": {
                        "status": "failed",
                        "error": "macOS VM startup hit the host active-VM limit",
                        "failure_code": "host_vm_limit_reached"
                    }
                }
            }"#,
        )
        .unwrap();
        let result = read_from_path(&state_file).expect("parses");
        assert_eq!(result.status.as_deref(), Some("failed"));
        assert_eq!(
            result.failure_code,
            Some(GuestImageFailureCode::HostVmLimitReached)
        );
    }

    #[test]
    fn read_failure_code_absent_on_old_state_is_none() {
        // Compat: an older failed record predates `failure_code`. Decoding must
        // not break, and the code is simply absent (iPhone falls back to copy).
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("init-state.json");
        fs::write(
            &state_file,
            r#"{
                "phase": "install_macos",
                "status": "failed",
                "phase_history": {
                    "install_macos": { "status": "failed", "error": "boom" }
                }
            }"#,
        )
        .unwrap();
        let result = read_from_path(&state_file).expect("parses");
        assert_eq!(result.error.as_deref(), Some("boom"));
        assert!(result.failure_code.is_none());
    }

    #[test]
    fn read_unknown_failure_code_is_failsoft_unknown() {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("init-state.json");
        fs::write(
            &state_file,
            r#"{
                "phase": "install_macos",
                "status": "failed",
                "phase_history": {
                    "install_macos": {
                        "status": "failed",
                        "error": "boom",
                        "failure_code": "some_future_code"
                    }
                }
            }"#,
        )
        .unwrap();
        let result = read_from_path(&state_file).expect("parses");
        assert_eq!(result.failure_code, Some(GuestImageFailureCode::Unknown));
    }

    // ── reconcile_failure: boot-scoped failure reconciliation ──────────────

    const BOOT_NOW: &str = "boottime:222";

    /// A `current_boot` host-limit failure stamped on the *live* boot still
    /// blocks: `/bootstrap/status` keeps surfacing it (restart / Check Again).
    #[test]
    fn same_boot_host_limit_still_blocks() {
        let raw = raw_from_json(
            r#"{
                "phase": "install_macos",
                "status": "failed",
                "phase_history": {
                    "install_macos": {
                        "status": "failed",
                        "error": "host macOS VM limit reached (HostBlocked)",
                        "failure_code": "host_vm_limit_reached",
                        "failure_scope": "current_boot",
                        "failure_boot_id": "boottime:222"
                    }
                }
            }"#,
        );
        let result = reconcile_failure(raw, BOOT_NOW);
        assert_eq!(result.status.as_deref(), Some("failed"));
        assert_eq!(
            result.failure_code,
            Some(GuestImageFailureCode::HostVmLimitReached),
            "same-boot host limit must remain blocking"
        );
    }

    /// A `current_boot` host-limit failure stamped on a *previous* boot is stale
    /// (reboot cleared it): reader masks it to a preparable state.
    #[test]
    fn previous_boot_host_limit_stops_blocking() {
        let raw = raw_from_json(
            r#"{
                "phase": "install_macos",
                "status": "failed",
                "phase_history": {
                    "install_macos": {
                        "status": "failed",
                        "error": "host macOS VM limit reached (HostBlocked)",
                        "failure_code": "host_vm_limit_reached",
                        "failure_scope": "current_boot",
                        "failure_boot_id": "boottime:111"
                    }
                }
            }"#,
        );
        let result = reconcile_failure(raw, BOOT_NOW);
        assert!(
            result.status.is_none() && result.failure_code.is_none(),
            "previous-boot host limit must be masked (preparable), got {result:?}"
        );
    }

    /// Compat rule (b): a legacy host-limit failure with NO `failure_scope` and
    /// NO `failure_boot_id` is treated as stale (un-blocks Macs stuck at upgrade
    /// time). `default_scope(host_vm_limit_reached) == current_boot`, absent boot
    /// id ⇒ different boot ⇒ masked.
    #[test]
    fn legacy_host_limit_without_boot_id_stops_blocking() {
        let raw = raw_from_json(
            r#"{
                "phase": "install_macos",
                "status": "failed",
                "phase_history": {
                    "install_macos": {
                        "status": "failed",
                        "error": "host macOS VM limit reached (HostBlocked)",
                        "failure_code": "host_vm_limit_reached"
                    }
                }
            }"#,
        );
        // No failure_scope / failure_boot_id parsed from the legacy record.
        assert!(raw.failure_scope.is_none());
        assert!(raw.failure_boot_id.is_none());
        let result = reconcile_failure(raw, BOOT_NOW);
        assert!(
            result.status.is_none() && result.failure_code.is_none(),
            "legacy host limit (no boot id) must be masked per compat rule (b), got {result:?}"
        );
    }

    /// Persistent failures (e.g. missing entitlement) are never boot-scoped and
    /// must keep blocking regardless of boot — a reboot does not fix them.
    #[test]
    fn persistent_failure_keeps_blocking_across_boots() {
        let json = r#"{
                "phase": "install_macos",
                "status": "failed",
                "phase_history": {
                    "install_macos": {
                        "status": "failed",
                        "error": "hypervisor entitlement missing",
                        "failure_code": "entitlement_missing",
                        "failure_scope": "persistent"
                    }
                }
            }"#;
        // Even on a different boot id, persistent stays blocking.
        let result = reconcile_failure(raw_from_json(json), BOOT_NOW);
        assert_eq!(result.status.as_deref(), Some("failed"));
        assert_eq!(
            result.failure_code,
            Some(GuestImageFailureCode::EntitlementMissing)
        );
    }

    /// A legacy persistent failure with no explicit scope is classified via
    /// `default_scope` and still blocks (`entitlement_missing` → persistent).
    #[test]
    fn legacy_persistent_failure_keeps_blocking() {
        let raw = raw_from_json(
            r#"{
                "phase": "install_macos",
                "status": "failed",
                "phase_history": {
                    "install_macos": {
                        "status": "failed",
                        "error": "hypervisor entitlement missing",
                        "failure_code": "entitlement_missing"
                    }
                }
            }"#,
        );
        assert!(raw.failure_scope.is_none());
        let result = reconcile_failure(raw, BOOT_NOW);
        assert_eq!(
            result.failure_code,
            Some(GuestImageFailureCode::EntitlementMissing),
            "legacy persistent failure must keep blocking"
        );
    }

    /// Retryable failures (e.g. IPSW download) are not boot-scoped: they stay
    /// visible as a failure (never masked), so the user still sees what happened.
    #[test]
    fn retryable_failure_is_not_masked() {
        let raw = raw_from_json(
            r#"{
                "phase": "download_ipsw",
                "status": "failed",
                "phase_history": {
                    "download_ipsw": {
                        "status": "failed",
                        "error": "IPSW download failed: connection reset",
                        "failure_code": "ipsw_download_failed",
                        "failure_scope": "retryable"
                    }
                }
            }"#,
        );
        let result = reconcile_failure(raw, BOOT_NOW);
        assert_eq!(result.status.as_deref(), Some("failed"));
        assert_eq!(
            result.failure_code,
            Some(GuestImageFailureCode::IpswDownloadFailed),
            "retryable failure must stay visible, not masked"
        );
    }

    /// Non-failed states pass through reconciliation untouched.
    #[test]
    fn reconcile_passes_through_non_failed_states() {
        let raw = raw_from_json(r#"{ "phase": "install_macos", "status": "in_progress" }"#);
        let result = reconcile_failure(raw, BOOT_NOW);
        assert_eq!(result.status.as_deref(), Some("in_progress"));
    }
}
