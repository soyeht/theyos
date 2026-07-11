//! Atomic CBOR file I/O under `$THEYOS_STATE_DIR/household/`.
//!
//! Write strategy: write to `<path>.tmp` → fsync → rename → fsync parent dir.
//! All identity files are mode 0600.

use std::fs::{self, File, OpenOptions};
use std::io::{Error, ErrorKind, Write};
use std::path::{Path, PathBuf};

use serde::{Serialize, de::DeserializeOwned};

use crate::cbor;
use crate::error::{HouseholdError, StorageError};

/// Subdirectory under `$THEYOS_STATE_DIR` where identity records live.
pub const HOUSEHOLD_SUBDIR: &str = "household";

#[must_use]
pub fn household_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(HOUSEHOLD_SUBDIR)
}

#[must_use]
pub fn household_record_path(state_dir: &Path) -> PathBuf {
    household_dir(state_dir).join("household_record.cbor")
}

/// Directory holding every member's `MachineCert`, one file per
/// `<m_id>.cbor`. Phase 3 introduced this layout in place of the legacy
/// `machine_cert.cbor` self-cert at the household-dir root; see
/// `specs/003-machine-join/contracts/machine-cert-cbor.md` (Storage section)
/// and the one-shot migration in [`load_state_dir`].
pub const MACHINE_CERTS_SUBDIR: &str = "machine_certs";

#[must_use]
pub fn machine_certs_dir(state_dir: &Path) -> PathBuf {
    household_dir(state_dir).join(MACHINE_CERTS_SUBDIR)
}

/// Path to a member's `MachineCert` under the unified `machine_certs/` layout.
#[must_use]
pub fn machine_cert_for(state_dir: &Path, m_id: &str) -> PathBuf {
    machine_certs_dir(state_dir).join(format!("{m_id}.cbor"))
}

/// Legacy single-self-cert path. Retained ONLY so [`load_state_dir`] can
/// detect and migrate it. New code MUST NOT read or write this path.
#[must_use]
pub fn legacy_machine_cert_path(state_dir: &Path) -> PathBuf {
    household_dir(state_dir).join("machine_cert.cbor")
}

/// Path to the `self_m_id` marker file. The marker is a one-line UTF-8
/// text file holding the `MachineId` of the cert under
/// `machine_certs/<m_id>.cbor` that identifies this machine. Phase 3
/// boot reads this file first so it can locate its own cert under the
/// unified `machine_certs/` layout without scanning the directory.
#[must_use]
pub fn self_m_id_marker_path(state_dir: &Path) -> PathBuf {
    household_dir(state_dir).join("self_m_id")
}

/// Read the `self_m_id` marker. Returns `Ok(None)` if absent (uninitialized
/// state or pre-migration).
pub fn read_self_m_id(state_dir: &Path) -> Result<Option<String>, StorageError> {
    let path = self_m_id_marker_path(state_dir);
    match fs::read_to_string(&path) {
        Ok(s) => {
            let trimmed = s.trim().to_string();
            if trimmed.is_empty() {
                return Err(StorageError::Encoding(HouseholdError::Cbor(format!(
                    "{} present but empty",
                    path.display()
                ))));
            }
            Ok(Some(trimmed))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_to_storage(&e, &path)),
    }
}

/// Atomically write the `self_m_id` marker. Used by `save_self_cert` and by
/// the [`load_state_dir`] migration of `machine_cert.cbor`.
pub fn write_self_m_id(state_dir: &Path, m_id: &str) -> Result<(), StorageError> {
    let path = self_m_id_marker_path(state_dir);
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| io_to_storage(&e, parent))?;
        }
    }
    let tmp = tmp_path_for(&path);
    let mut tmp_file = open_tmp_0600(&tmp)?;
    if let Err(e) = tmp_file.write_all(m_id.as_bytes()) {
        let _ = fs::remove_file(&tmp);
        return Err(io_to_storage(&e, &tmp));
    }
    if let Err(e) = tmp_file.write_all(b"\n") {
        let _ = fs::remove_file(&tmp);
        return Err(io_to_storage(&e, &tmp));
    }
    if let Err(e) = tmp_file.sync_all() {
        let _ = fs::remove_file(&tmp);
        return Err(io_to_storage(&e, &tmp));
    }
    drop(tmp_file);
    fs::rename(&tmp, &path).map_err(|e| io_to_storage(&e, &path))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Path to the active pair-device-window snapshot, written by
/// `theyos install` so the long-running daemon process picks it up at
/// startup. Phase 3 renamed this from `pair_window.cbor` to disambiguate
/// from `pair_machine_window.cbor`.
#[must_use]
pub fn pair_device_window_path(state_dir: &Path) -> PathBuf {
    household_dir(state_dir).join("pair_device_window.cbor")
}

/// Pre-Phase-3 path of the pair-device-window snapshot. Retained only so
/// [`load_state_dir`] can detect a legacy on-disk state and migrate it.
#[must_use]
pub fn legacy_pair_window_path(state_dir: &Path) -> PathBuf {
    household_dir(state_dir).join("pair_window.cbor")
}

#[must_use]
pub fn owner_person_cert_path(state_dir: &Path) -> PathBuf {
    household_dir(state_dir).join("owner_person_cert.cbor")
}

#[must_use]
pub fn household_auth_state_path(state_dir: &Path) -> PathBuf {
    household_dir(state_dir).join("household_auth_state.cbor")
}

#[must_use]
#[cfg(test)]
pub fn claw_vpn_mobile_mesh_path(state_dir: &Path) -> PathBuf {
    household_dir(state_dir).join("claw_vpn_mobile_mesh.cbor")
}

#[cfg(test)]
pub fn write_claw_vpn_mobile_mesh_snapshot(
    state_dir: &Path,
    snapshot: &crate::claw_vpn_mobile_state::ClawVpnMobileMeshSnapshot,
) -> Result<(), StorageError> {
    atomic_write_cbor(&claw_vpn_mobile_mesh_path(state_dir), snapshot)
}

#[cfg(test)]
pub fn read_claw_vpn_mobile_mesh_snapshot(
    state_dir: &Path,
) -> Result<Option<crate::claw_vpn_mobile_state::ClawVpnMobileMeshSnapshot>, StorageError> {
    read_optional_cbor(&claw_vpn_mobile_mesh_path(state_dir))
}

#[cfg(test)]
pub fn delete_claw_vpn_mobile_mesh_snapshot(state_dir: &Path) -> Result<(), StorageError> {
    delete_optional_file(&claw_vpn_mobile_mesh_path(state_dir))
}

/// Path to the Phase 3 finalize-intent preservation marker.
///
/// Written by `owner_approve_handler` before it launches the finalize
/// POST to M2. While this marker exists with a pre-Shamir on-disk record,
/// `recover_partial_phase3_commit` MUST NOT roll back the `.staged`
/// files; T073/T074's `recover_phase3_ceremony` boot driver (Phase 4)
/// needs them to probe M2 and complete or rescind the ceremony per
/// `contracts/shamir-transition.md` §"Recovery on M1 boot".
///
/// Removed by `owner_approve_handler` after `txn.commit()` returns Ok
/// AND the post-Shamir record has been promoted (the canonical commit
/// marker has flipped). Recovery is responsible for clearing it on the
/// roll-forward branch.
#[must_use]
pub fn phase3_finalize_ack_marker_path(state_dir: &Path) -> PathBuf {
    household_dir(state_dir).join("phase3_finalize_ack.marker")
}

#[must_use]
pub fn phase3_finalize_ack_marker_exists(state_dir: &Path) -> bool {
    phase3_finalize_ack_marker_path(state_dir).exists()
}

/// Atomically write the finalize-intent marker. Called by
/// `owner_approve_handler` before the first finalize POST to M2.
///
/// The marker payload is the candidate's `m_id` — operators inspecting
/// the file post-incident can identify which ceremony was in flight.
pub fn write_phase3_finalize_ack_marker(
    state_dir: &Path,
    candidate_m_id: &str,
) -> Result<(), StorageError> {
    let path = phase3_finalize_ack_marker_path(state_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| io_to_storage(&e, parent))?;
    }
    let staged = staged_path_for(&path);
    {
        let mut f = File::create(&staged).map_err(|e| io_to_storage(&e, &staged))?;
        f.write_all(candidate_m_id.as_bytes())
            .map_err(|e| io_to_storage(&e, &staged))?;
        f.sync_all().map_err(|e| io_to_storage(&e, &staged))?;
    }
    fs::rename(&staged, &path).map_err(|e| io_to_storage(&e, &path))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Best-effort marker delete. Missing-file is not an error.
pub fn clear_phase3_finalize_ack_marker(state_dir: &Path) -> Result<(), StorageError> {
    delete_optional_file(&phase3_finalize_ack_marker_path(state_dir))
}

/// Path to the durable copy of the `JoinResponse` M1 is about to POST
/// (or already `POSTed`) to M2's `local/finalize`. Written by
/// `owner_approve_handler` before launching the finalize POST so
/// boot-time `recover_phase3_ceremony` (T073) can re-POST the same
/// bytes after a crash without rebuilding them — `HH_priv` is destroyed
/// during commit, so the encrypted-shard-for-M2 inside `JoinResponse`
/// cannot be reconstructed post-crash.
///
/// Cleared best-effort after the ceremony commits or rolls back.
#[must_use]
pub fn phase3_pending_join_response_path(state_dir: &Path) -> PathBuf {
    household_dir(state_dir).join("phase3_pending_join_response.cbor")
}

#[must_use]
pub fn phase3_pending_join_response_exists(state_dir: &Path) -> bool {
    phase3_pending_join_response_path(state_dir).exists()
}

/// Atomically write the pending `JoinResponse` bytes. Called by
/// `owner_approve_handler` immediately before
/// `write_phase3_finalize_ack_marker` so the recovery driver always
/// observes both files together.
pub fn write_phase3_pending_join_response(
    state_dir: &Path,
    join_response_bytes: &[u8],
) -> Result<(), StorageError> {
    let path = phase3_pending_join_response_path(state_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| io_to_storage(&e, parent))?;
    }
    let staged = staged_path_for(&path);
    {
        let mut f = File::create(&staged).map_err(|e| io_to_storage(&e, &staged))?;
        f.write_all(join_response_bytes)
            .map_err(|e| io_to_storage(&e, &staged))?;
        f.sync_all().map_err(|e| io_to_storage(&e, &staged))?;
    }
    fs::rename(&staged, &path).map_err(|e| io_to_storage(&e, &path))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Read the pending `JoinResponse` bytes back. Returns `Ok(None)` when
/// the file is absent (no in-flight ceremony from this host).
pub fn read_phase3_pending_join_response(
    state_dir: &Path,
) -> Result<Option<Vec<u8>>, StorageError> {
    let path = phase3_pending_join_response_path(state_dir);
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_to_storage(&e, &path)),
    }
}

/// Best-effort delete. Missing-file is not an error.
pub fn clear_phase3_pending_join_response(state_dir: &Path) -> Result<(), StorageError> {
    delete_optional_file(&phase3_pending_join_response_path(state_dir))
}

/// R7.NB2: boot-time stale-marker sweep.
///
/// Called from `load_state_dir` after `recover_partial_phase3_commit`
/// runs. If the on-disk record is post-Shamir AND a marker is still
/// present, the marker is stale (the handler's clear after
/// `commit_preserve_on_error` Ok must have failed transiently, or the
/// crash window between commit and clear hit). Any subsequent boot
/// observing a post-Shamir record + marker should treat the household
/// as fully committed and remove the marker. The post-Shamir gate
/// matters because a marker WITH a pre-Shamir record is the
/// in-flight-ceremony state R6.1 protects.
fn clear_stale_phase3_marker_if_post_shamir(state_dir: &Path) {
    if !phase3_finalize_ack_marker_exists(state_dir) {
        return;
    }
    let record_path = household_record_path(state_dir);
    let post_shamir =
        match read_optional_cbor::<crate::household_record::HouseholdRecord>(&record_path) {
            Ok(Some(r)) => r.shamir_n > 1,
            // Pre-Shamir / missing / undecodable record — leave marker
            // alone. Pre-Shamir + marker is "preserve, T073/T074 will
            // probe"; missing record is uninitialised; undecodable is
            // already a tracing crisis (R6.NB2).
            _ => return,
        };
    if !post_shamir {
        return;
    }
    if let Err(e) = clear_phase3_finalize_ack_marker(state_dir) {
        tracing::warn!(
            stage = "recovery.stale_marker_clear_failed",
            path = %phase3_finalize_ack_marker_path(state_dir).display(),
            error = %e,
            "post-Shamir record on disk but stale marker clear failed; \
             will retry on next boot",
        );
    } else {
        tracing::info!(
            stage = "recovery.stale_marker_cleared",
            path = %phase3_finalize_ack_marker_path(state_dir).display(),
            "post-Shamir household: stale phase3_finalize_ack.marker removed",
        );
    }
    // T073: the pending `JoinResponse` is the recovery driver's
    // re-POST payload. Once the household is post-Shamir, no recovery
    // can re-POST it (HH_priv is gone, but more importantly the
    // ceremony already committed) so the file is dead weight. Clear
    // it best-effort along with the marker.
    if let Err(e) = clear_phase3_pending_join_response(state_dir) {
        tracing::warn!(
            stage = "recovery.stale_pending_join_response_clear_failed",
            path = %phase3_pending_join_response_path(state_dir).display(),
            error = %e,
        );
    }
}

/// Best-effort delete of the pair-device-window snapshot. Used when
/// consuming the token (success path) and on TTL expiry. Missing-file is
/// not an error.
pub fn delete_pair_device_window_snapshot(state_dir: &Path) -> Result<(), StorageError> {
    delete_optional_file(&pair_device_window_path(state_dir))
}

/// Best-effort cleanup helper for an uncommitted owner cert projection.
pub fn delete_owner_person_cert(state_dir: &Path) -> Result<(), StorageError> {
    delete_optional_file(&owner_person_cert_path(state_dir))
}

/// Roll back an owner auth-state commit if its secondary projection cannot be written.
pub fn delete_household_auth_state(state_dir: &Path) -> Result<(), StorageError> {
    delete_optional_file(&household_auth_state_path(state_dir))
}

/// Outcome of a [`load_state_dir`] call. Carries which one-shot migrations
/// fired so callers can `tracing::info!` them once at boot.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct LoadStateOutcome {
    /// `pair_window.cbor` was renamed to `pair_device_window.cbor` (T005).
    pub migrated_pair_device_window: bool,
    /// `machine_cert.cbor` was moved into `machine_certs/<m_id>.cbor` (T005a).
    /// Carries the `m_id` decoded from the migrated cert.
    pub migrated_self_machine_cert: Option<String>,
    /// `self_m_id` marker was reconstructed from a singleton
    /// `machine_certs/<m_id>.cbor` because a previous `save_self_cert`
    /// or migration crashed between the cert and marker promotions.
    /// Carries the recovered `m_id`.
    pub recovered_self_m_id_marker: Option<String>,
    /// `household_root_sole.cbor` was deleted because it was found
    /// alongside a present `shamir/self_shard.cbor`. That state can
    /// only arise from a crash between [`stage_commit_files`]'s commit
    /// step and `CeremonyTxn::commit`'s sole-shard unlink — the
    /// intended last action of the join ceremony. Leaving the
    /// plaintext sole-shard on disk while Shamir state already exists
    /// would be a security regression: a single file would still hold
    /// the household root scalar even though the household has moved
    /// to 2-of-2.
    pub recovered_post_join_sole_shard_deleted: bool,
    /// `recover_partial_phase3_commit` cleaned up after a crash in the
    /// middle of `StagedCommit::commit` for the Phase-3 join ceremony.
    /// `roll_forward` is the count of `.staged` files renamed to their
    /// final paths because the household record on disk was already
    /// post-Shamir (the canonical commit marker). `roll_back` is the
    /// count of `.staged` files unlinked because the household record
    /// was still pre-Shamir (the ceremony was logically not committed
    /// and the partial promotion had to be undone).
    pub partial_phase3_commit_rolled_forward: usize,
    pub partial_phase3_commit_rolled_back: usize,
}

/// Run all idempotent one-shot file-layout migrations and return their
/// outcome. Phase 3 introduces:
///
/// - `pair_window.cbor` → `pair_device_window.cbor` (T005).
/// - `machine_cert.cbor` (root of `<state_dir>/household/`) →
///   `machine_certs/<self_m_id>.cbor` (T005a).
///
/// Both branches are no-ops when the legacy file is absent or the new path
/// already exists. Calls are safe across concurrent invocations because the
/// underlying `std::fs::rename` is atomic on POSIX. Restart-after-crash:
/// either the legacy or the new path is observed, never both.
///
/// Production code MUST call this once at process startup, before any
/// reader touches `pair_device_window.cbor` or
/// `machine_certs/<m_id>.cbor`.
pub fn load_state_dir(state_dir: &Path) -> Result<LoadStateOutcome, StorageError> {
    let migrated_pair_device_window = migrate_pair_device_window(state_dir)?;
    let migrated_self_machine_cert = migrate_self_machine_cert(state_dir)?;
    // R7.4: `recover_partial_phase3_commit` MUST run BEFORE
    // `recover_self_m_id_marker`. Under the M2-side staged ordering
    // (founder cert is the FIRST file promoted), a crash that promoted
    // only the founder cert leaves a singleton `machine_certs/<founder_m_id>.cbor`
    // visible to `recover_self_m_id_marker` — which would write a
    // `self_m_id` pointing to the founder. Roll-back must run first so
    // it unlinks the orphan founder cert before marker recovery
    // observes it.
    //
    // R6.5: `recover_partial_phase3_commit` ALSO MUST run BEFORE
    // `recover_post_join_sole_shard`. Under the post-R5.7 ordering
    // (`[cert, self_shard, record]`), a crash between renames [2] and [3]
    // leaves `self_shard` at its final path while the record is still
    // pre-Shamir AND the legacy `household_root_sole.cbor` is still
    // present (it's only unlinked AFTER `staged.commit()` returns Ok in
    // `pair_machine.rs`). The roll-back branch of
    // `recover_partial_phase3_commit` unlinks the orphan `self_shard.cbor`
    // when both `sole` and `self_shard` are present, restoring the
    // pre-Shamir invariant. Running `recover_post_join_sole_shard` first
    // would mis-classify that crash as post-Shamir and delete `sole`,
    // permanently losing the pre-Shamir root.
    let (partial_phase3_commit_rolled_forward, partial_phase3_commit_rolled_back) =
        recover_partial_phase3_commit(state_dir);
    let recovered_self_m_id_marker = recover_self_m_id_marker(state_dir)?;
    let recovered_post_join_sole_shard_deleted = recover_post_join_sole_shard(state_dir)?;
    // R7.NB2: clear the finalize-intent marker unconditionally when
    // the on-disk record is post-Shamir. The handler clears it
    // best-effort after `commit_preserve_on_error` Ok, but a transient
    // FS error there would leave a stale marker indefinitely under
    // the previous design (marker clear lived inside the
    // `recover_partial_phase3_commit` post-Shamir branch and was only
    // reached when `staged.is_empty() == false`, which is the rare
    // post-crash path; the common Ok path observes empty `.staged` on
    // next boot and short-circuited before the clear).
    clear_stale_phase3_marker_if_post_shamir(state_dir);
    Ok(LoadStateOutcome {
        migrated_pair_device_window,
        migrated_self_machine_cert,
        recovered_self_m_id_marker,
        recovered_post_join_sole_shard_deleted,
        partial_phase3_commit_rolled_forward,
        partial_phase3_commit_rolled_back,
    })
}

/// Resolve the "sole-shard XOR Shamir state" boot invariant.
///
/// The Phase 3 join ceremony's commit step promotes every staged file
/// (`household_record.cbor`, the candidate `MachineCert`, M1's
/// encrypted `self_shard.cbor`) and then — as the **last** action —
/// deletes the legacy plaintext root at `household_root_sole.cbor`.
/// The unlink is intentionally last so a crash anywhere up to and
/// including the staged commit can be rolled back into the 1-machine
/// state by leaving the sole-shard intact.
///
/// If, however, the ceremony successfully committed the staged set
/// (so `shamir/self_shard.cbor` is now durable on disk) but crashed
/// **before** the unlink landed, we end up with **both** files alive:
///
/// - `household_root_sole.cbor` — plaintext household root scalar.
/// - `shamir/self_shard.cbor` — encrypted M1 share of the same scalar.
///
/// That is a **security regression**. The plaintext root would still
/// be reachable on a single read of one file, defeating the whole
/// point of the destructive 2-of-2 transition. The recovery probe
/// here closes the window: when both files exist, the Shamir state is
/// authoritative (the commit landed) and the sole-shard MUST be
/// deleted.
///
/// Returns `Ok(true)` if the cleanup ran, `Ok(false)` otherwise (steady
/// state — only one of the two files exists, or neither).
///
/// R6.5: also gates on `record.shamir_n > 1`. R5.7 reordered
/// `CeremonyTxn::prepare`'s `staged_files` so the record-flip is the
/// canonical commit marker. Under that ordering, a crash that promoted
/// `self_shard.cbor` but not `household_record.cbor` would leave both
/// `sole` and `self_shard` present with a pre-Shamir record. Without the
/// `shamir_n > 1` gate, this probe would mis-classify the crash as
/// committed and delete `sole` — irreversibly losing the pre-Shamir root.
/// The record is the source of truth for "is this household committed";
/// the file-presence check is now belt-and-suspenders. The orphan
/// `self_shard.cbor` for that crash is unlinked by
/// `recover_partial_phase3_commit`'s roll-back branch, which now runs
/// FIRST in `load_state_dir`.
fn recover_post_join_sole_shard(state_dir: &Path) -> Result<bool, StorageError> {
    // Inline path construction matches `pair_machine.rs` so we don't
    // create a circular dep into that module from here.
    let sole = household_dir(state_dir).join("household_root_sole.cbor");
    let shamir_self = household_dir(state_dir)
        .join("shamir")
        .join("self_shard.cbor");
    if !(sole.exists() && shamir_self.exists()) {
        return Ok(false);
    }
    let record_path = household_record_path(state_dir);
    let record_post_shamir =
        match read_optional_cbor::<crate::household_record::HouseholdRecord>(&record_path) {
            Ok(Some(r)) => r.shamir_n > 1,
            Ok(None) => false,
            Err(e) => {
                // R6.NB2: undecodable record is a crisis signal, not a
                // default-to-pre-Shamir. Refuse to delete `sole` here —
                // the operator-visible WARN above the early return makes
                // the boot-time diagnosis explicit.
                tracing::error!(
                    stage = "recovery.post_join_sole_shard.record_undecodable",
                    path = %record_path.display(),
                    error = %e,
                    hint = "refusing to unlink household_root_sole.cbor; \
                            operator must hand-validate household state before next boot",
                );
                return Ok(false);
            }
        };
    if !record_post_shamir {
        // The crash promoted `self_shard.cbor` but the canonical
        // commit marker (`record.shamir_n > 1`) hasn't flipped.
        // `recover_partial_phase3_commit`'s roll-back branch will
        // unlink the orphan `self_shard.cbor` (it ran before us).
        // Either way, do NOT delete `sole` — that would lose the
        // pre-Shamir root.
        return Ok(false);
    }
    fs::remove_file(&sole).map_err(|e| io_to_storage(&e, &sole))?;
    if let Some(parent) = sole.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    tracing::warn!(
        stage = "recovery.post_join_sole_shard_cleanup",
        path = %sole.display(),
        "deleted leftover household_root_sole.cbor — Shamir state already present"
    );
    Ok(true)
}

/// Boot-time recovery for a Phase-3 join ceremony whose
/// `StagedCommit::commit` crashed mid-promotion. The Phase-3
/// ceremony stages three files (candidate `MachineCert`, M1's
/// encrypted `self_shard.cbor`, and the updated
/// `household_record.cbor`) and renames them in that order; the
/// record is the canonical "is committed" marker. If the process
/// crashes mid-commit, some `.staged` siblings of those finals can
/// linger:
///
/// - **`household_record.cbor` is post-Shamir** (`shamir_n > 1`):
///   the marker has flipped, so the ceremony is logically committed;
///   any remaining `.staged` files are roll-forward orphans that
///   MUST be promoted to their final paths to complete the ceremony.
/// - **`household_record.cbor` is pre-Shamir** (`shamir_n == 1` or
///   missing): the marker has not flipped, so the ceremony is
///   logically rolled back; any `.staged` files (and any earlier
///   final-path siblings introduced by this ceremony) MUST be
///   unlinked. The candidate's `m_id` is recoverable from
///   `household_record.cbor.staged` (which holds the would-have-been
///   record with the new `members[]`); using that, the
///   partially-promoted candidate cert at
///   `machine_certs/<candidate_m_id>.cbor` is unlinked too.
///
/// Returns `(roll_forward_count, roll_back_count)`.
fn recover_partial_phase3_commit(state_dir: &Path) -> (usize, usize) {
    let staged = collect_phase3_staged(state_dir);
    if staged.is_empty() {
        return (0, 0);
    }
    let record_path = household_record_path(state_dir);
    let post_shamir =
        match read_optional_cbor::<crate::household_record::HouseholdRecord>(&record_path) {
            Ok(Some(r)) => r.shamir_n > 1,
            Ok(None) => false,
            Err(e) => {
                // R6.NB2: an undecodable record (truncated CBOR, partial
                // write that survived `fsync`, schema drift) is a crisis
                // signal, not "default to pre-Shamir → roll back". The
                // roll-back branch unlinks `.staged` and the partial
                // candidate cert, which on a healthy-but-undecodable
                // household would destroy ceremony evidence. Skip
                // recovery entirely; the operator-visible ERROR carries
                // the diagnosis. Subsequent boots through `try_load_existing`
                // / `bootstrap_or_load` will fail loudly on the same
                // record decode and refuse to start, which is the right
                // safety posture.
                tracing::error!(
                    stage = "recovery.partial_phase3_commit.record_undecodable",
                    path = %record_path.display(),
                    error = %e,
                    hint = "skipping Phase-3 .staged recovery; .staged files preserved; \
                            operator must hand-validate household state",
                );
                return (0, 0);
            }
        };
    // R6.1/R8: finalize-intent preservation gate — when the on-disk
    // record is still pre-Shamir BUT a `phase3_finalize_ack.marker`
    // exists, M1 has launched or may have launched finalize with M2.
    // The `.staged` files MUST survive on disk. T073/T074 will use
    // them to drive `recover_phase3_ceremony` per
    // `contracts/shamir-transition.md` §"Recovery on M1 boot".
    // The roll-forward branch below (post-Shamir record) is unaffected
    // — once the record has flipped, recovery completes the ceremony.
    if !post_shamir && phase3_finalize_ack_marker_exists(state_dir) {
        let marker = phase3_finalize_ack_marker_path(state_dir);
        tracing::error!(
            stage = "recovery.partial_phase3_commit.post_finalize_ack_pending",
            marker = %marker.display(),
            staged_count = staged.len(),
            hint = "M1 finalize outcome is in-flight or ambiguous; preserving .staged for \
                    T073/T074 recover_phase3_ceremony driver — do not unlink",
        );
        return (0, 0);
    }

    if post_shamir {
        let mut rolled_forward = 0_usize;
        for staged_path in &staged {
            let final_path = strip_staged_suffix(staged_path);
            if final_path.exists() {
                // Already promoted; just clean up the duplicate
                // `.staged` sibling.
                let _ = fs::remove_file(staged_path);
                continue;
            }
            if let Err(e) = fs::rename(staged_path, &final_path) {
                tracing::warn!(
                    stage = "recovery.partial_phase3_commit.roll_forward_failed",
                    staged = %staged_path.display(),
                    error = %e,
                );
                continue;
            }
            if let Some(parent) = final_path.parent() {
                if let Ok(dir) = File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
            tracing::warn!(
                stage = "recovery.partial_phase3_commit.roll_forward",
                final_path = %final_path.display(),
                "promoted leftover .staged after post-Shamir record",
            );
            rolled_forward += 1;
        }
        // R6.1 / R7.NB2: marker clear is hoisted into
        // `clear_stale_phase3_marker_if_post_shamir` called from
        // `load_state_dir` so it runs on every post-Shamir boot,
        // not only when `.staged` were rolled forward. Leaving the
        // clear here would be redundant; removing it is the
        // simplest way to avoid duplicate `delete_optional_file`
        // calls on the boot path.
        return (rolled_forward, 0);
    }

    // Roll-back path. Distinguish the two ceremony sides by the
    // shape of the on-disk record:
    //   - **M1 side** — `existing_record is Some` with `shamir_n == 1`.
    //     M1 is the founding machine; pre-ceremony state has the
    //     `household_record.cbor` at `shamir_n=1` and a
    //     `household_root_sole.cbor`. Roll-back unlinks the partially
    //     promoted candidate cert (identified via the staged record's
    //     `members[]` minus the on-disk `members[]`), and the orphan
    //     `self_shard.cbor` if the legacy `sole` still survives.
    //   - **M2 side** — `existing_record is None`. M2 is the candidate
    //     pre-household; pre-ceremony state has no record at all and
    //     no `sole`. Its staged set is wider (founder cert + own cert
    //     + `self_m_id` + `self_shard` + `pair_machine_window` +
    //     optional push-token + record). Roll-back must unlink ALL
    //     partially-promoted final-path siblings, including the
    //     founder cert (M2 has no other reason to hold it),
    //     `self_m_id` (no pre-ceremony identity), `self_shard.cbor`
    //     (no `sole` to gate on), `pair_machine_window.cbor` (window
    //     was about to be `Committed`), and `owner_push_token.cbor`.
    //     Without this, R7.4 leaves M2 in an inconsistent post-crash
    //     state where partial files survive and recovery cannot
    //     re-enter the ceremony cleanly.
    let on_disk_record_present = matches!(
        read_optional_cbor::<crate::household_record::HouseholdRecord>(&record_path),
        Ok(Some(_))
    );
    let staged_record_path = staged_path_for(&record_path);
    if let Ok(Some(staged_record)) =
        read_optional_cbor::<crate::household_record::HouseholdRecord>(&staged_record_path)
    {
        // The staged record's `members` carries both M1 and the
        // would-have-been candidate. On M1 side (record present at
        // shamir_n=1), only the candidate is "new". On M2 side
        // (record absent), every staged member is "new" — both the
        // founder cert and M2's own cert get unlinked (M2 has no
        // pre-ceremony reason to hold them).
        let on_disk_members: Vec<String> =
            match read_optional_cbor::<crate::household_record::HouseholdRecord>(&record_path) {
                Ok(Some(r)) => r
                    .members
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
                _ => Vec::new(),
            };
        for candidate in staged_record
            .members
            .iter()
            .filter(|m| !on_disk_members.iter().any(|o| o == m.as_str()))
        {
            let candidate_cert = machine_cert_for(state_dir, candidate.as_str());
            if candidate_cert.exists() {
                let _ = fs::remove_file(&candidate_cert);
                tracing::warn!(
                    stage = "recovery.partial_phase3_commit.roll_back",
                    path = %candidate_cert.display(),
                    "unlinked partially-promoted machine cert from rolled-back ceremony",
                );
            }
        }
    }
    let mut rolled_back = 0_usize;
    for staged_path in &staged {
        if fs::remove_file(staged_path).is_ok() {
            tracing::warn!(
                stage = "recovery.partial_phase3_commit.roll_back",
                staged = %staged_path.display(),
                "unlinked .staged from rolled-back ceremony",
            );
            rolled_back += 1;
        }
    }
    // Common to both sides: the partially-promoted `self_shard.cbor`
    // would confuse `recover_post_join_sole_shard` on a future boot.
    // On M1 the sole-shard is the gate; on M2 there is no sole, but
    // a stray `self_shard` would also be an orphan — unlink it
    // either way.
    let self_shard = household_dir(state_dir)
        .join("shamir")
        .join("self_shard.cbor");
    let sole = household_dir(state_dir).join("household_root_sole.cbor");
    let m1_side_orphan_self_shard = self_shard.exists() && sole.exists();
    let m2_side_orphan_self_shard = self_shard.exists() && !on_disk_record_present;
    if m1_side_orphan_self_shard || m2_side_orphan_self_shard {
        let _ = fs::remove_file(&self_shard);
        tracing::warn!(
            stage = "recovery.partial_phase3_commit.roll_back",
            path = %self_shard.display(),
            side = if on_disk_record_present { "m1" } else { "m2" },
            "unlinked partially-promoted self_shard.cbor",
        );
    }
    // R7.4: M2-side extras. None of these have an M1 analogue —
    // on M1, `self_m_id` predates the ceremony (set at install),
    // `pair_machine_window.cbor` is also pre-existing for the
    // founder window, and `owner_push_token.cbor` was registered
    // during Phase 2 pair-device. Touching them on M1-side rollback
    // would be destructive. Gate on `!on_disk_record_present`.
    if !on_disk_record_present {
        for path in [
            self_m_id_marker_path(state_dir),
            crate::pair_machine::pair_machine_window_path(state_dir),
            crate::owner_events::owner_push_token_path(state_dir),
        ] {
            if path.exists() {
                let _ = fs::remove_file(&path);
                tracing::warn!(
                    stage = "recovery.partial_phase3_commit.roll_back",
                    path = %path.display(),
                    side = "m2",
                    "unlinked M2-side partially-promoted ceremony artifact",
                );
            }
        }
    }
    (0, rolled_back)
}

fn collect_phase3_staged(state_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_staged_in(&household_dir(state_dir), &mut out);
    collect_staged_in(&household_dir(state_dir).join("shamir"), &mut out);
    collect_staged_in(&machine_certs_dir(state_dir), &mut out);
    out
}

fn strip_staged_suffix(path: &Path) -> PathBuf {
    let s = path.as_os_str().to_string_lossy().to_string();
    if let Some(stripped) = s.strip_suffix(".staged") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

/// Reconstruct the `self_m_id` marker file when it is missing despite a
/// well-formed cert file living under `machine_certs/<m_id>.cbor`. This
/// covers the narrow race window between [`stage_commit_files`]'s two
/// renames that [`crate::machine_cert::save_self_cert`] uses, as well as
/// crashes mid-migration of the legacy `machine_cert.cbor`.
///
/// Returns `Ok(Some(m_id))` if recovery wrote the marker. Returns
/// `Ok(None)` when:
/// - the marker is already present (no recovery needed),
/// - `machine_certs/` is empty (uninitialized state),
/// - or `machine_certs/` holds more than one cert (post-Phase-3 state, in
///   which case the marker should have been authoritative — leave the
///   inconsistency to the operator).
fn recover_self_m_id_marker(state_dir: &Path) -> Result<Option<String>, StorageError> {
    if read_self_m_id(state_dir)?.is_some() {
        return Ok(None);
    }
    let certs_dir = machine_certs_dir(state_dir);
    let entries = match fs::read_dir(&certs_dir) {
        Ok(it) => it,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_to_storage(&e, &certs_dir)),
    };
    let mut found: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("cbor") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            // Skip orphan staged files (`<m_id>.cbor.staged` extension is
            // "staged", not "cbor", but defensive: also skip empty stems).
            if !stem.is_empty() {
                found.push(stem.to_string());
            }
        }
    }
    if found.len() != 1 {
        // Operator-visible diagnostic: marker is missing AND we can't
        // unambiguously pick a singleton cert. Common cases:
        //   - 0 certs: the state dir is uninitialized; benign.
        //   - 2+ certs: post-Phase-3 state where the marker was the
        //     authoritative record of identity. Recovery refuses to
        //     guess; the operator must inspect and run a manual repair.
        if !found.is_empty() {
            tracing::warn!(
                stage = "recovery.self_m_id_marker.ambiguous",
                state_dir = %state_dir.display(),
                cert_count = found.len(),
                "self_m_id marker missing and machine_certs/ holds multiple certs — refusing to guess identity"
            );
        }
        return Ok(None);
    }
    let m_id = found.into_iter().next().expect("len == 1 above");
    tracing::warn!(
        stage = "recovery.self_m_id_marker.reconstructed",
        state_dir = %state_dir.display(),
        m_id = %m_id,
        "rebuilt self_m_id marker from singleton machine_certs/<m_id>.cbor"
    );
    write_self_m_id(state_dir, &m_id)?;
    Ok(Some(m_id))
}

fn migrate_pair_device_window(state_dir: &Path) -> Result<bool, StorageError> {
    let legacy = legacy_pair_window_path(state_dir);
    let target = pair_device_window_path(state_dir);
    if !legacy.exists() {
        return Ok(false);
    }
    if target.exists() {
        // Both present — the new path wins (Adoption-First, Constitution IV).
        // Drop the stale legacy file so no future reader sees it.
        delete_optional_file(&legacy)?;
        return Ok(false);
    }
    fs::rename(&legacy, &target).map_err(|e| io_to_storage(&e, &target))?;
    if let Some(parent) = target.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(true)
}

fn migrate_self_machine_cert(state_dir: &Path) -> Result<Option<String>, StorageError> {
    let legacy = legacy_machine_cert_path(state_dir);
    if !legacy.exists() {
        return Ok(None);
    }
    // Decode the legacy cert to learn its m_id; the new location is
    // `machine_certs/<m_id>.cbor` per
    // `contracts/machine-cert-cbor.md`'s Storage section.
    let cert: crate::machine_cert::MachineCert = read_optional_cbor(&legacy)?.ok_or_else(|| {
        StorageError::Encoding(HouseholdError::Cbor(format!(
            "decode legacy {}: file vanished mid-migration",
            legacy.display()
        )))
    })?;
    let m_id_str = cert.m_id.to_string();
    let new_path = machine_cert_for(state_dir, &m_id_str);
    if new_path.exists() {
        // Already migrated by a prior boot — drop the stale legacy file
        // and ensure the marker reflects the canonical id.
        delete_optional_file(&legacy)?;
        if read_self_m_id(state_dir)?.as_deref() != Some(m_id_str.as_str()) {
            write_self_m_id(state_dir, &m_id_str)?;
        }
        return Ok(None);
    }
    let certs_dir = machine_certs_dir(state_dir);
    if !certs_dir.exists() {
        fs::create_dir_all(&certs_dir).map_err(|e| io_to_storage(&e, &certs_dir))?;
    }
    fs::rename(&legacy, &new_path).map_err(|e| io_to_storage(&e, &new_path))?;
    if let Ok(dir) = File::open(&certs_dir) {
        let _ = dir.sync_all();
    }
    if let Some(parent) = legacy.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    write_self_m_id(state_dir, &m_id_str)?;
    Ok(Some(m_id_str))
}

/// Atomically encode `value` as canonical CBOR and write to `path` (mode 0600).
///
/// Tolerates ENOSPC at the temporary-write stage by cleaning the partial
/// file before returning [`StorageError::OutOfSpace`].
pub fn atomic_write_cbor<T: Serialize>(path: &Path, value: &T) -> Result<(), StorageError> {
    atomic_write_cbor_impl(path, value, None)
}

/// Test hook for injecting a failure after the temporary file is opened but
/// before any payload bytes are written.
#[doc(hidden)]
pub fn atomic_write_cbor_with_tmp_write_error<T: Serialize>(
    path: &Path,
    value: &T,
    error: Error,
) -> Result<(), StorageError> {
    atomic_write_cbor_impl(path, value, Some(error))
}

fn atomic_write_cbor_impl<T: Serialize>(
    path: &Path,
    value: &T,
    injected_tmp_write_error: Option<Error>,
) -> Result<(), StorageError> {
    let bytes = cbor::to_canonical_vec(value).map_err(StorageError::Encoding)?;

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| io_to_storage(&e, parent))?;
        }
    }

    let tmp_path = tmp_path_for(path);

    // Open with mode 0600 (Unix).
    let mut tmp_file = open_tmp_0600(&tmp_path)?;

    if let Some(e) = injected_tmp_write_error {
        let _ = fs::remove_file(&tmp_path);
        return Err(io_to_storage(&e, &tmp_path));
    }

    if let Err(e) = tmp_file.write_all(&bytes) {
        let _ = fs::remove_file(&tmp_path);
        return Err(io_to_storage(&e, &tmp_path));
    }
    if let Err(e) = tmp_file.flush() {
        let _ = fs::remove_file(&tmp_path);
        return Err(io_to_storage(&e, &tmp_path));
    }
    if let Err(e) = tmp_file.sync_all() {
        let _ = fs::remove_file(&tmp_path);
        return Err(io_to_storage(&e, &tmp_path));
    }
    drop(tmp_file);

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(io_to_storage(&e, path));
    }

    if let Some(parent) = path.parent() {
        // fsync the parent dir so the rename is durable.
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 3 two-phase commit (T029/T030)
// ---------------------------------------------------------------------------

/// A set of files staged for a two-phase commit. Each input is written
/// to `<path>.staged`; on [`StagedCommit::commit`] every staged file
/// is renamed to its final path and the parent directory is fsynced.
/// On [`StagedCommit::rollback`] every staged file is unlinked and no
/// `<path>` is touched.
#[must_use]
pub struct StagedCommit {
    items: Vec<StagedItem>,
    committed: bool,
}

struct StagedItem {
    final_path: PathBuf,
    staged_path: PathBuf,
}

/// Suffix used for staged files (`<path>.staged`).
pub const STAGED_SUFFIX: &str = ".staged";

#[must_use]
pub fn staged_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".staged");
    PathBuf::from(s)
}

/// Stage a set of `<path, bytes>` pairs onto disk via `<path>.staged`
/// files. The returned [`StagedCommit`] handle MUST eventually be
/// either committed or rolled back; dropping it without commit leaks
/// the staged files (boot recovery picks them up — see
/// [`detect_orphan_staged_files`]).
///
/// Durability: every `.staged` file is `fsync`'d, AND its containing
/// directory is `fsync`'d (to make the directory entry survive a
/// crash). Without the directory `fsync`, the kernel may have the
/// inode + data on disk while the directory entry pointing at them is
/// still cache-only. A power loss in that window leaks the inode
/// invisibly: `detect_orphan_staged_files` would not see it on the
/// next boot, and the file content would never be reclaimed.
pub fn stage_commit_files(items: &[(PathBuf, Vec<u8>)]) -> Result<StagedCommit, StorageError> {
    use std::collections::HashSet;
    let mut staged = Vec::with_capacity(items.len());
    let mut parents_to_fsync: HashSet<PathBuf> = HashSet::new();
    for (final_path, bytes) in items {
        if let Some(parent) = final_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| io_to_storage(&e, parent))?;
            }
            parents_to_fsync.insert(parent.to_path_buf());
        }
        let staged_path = staged_path_for(final_path);
        let mut tmp = open_tmp_0600(&staged_path)?;
        if let Err(e) = tmp.write_all(bytes) {
            let _ = fs::remove_file(&staged_path);
            return Err(io_to_storage(&e, &staged_path));
        }
        if let Err(e) = tmp.sync_all() {
            let _ = fs::remove_file(&staged_path);
            return Err(io_to_storage(&e, &staged_path));
        }
        drop(tmp);
        staged.push(StagedItem {
            final_path: final_path.clone(),
            staged_path,
        });
    }
    // fsync every distinct parent directory exactly once so the
    // freshly-created `.staged` direntries are durable.
    for parent in &parents_to_fsync {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(StagedCommit {
        items: staged,
        committed: false,
    })
}

impl StagedCommit {
    /// Atomically promote every staged file. Renames are sequential
    /// per POSIX guarantees; the parent directory of each final path
    /// is fsynced so the commit survives a crash mid-operation.
    pub fn commit(mut self) -> Result<(), StorageError> {
        let result = self.commit_inner();
        if result.is_ok() {
            self.committed = true;
        }
        result
    }

    /// Leave every staged file on disk and disarm Drop cleanup. Used
    /// when the caller has durable evidence that a recovery driver must
    /// decide whether to roll forward or roll back.
    pub fn preserve_for_recovery(mut self) {
        self.committed = true;
    }

    /// Like [`commit`], but on partial failure does NOT unlink the
    /// remaining `.staged` set. Used after M1 has launched finalize
    /// with M2 where the staged evidence MUST survive on disk for
    /// boot-time recovery to probe M2 and complete or rescind the
    /// ceremony per
    /// `contracts/shamir-transition.md` §"Recovery on M1 boot". The
    /// `phase3_finalize_ack.marker` is the gate that recovery uses to
    /// know which preserved-staged-set is in-flight.
    ///
    /// Drop is disarmed regardless of outcome — on Ok every `.staged`
    /// has already been consumed by `fs::rename`, on Err the partial
    /// promotion is INTENTIONALLY left for recovery.
    ///
    /// [`commit`]: Self::commit
    pub fn commit_preserve_on_error(mut self) -> Result<(), StorageError> {
        let result = self.commit_inner();
        // Disarm Drop in BOTH outcomes. R7.1: on Err the standard
        // `commit` drop would unlink the surviving `.staged`,
        // destroying the recovery evidence; here we leave them on
        // disk so `recover_partial_phase3_commit` can preserve or
        // roll forward based on the `phase3_finalize_ack.marker` +
        // `record.shamir_n` state at next boot.
        self.committed = true;
        result
    }

    fn commit_inner(&mut self) -> Result<(), StorageError> {
        for item in &self.items {
            fs::rename(&item.staged_path, &item.final_path)
                .map_err(|e| io_to_storage(&e, &item.final_path))?;
            if let Some(parent) = item.final_path.parent() {
                if let Ok(dir) = File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
        Ok(())
    }

    /// Discard every staged file. Idempotent on missing files.
    pub fn rollback(mut self) {
        for item in &self.items {
            let _ = fs::remove_file(&item.staged_path);
        }
        self.committed = true; // suppress drop-leak warning
    }
}

impl Drop for StagedCommit {
    fn drop(&mut self) {
        if !self.committed {
            // Best-effort cleanup — boot recovery will see the files
            // and decide based on the wider ceremony state.
            for item in &self.items {
                let _ = fs::remove_file(&item.staged_path);
            }
        }
    }
}

/// Boot-time scan: list every `*.staged` file under `state_dir/household`,
/// including the `shamir/` and `machine_certs/` subdirectories where the
/// Phase 3 ceremony stages files. Phase-3-staged files left after a crash
/// (e.g., `machine_certs/<m_id>.cbor.staged`) MUST be detected so the
/// caller can decide whether to roll forward or roll back.
#[must_use]
pub fn detect_orphan_staged_files(state_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_staged_in(&household_dir(state_dir), &mut out);
    // Subdirectories that participate in the Phase 3 staged commit set.
    collect_staged_in(&household_dir(state_dir).join("shamir"), &mut out);
    collect_staged_in(&machine_certs_dir(state_dir), &mut out);
    out
}

fn collect_staged_in(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.to_string_lossy().ends_with(STAGED_SUFFIX) {
            out.push(path);
        }
    }
}

/// Read a CBOR file and decode into `T`. Returns `Ok(None)` if the file does
/// not exist.
pub fn read_optional_cbor<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, StorageError> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_to_storage(&e, path)),
    };
    let value: T = cbor::from_canonical_slice(&bytes).map_err(|e| {
        StorageError::Encoding(HouseholdError::Cbor(format!(
            "decode {}: {e}",
            path.display()
        )))
    })?;
    Ok(Some(value))
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

fn open_tmp_0600(tmp_path: &Path) -> Result<File, StorageError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(tmp_path).map_err(|e| io_to_storage(&e, tmp_path))
}

fn delete_optional_file(path: &Path) -> Result<(), StorageError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_to_storage(&e, path)),
    }
}

fn io_to_storage(e: &std::io::Error, path: &Path) -> StorageError {
    match e.kind() {
        ErrorKind::PermissionDenied => StorageError::PermissionDenied {
            path: path.to_owned(),
            hint: "Check that the running user can write to the household state directory.".into(),
        },
        ErrorKind::StorageFull => StorageError::OutOfSpace {
            path: path.to_owned(),
            hint: "Free disk space and retry `theyos install`.".into(),
        },
        _ => {
            // ENOSPC may surface as Other on some platforms; sniff the message.
            let msg = e.to_string();
            if msg.contains("No space left") || msg.contains("ENOSPC") {
                return StorageError::OutOfSpace {
                    path: path.to_owned(),
                    hint: "Free disk space and retry `theyos install`.".into(),
                };
            }
            StorageError::Io {
                path: path.to_owned(),
                kind: format!("{:?}", e.kind()),
                hint: msg,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::tempdir;

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct Tiny(u32, String);

    #[test]
    fn atomic_round_trip() {
        let td = tempdir().unwrap();
        let path = td.path().join("nest").join("tiny.cbor");
        let value = Tiny(7, "foo".into());
        atomic_write_cbor(&path, &value).unwrap();
        let back: Option<Tiny> = read_optional_cbor(&path).unwrap();
        assert_eq!(Some(value), back);
    }

    #[test]
    fn claw_vpn_mobile_mesh_snapshot_round_trip_is_private_file() {
        use crate::claw_vpn_mobile_state::{
            ClawVpnMobileAclGrant, ClawVpnMobileClawId, ClawVpnMobileDeviceId,
            ClawVpnMobileMemberId, ClawVpnMobileMesh, ClawVpnMobileOfferToken,
            ClawVpnMobileRendezvousToken,
        };

        let td = tempdir().unwrap();
        let member = ClawVpnMobileMemberId::try_new("member-alpha").unwrap();
        let device = ClawVpnMobileDeviceId::try_new("device-alpha").unwrap();
        let claw = ClawVpnMobileClawId::try_new("claw-alpha").unwrap();
        let grant = ClawVpnMobileAclGrant::new(member, device.clone(), claw.clone());
        let mut mesh = ClawVpnMobileMesh::new(60).unwrap();
        assert!(mesh.enroll_device(device));
        assert!(mesh.set_claw_available(claw));
        assert!(mesh.grant(grant.clone()));
        let offer_token =
            ClawVpnMobileOfferToken::try_new("0123456789abcdef0123456789abcdef").unwrap();
        let rendezvous_token =
            ClawVpnMobileRendezvousToken::try_new("abcdef0123456789abcdef0123456789").unwrap();
        mesh.mint_offer_with_token(&grant, 10, offer_token.clone())
            .unwrap();
        let session = mesh
            .consume_offer_token(&offer_token, &grant, 20, rendezvous_token)
            .unwrap();

        let snapshot = mesh.snapshot();
        write_claw_vpn_mobile_mesh_snapshot(td.path(), &snapshot).unwrap();
        let path = claw_vpn_mobile_mesh_path(td.path());
        assert_eq!(
            path.file_name().and_then(std::ffi::OsStr::to_str),
            Some("claw_vpn_mobile_mesh.cbor")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let loaded = read_claw_vpn_mobile_mesh_snapshot(td.path())
            .unwrap()
            .unwrap();
        let restored = ClawVpnMobileMesh::from_snapshot(loaded).unwrap();
        assert!(restored.has_active_session(session));

        delete_claw_vpn_mobile_mesh_snapshot(td.path()).unwrap();
        assert!(
            read_claw_vpn_mobile_mesh_snapshot(td.path())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn read_returns_none_when_absent() {
        let td = tempdir().unwrap();
        let path = td.path().join("absent.cbor");
        let v: Option<Tiny> = read_optional_cbor(&path).unwrap();
        assert!(v.is_none());
    }

    #[test]
    fn no_orphan_tmp_after_success() {
        let td = tempdir().unwrap();
        let path = td.path().join("ok.cbor");
        atomic_write_cbor(&path, &Tiny(1, "a".into())).unwrap();
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        assert!(!std::path::Path::new(&tmp).exists());
    }
}
