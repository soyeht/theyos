//! Real `mesh_session_core_rs::intent::IntentNonceLedger` over
//! household-rs's `MeshIntentNonceLedger` (Lane R, @daisy, contract
//! verified by @delia/@ilia 2026-08-05 against `6d1ce46c`: `TrustedWallFloor`
//! has no public constructor — `from_roster_observation` is private, and
//! its only `#[cfg(test)] pub(crate)` escape hatch is unreachable from
//! here — so the floor this bridge uses must come from
//! `MachineRosterCoordinator::current_snapshot_with_trusted_wall_floor`,
//! never be built by hand; and `MeshIntentNonceKey`'s own doc — "Canonical
//! replay key. Channel and digest deliberately do not appear here." —
//! confirms the same key/evidence split core's own trait already keeps).
//!
//! Three real mismatches this bridge closes:
//!
//! - **Key projection**: core's `IntentNonceKey` (opaque accessors only)
//!   must become household's `MeshIntentNonceKey::new(...)`, which is
//!   fallible (its own id/delegated-key-id validation) where core's
//!   accessors already assume well-formed data.
//! - **Evidence bundling**: core passes `not_after`/`digest`/`channel` as
//!   separate arguments; household bundles them into one
//!   `MeshIntentNonceEvidence::new(channel, digest, not_after)` — also
//!   fallible (`not_after` must be non-zero).
//! - **Channel type**: core's `ExpectedChannel` and household's
//!   `MeshIntentChannel` are two distinct `Dev`/`Release` enums with no
//!   existing conversion anywhere in the repo — mapped directly here.
//!
//! `consume` itself is infallible on the household side
//! (`MeshIntentNonceLedger::consume` returns `MeshIntentNonceConsumeOutcome`
//! directly, no `Result`) where core's trait wants
//! `Result<NonceConsumeOutcome, IntentError>` — every real call is
//! therefore `Ok(...)`; only the PROJECTION steps before it can fail.

use std::time::Instant;

use household_rs::ids::{HouseholdId, MachineId};
use household_rs::machine_roster_store::MachineRosterCoordinator;
use household_rs::mesh_intent_nonce_ledger::{
    MeshIntentChannel, MeshIntentNonceConsumeControl, MeshIntentNonceConsumeOutcome,
    MeshIntentNonceEvidence, MeshIntentNonceKey, MeshIntentNonceLedger,
};
use mesh_session_core_rs::auth_state_machine::ExpectedChannel;
use mesh_session_core_rs::error::IntentError;
use mesh_session_core_rs::ingress::CeremonyDeadline;
use mesh_session_core_rs::intent::{IntentNonceKey, IntentNonceLedger, NonceConsumeOutcome};

/// Borrows a real, already-open ledger and an already-constructed roster
/// coordinator — this crate never opens/constructs either itself, same
/// discipline as `roster_bridge::HouseholdRosterSource` and
/// `d1_admission::RegistryD1Admission`. The coordinator is needed only
/// for `current_snapshot_with_trusted_wall_floor` — the ONE production
/// source of a real `TrustedWallFloor`.
pub struct HouseholdIntentNonceLedger<'r> {
    ledger: &'r MeshIntentNonceLedger,
    roster: &'r MachineRosterCoordinator,
}

impl<'r> HouseholdIntentNonceLedger<'r> {
    #[must_use]
    pub fn new(ledger: &'r MeshIntentNonceLedger, roster: &'r MachineRosterCoordinator) -> Self {
        Self { ledger, roster }
    }
}

impl IntentNonceLedger for HouseholdIntentNonceLedger<'_> {
    fn consume(
        &self,
        key: &IntentNonceKey,
        not_after: u64,
        digest: &[u8; 32],
        channel: ExpectedChannel,
        deadline: &CeremonyDeadline,
    ) -> Result<NonceConsumeOutcome, IntentError> {
        let household_key = MeshIntentNonceKey::new(
            HouseholdId(key.hh_id().to_string()),
            MachineId(key.initiator_m_id().to_string()),
            key.delegated_key_id().to_string(),
            *key.nonce(),
        )
        .map_err(|_| IntentError::NonceEvidenceRejected)?;

        let evidence = MeshIntentNonceEvidence::new(map_channel(channel), *digest, not_after)
            .map_err(|_| IntentError::NonceEvidenceRejected)?;

        let (_snapshot, trusted_floor) = self
            .roster
            .current_snapshot_with_trusted_wall_floor()
            .map_err(|_| IntentError::RosterSnapshotUnavailable)?;

        let control = MeshIntentNonceConsumeControl::from_absolute_deadline(
            Instant::now() + deadline.remaining(),
        );

        let outcome = self
            .ledger
            .consume(&household_key, &evidence, trusted_floor, &control);
        Ok(map_consume_outcome(outcome))
    }
}

/// Pure, directly-testable mapping — no ledger, no coordinator, no
/// household validation needed to exercise this. Same discipline as
/// `d1_admission::map_preauthorize_error`/`map_cancel_outcome`.
fn map_channel(channel: ExpectedChannel) -> MeshIntentChannel {
    match channel {
        ExpectedChannel::Dev => MeshIntentChannel::Dev,
        ExpectedChannel::Release => MeshIntentChannel::Release,
    }
}

/// Pure, directly-testable mapping: household's outcome carries payload
/// (`generation`/`evidence`/`stage`/`reason`) that core's `NonceConsumeOutcome`
/// has no field for — core's own doc says only `Committed` lets the
/// ceremony proceed and the other three all close the session, never
/// distinguishing further, so this is a deliberate, matching loss (same
/// discipline as `roster_bridge::map_currency_outcome` collapsing 6
/// `Unavailable*` reasons to one).
///
/// Takes `outcome` by value, not by reference: it is not `Copy` (its
/// payload variants own a `MeshIntentNonceEvidence`/enum), and every
/// caller — the real `consume` above and every test below — already
/// holds it as an owned value with nothing else to do with it.
#[allow(clippy::needless_pass_by_value)]
fn map_consume_outcome(outcome: MeshIntentNonceConsumeOutcome) -> NonceConsumeOutcome {
    match outcome {
        MeshIntentNonceConsumeOutcome::Committed { .. } => NonceConsumeOutcome::Committed,
        MeshIntentNonceConsumeOutcome::AlreadyConsumed { .. } => {
            NonceConsumeOutcome::AlreadyConsumed
        }
        MeshIntentNonceConsumeOutcome::MayHaveTakenEffect { .. } => {
            NonceConsumeOutcome::MayHaveTakenEffect
        }
        MeshIntentNonceConsumeOutcome::Unavailable { .. } => NonceConsumeOutcome::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use household_rs::mesh_intent_nonce_ledger::{
        MeshIntentNonceCommitStage, MeshIntentNonceUnavailable,
    };

    use super::*;

    #[test]
    fn channel_maps_one_to_one() {
        assert!(matches!(
            map_channel(ExpectedChannel::Dev),
            MeshIntentChannel::Dev
        ));
        assert!(matches!(
            map_channel(ExpectedChannel::Release),
            MeshIntentChannel::Release
        ));
    }

    #[test]
    fn committed_maps_to_committed_dropping_the_generation() {
        assert!(matches!(
            map_consume_outcome(MeshIntentNonceConsumeOutcome::Committed { generation: 7 }),
            NonceConsumeOutcome::Committed
        ));
    }

    #[test]
    fn already_consumed_maps_across_dropping_the_evidence() {
        let evidence = MeshIntentNonceEvidence::new(MeshIntentChannel::Dev, [0u8; 32], 1)
            .expect("valid fixture");
        assert!(matches!(
            map_consume_outcome(MeshIntentNonceConsumeOutcome::AlreadyConsumed { evidence }),
            NonceConsumeOutcome::AlreadyConsumed
        ));
    }

    /// Only `Committed` may let a ceremony proceed to Active — this pins
    /// that `MayHaveTakenEffect` never collapses into it by accident,
    /// regardless of which commit stage produced it.
    #[test]
    fn may_have_taken_effect_never_collapses_into_committed_for_any_stage() {
        let stages = [
            MeshIntentNonceCommitStage::WorkerInFlight,
            MeshIntentNonceCommitStage::DirtyMarkerWrite,
            MeshIntentNonceCommitStage::DirtyMarkerSync,
            MeshIntentNonceCommitStage::TempInspect,
            MeshIntentNonceCommitStage::TempCleanup,
            MeshIntentNonceCommitStage::TempOpen,
            MeshIntentNonceCommitStage::TempWrite,
            MeshIntentNonceCommitStage::TempFlush,
            MeshIntentNonceCommitStage::TempSync,
            MeshIntentNonceCommitStage::Rename,
            MeshIntentNonceCommitStage::ParentSync,
            MeshIntentNonceCommitStage::Readback,
            MeshIntentNonceCommitStage::ReadbackMismatch,
            MeshIntentNonceCommitStage::CleanMarkerWrite,
            MeshIntentNonceCommitStage::CleanMarkerSync,
            MeshIntentNonceCommitStage::PostCommitBinding,
        ];
        for stage in stages {
            assert!(matches!(
                map_consume_outcome(MeshIntentNonceConsumeOutcome::MayHaveTakenEffect { stage }),
                NonceConsumeOutcome::MayHaveTakenEffect
            ));
        }
    }

    #[test]
    fn unavailable_maps_across_dropping_the_reason() {
        assert!(matches!(
            map_consume_outcome(MeshIntentNonceConsumeOutcome::Unavailable {
                reason: MeshIntentNonceUnavailable::CapacityExhausted,
            }),
            NonceConsumeOutcome::Unavailable
        ));
    }
}
