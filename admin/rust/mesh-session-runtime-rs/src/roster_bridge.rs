//! Real `keystore_rs::mesh_session_bridge::RosterLookupSource` against
//! `household_rs::machine_roster_store::MachineRosterCoordinator` — the
//! adapter @ilia asked for directly: "a fonte real existe:
//! `MachineRosterCoordinator::query_machine_currency`
//! (`machine_roster_store.rs:1448`). Constrói o adapter real contra ela."
//!
//! This crate is the only place that can see both sides: keystore-rs's
//! `RosterLookupSource` seam trait (its own D4 types are `pub(crate)`-capped
//! and it cannot depend on household-rs — see that trait's own module doc
//! for why) and household-rs's real coordinator.
//!
//! `query_machine_currency` maps losslessly: household-rs's
//! [`PublicCurrencyOutcome`] carries 9 variants (`Active`, `Revoked`,
//! `NotListed`, and 6 `Unavailable*` reasons); D4's `RosterCurrency` (and
//! this seam's [`RosterCurrencyView`] mirror of it) only distinguishes
//! `Unavailable` as one case — a real, deliberate loss of the 6 distinct
//! reasons, not an oversight: D4's own trait never asked for more than
//! "can't tell you right now," and inventing a 6-way split on this seam
//! that D4 itself does not consume would be surface no caller needs.
//! `RosterStoreError` (the outer, fallible-call error) also collapses to
//! `Unavailable` for the same reason.
//!
//! `currency_revision` uses `RosterSnapshotView::checkpoint_sequence()` —
//! confirmed a genuine, not approximated, match against the trait's own
//! contract (`mesh-session-control-model-rs/src/validator.rs`, doc on
//! `RosterLookup::currency_revision`): "a monotonic counter a real
//! implementation bumps on any change to any machine's currency" —
//! household-wide by the trait's OWN design, not a per-machine counter this
//! adapter approximates down to something coarser. `checkpoint_sequence`
//! lives on the machine roster's own checkpoint chain
//! (`machine_roster_store.rs`'s `AcceptedChainRecordV1`), not a household
//! object shared with unrelated subsystems.
//!
//! The one real gap: `currency_revision`'s signature in both the D4 trait
//! and this seam is infallible (`-> u64`), but the only real source,
//! `MachineRosterCoordinator::current_snapshot()`, is fallible
//! (`Result<_, RosterSnapshotError>`). On error this returns `u64::MAX` —
//! documented, not silent: no real chain reaches that value in any
//! reachable system lifetime (it would need over 500 billion sequential
//! checkpoints), so it acts as a sentinel that can never spuriously equal a
//! caller's `expected_revision`, forcing "treat as changed" rather than a
//! false "unchanged" on the one path this seam cannot make infallible.
//! Directly composes with `RosterLookupBridge::acquire_currency_lease`
//! always failing closed regardless of the revision passed to it (see that
//! method's own doc in `keystore-rs`) — belt and suspenders, not a
//! load-bearing assumption on its own.

use household_rs::MachineId;
use household_rs::machine_roster_authority::{MachineRosterMemberV1, RosterSnapshotView};
use household_rs::machine_roster_store::{
    MachineRosterCoordinator, PublicCurrencyOutcome, RosterStoreError,
};
use keystore_rs::mesh_session_bridge::{RosterCurrencyView, RosterLookupSource};

/// Borrows a real, already-constructed coordinator — this crate never
/// constructs one itself, matching `RosterLookup`'s own trait doc ("this
/// crate never constructs a coordinator itself... needs household context
/// this crate has no business holding").
pub struct HouseholdRosterSource<'a> {
    coordinator: &'a MachineRosterCoordinator,
}

impl<'a> HouseholdRosterSource<'a> {
    #[must_use]
    pub fn new(coordinator: &'a MachineRosterCoordinator) -> Self {
        Self { coordinator }
    }
}

fn view_of(member: &MachineRosterMemberV1) -> RosterCurrencyView {
    RosterCurrencyView::Active {
        member_pub: member.m_pub.0.to_vec(),
        member_cert_fingerprint: member.machine_cert_fingerprint,
    }
}

/// Pure 9-variant-in, 4-variant-out mapping — factored out of the trait
/// impl so it is unit-testable directly against constructible
/// `PublicCurrencyOutcome`/`RosterStoreError` fixtures. `MachineRosterCoordinator`
/// itself has no test-support constructor in this workspace (nothing this
/// crate adds — see this module's own doc), so this is the only part of
/// the adapter that can be exercised without a live coordinator; the
/// coordinator call itself is a one-line, no-branching delegation covered
/// by household-rs's own test suite, not duplicated here.
fn map_currency_outcome(
    outcome: Result<PublicCurrencyOutcome, RosterStoreError>,
) -> RosterCurrencyView {
    match outcome {
        Ok(PublicCurrencyOutcome::Active { member }) => view_of(&member),
        Ok(PublicCurrencyOutcome::Revoked { .. }) => RosterCurrencyView::Revoked,
        Ok(PublicCurrencyOutcome::NotListed) => RosterCurrencyView::NotListed,
        Ok(
            PublicCurrencyOutcome::UnavailableNoGenesis
            | PublicCurrencyOutcome::UnavailableCheckpointStale
            | PublicCurrencyOutcome::UnavailableCheckpointForkConflict
            | PublicCurrencyOutcome::UnavailableEventForkConflict
            | PublicCurrencyOutcome::UnavailableClockState
            | PublicCurrencyOutcome::UnavailableOwnerAuthority,
        ) => RosterCurrencyView::Unavailable,
        Err(_) => RosterCurrencyView::Unavailable,
    }
}

impl RosterLookupSource for HouseholdRosterSource<'_> {
    fn query_machine_currency(&self, machine_id: &str) -> RosterCurrencyView {
        let m_id = MachineId(machine_id.to_string());
        map_currency_outcome(self.coordinator.query_machine_currency(&m_id))
    }

    fn currency_revision(&self, _machine_id: &str) -> u64 {
        self.coordinator
            .current_snapshot()
            .as_ref()
            .map(RosterSnapshotView::checkpoint_sequence)
            .unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use household_rs::HouseholdId;
    use household_rs::keys::P256PublicKey;
    use household_rs::machine_roster_authority::MachineRosterRevocationV1;

    use super::*;

    fn member_fixture() -> MachineRosterMemberV1 {
        MachineRosterMemberV1 {
            m_id: MachineId("m-1".to_string()),
            m_pub: P256PublicKey([0x02; 33]),
            machine_cert: vec![0xAA, 0xBB],
            machine_cert_fingerprint: [0xCC; 32],
        }
    }

    #[test]
    fn active_outcome_maps_losslessly() {
        let member = member_fixture();
        let expected_pub = member.m_pub.0.to_vec();
        let expected_fp = member.machine_cert_fingerprint;
        let view = map_currency_outcome(Ok(PublicCurrencyOutcome::Active {
            member: Box::new(member),
        }));
        match view {
            RosterCurrencyView::Active {
                member_pub,
                member_cert_fingerprint,
            } => {
                assert_eq!(member_pub, expected_pub);
                assert_eq!(member_cert_fingerprint, expected_fp);
            }
            other => panic!("expected Active, got {other:?}"),
        }
    }

    #[test]
    fn revoked_and_not_listed_map_directly() {
        let tombstone = MachineRosterRevocationV1 {
            v: 1,
            kind: "machine_roster_revocation".to_string(),
            hh_id: HouseholdId("hh-1".to_string()),
            epoch: [0u8; 32],
            sequence: 1,
            prev_event_hash: [0u8; 32],
            m_id: MachineId("m-1".to_string()),
            m_pub: P256PublicKey([0x02; 33]),
            machine_cert_fingerprint: [0u8; 32],
            revoked_at: 1,
            reason: household_rs::machine_roster_authority::RevocationReason::OwnerAction,
            cascade: household_rs::machine_roster_authority::RevocationCascade::MachineOnly,
            owner_p_id: household_rs::PersonId("p-1".to_string()),
            owner_cert_fingerprint: [0u8; 32],
            owner_person_cert: vec![],
            signature: household_rs::keys::P256Signature([0u8; 64]),
        };
        assert!(matches!(
            map_currency_outcome(Ok(PublicCurrencyOutcome::Revoked {
                tombstone: Box::new(tombstone)
            })),
            RosterCurrencyView::Revoked
        ));
        assert!(matches!(
            map_currency_outcome(Ok(PublicCurrencyOutcome::NotListed)),
            RosterCurrencyView::NotListed
        ));
    }

    /// All 6 `Unavailable*` reasons collapse to one `Unavailable` — pins
    /// the deliberate loss described in this module's own doc, and would
    /// catch a future variant added to `PublicCurrencyOutcome` that this
    /// match forgets to route (the match has no wildcard arm on the `Ok`
    /// side, so a new variant is a compile error here, not a silent drop).
    #[test]
    fn all_six_unavailable_reasons_collapse_to_unavailable() {
        let reasons = [
            PublicCurrencyOutcome::UnavailableNoGenesis,
            PublicCurrencyOutcome::UnavailableCheckpointStale,
            PublicCurrencyOutcome::UnavailableCheckpointForkConflict,
            PublicCurrencyOutcome::UnavailableEventForkConflict,
            PublicCurrencyOutcome::UnavailableClockState,
            PublicCurrencyOutcome::UnavailableOwnerAuthority,
        ];
        for reason in reasons {
            assert!(matches!(
                map_currency_outcome(Ok(reason)),
                RosterCurrencyView::Unavailable
            ));
        }
    }

    #[test]
    fn red_a_fallible_call_error_also_maps_to_unavailable_not_a_panic_or_default_active() {
        assert!(matches!(
            map_currency_outcome(Err(RosterStoreError::NotInitialized)),
            RosterCurrencyView::Unavailable
        ));
    }
}
