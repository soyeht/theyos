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

    // ── `map_channel` arm-qualification guard (@khai, 2026-08-05) ───────
    //
    // Complements, does not replace, `compile_fail_channel_mapping.rs`'s
    // trybuild proof. The two cover opposite halves of the same risk:
    // a new variant added to the real `ExpectedChannel` upstream trips
    // the trybuild fixture (its own copy of the arms goes non-exhaustive,
    // E0004) — but the trybuild fixture has its OWN copy of the arms
    // precisely because `map_channel` is private, so it can never see a
    // `_ =>` (or a bare-identifier catch-all like `other =>`) added to
    // the REAL function: that would compile clean and the fixture would
    // not change at all. This guard reads the real function's own source
    // and asserts every arm pattern is fully qualified — not a `grep '_
    // =>'`, which misses a bare-identifier catch-all binding with no
    // underscore at all (`other => MeshIntentChannel::Dev` is a
    // catch-all and contains no `_`).

    /// Parses top-level arm PATTERNS (the text before each `=>`) out of a
    /// match block's inner text. Scoped to this file's actual shape —
    /// simple `Pattern => Expr,` arms with no commas inside either half
    /// — not a general Rust parser: if `map_channel`'s match ever grows
    /// an arm whose body contains a comma (a tuple, a multi-arg call), a
    /// naive split here would mis-parse. The count assertion below is
    /// the tripwire for that: a mis-parse changes the arm count away
    /// from the pinned `2`, which fails loud instead of silently
    /// approving a miscounted arm as "qualified".
    fn arm_patterns(match_body: &str) -> Vec<&str> {
        match_body
            .split(',')
            .map(str::trim)
            .filter(|chunk| !chunk.is_empty())
            .map(|chunk| {
                chunk
                    .split_once("=>")
                    .map_or(chunk, |(pattern, _body)| pattern)
                    .trim()
            })
            .collect()
    }

    /// A pattern counts as "qualified" only if it names a specific
    /// variant via `Type::Variant` — never a bare identifier (which
    /// binds everything, functioning as a catch-all with no `_` in
    /// sight) and never `_` itself.
    fn is_qualified_arm(pattern: &str) -> bool {
        pattern.contains("::")
    }

    /// Positive control (@zain's standing requirement): proves
    /// `is_qualified_arm`/`arm_patterns` actually discriminate, on a
    /// synthetic fixture whose shape is deliberately NOT the real file
    /// — same reasoning as `mesh_intent_nonce_ledger.rs`'s own
    /// `split_partition_control_has_teeth`, so this demonstration never
    /// depends on the real match block's own, incidentally-editable
    /// shape.
    #[test]
    fn arm_qualification_control_has_teeth() {
        let all_qualified = "Channel::Dev => Other::Dev, Channel::Release => Other::Release";
        assert!(
            arm_patterns(all_qualified)
                .into_iter()
                .all(is_qualified_arm),
            "control fixture with two qualified arms must pass, or the \
             check itself is broken"
        );

        let bare_wildcard = "Channel::Dev => Other::Dev, _ => Other::Dev";
        assert!(
            !arm_patterns(bare_wildcard)
                .into_iter()
                .all(is_qualified_arm),
            "control failed to fire: a `_` arm must be rejected, or the \
             check discriminates nothing"
        );

        let bare_binding = "Channel::Dev => Other::Dev, other => Other::Dev";
        assert!(
            !arm_patterns(bare_binding).into_iter().all(is_qualified_arm),
            "control failed to fire: a bare-identifier catch-all (no \
             underscore, still matches everything) must be rejected too \
             — this is the exact gap a `grep '_ =>'` would miss"
        );
    }

    /// The real measurement. Reads this file's own source — `needle` is
    /// `concat!`'d so this guard's own search literal, living in this
    /// same file's test module, cannot match itself (same reasoning as
    /// `mesh_intent_nonce_ledger.rs`'s own `needle`/`marker`).
    #[test]
    fn map_channel_every_arm_is_fully_qualified() {
        let needle = concat!("fn map_channel", "(");
        // Partitioned at the real `mod tests` boundary rather than
        // trusting `find` to land on the right occurrence by luck of
        // ordering (@ilia): today `fn_body`'s own brace-matching already
        // scopes the search to `map_channel` alone, so nothing in this
        // test module's `=>` tokens can leak in — but a whole-file
        // search for `needle` itself has no such protection if a future
        // test ever needed a second, unrelated occurrence of the same
        // text. Marker is `concat!`'d for the same reason `needle` is:
        // this guard reads its own file and cannot avoid seeing its own
        // source.
        let marker = concat!("#[cfg(test)]", "\n", "mod tests {");
        let this_file = include_str!("intent_nonce_ledger_bridge.rs");
        let production = this_file
            .split_once(marker)
            .map_or(this_file, |(production, _test)| production);
        let fn_start = production
            .find(needle)
            .expect("map_channel's own definition must be present in production");

        let fn_brace_open = production[fn_start..]
            .find('{')
            .map(|offset| fn_start + offset)
            .expect("a fn definition must have an opening brace");
        let mut depth = 0i32;
        let mut fn_end = production.len();
        for (offset, ch) in production[fn_brace_open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        fn_end = fn_brace_open + offset + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let fn_body = &production[fn_start..fn_end];

        let match_kw = fn_body
            .find("match ")
            .expect("map_channel must still dispatch on channel via a match");
        let match_brace_open = fn_body[match_kw..]
            .find('{')
            .map(|offset| match_kw + offset)
            .expect("the match must have a body");
        let mut depth = 0i32;
        let mut match_brace_close = fn_body.len();
        for (offset, ch) in fn_body[match_brace_open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        match_brace_close = match_brace_open + offset + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let match_body = &fn_body[match_brace_open + 1..match_brace_close - 1];

        let arms = arm_patterns(match_body);
        // Non-vacuity: pinned to the known-today count, not `>= 1` — a
        // wrong count (including from the naive-parse limitation noted
        // above) fails loud instead of silently checking a subset.
        assert_eq!(
            arms.len(),
            2,
            "expected exactly the 2 known arms (Dev, Release); a \
             different count means either a real arm was added/removed \
             or this guard's naive comma-split mis-parsed a more complex \
             match body — in either case, verify by hand before trusting \
             this guard's verdict again"
        );
        let unqualified: Vec<&str> = arms
            .iter()
            .copied()
            .filter(|pattern| !is_qualified_arm(pattern))
            .collect();
        assert!(
            unqualified.is_empty(),
            "map_channel has an unqualified arm pattern: {unqualified:?} — \
             a bare `_` or bare-identifier catch-all here would silently \
             swallow a new upstream ExpectedChannel variant instead of \
             failing to compile. The trybuild fixture in \
             compile_fail_channel_mapping.rs cannot see this: it holds \
             its own copy of the arms and only fails when \
             ExpectedChannel itself changes, never when this real match \
             grows a catch-all"
        );
    }

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
