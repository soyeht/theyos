#![cfg(test)]

use super::*;

#[test]
fn red47_zero_threshold_rejected_before_any_session() {
    assert_eq!(RekeyThreshold::new(0), Err(RekeyError::InvalidRekeyPolicy));
}

#[test]
fn threshold_one_minus_one_never_underflows() {
    let t = RekeyThreshold::new(1).unwrap();
    assert_eq!(t.minus_one(), 0);
}

#[test]
fn misuse_after_send_non_marker_requires_a_real_permit_not_just_any_call() {
    let threshold = RekeyThreshold::new(3).unwrap();
    let mut tx = DirectionalRekeyState::new(threshold).unwrap();
    let permit = tx.before_send_non_marker().unwrap();
    tx.after_send_non_marker(permit).unwrap();
    assert_eq!(tx.policy_count(), 1);
}

#[test]
fn red_multi_permit_same_count_only_the_first_commits() {
    // Reproduces the audit finding literally: call before_* three
    // times against the SAME unmutated state, then try to apply all
    // three. Only the first succeeds; the second and third are
    // rejected as stale, because their expected_policy_count snapshot
    // (0) no longer matches self.policy_count (1, then 2) once an
    // earlier permit has already committed.
    let threshold = RekeyThreshold::new(4).unwrap(); // headroom so 3 non-markers are all legal to *attempt*
    let mut tx = DirectionalRekeyState::new(threshold).unwrap();
    let p1 = tx.before_send_non_marker().unwrap();
    let p2 = tx.before_send_non_marker().unwrap();
    let p3 = tx.before_send_non_marker().unwrap();

    tx.after_send_non_marker(p1).unwrap();
    assert_eq!(tx.policy_count(), 1);
    assert_eq!(tx.after_send_non_marker(p2), Err(RekeyError::StalePermit));
    assert_eq!(
        tx.policy_count(),
        1,
        "a rejected permit must not mutate state"
    );
    assert_eq!(tx.after_send_non_marker(p3), Err(RekeyError::StalePermit));
    assert_eq!(tx.policy_count(), 1);
}

/// 2026-08-04, @kiana, round 5: `SendNonMarkerPermit` used to
/// snapshot only `policy_count`, not `generation`. `policy_count`
/// cycles through `0..threshold` every generation, so a permit
/// obtained early and held back is replayable once real traffic
/// completes a full marker cycle and `policy_count` coincidentally
/// reads the same value again — in a DIFFERENT generation. Entirely
/// through the public API (`before_send_non_marker`/
/// `before_send_marker`/`after_send_marker`/`after_send_non_marker`):
/// mint a permit at (generation 0, count 0); drive real traffic
/// through threshold-1 sends plus a marker, landing back at
/// (generation 1, count 0); the held-back generation-0 permit must
/// now be rejected, not silently accepted into generation 1.
#[test]
fn red_cross_generation_permit_replay_rejected_after_a_full_marker_cycle() {
    let threshold = RekeyThreshold::new(2).unwrap(); // threshold-1 == 1
    let mut tx = DirectionalRekeyState::new(threshold).unwrap();

    // Mint a permit at (generation 0, count 0) and hold it back —
    // this is the "stale, waiting to be replayed" permit.
    let stale_permit = tx.before_send_non_marker().unwrap();

    // Real traffic advances state through a full cycle: one
    // non-marker (count 0 -> 1 == threshold-1), then a marker
    // (generation 0 -> 1, count resets to 0).
    let live_permit = tx.before_send_non_marker().unwrap();
    tx.after_send_non_marker(live_permit).unwrap();
    assert_eq!(tx.policy_count(), 1);
    let marker_permit = tx.before_send_marker().unwrap();
    tx.after_send_marker(marker_permit).unwrap();
    assert_eq!(tx.generation(), 1);
    assert_eq!(tx.policy_count(), 0);

    // policy_count is back to 0 -- coincidentally identical to what
    // stale_permit snapshotted -- but generation has moved from 0 to
    // 1. Without expected_generation, this would be wrongly accepted.
    assert_eq!(
        tx.after_send_non_marker(stale_permit),
        Err(RekeyError::StalePermit),
        "a permit from generation 0 must not be usable in generation 1, \
             even when policy_count happens to read the same value again"
    );
    assert_eq!(
        tx.policy_count(),
        0,
        "a rejected cross-generation permit must not mutate state"
    );
}

#[test]
fn red_donor_to_victim_marker_permit_rejected_cross_instance() {
    let threshold = RekeyThreshold::new(1).unwrap(); // threshold-1 == 0, marker eligible immediately
    let donor = DirectionalRekeyState::new(threshold).unwrap();
    let mut victim = DirectionalRekeyState::new(threshold).unwrap();

    let donor_permit = donor.before_send_marker().unwrap();
    let victim_generation_before = victim.generation();
    assert_eq!(
        victim.after_send_marker(donor_permit),
        Err(RekeyError::StalePermit)
    );
    assert_eq!(
        victim.generation(),
        victim_generation_before,
        "a foreign permit must not mutate the victim"
    );
}

#[test]
fn red_tx_permit_rejected_on_rx_and_vice_versa_within_one_session() {
    let threshold = RekeyThreshold::new(1).unwrap();
    let mut session = SessionRekeyState::new(threshold).unwrap();
    let tx_permit = session.tx().before_send_marker().unwrap();
    assert_eq!(
        session.rx().after_send_marker(tx_permit),
        Err(RekeyError::StalePermit)
    );

    let rx_permit = {
        // rx has no before_send_marker (it's driven by on_receive, not
        // permits) — use a second session's tx permit as the "foreign"
        // token instead, which is the actually-reachable cross-session
        // case.
        let other = DirectionalRekeyState::new(threshold).unwrap();
        other.before_send_marker().unwrap()
    };
    assert_eq!(
        session.tx().after_send_marker(rx_permit),
        Err(RekeyError::StalePermit)
    );
}

#[test]
fn red_stale_permit_rejected_before_any_coupled_side_effect_would_run() {
    // validate_marker_permit is what a caller (ActiveMeshSession)
    // checks BEFORE touching TransportState::rekey_outgoing() — prove
    // it independently rejects a stale permit without needing to
    // apply it first.
    let threshold = RekeyThreshold::new(1).unwrap();
    let state = DirectionalRekeyState::new(threshold).unwrap();
    let permit = state.before_send_marker().unwrap();
    let other = DirectionalRekeyState::new(threshold).unwrap();
    assert_eq!(
        other.validate_marker_permit(&permit),
        Err(RekeyError::StalePermit)
    );
}

#[test]
fn pos4_n3_two_data_marker_two_data_directional() {
    let threshold = RekeyThreshold::new(3).unwrap();
    let mut tx = DirectionalRekeyState::new(threshold).unwrap();

    // count=0: DATA -> count=1
    let permit = tx.before_send_non_marker().unwrap();
    tx.after_send_non_marker(permit).unwrap();
    assert_eq!(tx.policy_count(), 1);

    // count=1: DATA -> count=2
    let permit = tx.before_send_non_marker().unwrap();
    tx.after_send_non_marker(permit).unwrap();
    assert_eq!(tx.policy_count(), 2);

    // count=2==N-1: next MUST be a marker.
    assert_eq!(
        tx.before_send_non_marker().err(),
        Some(RekeyError::ExpectedRekeyMarker)
    );
    let permit = tx.before_send_marker().unwrap();
    assert_eq!(permit.next_generation(), 1);
    tx.after_send_marker(permit).unwrap();
    assert_eq!(tx.generation(), 1);
    assert_eq!(tx.policy_count(), 0);

    // Cycle repeats.
    let permit = tx.before_send_non_marker().unwrap();
    tx.after_send_non_marker(permit).unwrap();
    assert_eq!(tx.policy_count(), 1);
    let permit = tx.before_send_non_marker().unwrap();
    tx.after_send_non_marker(permit).unwrap();
    assert_eq!(tx.policy_count(), 2);
}

#[test]
fn red43_non_marker_at_n_minus_1_rejected_on_receive_too() {
    let threshold = RekeyThreshold::new(3).unwrap();
    let mut rx = DirectionalRekeyState::new(threshold).unwrap();
    rx.on_receive(IncomingRecord::NonMarker).unwrap();
    rx.on_receive(IncomingRecord::NonMarker).unwrap();
    assert_eq!(rx.policy_count(), 2);
    assert_eq!(
        rx.on_receive(IncomingRecord::NonMarker),
        Err(RekeyError::ExpectedRekeyMarker)
    );
}

#[test]
fn red25_premature_marker_rejected() {
    let threshold = RekeyThreshold::new(3).unwrap();
    let mut rx = DirectionalRekeyState::new(threshold).unwrap();
    // policy_count is 0, threshold-1 is 2 — far too early for a marker.
    assert_eq!(
        rx.on_receive(IncomingRecord::Marker { next_generation: 1 }),
        Err(RekeyError::PrematureRekeyMarker)
    );
    assert_eq!(rx.generation(), 0);
}

#[test]
fn red26_duplicate_marker_rejected_as_wrong_generation() {
    let threshold = RekeyThreshold::new(3).unwrap();
    let mut rx = DirectionalRekeyState::new(threshold).unwrap();
    rx.on_receive(IncomingRecord::NonMarker).unwrap();
    rx.on_receive(IncomingRecord::NonMarker).unwrap();
    rx.on_receive(IncomingRecord::Marker { next_generation: 1 })
        .unwrap();
    assert_eq!(rx.generation(), 1);
    // Same marker replayed — generation already advanced past it.
    assert_eq!(
        rx.on_receive(IncomingRecord::Marker { next_generation: 1 }),
        Err(RekeyError::WrongGeneration {
            expected: 2,
            got: 1
        })
    );
}

#[test]
fn red27_wrong_generation_skip_ahead_rejected() {
    let threshold = RekeyThreshold::new(3).unwrap();
    let mut rx = DirectionalRekeyState::new(threshold).unwrap();
    rx.on_receive(IncomingRecord::NonMarker).unwrap();
    rx.on_receive(IncomingRecord::NonMarker).unwrap();
    assert_eq!(
        rx.on_receive(IncomingRecord::Marker { next_generation: 5 }),
        Err(RekeyError::WrongGeneration {
            expected: 1,
            got: 5
        })
    );
}

#[test]
fn red28_wrong_count_marker_before_threshold_rejected() {
    let threshold = RekeyThreshold::new(3).unwrap();
    let mut rx = DirectionalRekeyState::new(threshold).unwrap();
    rx.on_receive(IncomingRecord::NonMarker).unwrap(); // count=1, still short of N-1=2
    assert_eq!(
        rx.on_receive(IncomingRecord::Marker { next_generation: 1 }),
        Err(RekeyError::PrematureRekeyMarker)
    );
}

#[test]
fn red29_simultaneous_opposite_directions_are_independent() {
    let threshold = RekeyThreshold::new(3).unwrap();
    let mut state = SessionRekeyState::new(threshold).unwrap();

    // Drive tx all the way through a rekey.
    let permit = state.tx().before_send_non_marker().unwrap();
    state.tx().after_send_non_marker(permit).unwrap();
    let permit = state.tx().before_send_non_marker().unwrap();
    state.tx().after_send_non_marker(permit).unwrap();
    let permit = state.tx().before_send_marker().unwrap();
    state.tx().after_send_marker(permit).unwrap();
    assert_eq!(state.tx().generation(), 1);

    // rx never touched — must be completely unaffected.
    assert_eq!(state.rx().generation(), 0);
    assert_eq!(state.rx().policy_count(), 0);

    // Drive rx independently and confirm tx is unaffected in turn.
    state.rx().on_receive(IncomingRecord::NonMarker).unwrap();
    assert_eq!(state.tx().policy_count(), 0);
    assert_eq!(state.tx().generation(), 1);
}

#[test]
fn generation_exhaustion_is_checked_not_wrapping() {
    let threshold = RekeyThreshold::new(1).unwrap();
    // Private-field construction is visible here because `tests` is a
    // child module of `rekey` — used only to force an edge state that
    // is otherwise impractical to reach by driving u64::MAX sends.
    let tx = DirectionalRekeyState {
        id: RekeyStateId::from_byte(1),
        generation: u64::MAX,
        policy_count: 0,
        threshold,
    };
    assert_eq!(
        tx.before_send_marker().err(),
        Some(RekeyError::GenerationExhausted)
    );
}

#[test]
fn red_rekey_state_id_256_bit_full_value_compared_not_probabilistic() {
    // Deterministic constructor (test-only) proves the comparison is
    // over the FULL 32-byte value, not e.g. a truncated prefix — two
    // ids built from the same byte are equal, two built from
    // different bytes are not, with no reliance on OsRng ever
    // producing (or not producing) a collision.
    let threshold = RekeyThreshold::new(1).unwrap();
    let a = DirectionalRekeyState {
        id: RekeyStateId::from_byte(7),
        generation: 0,
        policy_count: 0,
        threshold,
    };
    let b_same_id = DirectionalRekeyState {
        id: RekeyStateId::from_byte(7),
        generation: 0,
        policy_count: 0,
        threshold,
    };
    let b_diff_id = DirectionalRekeyState {
        id: RekeyStateId::from_byte(9),
        generation: 0,
        policy_count: 0,
        threshold,
    };

    // A permit issued by `a` is accepted by `b_same_id` — same
    // RekeyStateId value, even though it's a different instance —
    // proving the check is value equality, not e.g. instance/pointer
    // identity smuggled in some other way.
    let permit_from_a = a.before_send_marker().unwrap();
    assert_eq!(
        b_same_id.validate_marker_permit(&permit_from_a),
        Ok(()),
        "identical 32-byte ids must compare equal"
    );

    // The same permit is rejected by `b_diff_id` — different
    // RekeyStateId value.
    let permit_from_a_2 = a.before_send_marker().unwrap();
    assert_eq!(
        b_diff_id.validate_marker_permit(&permit_from_a_2),
        Err(RekeyError::StalePermit),
        "different 32-byte ids must not compare equal"
    );
}

#[test]
fn rekey_state_id_fresh_produces_distinct_values() {
    // Not a collision-resistance proof (that's what round 3's widening
    // to 256 bits is for) — just confirms two real OsRng-backed calls
    // in a row are not trivially returning a fixed/zeroed value.
    let a = RekeyStateId::fresh().unwrap();
    let b = RekeyStateId::fresh().unwrap();
    assert_ne!(a, b);
}
