mod phase3_support;

use household_rs::owner_events::OwnerEventType;
use household_rs::pair_machine::PairMachineState;

/// Coverage note: this test does not prove the commit's durability. Two
/// gaps, both structural:
/// (i) the committed G0 snapshot is not observable from here --
///     `sweep_stale_generations` is unconditional and runs inside the same
///     retry that completes the ceremony, so G0 is gone before the test
///     regains control;
/// (ii) "the verifier stopped verifying" is a negative property -- it only
///     shows up by feeding invalid artifacts to
///     `validate_candidate_install_artifacts` and asserting `Err`, and it
///     lives in a unit test in server-rs, where that is reachable.
/// This test proves the integrated ceremony: it completes on the wire, with
/// the correct ack and event log.
#[tokio::test]
async fn phase3_machine_join_remote() {
    let ceremony = phase3_support::run_remote_ceremony().await;
    phase3_support::assert_successful_remote_ceremony(&ceremony);

    assert_eq!(
        ceremony.founder.window.snapshot().await.state,
        PairMachineState::Committed
    );

    let founder_read = ceremony
        .founder
        .lifecycle
        .lock_shared()
        .expect("lock lifecycle shared");
    let committed_events = ceremony
        .founder
        .event_log
        .read_since(&founder_read, 0)
        .expect("read owner events");
    drop(founder_read);
    assert_eq!(committed_events.len(), 2);
    assert_eq!(committed_events[1].cursor, 2);
    assert_eq!(
        committed_events[1].event_type,
        OwnerEventType::MachineJoined
    );
}
