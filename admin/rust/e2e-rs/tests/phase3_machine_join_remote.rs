mod phase3_support;

use household_rs::owner_events::OwnerEventType;
use household_rs::pair_machine::PairMachineState;

#[tokio::test]
async fn phase3_machine_join_remote() {
    let ceremony = phase3_support::run_remote_ceremony().await;
    phase3_support::assert_successful_remote_ceremony(&ceremony);

    assert_eq!(
        ceremony.founder.window.snapshot().await.state,
        PairMachineState::Committed
    );
    assert_eq!(
        ceremony.candidate.window.snapshot().await.state,
        PairMachineState::Committed
    );

    let committed_events = ceremony
        .founder
        .event_log
        .read_since(0)
        .expect("read owner events");
    assert_eq!(committed_events.len(), 2);
    assert_eq!(committed_events[1].cursor, 2);
    assert_eq!(
        committed_events[1].event_type,
        OwnerEventType::MachineJoined
    );
}
