// RED-R23: PeerExpectation's fields are private -- a struct literal from
// outside its defining module must fail to compile, for any field values.
fn main() {
    let _ = household_rs::machine_roster_authority::PeerExpectation {
        checkpoint_hash: [0u8; 32],
        m_id: household_rs::MachineId("m-test".to_string()),
        source: household_rs::machine_roster_authority::PeerSelectionSource::LocalOwnerPresentSelection,
    };
}
