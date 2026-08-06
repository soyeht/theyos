// RED-R23: injected_for_harness is #[cfg(test)] pub(crate) -- invisible
// across the crate boundary this fixture compiles across (pub(crate) is a
// hard crate boundary regardless of build mode), AND absent entirely from
// a non-test build of household_rs (the rlib this fixture links against is
// built without --cfg test, so a #[cfg(test)] item does not exist in it at
// all, independent of visibility).
fn main() {
    let _ = household_rs::machine_roster_authority::PeerExpectation::injected_for_harness(
        [0u8; 32],
        household_rs::MachineId("m-test".to_string()),
        household_rs::machine_roster_authority::PeerSelectionSource::LocalOwnerPresentSelection,
    );
}
