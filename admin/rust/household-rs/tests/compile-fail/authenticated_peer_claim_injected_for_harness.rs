// D-1 successor (@kiana E1): injected_for_harness is #[cfg(test)]
// pub(crate) -- invisible across the crate boundary this fixture compiles
// across, AND absent entirely from a non-test build of household_rs.
// Mirrors peer_expectation_injected_for_harness.rs -- same reasoning: the
// absence of any other constructor IS the gate (no measured, authenticated
// source for an inbound peer's claimed m_id exists yet).
fn main() {
    let _ = household_rs::machine_roster_authority::AuthenticatedPeerClaim::injected_for_harness(
        household_rs::MachineId("m-test".to_string()),
    );
}
