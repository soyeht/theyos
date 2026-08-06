// D-1 successor (@kiana E1): AuthenticatedPeerClaim's field is private --
// a struct literal from outside its defining module must fail to compile,
// for any field value. Mirrors peer_expectation_struct_literal.rs.
fn main() {
    let _ = household_rs::machine_roster_authority::AuthenticatedPeerClaim {
        m_id: household_rs::MachineId("m-test".to_string()),
    };
}
