// Lane R (@ilia): `SealedBinding::from_membership_key` must reject a raw
// `ProofI` at the type level — it is not the capability (see
// `machine_roster_authority.rs`'s "Runtime-facade membership projection"
// section for why: `ProofI` is forgeable outside mesh-session-core-rs,
// authentication is a process, not a type property).
fn main() {
    let proof_i: mesh_session_core_rs::auth_frames::ProofI = todo!();
    let snapshot: household_rs::machine_roster_authority::RosterSnapshotView = todo!();
    let _ = household_rs::machine_roster_authority::SealedBinding::from_membership_key(
        &proof_i, &snapshot,
    );
}
