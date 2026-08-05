// Lane R (@ilia): `SealedBinding::from_membership_key` must reject a bare
// m_id (or any raw string/primitive) — only a real `D1MembershipKey`,
// minted by mesh-session-core-rs's own handshake code after
// verify_frame+delegation+checkpoint succeed, satisfies it.
fn main() {
    let raw_m_id: &str = "m-test";
    let snapshot: household_rs::machine_roster_authority::RosterSnapshotView = todo!();
    let _ = household_rs::machine_roster_authority::SealedBinding::from_membership_key(
        raw_m_id, &snapshot,
    );
}
