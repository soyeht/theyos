// @daisy, 2026-08-05, per @ilia: `intent_nonce_ledger_bridge::map_channel`
// is private, so this cannot call it directly — it reproduces that
// function's match arms verbatim (see that module's own source) against
// the REAL `ExpectedChannel`, minus the `Release` arm. The Release arm
// is deliberately omitted: proves the compiler rejects a missing arm
// here today, which is the exact E0004 mechanism that fires automatically
// the day `ExpectedChannel` gains a third variant and this match (or the
// real one) is not updated to match it — not a grep for a missing `_`,
// which would inherit the same hole a `_ =>` catch-all leaves.
fn main() {
    let channel: mesh_session_core_rs::auth_state_machine::ExpectedChannel = todo!();
    let _: household_rs::mesh_intent_nonce_ledger::MeshIntentChannel = match channel {
        mesh_session_core_rs::auth_state_machine::ExpectedChannel::Dev => {
            household_rs::mesh_intent_nonce_ledger::MeshIntentChannel::Dev
        }
    };
}
