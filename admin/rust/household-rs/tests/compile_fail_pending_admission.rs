//! D-9 carrier-B erratum1 E4: compiler-enforced Pending boundary.
//! A Pending admission is linear, and it exposes no forwarding gate before
//! the Ack commit transition consumes it.

#[test]
fn pending_admission_is_linear_and_cannot_forward() {
    let t = trybuild::TestCases::new();
    // Glob over this runner's own directory -- see the note in
    // `compile_fail_peer_expectation.rs`. Still one cargo target, so the
    // target inventory ratchet is unaffected by how many fixtures live here.
    t.compile_fail("tests/compile-fail/pending_admission/*.rs");
}
