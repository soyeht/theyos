//! D-9 carrier-B erratum1 E4: compiler-enforced Pending boundary.
//! A Pending admission is linear, and it exposes no forwarding gate before
//! the Ack commit transition consumes it.

#[test]
fn pending_admission_is_linear_and_cannot_forward() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/pending_admission_is_not_clone.rs");
    t.compile_fail("tests/compile-fail/pending_admission_has_no_forwarding_gate.rs");
    t.compile_fail("tests/compile-fail/registry_has_no_immediate_active_bypass.rs");
}
