//! RED-R23 (D-1/B-ROSTER-ADAPTER v2, erratum1): a REAL compile-fail proof
//! that `PeerExpectation` has no production constructor, not a comment
//! asserting it. A `#[test]` that never ran (because the code it exercises
//! never compiled) cannot prove this by itself — trybuild here forces an
//! actual, separate `rustc` invocation whose failure is the proof, checked
//! on every `cargo test` run rather than relying on a developer to notice
//! by inspection if someone later adds a public constructor.
//!
//! The two fixtures below fail for two independent, compiler-enforced
//! reasons -- both real, either alone already sufficient:
//! - `PeerExpectation`'s fields are private, so a struct literal from
//!   outside its defining module cannot be built at all;
//! - `injected_for_harness` is `#[cfg(test)] pub(crate)` -- invisible
//!   across the crate boundary this trybuild fixture compiles across, and
//!   (independently) absent entirely from a non-test build of the
//!   `household_rs` rlib these fixtures link against.

#[test]
fn peer_expectation_has_no_production_constructor() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/peer_expectation_struct_literal.rs");
    t.compile_fail("tests/compile-fail/peer_expectation_injected_for_harness.rs");
    t.compile_fail("tests/compile-fail/mesh_intent_nonce_ledger_raw_open.rs");
}
