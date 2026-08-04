//! D-1 successor (@kiana E1): a REAL compile-fail proof that
//! `AuthenticatedPeerClaim` — the responder-side counterpart to
//! `PeerExpectation` — has no production constructor, mirroring
//! `compile_fail_peer_expectation.rs`'s own RED-R23 proof for the
//! initiator side. Two independent, compiler-enforced reasons, either
//! alone sufficient:
//! - the field is private, so a struct literal from outside its defining
//!   module cannot be built at all;
//! - `injected_for_harness` is `#[cfg(test)] pub(crate)` — invisible
//!   across the crate boundary this fixture compiles across, and absent
//!   entirely from a non-test build of the `household_rs` rlib these
//!   fixtures link against.

#[test]
fn authenticated_peer_claim_has_no_production_constructor() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/authenticated_peer_claim_struct_literal.rs");
    t.compile_fail("tests/compile-fail/authenticated_peer_claim_injected_for_harness.rs");
}
