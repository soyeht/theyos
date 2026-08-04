//! RED-R23 (D-1/B-ROSTER-ADAPTER v2, erratum1) + D-1 successor (@kiana E1):
//! REAL compile-fail proofs that neither peer-authority claim type —
//! `PeerExpectation` (initiator) nor `AuthenticatedPeerClaim` (responder,
//! see `machine_roster_authority.rs`'s "Responder-side peer binding"
//! section) — has a production constructor, not a comment asserting it.
//! A `#[test]` that never ran (because the code it exercises never
//! compiled) cannot prove this by itself — trybuild here forces an
//! actual, separate `rustc` invocation whose failure is the proof, checked
//! on every `cargo test` run rather than relying on a developer to notice
//! by inspection if someone later adds a public constructor.
//!
//! Both types' fixtures fail for the same two independent,
//! compiler-enforced reasons — both real, either alone already
//! sufficient:
//! - the field(s) are private, so a struct literal from outside the
//!   defining module cannot be built at all;
//! - `injected_for_harness` is `#[cfg(test)] pub(crate)` — invisible
//!   across the crate boundary this trybuild fixture compiles across, and
//!   (independently) absent entirely from a non-test build of the
//!   `household_rs` rlib these fixtures link against.
//!
//! Both proofs share this one cargo test target (round D-1 successor,
//! @kiana) rather than each getting its own `tests/*.rs` file — this
//! project's Cargo target inventory is enumerated and pinned elsewhere
//! (`r1a7_enumerates_linked_targets_and_proves_zero_production_callers`);
//! adding a target per fixture pair inflates that count for no benefit
//! when an existing trybuild runner can just run more cases.

#[test]
fn peer_authority_claims_have_no_production_constructor() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/peer_expectation_struct_literal.rs");
    t.compile_fail("tests/compile-fail/peer_expectation_injected_for_harness.rs");
    t.compile_fail("tests/compile-fail/authenticated_peer_claim_struct_literal.rs");
    t.compile_fail("tests/compile-fail/authenticated_peer_claim_injected_for_harness.rs");
}
