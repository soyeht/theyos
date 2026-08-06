//! @daisy, 2026-08-05, per @ilia (ledger item, armed-not-exercised):
//! `intent_nonce_ledger_bridge::map_channel`'s exhaustive match (no
//! wildcard arm) was only verified by a unit test asserting both known
//! arms map correctly — that proves the two cases present today are
//! right, not that a THIRD case would be caught. A `#[test]` that never
//! ran (because the code it exercises never compiled) cannot prove
//! that by itself — trybuild forces a real, separate `rustc`
//! invocation whose failure is the proof, checked on every `cargo
//! test` run rather than relying on a developer to notice by
//! inspection if a future edit adds a `_ =>` catch-all.
//!
//! Not a grep for the absence of `_`: a grep-based check has the same
//! shape as the `_ =>` hole it exists to catch — it proves the source
//! text doesn't currently contain a wildcard, never that the compiler
//! would reject one being added. This proves the compiler mechanism
//! itself, via a real fixture missing an arm against the real
//! `ExpectedChannel`.

#[cfg(feature = "mesh-session-runtime")]
#[test]
fn channel_mapping_rejects_a_missing_arm() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/channel_mapping_is_exhaustive.rs");
}
