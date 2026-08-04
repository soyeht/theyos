//! D-4 `MeshSessionSigner` single-record control state — executable model.
//!
//! This crate is a standalone, from-scratch model of the control state
//! machine specified by:
//! - GO `kiana-d4-single-record-architecture-go.aecc5ecf…`
//! - erratum1 `…-erratum1.4d0e7e25…` (GC lock naming, single-transition activation)
//! - closed sweep `kiana-d4-v10-closed-sweep.953cc64d…`
//! - terminal sweep `kiana-d4-v11-terminal-sweep.c738e02c…`
//!
//! It exists to convert every blocker those sweeps found into an executable
//! invariant or test, not another prose freeze. It depends on nothing from
//! `household-rs`/`keystore-rs`/`admin/rust`'s workspace — roster lookup,
//! signature verification, and the physical secret backend are all
//! trait-injected so this crate never invents an API against real code it
//! cannot compile against.
//!
//! No production closure is claimed here. Gates that remain open (Secure
//! Enclave measurements, real TPM round-trip, `ApprovedFallback`, cross-peer
//! revoke transport, anti-rollback against filesystem snapshot restore) are
//! unaffected by anything in this crate.
//!
//! # Default build surface (round 6, items 4/5)
//!
//! Two things are gated OFF by default, each behind its own Cargo feature,
//! because a doc comment saying "test-only" or "no production path" is not
//! a control — in a normal build both were previously just as `pub` as
//! everything else:
//! - `test-support`: `cell::FaultInjectingCell`, `cell::open_fault_injecting`,
//!   `store::FaultInjectingStore`, and `ControlRecordCell::seed_for_test` —
//!   the fault-injection test double and the one escape hatch that bypasses
//!   `transition::apply` entirely.
//! - `roster-sync-unratified`: `validator::RosterSyncPurpose` — this crate
//!   has no ratified production authority model for `PurposeId::RosterSync`
//!   (D6 owns that and has not ratified anything here).
//!
//! The three `compile_fail` blocks below prove the gated surface is
//! genuinely absent under a plain `cargo test`/`cargo build` (no
//! `--features`) — if any of these three imports ever start compiling by
//! default, the corresponding doctest starts *passing* instead of failing
//! its own "must not compile" check, which itself then fails the doctest.
//!
//! ```compile_fail
//! use mesh_session_control_model_rs::cell::FaultInjectingCell;
//! ```
//!
//! ```compile_fail
//! use mesh_session_control_model_rs::cell::open_fault_injecting;
//! ```
//!
//! ```compile_fail
//! use mesh_session_control_model_rs::validator::RosterSyncPurpose;
//! ```
//!
//! Round 6, wave 9 — the audit of `6bd957a4` noted the previous wave added
//! `load_revalidated_report_for_test` without a matching compile-fail, so
//! the gating was asserted rather than proven. It is proven here:
//!
//! ```compile_fail
//! use mesh_session_control_model_rs::activate::load_revalidated_report_for_test;
//! ```
//!
//! The signing surface is sealed, not merely documented. **No downstream
//! crate can implement `SignPrimitive`**, so no foreign code can ever run
//! inside the roster-lease + `SignGuard` critical section — this is the
//! mechanism that replaces the removed public closure, and it is what makes
//! "the closure cannot capture a different signer" and "the operation
//! cannot self-deadlock by calling `cell.commit`" structural rather than
//! advisory:
//!
//! ```compile_fail
//! use mesh_session_control_model_rs::sign::{
//!     OpaqueSignPreimage, OpaqueSignature, SignPrimitive,
//! };
//! struct Evil;
//! impl SignPrimitive for Evil {
//!     fn sign_opaque(&self, _p: &OpaqueSignPreimage) -> OpaqueSignature {
//!         OpaqueSignature::new(vec![])
//!     }
//! }
//! ```
//!
//! The only implementation that exists anywhere is gated out of a default
//! build, which is what "the production signing surface stays closed until
//! the keystore bridge lands" means concretely:
//!
//! ```compile_fail
//! use mesh_session_control_model_rs::sign::FakeSignPrimitive;
//! ```
//!
//! And the sign path never hands back anything detachable — there is no
//! accessor for the sealed binding, so the wave-8 defect
//! (`|a| a.binding().clone()`) has no spelling at all:
//!
//! ```compile_fail
//! fn detach(c: &mesh_session_control_model_rs::sign::SignerCapability<'_>) {
//!     let _ = c.binding();
//! }
//! ```
//!
//! Taking the sign-path guard directly is likewise no longer public:
//!
//! ```compile_fail
//! fn take(cell: &mesh_session_control_model_rs::cell::ControlRecordCell) {
//!     let _ = cell.acquire_for_sign();
//! }
//! ```

pub mod activate;
pub mod cell;
pub mod commit;
pub mod gc;
pub mod locks;
pub mod record;
pub mod secret_backend;
pub mod sign;
pub mod store;
pub mod transition;
pub mod validator;
