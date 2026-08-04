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

pub mod activate;
pub mod cell;
pub mod commit;
pub mod gc;
pub mod locks;
pub mod record;
pub mod secret_backend;
pub mod store;
pub mod transition;
pub mod validator;
