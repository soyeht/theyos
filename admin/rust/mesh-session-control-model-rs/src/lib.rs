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

pub mod activate;
pub mod commit;
pub mod gc;
pub mod locks;
pub mod record;
pub mod secret_backend;
pub mod store;
pub mod transition;
pub mod validator;
