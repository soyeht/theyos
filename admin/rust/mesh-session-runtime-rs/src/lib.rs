//! Lane R (@ilia): the not-yet-complete production runtime facade
//! connecting `mesh-session-core-rs`'s protocol traits to real backends
//! (`household-rs`, `keystore-rs`). This round's scope, exactly:
//!
//! - `SystemClock`: a real `mesh_session_core_rs::intent::Clock`.
//! - `ledger_seam`: documents, but does not implement, the
//!   `IntentNonceLedger` requirement a future admission adapter will
//!   carry — no concrete backend exists in this workspace yet.
//! - `roster_bridge::HouseholdRosterSource`: a real
//!   `keystore_rs::mesh_session_bridge::RosterLookupSource` against
//!   `household_rs::machine_roster_store::MachineRosterCoordinator::query_machine_currency`.
//! - `d4_clock::SystemD4Clock`: a real
//!   `keystore_rs::mesh_session_bridge::ClockSource` (D4's own `Clock`,
//!   distinct from `mesh_session_core_rs::intent::Clock` above).
//!
//! Explicitly NOT in this round's scope (declared, not built — see each
//! module's own doc for why real material does not exist yet):
//! `SignatureVerifier`, a real `cell::open` call site, a TTL source, a
//! `generation: NonZeroU64` source, `D1Admission`, `ActiveGateAuthorization`
//! real adapters. `household-rs`'s own `SealedBinding::from_membership_key`
//! (feature `mesh-session-runtime` on that crate) is a separate,
//! already-landed piece this facade will eventually call into, not
//! duplicated here.
//!
//! Everything real in this crate lives behind the `mesh-session-runtime`
//! feature (non-default) — see this crate's own `Cargo.toml` for why
//! `household-rs`/`keystore-rs`/`mesh-session-core-rs` are all optional,
//! feature-gated dependencies rather than required ones (resolver-2
//! feature unification would otherwise make `keystore-rs`'s own
//! `mesh-session` feature un-disable-able workspace-wide).

#[cfg(feature = "mesh-session-runtime")]
mod clock;
#[cfg(feature = "mesh-session-runtime")]
pub use clock::SystemClock;

#[cfg(feature = "mesh-session-runtime")]
mod d4_clock;
#[cfg(feature = "mesh-session-runtime")]
pub use d4_clock::SystemD4Clock;

#[cfg(feature = "mesh-session-runtime")]
mod roster_bridge;
#[cfg(feature = "mesh-session-runtime")]
pub use roster_bridge::HouseholdRosterSource;

#[cfg(feature = "mesh-session-runtime")]
pub mod ledger_seam;

#[cfg(feature = "mesh-session-runtime")]
pub mod signer_seam;
