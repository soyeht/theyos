//! Lane R (@ilia): the not-yet-complete production runtime facade
//! connecting `mesh-session-core-rs`'s protocol traits to real backends
//! (`household-rs`, `keystore-rs`). This round's scope, exactly:
//!
//! - `SystemClock`: a real `mesh_session_core_rs::intent::Clock`.
//! - `intent_nonce_ledger_bridge::HouseholdIntentNonceLedger`: a real
//!   `mesh_session_core_rs::intent::IntentNonceLedger` over
//!   `household_rs::mesh_intent_nonce_ledger::MeshIntentNonceLedger`.
//!   Exhaustive channel mapping (no wildcard arm — `ExpectedChannel` and
//!   household's `MeshIntentChannel` are two distinct enums); the
//!   `TrustedWallFloor` it needs is sourced fresh on every call from
//!   `MachineRosterCoordinator::current_snapshot_with_trusted_wall_floor`,
//!   never constructed by this crate (that type's only constructor is
//!   private to household-rs); `MayHaveTakenEffect` is never reclassified
//!   into `Committed`/`AlreadyConsumed` for any of the real ledger's
//!   commit stages — see that module's own doc and tests.
//! - `ledger_seam`: predates the bridge above and is NOT used by it —
//!   see that module's own doc for why (the bridge sources its floor
//!   fresh per call rather than through this seam's construction-time
//!   `TrustedFloorProof`, which would go stale across a long-lived
//!   adapter instance). Kept for the type-level discipline it still
//!   documents for anything else in this crate that later needs durable
//!   nonce consumption.
//! - `roster_bridge::HouseholdRosterSource`: a real
//!   `keystore_rs::mesh_session_bridge::RosterLookupSource` against
//!   `household_rs::machine_roster_store::MachineRosterCoordinator::query_machine_currency`.
//! - `d4_clock::SystemD4Clock`: a real
//!   `keystore_rs::mesh_session_bridge::ClockSource` (D4's own `Clock`,
//!   distinct from `mesh_session_core_rs::intent::Clock` above).
//!
//! - `d1_admission::RegistryD1Admission`: a real
//!   `mesh_session_core_rs::intent::D1Admission` +
//!   `ActiveGateAuthorization` over `household_rs::mesh_session_registry
//!   ::MeshSessionRegistry`. Generic over `H: RevocableMeshSession`; the
//!   concrete `H` and whatever produces real `Weak<H>` handles are a
//!   different piece of the pipeline (see that module's own doc).
//!
//! Explicitly NOT in this round's scope (declared, not built — see
//! `signer_seam` and each other module's own doc for why real material
//! does not exist yet):
//! `SignatureVerifier`, a real `cell::open` call site, a TTL source, a
//! `generation: NonZeroU64` source, and a concrete `H: RevocableMeshSession`
//! (and whatever produces real `Weak<H>` handles for it). `household-rs`'s
//! own `SealedBinding::from_membership_key` (feature `mesh-session-runtime`
//! on that crate) is a separate, already-landed piece this facade calls
//! into, not duplicated here.
//!
//! Everything real in this crate lives behind the `mesh-session-runtime`
//! feature (non-default) — see this crate's own `Cargo.toml` for why
//! `household-rs`/`keystore-rs`/`mesh-session-core-rs` are all optional,
//! feature-gated dependencies rather than required ones (resolver-2
//! feature unification would otherwise make `keystore-rs`'s own
//! `mesh-session` feature un-disable-able workspace-wide).
//!
//! doc-scope: every declared module is named in this crate doc.

#[cfg(feature = "mesh-session-runtime")]
mod clock;
#[cfg(feature = "mesh-session-runtime")]
pub use clock::SystemClock;

#[cfg(feature = "mesh-session-runtime")]
mod d4_clock;
#[cfg(feature = "mesh-session-runtime")]
pub use d4_clock::SystemD4Clock;

#[cfg(feature = "mesh-session-runtime")]
mod d1_admission;
#[cfg(feature = "mesh-session-runtime")]
pub use d1_admission::{RegistryActiveGate, RegistryD1Admission, RegistryD1Pending};

#[cfg(feature = "mesh-session-runtime")]
mod intent_nonce_ledger_bridge;
#[cfg(feature = "mesh-session-runtime")]
pub use intent_nonce_ledger_bridge::HouseholdIntentNonceLedger;

#[cfg(feature = "mesh-session-runtime")]
mod roster_bridge;
#[cfg(feature = "mesh-session-runtime")]
pub use roster_bridge::HouseholdRosterSource;

#[cfg(feature = "mesh-session-runtime")]
pub mod ledger_seam;

#[cfg(feature = "mesh-session-runtime")]
pub mod signer_seam;
