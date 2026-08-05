//! Lane R (@ilia): the `IntentNonceLedger` seam this facade will require
//! once wired to a real backend. **Not implemented here — no concrete
//! adapter exists in this workspace yet, and this crate deliberately
//! does not fabricate one.** Every future constructor in this crate that
//! needs durable nonce consumption must accept
//! `L: mesh_session_core_rs::intent::IntentNonceLedger` generically,
//! exactly the way `mesh-session-core-rs`'s own handshake functions
//! already do — the re-export below exists so that requirement is
//! visible in this crate's own type surface, not only in prose
//! disconnected from any code a future implementer will actually touch.
//!
//! **The only sanctioned source, once it lands:**
//! `household-rs::MachineRosterCoordinator::open_mesh_intent_nonce_ledger`
//! (feature `mesh-session-runtime` on that crate). No other construction
//! path is approved — see the frozen adapter-design contract this seam
//! anticipates (`daisy-nonce-ledger-adapter-design.7571e9a3….md`,
//! 2026-08-04, self-hash verified).
//!
//! **`MayHaveTakenEffect` must never be reclassified.** A future adapter
//! mapping the real ledger's own outcome down to
//! [`NonceConsumeOutcome`] must map its `MayHaveTakenEffect`-shaped case
//! to [`NonceConsumeOutcome::MayHaveTakenEffect`] — never `Committed`,
//! never `AlreadyConsumed` — matching that enum's own documented contract
//! (`mesh-session-core-rs/src/intent.rs`). A durable ledger that guesses
//! `Committed` on an ambiguous outcome reintroduces exactly the
//! double-admission risk the three-valued outcome exists to prevent.

pub use mesh_session_core_rs::intent::{IntentNonceLedger, NonceConsumeOutcome};
