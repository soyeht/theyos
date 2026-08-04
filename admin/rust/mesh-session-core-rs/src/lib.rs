//! mesh-session-core-rs — B-SESSAO protocol-core primitives.
//!
//! Implements Fila 1 items 1, 2, 4, 5, and 3a of
//! `daisy-bsessao-implementable-queue-post-d4.452cdaf2…` (+ erratum
//! `0107bd2…`), against `daisy-bsessao-v6.7343d075…` (+ erratum
//! `63222d40…`), plus the 5 concrete auth frame schemas (v6 §4) and the
//! auth state machine through Active (v6 §13 + erratum), authorized
//! 2026-08-04 once the CBOR/wire foundation below was hardened:
//!
//! - [`wire`] — item 1: length-prefixed framing (fixed-ceiling entry
//!   points only) + type-byte/CBOR split.
//! - [`cbor`] — canonical (RFC 8949 deterministic) CBOR support for item 1.
//! - [`noise`] — item 2: Noise XX session-static setup. `HandshakeOutcome`/
//!   `run_xx_handshake` are `pub(crate)` — only [`auth_state_machine`] may
//!   drive a raw handshake; see its module doc.
//! - [`delegation`] — item 3a: `MeshSessionDelegation` schema/policy/
//!   partial binding. Deliberately does **not** implement signing — see
//!   the module doc for why.
//! - [`rekey`] — item 4: generic rekey threshold/counter state machine,
//!   permit-gated (misuse-resistant) send-side API.
//! - [`ingress`] — item 5: `PrevalidatedIngress<T>` scaffolding. `consume`
//!   is `pub(crate)` — only [`auth_state_machine`] may take one apart.
//! - [`auth_frames`] — the 5 auth frame schemas (v6 §4) + D9 Point2
//!   (`connection_intent_digest`) + K_mesh signing/verification.
//! - [`auth_state_machine`] — drives the 3 Noise flights then the 5 auth
//!   frames to Active, gating on delegation policy/signature/binding
//!   before ever trusting a peer's embedded key.
//!
//! Explicitly out of scope: item 3b (production delegation acceptance
//! against a live `RosterSnapshotView`), D-8, D9 Point 1
//! (`SignedMeshConnectionIntent`/`Capability`, `ExpectedResponder`
//! construction from an intent, nonce ledger, capability revocation), and
//! any concrete DATA/REKEY/CLOSE wire format. Nothing in this crate
//! reaches into `household-rs`, `keystore-rs`, or any other sibling crate.

pub mod auth_frames;
pub mod auth_state_machine;
pub mod cbor;
pub mod delegation;
pub mod error;
pub mod ingress;
pub mod noise;
pub mod rekey;
pub mod wire;
