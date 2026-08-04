//! mesh-session-core-rs — B-SESSAO protocol-core primitives.
//!
//! Implements exactly Fila 1 items 1, 2, 4, 5, and 3a of
//! `daisy-bsessao-implementable-queue-post-d4.452cdaf2…` (+ erratum
//! `0107bd2…`), against `daisy-bsessao-v6.7343d075…` (+ erratum
//! `63222d40…`):
//!
//! - [`wire`] — item 1: length-prefixed framing + type-byte/CBOR split.
//! - [`cbor`] — canonical (RFC 8949 deterministic) CBOR support for item 1.
//! - [`noise`] — item 2: Noise XX session-static setup.
//! - [`delegation`] — item 3a: `MeshSessionDelegation` schema/policy/
//!   partial binding. Deliberately does **not** implement signing — see
//!   the module doc for why.
//! - [`rekey`] — item 4: generic rekey threshold/counter state machine.
//! - [`ingress`] — item 5: `PrevalidatedIngress<T>` scaffolding.
//!
//! Explicitly out of scope (per the queue erratum and @kiana's direction
//! while building this crate): item 3b (production delegation acceptance
//! against a live `RosterSnapshotView`), D-8, D-9, the concrete Proof-R/
//! Proof-I/FinalConfirm/Activate/ActivateAck frame schemas, and any
//! concrete DATA/REKEY/CLOSE wire format. Nothing in this crate reaches
//! into `household-rs`, `keystore-rs`, or any other sibling crate.

pub mod cbor;
pub mod delegation;
pub mod error;
pub mod ingress;
pub mod noise;
pub mod rekey;
pub mod wire;
