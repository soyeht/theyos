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
//! - [`intent`] — D9 Point 1, carrier B (`kiana-d9-intent-carrier-b-addendum.c203463c…`):
//!   `SignedMeshConnectionIntent` (0x06) canonical/sign/verify/digest, a
//!   dedicated wire record separate from `AuthFrame`/`AuthFrameBody`, the
//!   caller-injected nonce-ledger and D1-admission seams (fail-closed
//!   defaults shipped, no real persistence). `0x07` (capability) stays
//!   reserved and unreachable.
//! - [`auth_state_machine`] — drives the 3 Noise flights, the 0x06 intent
//!   record, then the 5 auth frames to Active, gating on delegation
//!   policy/signature/binding before ever trusting a peer's embedded key;
//!   also owns the post-Active guarded DATA/CLOSE/REKEY operations on
//!   [`auth_state_machine::ActiveMeshSession`].
//! - [`post_active`] — `DATA`/`REVOKE_NOTICE`/`CLOSE`/`REKEY` (0x10/0x20/
//!   0x30/0x40) wire records, frozen by
//!   `kiana-bsessao-post-active-wire-addendum.b14fcf9520222ad3ab3ac3443ae4b0e7ba219411f41e3389751c92a402b64d8a.md`
//!   (+ provenance-only erratum1 `4be4cd3d0963cbc145b4aeb1f5450e5753e84f1b65e94e84af9ecd29832bf203.md`).
//!
//! Explicitly out of scope: item 3b (production delegation acceptance
//! against a live `RosterSnapshotView`), D-8, capability revocation
//! (`0x07`), how an initiator obtains/mints its own intent before dialing,
//! D-4's real signer, real nonce-ledger/D1 persistence, multiplexing/
//! stream IDs/compression/keepalive/close-reasons/retransmission/
//! fragmentation (addendum §9). Nothing in this crate reaches into
//! `household-rs`, `keystore-rs`, or any other sibling crate.

pub mod auth_frames;
pub mod auth_state_machine;
pub mod cbor;
pub mod delegation;
pub mod error;
pub mod ingress;
pub mod intent;
pub mod noise;
pub mod post_active;
pub mod rekey;
pub mod wire;
