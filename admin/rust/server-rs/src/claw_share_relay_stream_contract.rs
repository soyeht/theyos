//! Re-export shim for the Product A `relay_stream` offer contract.
//!
//! C7c-2a moved the contract (and the `RendezvousToken` leaf) into household-rs
//! so the guest (friend-cli) can parse + verify an offer without depending on
//! the engine crate. The types are unchanged (byte-identical CBOR / signatures /
//! Noise-prologue bytes); this module re-exports them at the original path so
//! every existing `crate::claw_share_relay_stream_contract::…` import keeps
//! working. The engine-only pieces (issuer-trust seam, Noise initiator/responder,
//! store, pool, admission, target router, mount, provision, runtime) stay here.

pub use household_rs::claw_share_relay_stream_contract::*;
