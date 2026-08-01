//! S0 — neutral tunnel wire mechanics, as a crate rather than a module.
//!
//! # Why this is a crate and not a module in `household-rs`
//!
//! The approved S0 design specifies the cross-import guard as a *reachability*
//! property: "the check must follow re-exports". No instrument in this
//! repository can evaluate one. `.github/scripts` holds six shell checkers, none
//! doing Rust symbol reachability, and the Phase-0 compileout checker is grep
//! over source text.
//!
//! A grep for `claw_vpn` inside a neutral *module* passes only by accident of
//! current content. `household-rs/src/lib.rs` already carries ten crate-root
//! `pub use` statements, so
//!
//! ```text
//! pub use claw_vpn::ClawVpnAgentSessionCore;   // in household-rs/src/lib.rs
//! use household_rs::ClawVpnAgentSessionCore;   // in the "neutral" module
//! ```
//!
//! reaches claw authority with the token `claw_vpn` appearing nowhere near the
//! use site. That is the crate's own established idiom, not a novel shape — so
//! the grep guard would have failed open against existing convention.
//!
//! Measured at the pre-extraction base: a `pub type` alias exposing
//! `ClawVpnAgentSessionCore` from the neutral module compiled clean under BOTH
//! `cargo check` and `cargo clippy -- -D warnings`. Nothing detected it. The
//! reach was not even an `unused_imports` warning, because the alias was used.
//!
//! As a separate crate the property is enforced by `cargo check`: with no
//! dependency edge to `household-rs`, no alias chain resolves. A policy that
//! depended on nobody writing an idiomatic line became a property the compiler
//! checks.
//!
//! # Surface discipline
//!
//! [`tunnel_wire`] is declared and **never re-exported from this crate root** —
//! deliberately, since a crate-root re-export is exactly the shape that defeated
//! the guard this crate replaces. Consumers name the module path.

pub mod canonical;
pub mod frame_stream;
pub mod pollable_pump;
pub mod tunnel_wire;
pub mod worker_pool;
