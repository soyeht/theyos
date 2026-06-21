//! Common vmrunner warm-pool contract types.
//!
//! This crate intentionally owns only data contracts that have active callers.
//! Platform-specific VM lifecycle, networking, boot, and filesystem behavior
//! stays in the Linux and macOS vmrunner crates.

pub mod warm_pool;

pub use warm_pool::{WarmPoolSlotState, WarmPoolSlotStatus, WarmPoolStatus, WarmPoolStatusWire};
