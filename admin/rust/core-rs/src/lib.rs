//! core-rs — shared foundation crate for the theyOS Rust backend.
//!
//! Extracts duplicated utilities from across the workspace into a single
//! dependency. All re-exports preserve existing public APIs so downstream
//! crates can migrate incrementally.

pub mod artifact_gc;
pub mod artifact_lock;
pub mod artifact_meta;
pub mod artifact_registry;
pub mod audit;
pub mod availability;
pub mod boot_id;
pub mod claw_llm;
pub mod constants;
pub mod crash;
#[cfg(feature = "db")]
pub mod db;
pub mod env;
pub mod error;
pub mod guest_image_failure;
pub mod host_resources;
pub mod id;
pub mod ipc;
pub mod maintenance;
pub mod manifest;
pub mod os;
pub mod pagination;
pub mod path;
pub mod poll;
pub mod retry;
pub mod slug;
pub mod templates;
pub mod time;

pub mod network_detect;

#[cfg(target_os = "macos")]
pub mod macos_logging;
