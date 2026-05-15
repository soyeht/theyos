//! Inlined orchestrator logic — pure functions that decide flow step sequences.
//!
//! Formerly orchestrator-rs (IPC subprocess). Now lives directly inside
//! executor-rs, eliminating one process-spawn and one IPC round-trip per flow.

pub mod create;
pub mod delete;
pub mod rebuild;
pub mod restart;
pub mod stop;
pub mod types;

pub use create::{is_port_conflict_error, run_create_instance_flow, validate_create_request};
pub use delete::run_delete_instance_flow;
pub use rebuild::run_rebuild_instance_flow;
pub use restart::run_restart_instance_flow;
pub use stop::run_stop_instance_flow;
pub use types::*;
