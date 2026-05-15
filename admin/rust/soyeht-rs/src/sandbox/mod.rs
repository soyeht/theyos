//! Concrete [`Verifier`](crate::verify_sandbox::Verifier) implementations.
//!
//! Current flavors:
//!   * [`firecracker`] — Firecracker microVM on Linux.  Delegates to an
//!     `imagebuilder build <claw> --verify-only` subprocess (Phase I.2b).
//!   * macOS/VZ will be added in a follow-up once the vmrunner-macos-rs
//!     surface exposes a disposable-VM entry point.

pub mod firecracker;
