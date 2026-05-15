//! Phase 3 failure-injection harness — test-side facade (T063).
//!
//! The actual registry lives in `server_rs::failure_injection` (gated
//! behind the `failure-injection` feature on `server-rs` so production
//! binaries compile it out entirely). This module re-exports the
//! arming API so individual `phase3_atomic_rollback*` tests can
//! `use phase3_support::failure_injector::{InjectionPoint, InjectionAction, arm, reset}`.
//!
//! ## Deviation from `tasks.md` T063 wording
//!
//! T063 specifies `admin/rust/e2e-rs/src/failure_injector.rs` as the
//! file path. We place the facade under `tests/phase3_support/` instead
//! because:
//!
//! 1. The handlers that consult the registry live in `server-rs`. The
//!    registry has to share a process with them, so it must be reachable
//!    from `server-rs` code.
//! 2. `e2e-rs` already pulls `server-rs` in as a `dev-dependency` (used
//!    by every `phase3_*.rs` integration test). `src/` modules cannot
//!    consume `dev-dependencies`, so a `src/failure_injector.rs` module
//!    cannot reach `server_rs::failure_injection::*`.
//! 3. Promoting `server-rs` to a non-dev `[dependencies]` entry would
//!    pull every Phase 3 server symbol into the `e2e-runner` binary
//!    even when the harness is not in use, blowing up the runner's
//!    target footprint for no functional benefit.
//!
//! Tests-side facade in `tests/phase3_support/` keeps the dep direction
//! sane while satisfying the T063 contract on the public API
//! (`InjectionPoint`, `InjectionAction`, `arm`, `reset`, `pop`,
//! `is_armed`, `apply`, `Outcome`).

#![allow(unused_imports)]

pub use server_rs::failure_injection::{
    InjectionAction, InjectionPoint, Outcome, apply, arm, is_armed, pop, reset,
};

use std::sync::{Mutex, MutexGuard, OnceLock};

/// Serialize tests that arm injections so two `#[tokio::test]`
/// functions running in parallel cannot pop each other's
/// registrations.
///
/// `cargo test` runs `#[test]` and `#[tokio::test]` on a shared
/// thread pool. The injection registry is process-global (single-
/// shot pop), so without this lock test A can register an arm at
/// point X and test B (running in parallel) can fire the handler
/// that pops X — leaving A's expected behaviour unobserved and B
/// inadvertently driving down a crash path it didn't ask for.
///
/// Tests acquire the lock at their start; the guard drops at the
/// end of the test scope.
pub fn lock_injection_tests() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let lock = LOCK.get_or_init(|| Mutex::new(()));
    match lock.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}
