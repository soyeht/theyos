//! Phase 3 failure-injection harness — handler-side registry (T064).
//!
//! Compiled in only under `cfg(any(test, feature = "failure-injection"))`.
//! `lib.rs` re-exports this module unconditionally as a no-op stub when
//! the feature is disabled so production code that mentions
//! `failure_injection::apply(...)` compiles to a constant `Continue`.
//!
//! See `e2e-rs/src/failure_injector.rs` for the test-side facade and
//! `specs/003-machine-join/contracts/shamir-transition.md` §"Failure-
//! injection test plan" for the documented scenarios.

#![cfg(any(test, feature = "failure-injection"))]
// The registry is test-only infrastructure (the cfg above guarantees
// it never compiles into a production binary). Clippy nags about
// `#[must_use]` and `# Panics` doc sections on its public API, but
// the API IS panicking by design (Panic action) and IS used purely
// for side effects (arm/reset). Silence the noise at module scope.
#![allow(
    clippy::must_use_candidate,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::doc_markdown
)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;

use tokio::sync::Notify;

/// Named crash points the M1 / M2 handlers honour when compiled with
/// the `failure-injection` feature. Each variant maps to one of the
/// scenarios in `contracts/shamir-transition.md` §"Failure-injection
/// test plan" and the T063 task description.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InjectionPoint {
    /// M2's `local/finalize` hits this immediately after CBOR decode +
    /// canonical-bytes check, before any staged file is opened.
    M2BeforeStage,
    /// M2's `local/finalize` hits this after the founder-cert staged
    /// file has been written but before `staged.commit()` runs.
    M2AfterFounderCertStaged,
    /// M2's `local/finalize` hits this immediately before `FinalizeAck`
    /// is encoded onto the response stream.
    M2BeforeAckEncode,
    /// M1's `owner_approve_handler` hits this after `finalize_with_m2`
    /// returns Ok and before `commit_preserve_on_error` runs (between
    /// 2PC steps 11 and 12).
    M1AfterAck,
    /// M1's `owner_approve_handler` hits this after
    /// `commit_preserve_on_error` returns Ok (i.e., step 12 rename +
    /// step 13 sole-shard unlink + keystore destroy all done) and
    /// BEFORE the `machine-joined` event append (step 14).
    M1AfterStagedCommit,
    /// `CeremonyTxn::commit_preserve_on_error` hits this synchronously
    /// IMMEDIATELY after `staged.commit_preserve_on_error()` returns
    /// Ok (step 12 staged-rename done) and BEFORE the keystore
    /// destroy + sole-shard unlink (step 13). Models "M1 crash
    /// between 2PC step 12 and step 13".
    ///
    /// Consulted via [`apply_sync`] because
    /// `CeremonyTxn::commit_preserve_on_error` runs inside a
    /// `tokio::task::spawn_blocking` and cannot await async hooks.
    M1AfterStagedRename,
    /// M1's `owner_approve_handler` hits this after the sole-shard
    /// unlink runs but before the `machine-joined` event append.
    M1AfterSoleShardDelete,
}

/// What the handler should do when it reaches a registered injection
/// point.
#[derive(Debug)]
pub enum InjectionAction {
    /// Panic with the supplied message.
    Panic(&'static str),
    /// Skip the next IO operation that follows the injection point.
    SkipWrite,
    /// Block until the supplied [`Notify`] is signalled.
    WaitNotify(Arc<Notify>),
    /// Signal the caller to surface the supplied message via its
    /// existing error path.
    EarlyReject(&'static str),
}

impl InjectionAction {
    pub fn panic(msg: &'static str) -> Self {
        Self::Panic(msg)
    }

    pub fn skip_write() -> Self {
        Self::SkipWrite
    }

    pub fn wait(notify: Arc<Notify>) -> Self {
        Self::WaitNotify(notify)
    }

    pub fn early_reject(msg: &'static str) -> Self {
        Self::EarlyReject(msg)
    }
}

struct Registry {
    pending: Mutex<HashMap<InjectionPoint, InjectionAction>>,
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry {
        pending: Mutex::new(HashMap::new()),
    })
}

/// Register an injection. Replaces any prior registration at the same
/// point. Tests typically call this before driving the ceremony.
pub fn arm(point: InjectionPoint, action: InjectionAction) {
    let mut g = registry().pending.lock().expect("injection registry");
    g.insert(point, action);
}

/// Clear every pending injection.
pub fn reset() {
    let mut g = registry().pending.lock().expect("injection registry");
    g.clear();
}

/// Consume a registered injection at `point`, if any.
#[must_use]
pub fn pop(point: InjectionPoint) -> Option<InjectionAction> {
    let mut g = registry().pending.lock().expect("injection registry");
    g.remove(&point)
}

/// Peek at a registered injection without consuming it.
#[must_use]
pub fn is_armed(point: InjectionPoint) -> bool {
    let g = registry().pending.lock().expect("injection registry");
    g.contains_key(&point)
}

/// Outcome of [`apply`] — what the handler should do next.
#[derive(Debug)]
pub enum Outcome {
    /// No injection (or the registered injection has fully resolved).
    Continue,
    /// `SkipWrite` — caller should skip the next staged write.
    Skip,
    /// `EarlyReject` — caller should surface this via its error path.
    EarlyReject(&'static str),
}

/// Synchronous variant of [`apply`] for code paths that cannot
/// `await` (e.g., `CeremonyTxn::commit_preserve_on_error` runs inside
/// `tokio::task::spawn_blocking`). Supports `Panic`, `SkipWrite`, and
/// `EarlyReject`. A registered `WaitNotify` is treated as `Continue`
/// (sync hook cannot block on a notify) — tests that need to freeze a
/// sync hook should arm `Panic` and abort the blocking task.
#[must_use]
pub fn apply_sync(point: InjectionPoint) -> Outcome {
    let Some(action) = pop(point) else {
        return Outcome::Continue;
    };
    match action {
        InjectionAction::Panic(msg) => {
            panic!("failure-injection at {point:?}: {msg}")
        }
        InjectionAction::SkipWrite => Outcome::Skip,
        InjectionAction::WaitNotify(_) => Outcome::Continue,
        InjectionAction::EarlyReject(msg) => Outcome::EarlyReject(msg),
    }
}

/// Apply the registered injection (if any) for `point`.
///
/// `Panic` panics in-place (the surrounding tokio task aborts).
/// `WaitNotify` awaits the notify and then returns `Continue`.
/// `SkipWrite` returns `Outcome::Skip`.
/// `EarlyReject(msg)` returns `Outcome::EarlyReject(msg)`.
/// No registered injection: `Outcome::Continue`.
pub async fn apply(point: InjectionPoint) -> Outcome {
    let Some(action) = pop(point) else {
        return Outcome::Continue;
    };
    match action {
        InjectionAction::Panic(msg) => {
            panic!("failure-injection at {point:?}: {msg}")
        }
        InjectionAction::SkipWrite => Outcome::Skip,
        InjectionAction::WaitNotify(notify) => {
            notify.notified().await;
            Outcome::Continue
        }
        InjectionAction::EarlyReject(msg) => Outcome::EarlyReject(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn arm_and_pop_round_trip() {
        reset();
        assert!(!is_armed(InjectionPoint::M1AfterAck));
        arm(InjectionPoint::M1AfterAck, InjectionAction::skip_write());
        assert!(is_armed(InjectionPoint::M1AfterAck));
        let popped = pop(InjectionPoint::M1AfterAck);
        assert!(matches!(popped, Some(InjectionAction::SkipWrite)));
        assert!(!is_armed(InjectionPoint::M1AfterAck));
    }

    #[tokio::test]
    async fn apply_continue_when_unarmed() {
        reset();
        let outcome = apply(InjectionPoint::M2BeforeStage).await;
        assert!(matches!(outcome, Outcome::Continue));
    }

    #[tokio::test]
    async fn apply_skip_when_armed() {
        reset();
        arm(
            InjectionPoint::M2AfterFounderCertStaged,
            InjectionAction::skip_write(),
        );
        let outcome = apply(InjectionPoint::M2AfterFounderCertStaged).await;
        assert!(matches!(outcome, Outcome::Skip));
    }

    #[tokio::test]
    async fn apply_wait_resumes_on_notify() {
        reset();
        let n = Arc::new(Notify::new());
        arm(
            InjectionPoint::M1AfterStagedCommit,
            InjectionAction::wait(Arc::clone(&n)),
        );
        let task = tokio::spawn(async move { apply(InjectionPoint::M1AfterStagedCommit).await });
        tokio::task::yield_now().await;
        n.notify_one();
        let outcome = task.await.expect("apply task");
        assert!(matches!(outcome, Outcome::Continue));
    }
}
