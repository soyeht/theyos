//! Lock ordering. Fixes the v11 sweep finding directly: `turnstile` must be
//! held **until** `access` is actually acquired, then released — not
//! released before attempting to acquire `access`. Modeled with real
//! `std::sync` primitives (this crate has no file-lock/`fs2` dependency —
//! that binding lives in the real integration, outside this standalone
//! model) plus an `OrderSpy` so the acquire/release sequence is asserted by
//! a test, not just read by eye.
//!
//! Successor to the generation audited at commit `d4ecb658` (NO-GO, finding
//! 2): `SignGuard`/`MutateGuard` are now two distinct concrete types, not
//! two variants of one enum — `store::AtomicControlRecordStore::replace_exact`
//! requires a `&MutateGuard` in its signature, so it is a *compile* error,
//! not just a documented convention, to call it while holding only a shared
//! sign-path guard.
//!
//! Second-round fix: a `&MutateGuard` alone only proves "the caller holds
//! *some* exclusive guard," not that it was acquired from the specific
//! `MeshSignerLocks` a given store is bound to. Because `MeshSignerLocks`
//! and the store are constructed independently, nothing previously stopped
//! a guard from one `MeshSignerLocks` instance being handed to
//! `replace_exact` on a store bound to a *different* one — two
//! independently constructed lock sets over the same path would not
//! exclude each other, reopening the exact compare-then-write race the
//! guard requirement was meant to close. Every guard now carries a
//! `LockToken` unique to the `MeshSignerLocks` that issued it; a store is
//! constructed with the token of the one lock set it accepts guards from,
//! and `replace_exact` asserts the two match.

use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Opaque identity of a `MeshSignerLocks` instance. Publicly constructible
/// only via `MeshSignerLocks::token`, never forged out of thin air — a
/// store bound to token T only ever accepts guards stamped with T.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockToken(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockEvent {
    TurnstileAcquire,
    TurnstileRelease,
    AccessAcquireShared,
    AccessAcquireExclusive,
    AccessRelease,
}

#[derive(Default)]
pub struct OrderSpy {
    events: Mutex<Vec<LockEvent>>,
}

impl OrderSpy {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    fn record(&self, e: LockEvent) {
        self.events.lock().unwrap().push(e);
    }
    #[must_use]
    pub fn events(&self) -> Vec<LockEvent> {
        self.events.lock().unwrap().clone()
    }
}

pub struct MeshSignerLocks {
    turnstile: Mutex<()>,
    access: RwLock<()>,
    spy: Arc<OrderSpy>,
    token: LockToken,
}

impl MeshSignerLocks {
    #[must_use]
    pub fn new(spy: Arc<OrderSpy>) -> Self {
        Self {
            turnstile: Mutex::new(()),
            access: RwLock::new(()),
            spy,
            token: LockToken(rand::random()),
        }
    }

    #[must_use]
    pub fn token(&self) -> LockToken {
        self.token
    }

    /// Sign path: turnstile -> access(shared) -> release turnstile.
    /// Turnstile is held across the `access` acquisition, not released
    /// beforehand — the v11 bug released it in a `{ }` block that closed
    /// *before* `access` was requested, which let new readers race ahead of
    /// a waiting writer with no ordering guarantee at all.
    pub fn acquire_for_sign(&self) -> SignGuard<'_> {
        let t = self.turnstile.lock().unwrap();
        self.spy.record(LockEvent::TurnstileAcquire);
        let g = self.access.read().unwrap();
        self.spy.record(LockEvent::AccessAcquireShared);
        drop(t);
        self.spy.record(LockEvent::TurnstileRelease);
        SignGuard(g, Arc::clone(&self.spy))
    }

    /// Mutation path: turnstile -> access(exclusive) -> release turnstile.
    /// Returns a distinct type from `acquire_for_sign` — see module doc.
    pub fn acquire_for_mutation(&self) -> MutateGuard<'_> {
        let t = self.turnstile.lock().unwrap();
        self.spy.record(LockEvent::TurnstileAcquire);
        let g = self.access.write().unwrap();
        self.spy.record(LockEvent::AccessAcquireExclusive);
        drop(t);
        self.spy.record(LockEvent::TurnstileRelease);
        MutateGuard(g, Arc::clone(&self.spy), self.token)
    }
}

/// `gc_serial` — exclusive, held by GC workers only, for the entire tick
/// including the slow `backend` call (erratum1 E1). No other flow ever
/// acquires it, so it cannot participate in a lock-ordering cycle with
/// `turnstile`/`access`. Successor fix (audit finding 6, "gc_serial RAII
/// real"): `gc::gc_worker_tick` now actually takes and holds this guard for
/// the whole tick, rather than leaving acquisition as an undocumented,
/// unenforced caller responsibility.
pub struct GcSerialLock {
    inner: Mutex<()>,
}

impl Default for GcSerialLock {
    fn default() -> Self {
        Self::new()
    }
}

impl GcSerialLock {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(()),
        }
    }
    pub fn acquire(&self) -> MutexGuard<'_, ()> {
        self.inner.lock().unwrap()
    }
}

/// Shared access — sufficient for signing / read-only use. Cannot be passed
/// where a `MutateGuard` is required. Carries no `LockToken`: the sign path
/// never calls `replace_exact`, so there is nothing for a token to guard
/// here.
pub struct SignGuard<'a>(#[allow(dead_code)] RwLockReadGuard<'a, ()>, Arc<OrderSpy>);

/// Exclusive access — required by any store mutation
/// (`AtomicControlRecordStore::replace_exact`). This is the type-level
/// enforcement audit finding 2 asked for: the store cannot be mutated
/// without a caller holding one of these, and the only way to obtain one is
/// `MeshSignerLocks::acquire_for_mutation`, which enforces the
/// turnstile-then-access ordering. The embedded `LockToken` is what lets a
/// store reject a guard acquired from a *different* `MeshSignerLocks` (see
/// module doc, second-round fix).
pub struct MutateGuard<'a>(
    #[allow(dead_code)] RwLockWriteGuard<'a, ()>,
    Arc<OrderSpy>,
    LockToken,
);

impl MutateGuard<'_> {
    #[must_use]
    pub fn token(&self) -> LockToken {
        self.2
    }
}

impl Drop for SignGuard<'_> {
    fn drop(&mut self) {
        self.1.record(LockEvent::AccessRelease);
    }
}

impl Drop for MutateGuard<'_> {
    fn drop(&mut self) {
        self.1.record(LockEvent::AccessRelease);
    }
}
