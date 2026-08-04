//! Lock ordering. Fixes the v11 sweep finding directly: `turnstile` must be
//! held **until** `access` is actually acquired, then released — not
//! released before attempting to acquire `access`. Modeled with real
//! `std::sync` primitives (this crate has no file-lock/`fs2` dependency —
//! that binding lives in the real integration, outside this standalone
//! model) plus an `OrderSpy` so the acquire/release sequence is asserted by
//! a test, not just read by eye.

use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

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
}

impl MeshSignerLocks {
    #[must_use]
    pub fn new(spy: Arc<OrderSpy>) -> Self {
        Self {
            turnstile: Mutex::new(()),
            access: RwLock::new(()),
            spy,
        }
    }

    /// Sign path: turnstile -> access(shared) -> release turnstile.
    /// Turnstile is held across the `access` acquisition, not released
    /// beforehand — the v11 bug released it in a `{ }` block that closed
    /// *before* `access` was requested, which let new readers race ahead of
    /// a waiting writer with no ordering guarantee at all.
    pub fn acquire_for_sign(&self) -> AccessGuard<'_> {
        let t = self.turnstile.lock().unwrap();
        self.spy.record(LockEvent::TurnstileAcquire);
        let g = self.access.read().unwrap();
        self.spy.record(LockEvent::AccessAcquireShared);
        drop(t);
        self.spy.record(LockEvent::TurnstileRelease);
        AccessGuard::Shared(g, Arc::clone(&self.spy))
    }

    /// Revoke/mutate path: turnstile -> access(exclusive) -> release turnstile.
    pub fn acquire_for_mutation(&self) -> AccessGuard<'_> {
        let t = self.turnstile.lock().unwrap();
        self.spy.record(LockEvent::TurnstileAcquire);
        let g = self.access.write().unwrap();
        self.spy.record(LockEvent::AccessAcquireExclusive);
        drop(t);
        self.spy.record(LockEvent::TurnstileRelease);
        AccessGuard::Exclusive(g, Arc::clone(&self.spy))
    }
}

/// `gc_serial` — exclusive, held by GC workers only, for the entire tick
/// including the slow backend call (erratum1 E1). No other flow ever
/// acquires it, so it cannot participate in a lock-ordering cycle with
/// `turnstile`/`access`.
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

pub enum AccessGuard<'a> {
    Shared(RwLockReadGuard<'a, ()>, Arc<OrderSpy>),
    Exclusive(RwLockWriteGuard<'a, ()>, Arc<OrderSpy>),
}

impl Drop for AccessGuard<'_> {
    fn drop(&mut self) {
        match self {
            AccessGuard::Shared(_, spy) | AccessGuard::Exclusive(_, spy) => {
                spy.record(LockEvent::AccessRelease);
            }
        }
    }
}
