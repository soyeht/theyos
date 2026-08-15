//! Feature-gated witnesses for first-owner lifecycle tests.
//!
//! This module is absent from ordinary and release builds. The hooks below
//! observe the real lifecycle/pair-window path and are keyed by an exact state
//! root so concurrently running tests cannot consume one another's evidence.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Fixed-width generation evidence captured at a real operation boundary.
pub type Generation = [u8; 32];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FirstOwnerTrace {
    pub shared_acquire_attempts: usize,
    pub shared_acquire_successes: usize,
    pub exclusive_acquire_attempts: usize,
    pub exclusive_acquire_successes: usize,
    pub rebinds: Vec<GenerationPair>,
    pub mints: Vec<GenerationPair>,
    pub persists: Vec<GenerationPair>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationPair {
    pub namespace: Generation,
    pub lifecycle: Generation,
    pub under_exclusive: bool,
}

#[derive(Default)]
struct RegistrationState {
    trace: FirstOwnerTrace,
    fail_on_contention: bool,
}

fn registry() -> &'static Mutex<HashMap<PathBuf, RegistrationState>> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, RegistrationState>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn key(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Scoped registration for one state root. Dropping it removes all hooks.
pub struct FirstOwnerRegistration {
    state_root: PathBuf,
}

impl FirstOwnerRegistration {
    /// Snapshot the evidence accumulated by the real path so far.
    #[must_use]
    pub fn trace(&self) -> FirstOwnerTrace {
        registry()
            .lock()
            .expect("first-owner observer registry poisoned")
            .get(&self.state_root)
            .map(|state| state.trace.clone())
            .unwrap_or_default()
    }
}

impl Drop for FirstOwnerRegistration {
    fn drop(&mut self) {
        registry()
            .lock()
            .expect("first-owner observer registry poisoned")
            .remove(&self.state_root);
    }
}

/// Register a state root and replace wall-clock waiting on lock contention by
/// a deterministic `LockTimeout`. Uncontended acquisitions still traverse the
/// real lock path and prove this channel is alive in the same run.
#[must_use]
pub fn register_deterministic(state_root: &Path) -> FirstOwnerRegistration {
    let state_root = key(state_root);
    let previous = registry()
        .lock()
        .expect("first-owner observer registry poisoned")
        .insert(
            state_root.clone(),
            RegistrationState {
                trace: FirstOwnerTrace::default(),
                fail_on_contention: true,
            },
        );
    assert!(previous.is_none(), "state root already has an observer");
    FirstOwnerRegistration { state_root }
}

pub(crate) fn lifecycle_attempt(state_root: &Path, exclusive: bool) {
    if let Some(state) = registry()
        .lock()
        .expect("first-owner observer registry poisoned")
        .get_mut(&key(state_root))
    {
        if exclusive {
            state.trace.exclusive_acquire_attempts += 1;
        } else {
            state.trace.shared_acquire_attempts += 1;
        }
    }
}

pub(crate) fn lifecycle_success(state_root: &Path, exclusive: bool) {
    if let Some(state) = registry()
        .lock()
        .expect("first-owner observer registry poisoned")
        .get_mut(&key(state_root))
    {
        if exclusive {
            state.trace.exclusive_acquire_successes += 1;
        } else {
            state.trace.shared_acquire_successes += 1;
        }
    }
}

pub(crate) fn fail_on_contention(state_root: &Path) -> bool {
    registry()
        .lock()
        .expect("first-owner observer registry poisoned")
        .get(&key(state_root))
        .is_some_and(|state| state.fail_on_contention)
}

fn record(
    state_root: &Path,
    namespace: Generation,
    lifecycle: Generation,
    under_exclusive: bool,
    select: impl FnOnce(&mut FirstOwnerTrace) -> &mut Vec<GenerationPair>,
) {
    if let Some(state) = registry()
        .lock()
        .expect("first-owner observer registry poisoned")
        .get_mut(&key(state_root))
    {
        select(&mut state.trace).push(GenerationPair {
            namespace,
            lifecycle,
            under_exclusive,
        });
    }
}

pub(crate) fn rebind(state_root: &Path, namespace: Generation, lifecycle: Generation) {
    record(state_root, namespace, lifecycle, true, |trace| {
        &mut trace.rebinds
    });
}

pub(crate) fn mint(state_root: &Path, namespace: Generation, lifecycle: Generation) {
    record(state_root, namespace, lifecycle, true, |trace| {
        &mut trace.mints
    });
}

pub(crate) fn persist(
    state_root: &Path,
    namespace: Generation,
    lifecycle: Generation,
    under_exclusive: bool,
) {
    record(state_root, namespace, lifecycle, under_exclusive, |trace| {
        &mut trace.persists
    });
}
