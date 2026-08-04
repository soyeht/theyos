//! `ControlRecordCell` — the sole way to obtain a real, working store for a
//! given `(path, identity, purpose)` from outside this crate. Owns its
//! `FileBackedStore`, `MeshSignerLocks`, and `GcSerialLock` together;
//! exposes only guard-gated, transition-mediated mutation — no raw store
//! accessor.
//!
//! Fourth-round fix (round 4, item 4): `FileBackedStore::new` is
//! `pub(crate)`; this factory, backed by a process-wide path-keyed
//! registry, is the only way in from outside, reusing a live pair rather
//! than duplicating it.
//!
//! Fifth-round fixes (round 5):
//! - item A1: `open` used to index the registry by path ALONE and hand
//!   back a live cell regardless of whether the caller's requested
//!   identity/purpose matched what that cell was actually built for —
//!   opening path P for identity A, then (while A's cell is still alive)
//!   opening the SAME path P for identity B, silently handed B's caller
//!   A's cell with no error at all. `open` now returns `Result`, and a
//!   mismatched reuse is a hard `OpenConflict`, never silent substitution.
//! - item A2: `FaultInjectingStore::new` was public and unrelated to this
//!   registry, wrapping its own internal `FileBackedStore` — two
//!   independent `FaultInjectingStore`+`MeshSignerLocks` pairs could still
//!   race on the same path exactly like the pre-registry bug. It now has
//!   its own parallel, identically-structured registry
//!   (`open_fault_injecting`), so both concrete store types are covered.
//!   `FaultInjectingCell` exposes its store/locks directly (unlike
//!   `ControlRecordCell`) — the whole type is test-only infrastructure by
//!   construction, so there is no production-bypass concern to close there,
//!   only the aliasing gap.
//! - item A3: `ControlRecordCell::store()` used to hand out `&FileBackedStore`
//!   directly, whose `replace_exact` (part of the public
//!   `AtomicControlRecordStore` trait) let a caller write ANY
//!   revision+1 content directly — completely bypassing
//!   `transition::apply` and every invariant it enforces (authority
//!   matrix, exact-token checks, cap, the GC state machine). That accessor
//!   is gone; the only ways to mutate are `commit` (a fully-built
//!   `RecordTransition`) and `commit_built` (a closure building one against
//!   a freshly read base, used by `gc`), both of which always go through
//!   `apply` first. `seed_for_test` remains as an explicitly-named escape
//!   hatch for adversarial test setup — still guard-gated (so misuse is
//!   still caught by the `LockToken` check), but its name makes clear it is
//!   not part of the production surface.
//! - item D11: `GcSerialLock` used to be constructed by whoever called
//!   `gc::gc_worker_tick`, with nothing tying it to the cell/path — two
//!   independent callers could each build their own lock and run two
//!   concurrent ticks against the same record, defeating gc_serial's whole
//!   purpose. It is now owned by the cell.

use crate::commit::{CommitError, commit_new_bytes};
use crate::locks::{GcSerialLock, MeshSignerLocks, MutateGuard, OrderSpy, SignGuard};
use crate::record::{ControlIdentity, MeshSignerControlRecordV1, PurposeId};
use crate::store::{AtomicControlRecordStore, FileBackedStore, LoadOutcome};
#[cfg(feature = "test-support")]
use crate::store::{FaultInjectingStore, ReplaceOutcome};
use crate::transition::{RecordTransition, TransitionError, apply};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

#[derive(Debug, thiserror::Error)]
pub enum CommitTransitionError {
    #[error("store has no record for this identity")]
    NoRecord,
    #[error("record is corrupt")]
    RecordCorrupt,
    #[error(transparent)]
    Transition(#[from] TransitionError),
    #[error(transparent)]
    Commit(#[from] CommitError),
    #[error(
        "this transition represents backend/admin-observed evidence and cannot be committed directly -- ActivateFromKeyObserved requires backend.load_exact + the full validator (activate::activate_from_key_observed); GcInspected/GcInspectionConflict/GcResolved/GcRemoval require a real SecretBackend call (gc::gc_worker_tick/gc_removal_pass)"
    )]
    PrivilegedTransition,
}

/// Transitions that assert something was actually observed from the
/// backend (or, for `ActivateFromKeyObserved`, validated against it) —
/// never safely constructible by a caller who hasn't actually gathered
/// that evidence. See `CommitTransitionError::PrivilegedTransition`.
fn is_privileged(t: &RecordTransition) -> bool {
    matches!(
        t,
        RecordTransition::ActivateFromKeyObserved { .. }
            | RecordTransition::GcInspected { .. }
            | RecordTransition::GcInspectionConflict { .. }
            | RecordTransition::GcResolved { .. }
            | RecordTransition::GcRemoval { .. }
    )
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("a live cell already exists for this path bound to a different identity/purpose")]
pub struct OpenConflict;

pub struct ControlRecordCell {
    store: FileBackedStore,
    locks: MeshSignerLocks,
    gc_serial: GcSerialLock,
    identity: ControlIdentity,
    purpose: PurposeId,
}

impl ControlRecordCell {
    #[must_use]
    pub fn identity(&self) -> &ControlIdentity {
        &self.identity
    }

    #[must_use]
    pub fn purpose(&self) -> PurposeId {
        self.purpose
    }

    /// Opaque identity of the underlying `MeshSignerLocks` — safe to expose
    /// on its own (it carries no mutation capability, just an
    /// equality-comparable id), unlike a raw store/locks accessor. Lets a
    /// caller confirm two `open()` calls returned the same live pair
    /// without needing anything `seed_for_test` guards.
    #[must_use]
    pub fn token(&self) -> crate::locks::LockToken {
        self.locks.token()
    }

    #[must_use]
    pub fn load_canonical(&self) -> LoadOutcome {
        self.store.load_canonical()
    }

    pub fn acquire_for_sign(&self) -> SignGuard<'_> {
        self.locks.acquire_for_sign()
    }

    pub fn acquire_for_mutation(&self) -> MutateGuard<'_> {
        self.locks.acquire_for_mutation()
    }

    /// Held for an entire GC tick (erratum1 E1) — see `gc::gc_worker_tick`.
    pub fn acquire_gc_serial(&self) -> MutexGuard<'_, ()> {
        self.gc_serial.acquire()
    }

    /// Builds `t` against a fresh read (guard held for the whole section)
    /// and commits it. The sanctioned way to mutate from outside this
    /// crate when the transition is already fully known.
    ///
    /// Round 6 fix (item 4, then widened in wave 4): this used to accept
    /// ANY `RecordTransition`. `ActivateFromKeyObserved` was closed off
    /// first (bypassed `backend.load_exact` + the full validator) — but
    /// the same bypass existed for every `Gc*` variant too: a caller could
    /// commit `GcResolved { residual_zero: true, .. }` directly, claiming
    /// a clean destroy that never actually touched `SecretBackend`, then
    /// `GcRemoval` to erase the tracking entry entirely — forging GC
    /// evidence with no backend involved at all. All five variants that
    /// represent "the backend/admin was actually consulted" are rejected
    /// here now; only the crate-internal `commit_built_privileged` (used
    /// exclusively by `activate.rs`/`gc.rs`, after they have actually
    /// gathered that evidence) may commit one.
    pub fn commit(
        &self,
        t: &RecordTransition,
        now: u64,
        max_cap: usize,
    ) -> Result<MeshSignerControlRecordV1, CommitTransitionError> {
        if is_privileged(t) {
            return Err(CommitTransitionError::PrivilegedTransition);
        }
        let guard = self.locks.acquire_for_mutation();
        let base = match self.store.load_canonical() {
            LoadOutcome::Exact(r) => *r,
            LoadOutcome::Missing => return Err(CommitTransitionError::NoRecord),
            LoadOutcome::Corrupt => return Err(CommitTransitionError::RecordCorrupt),
        };
        let new = apply(&base, t, now, max_cap)?;
        commit_new_bytes(&self.store, &guard, base.revision, &new, 8)?;
        Ok(new)
    }

    /// GC-shaped variant: `build` runs against a freshly read base *under*
    /// the guard and may report "nothing to do" (`None`) against that
    /// fresh state (e.g. the targeted entry was already resolved by a
    /// concurrent caller) — returns `Ok(None)` in that case rather than
    /// committing anything. Same privileged-transition rejection as
    /// `commit` — `build`'s output is checked after it runs, since the
    /// whole point of this variant is that the transition is not known
    /// until `build` sees a fresh read.
    pub fn commit_built(
        &self,
        build: impl FnOnce(&MeshSignerControlRecordV1) -> Option<RecordTransition>,
        now: u64,
        max_cap: usize,
    ) -> Result<Option<MeshSignerControlRecordV1>, CommitTransitionError> {
        self.commit_built_impl(build, now, max_cap, true)
    }

    /// Crate-internal only: identical to `commit_built` but WITHOUT the
    /// privileged-transition rejection. Exists solely for
    /// `activate::activate_from_key_observed` (which performs
    /// `backend.load_exact` + the full validator itself first) and
    /// `gc::gc_worker_tick`/`gc_removal_pass` (which call the real
    /// `SecretBackend` first) — never `pub`, so nothing outside this
    /// crate can reach it.
    pub(crate) fn commit_built_privileged(
        &self,
        build: impl FnOnce(&MeshSignerControlRecordV1) -> Option<RecordTransition>,
        now: u64,
        max_cap: usize,
    ) -> Result<Option<MeshSignerControlRecordV1>, CommitTransitionError> {
        self.commit_built_impl(build, now, max_cap, false)
    }

    fn commit_built_impl(
        &self,
        build: impl FnOnce(&MeshSignerControlRecordV1) -> Option<RecordTransition>,
        now: u64,
        max_cap: usize,
        reject_privileged: bool,
    ) -> Result<Option<MeshSignerControlRecordV1>, CommitTransitionError> {
        let guard = self.locks.acquire_for_mutation();
        let base = match self.store.load_canonical() {
            LoadOutcome::Exact(r) => *r,
            LoadOutcome::Missing => return Err(CommitTransitionError::NoRecord),
            LoadOutcome::Corrupt => return Err(CommitTransitionError::RecordCorrupt),
        };
        let Some(t) = build(&base) else {
            return Ok(None);
        };
        if reject_privileged && is_privileged(&t) {
            return Err(CommitTransitionError::PrivilegedTransition);
        }
        let new = apply(&base, &t, now, max_cap)?;
        commit_new_bytes(&self.store, &guard, base.revision, &new, 8)?;
        Ok(Some(new))
    }

    pub fn sweep_orphan_tmp(&self, guard: &MutateGuard<'_>) {
        self.store.sweep_orphan_tmp(guard);
    }

    /// Explicit escape hatch for adversarial test setup ONLY — bypasses
    /// `transition::apply` entirely, writing `record` verbatim if the CAS
    /// (revision + this store's own identity/purpose binding) accepts it.
    /// Still guard-gated (the `LockToken` check still applies), but its
    /// name makes clear this is not part of the production surface — a
    /// real caller has no legitimate reason to ever call this.
    ///
    /// Round 6 fix (item 4): a doc-comment name was the ONLY thing
    /// enforcing "test-only" — in a normal (non-test) build this was a
    /// fully `pub` method, reachable by any consumer of this crate as a
    /// library, letting it write ANY record content directly. Gated behind
    /// `test-support`, off by default; this crate's own `cargo test`
    /// enables it via the dev-dependency-on-self declared in `Cargo.toml`.
    #[cfg(feature = "test-support")]
    pub fn seed_for_test(
        &self,
        guard: &MutateGuard<'_>,
        expected_revision: u64,
        record: &MeshSignerControlRecordV1,
    ) -> ReplaceOutcome {
        self.store.replace_exact(guard, expected_revision, record)
    }
}

struct Registered<T> {
    cell: Weak<T>,
    identity: ControlIdentity,
    purpose: PurposeId,
}

fn control_record_registry() -> &'static Mutex<HashMap<PathBuf, Registered<ControlRecordCell>>> {
    static REG: OnceLock<Mutex<HashMap<PathBuf, Registered<ControlRecordCell>>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Best-effort canonical registry key: canonicalizes the *parent*
/// directory (which usually exists even before the record file itself
/// does — e.g. a fresh tempdir at genesis) and rejoins the file name, so a
/// pre-genesis and a post-genesis `open` call for logically the same file
/// resolve to the same key. Falls back to the raw path if the parent
/// cannot be canonicalized (it does not exist either, in which case
/// creating the file would fail regardless).
fn registry_key(path: &Path) -> PathBuf {
    let (Some(parent), Some(file_name)) = (path.parent(), path.file_name()) else {
        return path.to_path_buf();
    };
    match parent.canonicalize() {
        Ok(canon_parent) => canon_parent.join(file_name),
        Err(_) => path.to_path_buf(),
    }
}

/// Opens (or reuses, if still live) the cell for `path`. `spy` is supplied
/// by the caller (not generated internally) so callers retain their own
/// handle for `OrderSpy` inspection in tests.
///
/// Returns `Err(OpenConflict)` if a cell is already live for this path but
/// was built for a *different* `identity`/`purpose` — round 5, item A1: the
/// prior version silently handed back the existing cell regardless of
/// whether it matched what the caller actually asked for.
pub fn open(
    path: PathBuf,
    identity: ControlIdentity,
    purpose: PurposeId,
    spy: Arc<OrderSpy>,
) -> Result<Arc<ControlRecordCell>, OpenConflict> {
    let key = registry_key(&path);
    let mut reg = control_record_registry().lock().unwrap();
    if let Some(existing) = reg.get(&key)
        && let Some(cell) = existing.cell.upgrade()
    {
        if existing.identity != identity || existing.purpose != purpose {
            return Err(OpenConflict);
        }
        return Ok(cell);
    }
    let locks = MeshSignerLocks::new(spy);
    let store = FileBackedStore::new(path, locks.token(), identity.clone(), purpose);
    let cell = Arc::new(ControlRecordCell {
        store,
        locks,
        gc_serial: GcSerialLock::new(),
        identity: identity.clone(),
        purpose,
    });
    reg.insert(
        key,
        Registered {
            cell: Arc::downgrade(&cell),
            identity,
            purpose,
        },
    );
    Ok(cell)
}

/// Test-only double: wraps `FaultInjectingStore` instead of
/// `FileBackedStore`, exposing it (and the paired `MeshSignerLocks`)
/// directly — this whole type exists only for failpoint-injection tests
/// exercising the store/commit retry machinery at a low level, so there is
/// no production-bypass concern to close here, only the same path-aliasing
/// gap `ControlRecordCell` closes (round 5, item A2).
///
/// Round 6 fix (item 4): this whole module was fully `pub` in a normal
/// build despite being test-only in intent — gated behind `test-support`,
/// same as `seed_for_test`, for the same reason.
#[cfg(feature = "test-support")]
pub struct FaultInjectingCell {
    store: FaultInjectingStore,
    locks: MeshSignerLocks,
}

#[cfg(feature = "test-support")]
impl FaultInjectingCell {
    #[must_use]
    pub fn store(&self) -> &FaultInjectingStore {
        &self.store
    }

    #[must_use]
    pub fn locks(&self) -> &MeshSignerLocks {
        &self.locks
    }
}

#[cfg(feature = "test-support")]
fn fault_injecting_registry() -> &'static Mutex<HashMap<PathBuf, Registered<FaultInjectingCell>>> {
    static REG: OnceLock<Mutex<HashMap<PathBuf, Registered<FaultInjectingCell>>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(feature = "test-support")]
pub fn open_fault_injecting(
    path: PathBuf,
    identity: ControlIdentity,
    purpose: PurposeId,
    spy: Arc<OrderSpy>,
) -> Result<Arc<FaultInjectingCell>, OpenConflict> {
    let key = registry_key(&path);
    let mut reg = fault_injecting_registry().lock().unwrap();
    if let Some(existing) = reg.get(&key)
        && let Some(cell) = existing.cell.upgrade()
    {
        if existing.identity != identity || existing.purpose != purpose {
            return Err(OpenConflict);
        }
        return Ok(cell);
    }
    let locks = MeshSignerLocks::new(spy);
    let store = FaultInjectingStore::new(path, locks.token(), identity.clone(), purpose);
    let cell = Arc::new(FaultInjectingCell { store, locks });
    reg.insert(
        key,
        Registered {
            cell: Arc::downgrade(&cell),
            identity,
            purpose,
        },
    );
    Ok(cell)
}
