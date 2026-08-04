//! `ControlRecordCell` — the sole way to obtain a real `FileBackedStore`
//! from outside this crate, always paired with the one `MeshSignerLocks`
//! it was constructed against.
//!
//! Third-round fix (round 4, item 4): the `LockToken` binding
//! (`locks.rs`/`store.rs`) closes guard-vs-store mismatch *within* one
//! pair, but did nothing to stop constructing two *independently
//! self-consistent* pairs over the same path — each individually correct,
//! together reopening the exact TOCTOU the token was meant to close (this
//! crate's own earlier `two_stores_aliasing_the_same_path_...` test proved
//! only the cross-pair-misuse half of this, never two consistent pairs
//! racing each other). `FileBackedStore::new` is now `pub(crate)` —
//! unreachable from outside this crate — so this factory, backed by a
//! process-wide path-keyed registry, is the only way in: at most one live
//! cell exists per resolved path at a time. A second `open` call for a
//! path whose cell is still alive (any `Arc` clone still held anywhere)
//! returns that same cell; only once every reference has been dropped does
//! a later call create a genuinely fresh one (sequential, non-overlapping
//! reuse is safe).

use crate::locks::{MeshSignerLocks, OrderSpy};
use crate::record::{ControlIdentity, PurposeId};
use crate::store::FileBackedStore;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

pub struct ControlRecordCell {
    store: FileBackedStore,
    locks: MeshSignerLocks,
}

impl ControlRecordCell {
    #[must_use]
    pub fn store(&self) -> &FileBackedStore {
        &self.store
    }

    #[must_use]
    pub fn locks(&self) -> &MeshSignerLocks {
        &self.locks
    }
}

fn registry() -> &'static Mutex<HashMap<PathBuf, Weak<ControlRecordCell>>> {
    static REG: OnceLock<Mutex<HashMap<PathBuf, Weak<ControlRecordCell>>>> = OnceLock::new();
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
#[must_use]
pub fn open(
    path: PathBuf,
    identity: ControlIdentity,
    purpose: PurposeId,
    spy: Arc<OrderSpy>,
) -> Arc<ControlRecordCell> {
    let key = registry_key(&path);
    let mut reg = registry().lock().unwrap();
    if let Some(existing) = reg.get(&key).and_then(Weak::upgrade) {
        return existing;
    }
    let locks = MeshSignerLocks::new(spy);
    let store = FileBackedStore::new(path, locks.token(), identity, purpose);
    let cell = Arc::new(ControlRecordCell { store, locks });
    reg.insert(key, Arc::downgrade(&cell));
    cell
}
