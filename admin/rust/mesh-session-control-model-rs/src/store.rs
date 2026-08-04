//! `AtomicControlRecordStore` — CAS-by-revision persistence with a strict
//! three-way write outcome (`Committed | KnownNoEffect | MayHaveTakenEffect`).
//! A real file-backed implementation plus a fault-injecting test double that
//! can simulate a crash at any of the three risky boundaries
//! (pre-rename / rename itself / parent-fsync).
//!
//! Successor to the generation audited at commit `d4ecb658` (NO-GO, finding
//! 2): the prior `replace_exact` did an internal `load_canonical()`
//! (compare) fully decoupled from the later `rename()` (swap), with no lock
//! spanning the two — two concurrent callers could both pass the revision
//! check and both report `Committed`, one silently clobbering the other.
//! It also trusted `new_record.revision` verbatim, and accepted *any*
//! record as the first-ever write when the file was `Missing`. All three
//! gaps are closed here:
//! - `replace_exact` now requires a `&locks::MutateGuard` — a type that can
//!   only be constructed by `MeshSignerLocks::acquire_for_mutation`
//!   (turnstile-then-access-exclusive) — so compare-then-write happens in a
//!   single section under exclusive access, not just by caller convention.
//! - the revision relationship between `new_record` and the current disk
//!   state is verified, not trusted: a mutation must land on exactly
//!   `cur.revision + 1`; a stabilization rewrite must be byte-identical
//!   (including `revision`) to what is already on disk.
//! - `Missing` only accepts the canonical bootstrap record for the target
//!   identity/purpose — not an arbitrary caller-supplied first record.
//!
//! Second-round fix: a `&MutateGuard` alone proved only "some exclusive
//! guard exists," not that it came from the `MeshSignerLocks` this store is
//! meant to be paired with — two independently constructed lock sets over
//! the same path would not exclude each other. `FileBackedStore` is now
//! constructed with the `LockToken` of the one lock set it accepts, plus
//! the `(ControlIdentity, PurposeId)` it is bound to; `replace_exact`
//! asserts the guard's token matches and validates every write — genesis
//! included — against *this store's own binding*, never against whatever
//! identity/purpose `new_record` itself happens to claim.

use crate::locks::{LockToken, MutateGuard};
use crate::record::{ControlIdentity, MeshSignerControlRecordV1, PurposeId};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
#[cfg(feature = "test-support")]
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceOutcome {
    Committed,
    /// Provably no external effect: the failure happened strictly before
    /// `rename` was invoked, or the proposed write was rejected outright
    /// (stale revision, malformed revision relationship, non-canonical
    /// genesis record).
    KnownNoEffect,
    /// The failure happened at or after `rename` — the new content may or
    /// may not be durably visible. Never conflated with `KnownNoEffect`.
    /// Recovery must retry the identical bytes against the identical
    /// `expected_revision` until a definitive outcome is reached — a
    /// reread that merely "looks right" does not prove *this* write is
    /// what produced it (see `commit::commit_under_guard`).
    MayHaveTakenEffect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadOutcome {
    Missing,
    Exact(Box<MeshSignerControlRecordV1>),
    Corrupt,
}

pub trait AtomicControlRecordStore {
    fn load_canonical(&self) -> LoadOutcome;
    fn replace_exact(
        &self,
        guard: &MutateGuard<'_>,
        expected_revision: u64,
        new_record: &MeshSignerControlRecordV1,
    ) -> ReplaceOutcome;
    /// Best-effort cleanup of orphaned temp files from a prior crashed
    /// attempt. Requires the exclusive guard: the caller must not have
    /// created a tmp file for its *own* current attempt yet (sweep always
    /// runs first in a critical section), so anything found here predates
    /// this section and cannot belong to a write still in flight.
    fn sweep_orphan_tmp(&self, guard: &MutateGuard<'_>);
}

/// Recursively sorts every CBOR map's entries into RFC 7049 §3.9 / RFC 8949
/// §4.2.3 canonical key order, using ciborium's own verified
/// `CanonicalValue` comparator rather than a hand-rolled one. Arrays are
/// positional and need no reordering. Integer/text-length minimality is
/// already guaranteed by ciborium's encoder (its `Header::Positive` always
/// picks the shortest representation for a given value) — the one thing it
/// does *not* do automatically is sort map keys, which is what this closes.
/// Rejects (returns `None`) if two entries in the same map canonically
/// compare equal — a duplicate key, which sorting alone would only make
/// adjacent, never detect.
fn canonicalize_value(v: ciborium::Value) -> Option<ciborium::Value> {
    use ciborium::Value;
    use ciborium::value::CanonicalValue;
    match v {
        Value::Array(items) => Some(Value::Array(
            items
                .into_iter()
                .map(canonicalize_value)
                .collect::<Option<Vec<_>>>()?,
        )),
        Value::Map(entries) => {
            let mut entries = entries
                .into_iter()
                .map(|(k, val)| Some((canonicalize_value(k)?, canonicalize_value(val)?)))
                .collect::<Option<Vec<_>>>()?;
            entries.sort_by(|(k1, _), (k2, _)| {
                CanonicalValue::from(k1.clone()).cmp(&CanonicalValue::from(k2.clone()))
            });
            for w in entries.windows(2) {
                if CanonicalValue::from(w[0].0.clone()) == CanonicalValue::from(w[1].0.clone()) {
                    return None; // duplicate key
                }
            }
            Some(Value::Map(entries))
        }
        Value::Tag(t, inner) => Some(Value::Tag(t, Box::new(canonicalize_value(*inner)?))),
        other => Some(other),
    }
}

/// Encodes `rec` normally, then re-derives it through the canonical `Value`
/// tree so the bytes actually written are RFC-canonical regardless of the
/// struct's field declaration order — the name `to_canonical_bytes` used to
/// be aspirational only; this is what makes it true.
fn to_canonical_bytes(rec: &MeshSignerControlRecordV1) -> Option<Vec<u8>> {
    let mut raw = Vec::new();
    ciborium::into_writer(rec, &mut raw).ok()?;
    let value: ciborium::Value = ciborium::from_reader(raw.as_slice()).ok()?;
    let canonical_value = canonicalize_value(value)?;
    let mut canonical = Vec::new();
    ciborium::into_writer(&canonical_value, &mut canonical).ok()?;
    Some(canonical)
}

/// Decodes `bytes` only if they are *already* canonical: reread through the
/// same canonicalization pass used by `to_canonical_bytes` and require an
/// exact byte match against the input before trusting it. This single
/// round-trip check catches everything a bespoke validator would need
/// separate cases for — non-canonical map key order, a duplicate key
/// (rejected earlier, inside `canonicalize_value`), a non-minimal integer
/// encoding (ciborium's encoder only ever emits the minimal form, so any
/// input using a longer one re-encodes shorter and the lengths won't
/// match), and trailing bytes after one complete value (the re-encoding
/// only ever contains that one value, so a longer input can't match).
/// Without this, `LoadOutcome::Exact` proved only "this parses," never
/// "this is the one canonical encoding" — an important gap when this
/// file's bytes may later be hashed for a content-addressed audit trail,
/// where a non-canonical-but-semantically-equal encoding would silently
/// produce a different, non-reproducible hash.
fn from_canonical_bytes(bytes: &[u8]) -> Option<MeshSignerControlRecordV1> {
    let value: ciborium::Value = ciborium::from_reader(bytes).ok()?;
    let canonical_value = canonicalize_value(value)?;
    let mut recomputed = Vec::new();
    ciborium::into_writer(&canonical_value, &mut recomputed).ok()?;
    if recomputed != bytes {
        return None;
    }
    let rec: MeshSignerControlRecordV1 = ciborium::from_reader(bytes).ok()?;
    // Round 6, item (new) 4: CBOR shape validity says nothing about the
    // record's own semantic invariants — see
    // `MeshSignerControlRecordV1::invariants_hold`'s doc comment.
    if !rec.invariants_hold() {
        return None;
    }
    Some(rec)
}

/// Real file-backed store: temp file unique per attempt, its name
/// authenticating the `expected_revision` it targets plus a per-attempt
/// nonce (never a fixed name — v10/v11 bug: a fixed `.tmp` orphaned by one
/// crash permanently wedged every later attempt), `fsync` on the temp file,
/// `rename`, then `fsync` on the parent directory. `Committed` only after
/// the parent `fsync` returns `Ok`.
pub struct FileBackedStore {
    path: PathBuf,
    token: LockToken,
    identity: ControlIdentity,
    purpose: PurposeId,
}

impl FileBackedStore {
    /// `pub(crate)`, not `pub` — third-round fix (round 4, item 4): a
    /// public constructor let external code build a second, independently
    /// self-consistent `FileBackedStore`+`MeshSignerLocks` pair over the
    /// same path as an existing one, each individually passing the
    /// `LockToken` check but racing each other exactly like the pre-token
    /// bug. `cell::open` is now the only way to obtain a real
    /// `FileBackedStore` from outside this crate, backed by a process-wide
    /// path-keyed registry that reuses a live pair rather than duplicating
    /// it.
    #[must_use]
    pub(crate) fn new(
        path: PathBuf,
        token: LockToken,
        identity: ControlIdentity,
        purpose: PurposeId,
    ) -> Self {
        Self {
            path,
            token,
            identity,
            purpose,
        }
    }

    fn attempt_tmp_path(&self, expected_revision: u64) -> PathBuf {
        let nonce: u64 = rand::random();
        let mut name = self
            .path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(format!(".tmp.{expected_revision:020}.{nonce:016x}"));
        self.path.with_file_name(name)
    }

    /// A stable sibling path -- `<record>.lock` -- always created if
    /// absent, never removed. Deliberately a fixed name (not per-attempt
    /// like `attempt_tmp_path`): every process/attempt targeting this
    /// record must contend for the exact same lock, which requires them
    /// all opening the exact same path.
    fn lock_path(&self) -> PathBuf {
        let mut name = self
            .path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(".lock");
        self.path.with_file_name(name)
    }

    /// Blocking cross-process exclusive lock, held for as long as the
    /// returned `File` stays alive (released automatically on drop — see
    /// `replace_exact`'s own doc comment for why this exists). Returns
    /// `None` only if the lock file could not even be opened/created or
    /// the OS-level lock call itself failed — in both cases nothing this
    /// store could have done depends on holding it, so the caller treats
    /// that the same as `KnownNoEffect`.
    fn acquire_process_lock(&self) -> Option<File> {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .mode_0600()
            .open(self.lock_path())
            .ok()?;
        f.lock().ok()?;
        Some(f)
    }
}

/// Parses `<expected_revision>` back out of a tmp filename produced by
/// `attempt_tmp_path`, given the `<base>.tmp.` prefix. Returns `None` for
/// any name that does not match our own naming scheme — such a name was
/// never produced by this store and is treated as garbage, not trusted.
fn parse_tmp_revision(file_name: &str, prefix: &str) -> Option<u64> {
    let rest = file_name.strip_prefix(prefix)?;
    let (rev_str, _nonce) = rest.split_once('.')?;
    rev_str.parse::<u64>().ok()
}

impl AtomicControlRecordStore for FileBackedStore {
    fn load_canonical(&self) -> LoadOutcome {
        let mut file = match open_non_aliased(&self.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return LoadOutcome::Missing,
            Err(_) => return LoadOutcome::Corrupt,
            Ok(f) => f,
        };
        let bytes = {
            use std::io::Read;
            let mut buf = Vec::new();
            match file.read_to_end(&mut buf) {
                Ok(_) => buf,
                Err(_) => return LoadOutcome::Corrupt,
            }
        };
        match from_canonical_bytes(&bytes) {
            // Round 5, item A1: cross-check the decoded record's own
            // identity/purpose against what THIS store is bound to,
            // never trust that the file at `self.path` necessarily
            // holds content for the right identity — e.g. after a
            // drop-and-reopen at the same path for a DIFFERENT
            // identity, or any other way a leftover/foreign file could
            // end up there. Without this, `LoadOutcome::Exact` could
            // silently hand back a record for someone else's identity.
            Some(rec) if rec.identity == self.identity && rec.purpose == self.purpose => {
                LoadOutcome::Exact(Box::new(rec))
            }
            Some(_) | None => LoadOutcome::Corrupt,
        }
    }

    fn replace_exact(
        &self,
        guard: &MutateGuard<'_>,
        expected_revision: u64,
        new_record: &MeshSignerControlRecordV1,
    ) -> ReplaceOutcome {
        assert_eq!(
            guard.token(),
            self.token,
            "replace_exact called with a MutateGuard from a different MeshSignerLocks than this store is bound to — guards are not interchangeable across stores"
        );
        if new_record.identity != self.identity || new_record.purpose != self.purpose {
            // Never validated against whatever `new_record` itself claims —
            // always against this store's own fixed binding.
            return ReplaceOutcome::KnownNoEffect;
        }
        // Round 6: a REAL cross-process advisory lock for this whole
        // critical section (held until this function returns, released
        // automatically when `_process_lock` drops). `MeshSignerLocks`
        // alone only excludes other threads/calls WITHIN this process —
        // two independent processes, each with their own in-process lock
        // and their own `load_canonical` + `rename`, had nothing
        // preventing both from reading the same revision and both
        // renaming, one silently clobbering the other (confirmed: 6 real
        // processes racing the same file from revision 0 all reported
        // Committed).
        //
        // Correction (caught by audit before this claim shipped): this
        // lock is on `<self.path>.lock`, a path DERIVED from `self.path`
        // — NOT on `self.path`'s own inode. flock IS inode-scoped in
        // general, but that fact is irrelevant here, because a hardlink
        // alias of the RECORD (`record` / `alias`, same inode, different
        // names) produces TWO DIFFERENT derived lock paths
        // (`record.lock` / `alias.lock`, different inodes) — confirmed by
        // a real 6-process test: half via each name, sibling locks
        // correctly serialize each spelling on its own, but the two
        // spellings still produce two separate winners. This lock alone
        // does NOT close a hardlink alias; `open_non_aliased` (used by
        // `load_canonical`, and therefore inherited here) is what closes
        // it, by refusing to trust `self.path` at all once it has more
        // than one link.
        let Some(_process_lock) = self.acquire_process_lock() else {
            return ReplaceOutcome::KnownNoEffect; // could not even acquire -- no effect possible
        };
        let cur = match self.load_canonical() {
            LoadOutcome::Missing => {
                if expected_revision != crate::record::INITIAL_REVISION {
                    return ReplaceOutcome::KnownNoEffect;
                }
                // Genesis: only the canonical bootstrap record for THIS
                // store's own bound identity/purpose may be written when
                // nothing exists yet.
                let canonical =
                    MeshSignerControlRecordV1::bootstrap(self.identity.clone(), self.purpose);
                if *new_record != canonical {
                    return ReplaceOutcome::KnownNoEffect;
                }
                None
            }
            LoadOutcome::Exact(cur) => {
                if cur.revision != expected_revision {
                    return ReplaceOutcome::KnownNoEffect;
                }
                Some(cur)
            }
            LoadOutcome::Corrupt => return ReplaceOutcome::KnownNoEffect,
        };

        // Two, and only two, legitimate write shapes: a mutation must land
        // on exactly `cur.revision + 1`; a stabilization rewrite must be
        // byte-identical (including `revision`) to what is already on
        // disk. `new_record.revision` is verified here, never trusted.
        let is_valid_write = match &cur {
            None => true, // genesis already fully validated above
            Some(cur) => {
                if new_record.revision == cur.revision {
                    *new_record == **cur
                } else {
                    Some(new_record.revision) == cur.revision.checked_add(1)
                }
            }
        };
        if !is_valid_write {
            return ReplaceOutcome::KnownNoEffect;
        }

        let Some(bytes) = to_canonical_bytes(new_record) else {
            return ReplaceOutcome::KnownNoEffect;
        };
        let tmp = self.attempt_tmp_path(expected_revision);
        let mut f = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode_0600()
            .open(&tmp)
        {
            Ok(f) => f,
            Err(_) => return ReplaceOutcome::KnownNoEffect, // pre-rename, provably no effect
        };
        use std::io::Write;
        if f.write_all(&bytes).is_err() || f.sync_all().is_err() {
            let _ = fs::remove_file(&tmp);
            return ReplaceOutcome::KnownNoEffect;
        }
        drop(f);
        if fs::rename(&tmp, &self.path).is_err() {
            // The rename itself failed. Conservatively MayHaveTakenEffect,
            // never KnownNoEffect (v11 sweep A1: an EIO/remote-fs rename
            // error does not prove the far side never completed).
            return ReplaceOutcome::MayHaveTakenEffect;
        }
        match fsync_parent(&self.path) {
            Ok(()) => ReplaceOutcome::Committed,
            Err(_) => ReplaceOutcome::MayHaveTakenEffect,
        }
    }

    fn sweep_orphan_tmp(&self, guard: &MutateGuard<'_>) {
        assert_eq!(
            guard.token(),
            self.token,
            "sweep_orphan_tmp called with a MutateGuard from a different MeshSignerLocks than this store is bound to"
        );
        // Round 6 fix: this used to hold only the in-process `MutateGuard`
        // — "nothing else can be mid-write under a guard we are holding
        // first-in-section" was true only within THIS process. A second,
        // independent process's `replace_exact` could be past its own tmp
        // file's `sync_all` (durably on disk) but not yet at its own
        // `rename` — genuinely in-flight, not stale — and this function,
        // seeing no cross-process signal at all, would classify that tmp
        // as an orphan (its target revision, from the tmp's own filename,
        // being `>= current_revision` on disk right now doesn't save it
        // either — the classification logic never distinguished "stale"
        // from "legitimately in flight elsewhere" without a shared lock).
        // Deleting it out from under that other process's still-open
        // write would surface as a `rename` failure there —
        // conservatively `MayHaveTakenEffect`, but a real durability bug
        // nonetheless. The same stable process lock `replace_exact` holds
        // for its own tmp-write-through-rename section now also covers
        // sweep's classify-and-unlink section, so the two can never
        // interleave.
        let Some(_process_lock) = self.acquire_process_lock() else {
            return;
        };
        let Some(parent) = self.path.parent() else {
            return;
        };
        let Some(base) = self.path.file_name().and_then(|n| n.to_str()) else {
            return;
        };
        let prefix = format!("{base}.tmp.");
        let current_revision = match self.load_canonical() {
            LoadOutcome::Exact(r) => Some(r.revision),
            LoadOutcome::Missing | LoadOutcome::Corrupt => None,
        };
        let Ok(entries) = fs::read_dir(parent) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with(&prefix) {
                continue;
            }
            // Provably stale: this tmp targets a revision strictly older
            // than what is on disk now, so no rename of it could ever
            // legitimately land again. An unparseable name (never produced
            // by this store) or no canonical record yet (nothing else can
            // be mid-write under the process lock we are holding
            // first-in-section, now true cross-process too) is also swept.
            let is_stale = match (parse_tmp_revision(&name, &prefix), current_revision) {
                (Some(tmp_rev), Some(cur)) => tmp_rev < cur,
                _ => true,
            };
            if is_stale {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

fn fsync_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| io::Error::other("no parent"))?;
    let dir = File::open(parent)?;
    dir.sync_all()
}

/// Round 6: opens `path`, refusing to trust it at all if it is aliasable —
/// hardlinked (`nlink != 1`) or a symlink. `nlink` is checked on the
/// OPENED HANDLE's own metadata (`fstat`, not a separate path-based `stat`
/// call), so it is immune to TOCTOU once open, and — being a property of
/// the inode itself — reports identically no matter which of the inode's
/// several names was used to open it: as soon as ANY hardlink alias of
/// this file exists anywhere, opening it through ANY of its names is
/// rejected, closing exactly the gap a per-path lock file (see
/// `acquire_process_lock`'s own corrected doc comment) cannot: two
/// different processes each holding a real, uncontended lock on their own
/// derived `<their-path>.lock` still raced the SAME record through two
/// different hardlinked spellings before this existed (confirmed by a
/// real 6-process test, half via each name — sibling locks correctly
/// serialize each spelling on its own, but the two spellings still
/// produce two separate winners).
///
/// The symlink check (`fs::symlink_metadata` on `path` immediately before
/// open) has a narrow, honestly-documented residual TOCTOU window this
/// crate does not close: doing so atomically requires an `O_NOFOLLOW` open
/// flag, whose raw value is platform-specific and not something this
/// crate is willing to hardcode without the `libc` crate providing it —
/// an external dependency this fix does not otherwise need.
#[cfg(unix)]
fn open_non_aliased(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::MetadataExt;
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(io::Error::other(
            "refusing to trust a path whose final component is a symlink",
        ));
    }
    let f = File::open(path)?;
    if f.metadata()?.nlink() != 1 {
        return Err(io::Error::other(
            "refusing to trust a path with more than one hard link",
        ));
    }
    Ok(f)
}

/// Non-unix fallback: `nlink`/hardlink identity is not portably available
/// via `std::fs`, so this reduces to a plain open. Documented gap, not a
/// silent one.
#[cfg(not(unix))]
fn open_non_aliased(path: &Path) -> io::Result<File> {
    File::open(path)
}

trait Mode0600 {
    fn mode_0600(&mut self) -> &mut Self;
}
impl Mode0600 for OpenOptions {
    #[cfg(unix)]
    fn mode_0600(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.mode(0o600)
    }
    #[cfg(not(unix))]
    fn mode_0600(&mut self) -> &mut Self {
        self
    }
}

/// In-memory store wrapping a real `FileBackedStore` so failpoint tests
/// exercise the real tmp/rename/fsync code path, with the ability to force
/// a specific `ReplaceOutcome` on the Nth call regardless of what actually
/// happened on disk — this is what lets a test assert "the algorithm layer
/// behaves correctly under `MayHaveTakenEffect`" without needing to
/// actually corrupt the OS's rename() syscall.
///
/// Round 6 fix (item 4): gated behind `test-support` here too, not just at
/// `cell::open_fault_injecting` — this type and its `new` constructor were
/// fully `pub` regardless of that gate, so an external consumer could
/// reach `FaultInjectingStore::new` directly, bypassing the registry
/// entirely, even after `cell::open_fault_injecting` itself was closed.
#[cfg(feature = "test-support")]
pub struct FaultInjectingStore {
    inner: FileBackedStore,
    forced_outcome: std::sync::Mutex<Option<ReplaceOutcome>>,
    force_may_have_taken_effect_count: AtomicU64,
    call_count: AtomicU64,
}

#[cfg(feature = "test-support")]
impl FaultInjectingStore {
    #[must_use]
    pub fn new(
        path: PathBuf,
        token: LockToken,
        identity: ControlIdentity,
        purpose: PurposeId,
    ) -> Self {
        Self {
            inner: FileBackedStore::new(path, token, identity, purpose),
            forced_outcome: std::sync::Mutex::new(None),
            force_may_have_taken_effect_count: AtomicU64::new(0),
            call_count: AtomicU64::new(0),
        }
    }

    pub fn force_next_outcome(&self, outcome: ReplaceOutcome) {
        *self.forced_outcome.lock().unwrap() = Some(outcome);
    }

    /// Forces the next `n` `replace_exact` calls to report
    /// `MayHaveTakenEffect` even though the real underlying write (rename,
    /// visible immediately) always actually lands — simulating a parent
    /// `fsync` that keeps failing while the rename itself keeps
    /// succeeding. Used to prove recovery keeps issuing real, potentially
    /// committing writes rather than concluding from a single reread.
    pub fn force_may_have_taken_effect_for_next_calls(&self, n: u64) {
        self.force_may_have_taken_effect_count
            .store(n, Ordering::SeqCst);
    }

    #[must_use]
    pub fn calls(&self) -> u64 {
        self.call_count.load(Ordering::SeqCst)
    }
}

#[cfg(feature = "test-support")]
impl AtomicControlRecordStore for FaultInjectingStore {
    fn load_canonical(&self) -> LoadOutcome {
        self.inner.load_canonical()
    }

    fn replace_exact(
        &self,
        guard: &MutateGuard<'_>,
        expected_revision: u64,
        new_record: &MeshSignerControlRecordV1,
    ) -> ReplaceOutcome {
        self.call_count.fetch_add(1, Ordering::SeqCst);

        let remaining = self
            .force_may_have_taken_effect_count
            .load(Ordering::SeqCst);
        if remaining > 0 {
            self.force_may_have_taken_effect_count
                .fetch_sub(1, Ordering::SeqCst);
            let real = self
                .inner
                .replace_exact(guard, expected_revision, new_record);
            return if real == ReplaceOutcome::Committed {
                ReplaceOutcome::MayHaveTakenEffect
            } else {
                real
            };
        }

        if let Some(forced) = self.forced_outcome.lock().unwrap().take() {
            // Simulate the outcome WITHOUT performing the real write when
            // forcing KnownNoEffect (nothing should happen); for
            // MayHaveTakenEffect, actually perform the write so the disk
            // state is consistent with "it might have landed" — this
            // matters for recovery tests that then reread the record.
            return match forced {
                ReplaceOutcome::KnownNoEffect => ReplaceOutcome::KnownNoEffect,
                ReplaceOutcome::Committed | ReplaceOutcome::MayHaveTakenEffect => {
                    let real = self
                        .inner
                        .replace_exact(guard, expected_revision, new_record);
                    if real == ReplaceOutcome::Committed {
                        forced // report the forced (possibly weaker) outcome even though
                    // the real write landed, so the algorithm layer is tested
                    // against the pessimistic case
                    } else {
                        real
                    }
                }
            };
        }
        self.inner
            .replace_exact(guard, expected_revision, new_record)
    }

    fn sweep_orphan_tmp(&self, guard: &MutateGuard<'_>) {
        self.inner.sweep_orphan_tmp(guard);
    }
}
