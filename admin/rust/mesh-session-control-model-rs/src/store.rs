//! `AtomicControlRecordStore` — CAS-by-revision persistence with a strict
//! three-way write outcome (`Committed | KnownNoEffect | MayHaveTakenEffect`).
//! A real file-backed implementation plus a fault-injecting test double that
//! can simulate a crash at any of the three risky boundaries
//! (pre-rename / rename itself / parent-fsync).

use crate::record::MeshSignerControlRecordV1;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceOutcome {
    Committed,
    /// Provably no external effect: the failure happened strictly before
    /// `rename` was invoked.
    KnownNoEffect,
    /// The failure happened at or after `rename` — the new content may or
    /// may not be durably visible. Never conflated with `KnownNoEffect`.
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
        expected_revision: u64,
        new_record: &MeshSignerControlRecordV1,
    ) -> ReplaceOutcome;
    /// Best-effort cleanup of orphaned temp files from a prior crashed
    /// attempt. Only ever called by a caller already holding the exclusive
    /// write lock for this record — see `ensure_durable`.
    fn sweep_orphan_tmp(&self);
}

fn to_canonical_bytes(rec: &MeshSignerControlRecordV1) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(rec, &mut buf).ok()?;
    Some(buf)
}

fn from_canonical_bytes(bytes: &[u8]) -> Option<MeshSignerControlRecordV1> {
    ciborium::from_reader(bytes).ok()
}

/// Real file-backed store: temp file unique per attempt (never a fixed
/// name — v10/v11 bug: a fixed `.tmp` orphaned by one crash permanently
/// wedged every later attempt), `fsync` on the temp file, `rename`, then
/// `fsync` on the parent directory. `Committed` only after the parent
/// `fsync` returns `Ok`.
pub struct FileBackedStore {
    path: PathBuf,
}

impl FileBackedStore {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn attempt_tmp_path(&self) -> PathBuf {
        let nonce: u64 = rand::random();
        let mut name = self
            .path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(format!(".tmp.{nonce:016x}"));
        self.path.with_file_name(name)
    }
}

impl AtomicControlRecordStore for FileBackedStore {
    fn load_canonical(&self) -> LoadOutcome {
        match fs::read(&self.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => LoadOutcome::Missing,
            Err(_) => LoadOutcome::Corrupt,
            Ok(bytes) => match from_canonical_bytes(&bytes) {
                Some(rec) => LoadOutcome::Exact(Box::new(rec)),
                None => LoadOutcome::Corrupt,
            },
        }
    }

    fn replace_exact(
        &self,
        expected_revision: u64,
        new_record: &MeshSignerControlRecordV1,
    ) -> ReplaceOutcome {
        match self.load_canonical() {
            LoadOutcome::Missing if expected_revision != crate::record::INITIAL_REVISION => {
                return ReplaceOutcome::KnownNoEffect;
            }
            LoadOutcome::Exact(cur) if cur.revision != expected_revision => {
                return ReplaceOutcome::KnownNoEffect;
            }
            LoadOutcome::Corrupt => return ReplaceOutcome::KnownNoEffect,
            _ => {}
        }
        let Some(bytes) = to_canonical_bytes(new_record) else {
            return ReplaceOutcome::KnownNoEffect;
        };
        let tmp = self.attempt_tmp_path();
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

    fn sweep_orphan_tmp(&self) {
        let Some(parent) = self.path.parent() else {
            return;
        };
        let Some(base) = self.path.file_name().and_then(|n| n.to_str()) else {
            return;
        };
        let prefix = format!("{base}.tmp.");
        if let Ok(entries) = fs::read_dir(parent) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().starts_with(&prefix) {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}

fn fsync_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| io::Error::other("no parent"))?;
    let dir = File::open(parent)?;
    dir.sync_all()
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
pub struct FaultInjectingStore {
    inner: FileBackedStore,
    forced_outcome: std::sync::Mutex<Option<ReplaceOutcome>>,
    call_count: AtomicU64,
}

impl FaultInjectingStore {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            inner: FileBackedStore::new(path),
            forced_outcome: std::sync::Mutex::new(None),
            call_count: AtomicU64::new(0),
        }
    }

    pub fn force_next_outcome(&self, outcome: ReplaceOutcome) {
        *self.forced_outcome.lock().unwrap() = Some(outcome);
    }

    #[must_use]
    pub fn calls(&self) -> u64 {
        self.call_count.load(Ordering::SeqCst)
    }
}

impl AtomicControlRecordStore for FaultInjectingStore {
    fn load_canonical(&self) -> LoadOutcome {
        self.inner.load_canonical()
    }

    fn replace_exact(
        &self,
        expected_revision: u64,
        new_record: &MeshSignerControlRecordV1,
    ) -> ReplaceOutcome {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if let Some(forced) = self.forced_outcome.lock().unwrap().take() {
            // Simulate the outcome WITHOUT performing the real write when
            // forcing KnownNoEffect (nothing should happen); for
            // MayHaveTakenEffect, actually perform the write so the disk
            // state is consistent with "it might have landed" — this
            // matters for recovery tests that then reread the record.
            return match forced {
                ReplaceOutcome::KnownNoEffect => ReplaceOutcome::KnownNoEffect,
                ReplaceOutcome::Committed | ReplaceOutcome::MayHaveTakenEffect => {
                    let real = self.inner.replace_exact(expected_revision, new_record);
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
        self.inner.replace_exact(expected_revision, new_record)
    }

    fn sweep_orphan_tmp(&self) {
        self.inner.sweep_orphan_tmp();
    }
}
