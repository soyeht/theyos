//! `BootstrapState` — onboarding state machine for the Soyeht engine.
//!
//! Persisted at `<state_dir>/identity.bootstrap_state` as a plain UTF-8 text
//! file (one line, newline-terminated). Writing the file is atomic: tmp →
//! fsync → rename.
//!
//! Valid transitions (see contracts/bootstrap-status.md):
//!
//! ```text
//! Uninitialized     → ReadyForNaming  (reserved; currently unused, skipped to NamedAwaitingPair)
//! Uninitialized     → NamedAwaitingPair  (POST /bootstrap/initialize)
//! ReadyForNaming    → NamedAwaitingPair  (POST /bootstrap/initialize)
//! NamedAwaitingPair → Ready              (owner-pairing finalizes)
//! NamedAwaitingPair → PairMachineInstallRestartRequired
//!                                            (candidate install committed;
//!                                             exact finalize replay pending)
//! PairMachineInstallRestartRequired → Ready  (exact retained Ack replay armed;
//!                                             peer receipt remains unproven)
//! *                 → Recovering         (future spec 007-recovery-flow)
//! ```
//!
//! Invalid transitions return `TransitionError`. The file on disk is the
//! source of truth; in-memory state is always re-read from disk on boot.

use std::fmt;
use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use crate::error::StorageError;
use crate::household_lifecycle::{
    HouseholdLifecycleGenerationV1, HouseholdLifecycleLockError, LifecycleWriteGuard,
};

// ── State enum ────────────────────────────────────────────────────────────────

/// Onboarding state machine state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapState {
    Uninitialized,
    ReadyForNaming,
    NamedAwaitingPair,
    /// A Pair-Machine candidate install is terminal and its exact Ack is
    /// retained, but the cold G1 process has not yet established the named
    /// conservative delivery boundary for exact replay.
    /// This is deliberately distinct from generic fail-stop `Recovering`.
    PairMachineInstallRestartRequired,
    Ready,
    Recovering,
}

impl BootstrapState {
    /// Canonical wire/file representation (`snake_case` string).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uninitialized => "uninitialized",
            Self::ReadyForNaming => "ready_for_naming",
            Self::NamedAwaitingPair => "named_awaiting_pair",
            Self::PairMachineInstallRestartRequired => "pair_machine_install_restart_required",
            Self::Ready => "ready",
            Self::Recovering => "recovering",
        }
    }

    /// Parse from the canonical string representation.
    ///
    /// Returns `None` for unknown strings (forward-compatibility: new states
    /// written by a newer engine version are treated as `Recovering` by older
    /// engines — callers should handle `None` conservatively).
    #[must_use]
    pub fn parse_canonical(s: &str) -> Option<Self> {
        match s.trim() {
            "uninitialized" => Some(Self::Uninitialized),
            "ready_for_naming" => Some(Self::ReadyForNaming),
            "named_awaiting_pair" => Some(Self::NamedAwaitingPair),
            "pair_machine_install_restart_required" => {
                Some(Self::PairMachineInstallRestartRequired)
            }
            "ready" => Some(Self::Ready),
            "recovering" => Some(Self::Recovering),
            _ => None,
        }
    }

    /// Attempt to transition to `next`. Returns `Err` if the transition is
    /// not valid per the state machine specification.
    pub fn transition(self, next: Self) -> Result<Self, TransitionError> {
        use BootstrapState::{
            NamedAwaitingPair, PairMachineInstallRestartRequired, Ready, ReadyForNaming,
            Recovering, Uninitialized,
        };
        let ok = matches!(
            (self, next),
            // Forward onboarding transitions + idempotent self-transitions
            // (self-loops allowed; persist is skipped upstream).
            (Uninitialized, Uninitialized | ReadyForNaming | NamedAwaitingPair)
            | (ReadyForNaming, ReadyForNaming | NamedAwaitingPair)
            | (
                Uninitialized | ReadyForNaming | NamedAwaitingPair,
                PairMachineInstallRestartRequired,
            )
            | (NamedAwaitingPair, NamedAwaitingPair | Ready | Recovering)
            | (
                PairMachineInstallRestartRequired,
                PairMachineInstallRestartRequired | Ready | Recovering,
            )
            // Recovery interplays with Ready bidirectionally.
            | (Ready | Recovering, Ready | Recovering)
        );
        if ok {
            Ok(next)
        } else {
            Err(TransitionError {
                from: self,
                to: next,
            })
        }
    }
}

impl fmt::Display for BootstrapState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Error types ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
#[error("invalid state transition {from} → {to}")]
pub struct TransitionError {
    pub from: BootstrapState,
    pub to: BootstrapState,
}

#[derive(Debug, thiserror::Error)]
pub enum BootstrapStateError {
    #[error("I/O error reading bootstrap state: {0}")]
    Io(#[from] io::Error),
    #[error("unknown bootstrap state string {0:?}; treating as uninitialized")]
    Unknown(String),
    #[error("state transition error: {0}")]
    Transition(#[from] TransitionError),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("household lifecycle operation failed: {0}")]
    Lifecycle(#[from] HouseholdLifecycleLockError),
    #[error("Ready must be persisted through a lifecycle-generation guard")]
    ReadyRequiresLifecycleGuard,
    #[error("the lifecycle generation changed before Ready could be persisted")]
    ReadyGenerationChanged,
}

// ── Persistence ────────────────────────────────────────────────────────────────

fn state_file_path(state_dir: &Path) -> PathBuf {
    state_dir.join("identity.bootstrap_state")
}

/// Build a staged bootstrap-state item only for a non-Ready transaction.
///
/// Multi-file onboarding staging needs the path and exact bytes, but exposing
/// the path alone would let a sibling module bypass
/// [`persist_ready_under_lifecycle`]. This constructor keeps that capability
/// closed and applies the same Ready rejection as [`persist`].
pub(crate) fn staged_non_ready_item(
    state_dir: &Path,
    state: BootstrapState,
) -> Result<(PathBuf, Vec<u8>), BootstrapStateError> {
    if state == BootstrapState::Ready {
        return Err(BootstrapStateError::ReadyRequiresLifecycleGuard);
    }
    let mut bytes = state.as_str().as_bytes().to_vec();
    bytes.push(b'\n');
    Ok((state_file_path(state_dir), bytes))
}

/// Read the bootstrap state from `<state_dir>/identity.bootstrap_state`.
///
/// - Returns `Ok(Uninitialized)` when the file does not exist.
/// - Returns `Err(Unknown)` when the file exists but contains an unrecognised
///   state string; callers should log and treat as `Uninitialized`.
pub fn load(state_dir: &Path) -> Result<BootstrapState, BootstrapStateError> {
    let path = state_file_path(state_dir);
    match fs::read_to_string(&path) {
        Ok(raw) => {
            let s = raw.trim();
            BootstrapState::parse_canonical(s)
                .ok_or_else(|| BootstrapStateError::Unknown(s.to_string()))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BootstrapState::Uninitialized),
        Err(e) => Err(BootstrapStateError::Io(e)),
    }
}

/// Atomically persist `state` to `<state_dir>/identity.bootstrap_state`.
///
/// Write strategy: write to `<path>.tmp` → fsync → rename → fsync parent.
pub fn persist(state_dir: &Path, state: BootstrapState) -> Result<(), BootstrapStateError> {
    if state == BootstrapState::Ready {
        return Err(BootstrapStateError::ReadyRequiresLifecycleGuard);
    }
    persist_impl(state_dir, state)
}

/// Durably persist `Ready` while proving the writer still owns the exact
/// lifecycle generation whose authority it is publishing.
///
/// This is the only production entry point that can write `Ready`. Keeping
/// that invariant in the persistence API (instead of at a source-code
/// convention) means a newly added direct or dynamic call to [`persist`]
/// fails closed. `expected_generation` must come from the ceremony or record
/// being completed; merely reading a generation and later reopening a guard is
/// insufficient.
pub fn persist_ready_under_lifecycle(
    lifecycle: &LifecycleWriteGuard,
    state_dir: &Path,
    expected_generation: HouseholdLifecycleGenerationV1,
) -> Result<(), BootstrapStateError> {
    lifecycle.verify_state_root(state_dir)?;
    if lifecycle.lifecycle_generation()? != Some(expected_generation) {
        return Err(BootstrapStateError::ReadyGenerationChanged);
    }
    persist_impl(state_dir, BootstrapState::Ready)?;
    lifecycle.sync_state_root()?;
    if lifecycle.lifecycle_generation()? != Some(expected_generation)
        || load(state_dir)? != BootstrapState::Ready
    {
        return Err(BootstrapStateError::ReadyGenerationChanged);
    }
    Ok(())
}

fn persist_impl(state_dir: &Path, state: BootstrapState) -> Result<(), BootstrapStateError> {
    let path = state_file_path(state_dir);
    let tmp = path.with_extension("tmp");

    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(&tmp)?;
    file.write_all(state.as_str().as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);

    fs::rename(&tmp, &path)?;

    // Propagate the parent-directory barrier. A visible rename is not proof
    // that the new directory entry will survive a crash, and callers use a
    // successful return as the durable bootstrap-state commit point.
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "bootstrap state path has no parent directory",
        )
    })?;
    let dir = fs::File::open(parent).map_err(|error| {
        BootstrapStateError::Storage(StorageError::MayHaveTakenEffect {
            path: path.clone(),
            hint: format!("open parent after bootstrap-state rename: {error}"),
        })
    })?;
    dir.sync_all().map_err(|error| {
        BootstrapStateError::Storage(StorageError::MayHaveTakenEffect {
            path: path.clone(),
            hint: format!("fsync parent after bootstrap-state rename: {error}"),
        })
    })?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::household_lifecycle::HouseholdLifecycleLock;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn load_missing_returns_uninitialized() {
        let dir = tmp();
        assert_eq!(load(dir.path()).unwrap(), BootstrapState::Uninitialized);
    }

    #[test]
    fn persist_and_load_roundtrip() {
        let dir = tmp();
        let cases = [
            BootstrapState::Uninitialized,
            BootstrapState::ReadyForNaming,
            BootstrapState::NamedAwaitingPair,
            BootstrapState::PairMachineInstallRestartRequired,
            BootstrapState::Recovering,
        ];
        for state in cases {
            persist(dir.path(), state).unwrap();
            assert_eq!(load(dir.path()).unwrap(), state);
        }
    }

    #[test]
    fn ready_requires_the_exact_lifecycle_generation() {
        let dir = tmp();
        assert!(matches!(
            persist(dir.path(), BootstrapState::Ready),
            Err(BootstrapStateError::ReadyRequiresLifecycleGuard)
        ));
        assert!(matches!(
            staged_non_ready_item(dir.path(), BootstrapState::Ready),
            Err(BootstrapStateError::ReadyRequiresLifecycleGuard)
        ));

        let lifecycle = HouseholdLifecycleLock::open_verified(dir.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let generation = guard.ensure_lifecycle_generation().unwrap();
        let stale = guard.rotate_lifecycle_generation().unwrap();
        assert_ne!(generation, stale);
        assert!(matches!(
            persist_ready_under_lifecycle(&guard, dir.path(), generation),
            Err(BootstrapStateError::ReadyGenerationChanged)
        ));
        assert_eq!(load(dir.path()).unwrap(), BootstrapState::Uninitialized);

        persist_ready_under_lifecycle(&guard, dir.path(), stale).unwrap();
        assert_eq!(load(dir.path()).unwrap(), BootstrapState::Ready);

        let other = tmp();
        assert!(matches!(
            persist_ready_under_lifecycle(&guard, other.path(), stale),
            Err(BootstrapStateError::Lifecycle(
                HouseholdLifecycleLockError::UnsafePath
            ))
        ));
    }

    #[test]
    fn valid_transitions_accepted() {
        use BootstrapState::*;
        let pairs = [
            (Uninitialized, ReadyForNaming),
            (Uninitialized, NamedAwaitingPair),
            (ReadyForNaming, NamedAwaitingPair),
            (NamedAwaitingPair, Ready),
            (NamedAwaitingPair, PairMachineInstallRestartRequired),
            (PairMachineInstallRestartRequired, Ready),
            (NamedAwaitingPair, Recovering),
            (Ready, Recovering),
            (Recovering, Ready),
        ];
        for (from, to) in pairs {
            assert!(from.transition(to).is_ok(), "{from} → {to} should be valid");
        }
    }

    #[test]
    fn invalid_transitions_rejected() {
        use BootstrapState::*;
        let pairs = [
            (Ready, Uninitialized),
            (Ready, ReadyForNaming),
            (Ready, NamedAwaitingPair),
            (Ready, PairMachineInstallRestartRequired),
            (Recovering, PairMachineInstallRestartRequired),
            (NamedAwaitingPair, Uninitialized),
            (NamedAwaitingPair, ReadyForNaming),
        ];
        for (from, to) in pairs {
            assert!(
                from.transition(to).is_err(),
                "{from} → {to} should be invalid"
            );
        }
    }

    #[test]
    fn unknown_file_content_returns_error() {
        let dir = tmp();
        std::fs::write(
            dir.path().join("identity.bootstrap_state"),
            "some_future_state\n",
        )
        .unwrap();
        assert!(matches!(
            load(dir.path()),
            Err(BootstrapStateError::Unknown(_))
        ));
    }

    #[test]
    fn as_str_matches_from_str_roundtrip() {
        let states = [
            BootstrapState::Uninitialized,
            BootstrapState::ReadyForNaming,
            BootstrapState::NamedAwaitingPair,
            BootstrapState::PairMachineInstallRestartRequired,
            BootstrapState::Ready,
            BootstrapState::Recovering,
        ];
        for s in states {
            assert_eq!(BootstrapState::parse_canonical(s.as_str()), Some(s));
        }
    }
}
