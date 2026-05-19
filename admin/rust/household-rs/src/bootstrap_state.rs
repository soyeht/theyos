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

// ── State enum ────────────────────────────────────────────────────────────────

/// Onboarding state machine state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapState {
    Uninitialized,
    ReadyForNaming,
    NamedAwaitingPair,
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
            "ready" => Some(Self::Ready),
            "recovering" => Some(Self::Recovering),
            _ => None,
        }
    }

    /// Attempt to transition to `next`. Returns `Err` if the transition is
    /// not valid per the state machine specification.
    pub fn transition(self, next: Self) -> Result<Self, TransitionError> {
        use BootstrapState::{NamedAwaitingPair, Ready, ReadyForNaming, Recovering, Uninitialized};
        let ok = matches!(
            (self, next),
            // Forward onboarding transitions + idempotent self-transitions
            // (self-loops allowed; persist is skipped upstream).
            (Uninitialized, Uninitialized | ReadyForNaming | NamedAwaitingPair)
            | (ReadyForNaming, ReadyForNaming | NamedAwaitingPair)
            | (NamedAwaitingPair, NamedAwaitingPair | Ready | Recovering)
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
}

// ── Persistence ────────────────────────────────────────────────────────────────

fn state_file_path(state_dir: &Path) -> PathBuf {
    state_dir.join("identity.bootstrap_state")
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

    // fsync parent directory so the rename is durable on crash.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
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
            BootstrapState::Ready,
            BootstrapState::Recovering,
        ];
        for state in cases {
            persist(dir.path(), state).unwrap();
            assert_eq!(load(dir.path()).unwrap(), state);
        }
    }

    #[test]
    fn valid_transitions_accepted() {
        use BootstrapState::*;
        let pairs = [
            (Uninitialized, ReadyForNaming),
            (Uninitialized, NamedAwaitingPair),
            (ReadyForNaming, NamedAwaitingPair),
            (NamedAwaitingPair, Ready),
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
            BootstrapState::Ready,
            BootstrapState::Recovering,
        ];
        for s in states {
            assert_eq!(BootstrapState::parse_canonical(s.as_str()), Some(s));
        }
    }
}
