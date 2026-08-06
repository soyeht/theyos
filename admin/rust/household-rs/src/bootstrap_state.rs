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
mod durable_ready_writer_containment {
    //! Gate: the set of code paths that can durably write `Ready` is exactly one.
    //!
    //! `Ready` cannot carry its own authority token. `BootstrapState` derives
    //! `Deserialize`, so a `Ready(Witness)` would be mintable by any
    //! deserializer -- authority arriving over the wire, same alphabet and
    //! different authority. And every `== BootstrapState::Ready` comparison would
    //! need to *construct* a `Ready` to compare against, demanding mint authority
    //! in pure observers.
    //!
    //! The handle is on the PATH instead, and it already exists:
    //!
    //!   persist_impl                                 PRIVATE, sole file writer
    //!     caller 1: persist()                        REJECTS Ready
    //!     caller 2: persist_ready_under_lifecycle()  requires &LifecycleWriteGuard
    //!
    //! `LifecycleWriteGuard` is immune to the serde objection precisely because
    //! it is not the value that travels on the wire -- it is a lock guard.
    //! Because `persist_impl` is private, the caller universe is bounded by this
    //! module, so the durable writer set is compiler-bounded rather than swept.
    //!
    //! What this test adds is the part the compiler CANNOT express: that nobody
    //! widens `persist_impl` to `pub` (which would unbound the universe), and
    //! that no third in-module caller appears. Both are legal edits; only a gate
    //! catches them.
    //!
    //! Deliberately NOT covered: the in-memory `Arc<RwLock<BootstrapState>>`
    //! cell, whose three `Ready` writers were enumerated mechanically by a
    //! compiler oracle and are tracked as named debt. This gate is about the
    //! durable path.

    const SOURCE: &str = include_str!("bootstrap_state.rs");

    #[test]
    fn persist_impl_stays_private_and_has_exactly_two_callers() {
        // Positive control: if the needle stops matching, everything below would
        // pass vacuously against empty sets.
        // Every check below is LINE-ANCHORED, never `contains`. This module
        // quotes the very strings it checks for, and `include_str!` of the file
        // that holds it means self-reference breaks BOTH directions: a negative
        // `contains` finds its own literal and fails spuriously, and a positive
        // `contains` finds its own literal and passes vacuously even if the item
        // were deleted. Anchoring at line start makes a quoted needle inert.
        let starts = |needle: &str| SOURCE.lines().any(|l| l.trim_start().starts_with(needle));

        assert!(
            starts("fn persist_impl(") || starts("pub fn persist_impl("),
            "persist_impl not found -- this gate is measuring nothing"
        );

        // 1. It must stay PRIVATE. `pub fn persist_impl` would unbound the caller
        //    universe and make the containment argument false, silently.
        assert!(
            !starts("pub fn persist_impl("),
            "persist_impl became public. The durable-Ready containment argument \
             rests on its caller universe being bounded by this module; making it \
             pub removes that bound and any crate could then write Ready directly."
        );

        // 2. The in-module caller set must stay exactly two. Count call sites --
        //    `persist_impl(` with an open paren -- excluding the definition and
        //    comment lines, so prose references never count.
        // Match a line that BEGINS with the call form, not one that merely
        // contains it: this module names the needle inside its own filter, and a
        // `contains` would count that literal as a third caller.
        // This module quotes "fn persist_impl(" and "pub fn persist_impl(" inside
        // its own assertions, and a bare-identifier needle would count those and
        // make the gate churn whenever its own text is edited -- the same
        // self-reference that has already bitten two guards in this delivery.
        let call_sites: Vec<&str> = SOURCE
            .lines()
            .filter(|line| {
                let t = line.trim_start();
                !t.starts_with("//")
                    && !t.starts_with("fn persist_impl(")
                    && t.starts_with("persist_impl(state_dir")
            })
            .map(str::trim)
            .collect();

        assert_eq!(
            call_sites.len(),
            2,
            "the persist_impl caller set changed: {call_sites:?}. Exactly two are \
             sanctioned -- persist(), which REJECTS Ready, and \
             persist_ready_under_lifecycle(), which requires a &LifecycleWriteGuard \
             and revalidates the generation before AND after the write. A third \
             caller is a third way to durably write bootstrap state; if it is \
             legitimate, say why it may bypass the guard and update this gate."
        );
    }

    #[test]
    fn the_guarded_caller_is_the_only_one_that_may_write_ready() {
        let starts = |needle: &str| SOURCE.lines().any(|l| l.trim_start().starts_with(needle));

        // DELIBERATELY NOT ASSERTED HERE: "persist() still rejects Ready".
        //
        // A source check for `ReadyRequiresLifecycleGuard` is TOOTHLESS: the
        // identifier also appears in the error enum declaration, so the check is
        // satisfied whether or not the rejection exists. Measured, not assumed --
        // deleting the rejection body from persist() left such a check GREEN.
        //
        // The property is gated behaviourally instead, by
        // `tests::ready_requires_the_exact_lifecycle_generation`, which calls
        // persist(dir, Ready) and asserts the error. Measured: deleting that same
        // rejection body makes THAT test FAIL. Keeping a source assertion that
        // cannot fail, beside a behavioural one that can, would add the
        // appearance of coverage and none of the coverage.
        assert!(
            starts("pub fn persist_ready_under_lifecycle("),
            "the guarded durable-Ready entry point is gone or renamed"
        );
        assert!(
            starts("lifecycle: &LifecycleWriteGuard"),
            "persist_ready_under_lifecycle no longer takes the lifecycle guard -- \
             the token that makes this path authoritative"
        );
    }
}

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
