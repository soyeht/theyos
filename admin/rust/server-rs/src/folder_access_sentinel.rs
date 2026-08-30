//! Self-diagnosis for silent macOS TCC folder-access rot.
//!
//! Measured on the owner's machine (2026-08-28/29): a long-lived engine
//! process — nine days across an app update — had its TCC evaluation degrade
//! so that every child shell got `EPERM` on `~/Documents` with **no prompt
//! and no log line anywhere**, while the TCC database still said "allowed".
//! The only cure that worked was restarting the engine process; nothing
//! detected the state, so it was cured by hand, twice.
//!
//! This sentinel makes the engine notice and cure itself. Every
//! [`PROBE_INTERVAL`] it lists `~/Documents` (the folder class the incident
//! hit) and feeds the outcome to a pure state machine:
//!
//!  - a process that has NEVER seen the folder readable stays put forever —
//!    that is a real user denial or a pending prompt, a restart cannot fix
//!    it, and exiting would put launchd's `KeepAlive` into a restart loop;
//!  - only the incident signature — readable earlier in this process's
//!    life, then [`CONSECUTIVE_DENIALS_TO_DEGRADE`] permission errors in a
//!    row — declares the process degraded, and the loop exits with
//!    [`EXIT_CODE_FOLDER_ACCESS_DEGRADED`] so launchd brings up a fresh
//!    process, whose TCC evaluation starts clean (the cure proven by hand).
//!
//! The state machine is pure and the destructive step is reachable only
//! through it: rules that decide whether destruction is allowed have to be
//! testable, not asserted by comments.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Distinctive exit code so `/tmp/soyeht-engine.log` and `launchctl` history
/// attribute the restart to this sentinel rather than to a crash.
pub const EXIT_CODE_FOLDER_ACCESS_DEGRADED: i32 = 86;

/// Denials must persist across this many consecutive probes before the
/// process declares itself degraded — a single transient refusal (e.g. a
/// prompt mid-flight) must not cost every live session.
pub const CONSECUTIVE_DENIALS_TO_DEGRADE: u8 = 3;

/// One probe per minute detects the rot within ~4 minutes of onset without
/// meaningfully touching the disk (one `opendir` + one `readdir`).
pub const PROBE_INTERVAL: Duration = Duration::from_secs(60);

/// Outcome of one directory probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    Readable,
    /// `EPERM`/`EACCES`-shaped refusal. On macOS the TCC deny surfaces as
    /// `PermissionDenied`; a plain-chmod `EACCES` lands here too, which is
    /// acceptable — the healthy→denied flip gate still applies, and a
    /// restart on a genuinely re-chmodded home folder is harmless next to
    /// the alternative of never healing the TCC case.
    PermissionDenied,
    /// Anything else (folder missing, volume unmounted, transient IO):
    /// neither evidence of health nor of rot.
    Indeterminate,
}

/// Sentinel health, advanced one probe at a time by [`next_health`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// No probe has succeeded since this process started. Includes the
    /// born-denied case, which must never trigger a restart.
    NeverReadable,
    Healthy,
    /// Readable earlier, now denied for `n` consecutive probes.
    Suspect(u8),
    /// The incident signature is confirmed; the process should be replaced.
    Degraded,
}

#[must_use]
pub fn next_health(current: Health, probe: Probe) -> Health {
    match (current, probe) {
        // A readable probe makes (or keeps) the process healthy, and clears
        // any suspicion outright.
        (Health::NeverReadable | Health::Suspect(_), Probe::Readable) => Health::Healthy,
        // Born denied (or never yet readable): a restart cannot help and
        // would loop under launchd KeepAlive. Hold position until an Ok.
        (Health::NeverReadable, _) => Health::NeverReadable,

        (Health::Healthy, Probe::PermissionDenied) => Health::Suspect(1),
        (Health::Healthy, _) => Health::Healthy,

        (Health::Suspect(n), Probe::PermissionDenied) => {
            if n.saturating_add(1) >= CONSECUTIVE_DENIALS_TO_DEGRADE {
                Health::Degraded
            } else {
                Health::Suspect(n + 1)
            }
        }
        // An indeterminate reading neither clears suspicion nor deepens it.
        (Health::Suspect(n), Probe::Indeterminate) => Health::Suspect(n),

        (Health::Degraded, _) => Health::Degraded,
    }
}

#[must_use]
pub fn classify(result: io::Result<()>) -> Probe {
    match result {
        Ok(()) => Probe::Readable,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Probe::PermissionDenied,
        Err(_) => Probe::Indeterminate,
    }
}

/// One real probe: `opendir` + first `readdir`, the exact operations the
/// incident's `ls` died on.
fn probe_dir(path: &Path) -> Probe {
    classify(std::fs::read_dir(path).map(|mut entries| {
        // Force one readdir: TCC mediates enumeration, not just open.
        let _ = entries.next();
    }))
}

/// Spawns the sentinel loop watching `$HOME/Documents`. Returns `None` when
/// no home directory is available (headless/CI), which disables the
/// sentinel rather than probing a meaningless path.
#[must_use]
pub fn start_folder_access_sentinel() -> Option<tokio::task::JoinHandle<()>> {
    let home = std::env::var_os("HOME")?;
    let target = PathBuf::from(home).join("Documents");
    Some(tokio::spawn(async move {
        let mut health = Health::NeverReadable;
        loop {
            tokio::time::sleep(PROBE_INTERVAL).await;
            let path = target.clone();
            // TCC consults can block for seconds; keep them off the runtime.
            let probe = match tokio::task::spawn_blocking(move || probe_dir(&path)).await {
                Ok(p) => p,
                Err(_) => Probe::Indeterminate,
            };
            let next = next_health(health, probe);
            if next != health {
                tracing::warn!(
                    "[folder-access-sentinel] {:?} -> {:?} probing {}",
                    health,
                    next,
                    target.display()
                );
            }
            if next == Health::Degraded {
                tracing::error!(
                    "[folder-access-sentinel] {} was readable earlier in this process's \
                     life and has now been permission-denied {} consecutive times — the \
                     silent TCC degradation of 2026-08-28. Exiting with code {} so launchd \
                     KeepAlive replaces this process with one whose TCC evaluation starts \
                     clean.",
                    target.display(),
                    CONSECUTIVE_DENIALS_TO_DEGRADE,
                    EXIT_CODE_FOLDER_ACCESS_DEGRADED
                );
                std::process::exit(EXIT_CODE_FOLDER_ACCESS_DEGRADED);
            }
            health = next;
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(start: Health, probes: &[Probe]) -> Health {
        probes.iter().fold(start, |h, p| next_health(h, *p))
    }

    #[test]
    fn born_denied_never_degrades() {
        // The restart-loop guard: a process that never saw the folder
        // readable must hold NeverReadable through any run of denials.
        let h = run(Health::NeverReadable, &[Probe::PermissionDenied; 50]);
        assert_eq!(h, Health::NeverReadable);
    }

    #[test]
    fn the_incident_signature_degrades_after_three_consecutive_denials() {
        let h = run(
            Health::NeverReadable,
            &[
                Probe::Readable,
                Probe::PermissionDenied,
                Probe::PermissionDenied,
                Probe::PermissionDenied,
            ],
        );
        assert_eq!(h, Health::Degraded);
    }

    #[test]
    fn two_denials_are_still_suspect_not_degraded() {
        let h = run(
            Health::Healthy,
            &[Probe::PermissionDenied, Probe::PermissionDenied],
        );
        assert_eq!(h, Health::Suspect(2));
    }

    #[test]
    fn a_readable_probe_clears_suspicion_entirely() {
        let h = run(
            Health::Healthy,
            &[
                Probe::PermissionDenied,
                Probe::PermissionDenied,
                Probe::Readable,
                Probe::PermissionDenied,
                Probe::PermissionDenied,
            ],
        );
        // The counter restarted after the recovery: still suspect, not degraded.
        assert_eq!(h, Health::Suspect(2));
    }

    #[test]
    fn indeterminate_probes_neither_heal_nor_damn() {
        let h = run(
            Health::Healthy,
            &[
                Probe::PermissionDenied,
                Probe::Indeterminate,
                Probe::PermissionDenied,
                Probe::Indeterminate,
                Probe::PermissionDenied,
            ],
        );
        assert_eq!(h, Health::Degraded);
        assert_eq!(
            run(Health::NeverReadable, &[Probe::Indeterminate; 10]),
            Health::NeverReadable
        );
    }

    #[test]
    fn degraded_is_terminal_for_this_process() {
        assert_eq!(next_health(Health::Degraded, Probe::Readable), Health::Degraded);
    }

    #[test]
    fn classification_maps_eperm_to_denied_and_the_rest_apart() {
        assert_eq!(classify(Ok(())), Probe::Readable);
        assert_eq!(
            classify(Err(io::Error::from(io::ErrorKind::PermissionDenied))),
            Probe::PermissionDenied
        );
        assert_eq!(
            classify(Err(io::Error::from(io::ErrorKind::NotFound))),
            Probe::Indeterminate
        );
    }
}
