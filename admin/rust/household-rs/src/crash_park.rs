//! Test-only crash-window park, for real `kill -9` inside a durable write.
//!
//! The crates already carry fail-injection hooks that make a named stage
//! RETURN AN ERROR. That exercises the error path; it does not exercise the
//! process disappearing mid-window, which is the case the durability protocol
//! actually exists for — markers, breadcrumbs and restart recovery are only
//! load-bearing when nothing got to run after the crash.
//!
//! So this parks instead of returning. A child process armed by environment
//! reaches the named site inside the real routine — lock held, whatever bytes
//! already reached the disk still there, nothing unwound — creates a ready
//! file, and blocks forever. The parent observes the ready file and sends
//! `SIGKILL`. What survives is exactly what the filesystem kept.
//!
//! Deliberately called from INSIDE the existing fail-injection functions
//! rather than from new call sites: the value of these points is that
//! production traverses them, and a parallel hook could drift away from the
//! code being measured. Nothing here is compiled into production — the
//! callers are all `#[cfg(test)]` modules whose `cfg(not(test))` twins are
//! const `false`.

/// Names the site this process must park at.
pub(crate) const PARK_SITE_ENV: &str = "THEYOS_CRASH_PARK_SITE";
/// Names the file to create once parked, so the parent can wait for arrival
/// rather than racing a sleep.
pub(crate) const PARK_READY_ENV: &str = "THEYOS_CRASH_PARK_READY";

/// Process-global rather than thread-local, and that is load-bearing: the
/// ledger hands the non-cancellable part of a commit to a WORKER THREAD (see
/// `MeshIntentNonceCommitStage::WorkerInFlight`). A thread-local arm set by
/// the caller is invisible there, so the park never fires and the child exits
/// cleanly — a harness that silently measures nothing.
static ARMED: std::sync::Mutex<Option<(String, std::path::PathBuf)>> = std::sync::Mutex::new(None);

/// Arm this thread from the environment, explicitly.
///
/// Deliberately NOT read inside `park_if_armed`. Reading the environment on
/// every call armed the process from the moment it started, so the park fired
/// at the first matching stage in the process lifetime — which for a ledger is
/// the `atomic_replace` inside `open`'s own initialization, not the operation
/// under test. The crash then landed on the wrong write: the marker was
/// `INITIALIZING` rather than `DIRTY`, the record on disk was the empty
/// initial one, and a replay "committing again" looked like a double-consume
/// when it was just a fresh consume after a crashed init.
///
/// So arming is a separate, explicit step the harness performs AFTER the
/// subject is open and immediately before the operation it means to observe.
/// The observation binds to the operation, not to the process.
pub(crate) fn arm_from_env() {
    let (Some(site), Some(ready)) = (
        std::env::var_os(PARK_SITE_ENV),
        std::env::var_os(PARK_READY_ENV),
    ) else {
        return;
    };
    let Some(site) = site.to_str().map(str::to_owned) else {
        return;
    };
    if let Ok(mut armed) = ARMED.lock() {
        *armed = Some((site, std::path::PathBuf::from(ready)));
    }
}

/// Park forever if this thread was armed for `site`.
///
/// `site` is a stable string rather than a typed enum because the four
/// fail-injection modules live in different files with different stage types;
/// a shared string keeps one park implementation instead of four copies.
/// Every caller passes a literal, and the harness asserts it reached the site
/// (via the ready file) before killing — so a typo cannot silently turn into
/// "the crash never happened and the test still passed".
pub(crate) fn park_if_armed(site: &str) {
    // Clone out and DROP the guard before parking: parking forever while
    // holding the lock would deadlock any other thread that reaches a site.
    let ready = {
        let Ok(armed) = ARMED.lock() else {
            return;
        };
        armed
            .as_ref()
            .filter(|(armed_site, _)| armed_site == site)
            .map(|(_, ready)| ready.clone())
    };
    let Some(ready) = ready else {
        return;
    };
    // Created AFTER arriving, and synced, because this process is about to be
    // killed uncleanly and the parent must not act on a buffered entry.
    if let Ok(file) = std::fs::File::create(&ready) {
        let _ = file.sync_all();
    }
    loop {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
