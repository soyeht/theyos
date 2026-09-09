#![cfg(test)]

use std::fs::{self, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::thread;

use tempfile::TempDir;

use super::*;

const CHILD_TEST_NAME: &str = "household_lifecycle::tests::multiprocess_shared_lifecycle_worker";
const CHILD_STATE_ENV: &str = "THEYOS_HOUSEHOLD_LIFECYCLE_CHILD_STATE";
const CHILD_READY_ENV: &str = "THEYOS_HOUSEHOLD_LIFECYCLE_CHILD_READY";

#[test]
fn shared_guard_blocks_exclusive_until_it_is_released() {
    let temp = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
    let shared = lifecycle.lock_shared().unwrap();
    assert_eq!(
        lifecycle
            .lock_exclusive_until(Instant::now() + Duration::from_millis(50))
            .unwrap_err(),
        HouseholdLifecycleLockError::LockTimeout
    );
    drop(shared);
    lifecycle
        .lock_exclusive_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
}

#[test]
fn visible_lock_is_never_reused_without_the_state_root_barrier() {
    let temp = TempDir::new().unwrap();
    let armed = lifecycle_fail_injection::arm_parent_sync();
    assert_eq!(
        HouseholdLifecycleLock::open_verified(temp.path()).unwrap_err(),
        HouseholdLifecycleLockError::Io
    );
    assert!(
        temp.path().join(HOUSEHOLD_LIFECYCLE_LOCK_FILENAME).exists(),
        "the failpoint models a visible lock whose parent barrier failed"
    );
    drop(armed);
    HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
}

/// The lifecycle-lock allowlist, pinned by EXACT SET EQUALITY.
///
/// This gate returns [`HouseholdLifecycleLockError::UnsupportedFilesystem`],
/// so it decides whether the lifecycle lock can exist at all — every guard
/// built on that lock inherits this set. It was the LAST `matches!` arm of
/// its kind in this crate: the ledger's twin was pinned by equality while
/// this one kept the or-pattern on Linux and a bare `== b"apfs"` on macOS,
/// with nothing asserting either. Closing one and leaving the other is
/// shutting the door and leaving the window.
///
/// Membership assertions would not do. They catch only the magics they
/// happen to name; add one nobody anticipated and every assertion stays
/// green while the gate quietly admits it.
#[test]
fn lifecycle_lock_filesystem_allowlist_is_exact_and_review_gated() {
    assert_eq!(
        LINUX_LIFECYCLE_LOCK_FILESYSTEMS,
        [EXT4_SUPER_MAGIC, XFS_SUPER_MAGIC, BTRFS_SUPER_MAGIC],
        "the Linux lifecycle-lock allowlist changed. This set decides whether a \
             lifecycle lock may exist, and every guard built on that lock inherits it; \
             re-justify admission before changing this set"
    );
    assert_eq!(
        MACOS_LIFECYCLE_LOCK_FILESYSTEMS,
        [b"apfs".as_slice()],
        "the macOS lifecycle-lock allowlist changed; same obligation as the Linux set"
    );

    for magic in LINUX_LIFECYCLE_LOCK_FILESYSTEMS {
        assert!(linux_lifecycle_filesystem_is_allowlisted(magic));
    }
    for name in MACOS_LIFECYCLE_LOCK_FILESYSTEMS {
        assert!(macos_lifecycle_filesystem_is_allowlisted(name));
    }
    // 0x0102_1994 tmpfs, 0x0000_6969 NFS — named locally because this
    // module does not define them, and the point is to probe OUTSIDE the
    // admitted set.
    for magic in [0x0102_1994, 0x0000_6969, i64::MAX, 0] {
        assert!(!linux_lifecycle_filesystem_is_allowlisted(magic));
    }
    // `apfs2` is the load-bearing one: an implementation using
    // `starts_with` instead of equality would admit it, and someone could
    // make that change believing it equivalent.
    for name in [b"tmpfs".as_slice(), b"nfs", b"hfs", b"", b"apfs2", b"apf"] {
        assert!(
            !macos_lifecycle_filesystem_is_allowlisted(name),
            "{} must not be admitted",
            String::from_utf8_lossy(name)
        );
    }
}

/// The crate has TWO filesystem allowlists. This pins them to the SAME set
/// and fails when EITHER moves alone.
///
/// That is the property that makes the crosscheck worth having: two copies
/// that must agree, with nothing comparing them, is drift waiting to
/// happen — and they had already diverged in FORM (the ledger read a named
/// set on both platforms while this module used an or-pattern and a bare
/// literal), which is how content diverges next without a signal.
///
/// They must agree because they answer the same physical question about
/// the same directory: the lifecycle lock and the ledger record live under
/// one household. A filesystem good enough to hold the lock but not the
/// record — or the reverse — is not a state this crate can represent.
///
/// If a future change makes them legitimately differ, do not delete this
/// test: assert the intended difference here, with the reason, so the
/// divergence stays declared instead of silent.
#[test]
fn the_two_filesystem_allowlists_are_the_same_set() {
    assert_eq!(
        LINUX_LIFECYCLE_LOCK_FILESYSTEMS,
        crate::mesh_intent_nonce_ledger::LINUX_RENAME_KNOWN_NO_EFFECT_FILESYSTEMS,
        "the lifecycle-lock and nonce-ledger Linux allowlists drifted apart. They \
             govern the same household directory and must admit the same filesystems; \
             change both together, or declare the difference here with its reason"
    );
    assert_eq!(
        MACOS_LIFECYCLE_LOCK_FILESYSTEMS,
        crate::mesh_intent_nonce_ledger::MACOS_RENAME_KNOWN_NO_EFFECT_FILESYSTEMS,
        "the lifecycle-lock and nonce-ledger macOS allowlists drifted apart; same \
             obligation as the Linux sets"
    );
}

#[test]
fn lifecycle_generation_is_fixed_width_durable_and_changes_per_rotation() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    assert_eq!(write.lifecycle_generation().unwrap(), None);
    let first = write.ensure_lifecycle_generation().unwrap();
    assert_eq!(
        write.lifecycle_generation().unwrap(),
        Some(first),
        "an established witness must round-trip exact bytes"
    );
    let second = write.rotate_lifecycle_generation().unwrap();
    assert_ne!(first, second);
    assert_eq!(write.lifecycle_generation().unwrap(), Some(second));
    let metadata = fs::metadata(temp.path().join(HOUSEHOLD_LIFECYCLE_GENERATION_FILENAME)).unwrap();
    assert_eq!(metadata.len(), GENERATION_FILE_BYTES as u64);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
}

#[test]
fn visible_generation_after_lost_parent_ack_is_stabilized_before_reuse() {
    let temp = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    generation_fail_injection::arm_after_rename();
    assert_eq!(
        write.ensure_lifecycle_generation().unwrap_err(),
        HouseholdLifecycleLockError::Io
    );
    assert!(
        temp.path()
            .join(HOUSEHOLD_LIFECYCLE_GENERATION_FILENAME)
            .exists(),
        "the failpoint models rename visibility without a parent-barrier acknowledgement"
    );

    let sticky = generation_fail_injection::arm_existing_parent_sync();
    assert_eq!(
        write.lifecycle_generation().unwrap_err(),
        HouseholdLifecycleLockError::Io,
        "retry must not trust the visible witness while its stabilizing barrier fails"
    );
    drop(sticky);
    write
        .lifecycle_generation()
        .unwrap()
        .expect("retry re-proves file and parent durability before returning the witness");
}

#[test]
fn generation_operation_sweeps_crash_orphaned_nonce_temp() {
    let temp = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    let orphan = temp.path().join(format!("{GENERATION_TMP_PREFIX}orphan"));
    fs::write(&orphan, b"partial").unwrap();
    write.ensure_lifecycle_generation().unwrap();
    assert!(!orphan.exists());
}

#[test]
fn shared_guard_refuses_an_unresolved_teardown_breadcrumb() {
    let temp = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
    fs::create_dir(temp.path().join(HOUSEHOLD_TEARDOWN_BREADCRUMB)).unwrap();
    assert_eq!(
        lifecycle.lock_shared().unwrap_err(),
        HouseholdLifecycleLockError::RecoveryRequired
    );
    let write = lifecycle.lock_exclusive().unwrap();
    assert!(write.teardown_breadcrumb_exists().unwrap());
    assert!(write.remove_tearing_down().unwrap());
    drop(write);
    lifecycle.lock_shared().unwrap();
}

/// Point `lock_path` at a different file, leaving the original inode
/// unlinked but intact.
///
/// The obvious spelling — `remove_file` then `create_new` at the same path
/// — lets the kernel hand the new file the inode the old one just freed.
/// Both tests below detect the swap by an `st_dev`/`st_ino` comparison, but
/// not the same one:
///
/// - `lock_shared` uses [`Self::file_matches_expected`] — the freshly opened
///   lock against the identity `open_verified` memorised.
/// - the write guard uses `binding_is_current`, whose `named_lock_matches`
///   is called with the fd the guard is *already holding* — the path as it
///   is now against the file opened before the swap.
///
/// In both, one side predates the substitution, which is exactly why they
/// can see it. (`named_lock_matches` against a file just opened *from* the
/// path it stats compares a value with itself and never detects anything;
/// only the held-fd caller gives it two different instants.)
///
/// Only the first is actually exposed to inode reuse, and the difference is
/// what makes this helper worth having. `open_verified` keeps `state_dir`
/// open but stores the lock as bare `lock_dev`/`lock_ino` — nothing holds
/// that inode, so `remove_file` frees it and the replacement can be handed
/// the same number. The write guard, by contrast, is still holding an open
/// file on the lock, which pins the inode and rules the reuse out.
///
/// So the second test is deterministic today for a reason that lives in
/// `lock_exclusive`, not in its own setup. Routing both through this helper
/// keeps it that way if that ever changes, and costs nothing now.
///
/// Creating the substitute while the original is still linked forces a
/// distinct inode — two simultaneously-linked files cannot share one on any
/// local filesystem — and `rename` swaps it in atomically. That makes the
/// mismatch an invariant of the setup rather than a property of the
/// allocator.
fn substitute_lock_file(dir: &Path, lock_path: &Path) {
    let substitute = dir.join("substitute-lock.tmp");
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&substitute)
        .unwrap();
    fs::rename(&substitute, lock_path).unwrap();
}

#[test]
fn named_lock_substitution_after_open_fails_closed() {
    let temp = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
    let lock_path = temp.path().join(HOUSEHOLD_LIFECYCLE_LOCK_FILENAME);
    substitute_lock_file(temp.path(), &lock_path);
    assert_eq!(
        lifecycle.lock_shared().unwrap_err(),
        HouseholdLifecycleLockError::UnsafePath
    );
}

#[test]
fn named_lock_substitution_after_flock_blocks_write_guard_mutation() {
    let temp = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    let lock_path = temp.path().join(HOUSEHOLD_LIFECYCLE_LOCK_FILENAME);
    substitute_lock_file(temp.path(), &lock_path);
    assert_eq!(
        write.sync_state_root().unwrap_err(),
        HouseholdLifecycleLockError::UnsafePath
    );
    assert_eq!(
        write.rename_household_to_tearing_down().unwrap_err(),
        HouseholdLifecycleLockError::UnsafePath
    );
}

#[test]
fn write_guard_rejects_a_different_state_root() {
    let first = TempDir::new().unwrap();
    let second = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(first.path()).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    assert_eq!(
        write.verify_state_root(second.path()).unwrap_err(),
        HouseholdLifecycleLockError::UnsafePath
    );
    write.verify_state_root(first.path()).unwrap();
}

#[test]
fn read_guard_rejects_a_different_state_root() {
    let first = TempDir::new().unwrap();
    let second = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(first.path()).unwrap();
    let read = lifecycle.lock_shared().unwrap();
    assert_eq!(
        read.verify_state_root(second.path()).unwrap_err(),
        HouseholdLifecycleLockError::UnsafePath
    );
    read.verify_state_root(first.path()).unwrap();
}

#[test]
fn residual_household_directory_without_record_is_not_installed_authority() {
    let state = TempDir::new().unwrap();
    fs::create_dir(state.path().join(HOUSEHOLD_SUBDIR)).unwrap();
    fs::create_dir(state.path().join(HOUSEHOLD_SUBDIR).join("owner_events")).unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    assert!(!write.household_exists().unwrap());
}

#[test]
fn lifecycle_flock_serializes_processes_and_releases_on_child_death() {
    let temp = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
    let ready = temp.path().join("child-shared-ready");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(CHILD_TEST_NAME)
        .arg("--nocapture")
        .env(CHILD_STATE_ENV, temp.path())
        .env(CHILD_READY_ENV, &ready)
        .spawn()
        .unwrap();
    let ready_deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(
            Instant::now() < ready_deadline,
            "child never acquired lifecycle shared guard"
        );
        thread::sleep(Duration::from_millis(5));
    }

    assert_eq!(
        lifecycle
            .lock_exclusive_until(Instant::now() + Duration::from_millis(50))
            .unwrap_err(),
        HouseholdLifecycleLockError::LockTimeout
    );
    child.kill().unwrap();
    child.wait().unwrap();
    lifecycle
        .lock_exclusive_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
}

const ROTATE_CRASH_WORKER: &str = "household_lifecycle::tests::generation_rotate_crash_worker";

/// Child: rotate the generation, parking after the rename so the parent
/// can SIGKILL it in exactly that window.
#[test]
fn generation_rotate_crash_worker() {
    let Some(state_path) = std::env::var_os(CHILD_STATE_ENV).map(PathBuf::from) else {
        return;
    };
    let lifecycle = HouseholdLifecycleLock::open_verified(&state_path).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    // Arm only now, with the lock already held: arming earlier would let
    // the park fire on some other generation write during open, and the
    // crash would land on a different operation than the one under test.
    crate::crash_park::arm_from_env();
    let _ = write.rotate_lifecycle_generation();
}

/// G0 -> G1 across a REAL crash in the post-rename window.
///
/// `rotate_lifecycle_generation` renames the new witness into place, and
/// only then syncs the parent and reads it back. A process killed between
/// those leaves a generation file that is VISIBLE but whose parent barrier
/// never completed, and no caller alive to be told the rotation failed.
///
/// Two things must hold afterwards:
/// - the witness still reads back as a well-formed generation (never torn,
///   never a partial write) — it is fixed-width and renamed, so tearing
///   would mean the atomicity claim is wrong;
/// - the household can still make progress, and the generation it moves to
///   is distinct from BOTH the pre-crash G0 and whatever became visible.
///   Landing back on G0 would be the ABA that lets artifacts tagged with
///   the old generation be adopted as current.
#[test]
fn sigkill_after_generation_rename_leaves_a_readable_witness_and_no_aba() {
    let temp = TempDir::new().unwrap();
    let g0 = {
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let write = lifecycle.lock_exclusive().unwrap();
        write.ensure_lifecycle_generation().unwrap()
    };

    let ready = temp.path().join("parked-generation-after-rename");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(ROTATE_CRASH_WORKER)
        .arg("--nocapture")
        .env(CHILD_STATE_ENV, temp.path())
        .env(crate::crash_park::PARK_SITE_ENV, "generation:after_rename")
        .env(crate::crash_park::PARK_READY_ENV, &ready)
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    while !ready.exists() {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("child exited ({status}) without reaching the post-rename window");
        }
        assert!(
            Instant::now() < deadline,
            "child never reached generation:after_rename"
        );
        thread::sleep(Duration::from_millis(10));
    }
    child.kill().unwrap();
    assert!(
        !child.wait().unwrap().success(),
        "the child was supposed to be killed in the window, not to exit cleanly"
    );

    // Restart: a fresh lock over the same state directory.
    let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();

    let visible = write
        .lifecycle_generation()
        .expect("witness must still parse after a crash in the rename window");
    let visible = visible.expect("a witness was established before the crash");
    assert_ne!(
        visible, g0,
        "the rename had already landed, so the visible witness must be the new one"
    );

    let g2 = write
        .rotate_lifecycle_generation()
        .expect("the household must still be able to advance after the crash");
    assert_ne!(g2, visible, "a rotation must advance");
    assert_ne!(
        g2, g0,
        "rotating after the crash must not land back on the pre-crash generation:              that is the ABA that lets old-generation artifacts be adopted as current"
    );
}

#[test]
fn multiprocess_shared_lifecycle_worker() {
    let Some(state_path) = std::env::var_os(CHILD_STATE_ENV).map(PathBuf::from) else {
        return;
    };
    let ready = PathBuf::from(std::env::var_os(CHILD_READY_ENV).unwrap());
    let lifecycle = HouseholdLifecycleLock::open_verified(&state_path).unwrap();
    let _shared = lifecycle.lock_shared().unwrap();
    fs::write(ready, b"ready").unwrap();
    // The parent deliberately terminates this process. A finite fallback
    // keeps an orphaned manually-invoked child from living forever.
    thread::sleep(Duration::from_secs(20));
}
