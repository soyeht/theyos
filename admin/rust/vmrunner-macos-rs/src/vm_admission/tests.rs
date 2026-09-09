#![cfg(test)]

use super::*;
use std::collections::HashSet;
use std::sync::Mutex;

/// Build an admission instance with an injected boot id and a fake liveness
/// set, backed by a temp registry file.
fn test_admission(dir: &Path, boot_id: &str, alive: HashSet<i32>) -> VmAdmission {
    let alive = Arc::new(Mutex::new(alive));
    let alive2 = Arc::clone(&alive);
    VmAdmission {
        slots: MacOSVmSlotManager::new(),
        registry_path: dir.join(REGISTRY_FILENAME),
        boot_id: boot_id.to_string(),
        liveness: Arc::new(move |pid| alive2.lock().unwrap().contains(&pid)),
    }
}

fn read_raw(dir: &Path) -> Registry {
    let s = std::fs::read_to_string(dir.join(REGISTRY_FILENAME)).unwrap_or_default();
    if s.trim().is_empty() {
        Registry::default()
    } else {
        serde_json::from_str(&s).unwrap()
    }
}

#[test]
fn reserve_succeeds_until_limit_then_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    let mut alive = HashSet::new();
    alive.insert(current_pid());
    let adm = test_admission(tmp.path(), "boot-A", alive);

    let l1 = adm.reserve(VmKind::Install, None).expect("first reserve");
    let l2 = adm.reserve(VmKind::WarmPool, None).expect("second reserve");

    // Third must be refused with CapacityFull (limit is 2), no VM started.
    let err = adm.reserve(VmKind::UserClaw, None).unwrap_err();
    match err {
        AdmissionError::HostVmLimitReached {
            live,
            suspected_orphans,
            reason,
        } => {
            assert_eq!(live, 2);
            assert_eq!(suspected_orphans, 0);
            assert_eq!(reason, LimitReason::CapacityFull);
        }
        AdmissionError::Registry(e) => panic!("expected HostVmLimitReached, got Registry({e})"),
    }

    // Releasing one frees a slot.
    l1.release_clean();
    let _l3 = adm
        .reserve(VmKind::UserClaw, None)
        .expect("reserve after release");
    drop(l2);
}

#[test]
fn same_boot_dead_pid_is_suspected_orphan_and_counts() {
    let tmp = tempfile::tempdir().unwrap();
    // Seed a registry with two leases from a DEAD pid on the SAME boot.
    let dead_pid = 999_999; // not in alive set
    let reg = Registry {
        version: 1,
        blocked_boot_id: None,
        leases: vec![
            VmLeaseRecord {
                lease_id: "a".into(),
                owner_pid: dead_pid,
                boot_id: "boot-A".into(),
                kind: VmKind::Install,
                instance_id: None,
                started_at: 1,
                state: LeaseState::Running,
            },
            VmLeaseRecord {
                lease_id: "b".into(),
                owner_pid: dead_pid,
                boot_id: "boot-A".into(),
                kind: VmKind::Snapshot,
                instance_id: None,
                started_at: 2,
                state: LeaseState::Running,
            },
        ],
    };
    std::fs::write(
        tmp.path().join(REGISTRY_FILENAME),
        serde_json::to_string_pretty(&reg).unwrap(),
    )
    .unwrap();

    let mut alive = HashSet::new();
    alive.insert(current_pid()); // dead_pid is NOT alive
    let adm = test_admission(tmp.path(), "boot-A", alive);

    // Both dead-pid leases are suspected orphans on this boot → limit reached,
    // refuse WITHOUT removing them.
    let err = adm.reserve(VmKind::Install, None).unwrap_err();
    match err {
        AdmissionError::HostVmLimitReached {
            live,
            suspected_orphans,
            reason,
        } => {
            assert_eq!(live, 0);
            assert_eq!(suspected_orphans, 2);
            assert_eq!(reason, LimitReason::CapacityFull);
        }
        AdmissionError::Registry(e) => panic!("expected HostVmLimitReached, got Registry({e})"),
    }
    // Orphans must NOT be silently removed.
    assert_eq!(read_raw(tmp.path()).leases.len(), 2);
}

#[test]
fn different_boot_leases_are_reclaimed() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry {
        version: 1,
        blocked_boot_id: Some("boot-OLD".into()),
        leases: vec![VmLeaseRecord {
            lease_id: "old".into(),
            owner_pid: 12345,
            boot_id: "boot-OLD".into(),
            kind: VmKind::Install,
            instance_id: None,
            started_at: 1,
            state: LeaseState::Running,
        }],
    };
    std::fs::write(
        tmp.path().join(REGISTRY_FILENAME),
        serde_json::to_string_pretty(&reg).unwrap(),
    )
    .unwrap();

    let mut alive = HashSet::new();
    alive.insert(current_pid());
    let adm = test_admission(tmp.path(), "boot-NEW", alive);

    // New boot: old lease reconciled away, blocked flag cleared, reserve OK.
    let snap = adm.reconcile_now().unwrap();
    assert_eq!(snap.live, 0);
    assert_eq!(snap.suspected_orphans, 0);
    assert!(!snap.host_blocked);
    assert_eq!(read_raw(tmp.path()).leases.len(), 0);

    let _l = adm
        .reserve(VmKind::Install, None)
        .expect("reserve on new boot");
}

#[test]
fn host_blocked_flag_refuses_without_capacity() {
    let tmp = tempfile::tempdir().unwrap();
    let mut alive = HashSet::new();
    alive.insert(current_pid());
    let adm = test_admission(tmp.path(), "boot-A", alive);

    // No leases yet, but the host was reactively flagged blocked.
    adm.mark_host_blocked().unwrap();

    let err = adm.reserve(VmKind::Install, None).unwrap_err();
    match err {
        AdmissionError::HostVmLimitReached { reason, live, .. } => {
            assert_eq!(reason, LimitReason::HostBlocked);
            assert_eq!(live, 0);
        }
        AdmissionError::Registry(e) => panic!("expected HostBlocked, got Registry({e})"),
    }

    // Clearing the flag re-enables reservations.
    adm.clear_host_blocked().unwrap();
    let _l = adm
        .reserve(VmKind::Install, None)
        .expect("reserve after clear");
}

#[test]
fn dropped_lease_without_release_is_retained_failclosed() {
    let tmp = tempfile::tempdir().unwrap();
    let mut alive = HashSet::new();
    alive.insert(current_pid());
    let adm = test_admission(tmp.path(), "boot-A", alive);

    {
        let _l = adm.reserve(VmKind::Install, None).expect("reserve");
        // dropped here WITHOUT release_clean
    }
    // Record retained (fail-closed): the lease still counts.
    assert_eq!(read_raw(tmp.path()).leases.len(), 1);
}

#[test]
fn panicking_owner_retains_lease_failclosed() {
    let tmp = tempfile::tempdir().unwrap();
    let mut alive = HashSet::new();
    alive.insert(current_pid());
    let adm = test_admission(tmp.path(), "boot-A", alive);

    // A panic while holding a lease (e.g. `boot_warm_pool_vm` panicking mid-boot)
    // must NOT become a clean release: a panic skips the explicit
    // `release_clean`, so `VmLease::drop` runs and RETAINS the registry record.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _lease = adm.reserve(VmKind::WarmPool, None).expect("reserve");
        panic!("simulated boot panic while holding the lease");
    }));
    assert!(result.is_err(), "the closure must have panicked");

    // Fail-closed: the lease record is retained (not removed) — the slot keeps
    // counting until the owner dies and reboot clears it.
    assert_eq!(
        read_raw(tmp.path()).leases.len(),
        1,
        "a panic must retain the lease record (fail-closed), not clean-release it"
    );
}

#[test]
fn corrupt_registry_is_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    // Write a non-JSON blob into the registry.
    std::fs::write(
        tmp.path().join(REGISTRY_FILENAME),
        b"{ this is not valid json ]]",
    )
    .unwrap();

    let mut alive = HashSet::new();
    alive.insert(current_pid());
    let adm = test_admission(tmp.path(), "boot-A", alive);

    // A corrupt registry must NOT be silently reset — reserve fails closed.
    let err = adm.reserve(VmKind::Install, None).unwrap_err();
    match err {
        AdmissionError::Registry(msg) => assert!(msg.contains("corrupt"), "unexpected: {msg}"),
        AdmissionError::HostVmLimitReached { .. } => {
            panic!("corrupt registry must not be treated as free capacity")
        }
    }
    // The corrupt file is left intact (not silently overwritten).
    let raw = std::fs::read_to_string(tmp.path().join(REGISTRY_FILENAME)).unwrap();
    assert!(raw.contains("not valid json"));
}

#[test]
fn writes_are_atomic_via_rename() {
    // A successful reserve leaves a well-formed registry and no leftover temp file.
    let tmp = tempfile::tempdir().unwrap();
    let mut alive = HashSet::new();
    alive.insert(current_pid());
    let adm = test_admission(tmp.path(), "boot-A", alive);

    let lease = adm.reserve(VmKind::Install, None).expect("reserve");
    // Registry parses cleanly.
    let _ = read_raw(tmp.path());
    // No stray temp files remain in the directory.
    let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "temp file left behind: {leftovers:?}");
    lease.release_clean();
}

#[test]
fn release_clean_removes_record() {
    let tmp = tempfile::tempdir().unwrap();
    let mut alive = HashSet::new();
    alive.insert(current_pid());
    let adm = test_admission(tmp.path(), "boot-A", alive);

    let l = adm.reserve(VmKind::Install, None).expect("reserve");
    assert_eq!(read_raw(tmp.path()).leases.len(), 1);
    l.release_clean();
    assert_eq!(read_raw(tmp.path()).leases.len(), 0);
}

#[test]
fn mark_running_updates_record_state() {
    let tmp = tempfile::tempdir().unwrap();
    let mut alive = HashSet::new();
    alive.insert(current_pid());
    let adm = test_admission(tmp.path(), "boot-A", alive);

    let l = adm
        .reserve(VmKind::UserClaw, Some("inst-a".into()))
        .unwrap();
    assert_eq!(read_raw(tmp.path()).leases[0].state, LeaseState::Starting);
    l.mark_running();
    assert_eq!(read_raw(tmp.path()).leases[0].state, LeaseState::Running);
    l.release_clean();
}

// ── helpers for the pure-logic / persistence tests below ──────────────────

fn liveness_from(alive: &[i32]) -> Liveness {
    let set: HashSet<i32> = alive.iter().copied().collect();
    Arc::new(move |pid| set.contains(&pid))
}

fn rec(lease_id: &str, owner_pid: i32, boot_id: &str) -> VmLeaseRecord {
    VmLeaseRecord {
        lease_id: lease_id.into(),
        owner_pid,
        boot_id: boot_id.into(),
        kind: VmKind::Install,
        instance_id: None,
        started_at: 1,
        state: LeaseState::Running,
    }
}

fn write_registry_file(dir: &Path, reg: &Registry) {
    std::fs::write(
        dir.join(REGISTRY_FILENAME),
        serde_json::to_string_pretty(reg).unwrap(),
    )
    .unwrap();
}

// ── FileGuard read/write I/O paths ────────────────────────────────────────

#[test]
fn file_guard_read_missing_registry_is_default() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(REGISTRY_FILENAME);
    let guard = FileGuard::lock_exclusive(&path).expect("lock");
    let reg = guard.read_registry().expect("read missing");
    assert!(reg.leases.is_empty());
    assert!(reg.blocked_boot_id.is_none());
}

#[test]
fn file_guard_read_empty_and_whitespace_are_default() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(REGISTRY_FILENAME);
    for blob in ["", "   \n\t  "] {
        std::fs::write(&path, blob).unwrap();
        let guard = FileGuard::lock_exclusive(&path).expect("lock");
        let reg = guard.read_registry().expect("read blank");
        assert!(
            reg.leases.is_empty(),
            "blob {blob:?} should decode to default"
        );
    }
}

#[test]
fn file_guard_read_invalid_json_is_corrupt_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(REGISTRY_FILENAME);
    std::fs::write(&path, b"{ not json ]]").unwrap();
    let guard = FileGuard::lock_exclusive(&path).expect("lock");
    let err = guard.read_registry().unwrap_err();
    match err {
        AdmissionError::Registry(msg) => assert!(msg.contains("corrupt"), "got {msg}"),
        AdmissionError::HostVmLimitReached { .. } => {
            panic!("a corrupt registry must surface as a Registry error, not a limit error")
        }
    }
}

#[test]
fn file_guard_write_then_read_roundtrips_under_one_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(REGISTRY_FILENAME);
    let reg = Registry {
        version: 1,
        blocked_boot_id: Some("boot-A".into()),
        leases: vec![rec("a", 10, "boot-A"), rec("b", 11, "boot-A")],
    };
    let guard = FileGuard::lock_exclusive(&path).expect("lock");
    guard.write_registry(&reg).expect("write");
    let back = guard.read_registry().expect("read back");
    assert_eq!(back.blocked_boot_id.as_deref(), Some("boot-A"));
    let ids: Vec<_> = back.leases.iter().map(|l| l.lease_id.clone()).collect();
    assert_eq!(ids, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn file_guard_write_is_atomic_and_locks_a_sidecar() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(REGISTRY_FILENAME);
    {
        let guard = FileGuard::lock_exclusive(&path).expect("lock");
        guard.write_registry(&Registry::default()).expect("write");
    }
    // The advisory lock lives on a `.lock` sidecar, not the data file.
    assert!(
        path.with_extension("lock").exists(),
        "sidecar lock must exist"
    );
    // No leftover temp files from the atomic temp+rename.
    let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "temp left behind: {leftovers:?}");
}

// ── reconcile / count / snapshot pure helpers ─────────────────────────────

#[test]
fn reconcile_drops_other_boot_keeps_same_boot_and_reports_change() {
    let liveness = liveness_from(&[10]);
    let mut reg = Registry {
        version: 1,
        blocked_boot_id: None,
        leases: vec![rec("keep", 10, "boot-A"), rec("drop", 10, "boot-OLD")],
    };
    assert!(reconcile(&mut reg, "boot-A", &liveness));
    let ids: Vec<_> = reg.leases.iter().map(|l| l.lease_id.clone()).collect();
    assert_eq!(ids, vec!["keep".to_string()]);
    // Second pass: nothing left to change → not changed (idempotent).
    assert!(!reconcile(&mut reg, "boot-A", &liveness));
}

#[test]
fn reconcile_clears_blocked_flag_from_other_boot_only() {
    let liveness = liveness_from(&[]);
    let mut reg = Registry {
        version: 1,
        blocked_boot_id: Some("boot-OLD".into()),
        leases: vec![],
    };
    assert!(reconcile(&mut reg, "boot-A", &liveness));
    assert!(reg.blocked_boot_id.is_none());
    // A current-boot block is preserved (no change).
    reg.blocked_boot_id = Some("boot-A".into());
    assert!(!reconcile(&mut reg, "boot-A", &liveness));
    assert_eq!(reg.blocked_boot_id.as_deref(), Some("boot-A"));
}

#[test]
fn count_splits_live_and_orphans_ignoring_other_boots() {
    let liveness = liveness_from(&[10]); // pid 10 alive, 11 dead
    let reg = Registry {
        version: 1,
        blocked_boot_id: None,
        leases: vec![
            rec("live", 10, "boot-A"),
            rec("orphan", 11, "boot-A"),
            rec("elsewhere", 10, "boot-OLD"),
        ],
    };
    assert_eq!(count(&reg, "boot-A", &liveness), (1, 1));
}

#[test]
fn snapshot_available_saturates_at_zero_when_overcapacity() {
    let liveness = liveness_from(&[10]);
    // One more live lease than the host limit allows.
    let leases = (0..=MACOS_VM_LIMIT)
        .map(|i| rec(&format!("l{i}"), 10, "boot-A"))
        .collect();
    let reg = Registry {
        version: 1,
        blocked_boot_id: None,
        leases,
    };
    let snap = snapshot(&reg, "boot-A", &liveness);
    assert_eq!(snap.live, MACOS_VM_LIMIT + 1);
    assert_eq!(
        snap.available, 0,
        "available must floor at 0, never underflow"
    );
    assert!(!snap.host_blocked);
}

#[test]
fn snapshot_reports_host_blocked_only_for_current_boot() {
    let liveness = liveness_from(&[]);
    let mut reg = Registry {
        version: 1,
        blocked_boot_id: Some("boot-A".into()),
        leases: vec![],
    };
    assert!(snapshot(&reg, "boot-A", &liveness).host_blocked);
    reg.blocked_boot_id = Some("boot-OTHER".into());
    assert!(!snapshot(&reg, "boot-A", &liveness).host_blocked);
}

// ── set_lease_state / remove_lease persistence helpers ────────────────────

#[test]
fn set_lease_state_updates_known_and_noops_unknown() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(REGISTRY_FILENAME);
    write_registry_file(
        tmp.path(),
        &Registry {
            version: 1,
            blocked_boot_id: None,
            leases: vec![rec("known", 10, "boot-A")],
        },
    );
    // Unknown id: Ok, no mutation.
    set_lease_state(&path, "nope", LeaseState::Stopping).expect("noop ok");
    assert_eq!(read_raw(tmp.path()).leases[0].state, LeaseState::Running);
    // Known id: state updated and persisted.
    set_lease_state(&path, "known", LeaseState::Stopping).expect("update ok");
    assert_eq!(read_raw(tmp.path()).leases[0].state, LeaseState::Stopping);
}

#[test]
fn remove_lease_removes_known_and_noops_unknown() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(REGISTRY_FILENAME);
    write_registry_file(
        tmp.path(),
        &Registry {
            version: 1,
            blocked_boot_id: None,
            leases: vec![rec("a", 10, "boot-A"), rec("b", 11, "boot-A")],
        },
    );
    remove_lease(&path, "missing").expect("noop ok");
    assert_eq!(read_raw(tmp.path()).leases.len(), 2);
    remove_lease(&path, "a").expect("remove ok");
    let ids: Vec<_> = read_raw(tmp.path())
        .leases
        .iter()
        .map(|l| l.lease_id.clone())
        .collect();
    assert_eq!(ids, vec!["b".to_string()]);
}

// ── pid_alive_real errno edges ────────────────────────────────────────────

#[test]
fn pid_alive_real_handles_nonpositive_self_and_dead() {
    assert!(!pid_alive_real(0), "pid 0 is not a real process to probe");
    assert!(!pid_alive_real(-1), "negative pid is rejected");
    assert!(pid_alive_real(current_pid()), "this test process is alive");
    // launchd (pid 1) always exists; kill(1, 0) returns 0 (root) or EPERM
    // (non-root) — both map to alive.
    assert!(pid_alive_real(1), "pid 1 (launchd) must read as alive");
    // Above macOS PID_MAX (~99998), so reliably absent → ESRCH → dead.
    assert!(!pid_alive_real(999_999), "an impossible pid reads as dead");
}
