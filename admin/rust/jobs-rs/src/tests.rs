#![cfg(test)]

use super::*;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

fn temp_db() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ts = core_rs::time::unix_now_nanos();
    let path = format!("/tmp/jobs_rs_test_{ts}_{n}.db");
    let _ = std::fs::remove_file(&path);
    path
}

fn make_job() -> Job {
    Job::new(
        JobType::CreateInstance,
        "inst-test",
        r#"{"name":"test","clawType":"picoclaw","port":0}"#,
    )
}

#[test]
fn store_new_creates_table() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");
    // If the table was created we can query it without error.
    let jobs = s.list_pending(0).expect("list_pending on fresh db");
    assert!(jobs.is_empty());
}

#[test]
fn create_sets_pending_status() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");
    let mut job = make_job();
    s.create(&mut job).expect("create");
    assert_eq!(job.status, Status::Pending);
}

#[test]
fn create_auto_generates_id() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");
    let mut job = make_job();
    job.id = String::new(); // force auto-generation
    s.create(&mut job).expect("create");
    assert!(!job.id.is_empty(), "ID should be auto-generated");
}

#[test]
fn create_preserves_provided_id() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");
    let mut job = make_job();
    job.id = "job_fixed_id_xyz".to_string();
    s.create(&mut job).expect("create");
    let got = s.get("job_fixed_id_xyz").expect("get");
    assert_eq!(got.id, "job_fixed_id_xyz");
}

#[test]
fn get_returns_created_job() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");
    let mut job = make_job();
    s.create(&mut job).expect("create");
    let got = s.get(&job.id).expect("get");
    assert_eq!(got.id, job.id);
    assert_eq!(got.instance_id, "inst-test");
    assert_eq!(got.status, Status::Pending);
}

#[test]
fn get_missing_errors() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");
    let result = s.get("nonexistent_id");
    assert!(
        matches!(result, Err(JobError::NotFound(_))),
        "expected NotFound, got {result:?}"
    );
}

#[test]
fn update_changes_status() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");
    let mut job = make_job();
    s.create(&mut job).expect("create");
    job.status = Status::Completed;
    job.completed_at = Some(now_iso());
    s.update(&job).expect("update");
    let got = s.get(&job.id).expect("get after update");
    assert_eq!(got.status, Status::Completed);
}

#[test]
fn claim_returns_none_when_empty() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");
    let result = s.claim_next_pending().expect("claim on empty");
    assert!(result.is_none(), "expected None on empty store");
}

#[test]
fn claim_sets_running() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");
    let mut job = make_job();
    s.create(&mut job).expect("create");
    let claimed = s.claim_next_pending().expect("claim").expect("some job");
    assert_eq!(claimed.status, Status::Running);
    assert!(claimed.started_at.is_some(), "started_at must be set");
    assert_eq!(claimed.message.as_deref(), Some("Processing..."));
}

#[test]
fn claim_oldest_first() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");

    let mut old = Job {
        id: "old_job".to_string(),
        job_type: JobType::CreateInstance,
        status: Status::Pending,
        instance_id: "inst-old".to_string(),
        payload: "{}".to_string(),
        result: None,
        error: None,
        message: None,
        actor: None,
        created_at: "2020-01-01T00:00:00Z".to_string(),
        started_at: None,
        completed_at: None,
        retries: 0,
    };
    let mut new = Job {
        id: "new_job".to_string(),
        job_type: JobType::CreateInstance,
        status: Status::Pending,
        instance_id: "inst-new".to_string(),
        payload: "{}".to_string(),
        result: None,
        error: None,
        message: None,
        actor: None,
        created_at: "2025-01-01T00:00:00Z".to_string(),
        started_at: None,
        completed_at: None,
        retries: 0,
    };
    s.create(&mut old).expect("create old");
    s.create(&mut new).expect("create new");

    let claimed = s.claim_next_pending().expect("claim").expect("some job");
    assert_eq!(
        claimed.instance_id, "inst-old",
        "should claim oldest job first"
    );
}

#[test]
fn claim_skips_non_pending() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");

    // Create a job and mark it running manually
    let mut running = make_job();
    running.instance_id = "inst-running".to_string();
    s.create(&mut running).expect("create running");
    running.status = Status::Running;
    running.started_at = Some(now_iso());
    s.update(&running).expect("update to running");

    // Create a pending job
    let mut pending = make_job();
    pending.instance_id = "inst-pending".to_string();
    s.create(&mut pending).expect("create pending");

    let claimed = s.claim_next_pending().expect("claim").expect("some job");
    assert_eq!(claimed.instance_id, "inst-pending");
}

#[test]
fn claim_concurrent_no_duplicates() {
    // 10 threads racing to claim 1 job → exactly 1 or 0 claims
    // (0 is acceptable if a race causes an error, but duplicates are not)
    let path = temp_db();
    let store = Arc::new(Store::new(&path).expect("Store::new"));

    let mut job = make_job();
    store.create(&mut job).expect("create");

    let claimed = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let mut handles = vec![];
    for _ in 0..10 {
        let s = Arc::clone(&store);
        let c = Arc::clone(&claimed);
        handles.push(std::thread::spawn(move || {
            if let Ok(Some(_)) = s.claim_next_pending() {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let n = claimed.load(std::sync::atomic::Ordering::SeqCst);
    assert!(n <= 1, "expected at most 1 claim, got {n}");
}

#[test]
fn list_pending_sorted_oldest_first() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");

    for (instance_id, ts) in [
        ("inst-mid", "2023-06-01T00:00:00Z"),
        ("inst-old", "2020-01-01T00:00:00Z"),
        ("inst-new", "2025-01-01T00:00:00Z"),
    ] {
        let mut job = Job {
            id: generate_id(),
            job_type: JobType::CreateInstance,
            status: Status::Pending,
            instance_id: instance_id.to_string(),
            payload: "{}".to_string(),
            result: None,
            error: None,
            message: None,
            actor: None,
            created_at: ts.to_string(),
            started_at: None,
            completed_at: None,
            retries: 0,
        };
        s.create(&mut job).expect("create");
    }

    let pending = s.list_pending(0).expect("list_pending");
    assert_eq!(pending.len(), 3);
    assert_eq!(pending[0].instance_id, "inst-old");
    assert_eq!(pending[1].instance_id, "inst-mid");
    assert_eq!(pending[2].instance_id, "inst-new");
}

#[test]
fn list_pending_excludes_running() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");

    let mut running = make_job();
    running.instance_id = "inst-running".to_string();
    s.create(&mut running).expect("create");
    running.status = Status::Running;
    running.started_at = Some(now_iso());
    s.update(&running).expect("update");

    let mut pending = make_job();
    pending.instance_id = "inst-pending".to_string();
    s.create(&mut pending).expect("create");

    let list = s.list_pending(0).expect("list_pending");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].instance_id, "inst-pending");
}

#[test]
fn generate_id_produces_unique_ids() {
    let n = 200;
    let ids: std::collections::HashSet<String> = (0..n).map(|_| generate_id()).collect();
    assert_eq!(ids.len(), n, "all generated IDs must be unique");
}

#[test]
fn now_iso_format_looks_correct() {
    let iso = now_iso();
    // e.g. "2026-02-25T12:34:56Z"
    assert_eq!(iso.len(), 20, "ISO string length = {iso}");
    assert!(iso.ends_with('Z'), "must end with Z: {iso}");
    assert!(iso.contains('T'), "must contain T: {iso}");
}

#[test]
fn install_claw_job_type_roundtrip() {
    assert_eq!(JobType::InstallClaw.as_str(), "install_claw");
    assert_eq!(JobType::from_str("install_claw"), JobType::InstallClaw);
}

#[test]
fn uninstall_claw_job_type_roundtrip() {
    assert_eq!(JobType::UninstallClaw.as_str(), "uninstall_claw");
    assert_eq!(JobType::from_str("uninstall_claw"), JobType::UninstallClaw);
}

#[test]
fn claim_by_types_filters_correctly() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");

    // Create one instance job and one install job
    let mut inst_job = make_job(); // CreateInstance
    inst_job.instance_id = "inst-a".to_string();
    s.create(&mut inst_job).expect("create");

    let mut install_job = Job::new(JobType::InstallClaw, "picoclaw", "{}");
    s.create(&mut install_job).expect("create");

    // claim_by_types with install_claw should only get the install job
    let claimed = s
        .claim_next_pending_by_types(&["install_claw"])
        .expect("claim")
        .expect("should find install job");
    assert_eq!(claimed.job_type, JobType::InstallClaw);
    assert_eq!(claimed.instance_id, "picoclaw");

    // The instance job should still be pending
    let pending = s.list_pending(0).expect("list");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].instance_id, "inst-a");
}

#[test]
fn claim_excluding_filters_correctly() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");

    // Create one install job and one instance job
    let mut install_job = Job::new(JobType::InstallClaw, "picoclaw", "{}");
    install_job.created_at = "2020-01-01T00:00:00Z".to_string();
    s.create(&mut install_job).expect("create");

    let mut inst_job = make_job(); // CreateInstance
    inst_job.instance_id = "inst-a".to_string();
    inst_job.created_at = "2025-01-01T00:00:00Z".to_string();
    s.create(&mut inst_job).expect("create");

    // claim_excluding install types should skip the install job
    let claimed = s
        .claim_next_pending_excluding(&["install_claw", "uninstall_claw"])
        .expect("claim")
        .expect("should find instance job");
    assert_eq!(claimed.job_type, JobType::CreateInstance);
    assert_eq!(claimed.instance_id, "inst-a");

    // The install job should still be pending
    let pending = s.list_pending(0).expect("list");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].job_type, JobType::InstallClaw);
}

#[test]
fn update_result_overwrites_only_result_column() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");
    let mut job = Job::new(JobType::InstallClaw, "picoclaw", "{}");
    s.create(&mut job).expect("create");
    let job_id = job.id.clone();

    // First write
    s.update_result(&job_id, r#"{"phase":"downloading","percent":25}"#)
        .expect("update_result");
    let got = s.get(&job_id).expect("get");
    assert_eq!(
        got.result.as_deref(),
        Some(r#"{"phase":"downloading","percent":25}"#)
    );
    // Status must be unchanged
    assert_eq!(got.status, Status::Pending);

    // Overwrite
    s.update_result(&job_id, r#"{"phase":"downloading","percent":75}"#)
        .expect("update_result");
    let got = s.get(&job_id).expect("get");
    assert_eq!(
        got.result.as_deref(),
        Some(r#"{"phase":"downloading","percent":75}"#)
    );
}

#[test]
fn update_result_returns_not_found_for_missing_job() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");
    let err = s
        .update_result("does-not-exist", "{}")
        .expect_err("should be NotFound");
    matches!(err, JobError::NotFound(_));
}

#[test]
fn delete_by_id_removes_created_job() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");
    let mut job = make_job();
    s.create(&mut job).expect("create");
    s.delete_by_id(&job.id).expect("delete");
    assert!(
        matches!(s.get(&job.id), Err(JobError::NotFound(_))),
        "job should be gone after delete_by_id"
    );
}

#[test]
fn delete_by_id_returns_not_found_for_missing_job() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");
    let err = s
        .delete_by_id("does-not-exist")
        .expect_err("should be NotFound");
    assert!(
        matches!(err, JobError::NotFound(_)),
        "expected NotFound, got {err:?}"
    );
}

#[test]
fn reset_stale_install_jobs_covers_install_and_uninstall_pending_and_running() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");

    // install_claw / pending
    let mut j1 = Job::new(JobType::InstallClaw, "picoclaw", "{}");
    s.create(&mut j1).expect("create");

    // install_claw / running
    let mut j2 = Job::new(JobType::InstallClaw, "zeroclaw", "{}");
    s.create(&mut j2).expect("create");
    j2.status = Status::Running;
    j2.started_at = Some(now_iso());
    s.update(&j2).expect("update");

    // uninstall_claw / pending
    let mut j3 = Job::new(JobType::UninstallClaw, "nanobot", "{}");
    s.create(&mut j3).expect("create");

    // uninstall_claw / running
    let mut j4 = Job::new(JobType::UninstallClaw, "openclaw", "{}");
    s.create(&mut j4).expect("create");
    j4.status = Status::Running;
    j4.started_at = Some(now_iso());
    s.update(&j4).expect("update");

    // create_instance / running — must NOT be touched
    let mut j5 = make_job();
    j5.instance_id = "inst-untouched".to_string();
    s.create(&mut j5).expect("create");
    j5.status = Status::Running;
    j5.started_at = Some(now_iso());
    s.update(&j5).expect("update");

    let reset = s.reset_stale_install_jobs().expect("reset");
    assert_eq!(reset, 4, "should reset all 4 install/uninstall jobs");

    // All four install/uninstall jobs now Failed
    for (id, _) in [
        (j1.id.as_str(), "j1"),
        (j2.id.as_str(), "j2"),
        (j3.id.as_str(), "j3"),
        (j4.id.as_str(), "j4"),
    ] {
        let got = s.get(id).expect("get");
        assert_eq!(got.status, Status::Failed);
        assert!(got.error.is_some());
        assert_eq!(got.result, None, "result must be cleared on reset");
        assert!(got.completed_at.is_some());
    }

    // create_instance untouched
    let got_inst = s.get(&j5.id).expect("get");
    assert_eq!(got_inst.status, Status::Running);
    assert!(got_inst.error.is_none());
}

#[test]
fn reset_stale_install_jobs_leaves_already_completed_alone() {
    let path = temp_db();
    let s = Store::new(&path).expect("Store::new");

    let mut j = Job::new(JobType::InstallClaw, "picoclaw", "{}");
    s.create(&mut j).expect("create");
    j.status = Status::Completed;
    j.completed_at = Some(now_iso());
    j.result = Some(r#"{"ok":true}"#.to_string());
    s.update(&j).expect("update");

    let reset = s.reset_stale_install_jobs().expect("reset");
    assert_eq!(reset, 0);

    let got = s.get(&j.id).expect("get");
    assert_eq!(got.status, Status::Completed);
    assert_eq!(got.result.as_deref(), Some(r#"{"ok":true}"#));
}
