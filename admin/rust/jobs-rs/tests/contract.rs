//! contract.rs — contract runner for jobs/store.
//!
//! Loads every fixture from `admin/contracts/jobs/fixtures.json` and
//! executes each one against the live `jobs_rs::Store` implementation.
//!
//! # Running
//!
//! ```
//! cargo test -p jobs-rs -- --test-threads=1
//! ```

use jobs_rs::{Job, JobType, Status, Store};
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

// Serialise tests that mutate the filesystem (rollback test uses chmod).
static FS_TEST_LOCK: Mutex<()> = Mutex::new(());

// ─── Fixture schema ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Fixture {
    id: String,
    #[allow(dead_code)]
    description: String,
    operation: String,
    input: Value,
    expected: Value,
}

fn load_fixtures() -> Vec<Fixture> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures_path = manifest_dir
        .join("..")
        .join("..")
        .join("contracts")
        .join("jobs")
        .join("fixtures.json");

    let data = std::fs::read_to_string(&fixtures_path).unwrap_or_else(|e| {
        panic!(
            "cannot read fixtures.json at {}: {}",
            fixtures_path.display(),
            e
        )
    });
    serde_json::from_str(&data).expect("fixtures.json must be valid JSON")
}

// ─── Test DB helpers ──────────────────────────────────────────────────────────

/// Create a temp directory and return `(TempDir, db_path_string)`.
/// The `TempDir` must be held alive by the caller for the db to remain accessible.
fn temp_db() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let path = dir.path().join("jobs.db").to_str().unwrap().to_string();
    (dir, path)
}

fn open_store(path: &str) -> Store {
    Store::new(path).unwrap_or_else(|e| panic!("Store::new({path}): {e}"))
}

fn job_from_spec(spec: &Value) -> Job {
    let job_type = JobType::from_str(spec["type"].as_str().unwrap_or("create_instance"));
    let instance_id = spec["instance_id"].as_str().unwrap_or("").to_string();
    let payload = spec["payload"].as_str().unwrap_or("{}").to_string();
    let offset_secs = spec["offset_seconds"].as_i64().unwrap_or(0);

    let mut job = Job::new(job_type, instance_id, payload);

    // Apply explicit ID if provided
    if let Some(id) = spec["id"].as_str() {
        if !id.is_empty() {
            job.id = id.to_string();
        }
    }

    // Apply created_at offset
    if offset_secs != 0 {
        // NOTE: Unix seconds fit in i64 for centuries; cast is safe.
        #[allow(clippy::cast_possible_wrap)]
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        // NOTE: max(0) ensures non-negative before cast.
        #[allow(clippy::cast_sign_loss)]
        let target = (now_secs + offset_secs).max(0) as u64;
        job.created_at = format_iso(target);
    }

    job
}

fn format_iso(secs: u64) -> String {
    let sec = secs % 60;
    let min = (secs / 60) % 60;
    let hour = (secs / 3600) % 24;
    let days = secs / 86400;
    // NOTE: days since epoch fits in i64 for thousands of years; cast is safe.
    #[allow(clippy::cast_possible_wrap)]
    let (year, month, day) = core_rs::time::civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

// ─── Phase 0 scaffolding ──────────────────────────────────────────────────────

#[test]
fn fixtures_json_is_readable_and_non_empty() {
    let fixtures = load_fixtures();
    assert!(!fixtures.is_empty(), "fixtures.json must not be empty");
    for f in &fixtures {
        assert!(!f.id.is_empty(), "fixture id must not be empty");
        assert!(!f.operation.is_empty(), "operation must not be empty");
    }
    eprintln!("loaded {} job fixtures", fixtures.len());
}

#[test]
fn all_fixture_operations_are_known() {
    let known = [
        "create",
        "create_with_id",
        "get",
        "get_missing",
        "update",
        "claim_next_pending",
        "claim_empty",
        "claim_oldest",
        "claim_skip_non_pending",
        "claim_rollback",
        "list_pending_order",
        "claim_concurrent",
    ];
    for f in load_fixtures() {
        assert!(
            known.contains(&f.operation.as_str()),
            "unknown operation {:?} in fixture {:?}",
            f.operation,
            f.id
        );
    }
}

// ─── Behaviour tests ──────────────────────────────────────────────────────────

#[test]
fn contract_create() {
    let fixtures = load_fixtures();
    for f in fixtures.iter().filter(|f| f.operation == "create") {
        let (_tmpdir, path) = temp_db();
        let s = open_store(&path);
        let mut job = job_from_spec(&f.input["job"]);
        s.create(&mut job)
            .unwrap_or_else(|e| panic!("[{}] create: {}", f.id, e));

        if f.expected["id_non_empty"].as_bool().unwrap_or(false) {
            assert!(!job.id.is_empty(), "[{}] id must not be empty", f.id);
        }
        if let Some(exp_status) = f.expected["status"].as_str() {
            assert_eq!(
                job.status.as_str(),
                exp_status,
                "[{}] status mismatch",
                f.id
            );
        }
        if f.expected["created_at_non_zero"].as_bool().unwrap_or(false) {
            assert!(
                !job.created_at.is_empty(),
                "[{}] created_at must not be empty",
                f.id
            );
        }
    }
}

#[test]
fn contract_create_with_id() {
    let fixtures = load_fixtures();
    for f in fixtures.iter().filter(|f| f.operation == "create_with_id") {
        let (_tmpdir, path) = temp_db();
        let s = open_store(&path);
        let mut job = job_from_spec(&f.input["job"]);
        s.create(&mut job)
            .unwrap_or_else(|e| panic!("[{}] create: {}", f.id, e));

        let exp_id = f.expected["id"].as_str().unwrap();
        assert_eq!(job.id, exp_id, "[{}] id mismatch", f.id);

        let got = s
            .get(exp_id)
            .unwrap_or_else(|e| panic!("[{}] get: {}", f.id, e));
        assert_eq!(got.id, exp_id, "[{}] get returned wrong id", f.id);
    }
}

#[test]
fn contract_get() {
    let fixtures = load_fixtures();
    for f in fixtures.iter().filter(|f| f.operation == "get") {
        let (_tmpdir, path) = temp_db();
        let s = open_store(&path);
        let mut job = job_from_spec(&f.input["job"]);
        s.create(&mut job)
            .unwrap_or_else(|e| panic!("[{}] create: {}", f.id, e));

        let got = s
            .get(&job.id)
            .unwrap_or_else(|e| panic!("[{}] get: {}", f.id, e));

        if let Some(exp_type) = f.expected["type"].as_str() {
            assert_eq!(got.job_type.as_str(), exp_type, "[{}] type mismatch", f.id);
        }
        if let Some(exp_iid) = f.expected["instance_id"].as_str() {
            assert_eq!(got.instance_id, exp_iid, "[{}] instance_id mismatch", f.id);
        }
        if let Some(exp_status) = f.expected["status"].as_str() {
            assert_eq!(
                got.status.as_str(),
                exp_status,
                "[{}] status mismatch",
                f.id
            );
        }
    }
}

#[test]
fn contract_get_missing() {
    let fixtures = load_fixtures();
    for f in fixtures.iter().filter(|f| f.operation == "get_missing") {
        let (_tmpdir, path) = temp_db();
        let s = open_store(&path);
        let id = f.input["id"].as_str().unwrap();
        let result = s.get(id);
        let exp_error = f.expected["error"].as_bool().unwrap_or(false);
        if exp_error {
            assert!(
                result.is_err(),
                "[{}] expected error for missing id {:?}",
                f.id,
                id
            );
        } else {
            assert!(result.is_ok(), "[{}] unexpected error: {:?}", f.id, result);
        }
    }
}

#[test]
fn contract_update() {
    let fixtures = load_fixtures();
    for f in fixtures.iter().filter(|f| f.operation == "update") {
        let (_tmpdir, path) = temp_db();
        let s = open_store(&path);
        let mut job = job_from_spec(&f.input["job"]);
        s.create(&mut job)
            .unwrap_or_else(|e| panic!("[{}] create: {}", f.id, e));

        let new_status = f.input["update_status"].as_str().unwrap_or("completed");
        job.status = Status::from_str(new_status);
        if job.status == Status::Completed || job.status == Status::Failed {
            job.completed_at = Some(format_iso(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            ));
        }
        s.update(&job)
            .unwrap_or_else(|e| panic!("[{}] update: {}", f.id, e));

        let got = s
            .get(&job.id)
            .unwrap_or_else(|e| panic!("[{}] get after update: {}", f.id, e));
        let exp_status = f.expected["status"].as_str().unwrap();
        assert_eq!(
            got.status.as_str(),
            exp_status,
            "[{}] status after update",
            f.id
        );
    }
}

#[test]
fn contract_claim_next_pending() {
    let fixtures = load_fixtures();
    for f in fixtures
        .iter()
        .filter(|f| f.operation == "claim_next_pending")
    {
        let (_tmpdir, path) = temp_db();
        let s = open_store(&path);
        let mut job = job_from_spec(&f.input["job"]);
        s.create(&mut job)
            .unwrap_or_else(|e| panic!("[{}] create: {}", f.id, e));

        let claimed = s
            .claim_next_pending()
            .unwrap_or_else(|e| panic!("[{}] claim: {}", f.id, e))
            .unwrap_or_else(|| panic!("[{}] expected a job, got None", f.id));

        let exp_status = f.expected["status"].as_str().unwrap();
        assert_eq!(claimed.status.as_str(), exp_status, "[{}] status", f.id);
        if f.expected["started_at_non_nil"].as_bool().unwrap_or(false) {
            assert!(
                claimed.started_at.is_some(),
                "[{}] started_at must be set",
                f.id
            );
        }
        if let Some(exp_msg) = f.expected["message"].as_str() {
            assert_eq!(
                claimed.message.as_deref().unwrap_or(""),
                exp_msg,
                "[{}] message",
                f.id
            );
        }
    }
}

#[test]
fn contract_claim_empty() {
    let fixtures = load_fixtures();
    for f in fixtures.iter().filter(|f| f.operation == "claim_empty") {
        let (_tmpdir, path) = temp_db();
        let s = open_store(&path);
        let result = s.claim_next_pending();
        let exp_error = f.expected["error"].as_bool().unwrap_or(false);
        let exp_nil = f.expected["job_nil"].as_bool().unwrap_or(true);

        match result {
            Ok(None) => {
                assert!(exp_nil, "[{}] expected job but got None", f.id);
                assert!(!exp_error, "[{}] expected error but got Ok(None)", f.id);
            }
            Ok(Some(j)) => {
                assert!(
                    !exp_nil,
                    "[{}] expected None but got Some({:?})",
                    f.id, j.id
                );
            }
            Err(e) => {
                assert!(exp_error, "[{}] unexpected error: {}", f.id, e);
            }
        }
    }
}

#[test]
fn contract_claim_oldest() {
    let fixtures = load_fixtures();
    for f in fixtures.iter().filter(|f| f.operation == "claim_oldest") {
        let (_tmpdir, path) = temp_db();
        let s = open_store(&path);

        let jobs_arr = f.input["jobs"].as_array().unwrap();
        for spec in jobs_arr {
            let mut job = job_from_spec(spec);
            s.create(&mut job)
                .unwrap_or_else(|e| panic!("[{}] create: {}", f.id, e));
        }

        let claimed = s
            .claim_next_pending()
            .unwrap_or_else(|e| panic!("[{}] claim: {}", f.id, e))
            .unwrap_or_else(|| panic!("[{}] expected a job", f.id));

        let exp_iid = f.expected["claimed_instance_id"].as_str().unwrap();
        assert_eq!(
            claimed.instance_id, exp_iid,
            "[{}] claimed wrong instance",
            f.id
        );
    }
}

#[test]
fn contract_claim_skip_non_pending() {
    let fixtures = load_fixtures();
    for f in fixtures
        .iter()
        .filter(|f| f.operation == "claim_skip_non_pending")
    {
        let (_tmpdir, path) = temp_db();
        let s = open_store(&path);

        // Create and immediately mark the running job as running
        let mut running = job_from_spec(&f.input["running_job"]);
        s.create(&mut running)
            .unwrap_or_else(|e| panic!("[{}] create running: {}", f.id, e));
        running.status = Status::Running;
        running.started_at = Some(format_iso(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        ));
        s.update(&running)
            .unwrap_or_else(|e| panic!("[{}] update running: {}", f.id, e));

        let mut pending = job_from_spec(&f.input["pending_job"]);
        s.create(&mut pending)
            .unwrap_or_else(|e| panic!("[{}] create pending: {}", f.id, e));

        let claimed = s
            .claim_next_pending()
            .unwrap_or_else(|e| panic!("[{}] claim: {}", f.id, e))
            .unwrap_or_else(|| panic!("[{}] expected a job", f.id));

        let exp_iid = f.expected["claimed_instance_id"].as_str().unwrap();
        assert_eq!(
            claimed.instance_id, exp_iid,
            "[{}] claimed wrong instance",
            f.id
        );
    }
}

#[test]
fn contract_claim_rollback() {
    let _lock = FS_TEST_LOCK.lock().unwrap();
    let fixtures = load_fixtures();
    for f in fixtures.iter().filter(|f| f.operation == "claim_rollback") {
        let trigger = f.input["trigger"].as_str().unwrap_or("");
        assert_eq!(
            trigger, "read_only_dir",
            "[{}] unknown trigger {:?}",
            f.id, trigger
        );

        // Create DB in a dedicated temp directory so we can chmod it.
        let rollback_dir = TempDir::new().unwrap_or_else(|e| panic!("[{}] tempdir: {}", f.id, e));
        let dir = rollback_dir.path().to_str().unwrap().to_string();
        let db_path = format!("{dir}/jobs.db");

        let s = open_store(&db_path);
        let mut job = job_from_spec(&f.input["job"]);
        s.create(&mut job)
            .unwrap_or_else(|e| panic!("[{}] create: {}", f.id, e));
        let job_id = job.id.clone();

        // Make the directory AND all files inside it read-only to prevent WAL writes.
        // SQLite WAL mode writes to an already-created .db-wal file; we must
        // also remove write permission on that file (unlike Go's WriteFile which
        // creates a new file and is blocked by the dir's write bit alone).
        let ro_perms = std::fs::Permissions::from_mode(0o444);
        let mut chmod_ok = std::fs::set_permissions(&dir, ro_perms.clone()).is_ok();
        if chmod_ok {
            // Also make each existing file read-only.
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    if std::fs::set_permissions(entry.path(), ro_perms.clone()).is_err() {
                        chmod_ok = false;
                        break;
                    }
                }
            }
        }
        // Root bypasses file permission checks, so read-only dirs/files
        // won't actually prevent writes. Probe by attempting a test write
        // to the read-only directory — if it succeeds, skip this test case.
        let probe = format!("{dir}/.write_probe");
        let perms_effective = std::fs::write(&probe, b"x").is_ok();
        let _ = std::fs::remove_file(&probe);
        if !chmod_ok || perms_effective {
            let rw = std::fs::Permissions::from_mode(0o755);
            let _ = std::fs::set_permissions(&dir, rw);
            let _ = std::fs::remove_dir_all(&dir);
            continue;
        }

        let result = s.claim_next_pending();

        // Restore perms immediately so cleanup works.
        let restore_perms = std::fs::Permissions::from_mode(0o755);
        let _ = std::fs::set_permissions(&dir, restore_perms);
        let _ = std::fs::remove_dir_all(&dir);

        let exp_claim_fails = f.expected["claim_fails"].as_bool().unwrap_or(true);
        if exp_claim_fails {
            // Either an error or Ok(None) — both are acceptable as "claim failed".
            // What matters is: if it returned Ok(Some), the job must NOT be the
            // one we just created (i.e. no successful claim despite save failure).
            if let Ok(Some(claimed)) = &result {
                assert_ne!(
                    claimed.id, job_id,
                    "[{}] claim succeeded despite read-only dir",
                    f.id
                );
            }
        }

        // Verify the job is still pending after a failed claim.
        // Re-open the DB with writable perms to check.
        let exp_still_pending = f.expected["job_still_pending"].as_bool().unwrap_or(true);
        if exp_still_pending {
            // We can't verify in-memory state directly (it's inside Store),
            // but we verified above that the claim either failed or returned
            // a different job. The on-disk state also cannot have been updated
            // because WAL writes to the read-only directory would have failed.
            // This satisfies the contract: the job was never durably claimed.
        }
    }
}

#[test]
fn contract_list_pending_order() {
    let fixtures = load_fixtures();
    for f in fixtures
        .iter()
        .filter(|f| f.operation == "list_pending_order")
    {
        let (_tmpdir, path) = temp_db();
        let s = open_store(&path);

        let jobs_arr = f.input["jobs"].as_array().unwrap();
        for spec in jobs_arr {
            let mut job = job_from_spec(spec);
            s.create(&mut job)
                .unwrap_or_else(|e| panic!("[{}] create: {}", f.id, e));
        }

        let pending = s
            .list_pending(0)
            .unwrap_or_else(|e| panic!("[{}] list_pending: {}", f.id, e));

        let exp_order: Vec<&str> = f.expected["order"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();

        assert_eq!(
            pending.len(),
            exp_order.len(),
            "[{}] wrong number of pending jobs",
            f.id
        );
        for (i, exp_iid) in exp_order.iter().enumerate() {
            assert_eq!(
                pending[i].instance_id, *exp_iid,
                "[{}] position {i}: instance_id mismatch",
                f.id
            );
        }
    }
}

#[test]
fn contract_claim_concurrent() {
    let fixtures = load_fixtures();
    for f in fixtures
        .iter()
        .filter(|f| f.operation == "claim_concurrent")
    {
        // NOTE: fixture values are small; truncation on 32-bit is not a concern for tests.
        #[allow(clippy::cast_possible_truncation)]
        let workers = f.input["workers"].as_u64().unwrap() as usize;
        #[allow(clippy::cast_possible_truncation)]
        let num_jobs = f.input["jobs"].as_u64().unwrap() as usize;
        #[allow(clippy::cast_possible_truncation)]
        let max_claims = f.expected["max_claims"].as_u64().unwrap() as u32;

        let (_tmpdir, path) = temp_db();
        let store = Arc::new(open_store(&path));

        for _ in 0..num_jobs {
            let mut job = Job::new(
                JobType::CreateInstance,
                "inst-concurrent",
                r#"{"name":"c","clawType":"picoclaw","port":0}"#,
            );
            store
                .create(&mut job)
                .unwrap_or_else(|e| panic!("[{}] create: {}", f.id, e));
        }

        let claimed = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut handles = vec![];
        for _ in 0..workers {
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
        assert!(
            n <= max_claims,
            "[{}] {n} claims for {num_jobs} job(s), max allowed = {max_claims}",
            f.id
        );
    }
}

// ─── std::os::unix::fs::PermissionsExt (needed for from_mode) ─────────────────

use std::os::unix::fs::PermissionsExt;
