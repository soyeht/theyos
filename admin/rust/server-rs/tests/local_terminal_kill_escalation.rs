//! E6 — TTY-wide kill escalation for broker-owned local PTY sessions.
//!
//! Before E6, `close_local` only sent `SIGKILL` to the single tracked child
//! pid. Ported from `soyeht-ios` PR #317's `NativePTY` technique:
//! `PtySession::close` now snapshots every pid attached to the session's
//! TTY and escalates `SIGHUP` (immediately) -> `SIGTERM` (after 2s, if
//! anything survived) -> `SIGKILL` (after another 2s, if still surviving).
//!
//! This test proves the brief's literal acceptance criterion: a child that
//! installs `SIG_IGN` for both `SIGHUP` and `SIGTERM` on purpose — so it can
//! only ever be brought down by `SIGKILL` — still dies within ~5s of
//! `close()`/`DELETE`. It necessarily takes several real seconds to run
//! (the escalation's own 2s/2s timers are not mocked).

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get};
use axum::{Router, body::Body};
use axum_test::TestServer;
use core_rs::env::set_test_env;
use executor_rs::{Executor, FlowConfig};
use jobs_rs::Store as JobsStore;
use server_rs::auth::AuthUser;
use server_rs::handlers_terminal::{
    handle_local_terminal_create, handle_local_terminal_delete, handle_local_terminal_list,
    handle_local_terminal_pty,
};
use server_rs::ratelimit::Limiter;
use server_rs::state::{AppState, SharedState};
use session_rs::SessionStore;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use store_rs::InstanceDb;
use terminal_rs::pty::PtyManager;
use vmrunner_rs::VmRunner;

fn fake_ipc_bin() -> String {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("fake-ipc.sh");
    std::fs::write(
        &path,
        b"#!/bin/sh\nwhile IFS= read -r _l; do printf '{\"ok\":true,\"result\":{}}\\n'; done\n",
    )
    .expect("write fake ipc");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake ipc");
    }
    std::mem::forget(dir);
    path.to_string_lossy().into_owned()
}

fn fixture() -> (Router, SharedState) {
    let sessions = SessionStore::open(":memory:").expect("session store");
    let jobs = JobsStore::new(":memory:").expect("jobs store");
    let instance_db = InstanceDb::open(":memory:").expect("instance db");
    let rate_limiter = Limiter::new(":memory:", 100).expect("rate limiter");

    let fake_bin = fake_ipc_bin();
    let flow_config = FlowConfig {
        vmrunner_bin: fake_bin.clone(),
        store_bin: fake_bin.clone(),
        terminal_bin: fake_bin.clone(),
        firecracker_state_dir: "/tmp".to_string(),
        firecracker_bin: "/tmp/fake-fc".to_string(),
        kernel_image: "/tmp/vmlinux".to_string(),
        base_rootfs: "/tmp/rootfs.ext4".to_string(),
        ssh_key: "/tmp/ssh_key".to_string(),
        ssh_pubkey: "/tmp/ssh_key.pub".to_string(),
        ssh_wait_tries: 1,
        store_db_path: ":memory:".to_string(),
    };
    let executor = Executor::new(flow_config).expect("fake executor");

    let conv_dir = tempfile::TempDir::new().expect("conv tempdir");
    let conv_path = conv_dir.path().to_path_buf();
    std::mem::forget(conv_dir);
    let pty_mgr = Arc::new(PtyManager::new("/nonexistent-ctl", conv_path));

    set_test_env("FIRECRACKER_STATE_DIR", "/tmp");
    set_test_env("FIRECRACKER_BIN", "/tmp/fc");
    set_test_env("FIRECRACKER_KERNEL_IMAGE", "/tmp/vmlinux");
    set_test_env("FIRECRACKER_BASE_ROOTFS", "/tmp/rootfs.ext4");
    set_test_env("FIRECRACKER_SSH_KEY", "/tmp/id_rsa");
    set_test_env("FIRECRACKER_SSH_PUBKEY", "/tmp/id_rsa.pub");
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open("/tmp/rootfs.ext4");
    let vm_runner = Arc::new(VmRunner::from_env().expect("vm runner"));

    let claw_dir = tempfile::TempDir::new().expect("claw tempdir");
    let claw_path = claw_dir.path().join("installed_claws.json");
    std::mem::forget(claw_dir);

    let state: SharedState = Arc::new(AppState {
        sessions,
        jobs,
        ver_cache: std::sync::RwLock::default(),
        instance_db,
        rate_limiter: Arc::new(rate_limiter),
        executor: Arc::new(Mutex::new(executor)),
        pty_mgr,
        vm_runner,
        mobile_tokens: Arc::new(server_rs::mobile_token::MobileTokenStore::new()),
        mobile_sessions: server_rs::mobile_token::MobileSessionDb::open(":memory:")
            .expect("mobile session db"),
        claw_store: claw_rs::ClawStore::new(&claw_path).expect("claw store"),
        theyos_dir: std::path::PathBuf::from("/tmp/theyos-test"),
        locks_dir: std::path::PathBuf::from("/tmp/theyos-test-locks"),
        capacity_lock: tokio::sync::Mutex::new(()),
        llm_proxy_client: server_rs::handlers_llm::ProxyClient::from_env(),
    });

    let auth = AuthUser {
        user_id: "user-alpha".to_string(),
        username: "user-alpha".to_string(),
        role: store_rs::UserRole::User,
    };
    let app = Router::new()
        .route(
            "/api/v1/terminals/local",
            get(handle_local_terminal_list).post(handle_local_terminal_create),
        )
        .route(
            "/api/v1/terminals/local/{conversation_id}/pty",
            get(handle_local_terminal_pty),
        )
        .route(
            "/api/v1/terminals/local/{conversation_id}",
            delete(handle_local_terminal_delete),
        )
        .layer(middleware::from_fn_with_state(auth, inject_auth))
        .with_state(state.clone());

    (app, state)
}

async fn inject_auth(State(user): State<AuthUser>, mut req: Request<Body>, next: Next) -> Response {
    req.extensions_mut().insert(user);
    next.run(req).await
}

fn python3_path() -> String {
    let out = std::process::Command::new("which")
        .arg("python3")
        .output()
        .expect("run which python3");
    assert!(out.status.success(), "python3 not found on PATH");
    String::from_utf8(out.stdout)
        .expect("which output is utf8")
        .trim()
        .to_string()
}

/// A child that ignores both SIGHUP and SIGTERM on purpose, so it can only
/// ever be brought down by SIGKILL — the scenario the brief's acceptance
/// criterion targets.
const IGNORE_HUP_AND_TERM_SCRIPT: &str = "import signal, time\n\
     signal.signal(signal.SIGHUP, signal.SIG_IGN)\n\
     signal.signal(signal.SIGTERM, signal.SIG_IGN)\n\
     time.sleep(60)\n";

/// `kill -0 <pid>`: true if a process with that pid exists (and we may
/// signal it) — checked out-of-process via the real `kill(1)` utility, not
/// a Rust dependency, since the spawned child is a real OS child of the
/// test binary either way.
fn pid_exists(pid: i64) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn wait_for_alive(state: &SharedState, conv_id: &str) {
    for _ in 0..200 {
        if let Some(sess) = state.pty_mgr.get_local(conv_id) {
            if !sess.is_closed() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("session {conv_id} never became alive");
}

#[tokio::test]
async fn child_ignoring_hup_and_term_still_dies_within_5s_of_close() {
    let (app, state) = fixture();
    let server = TestServer::builder()
        .http_transport()
        .build(app)
        .expect("test server");

    let conv_id = "conv-e6-stubborn";
    let create = server
        .post("/api/v1/terminals/local")
        .json(&serde_json::json!({
            "conversation_id": conv_id,
            "argv": [python3_path(), "-c", IGNORE_HUP_AND_TERM_SCRIPT],
            "cols": 80,
            "rows": 24,
        }))
        .await;
    assert_eq!(create.status_code(), StatusCode::OK, "{}", create.text());

    wait_for_alive(&state, conv_id).await;

    // Give the child a moment to install its signal handlers before we
    // start trying to kill it (otherwise the very first SIGHUP could land
    // before `signal.signal()` runs and use Python's default HUP
    // disposition — which terminates — defeating the point of the test).
    tokio::time::sleep(Duration::from_millis(300)).await;

    let list = server.get("/api/v1/terminals/local").await;
    assert_eq!(list.status_code(), StatusCode::OK);
    let list_json: serde_json::Value = list.json();
    let entry = list_json["data"]
        .as_array()
        .expect("data array")
        .iter()
        .find(|i| i["conversation_id"] == conv_id)
        .expect("session must be listed");
    let pgid = entry["pgid"].as_i64().expect("pgid must be an integer");
    assert!(pgid > 0, "pgid must be a real positive process group id");
    assert!(
        pid_exists(pgid),
        "precondition: the stubborn child must be alive before close"
    );

    let started = Instant::now();
    let del = server
        .delete(&format!("/api/v1/terminals/local/{conv_id}"))
        .await;
    assert_eq!(del.status_code(), StatusCode::NO_CONTENT);

    // Poll well past the 5s bound so a failure reports "still alive after
    // Nms" instead of just hanging silently on a broken escalation.
    let deadline = started + Duration::from_secs(8);
    while Instant::now() < deadline && pid_exists(pgid) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let elapsed = started.elapsed();

    assert!(
        !pid_exists(pgid),
        "child ignoring HUP/TERM must be dead by now (SIGKILL cannot be ignored), \
         still alive after {elapsed:?}"
    );
    assert!(
        elapsed <= Duration::from_secs(5),
        "brief's acceptance criterion: must die within <=5s of close, took {elapsed:?}"
    );
}

/// Forks a grandchild into a NEW process group (still on the same
/// controlling terminal — no `setsid()`), ignores HUP/TERM in it, and
/// writes its pid to `sys.argv[1]` once ready. This is exactly the shape
/// `list_tty_pids`/the individual-`tty_pids` escalation path exists for: a
/// process the session's direct child spawned, that ISN'T in the tracked
/// `pgid` (so the E6 review found it's skipped — `member == pgid` — by
/// every OTHER test here, which all happen to use a child whose own pgid
/// equals the session's, exercising only the group-signal path).
const FORK_GRANDCHILD_IN_NEW_PGROUP_SCRIPT: &str = "import os, sys, signal, time\n\
     pidfile = sys.argv[1]\n\
     child = os.fork()\n\
     if child == 0:\n\
     \x20\x20\x20\x20os.setpgid(0, 0)\n\
     \x20\x20\x20\x20signal.signal(signal.SIGHUP, signal.SIG_IGN)\n\
     \x20\x20\x20\x20signal.signal(signal.SIGTERM, signal.SIG_IGN)\n\
     \x20\x20\x20\x20with open(pidfile, \"w\") as f:\n\
     \x20\x20\x20\x20\x20\x20\x20\x20f.write(str(os.getpid()))\n\
     \x20\x20\x20\x20time.sleep(60)\n\
     else:\n\
     \x20\x20\x20\x20time.sleep(60)\n";

async fn wait_for_pidfile(path: &std::path::Path) -> i64 {
    for _ in 0..300 {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(pid) = content.trim().parse::<i64>() {
                return pid;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("grandchild never wrote its pid to {}", path.display());
}

#[tokio::test]
async fn list_tty_pids_finds_and_close_kills_a_grandchild_in_a_different_pgroup() {
    let (app, state) = fixture();
    let server = TestServer::builder()
        .http_transport()
        .build(app)
        .expect("test server");

    let pidfile_dir = tempfile::TempDir::new().expect("pidfile tempdir");
    let pidfile = pidfile_dir.path().join("grandchild.pid");

    let conv_id = "conv-e6-grandchild-tty-member";
    let create = server
        .post("/api/v1/terminals/local")
        .json(&serde_json::json!({
            "conversation_id": conv_id,
            "argv": [
                python3_path(),
                "-c",
                FORK_GRANDCHILD_IN_NEW_PGROUP_SCRIPT,
                pidfile.to_string_lossy(),
            ],
            "cols": 80,
            "rows": 24,
        }))
        .await;
    assert_eq!(create.status_code(), StatusCode::OK, "{}", create.text());

    wait_for_alive(&state, conv_id).await;
    let grandchild_pid = wait_for_pidfile(&pidfile).await;

    let list = server.get("/api/v1/terminals/local").await;
    let list_json: serde_json::Value = list.json();
    let entry = list_json["data"]
        .as_array()
        .expect("data array")
        .iter()
        .find(|i| i["conversation_id"] == conv_id)
        .expect("session must be listed");
    let pgid = entry["pgid"].as_i64().expect("pgid must be an integer");
    let slave_tty_path = entry["slave_tty_path"]
        .as_str()
        .expect("slave_tty_path must be present")
        .to_string();

    assert_ne!(
        grandchild_pid, pgid,
        "precondition: the grandchild must have its OWN pgroup, not the session's \
         (otherwise this test exercises the same group-signal path every other E6 \
         test already covers, not the individual tty_pids path)"
    );
    assert!(
        pid_exists(grandchild_pid),
        "precondition: the grandchild must be alive before we check list_tty_pids"
    );

    // Property (1): list_tty_pids must find the grandchild by TTY
    // membership — it is NOT the session's tracked child and NOT in its
    // process group, so the ONLY way to find it is the actual OS-specific
    // mechanism E6 exists for (proc_listpids(PROC_TTY_ONLY) on macOS, the
    // /proc tty_nr scan on Linux).
    let tty_pids = core_rs::os::list_tty_pids(&slave_tty_path);
    assert!(
        tty_pids.contains(&u32::try_from(grandchild_pid).expect("pid fits u32")),
        "list_tty_pids({slave_tty_path}) = {tty_pids:?} must contain the grandchild {grandchild_pid}"
    );

    // Property (2): close() must kill it within the SLA — this can ONLY
    // happen via the individual tty_pids signal path (the grandchild's own
    // pgroup is never targeted by our group-wide kill(-pgid, ...), since
    // its pgroup differs from the session's).
    let started = Instant::now();
    let del = server
        .delete(&format!("/api/v1/terminals/local/{conv_id}"))
        .await;
    assert_eq!(del.status_code(), StatusCode::NO_CONTENT);

    let deadline = started + Duration::from_secs(8);
    while Instant::now() < deadline && pid_exists(grandchild_pid) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let elapsed = started.elapsed();

    assert!(
        !pid_exists(grandchild_pid),
        "grandchild in a different pgroup must still be killed via list_tty_pids, \
         still alive after {elapsed:?}"
    );
    assert!(
        elapsed <= Duration::from_secs(5),
        "must die within <=5s of close, took {elapsed:?}"
    );
}
