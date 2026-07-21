//! E2 — tail replay on WS reattach for broker-owned local PTY sessions.
//!
//! Exercises `serve_pty_websocket`'s replay window end-to-end over a real
//! WebSocket upgrade (`axum-test`'s `ws` feature): a local session accumulates
//! more than `TAIL_REPLAY_BYTES` of conversation log, then a fresh WS attach
//! must only receive the tail (plus a `CTL:replay_truncated` marker), while
//! `?full_replay=true` opts back into the entire log.
//!
//! `CTL_PREFIX` / `TAIL_REPLAY_BYTES` are duplicated here from
//! `handlers_terminal.rs` (private consts, not part of the crate's public
//! surface) — they encode the wire protocol contract, not an implementation
//! detail, so a literal match is the right thing to assert against.

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Router, body::Body};
use axum_test::TestServer;
use core_rs::env::set_test_env;
use executor_rs::{Executor, FlowConfig};
use jobs_rs::Store as JobsStore;
use server_rs::auth::AuthUser;
use server_rs::handlers_terminal::{
    handle_local_terminal_create, handle_local_terminal_delete, handle_local_terminal_pty,
};
use server_rs::ratelimit::Limiter;
use server_rs::state::{AppState, SharedState};
use session_rs::SessionStore;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use store_rs::InstanceDb;
use terminal_rs::pty::PtyManager;
use vmrunner_rs::VmRunner;

const CTL_PREFIX: &[u8] = b"\x00\x01CTL:";
const TAIL_REPLAY_BYTES: u64 = 2 * 1024 * 1024;

fn ctl_marker(name: &str) -> Vec<u8> {
    let mut m = CTL_PREFIX.to_vec();
    m.extend_from_slice(name.as_bytes());
    m
}

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

/// Builds a minimal `AppState` + router exposing only the broker-owned local
/// terminal endpoints. Local terminal handlers take only `AuthUser` (no
/// per-conversation instance-DB ownership check), so nothing else needs to
/// be seeded.
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

    // Real conv_dir (not the fake ctl path — local sessions never exec it).
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
            post(handle_local_terminal_create),
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

/// Deterministic non-newline payload: digit `i % 10` at each position. Using
/// only ASCII digits sidesteps PTY `OPOST`/`ONLCR` byte-count surprises that
/// would come from embedding `\n` in the generated content.
fn digit_pattern(byte_len: usize) -> Vec<u8> {
    (0..byte_len).map(|i| b'0' + (i % 10) as u8).collect()
}

/// A short Python program (not the huge payload itself — that would blow
/// past `ARG_MAX` as a `-c` argument) that writes `digit_pattern(byte_len)`
/// to stdout, flushes, then sleeps so the child stays alive (and the local
/// session stays "live") long enough to attach and read the replay.
fn python_pattern_script(byte_len: usize) -> String {
    format!(
        "import sys, time\n\
         sys.stdout.write((\"0123456789\" * (({byte_len} // 10) + 1))[:{byte_len}])\n\
         sys.stdout.flush()\n\
         time.sleep(1000)\n"
    )
}

/// Absolute path to `python3`, resolved once via `which`. The local terminal
/// endpoint clears the child's environment (no inherited PATH), so argv[0]
/// must be an absolute path rather than relying on PATH lookup — this also
/// sidesteps any platform difference in `execvp`'s no-PATH fallback search.
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

async fn wait_for_log_size(state: &SharedState, conv_id: &str, expected: u64) {
    for _ in 0..300 {
        if let Some(sess) = state.pty_mgr.get_local(conv_id) {
            if sess.log().current_size() >= expected {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for conv log to reach {expected} bytes");
}

/// Reads WS messages from `replay_start` through `replay_done`, returning
/// whether a `replay_truncated` marker was seen and the concatenated content
/// bytes in between.
async fn drain_replay(ws: &mut axum_test::TestWebSocket) -> (bool, Vec<u8>) {
    let first = ws.receive_bytes().await;
    assert_eq!(
        first.as_ref(),
        ctl_marker("replay_start").as_slice(),
        "first frame must be replay_start"
    );

    let mut truncated = false;
    let mut content = Vec::new();
    loop {
        let msg = ws.receive_bytes().await;
        if msg.as_ref() == ctl_marker("replay_truncated").as_slice() {
            truncated = true;
            continue;
        }
        if msg.as_ref() == ctl_marker("replay_done").as_slice() {
            break;
        }
        content.extend_from_slice(&msg);
    }
    (truncated, content)
}

async fn create_local_session(server: &TestServer, conv_id: &str, argv: Vec<String>) {
    let resp = server
        .post("/api/v1/terminals/local")
        .json(&serde_json::json!({
            "conversation_id": conv_id,
            "argv": argv,
            "cols": 80,
            "rows": 24,
        }))
        .await;
    assert_eq!(resp.status_code(), StatusCode::OK, "{}", resp.text());
}

async fn delete_local_session(server: &TestServer, conv_id: &str) {
    let resp = server
        .delete(&format!("/api/v1/terminals/local/{conv_id}"))
        .await;
    assert_eq!(resp.status_code(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn reattach_replays_only_tail_and_marks_truncated() {
    let (app, state) = fixture();
    let server = TestServer::builder()
        .http_transport()
        .build(app)
        .expect("test server");

    let conv_id = "conv-e2-tail";
    let total_len: usize = 3 * 1024 * 1024; // > TAIL_REPLAY_BYTES (2 MiB)
    create_local_session(
        &server,
        conv_id,
        vec![
            python3_path(),
            "-c".to_string(),
            python_pattern_script(total_len),
        ],
    )
    .await;
    wait_for_log_size(&state, conv_id, total_len as u64).await;

    let path = format!("/api/v1/terminals/local/{conv_id}/pty");
    let response = server.get_websocket(&path).await;
    assert_eq!(response.status_code(), StatusCode::SWITCHING_PROTOCOLS);
    let mut ws = response.into_websocket().await;

    let (truncated, content) = drain_replay(&mut ws).await;
    ws.close().await;

    assert!(
        truncated,
        "a 3 MiB log must be truncated to the tail on default reattach"
    );
    assert_eq!(
        content.len() as u64,
        TAIL_REPLAY_BYTES,
        "reattach must transfer ~2 MiB, not the full 3 MiB log"
    );
    let full = digit_pattern(total_len);
    let expected_tail = &full[total_len - TAIL_REPLAY_BYTES as usize..];
    assert_eq!(content, expected_tail, "must be the LAST bytes, not any 2 MiB slice");

    delete_local_session(&server, conv_id).await;
}

#[tokio::test]
async fn full_replay_query_param_opts_into_entire_log() {
    let (app, state) = fixture();
    let server = TestServer::builder()
        .http_transport()
        .build(app)
        .expect("test server");

    let conv_id = "conv-e2-full";
    let total_len: usize = 3 * 1024 * 1024;
    create_local_session(
        &server,
        conv_id,
        vec![
            python3_path(),
            "-c".to_string(),
            python_pattern_script(total_len),
        ],
    )
    .await;
    wait_for_log_size(&state, conv_id, total_len as u64).await;

    let path = format!("/api/v1/terminals/local/{conv_id}/pty?full_replay=true");
    let response = server.get_websocket(&path).await;
    assert_eq!(response.status_code(), StatusCode::SWITCHING_PROTOCOLS);
    let mut ws = response.into_websocket().await;

    let (truncated, content) = drain_replay(&mut ws).await;
    ws.close().await;

    assert!(!truncated, "full_replay=true must not truncate");
    assert_eq!(content.len(), total_len, "full_replay=true must transfer the entire log");
    assert_eq!(content, digit_pattern(total_len));

    delete_local_session(&server, conv_id).await;
}

#[tokio::test]
async fn short_log_under_tail_cap_is_not_truncated() {
    let (app, state) = fixture();
    let server = TestServer::builder()
        .http_transport()
        .build(app)
        .expect("test server");

    let conv_id = "conv-e2-short";
    let total_len: usize = 4096; // well under TAIL_REPLAY_BYTES
    create_local_session(
        &server,
        conv_id,
        vec![
            python3_path(),
            "-c".to_string(),
            python_pattern_script(total_len),
        ],
    )
    .await;
    wait_for_log_size(&state, conv_id, total_len as u64).await;

    let path = format!("/api/v1/terminals/local/{conv_id}/pty");
    let response = server.get_websocket(&path).await;
    assert_eq!(response.status_code(), StatusCode::SWITCHING_PROTOCOLS);
    let mut ws = response.into_websocket().await;

    let (truncated, content) = drain_replay(&mut ws).await;
    ws.close().await;

    assert!(
        !truncated,
        "a log smaller than the tail cap must never be marked truncated"
    );
    assert_eq!(content.len(), total_len);
    assert_eq!(content, digit_pattern(total_len));

    delete_local_session(&server, conv_id).await;
}
