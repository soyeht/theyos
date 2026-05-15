//! session-ipc — JSON-RPC-over-stdin/stdout bridge for the session-rs `SessionStore`.
//!
//! Protocol: one JSON object per line on stdin, one JSON response per line on stdout.
//!
//! # Environment variables
//!
//! - `THEYOS_SESSION_DB` — path to the `SQLite` database (default: `/tmp/theyos-sessions.db`)
//! - `SOYEHT_ADMIN_USER` — admin username (default: `admin`)
//! - `SOYEHT_ADMIN_PASSWORD` — admin password (default: empty, warns)

use core_rs::ipc::{harness::run_ipc_loop_with_init, wire::Response};
use serde_json::Value;
use session_rs::SessionStore;

fn main() {
    run_ipc_loop_with_init("session-ipc", init, dispatch);
}

fn init(_args: &[String]) -> SessionStore {
    let db_path = std::env::var("THEYOS_SESSION_DB")
        .unwrap_or_else(|_| "/tmp/theyos-sessions.db".to_string());

    match SessionStore::open(&db_path) {
        Ok(s) => {
            eprintln!("[session-ipc] store opened at {db_path}");
            s
        }
        Err(e) => {
            eprintln!("[session-ipc] failed to open store at {db_path}: {e}");
            std::process::exit(1);
        }
    }
}

fn dispatch(store: &SessionStore, method: &str, params: &Value) -> Response {
    match method {
        "ValidateCredentials" => handle_validate_credentials(store, params),
        "CreateSession" => handle_create_session(store, params),
        "ValidateSession" => handle_validate_session(store, params),
        "DeleteSession" => handle_delete_session(store, params),
        "CleanupExpired" => handle_cleanup_expired(store),
        other => Response::err(format!("unknown method: {other}")),
    }
}

fn handle_validate_credentials(store: &SessionStore, params: &Value) -> Response {
    let Some(username) = params["username"].as_str() else {
        return Response::err("missing 'username' param");
    };
    let Some(password) = params["password"].as_str() else {
        return Response::err("missing 'password' param");
    };

    match store.validate_credentials(username, password) {
        Ok(()) => Response::ok(serde_json::json!({"valid": true})),
        Err(session_rs::SessionError::InvalidCredentials) => {
            Response::ok(serde_json::json!({"valid": false}))
        }
        Err(e) => Response::err(e),
    }
}

fn handle_create_session(store: &SessionStore, params: &Value) -> Response {
    let Some(username) = params["username"].as_str() else {
        return Response::err("missing 'username' param");
    };

    match store.create_session(username) {
        Ok(token) => Response::ok(serde_json::json!({"token": token})),
        Err(e) => Response::err(e),
    }
}

fn handle_validate_session(store: &SessionStore, params: &Value) -> Response {
    let Some(token) = params["token"].as_str() else {
        return Response::err("missing 'token' param");
    };

    let username = store.validate_session(token);
    Response::ok(serde_json::json!({"username": username}))
}

fn handle_delete_session(store: &SessionStore, params: &Value) -> Response {
    let Some(token) = params["token"].as_str() else {
        return Response::err("missing 'token' param");
    };

    match store.delete_session(token) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e),
    }
}

fn handle_cleanup_expired(store: &SessionStore) -> Response {
    match store.cleanup_expired() {
        Ok(n) => Response::ok(serde_json::json!({"removed": n})),
        Err(e) => Response::err(e),
    }
}
