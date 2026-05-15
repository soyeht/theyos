//! jobs-ipc — JSON-RPC-over-stdin/stdout bridge for the jobs-rs Store.
//!
//! Protocol: one JSON object per line on stdin, one JSON response per line on stdout.
//!
//! # Usage
//!
//! ```bash
//! jobs-ipc --db-path /tmp/jobs.db
//! ```

use core_rs::ipc::{
    harness::{require_arg, run_ipc_loop_with_init},
    wire::Response,
};
use jobs_rs::{Job, Store};
use serde_json::Value;

fn main() {
    run_ipc_loop_with_init("jobs-ipc", init, dispatch);
}

fn init(args: &[String]) -> Store {
    let db_path = require_arg(args, "--db-path", "jobs-ipc");

    match Store::new(&db_path) {
        Ok(s) => {
            eprintln!("[jobs-ipc] store opened at {db_path}");
            s
        }
        Err(e) => {
            eprintln!("[jobs-ipc] failed to open store at {db_path}: {e}");
            std::process::exit(1);
        }
    }
}

// ─── Dispatch ─────────────────────────────────────────────────────────────────

fn dispatch(store: &Store, method: &str, params: &Value) -> Response {
    match method {
        "Create" => handle_create(store, params),
        "Get" => handle_get(store, params),
        "Update" => handle_update(store, params),
        "ListPending" => handle_list_pending(store, params),
        "ListByInstance" => handle_list_by_instance(store, params),
        "ListRecent" => handle_list_recent(store, params),
        "ClaimNextPending" => handle_claim_next_pending(store),
        "CleanupOld" => handle_cleanup_old(store, params),
        other => Response::err(format!("unknown method: {other}")),
    }
}

fn handle_create(store: &Store, params: &Value) -> Response {
    let mut job: Job = match serde_json::from_value(params["job"].clone()) {
        Ok(j) => j,
        Err(e) => return Response::err(format!("invalid job: {e}")),
    };

    match store.create(&mut job) {
        Ok(()) => Response::ok(serde_json::json!({"job": job})),
        Err(e) => Response::err(e),
    }
}

fn handle_get(store: &Store, params: &Value) -> Response {
    let Some(id) = params["id"].as_str() else {
        return Response::err("missing 'id' param");
    };

    match store.get(id) {
        Ok(job) => Response::ok(serde_json::json!({"job": job})),
        Err(e) => Response::err(e),
    }
}

fn handle_update(store: &Store, params: &Value) -> Response {
    let job: Job = match serde_json::from_value(params["job"].clone()) {
        Ok(j) => j,
        Err(e) => return Response::err(format!("invalid job: {e}")),
    };

    match store.update(&job) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e),
    }
}

fn handle_list_pending(store: &Store, params: &Value) -> Response {
    // NOTE: limit is always a small count; truncation on 32-bit is not a concern here.
    #[allow(clippy::cast_possible_truncation)]
    let limit = params["limit"].as_u64().unwrap_or(0) as usize;
    match store.list_pending(limit) {
        Ok(jobs) => Response::ok(serde_json::json!({"jobs": jobs})),
        Err(e) => Response::err(e),
    }
}

fn handle_list_by_instance(store: &Store, params: &Value) -> Response {
    let Some(instance_id) = params["instanceId"].as_str() else {
        return Response::err("missing 'instanceId' param");
    };
    // NOTE: limit is always a small count; truncation on 32-bit is not a concern here.
    #[allow(clippy::cast_possible_truncation)]
    let limit = params["limit"].as_u64().unwrap_or(0) as usize;
    match store.list_by_instance(instance_id, limit) {
        Ok(jobs) => Response::ok(serde_json::json!({"jobs": jobs})),
        Err(e) => Response::err(e),
    }
}

fn handle_list_recent(store: &Store, params: &Value) -> Response {
    // NOTE: limit is always a small count; truncation on 32-bit is not a concern here.
    #[allow(clippy::cast_possible_truncation)]
    let limit = params["limit"].as_u64().unwrap_or(0) as usize;
    match store.list_recent(limit) {
        Ok(jobs) => Response::ok(serde_json::json!({"jobs": jobs})),
        Err(e) => Response::err(e),
    }
}

fn handle_claim_next_pending(store: &Store) -> Response {
    match store.claim_next_pending() {
        Ok(Some(job)) => Response::ok(serde_json::json!({"job": job})),
        Ok(None) => Response::ok(serde_json::json!({"job": null})),
        Err(e) => Response::err(e),
    }
}

fn handle_cleanup_old(store: &Store, params: &Value) -> Response {
    let secs = params["olderThanSecs"].as_u64().unwrap_or(0);
    match store.cleanup_old(secs) {
        Ok(n) => Response::ok(serde_json::json!({"removed": n})),
        Err(e) => Response::err(e),
    }
}
