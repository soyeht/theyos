//! `vmrunner_ipc.rs` — JSON-RPC line-protocol IPC binary for VM lifecycle operations.
//!
//! # Protocol
//!
//! One JSON object per line on stdin; one JSON response per line on stdout.
//!
//! Request format:
//! ```json
//! {"method": "Create", "params": { ... }}
//! ```
//!
//! Response format:
//! ```json
//! {"ok": true, "result": {...}}
//! {"ok": false, "error": "description"}
//! ```
//!
//! # Supported methods
//!
//! | Method          | Required params                                                    |
//! |-----------------|---------------------------------------------------------------------|
//! | Create          | container, customer, claw_type, state_dir, firecracker_bin,       |
//! |                 | kernel_image, base_rootfs, ssh_key, ssh_pubkey                     |
//! | Stop            | container, state_dir                                               |
//! | Delete          | container, state_dir                                               |
//! | Restart         | container, state_dir, ssh_key, firecracker_bin, kernel_image       |
//! | Rebuild         | container, state_dir, ssh_key, firecracker_bin, kernel_image       |
//! | CleanupSystemd  | container                                                           |
//! | CleanupFs       | claw_type, name, state_dir                                         |
//! | FetchLogs       | container, state_dir, ssh_key, tail                                |
//! | TakeBaseSnapshot| container, claw_type, home, state_dir, kernel_image, ssh_key       |
//! | WarmPoolInit    | state_dir, firecracker_bin, kernel_image, base_rootfs,             |
//! |                 | ssh_key, ssh_pubkey                                                |
//! | WarmPoolRefill  | claw_type, state_dir, firecracker_bin, kernel_image,               |
//! |                 | base_rootfs, ssh_key, ssh_pubkey                                   |
//! | WarmPoolStatus  | state_dir (optional, for stale entry cleanup)                     |

use core_rs::ipc::wire::Response;
use serde_json::Value;
use std::path::PathBuf;

use vmrunner_common_rs::VmCreateResourceSpec;
use vmrunner_rs::{VmConfig, VmEnv, VmRunner};

#[tokio::main]
async fn main() {
    // Initialize tracing so tracing::info!/tracing::warn! calls in vmrunner_rs are
    // visible in backend.log (vmrunner_ipc stderr is inherited by the server process).
    // Default level: INFO. Override with RUST_LOG env var.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    core_rs::ipc::harness::run_ipc_loop_async("vmrunner-ipc", |method, params| {
        let method = method.to_string();
        let params = params.clone();
        async move { dispatch(&method, &params).await }
    })
    .await;
}

// ── Dispatch ───────────────────────────────────────────────────────────────

async fn dispatch(method: &str, params: &Value) -> Response {
    match method {
        "Create" => handle_create(params).await,
        "Stop" => handle_stop(params),
        "Delete" => handle_delete(params),
        "Restart" => handle_restart(params).await,
        "Rebuild" => handle_rebuild(params).await,
        "CleanupSystemd" => handle_cleanup_systemd(params),
        "CleanupFs" => handle_cleanup_fs(params),
        "FetchLogs" => handle_fetch_logs(params).await,
        "TakeBaseSnapshot" => handle_take_base_snapshot(params).await,
        "WarmPoolInit" => handle_warm_pool_init(params),
        "WarmPoolRefill" => handle_warm_pool_refill(params),
        "WarmPoolStatus" => handle_warm_pool_status(params),
        "WarmPoolDrain" => handle_warm_pool_drain(params),
        other => Response::err(format!("unknown method: {other}")),
    }
}

// ── Handlers ───────────────────────────────────────────────────────────────

async fn handle_create(params: &Value) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };
    let customer = match params["customer"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("customer is required"),
    };
    let claw_type = match params["claw_type"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("claw_type is required"),
    };
    let customer_dir = params["customer_dir"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    let env = match build_vm_env(params) {
        Ok(e) => e,
        Err(e) => return Response::err(e),
    };
    let runner = VmRunner { env };

    let tools: Vec<String> = params["tools"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(std::string::ToString::to_string))
                .collect()
        })
        .unwrap_or_default();

    let resources =
        serde_json::from_value::<VmCreateResourceSpec>(params.clone()).unwrap_or_default();

    let config = VmConfig {
        container,
        customer,
        claw_type,
        customer_dir,
        tools,
        cpu_cores: resources.cpu_cores,
        ram_mb: resources.ram_mb,
        disk_gb: resources.disk_gb,
    };

    match runner.create(&config).await {
        Ok(result) => {
            let phases_json: Vec<serde_json::Value> = result
                .phases
                .iter()
                .map(|(name, duration)| {
                    serde_json::json!({
                        "phase": name,
                        "ms": duration.as_millis()
                    })
                })
                .collect();

            Response::ok(serde_json::json!({
                "created": true,
                "golden_image_used": result.golden_image_used,
                "install_skipped": result.install_skipped,
                "phases": phases_json,
                "total_ms": result.total_duration.as_millis()
            }))
        }
        Err(ref e) => {
            // If the error carries structured context, include it in the response
            // so that executor-rs and server-rs can surface it without log diving.
            if let Some(ctx) = e.context() {
                if let Ok(ctx_json) = serde_json::to_value(ctx) {
                    return Response::err_with_context(e, ctx_json);
                }
            }
            Response::err(e)
        }
    }
}

fn handle_stop(params: &Value) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };
    let state_dir = match params["state_dir"].as_str() {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => return Response::err("state_dir is required"),
    };

    let runner = make_minimal_runner(state_dir);
    match runner.stop(&container) {
        Ok(()) => Response::ok(serde_json::json!({"stopped": true})),
        Err(e) => Response::err(e),
    }
}

fn handle_delete(params: &Value) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };
    let state_dir = match params["state_dir"].as_str() {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => return Response::err("state_dir is required"),
    };

    let runner = make_minimal_runner(state_dir);
    match runner.delete(&container) {
        Ok(()) => Response::ok(serde_json::json!({"deleted": true})),
        Err(e) => Response::err(e),
    }
}

async fn handle_restart(params: &Value) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };
    let state_dir = match params["state_dir"].as_str() {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => return Response::err("state_dir is required"),
    };
    let ssh_key = match params["ssh_key"].as_str() {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => return Response::err("ssh_key is required"),
    };
    // NOTE: ssh_wait_tries is a small count (default 20); u64→u32 truncation is benign.
    #[allow(clippy::cast_possible_truncation)]
    let ssh_wait_tries = params["ssh_wait_tries"].as_u64().map_or(20, |v| v as u32);

    let mut env = minimal_env(state_dir);
    env.ssh_key = ssh_key;
    env.ssh_wait_tries = ssh_wait_tries;
    if let Some(v) = params["firecracker_bin"].as_str().filter(|s| !s.is_empty()) {
        env.firecracker_bin = PathBuf::from(v);
    }
    if let Some(v) = params["kernel_image"].as_str().filter(|s| !s.is_empty()) {
        env.kernel_image = PathBuf::from(v);
    }
    let runner = VmRunner { env };

    match runner.restart(&container).await {
        Ok(()) => Response::ok(serde_json::json!({"restarted": true})),
        Err(e) => Response::err(e),
    }
}

async fn handle_rebuild(params: &Value) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };
    let state_dir = match params["state_dir"].as_str() {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => return Response::err("state_dir is required"),
    };
    let ssh_key = match params["ssh_key"].as_str() {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => return Response::err("ssh_key is required"),
    };
    // NOTE: ssh_wait_tries is a small count (default 20); u64→u32 truncation is benign.
    #[allow(clippy::cast_possible_truncation)]
    let ssh_wait_tries = params["ssh_wait_tries"].as_u64().map_or(20, |v| v as u32);

    let mut env = minimal_env(state_dir);
    env.ssh_key = ssh_key;
    env.ssh_wait_tries = ssh_wait_tries;
    if let Some(v) = params["firecracker_bin"].as_str().filter(|s| !s.is_empty()) {
        env.firecracker_bin = PathBuf::from(v);
    }
    if let Some(v) = params["kernel_image"].as_str().filter(|s| !s.is_empty()) {
        env.kernel_image = PathBuf::from(v);
    }
    let runner = VmRunner { env };

    match runner.rebuild(&container).await {
        Ok(()) => Response::ok(serde_json::json!({"rebuilt": true})),
        Err(e) => Response::err(e),
    }
}

fn handle_cleanup_systemd(params: &Value) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };

    let runner = make_minimal_runner(PathBuf::from("/tmp"));
    match runner.cleanup_systemd(&container) {
        Ok(()) => Response::ok(serde_json::json!({"cleaned": true})),
        Err(e) => Response::err(e),
    }
}

fn handle_cleanup_fs(params: &Value) -> Response {
    let claw_type = match params["claw_type"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("claw_type is required"),
    };
    let name = match params["name"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("name is required"),
    };
    let state_dir = match params["state_dir"].as_str() {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => return Response::err("state_dir is required"),
    };

    let runner = make_minimal_runner(state_dir);
    match runner.cleanup_fs(&claw_type, &name) {
        Ok(()) => Response::ok(serde_json::json!({"cleaned": true})),
        Err(e) => Response::err(e),
    }
}

async fn handle_fetch_logs(params: &Value) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };
    let state_dir = match params["state_dir"].as_str() {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => return Response::err("state_dir is required"),
    };
    let ssh_key = match params["ssh_key"].as_str() {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => return Response::err("ssh_key is required"),
    };
    // NOTE: tail is a log-line count (default 200); u64→usize truncation is benign in practice.
    #[allow(clippy::cast_possible_truncation)]
    let tail = params["tail"].as_u64().unwrap_or(200) as usize;

    let mut env = minimal_env(state_dir);
    env.ssh_key = ssh_key;
    let runner = VmRunner { env };

    match runner.fetch_logs(&container, tail).await {
        Ok(lines) => {
            let json_lines: Vec<Value> = lines.into_iter().map(Value::String).collect();
            Response::ok(serde_json::json!({"lines": json_lines}))
        }
        Err(e) => Response::err(e),
    }
}

async fn handle_take_base_snapshot(params: &Value) -> Response {
    let container = match params["container"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("container is required"),
    };
    let claw_type = match params["claw_type"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("claw_type is required"),
    };
    let state_dir = match params["state_dir"].as_str() {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => return Response::err("state_dir is required"),
    };
    let ssh_key = match params["ssh_key"].as_str() {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => return Response::err("ssh_key is required"),
    };
    let kernel_image = params["kernel_image"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let home = params["home"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    let mut env = minimal_env(state_dir);
    if let Some(home) = home {
        env.home = home;
    }
    env.ssh_key = ssh_key;
    if let Some(kernel_image) = kernel_image {
        env.kernel_image = kernel_image;
    } else if let Ok(default_env) = VmEnv::from_env() {
        env.kernel_image = default_env.kernel_image;
    }
    let runner = VmRunner { env };
    match runner.take_base_snapshot(&container, &claw_type).await {
        Ok(()) => Response::ok(serde_json::json!({"snapshot_taken": true})),
        Err(e) => Response::err(e),
    }
}

fn handle_warm_pool_init(params: &Value) -> Response {
    use vmrunner_rs::warm_pool::{WarmPool, clear_shutdown, global_pool, warm_pool_enabled};

    if !warm_pool_enabled() {
        return Response::ok(serde_json::json!({"warm_pool_init": "disabled"}));
    }

    // Reset the shutdown flag so new fill tasks are not immediately aborted.
    // This must happen before spawning any fill tasks.
    clear_shutdown();

    // Build VmEnv from params (same fields as Create)
    let env = match build_vm_env(params) {
        Ok(e) => e,
        Err(e) => return Response::err(e),
    };
    let runner = VmRunner { env };

    // Spawn a background task to fill all pool slots.
    // Returns immediately so the backend startup isn't blocked.

    let claw_types: Vec<String> = WarmPool::all_claw_types()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    // Mark all slots as filling before spawning tasks (so status reports show
    // them as in-progress rather than missing)
    {
        let mut pool = global_pool()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for ct in &claw_types {
            pool.mark_filling(ct);
        }
    }

    // Limit concurrency: fill 2 at a time to avoid overwhelming the host
    // (each load_snapshot takes 13-15s and is CPU-heavy in FC)
    let runner = std::sync::Arc::new(runner);
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
    for ct in claw_types {
        let runner = runner.clone();
        let sem = semaphore.clone();
        tokio::spawn(async move {
            // Acquire concurrency slot (max 2)
            let _permit = sem.acquire().await.expect("semaphore closed unexpectedly");

            tracing::info!("[vmrunner-pool-init] filling slot for {ct}");
            match runner.fill_pool_slot(&ct).await {
                Ok(()) => tracing::info!("[vmrunner-pool-init] slot ready: {ct}"),
                Err(e) => {
                    tracing::error!("[vmrunner-pool-init] slot failed for {ct}: {e}");
                    let mut pool = vmrunner_rs::warm_pool::global_pool()
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    pool.unmark_filling(&ct);
                }
            }
        });
    }

    Response::ok(serde_json::json!({"warm_pool_init": "started", "filling": 6}))
}

fn handle_warm_pool_refill(params: &Value) -> Response {
    use vmrunner_rs::warm_pool::{clear_shutdown, global_pool, warm_pool_enabled};

    let claw_type = match params["claw_type"].as_str() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return Response::err("claw_type is required"),
    };

    if !warm_pool_enabled() {
        return Response::ok(serde_json::json!({
            "warm_pool_refill": "disabled",
            "claw_type": claw_type
        }));
    }

    let env = match build_vm_env(params) {
        Ok(e) => e,
        Err(e) => return Response::err(e),
    };

    // A preceding drain sets the global shutdown flag to abort in-flight fills.
    // Explicit refill requests mean the caller wants the pool live again.
    clear_shutdown();

    // Only fill if slot is empty/in-progress
    {
        let pool = global_pool()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !pool.slot_is_empty(&claw_type) {
            return Response::ok(serde_json::json!({
                "warm_pool_refill": "already_warm",
                "claw_type": claw_type
            }));
        }
    }

    // Mark filling
    let should_fill = {
        let mut pool = global_pool()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pool.mark_filling(&claw_type)
    };

    if !should_fill {
        return Response::ok(serde_json::json!({
            "warm_pool_refill": "already_filling",
            "claw_type": claw_type
        }));
    }

    let ct = claw_type.clone();
    tokio::spawn(async move {
        let runner = VmRunner { env };
        tracing::info!("[vmrunner-pool] refill started for {ct}");
        match runner.fill_pool_slot(&ct).await {
            Ok(()) => tracing::info!("[vmrunner-pool] refill done: {ct}"),
            Err(e) => {
                tracing::error!("[vmrunner-pool] refill failed for {ct}: {e}");
                let mut pool = global_pool()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                pool.unmark_filling(&ct);
            }
        }
    });

    Response::ok(serde_json::json!({
        "warm_pool_refill": "started",
        "claw_type": claw_type
    }))
}

fn handle_warm_pool_status(params: &Value) -> Response {
    use vmrunner_rs::warm_pool::{WarmEntry, WarmPool, global_pool};

    let state_dir = params["state_dir"].as_str().map(PathBuf::from);

    let mut pool = global_pool()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // Collect stale entries that need filesystem cleanup.
    let mut stale_entries: Vec<WarmEntry> = Vec::new();

    let status: serde_json::Map<String, serde_json::Value> = WarmPool::all_claw_types()
        .iter()
        .map(|ct| {
            let mut stale_out = None;
            let state = pool.health_check(ct, &mut stale_out);
            if let Some(entry) = stale_out {
                stale_entries.push(entry);
            }
            (ct.to_string(), serde_json::Value::String(state.to_string()))
        })
        .collect();

    // Drop the lock before doing I/O cleanup.
    drop(pool);

    // Clean up any stale entries (kill processes, remove directories).
    for entry in &stale_entries {
        tracing::warn!(
            "[vmrunner-pool-status] evicting stale warm entry {} \
             (fc_pid={:?}, slirp_pid={:?})",
            entry.container,
            entry.inst.firecracker_pid(),
            entry.inst.slirp_pid(),
        );
        if let Some(ref sd) = state_dir {
            let dir = sd.join(&entry.container);
            vmrunner_rs::create_guard::do_cleanup(
                &dir,
                entry.inst.firecracker_pid(),
                entry.inst.slirp_pid(),
            );
        }
    }

    Response::ok(serde_json::Value::Object(status))
}

fn handle_warm_pool_drain(params: &Value) -> Response {
    let state_dir = match params["state_dir"].as_str() {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => return Response::err("state_dir is required".to_string()),
    };
    let runner = VmRunner {
        env: minimal_env(state_dir),
    };
    let drained = runner.drain_warm_pool();
    Response::ok(serde_json::json!({ "drained": drained }))
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Extract a `VmEnv` from IPC params (shared between Create, `WarmPoolInit`, `WarmPoolRefill`).
fn build_vm_env(params: &Value) -> Result<vmrunner_rs::VmEnv, String> {
    let state_dir = match params["state_dir"].as_str() {
        Some(v) if !v.is_empty() => std::path::PathBuf::from(v),
        _ => return Err("state_dir is required".to_string()),
    };
    let firecracker_bin = match params["firecracker_bin"].as_str() {
        Some(v) if !v.is_empty() => std::path::PathBuf::from(v),
        _ => return Err("firecracker_bin is required".to_string()),
    };
    let kernel_image = match params["kernel_image"].as_str() {
        Some(v) if !v.is_empty() => std::path::PathBuf::from(v),
        _ => return Err("kernel_image is required".to_string()),
    };
    let base_rootfs = match params["base_rootfs"].as_str() {
        Some(v) if !v.is_empty() => std::path::PathBuf::from(v),
        _ => return Err("base_rootfs is required".to_string()),
    };
    let ssh_key = match params["ssh_key"].as_str() {
        Some(v) if !v.is_empty() => std::path::PathBuf::from(v),
        _ => return Err("ssh_key is required".to_string()),
    };
    let ssh_pubkey = match params["ssh_pubkey"].as_str() {
        Some(v) if !v.is_empty() => std::path::PathBuf::from(v),
        _ => return Err("ssh_pubkey is required".to_string()),
    };
    // NOTE: ssh_wait_tries is a small count (default 20); u64→u32 truncation is benign.
    #[allow(clippy::cast_possible_truncation)]
    let ssh_wait_tries = params["ssh_wait_tries"].as_u64().map_or(20, |v| v as u32);
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()));

    Ok(vmrunner_rs::VmEnv {
        state_dir,
        firecracker_bin,
        kernel_image,
        base_rootfs,
        ssh_key,
        ssh_pubkey,
        ssh_wait_tries,
        home,
    })
}

fn minimal_env(state_dir: PathBuf) -> VmEnv {
    VmEnv {
        state_dir,
        firecracker_bin: PathBuf::new(),
        kernel_image: PathBuf::new(),
        base_rootfs: PathBuf::new(),
        ssh_key: PathBuf::new(),
        ssh_pubkey: PathBuf::new(),
        ssh_wait_tries: 20,
        home: PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())),
    }
}

fn make_minimal_runner(state_dir: PathBuf) -> VmRunner {
    VmRunner {
        env: minimal_env(state_dir),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::await_holding_lock)]

    use super::*;

    /// Serializes tests that touch the `warm_pool` global state (shutdown flag
    /// and `global_pool`). Without this, parallel `cargo test` lets one test's
    /// `signal_shutdown()` race with another's `clear_shutdown()` and the
    /// `is_shutting_down()` assertions flake.
    static WARM_POOL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn dispatch_unknown_method() {
        let resp = dispatch("Explode", &Value::Null).await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("unknown method"));
    }

    #[tokio::test]
    async fn create_missing_container_errors() {
        let resp = dispatch(
            "Create",
            &serde_json::json!({
                "customer": "test",
                "claw_type": "picoclaw",
                "port": 35000
            }),
        )
        .await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("container"));
    }

    #[tokio::test]
    async fn create_missing_state_dir_errors() {
        let resp = dispatch(
            "Create",
            &serde_json::json!({
                "container": "picoclaw-test",
                "customer": "test",
                "claw_type": "picoclaw",
                "port": 35000
                // state_dir missing
            }),
        )
        .await;
        assert!(!resp.ok);
        let err = resp.error.unwrap();
        assert!(
            err.contains("state_dir") || err.contains("firecracker_bin"),
            "unexpected: {err}"
        );
    }

    #[tokio::test]
    async fn stop_missing_container_errors() {
        let resp = dispatch("Stop", &serde_json::json!({"state_dir": "/tmp"})).await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("container"));
    }

    #[tokio::test]
    async fn rebuild_missing_container_errors() {
        let resp = dispatch(
            "Rebuild",
            &serde_json::json!({
                "state_dir": "/tmp",
                "ssh_key": "/tmp/key"
            }),
        )
        .await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("container"));
    }

    #[tokio::test]
    async fn rebuild_missing_ssh_key_errors() {
        let resp = dispatch(
            "Rebuild",
            &serde_json::json!({
                "container": "picoclaw-test",
                "state_dir": "/tmp"
                // ssh_key missing
            }),
        )
        .await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("ssh_key"));
    }

    #[tokio::test]
    async fn delete_missing_state_dir_errors() {
        let resp = dispatch("Delete", &serde_json::json!({"container": "picoclaw-test"})).await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("state_dir"));
    }

    #[tokio::test]
    async fn fetch_logs_missing_ssh_key_errors() {
        let resp = dispatch(
            "FetchLogs",
            &serde_json::json!({
                "container": "picoclaw-test",
                "state_dir": "/tmp",
                "tail": 50
                // ssh_key missing
            }),
        )
        .await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("ssh_key"));
    }

    #[tokio::test]
    async fn take_base_snapshot_missing_ssh_key_errors() {
        let resp = dispatch(
            "TakeBaseSnapshot",
            &serde_json::json!({
                "container": "picoclaw-test",
                "claw_type": "picoclaw",
                "state_dir": "/tmp"
            }),
        )
        .await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("ssh_key"));
    }

    #[tokio::test]
    async fn cleanup_systemd_missing_container_errors() {
        let resp = dispatch("CleanupSystemd", &serde_json::json!({})).await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("container"));
    }

    #[tokio::test]
    async fn cleanup_fs_missing_params_errors() {
        let resp = dispatch("CleanupFs", &serde_json::json!({"claw_type": "picoclaw"})).await;
        assert!(!resp.ok);
        // Should error on missing "name"
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn warm_pool_init_missing_state_dir_errors() {
        let _g = WARM_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let resp = dispatch(
            "WarmPoolInit",
            &serde_json::json!({
                "firecracker_bin": "/tmp/fc",
                "kernel_image": "/tmp/kernel",
                "base_rootfs": "/tmp/rootfs",
                "ssh_key": "/tmp/key",
                "ssh_pubkey": "/tmp/key.pub"
                // state_dir missing
            }),
        )
        .await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("state_dir"));
    }

    #[tokio::test]
    async fn warm_pool_refill_missing_claw_type_errors() {
        let _g = WARM_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let resp = dispatch(
            "WarmPoolRefill",
            &serde_json::json!({
                "state_dir": "/tmp",
                "firecracker_bin": "/tmp/fc",
                "kernel_image": "/tmp/kernel",
                "base_rootfs": "/tmp/rootfs",
                "ssh_key": "/tmp/key",
                "ssh_pubkey": "/tmp/key.pub"
                // claw_type missing
            }),
        )
        .await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("claw_type"));
    }

    #[tokio::test]
    async fn warm_pool_refill_clears_shutdown_flag() {
        use vmrunner_rs::warm_pool::{clear_shutdown, is_shutting_down, signal_shutdown};

        let _g = WARM_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        clear_shutdown();
        signal_shutdown();
        assert!(is_shutting_down());

        let resp = dispatch(
            "WarmPoolRefill",
            &serde_json::json!({
                "claw_type": "picoclaw",
                "state_dir": "/tmp",
                "firecracker_bin": "/tmp/fc",
                "kernel_image": "/tmp/kernel",
                "base_rootfs": "/tmp/rootfs",
                "ssh_key": "/tmp/key",
                "ssh_pubkey": "/tmp/key.pub"
            }),
        )
        .await;

        assert!(resp.ok, "expected ok, got: {:?}", resp.error);
        assert!(
            !is_shutting_down(),
            "WarmPoolRefill should clear shutdown before spawning a new fill"
        );

        clear_shutdown();
    }

    #[tokio::test]
    async fn warm_pool_status_returns_ok() {
        let _g = WARM_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let resp = dispatch("WarmPoolStatus", &serde_json::json!({})).await;
        assert!(resp.ok, "expected ok, got: {:?}", resp.error);
        let result = resp.result.unwrap();
        // Should contain all 6 claw types
        for ct in &[
            "picoclaw", "zeroclaw", "nanobot", "openclaw", "nullclaw", "ironclaw",
        ] {
            assert!(
                result.get(ct).is_some(),
                "missing claw type {ct} in pool status"
            );
        }
    }

    #[tokio::test]
    async fn warm_pool_drain_requires_state_dir() {
        let _g = WARM_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let resp = dispatch("WarmPoolDrain", &serde_json::json!({})).await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("state_dir"));
    }

    #[tokio::test]
    async fn warm_pool_drain_returns_drained_count() {
        let _g = WARM_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::TempDir::new().unwrap();
        let resp = dispatch(
            "WarmPoolDrain",
            &serde_json::json!({ "state_dir": tmp.path().to_str().unwrap() }),
        )
        .await;
        assert!(resp.ok, "expected ok, got: {:?}", resp.error);
        let result = resp.result.unwrap();
        // Pool is empty in tests, so drained should be 0
        assert_eq!(result["drained"], 0);
    }
}
