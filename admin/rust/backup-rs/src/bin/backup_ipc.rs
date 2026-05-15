//! backup-ipc — JSON-RPC-over-stdin/stdout bridge for backup-rs.
//!
//! # Protocol
//!
//! One JSON object per line on **stdin**, one JSON response per line on **stdout**.
//!
//! ## Request format
//!
//! ```json
//! {"method":"Ping","params":{}}
//! {"method":"Backup","params":{"db_path":"/data/theyos.db","backup_dir":"/backups","retain_count":7}}
//! {"method":"ListBackups","params":{"db_path":"/data/theyos.db","limit":10}}
//! ```
//!
//! ## Response format
//!
//! ```json
//! {"ok":true,"result":"pong"}
//! {"ok":true,"result":"/backups/backup-2026-01-15T14-30-00.db"}
//! {"ok":false,"error":"db error: ..."}
//! ```

use backup_rs::BackupManager;
use core_rs::ipc::{harness::run_ipc_loop, wire::Response};
use serde::Deserialize;
use serde_json::Value;

// ─── Params structs ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct BackupParams {
    db_path: String,
    backup_dir: String,
    #[serde(default = "default_retain_count")]
    retain_count: usize,
}

fn default_retain_count() -> usize {
    7
}

#[derive(Deserialize)]
struct ListBackupsParams {
    db_path: String,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    10
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    run_ipc_loop("backup-ipc", dispatch);
}

// ─── Dispatch ─────────────────────────────────────────────────────────────────

fn dispatch(method: &str, params: &Value) -> Response {
    match method {
        "Backup" => {
            let p: BackupParams = match serde_json::from_value(params.clone()) {
                Ok(p) => p,
                Err(e) => return Response::err(format!("invalid Backup params: {e}")),
            };
            match BackupManager::new(&p.db_path, &p.backup_dir, p.retain_count) {
                Ok(mgr) => match mgr.backup() {
                    Ok(path) => Response::ok(serde_json::to_value(path).unwrap_or(Value::Null)),
                    Err(e) => Response::err(e),
                },
                Err(e) => Response::err(e),
            }
        }

        "ListBackups" => {
            let p: ListBackupsParams = match serde_json::from_value(params.clone()) {
                Ok(p) => p,
                Err(e) => return Response::err(format!("invalid ListBackups params: {e}")),
            };
            match BackupManager::new(&p.db_path, "/tmp", 0) {
                Ok(mgr) => match mgr.list_backups(p.limit) {
                    Ok(entries) => {
                        Response::ok(serde_json::to_value(entries).unwrap_or(Value::Null))
                    }
                    Err(e) => Response::err(e),
                },
                Err(e) => Response::err(e),
            }
        }

        other => Response::err(format!("unknown method: {other}")),
    }
}
