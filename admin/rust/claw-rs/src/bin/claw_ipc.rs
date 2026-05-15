//! `claw_ipc` — IPC binary for the claw-rs registry.
//!
//! Protocol: newline-delimited JSON on stdin/stdout.
//! Each request: `{ "cmd": "...", ...args }` → response: JSON line.
//!
//! Commands:
//!   Ping                                    → { "ok": true }
//!   Names                                   → { "names": [...] }
//!   Get      { "name": "..." }              → { "type": `ClawType` | null }
//!   `IsValid`  { "name": "..." }              → { "valid": bool }
//!   Sources                                 → { "sources": [...] }
//!   `PortsPaths`                              → { "paths": [...] }
//!   `DataBaseDir` { "name": "..." }           → { "dir": "..." | null }
//!   `ResolveHostBaseDir` { "name":"...", "remote": bool } → { "dir": "..." | null }
//!   `HasCleanup` { "name": "..." }            → { "`has_cleanup"`: bool }

use claw_rs::Registry;
use serde::Deserialize;
use serde_json::Value;
use std::io::{self, BufRead, Write};

#[derive(Debug, Deserialize)]
struct Request {
    cmd: String,
    #[serde(flatten)]
    args: serde_json::Map<String, Value>,
}

fn main() {
    // Build registry once at startup from env vars.
    let registry = Registry::from_env();

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[claw_ipc] stdin read error: {e}");
                break;
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let response = handle_request(&registry, line);
        if let Err(e) = writeln!(out, "{response}") {
            eprintln!("[claw_ipc] stdout write error: {e}");
            break;
        }
        if let Err(e) = out.flush() {
            eprintln!("[claw_ipc] stdout flush error: {e}");
            break;
        }
    }
}

fn handle_request(registry: &Registry, line: &str) -> String {
    let req: Request = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            return error_response(&format!("invalid JSON request: {e}"));
        }
    };

    match req.cmd.as_str() {
        "Ping" => serde_json::json!({ "ok": true }).to_string(),

        "Names" => {
            let names = registry.names();
            serde_json::json!({ "names": names }).to_string()
        }

        "Get" => {
            let Some(name) = req.args.get("name").and_then(|v| v.as_str()) else {
                return error_response("Get: missing 'name' field");
            };
            let ct = registry.get(name);
            serde_json::json!({ "type": ct }).to_string()
        }

        "IsValid" => {
            let Some(name) = req.args.get("name").and_then(|v| v.as_str()) else {
                return error_response("IsValid: missing 'name' field");
            };
            let valid = registry.is_valid(name);
            serde_json::json!({ "valid": valid }).to_string()
        }

        "Sources" => {
            let sources = registry.sources();
            serde_json::json!({ "sources": sources }).to_string()
        }

        "PortsPaths" => {
            let paths = registry.ports_paths();
            serde_json::json!({ "paths": paths }).to_string()
        }

        "DataBaseDir" => {
            let Some(name) = req.args.get("name").and_then(|v| v.as_str()) else {
                return error_response("DataBaseDir: missing 'name' field");
            };
            let dir = registry.data_base_dir(name);
            serde_json::json!({ "dir": dir }).to_string()
        }

        "ResolveHostBaseDir" => {
            let Some(name) = req.args.get("name").and_then(|v| v.as_str()) else {
                return error_response("ResolveHostBaseDir: missing 'name' field");
            };
            let remote = req
                .args
                .get("remote")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let dir = registry.resolve_host_base_dir(name, remote);
            serde_json::json!({ "dir": dir }).to_string()
        }

        "HasCleanup" => {
            let Some(name) = req.args.get("name").and_then(|v| v.as_str()) else {
                return error_response("HasCleanup: missing 'name' field");
            };
            let has_cleanup = registry.has_cleanup(name);
            serde_json::json!({ "has_cleanup": has_cleanup }).to_string()
        }

        other => error_response(&format!("unknown command: {other}")),
    }
}

fn error_response(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}
