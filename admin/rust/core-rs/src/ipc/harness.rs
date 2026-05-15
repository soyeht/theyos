//! IPC harness — `run_ipc_loop` eliminates ~80 lines of boilerplate per binary.

use super::wire::{Request, Response, write_response};
use serde_json::json;
use std::io::{self, BufRead};

#[cfg(feature = "async-ipc")]
use tokio::io::AsyncBufReadExt;

/// Run the standard IPC main loop.
///
/// Reads JSON-RPC requests from stdin, dispatches them via `dispatcher`,
/// and writes responses to stdout. Handles `Ping` automatically.
///
/// # Arguments
///
/// - `name`: binary name for log messages (e.g. `"store-ipc"`)
/// - `dispatcher`: `FnMut(&str, &serde_json::Value) -> Response` that handles
///   each method call. Return `Response::err(...)` for unknown methods.
pub fn run_ipc_loop<F>(name: &str, mut dispatcher: F)
where
    F: FnMut(&str, &serde_json::Value) -> Response,
{
    eprintln!("[{name}] ready for requests");

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };

        if line.trim().is_empty() {
            continue;
        }

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::err(format!("invalid request JSON: {e}"));
                let _ = write_response(&mut out, &resp);
                continue;
            }
        };

        let resp = if req.method == "Ping" {
            Response::ok(json!({"pong": true}))
        } else {
            dispatcher(&req.method, &req.params)
        };

        if write_response(&mut out, &resp).is_err() {
            break;
        }
    }

    eprintln!("[{name}] stdin closed, exiting");
}

/// Run the standard IPC main loop with an init phase.
///
/// Same as `run_ipc_loop` but calls `init` first with the parsed command-line
/// args, allowing the binary to set up state before entering the dispatch loop.
pub fn run_ipc_loop_with_init<S, I, F>(name: &str, init: I, mut dispatcher: F)
where
    I: FnOnce(&[String]) -> S,
    F: FnMut(&S, &str, &serde_json::Value) -> Response,
{
    let args: Vec<String> = std::env::args().collect();
    let state = init(&args);

    eprintln!("[{name}] ready for requests");

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };

        if line.trim().is_empty() {
            continue;
        }

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::err(format!("invalid request JSON: {e}"));
                let _ = write_response(&mut out, &resp);
                continue;
            }
        };

        let resp = if req.method == "Ping" {
            Response::ok(json!({"pong": true}))
        } else {
            dispatcher(&state, &req.method, &req.params)
        };

        if write_response(&mut out, &resp).is_err() {
            break;
        }
    }

    eprintln!("[{name}] stdin closed, exiting");
}

// ── Async variant (requires `async-ipc` feature → tokio) ──────────────

/// Async version of [`run_ipc_loop`] for binaries that need `.await` in
/// their dispatcher (e.g. vmrunner-ipc calling async `VmRunner` methods).
///
/// Same JSON-RPC-over-stdio protocol as the sync variant: one JSON object
/// per line on stdin, one JSON response per line on stdout, with automatic
/// `Ping → Pong` handling.
///
/// # Arguments
///
/// - `name`: binary name for log messages (e.g. `"vmrunner-ipc"`)
/// - `dispatcher`: async function `(&str, &serde_json::Value) -> Response`
#[cfg(feature = "async-ipc")]
pub async fn run_ipc_loop_async<F, Fut>(name: &str, mut dispatcher: F)
where
    F: FnMut(&str, &serde_json::Value) -> Fut,
    Fut: std::future::Future<Output = Response>,
{
    eprintln!("[{name}] ready for requests (async)");

    let stdin = tokio::io::stdin();
    let mut reader = tokio::io::BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break, // EOF or read error
            Ok(_) => {}
        }

        if line.trim().is_empty() {
            continue;
        }

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::err(format!("invalid request JSON: {e}"));
                if async_write_response(&mut stdout, &resp).await.is_err() {
                    break;
                }
                continue;
            }
        };

        let resp = if req.method == "Ping" {
            Response::ok(json!({"pong": true}))
        } else {
            dispatcher(&req.method, &req.params).await
        };

        if async_write_response(&mut stdout, &resp).await.is_err() {
            break;
        }
    }

    eprintln!("[{name}] stdin closed, exiting");
}

// ── CLI arg helpers ───────────────────────────────────────────────────

/// Parse a `--key value` pair from a CLI arg slice.
///
/// Four IPC binaries use the same `args.windows(2)` idiom to extract
/// `--db-path`, `--admin-url`, etc.  This function consolidates that
/// pattern.
///
/// ```ignore
/// let db_path = parse_arg(args, "--db-path").unwrap_or_else(|| {
///     eprintln!("usage: my-ipc --db-path <path>");
///     std::process::exit(1);
/// });
/// ```
#[must_use]
pub fn parse_arg(args: &[String], key: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == key).map(|w| w[1].clone())
}

/// Parse a required `--key value` pair, exiting with a usage message if
/// absent.
///
/// `binary_name` is used in the error message.
#[must_use]
pub fn require_arg(args: &[String], key: &str, binary_name: &str) -> String {
    parse_arg(args, key).unwrap_or_else(|| {
        eprintln!("[{binary_name}] missing required argument: {key}");
        std::process::exit(1);
    })
}

/// Write a JSON response line to an async writer.
#[cfg(feature = "async-ipc")]
async fn async_write_response(out: &mut tokio::io::Stdout, resp: &Response) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let bytes = serde_json::to_vec(resp).map_err(std::io::Error::other)?;
    out.write_all(&bytes).await?;
    out.write_all(b"\n").await?;
    out.flush().await
}
