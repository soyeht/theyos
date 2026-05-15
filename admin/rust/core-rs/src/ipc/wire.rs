//! IPC wire types — shared across all IPC binaries.
//!
//! Protocol: one JSON object per line on stdin, one JSON response per line on stdout.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;

/// Incoming JSON-RPC request.
#[derive(Debug, Deserialize)]
pub struct Request {
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// Outgoing JSON-RPC response.
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Structured diagnostic context for errors (phase, command, `exit_code`,
    /// `stderr_tail`, `serial_log_tail`, etc.). Optional — absent on success and
    /// on errors that don't carry structured context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_context: Option<Value>,
}

impl Response {
    /// Success response with a result payload.
    #[must_use]
    pub fn ok(result: Value) -> Self {
        Response {
            ok: true,
            result: Some(result),
            error: None,
            error_context: None,
        }
    }

    /// Success response with no result payload.
    #[must_use]
    pub fn ok_empty() -> Self {
        Response {
            ok: true,
            result: None,
            error: None,
            error_context: None,
        }
    }

    /// Error response — plain string message, no structured context.
    pub fn err(msg: impl std::fmt::Display) -> Self {
        Response {
            ok: false,
            result: None,
            error: Some(msg.to_string()),
            error_context: None,
        }
    }

    /// Error response with structured diagnostic context serialized as JSON.
    pub fn err_with_context(msg: impl std::fmt::Display, context: Value) -> Self {
        Response {
            ok: false,
            result: None,
            error: Some(msg.to_string()),
            error_context: Some(context),
        }
    }

    /// Error response with a machine-readable numeric error code.
    ///
    /// The code is encoded in `error_context.code` so callers can dispatch
    /// on specific error conditions (e.g. `MACOS_VM_LIMIT_REACHED = 2001`).
    pub fn err_code(code: u32, msg: impl std::fmt::Display) -> Self {
        Self::err_with_context(msg, serde_json::json!({ "code": code }))
    }
}

/// Write a response as a single JSON line to the output.
///
/// # Errors
///
/// Returns an error if serialization or writing to the output stream fails.
pub fn write_response(out: &mut impl Write, resp: &Response) -> std::io::Result<()> {
    serde_json::to_writer(&mut *out, resp)?;
    out.write_all(b"\n")?;
    out.flush()
}
