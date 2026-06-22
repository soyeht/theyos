//! IPC wire types — shared across all IPC binaries.
//!
//! Protocol: one JSON object per line on stdin, one JSON response per line on stdout.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::io::Write;

/// JSON field that carries structured diagnostic context on IPC errors.
pub const ERROR_CONTEXT_FIELD: &str = "error_context";

/// JSON field inside [`ERROR_CONTEXT_FIELD`] for machine-readable numeric codes.
pub const ERROR_CODE_FIELD: &str = "code";

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
        Self::err_with_context(msg, error_code_context(code))
    }
}

/// Build the structured IPC error context for a numeric machine-readable code.
#[must_use]
pub fn error_code_context(code: u32) -> Value {
    let mut context = Map::new();
    context.insert(ERROR_CODE_FIELD.to_string(), Value::from(code));
    Value::Object(context)
}

/// Wrap an IPC error context under the canonical `error_context` field.
#[must_use]
pub fn error_context_result(context: Value) -> Value {
    let mut result = Map::new();
    result.insert(ERROR_CONTEXT_FIELD.to_string(), context);
    Value::Object(result)
}

/// Serialize an IPC error context result wrapper for storage in job results.
#[must_use]
pub fn error_context_result_string(context: Value) -> String {
    serde_json::to_string(&error_context_result(context)).unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn err_code_preserves_current_context_shape() {
        let response = serde_json::to_value(Response::err_code(2001, "limit")).unwrap();

        assert_eq!(
            response,
            json!({
                "ok": false,
                "error": "limit",
                "error_context": {
                    "code": 2001
                }
            })
        );
    }

    #[test]
    fn error_context_result_preserves_job_result_shape() {
        assert_eq!(
            error_context_result(json!({"phase": "vm_boot"})),
            json!({
                "error_context": {
                    "phase": "vm_boot"
                }
            })
        );
    }
}
