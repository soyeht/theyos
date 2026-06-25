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

/// JSON-RPC request envelope.
///
/// `Serialize` so the IPC client can build it via [`Request::new`] instead of an
/// inline `json!` literal.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub method: String,
    #[serde(default)]
    pub params: Value,
    /// Optional additive protocol version (P2). Absent on legacy wire and NOT
    /// emitted by the default sender — `skip_serializing_if` keeps the
    /// no-version serialization byte-identical to the pre-P2
    /// `{"method","params"}` object. Declared last so the field order matches
    /// the legacy form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
}

impl Request {
    /// Build a request envelope with no protocol version. Serializing it is
    /// byte-identical to the legacy `{"method", "params"}` wire form.
    #[must_use]
    pub fn new(method: impl Into<String>, params: Value) -> Self {
        Request {
            method: method.into(),
            params,
            version: None,
        }
    }

    /// Attach an explicit protocol version. NOT used by the default sender (P2
    /// is plumb-only); available for a future opt-in.
    #[must_use]
    pub fn with_version(mut self, version: u32) -> Self {
        self.version = Some(version);
        self
    }
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

/// Extract the machine-readable numeric error code from an IPC error context,
/// if present. Strict: only an in-range `u32` JSON number is accepted - strings,
/// floats, garbage, or out-of-range values yield `None` (no permissive parse).
#[must_use]
pub fn ipc_code_from_context(error_context: &Option<Value>) -> Option<u32> {
    error_context
        .as_ref()
        .and_then(|ctx| ctx.get(ERROR_CODE_FIELD))
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
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
    use crate::ipc::protocol::PROTOCOL_VERSION;
    use serde_json::json;

    // ── P2: additive request envelope versioning ────────────────────────────

    #[test]
    fn request_without_version_serializes_byte_identical_to_legacy() {
        let req = Request::new("Create", json!({"a": 1}));
        let got = serde_json::to_string(&req).unwrap();
        // Exactly the pre-P2 inline `json!({"method","params"})` bytes.
        let legacy =
            serde_json::to_string(&json!({"method": "Create", "params": {"a": 1}})).unwrap();
        assert_eq!(got, legacy);
        assert_eq!(got, r#"{"method":"Create","params":{"a":1}}"#);
    }

    #[test]
    fn request_with_version_round_trips() {
        let req = Request::new("Stop", json!({})).with_version(PROTOCOL_VERSION);
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains(r#""version":1"#), "serialized: {s}");
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(back.method, "Stop");
        assert_eq!(back.version, Some(PROTOCOL_VERSION));
    }

    #[test]
    fn legacy_request_without_version_parses_as_none() {
        let back: Request =
            serde_json::from_str(r#"{"method":"Delete","params":{"id":"x"}}"#).unwrap();
        assert_eq!(back.method, "Delete");
        assert_eq!(back.params, json!({"id": "x"}));
        assert_eq!(back.version, None);
    }

    #[test]
    fn versioned_request_parses_as_some() {
        let back: Request =
            serde_json::from_str(r#"{"method":"Delete","params":{},"version":1}"#).unwrap();
        assert_eq!(back.version, Some(1));
    }

    #[test]
    fn unknown_extra_field_is_tolerated() {
        // No `deny_unknown_fields` → forward-compatible receive.
        let back: Request = serde_json::from_str(
            r#"{"method":"Delete","params":{},"version":2,"future_field":"ignored"}"#,
        )
        .unwrap();
        assert_eq!(back.method, "Delete");
        assert_eq!(back.version, Some(2));
    }

    #[test]
    fn request_missing_params_still_defaults() {
        let back: Request = serde_json::from_str(r#"{"method":"Ping"}"#).unwrap();
        assert_eq!(back.method, "Ping");
        assert_eq!(back.params, Value::Null);
        assert_eq!(back.version, None);
    }

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

    #[test]
    fn ipc_code_from_context_accepts_only_in_range_u32() {
        assert_eq!(
            ipc_code_from_context(&Some(json!({"code": 2001}))),
            Some(2001)
        );
        // Absent context / absent code.
        assert_eq!(ipc_code_from_context(&None), None);
        assert_eq!(ipc_code_from_context(&Some(json!({"phase": "x"}))), None);
        // No permissive parse: a string code is rejected.
        assert_eq!(ipc_code_from_context(&Some(json!({"code": "2001"}))), None);
        // Floats and negatives are not u32 integers.
        assert_eq!(ipc_code_from_context(&Some(json!({"code": 2001.5}))), None);
        assert_eq!(ipc_code_from_context(&Some(json!({"code": -1}))), None);
        // Out of u32 range.
        assert_eq!(
            ipc_code_from_context(&Some(json!({"code": 5_000_000_000u64}))),
            None
        );
    }
}
