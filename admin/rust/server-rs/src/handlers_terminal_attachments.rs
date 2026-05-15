//! Attachment upload handler.
//!
//!   POST /api/v1/terminals/{container}/attachments → `handle_upload_attachment`

use axum::Json;
use axum::extract::{Multipart, Path, State};
use core_rs::error::ApiError;
use serde_json::json;
use std::io::Write;
use std::time::SystemTime;

use crate::auth::AuthUser;
use crate::handlers_terminal::{require_terminal_access, validate_container, verify_session_owner};
use crate::state::SharedState;

/// Maximum upload size enforced at the application level (100 MB).
const MAX_UPLOAD_SIZE: usize = 100 * 1024 * 1024;

/// Valid attachment kinds.
const VALID_KINDS: &[&str] = &["media", "document", "file", "location"];

/// Handle a multipart file upload to a claw's ~/Downloads directory.
///
/// Field order is enforced: `session` → `kind` → `filename` → `file`.
/// The handler rejects the request if `file` arrives before `session`
/// to ensure ownership is validated before writing temp data.
///
/// # Errors
///
/// Returns [`ApiError`] on multipart parse error, invalid field values,
/// file size limit exceeded, temp file I/O failure, or SSH upload failure.
#[allow(clippy::too_many_lines)]
pub async fn handle_upload_attachment(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(container): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, ApiError> {
    let container = validate_container(&container)?;
    require_terminal_access(&state, &auth, &container).await?;

    // -- Parse multipart fields in strict order --
    let mut session: Option<String> = None;
    let mut kind: Option<String> = None;
    let mut filename: Option<String> = None;
    let mut temp_file: Option<tempfile::NamedTempFile> = None;
    let mut file_size: usize = 0;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(format!("multipart error: {e}")))?
    {
        let field_name = field
            .name()
            .ok_or_else(|| ApiError::bad_request("unnamed field"))?
            .to_string();

        match field_name.as_str() {
            "session" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(format!("session field: {e}")))?;
                if text.is_empty() {
                    return Err(ApiError::bad_request("session is required"));
                }
                session = Some(text);
            }
            "kind" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(format!("kind field: {e}")))?;
                if !VALID_KINDS.contains(&text.as_str()) {
                    return Err(ApiError::bad_request(format!(
                        "invalid kind '{}', expected one of: {}",
                        text,
                        VALID_KINDS.join(", ")
                    )));
                }
                kind = Some(text);
            }
            "filename" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(format!("filename field: {e}")))?;
                filename = Some(text);
            }
            "file" => {
                // Reject if session hasn't been parsed yet
                if session.is_none() {
                    return Err(ApiError::bad_request(
                        "field order violation: session must come before file",
                    ));
                }

                // Stream chunks to temp file
                let mut tmp = tempfile::NamedTempFile::new()
                    .map_err(|e| ApiError::internal(format!("create temp file: {e}")))?;

                let mut chunk_stream = field;
                while let Some(chunk) = chunk_stream
                    .chunk()
                    .await
                    .map_err(|e| ApiError::bad_request(format!("file read: {e}")))?
                {
                    file_size += chunk.len();
                    if file_size > MAX_UPLOAD_SIZE {
                        return Err(ApiError::bad_request("file exceeds 100 MB limit"));
                    }
                    tmp.write_all(&chunk)
                        .map_err(|e| ApiError::internal(format!("write temp file: {e}")))?;
                }
                tmp.flush()
                    .map_err(|e| ApiError::internal(format!("flush temp file: {e}")))?;
                temp_file = Some(tmp);
            }
            _ => {
                // Skip unknown fields
            }
        }
    }

    // -- Validate required fields --
    let session = session.ok_or_else(|| ApiError::bad_request("session is required"))?;
    let kind = kind.ok_or_else(|| ApiError::bad_request("kind is required"))?;
    let temp_file = temp_file.ok_or_else(|| ApiError::bad_request("file is required"))?;

    // -- Verify session ownership (returns 404, not 403) --
    verify_session_owner(&state, &session, &container, &auth.username).await?;

    // -- Sanitize filename --
    let raw_name = filename.unwrap_or_default();
    let sanitized = sanitize_filename(&raw_name);

    // -- Map kind to subfolder name --
    let subfolder = match kind.as_str() {
        "media" => "Photos",
        "document" => "Documents",
        "location" => "Location",
        _ => "Files",
    };

    // -- Upload to claw via SSH --
    let remote_path = state
        .vm_runner
        .upload_file_to_downloads(&container, temp_file.path(), subfolder, &sanitized)
        .await
        .map_err(|e| ApiError::internal(format!("upload to claw: {e}")))?;

    tracing::info!(
        container = %container,
        session = %session,
        kind = %kind,
        filename = %sanitized,
        size = file_size,
        "attachment uploaded"
    );

    Ok(Json(json!({
        "attachment": {
            "filename": sanitized,
            "kind": kind,
            "size_bytes": file_size,
            "remote_path": remote_path,
            "uploaded_at": iso8601_now(),
        }
    })))
}

/// Sanitize a filename to contain only `[A-Za-z0-9._-]` characters.
///
/// Preserves the original extension. Falls back to a timestamp-based name
/// if the result would be empty.
fn sanitize_filename(raw: &str) -> String {
    let path = std::path::Path::new(raw);
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("bin");
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");

    // Keep only safe ASCII characters
    let safe_stem: String = stem
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect();

    let safe_ext: String = ext
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.')
        .collect();

    let final_stem = if safe_stem.is_empty() {
        let secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("attachment-{secs}")
    } else {
        safe_stem
    };

    if safe_ext.is_empty() {
        final_stem
    } else {
        format!("{final_stem}.{safe_ext}")
    }
}

/// ISO 8601 timestamp from system clock (no chrono dependency needed).
#[allow(clippy::many_single_char_names)]
fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple UTC timestamp — good enough for API responses
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    // Approximate date from days since epoch (no leap-second precision needed)
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(days_since_epoch: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's date library (public domain).
    let z = days_since_epoch + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
