//! Append-only audit log for every LLM request that flows through the
//! proxy.
//!
//! Records are emitted at request-completion time as one JSON object per
//! line (JSONL) into a configurable file. The schema is:
//!
//! ```json
//! {
//!   "ts":            "2026-05-17T12:34:56.789Z",   // RFC3339 UTC
//!   "provider":      "anthropic",                   // matches catalog id
//!   "claw_type":     "openclaw",                    // null on default route
//!   "model":         "claude-opus-4-7",             // from request body
//!   "stream":        true,
//!   "status":        "ok",                          // "ok" | "error"
//!   "error_kind":    null,                          // ProxyError::kind() when status=error
//!   "latency_ms":    1247,
//!   "input_tokens":  null,                          // populated when upstream returns usage
//!   "output_tokens": null
//! }
//! ```
//!
//! ## What's intentionally NOT logged
//!
//! - Prompts / message contents — the audit log lives on disk; including
//!   prompts would defeat the "credentials never leave the host" posture
//!   we maintain everywhere else (a malicious actor with disk read would
//!   recover entire conversations).
//! - API keys — these are in the keystore; they never enter the audit
//!   path.
//!
//! ## Threading
//!
//! [`AuditLogger`] is `Send + Sync + Clone`. Clones share the same
//! underlying file handle through an `Arc<Mutex<...>>`. Writes are
//! line-flushed so a crash mid-stream leaves the file in a parseable
//! state (the last record is either fully present or fully absent).

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct AuditLogger {
    inner: Option<Arc<AuditInner>>,
}

struct AuditInner {
    path: PathBuf,
    file: Mutex<File>,
}

impl AuditLogger {
    /// Build a logger that writes to `path` in append mode. Creates
    /// missing parent directories. Returns a disabled logger if `path`
    /// is `None`.
    pub fn open(path: Option<&Path>) -> std::io::Result<Self> {
        let Some(path) = path else {
            return Ok(Self { inner: None });
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            inner: Some(Arc::new(AuditInner {
                path: path.to_path_buf(),
                file: Mutex::new(file),
            })),
        })
    }

    /// A no-op logger for tests and the "disabled" production case.
    #[must_use]
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    /// True when the logger will actually write — useful in tests.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Read up to `limit` audit records, newest-first. When `before` is
    /// `Some`, only records strictly older than that timestamp (string
    /// comparison on the ISO-8601-formatted `ts` field — RFC3339 sorts
    /// lexicographically) are returned.
    ///
    /// Implementation reads the whole file (JSONL is line-delimited so
    /// no streaming partial-record concerns) and reverses in memory.
    /// Acceptable for v1 — operators reviewing the admin UI scroll
    /// through hundreds of records, not millions; the audit file is
    /// truncated/rotated by external tooling well before scan latency
    /// becomes a problem. A streaming tail-reader is a v1.x improvement
    /// once we see real audit-file sizes in production.
    ///
    /// Returns an empty vec when the logger is disabled or the file
    /// hasn't been created yet (no records ever written).
    pub fn read_paginated(
        &self,
        limit: usize,
        before: Option<&str>,
    ) -> std::io::Result<Vec<AuditRecord>> {
        let Some(inner) = &self.inner else {
            return Ok(Vec::new());
        };
        let file = match File::open(&inner.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut records: Vec<AuditRecord> = BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter(|l| !l.trim().is_empty())
            .filter_map(|line| match serde_json::from_str::<AuditRecord>(&line) {
                Ok(r) => Some(r),
                Err(e) => {
                    // Skip truncated / non-JSON lines without failing
                    // the whole request — partial writes can happen if
                    // the process was killed mid-record.
                    tracing::warn!(error = %e, "audit line not parseable; skipping");
                    None
                }
            })
            .collect();
        // Newest first.
        records.sort_by(|a, b| b.ts.cmp(&a.ts));
        if let Some(cutoff) = before {
            records.retain(|r| r.ts.as_str() < cutoff);
        }
        records.truncate(limit);
        Ok(records)
    }

    /// Append `record` to the log. Best-effort: on disk-full / permission
    /// errors we log a `tracing::warn` and DROP the record. The proxy must
    /// not fail a request because audit is broken.
    pub fn write(&self, record: &AuditRecord) {
        let Some(inner) = &self.inner else {
            return;
        };
        let line = match serde_json::to_string(record) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "audit record serialise failed");
                return;
            }
        };
        match inner.file.lock() {
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "{line}") {
                    tracing::warn!(error = %e, path = %inner.path.display(), "audit write failed");
                }
            }
            Err(_) => {
                tracing::warn!("audit mutex poisoned; skipping record");
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// RFC3339 timestamp, UTC, millisecond precision.
    pub ts: String,
    pub provider: String,
    /// `null` when the request hit the default (no-claw-stamp) route.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claw_type: Option<String>,
    pub model: String,
    pub stream: bool,
    pub status: AuditStatus,
    /// Set when `status` is `error` — matches `ProxyError::kind()`.
    /// Owned `String` rather than `&'static str` so deserialisation (e.g.
    /// reading the log file back) works without lifetime gymnastics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    pub latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditStatus {
    Ok,
    Error,
}

impl AuditRecord {
    /// Build a record stamped with the current time.
    #[must_use]
    pub fn now(
        provider: impl Into<String>,
        claw_type: Option<&str>,
        model: impl Into<String>,
        stream: bool,
        status: AuditStatus,
        error_kind: Option<&str>,
        latency_ms: u64,
    ) -> Self {
        Self {
            ts: now_rfc3339(),
            provider: provider.into(),
            claw_type: claw_type.map(String::from),
            model: model.into(),
            stream,
            status,
            error_kind: error_kind.map(String::from),
            latency_ms,
            input_tokens: None,
            output_tokens: None,
        }
    }
}

fn now_rfc3339() -> String {
    // Avoid pulling in chrono just for one timestamp; format ISO 8601 by
    // hand. Resolution is millisecond, UTC, with Z suffix.
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let (year, month, day, hour, minute, second) = epoch_to_ymdhms(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Convert a Unix timestamp to `(year, month, day, hour, minute, second)`
/// using the proleptic Gregorian calendar. Good enough for audit records
/// — no leap-second handling, but no leap-second loss either.
fn epoch_to_ymdhms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let second = (secs % 60) as u32;
    let total_minutes = secs / 60;
    let minute = (total_minutes % 60) as u32;
    let total_hours = total_minutes / 60;
    let hour = (total_hours % 24) as u32;
    let mut days = total_hours / 24;

    // 1970-01-01 was a Thursday — we don't actually need the day-of-week.
    let mut year: u32 = 1970;
    loop {
        let in_year = if is_leap(year) { 366 } else { 365 };
        if days < in_year {
            break;
        }
        days -= in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let months: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month: u32 = 1;
    for m_len in months {
        if days < m_len {
            break;
        }
        days -= m_len;
        month += 1;
    }
    // `days` is the residual day-within-month, always 0..31 — safe to
    // truncate u64 → u32. Use `try_from` so clippy is satisfied without
    // an `as` cast.
    let day = u32::try_from(days).unwrap_or(0) + 1;
    (year, month, day, hour, minute, second)
}

fn is_leap(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn disabled_logger_silently_drops_records() {
        let logger = AuditLogger::disabled();
        assert!(!logger.is_enabled());
        // Just verify no panic and no file is touched.
        logger.write(&AuditRecord::now(
            "test",
            None,
            "model",
            false,
            AuditStatus::Ok,
            None,
            42,
        ));
    }

    #[test]
    fn enabled_logger_writes_one_jsonl_line_per_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let logger = AuditLogger::open(Some(&path)).unwrap();
        assert!(logger.is_enabled());
        logger.write(&AuditRecord::now(
            "anthropic",
            Some("openclaw"),
            "claude-opus-4-7",
            true,
            AuditStatus::Ok,
            None,
            1234,
        ));
        logger.write(&AuditRecord::now(
            "anthropic",
            Some("hermes-agent"),
            "claude-opus-4-7",
            false,
            AuditStatus::Error,
            Some("proxy.upstream"),
            500,
        ));

        let raw = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 records, got {}", lines.len());

        let r1: AuditRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(r1.provider, "anthropic");
        assert_eq!(r1.claw_type.as_deref(), Some("openclaw"));
        assert_eq!(r1.status, AuditStatus::Ok);
        assert_eq!(r1.latency_ms, 1234);
        assert!(r1.error_kind.is_none());

        let r2: AuditRecord = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(r2.status, AuditStatus::Error);
        assert_eq!(r2.error_kind.as_deref(), Some("proxy.upstream"));
    }

    #[test]
    fn concurrent_writes_do_not_interleave_lines() {
        // The audit log is shared across request handlers; lines must
        // come out fully written, never split across threads.
        let dir = tempdir().unwrap();
        let path = dir.path().join("concurrent.log");
        let logger = AuditLogger::open(Some(&path)).unwrap();

        let n: u32 = 64;
        let handles: Vec<_> = (0..n)
            .map(|i| {
                let logger = logger.clone();
                std::thread::spawn(move || {
                    logger.write(&AuditRecord::now(
                        format!("p{i}"),
                        Some("openclaw"),
                        "m",
                        false,
                        AuditStatus::Ok,
                        None,
                        u64::from(i),
                    ));
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let raw = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), n as usize);
        for line in lines {
            // Every line must parse — interleaving would break this.
            let _: AuditRecord = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("malformed audit line: {line}\nerror: {e}"));
        }
    }

    #[test]
    fn record_omits_optional_fields_when_unset() {
        let r = AuditRecord::now("p", None, "m", false, AuditStatus::Ok, None, 1);
        let json = serde_json::to_string(&r).unwrap();
        // Optional fields with None must not appear in the JSON; the
        // schema documented above lists them as null but we elide them
        // to keep the log file small and grep-friendly.
        assert!(!json.contains("claw_type"), "claw_type leaked: {json}");
        assert!(!json.contains("error_kind"), "error_kind leaked: {json}");
        assert!(!json.contains("input_tokens"), "input_tokens leaked: {json}");
        assert!(!json.contains("output_tokens"), "output_tokens leaked: {json}");
    }

    #[test]
    fn timestamp_is_rfc3339_utc_with_millisecond_precision() {
        let r = AuditRecord::now("p", None, "m", false, AuditStatus::Ok, None, 1);
        // YYYY-MM-DDTHH:MM:SS.mmmZ — 24 characters.
        assert_eq!(r.ts.len(), 24, "unexpected ts shape: {}", r.ts);
        assert!(r.ts.ends_with('Z'), "missing Z: {}", r.ts);
        assert!(r.ts.contains('T'), "missing T: {}", r.ts);
        let year: u32 = r.ts[..4].parse().unwrap();
        // Sanity bounds — way past 2025, not in the year 10000.
        assert!((2024..3000).contains(&year), "year out of bounds: {year}");
    }

    #[test]
    #[allow(clippy::many_single_char_names)] // matches the tuple's field semantics (y, m, d, h, mi, s)
    fn ymdhms_conversion_matches_known_dates() {
        // 1970-01-01T00:00:00Z exact.
        let (y, m, d, h, mi, s) = epoch_to_ymdhms(0);
        assert_eq!((y, m, d, h, mi, s), (1970, 1, 1, 0, 0, 0));

        // 2000-02-29T00:00:00Z (leap day) — Y=2000, leap=true;
        // epoch = 951_782_400.
        let (y, m, d, _, _, _) = epoch_to_ymdhms(951_782_400);
        assert_eq!((y, m, d), (2000, 2, 29));

        // 2020-01-01T12:34:56Z; verify hours/minutes/seconds too.
        // 2020-01-01T00:00:00Z is epoch 1_577_836_800 (50 years × 365 +
        // 13 leap days from 1972..2020). 12*3600 + 34*60 + 56 = 45_296.
        let (y, m, d, h, mi, s) = epoch_to_ymdhms(1_577_836_800 + 45_296);
        assert_eq!((y, m, d, h, mi, s), (2020, 1, 1, 12, 34, 56));

        // Round-trip a recent timestamp through SystemTime to be sure the
        // function lines up with the live wall clock without us hard-
        // coding a value that drifts (the original test had this bug).
        let now_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (y, _, _, _, _, _) = epoch_to_ymdhms(now_secs);
        assert!((2024..3000).contains(&y), "wall-clock year out of bounds: {y}");
    }
}
