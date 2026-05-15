//! Date/time helpers used by instance handlers.
//!
//! Delegates to core-rs for the actual implementation.

/// Current unix timestamp in seconds, refusing clocks before the Unix epoch.
pub(crate) fn unix_now_secs_checked(stage: &'static str) -> Option<u64> {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => Some(d.as_secs()),
        Err(e) => {
            tracing::warn!(
                stage = stage,
                error = %e,
                "system clock is before UNIX_EPOCH"
            );
            None
        }
    }
}

/// Format a unix timestamp as "YYYY-MM-DD" for `sunset_date`.
pub(crate) fn format_date(unix_secs: u64) -> String {
    core_rs::time::format_date(unix_secs)
}
