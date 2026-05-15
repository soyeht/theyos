//! Polling helpers — consolidated wait-for-path/socket patterns.
//!
//! Four crates independently implemented "poll until a filesystem path appears"
//! with varying intervals and error handling. This module provides a single
//! configurable entry point.

use std::path::Path;
use std::time::{Duration, Instant};

/// Poll until a filesystem path exists, or timeout.
///
/// Checks `path.exists()` every `interval`, returning `Ok(())` the moment the
/// path appears. Returns `Err(elapsed)` if the deadline passes first.
///
/// # Errors
///
/// Returns `Err(elapsed)` if the path does not appear within `timeout`.
///
/// # Panics
///
/// Panics if `deadline < timeout` (should never happen since `deadline = now + timeout`).
///
/// # Examples
///
/// ```ignore
/// // Wait up to 15s for a Unix socket to appear, checking every 25ms
/// poll_until_exists_async(path, Duration::from_secs(15), Duration::from_millis(25)).await?;
/// ```
#[cfg(feature = "async-ipc")]
pub async fn poll_until_exists_async(
    path: &Path,
    timeout: Duration,
    interval: Duration,
) -> Result<(), Duration> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(deadline.checked_sub(timeout).unwrap().elapsed());
        }
        tokio::time::sleep(interval).await;
    }
}

/// Synchronous version of [`poll_until_exists_async`].
///
/// # Errors
///
/// Returns `Err(elapsed)` if the path does not appear within `timeout`.
pub fn poll_until_exists(
    path: &Path,
    timeout: Duration,
    interval: Duration,
) -> Result<(), Duration> {
    let start = Instant::now();
    let deadline = start + timeout;
    loop {
        if path.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(start.elapsed());
        }
        std::thread::sleep(interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_existing_path_returns_immediately() {
        // /tmp always exists
        let result = poll_until_exists(
            Path::new("/tmp"),
            Duration::from_millis(100),
            Duration::from_millis(10),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn poll_missing_path_returns_elapsed() {
        let result = poll_until_exists(
            Path::new("/nonexistent/__core_rs_poll_test__"),
            Duration::from_millis(50),
            Duration::from_millis(10),
        );
        assert!(result.is_err());
        let elapsed = result.unwrap_err();
        assert!(elapsed >= Duration::from_millis(50));
    }

    #[cfg(feature = "async-ipc")]
    #[tokio::test]
    async fn poll_async_existing_path() {
        let result = poll_until_exists_async(
            Path::new("/tmp"),
            Duration::from_millis(100),
            Duration::from_millis(10),
        )
        .await;
        assert!(result.is_ok());
    }

    #[cfg(feature = "async-ipc")]
    #[tokio::test]
    async fn poll_async_missing_path_times_out() {
        let result = poll_until_exists_async(
            Path::new("/nonexistent/__core_rs_poll_test__"),
            Duration::from_millis(50),
            Duration::from_millis(10),
        )
        .await;
        assert!(result.is_err());
    }
}
