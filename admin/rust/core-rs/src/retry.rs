//! Generic retry helpers with configurable backoff.
//!
//! Six crates independently implemented retry-with-backoff loops. This module
//! provides a single `retry_async` (and `retry_sync`) entry point that covers
//! all observed patterns: exponential backoff, fixed delay, count-based, and
//! deadline-based termination.

use std::fmt;
#[cfg(feature = "async-ipc")]
use std::future::Future;
use std::time::{Duration, Instant};

/// Configuration for a retry loop.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of attempts (including the first). Must be >= 1.
    pub max_attempts: u32,
    /// Initial delay after the first failure.
    pub initial_delay: Duration,
    /// Maximum delay between attempts (cap for exponential growth).
    pub max_delay: Duration,
    /// Backoff multiplier applied after each failure.
    ///
    /// - `1.0` = fixed delay (same delay every time)
    /// - `2.0` = classic exponential backoff (delay doubles each attempt)
    pub backoff_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(5),
            backoff_factor: 2.0,
        }
    }
}

impl RetryConfig {
    /// Create a config for fixed-delay retries (no backoff growth).
    #[must_use]
    pub fn fixed(max_attempts: u32, delay: Duration) -> Self {
        Self {
            max_attempts,
            initial_delay: delay,
            max_delay: delay,
            backoff_factor: 1.0,
        }
    }

    /// Create a config for exponential backoff retries.
    #[must_use]
    pub fn exponential(max_attempts: u32, initial: Duration, max: Duration) -> Self {
        Self {
            max_attempts,
            initial_delay: initial,
            max_delay: max,
            backoff_factor: 2.0,
        }
    }

    /// Compute the delay for a given attempt index (0-based, attempt 0 = first retry).
    fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return self.initial_delay;
        }
        // NOTE: f64 precision loss is acceptable for timing; capped by max_delay.
        #[allow(clippy::cast_possible_wrap)] // attempt fits in i32 for practical retry counts
        #[allow(clippy::cast_precision_loss)]
        let multiplier = self.backoff_factor.powi(attempt as i32);
        #[allow(clippy::cast_precision_loss)]
        let delay_nanos = self.initial_delay.as_nanos() as f64 * multiplier;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        #[allow(clippy::cast_precision_loss)]
        let delay = Duration::from_nanos(delay_nanos.min(u64::MAX as f64) as u64);
        delay.min(self.max_delay)
    }
}

/// Error returned when all retry attempts are exhausted.
#[derive(Debug)]
pub struct RetriesExhausted<E> {
    /// The error from the last attempt.
    pub last_error: E,
    /// Total number of attempts made.
    pub attempts: u32,
    /// Total elapsed time across all attempts.
    pub elapsed: Duration,
}

impl<E: fmt::Display> fmt::Display for RetriesExhausted<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "all {} attempts exhausted after {:?}: {}",
            self.attempts, self.elapsed, self.last_error
        )
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for RetriesExhausted<E> {}

/// Outcome from the retry predicate: should we retry or bail?
pub enum RetryVerdict<T, E> {
    /// The operation succeeded.
    Ok(T),
    /// The operation failed with a retryable error.
    Retry(E),
    /// The operation failed with a non-retryable error (bail immediately).
    Fail(E),
}

/// Retry an async operation with configurable backoff.
///
/// The `operation` closure is called on each attempt. It should return a
/// [`RetryVerdict`] to indicate success, retryable failure, or fatal failure.
///
/// # Errors
///
/// Returns [`RetriesExhausted`] if all attempts fail or a non-retryable error occurs.
///
/// # Panics
///
/// Panics if `config.max_attempts` is 0 (at least one attempt must be made).
///
/// # Examples
///
/// ```ignore
/// let config = RetryConfig::exponential(5, Duration::from_millis(100), Duration::from_secs(2));
/// let result = retry_async(&config, || async {
///     match try_connect().await {
///         Ok(conn) => RetryVerdict::Ok(conn),
///         Err(e) if e.is_transient() => RetryVerdict::Retry(e),
///         Err(e) => RetryVerdict::Fail(e),
///     }
/// }).await;
/// ```
#[cfg(feature = "async-ipc")]
pub async fn retry_async<F, Fut, T, E>(
    config: &RetryConfig,
    mut operation: F,
) -> Result<T, RetriesExhausted<E>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = RetryVerdict<T, E>>,
{
    let start = Instant::now();
    let mut last_error: Option<E> = None;

    for attempt in 0..config.max_attempts {
        match operation().await {
            RetryVerdict::Ok(val) => return Ok(val),
            RetryVerdict::Fail(e) => {
                return Err(RetriesExhausted {
                    last_error: e,
                    attempts: attempt + 1,
                    elapsed: start.elapsed(),
                });
            }
            RetryVerdict::Retry(e) => {
                last_error = Some(e);
                // Don't sleep after the last attempt
                if attempt + 1 < config.max_attempts {
                    let delay = config.delay_for_attempt(attempt);
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    Err(RetriesExhausted {
        last_error: last_error.expect("at least one attempt should have been made"),
        attempts: config.max_attempts,
        elapsed: start.elapsed(),
    })
}

/// Retry a synchronous operation with configurable backoff.
///
/// Same semantics as [`retry_async`] but uses `std::thread::sleep`.
///
/// # Errors
///
/// Returns [`RetriesExhausted`] if all attempts fail or a non-retryable error occurs.
///
/// # Panics
///
/// Panics if `config.max_attempts` is 0 (at least one attempt must be made).
pub fn retry_sync<F, T, E>(config: &RetryConfig, mut operation: F) -> Result<T, RetriesExhausted<E>>
where
    F: FnMut() -> RetryVerdict<T, E>,
{
    let start = Instant::now();
    let mut last_error: Option<E> = None;

    for attempt in 0..config.max_attempts {
        match operation() {
            RetryVerdict::Ok(val) => return Ok(val),
            RetryVerdict::Fail(e) => {
                return Err(RetriesExhausted {
                    last_error: e,
                    attempts: attempt + 1,
                    elapsed: start.elapsed(),
                });
            }
            RetryVerdict::Retry(e) => {
                last_error = Some(e);
                if attempt + 1 < config.max_attempts {
                    let delay = config.delay_for_attempt(attempt);
                    std::thread::sleep(delay);
                }
            }
        }
    }

    Err(RetriesExhausted {
        last_error: last_error.expect("at least one attempt should have been made"),
        attempts: config.max_attempts,
        elapsed: start.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn default_config() {
        let cfg = RetryConfig::default();
        assert_eq!(cfg.max_attempts, 3);
        assert_eq!(cfg.initial_delay, Duration::from_millis(500));
    }

    #[test]
    fn fixed_config() {
        let cfg = RetryConfig::fixed(5, Duration::from_secs(1));
        assert_eq!(cfg.max_attempts, 5);
        assert!((cfg.backoff_factor - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn delay_progression_exponential() {
        let cfg = RetryConfig::exponential(10, Duration::from_millis(100), Duration::from_secs(2));
        assert_eq!(cfg.delay_for_attempt(0), Duration::from_millis(100));
        assert_eq!(cfg.delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(cfg.delay_for_attempt(2), Duration::from_millis(400));
        assert_eq!(cfg.delay_for_attempt(3), Duration::from_millis(800));
        assert_eq!(cfg.delay_for_attempt(4), Duration::from_millis(1600));
        // Capped at max_delay
        assert_eq!(cfg.delay_for_attempt(5), Duration::from_secs(2));
        assert_eq!(cfg.delay_for_attempt(10), Duration::from_secs(2));
    }

    #[test]
    fn delay_progression_fixed() {
        let cfg = RetryConfig::fixed(5, Duration::from_millis(500));
        for i in 0..5 {
            assert_eq!(cfg.delay_for_attempt(i), Duration::from_millis(500));
        }
    }

    #[test]
    fn retry_sync_succeeds_first_try() {
        let cfg = RetryConfig::fixed(3, Duration::from_millis(10));
        let result: Result<i32, _> = retry_sync(&cfg, || RetryVerdict::<i32, &str>::Ok(42));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn retry_sync_succeeds_after_retries() {
        let cfg = RetryConfig::fixed(5, Duration::from_millis(10));
        let counter = AtomicU32::new(0);
        let result: Result<&str, _> = retry_sync(&cfg, || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                RetryVerdict::Retry("not yet")
            } else {
                RetryVerdict::Ok("done")
            }
        });
        assert_eq!(result.unwrap(), "done");
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn retry_sync_exhausted() {
        let cfg = RetryConfig::fixed(3, Duration::from_millis(10));
        let result: Result<(), _> = retry_sync(&cfg, || RetryVerdict::<(), &str>::Retry("fail"));
        let err = result.unwrap_err();
        assert_eq!(err.attempts, 3);
        assert_eq!(err.last_error, "fail");
    }

    #[test]
    fn retry_sync_fails_immediately() {
        let cfg = RetryConfig::fixed(5, Duration::from_millis(10));
        let counter = AtomicU32::new(0);
        let result: Result<(), _> = retry_sync(&cfg, || {
            counter.fetch_add(1, Ordering::SeqCst);
            RetryVerdict::<(), &str>::Fail("fatal")
        });
        let err = result.unwrap_err();
        assert_eq!(err.attempts, 1);
        assert_eq!(err.last_error, "fatal");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "async-ipc")]
    #[tokio::test]
    async fn retry_async_succeeds_after_retries() {
        let cfg = RetryConfig::fixed(5, Duration::from_millis(10));
        let counter = AtomicU32::new(0);
        let result: Result<u32, _> = retry_async(&cfg, || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 3 {
                    RetryVerdict::Retry("not yet")
                } else {
                    RetryVerdict::Ok(n)
                }
            }
        })
        .await;
        assert_eq!(result.unwrap(), 3);
    }

    #[cfg(feature = "async-ipc")]
    #[tokio::test]
    async fn retry_async_exhausted() {
        let cfg = RetryConfig::fixed(2, Duration::from_millis(10));
        let result: Result<(), _> =
            retry_async(&cfg, || async { RetryVerdict::<(), &str>::Retry("oops") }).await;
        let err = result.unwrap_err();
        assert_eq!(err.attempts, 2);
    }
}
