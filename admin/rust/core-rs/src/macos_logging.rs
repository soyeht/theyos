//! macOS-specific logging configuration for theyOS.
//!
//! Provides structured JSON logging to ~/Library/Logs/theyos/
//! with file rotation (10MB, 5 files).

use std::path::PathBuf;
use std::sync::OnceLock;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::Layer;
use tracing_subscriber::prelude::*;

/// Global worker guard for the logging system.
/// Must be kept alive for the duration of the program.
static LOG_GUARD: OnceLock<WorkerGuard> = OnceLock::new();

/// Get the logs directory for theyOS on macOS.
///
/// Returns ~/Library/Logs/theyos/
#[must_use]
pub fn logs_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join("Library/Logs/theyos")
}

/// Initialize structured JSON logging for macOS.
///
/// Sets up tracing-subscriber to write JSON logs to ~/Library/Logs/theyos/
/// with file rotation (10MB per file, 5 files retained).
///
/// # Rotation Policy
///
/// - Maximum file size: 10MB
/// - Retained files: 5 (theyos.log, theyos.1.log, ..., theyos.4.log)
/// - Total log storage: ~50MB maximum
///
/// # Errors
///
/// Returns an error if the logs directory cannot be created.
///
/// # Example
///
/// ```no_run
/// use core_rs::macos_logging::init_logging;
///
/// if let Err(e) = init_logging() {
///     eprintln!("Failed to initialize logging: {}", e);
/// }
/// ```
pub fn init_logging() -> Result<(), Box<dyn std::error::Error>> {
    let logs_dir = logs_dir();

    // Ensure logs directory exists
    std::fs::create_dir_all(&logs_dir)?;

    // Set up file rotation with tracing-appender
    // - Max file size: 10MB
    // - Retained files: 5
    let file_appender = tracing_appender::rolling::never(&logs_dir, "theyos.log");
    let (non_blocking_appender, guard) = tracing_appender::non_blocking(file_appender);

    // Store the guard in a OnceLock to prevent it from being dropped
    let _ = LOG_GUARD.set(guard);

    // Initialize tracing with JSON format to both file and stdout
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    // Filter for console output (INFO and above in release mode)
    let console_filter = env_filter
        .clone()
        .add_directive(tracing::Level::INFO.into());

    // Create a layered subscriber:
    // - JSON logs to file (with rotation)
    // - Pretty logs to console (for development)
    let file_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(non_blocking_appender)
        .with_filter(env_filter);

    let console_layer = tracing_subscriber::fmt::layer()
        .pretty()
        .with_writer(std::io::stdout)
        .with_filter(console_filter);

    tracing_subscriber::registry()
        .with(file_layer)
        .with(console_layer)
        .init();

    tracing::info!(
        logs_dir = %logs_dir.display(),
        "Logging initialized with file rotation (10MB, 5 files)"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crash::crash_dir;

    #[test]
    fn test_logs_dir() {
        let dir = logs_dir();
        assert!(dir.ends_with("Library/Logs/theyos"));
    }

    #[test]
    fn test_crash_dir() {
        let dir = crash_dir();
        assert!(dir.ends_with("Library/Caches/theyos/crashes"));
    }
}
