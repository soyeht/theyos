//! Crash reporting for theyOS.
//!
//! Installs a panic handler that writes crash reports with stacktraces
//! to ~/Library/Caches/theyos/crashes/ on macOS,
//! or ~/.cache/theyos/crashes/ on Linux.

use std::fmt::Write;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

/// Get the crash reports directory for theyOS.
///
/// Returns:
/// - macOS: ~/Library/Caches/theyos/crashes/
/// - Linux: ~/.cache/theyos/crashes/
#[must_use]
pub fn crash_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());

    #[cfg(target_os = "macos")]
    {
        PathBuf::from(home)
            .join("Library")
            .join("Caches")
            .join("theyos")
            .join("crashes")
    }

    #[cfg(target_os = "linux")]
    {
        PathBuf::from(home)
            .join(".cache")
            .join("theyos")
            .join("crashes")
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        PathBuf::from(home).join(".theyos").join("crashes")
    }
}

/// Initialize panic handler for crash reports.
///
/// Installs a panic hook that writes crash reports with stacktraces
/// to ~/Library/Caches/theyos/crashes/
///
/// # Crash Report Format
///
/// Each crash report includes:
/// - Timestamp of the panic
/// - Panic message and payload
/// - File and line number where panic occurred
/// - Stack backtrace
///
/// # Errors
///
/// Returns an error if the crash directory cannot be created.
///
/// # Example
///
/// ```no_run
/// use core_rs::crash::init_panic_handler;
///
/// if let Err(e) = init_panic_handler() {
///     eprintln!("Failed to initialize panic handler: {}", e);
/// }
/// ```
pub fn init_panic_handler() -> Result<(), Box<dyn std::error::Error>> {
    let crash_dir = crash_dir();

    // Ensure crash directory exists
    std::fs::create_dir_all(&crash_dir)?;

    // Capture the default panic hook for chaining
    let default_hook = std::panic::take_hook();

    // Clone crash_dir for use in the panic hook
    let crash_dir_for_hook = crash_dir.clone();

    // Install custom panic hook
    std::panic::set_hook(Box::new(move |panic_info| {
        // Generate timestamp-based filename
        let timestamp = UNIX_EPOCH.elapsed().unwrap_or_default().as_secs();
        let crash_file = crash_dir_for_hook.join(format!("crash-{timestamp}.log"));

        // Build crash report
        let mut report = String::new();

        // Header with timestamp
        let datetime = chrono::Local::now().format("%Y-%m-%d %H:%M:%S %.3f %Z");

        let _ = writeln!(report, "theyOS Crash Report");
        let _ = writeln!(report, "Timestamp: {datetime}");

        // Panic location
        let location = panic_info
            .location()
            .unwrap_or_else(|| std::panic::Location::caller());
        let _ = writeln!(
            report,
            "Location: {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );

        // Panic message
        let payload = panic_info.payload();
        if let Some(s) = payload.downcast_ref::<&str>() {
            let _ = writeln!(report, "Message: {s}");
        } else if let Some(s) = payload.downcast_ref::<String>() {
            let _ = writeln!(report, "Message: {s}");
        } else {
            let _ = writeln!(report, "Message: {payload:?}");
        }

        // Backtrace
        let _ = writeln!(report, "Backtrace:");
        let backtrace = std::backtrace::Backtrace::capture();
        let _ = writeln!(report, "{backtrace:?}");

        // Write crash report to file
        match std::fs::write(&crash_file, report.as_bytes()) {
            Ok(()) => {
                eprintln!("Crash report written to: {}", crash_file.display());
                eprintln!("Please include this file when reporting bugs.");
            }
            Err(e) => {
                eprintln!(
                    "Failed to write crash report to {}: {}",
                    crash_file.display(),
                    e
                );
            }
        }

        // Chain to default hook (prints to stderr and may abort)
        default_hook(panic_info);
    }));

    #[cfg(target_os = "macos")]
    tracing::debug!(
        crash_dir = %crash_dir.display(),
        "Panic handler initialized"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crash_dir() {
        let dir = crash_dir();
        let path_str = dir.to_string_lossy();
        assert!(path_str.contains("cache") || path_str.contains("Caches"));
        assert!(path_str.contains("theyos"));
        assert!(path_str.contains("crashes"));
    }

    #[test]
    fn test_init_panic_handler_creates_dir() {
        let dir = crash_dir();
        let _ = std::fs::create_dir_all(&dir);

        // Should not fail even if directory exists
        let result = init_panic_handler();
        assert!(result.is_ok());
    }
}
