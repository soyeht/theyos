//! The supervisor's command line, shared by two entry points.
//!
//! `soyeht-ptyd` is the historical helper binary and stays in the package:
//! installers still call it for `--contract` and `--status`, and a daemon
//! loaded from a previous release keeps running it until the next login.
//!
//! `theyos-engine ptyd` is the entry point the `LaunchAgent` uses from now on.
//! The reason is macOS TCC: Accessibility is granted per executable path, and
//! the supervisor is the parent of every pane shell, so whatever runs the
//! supervisor is what the person has to authorise in System Settings before
//! an agent in a pane can drive other apps. On 2026-09-08 that meant a third
//! entry (`soyeht-ptyd`) next to the app and `theyos-engine`, each asking on
//! its own. Running the supervisor from the engine's own file leaves one
//! grant that already exists and that survives engine updates, because the
//! grant follows the path and the signing team, not the bytes.
//!
//! The process is still separate from the HTTP engine: same file, different
//! process, so a supervisor never restarts because an engine was swapped.

use std::path::PathBuf;

/// Printed verbatim when the arguments match no mode.
pub const USAGE: &str = "usage: [soyeht-ptyd | theyos-engine ptyd] --socket PATH --state-dir DIRECTORY | --status --socket PATH | --contract";

/// The supervisor's own log filter. Independent of the engine's `RUST_LOG`
/// contract so a daemon started through either entry point logs the same.
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter("terminal_rs=info")
        .init();
}

/// Runs one supervisor mode. `args` excludes the program name and, for the
/// engine entry point, the `ptyd` word itself.
///
/// `--status` against an unreachable or incompatible daemon exits the process
/// with status 2 after printing a machine-readable error, because installers
/// distinguish "no daemon" from "wrong protocol" by that reply alone.
pub async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args == ["--contract"] {
        println!(
            "{}",
            serde_json::json!({"protocol_version": crate::supervisor_wire::VERSION})
        );
        return Ok(());
    }
    if args.len() == 3 && args[0] == "--status" && args[1] == "--socket" {
        let result = crate::supervisor_client::SupervisorClient::new(PathBuf::from(&args[2]))
            .status()
            .await;
        match result {
            Ok(status) => println!("{}", serde_json::to_string(&status)?),
            Err(error) => {
                let code = if matches!(error, crate::supervisor_client::ClientError::Protocol) {
                    "protocol_incompatible"
                } else {
                    "unavailable"
                };
                // Machine-readable failure for the installer. No paths,
                // fabricated inventory, or unstable Debug error formatting.
                eprintln!("{}", serde_json::json!({"error": code}));
                std::process::exit(2);
            }
        }
        return Ok(());
    }
    if args.len() != 4 || args[0] != "--socket" || args[2] != "--state-dir" {
        return Err(USAGE.into());
    }
    crate::supervisor::serve(&PathBuf::from(&args[1]), &PathBuf::from(&args[3])).await?;
    Ok(())
}
