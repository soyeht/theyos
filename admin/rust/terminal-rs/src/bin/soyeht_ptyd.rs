//! Run as an independent `LaunchAgent`. The engine connects over UDS and never
//! starts, stops or owns this process through stdin/stdout.
//!
//! Since the Accessibility fix this binary shares its whole command line with
//! `theyos-engine ptyd` (see `terminal_rs::supervisor_cli`). It stays in the
//! package for `--contract`/`--status` callers and for daemons loaded by an
//! earlier release.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    terminal_rs::supervisor_cli::init_tracing();
    let args: Vec<String> = std::env::args().skip(1).collect();
    terminal_rs::supervisor_cli::run(&args).await
}
