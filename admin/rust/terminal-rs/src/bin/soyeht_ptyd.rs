//! Run as an independent `LaunchAgent`. The engine connects over UDS and never
//! starts, stops or owns this process through stdin/stdout.

use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("terminal_rs=info")
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--contract"] {
        println!(
            "{}",
            serde_json::json!({"protocol_version": terminal_rs::supervisor_wire::VERSION})
        );
        return Ok(());
    }
    if args.len() == 3 && args[0] == "--status" && args[1] == "--socket" {
        let status = terminal_rs::supervisor_client::SupervisorClient::new(PathBuf::from(&args[2]))
            .status()
            .await?;
        println!("{}", serde_json::to_string(&status)?);
        return Ok(());
    }
    if args.len() != 4 || args[0] != "--socket" || args[2] != "--state-dir" {
        return Err("usage: soyeht-ptyd --socket PATH --state-dir DIRECTORY | --status --socket PATH | --contract".into());
    }
    terminal_rs::supervisor::serve(&PathBuf::from(&args[1]), &PathBuf::from(&args[3])).await?;
    Ok(())
}
