//! `theyos-engine accessibility` answers for the engine file itself, as one
//! JSON object, without starting an engine.

use std::process::Command;

fn engine() -> Command {
    Command::new(env!("CARGO_BIN_EXE_server"))
}

#[test]
fn accessibility_reports_trust_as_json_without_prompting() {
    let output = engine().arg("accessibility").output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reply: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(reply["trusted"].is_boolean(), "reply: {reply}");
    assert_eq!(reply["prompted"], false);
    assert!(reply["supported"].is_boolean());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Starting server-rs"),
        "must not start an engine: {stderr}"
    );
}

#[test]
fn accessibility_rejects_unknown_flags_with_usage() {
    let output = engine().args(["accessibility", "--what"]).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage:"));
}
