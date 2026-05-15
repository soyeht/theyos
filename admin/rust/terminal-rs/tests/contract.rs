//! Contract tests driven by `admin/contracts/terminal/fixtures.json`.
//! Each fixture creates a fresh `Manager` and runs setup operations before
//! the main assertion.

// Test fixtures store counts and offsets as u64 (JSON default); casting to
// usize/i32 is intentional and safe for the small values used in tests.
#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]

use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use terminal_rs::Manager;

// ─── Fixture types ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Fixture {
    id: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    operation: String,
    #[serde(default)]
    setup: Vec<SetupOp>,
    input: Value,
    #[serde(default)]
    expected: Value,
}

#[derive(Debug, Deserialize)]
struct SetupOp {
    op: String,
    #[serde(default)]
    container: String,
}

fn fixtures_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("..")
        .join("contracts")
        .join("terminal")
        .join("fixtures.json")
}

fn load_fixtures() -> Vec<Fixture> {
    let data = fs::read_to_string(fixtures_path()).expect("read fixtures.json");
    serde_json::from_str(&data).expect("parse fixtures.json")
}

fn find_fixture<'a>(fixtures: &'a [Fixture], id: &str) -> &'a Fixture {
    fixtures
        .iter()
        .find(|f| f.id == id)
        .unwrap_or_else(|| panic!("fixture '{id}' not found"))
}

fn run_setup(manager: &Manager, ops: &[SetupOp]) {
    for op in ops {
        match op.op.as_str() {
            "ensure_container" => {
                manager.ensure_container(&op.container);
            }
            other => panic!("unknown setup op: {other}"),
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn contract_ensure_container_adds_and_lists_sorted() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "ensure_container_adds_and_lists_sorted");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let containers: Vec<String> = f.input["containers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    for c in &containers {
        m.ensure_container(c);
    }

    let expected_list: Vec<String> = f.expected["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let got = m.list_containers();
    assert_eq!(got, expected_list);

    let boot_lines: Vec<String> = f.expected["boot_history_per_container"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    // Verify each container has boot lines
    for c in &expected_list {
        let hist = m.get_session_history(c, "");
        assert!(
            hist.len() >= boot_lines.len(),
            "container {c} has {} history lines, expected at least {}",
            hist.len(),
            boot_lines.len()
        );
        // First line should start with "[boot] terminal ready :: "
        assert!(
            hist[0].starts_with("[boot] terminal ready :: "),
            "container {c} boot line: {}",
            hist[0]
        );
        // Second line is the prompt
        assert_eq!(hist[1], "soyeht@local:~$ ");
    }
}

#[test]
fn contract_ensure_container_idempotent() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "ensure_container_idempotent");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    m.ensure_container(container);

    let expected_count = f.expected["count"].as_u64().unwrap() as usize;
    let got = m.list_containers();
    assert_eq!(got.len(), expected_count);

    let expected_list: Vec<String> = f.expected["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(got, expected_list);
}

#[test]
fn contract_ensure_container_empty_ignored() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "ensure_container_empty_ignored");

    let m = Manager::new_empty();

    let containers: Vec<String> = f.input["containers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    for c in &containers {
        m.ensure_container(c);
    }

    let expected_count = f.expected["count"].as_u64().unwrap() as usize;
    assert_eq!(m.list_containers().len(), expected_count);
}

#[test]
fn contract_remove_container_removes_from_list() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "remove_container_removes_from_list");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    m.remove_container(container);

    let expected_count = f.expected["count"].as_u64().unwrap() as usize;
    let expected_list: Vec<String> = f.expected["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let got = m.list_containers();
    assert_eq!(got.len(), expected_count);
    assert_eq!(got, expected_list);
}

#[test]
fn contract_remove_container_cleans_sessions() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "remove_container_cleans_sessions");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let command = f.input["command"].as_str().unwrap();
    let user = f.input["user"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();

    m.remove_container(container);

    let err = m
        .run_command(container, session_id, user, command)
        .unwrap_err();

    let expected_contains = f.expected["error_contains"].as_str().unwrap();
    assert!(
        err.to_string().contains(expected_contains),
        "error '{err}' should contain '{expected_contains}'"
    );
}

#[test]
fn contract_has_container_true() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "has_container_true");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let expected = f.expected["result"].as_bool().unwrap();
    assert_eq!(m.has_container(container), expected);
}

#[test]
fn contract_has_container_false_empty() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "has_container_false_empty");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let expected = f.expected["result"].as_bool().unwrap();
    assert_eq!(m.has_container(container), expected);
}

#[test]
fn contract_has_container_false_whitespace() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "has_container_false_whitespace");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let expected = f.expected["result"].as_bool().unwrap();
    assert_eq!(m.has_container(container), expected);
}

#[test]
fn contract_run_command_empty_noop() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "run_command_empty_noop");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();
    let user = f.input["user"].as_str().unwrap();
    let command = f.input["command"].as_str().unwrap();

    m.run_command(container, session_id, user, command).unwrap();

    let expected_count = f.expected["history_count"].as_u64().unwrap() as usize;
    let expected_history: Vec<String> = f.expected["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let hist = m.get_session_history(container, session_id);
    assert_eq!(hist.len(), expected_count);
    assert_eq!(hist, expected_history);
}

#[test]
fn contract_run_command_clear_resets_history() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "run_command_clear_resets_history");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();
    let user = f.input["user"].as_str().unwrap();
    let command = f.input["command"].as_str().unwrap();

    m.run_command(container, session_id, user, command).unwrap();

    let expected_count = f.expected["history_count"].as_u64().unwrap() as usize;
    let expected_history: Vec<String> = f.expected["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let hist = m.get_session_history(container, session_id);
    assert_eq!(hist.len(), expected_count);
    assert_eq!(hist, expected_history);
}

#[test]
fn contract_run_command_success_appends_output_and_prompt() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "run_command_success_appends_output_and_prompt");

    let mock_output = f.input["mock_output"].as_str().unwrap();
    let mock_exit_code = f.input["mock_exit_code"].as_i64().unwrap() as i32;

    let m = Manager::new_with_mock(mock_output, mock_exit_code);
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();
    let user = f.input["user"].as_str().unwrap();
    let command = f.input["command"].as_str().unwrap();

    m.run_command(container, session_id, user, command).unwrap();

    let expected_count = f.expected["history_count"].as_u64().unwrap() as usize;
    let expected_history: Vec<String> = f.expected["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let hist = m.get_session_history(container, session_id);
    assert_eq!(hist.len(), expected_count, "history: {hist:?}");
    assert_eq!(hist, expected_history);
}

#[test]
fn contract_run_command_nonzero_adds_exit_line() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "run_command_nonzero_adds_exit_line");

    let mock_output = f.input["mock_output"].as_str().unwrap();
    let mock_exit_code = f.input["mock_exit_code"].as_i64().unwrap() as i32;

    let m = Manager::new_with_mock(mock_output, mock_exit_code);
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();
    let user = f.input["user"].as_str().unwrap();
    let command = f.input["command"].as_str().unwrap();

    m.run_command(container, session_id, user, command).unwrap();

    let expected_count = f.expected["history_count"].as_u64().unwrap() as usize;
    let expected_history: Vec<String> = f.expected["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let hist = m.get_session_history(container, session_id);
    assert_eq!(hist.len(), expected_count, "history: {hist:?}");
    assert_eq!(hist, expected_history);
}

#[test]
fn contract_run_command_missing_container_error() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "run_command_missing_container_error");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();
    let user = f.input["user"].as_str().unwrap();
    let command = f.input["command"].as_str().unwrap();

    let err = m
        .run_command(container, session_id, user, command)
        .unwrap_err();

    let expected_contains = f.expected["error_contains"].as_str().unwrap();
    assert!(
        err.to_string().contains(expected_contains),
        "error '{err}' should contain '{expected_contains}'"
    );
}

#[test]
fn contract_restart_appends_reset_and_prompt() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "restart_appends_reset_and_prompt");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();

    m.restart(container, session_id).unwrap();

    let expected_count = f.expected["history_count"].as_u64().unwrap() as usize;
    let expected_history: Vec<String> = f.expected["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let hist = m.get_session_history(container, session_id);
    assert_eq!(hist.len(), expected_count);
    assert_eq!(hist, expected_history);
}

#[test]
fn contract_restart_missing_container_error() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "restart_missing_container_error");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();

    let err = m.restart(container, session_id).unwrap_err();

    let expected_contains = f.expected["error_contains"].as_str().unwrap();
    assert!(
        err.to_string().contains(expected_contains),
        "error '{err}' should contain '{expected_contains}'"
    );
}

#[test]
fn contract_history_cap_400_lines() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "history_cap_400_lines");

    let mock_output = f.input["mock_output_per_command"].as_str().unwrap();
    let m = Manager::new_with_mock(mock_output, 0);
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();
    let user = f.input["user"].as_str().unwrap();
    let num_commands = f.input["num_commands"].as_u64().unwrap() as usize;

    for i in 0..num_commands {
        m.run_command(container, session_id, user, &format!("cmd-{i}"))
            .unwrap();
    }

    let max_history = f.expected["max_history"].as_u64().unwrap() as usize;
    let hist = m.get_session_history(container, session_id);
    assert!(
        hist.len() <= max_history,
        "history length {} exceeds cap {max_history}",
        hist.len()
    );
}

#[test]
fn contract_list_containers_empty() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "list_containers_empty");

    let m = Manager::new_empty();

    let expected_count = f.expected["count"].as_u64().unwrap() as usize;
    let got = m.list_containers();
    assert_eq!(got.len(), expected_count);
}

#[test]
fn contract_list_containers_sorted_multiple() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "list_containers_sorted_multiple");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let expected_count = f.expected["count"].as_u64().unwrap() as usize;
    let expected_list: Vec<String> = f.expected["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let got = m.list_containers();
    assert_eq!(got.len(), expected_count);
    assert_eq!(got, expected_list);
}

// PTY Contract Tests

#[test]
fn contract_start_pty_session_success() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "start_pty_session_success");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();

    // In the Rust Manager, run_command creates the session implicitly
    m.run_command(container, session_id, "soyeht", "").unwrap();

    let hist = m.get_session_history(container, session_id);
    assert!(!hist.is_empty(), "session should have boot history");
}

#[test]
fn contract_start_pty_session_idempotent() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "start_pty_session_idempotent");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();

    // Create session first
    m.run_command(container, session_id, "soyeht", "").unwrap();
    let hist1 = m.get_session_history(container, session_id);

    // Second call should reuse same session (append nothing new for empty command)
    m.run_command(container, session_id, "soyeht", "").unwrap();
    let hist2 = m.get_session_history(container, session_id);

    // History should be same (no duplicate boot lines)
    assert_eq!(hist1.len(), hist2.len(), "session should be idempotent");
}

#[test]
fn contract_start_pty_session_missing_container() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "start_pty_session_missing_container");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();

    let err = m
        .run_command(container, session_id, "soyeht", "ls")
        .unwrap_err();

    let expected_contains = f.expected["error_contains"].as_str().unwrap();
    assert!(
        err.to_string().contains(expected_contains),
        "error '{err}' should contain '{expected_contains}'"
    );
}

#[test]
fn contract_pty_snapshot_returns_lines_and_cursor() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "pty_snapshot_returns_lines_and_cursor");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();

    // Ensure session exists
    m.run_command(container, session_id, "soyeht", "").unwrap();

    let hist = m.get_session_history(container, session_id);
    let cursor_gte = f.expected["cursor_gte"].as_u64().unwrap() as usize;

    assert!(
        hist.len() >= cursor_gte,
        "history length {} should be >= {cursor_gte}",
        hist.len()
    );
}

#[test]
fn contract_pty_poll_returns_incremental_lines() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "pty_poll_returns_incremental_lines");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();
    let cursor = f.input["cursor"].as_u64().unwrap() as usize;

    // Ensure session exists
    m.run_command(container, session_id, "soyeht", "").unwrap();

    let hist = m.get_session_history(container, session_id);
    let new_lines: Vec<String> = hist.iter().skip(cursor).cloned().collect();

    let expected_lines_count = f.expected["lines_count"].as_u64().unwrap() as usize;
    assert_eq!(
        new_lines.len(),
        expected_lines_count,
        "new lines count should match"
    );
}

#[test]
fn contract_pty_write_accepts_commands() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "pty_write_accepts_commands");

    let m = Manager::new_with_mock("test output", 0);
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();
    let data = f.input["data"].as_str().unwrap();

    // Ensure session exists
    m.run_command(container, session_id, "soyeht", "").unwrap();

    let initial_len = m.get_session_history(container, session_id).len();

    // Write command (simulated via run_command for each line)
    for cmd in data.lines() {
        if !cmd.trim().is_empty() {
            m.run_command(container, session_id, "soyeht", cmd).unwrap();
        }
    }

    let final_len = m.get_session_history(container, session_id).len();
    let accepted_gte = f.expected["accepted_gte"].as_u64().unwrap() as usize;

    // Should have added at least the accepted_gte lines
    assert!(
        final_len >= initial_len + accepted_gte,
        "history should grow by at least {accepted_gte}"
    );
}

#[test]
fn contract_pty_resize_noop_success() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "pty_resize_noop_success");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();

    // Ensure session exists (resize is no-op but validates container)
    m.run_command(container, session_id, "soyeht", "").unwrap();

    // Resize is a no-op in current implementation, just verify container exists
    let hist = m.get_session_history(container, session_id);
    assert!(
        !hist.is_empty(),
        "session should exist after resize validation"
    );
}

#[test]
fn contract_pty_operations_missing_container() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "pty_operations_missing_container");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();

    let err = m
        .run_command(container, session_id, "soyeht", "ls")
        .unwrap_err();

    let expected_contains = f.expected["error_contains"].as_str().unwrap();
    assert!(
        err.to_string().contains(expected_contains),
        "error '{err}' should contain '{expected_contains}'"
    );
}

#[test]
fn contract_get_session_history_with_session() {
    let fixtures = load_fixtures();
    let f = find_fixture(&fixtures, "get_session_history_with_session");

    let m = Manager::new_empty();
    run_setup(&m, &f.setup);

    let container = f.input["container"].as_str().unwrap();
    let session_id = f.input["session_id"].as_str().unwrap();

    // Create session with specific ID
    m.run_command(container, session_id, "soyeht", "").unwrap();

    let hist = m.get_session_history(container, session_id);
    let expected_count = f.expected["history_count"].as_u64().unwrap() as usize;

    assert_eq!(hist.len(), expected_count, "history count should match");

    if f.expected["has_boot_line"].as_bool().unwrap() && !hist.is_empty() {
        assert!(
            hist[0].starts_with("[boot]"),
            "first line should be boot line, got: {}",
            hist[0]
        );
    }
}
