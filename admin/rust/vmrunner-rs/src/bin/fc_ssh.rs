//! fc-ssh — Firecracker SSH bridge (replaces fc-agent-runtime.sh for terminal/PTY).
//!
//! Handles the subset of `fc-agent-runtime.sh` commands that go through the
//! online terminal path: `exec`, `pty`, `logs`, `list`, `status`, `tmux-cleanup`.
//!
//! Called by:
//!   - `terminal-rs` `FirecrackerExecutor`  → `exec <container> <cmd>`
//!   - `terminal-rs` `PtyManager`           → `pty <container> <session_name>`
//!   - `soyeht doctor`                  → `help`, `list`, `status [container]`
//!   - `soyeht admin-host-logs`         → (reads log files directly, not this binary)
//!
//! Usage:
//!   `fc-ssh exec          <CONTAINER> <COMMAND>`         — Run command in VM via SSH; exit code propagated
//!   `fc-ssh pty           <CONTAINER> <SESSION>`         — Interactive SSH PTY via tmux (execvp)
//!   `fc-ssh pty           <CONTAINER> <SESSION> --grouped <BASE>` — Grouped tmux session (independent dims)
//!   `fc-ssh capture-pane  <CONTAINER> <SESSION>`         — Capture tmux pane contents (best-effort)
//!   `fc-ssh pane-pipe     <CONTAINER> <PANE_ID>`         — Stream tmux pane via pipe-pane (numeric, e.g. 2 for %2)
//!   `fc-ssh tmux-cleanup  <CONTAINER> [HOURS]`           — Kill idle soyeht_ tmux sessions (default: 24h)
//!   `fc-ssh logs          <CONTAINER> [TAIL]`            — Print tail of serial.log
//!   `fc-ssh list`                                        — List known instance containers
//!   `fc-ssh status        [CONTAINER]`                   — Show running status of one or all instances
//!   `fc-ssh help`                                        — Print this usage

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[allow(clippy::too_many_lines)] // Dispatch table — splitting hurts readability
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let subcmd = args.get(1).map_or("help", std::string::String::as_str);

    match subcmd {
        "help" | "--help" | "-h" => {
            print_usage();
        }
        "list" => {
            cmd_list();
        }
        "status" => {
            let container = args.get(2).map(std::string::String::as_str);
            cmd_status(container);
        }
        "logs" => {
            let container = if let Some(c) = args.get(2) {
                c.as_str()
            } else {
                eprintln!("[fc-ssh] logs: CONTAINER required");
                std::process::exit(1);
            };
            let tail: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(100);
            cmd_logs(container, tail);
        }
        "pty" => {
            let container = if let Some(c) = args.get(2) {
                c.as_str()
            } else {
                eprintln!("[fc-ssh] pty: CONTAINER required");
                std::process::exit(1);
            };
            let session_name = if let Some(s) = args.get(3) {
                s.as_str()
            } else {
                eprintln!("[fc-ssh] pty: SESSION_NAME required");
                std::process::exit(1);
            };
            // Parse optional --grouped <base_session> after session_name.
            let grouped_base = if args.get(4).map(String::as_str) == Some("--grouped") {
                Some(
                    args.get(5)
                        .unwrap_or_else(|| {
                            eprintln!("[fc-ssh] pty: --grouped requires BASE_SESSION");
                            std::process::exit(1);
                        })
                        .as_str(),
                )
            } else {
                None
            };
            cmd_pty(container, session_name, grouped_base);
        }
        "tmux-cleanup" => {
            let container = if let Some(c) = args.get(2) {
                c.as_str()
            } else {
                eprintln!("[fc-ssh] tmux-cleanup: CONTAINER required");
                std::process::exit(1);
            };
            let max_idle_hours: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(24);
            cmd_tmux_cleanup(container, max_idle_hours);
        }
        "exec" => {
            let container = if let Some(c) = args.get(2) {
                c.as_str()
            } else {
                eprintln!("[fc-ssh] exec: CONTAINER required");
                std::process::exit(1);
            };
            let command = if let Some(c) = args.get(3) {
                c.as_str()
            } else {
                eprintln!("[fc-ssh] exec: COMMAND required");
                std::process::exit(1);
            };
            cmd_exec(container, command);
        }
        "capture-pane" => {
            let container = if let Some(c) = args.get(2) {
                c.as_str()
            } else {
                eprintln!("[fc-ssh] capture-pane: CONTAINER required");
                std::process::exit(1);
            };
            let session_name = if let Some(s) = args.get(3) {
                s.as_str()
            } else {
                eprintln!("[fc-ssh] capture-pane: SESSION_NAME required");
                std::process::exit(1);
            };
            cmd_capture_pane(container, session_name);
        }
        "pane-pipe" => {
            let container = if let Some(c) = args.get(2) {
                c.as_str()
            } else {
                eprintln!("[fc-ssh] pane-pipe: CONTAINER required");
                std::process::exit(1);
            };
            let pane_id = if let Some(p) = args.get(3) {
                p.as_str()
            } else {
                eprintln!("[fc-ssh] pane-pipe: PANE_ID required");
                std::process::exit(1);
            };
            cmd_pane_pipe(container, pane_id);
        }
        other => {
            eprintln!("[fc-ssh] unknown subcommand: {other}");
            print_usage();
            std::process::exit(1);
        }
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// `exec <container> <command>` — run command in VM, propagate exit code.
fn cmd_exec(container: &str, command: &str) {
    let (ssh_key, ssh_port) = resolve_instance(container);
    let port_str = ssh_port.to_string();
    let quoted = shell_quote(command);

    let ssh_bin = resolve_ssh_bin();
    let status = Command::new(&ssh_bin)
        .args(build_ssh_opts(&ssh_key, &port_str))
        .args(["root@127.0.0.1", &format!("/bin/sh -lc {quoted}")])
        .status();

    match status {
        Ok(s) => {
            // Preserve signal exit codes (128 + signal).
            use std::os::unix::process::ExitStatusExt;
            let code = s
                .code()
                .unwrap_or_else(|| s.signal().map_or(1, |sig| 128 + sig));
            std::process::exit(code);
        }
        Err(e) => {
            eprintln!("[fc-ssh] exec ssh failed: {e}");
            std::process::exit(1);
        }
    }
}

/// `pty <container> <session_name> [--grouped <base>]` — replace process with
/// interactive SSH into a tmux session (execvp).
///
/// The tmux session name must be pre-validated by the caller (the HTTP handler
/// or `PtyManager`). This function performs defense-in-depth validation and
/// exits with code 1 if the name is invalid.
///
/// ## Normal mode (no --grouped)
///
/// Uses `tmux new-session -A -s <name>` which is idempotent: creates the
/// session if it doesn't exist, attaches if it does. This is the foundation
/// of terminal session persistence — when the SSH/WebSocket connection drops,
/// the tmux session inside the VM survives.
///
/// ## Grouped mode (--grouped <base>)
///
/// Creates a tmux **grouped session** linked to `<base>`. Grouped sessions
/// share windows and panes with the base session but have independent
/// dimensions and active window/pane state. This allows multiple clients
/// (e.g., mobile and browser) to view the same terminal content at their own
/// screen sizes without the smallest-client-wins problem.
///
/// The base session is created (detached) if it doesn't already exist. The
/// grouped session name is `<session_name>` and it targets `<base>`.
fn cmd_pty(container: &str, _session_name: &str, _grouped_base: Option<&str>) {
    // v2: tmux has been removed from the guest. The backend now owns the PTY master
    // and handles replay/scrollback via an append-only conversation log on disk.
    // `session_name` and `grouped_base` are accepted for CLI compatibility but
    // ignored — the backend identifies conversations on its own side.
    let (ssh_key, ssh_port) = resolve_instance(container);
    let port_str = ssh_port.to_string();

    // Launch a direct interactive login shell inside the guest. Try bash first
    // (standard on Ubuntu guests); fall back to sh -l if bash is missing.
    // `exec` replaces the shell that SSH itself spawns so `$!` in scripts and
    // tty ownership are clean.
    let shell_cmd = "export TERM=xterm-256color LANG=C.UTF-8 COLORTERM=truecolor; \
                     if command -v bash >/dev/null 2>&1; then exec bash -l -i; \
                     else exec sh -l; fi";

    let ssh_bin = resolve_ssh_bin();
    let err = Command::new(&ssh_bin)
        .args(build_ssh_opts(&ssh_key, &port_str))
        .args(["-tt", "root@127.0.0.1", shell_cmd])
        .exec(); // replaces the process — only returns on error

    eprintln!("[fc-ssh] pty execvp failed: {err}");
    std::process::exit(1);
}

/// `tmux-cleanup <container> [max_idle_hours]` — kill idle tmux sessions.
///
/// Lists all tmux sessions in the VM, filters to those with the `soyeht_`
/// prefix, and kills any that have been inactive for longer than
/// `max_idle_hours`. Sessions created manually by the user (without the
/// `soyeht_` prefix) are never touched.
///
/// **Grouped session safety**: base sessions that still have active grouped
/// clients (sessions matching `<base>_c*`) are skipped even if idle, because
/// killing the base while grouped sessions are alive would break tmux API
/// endpoints that target the base session name.
///
/// This is best-effort: exits 0 even if no sessions are found or if SSH
/// fails (the VM might be stopped).
fn cmd_tmux_cleanup(container: &str, max_idle_hours: u64) {
    let (ssh_key, ssh_port) = resolve_instance(container);
    let port_str = ssh_port.to_string();
    let ssh_bin = resolve_ssh_bin();

    // List sessions with name and last activity timestamp.
    // Format: "session_name<tab>activity_epoch"
    let list_cmd =
        "tmux list-sessions -F '#{session_name}\t#{session_activity}' 2>/dev/null || true";

    let output = Command::new(&ssh_bin)
        .args(build_ssh_opts(&ssh_key, &port_str))
        .args(["root@127.0.0.1", list_cmd])
        .output();

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            eprintln!("[fc-ssh] tmux-cleanup: ssh failed: {e}");
            return; // best-effort
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let max_idle_secs = max_idle_hours * 3600;

    // Collect all soyeht_ session names for grouped-session protection check.
    let all_names: Vec<&str> = stdout
        .lines()
        .filter_map(|line| {
            let name = line.split('\t').next()?;
            if name.starts_with("soyeht_") {
                Some(name)
            } else {
                None
            }
        })
        .collect();

    let mut to_kill = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 2 {
            continue;
        }
        let name = parts[0];
        let activity: u64 = match parts[1].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Only clean up soyeht_ sessions.
        if !name.starts_with("soyeht_") {
            continue;
        }

        let idle_secs = now.saturating_sub(activity);
        if idle_secs > max_idle_secs {
            // Protect base sessions that have active grouped clients.
            // A base session `soyeht_X` is protected if any `soyeht_X_c*`
            // session exists (regardless of that session's idle time).
            if !name.contains("_c") && has_active_grouped_clients(name, &all_names) {
                eprintln!(
                    "[fc-ssh] tmux-cleanup: skipping base session {name} \
                     (has active grouped clients)"
                );
                continue;
            }
            to_kill.push(name.to_string());
        }
    }

    if to_kill.is_empty() {
        return;
    }

    for name in &to_kill {
        let kill_cmd = format!("tmux kill-session -t {name} 2>/dev/null || true");
        let _ = Command::new(&ssh_bin)
            .args(build_ssh_opts(&ssh_key, &port_str))
            .args(["root@127.0.0.1", &kill_cmd])
            .status();
        eprintln!("[fc-ssh] tmux-cleanup: killed idle session {name}");
    }
}

/// Check if a base session has any active grouped client sessions.
///
/// Grouped sessions follow the naming convention `{base}_c{client_id}`.
fn has_active_grouped_clients(base_name: &str, all_names: &[&str]) -> bool {
    let prefix = format!("{base_name}_c");
    all_names.iter().any(|n| n.starts_with(&prefix))
}

/// `capture-pane <container> <session_name>` — capture tmux pane contents.
///
/// Runs `tmux capture-pane -t <name> -p -S -` via SSH, outputs to stdout.
/// Best-effort: exits 0 even on failure (session may not exist).
fn cmd_capture_pane(container: &str, session_name: &str) {
    let validated = match sanitize_tmux_name(session_name) {
        Ok(name) => name,
        Err(e) => {
            eprintln!("[fc-ssh] capture-pane: invalid session name: {e}");
            return; // best-effort
        }
    };

    let (ssh_key, ssh_port) = resolve_instance(container);
    let port_str = ssh_port.to_string();
    let ssh_bin = resolve_ssh_bin();

    let capture_cmd = format!("tmux capture-pane -t {validated} -p -S - 2>/dev/null || true");

    let output = Command::new(&ssh_bin)
        .args(build_ssh_opts(&ssh_key, &port_str))
        .args(["root@127.0.0.1", &capture_cmd])
        .output();

    match output {
        Ok(o) => {
            if !o.stdout.is_empty() {
                print!("{}", String::from_utf8_lossy(&o.stdout));
            }
        }
        Err(e) => {
            eprintln!("[fc-ssh] capture-pane: ssh failed: {e}");
            // best-effort — exit 0
        }
    }
}

/// `pane-pipe <container> <pane_id>` — stream a specific tmux pane via pipe-pane.
///
/// Connects to the VM via SSH (non-interactive, no `-tt`) and runs a script
/// that:
/// 1. Outputs `capture-pane -e -p -S -500` scrollback to stdout
/// 2. Creates a FIFO and activates `tmux pipe-pane` to stream live output
/// 3. `exec cat` from the FIFO (replaces shell for clean exit propagation)
///
/// The pane ID is numeric (e.g. `2` for tmux pane `%2`). Validation is
/// defense-in-depth; the HTTP handler already validates.
fn cmd_pane_pipe(container: &str, pane_id: &str) {
    if pane_id.is_empty() || !pane_id.chars().all(|c| c.is_ascii_digit()) {
        eprintln!("[fc-ssh] pane-pipe: invalid pane id: {pane_id}");
        std::process::exit(1);
    }

    let (ssh_key, ssh_port) = resolve_instance(container);
    let port_str = ssh_port.to_string();
    let pane_target = format!("%{pane_id}");

    let remote_script = format!(
        "PANE='{pane_target}'; \
         FIFO=\"/tmp/pp_$$_$RANDOM\"; \
         mkfifo \"$FIFO\" || exit 1; \
         trap 'tmux pipe-pane -t \"$PANE\" 2>/dev/null; rm -f \"$FIFO\"' EXIT INT TERM; \
         tmux capture-pane -t \"$PANE\" -e -p -S -500; \
         tmux pipe-pane -t \"$PANE\" \"cat > $FIFO\"; \
         exec cat < \"$FIFO\""
    );

    let ssh_bin = resolve_ssh_bin();
    // No -tt: raw byte stream, no remote PTY allocation.
    let err = Command::new(&ssh_bin)
        .args(build_ssh_opts(&ssh_key, &port_str))
        .args(["root@127.0.0.1", &remote_script])
        .exec();

    eprintln!("[fc-ssh] pane-pipe execvp failed: {err}");
    std::process::exit(1);
}

/// `logs <container> [tail]` — print tail of serial.log.
fn cmd_logs(container: &str, tail: usize) {
    let state_dir = resolve_state_dir();
    let serial_log = state_dir.join(container).join("serial.log");

    if !serial_log.exists() {
        eprintln!(
            "[fc-ssh] no serial.log for {container}: {}",
            serial_log.display()
        );
        std::process::exit(1);
    }

    let content = match std::fs::read_to_string(&serial_log) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[fc-ssh] read {}: {e}", serial_log.display());
            std::process::exit(1);
        }
    };

    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(tail);
    for line in &lines[start..] {
        println!("{line}");
    }
}

/// `list` — list known instance directories.
fn cmd_list() {
    let state_dir = resolve_state_dir();
    let rd = match std::fs::read_dir(&state_dir) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[fc-ssh] list: read {}: {e}", state_dir.display());
            std::process::exit(1);
        }
    };

    let mut names: Vec<String> = rd
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().join("instance.env").exists())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();

    names.sort();
    for name in &names {
        println!("{name}");
    }
}

/// `status [container]` — show running state of one or all instances.
fn cmd_status(filter: Option<&str>) {
    let state_dir = resolve_state_dir();
    let rd = match std::fs::read_dir(&state_dir) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[fc-ssh] status: read {}: {e}", state_dir.display());
            std::process::exit(1);
        }
    };

    let mut entries: Vec<PathBuf> = rd
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.join("instance.env").exists())
        .collect();

    entries.sort();

    let mut any = false;
    for path in &entries {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");

        if let Some(f) = filter {
            if name != f {
                continue;
            }
        }
        any = true;

        // Read claw_type and port from instance.env
        let env_content = std::fs::read_to_string(path.join("instance.env")).unwrap_or_default();
        let claw_type = env_line(&env_content, "CLAW_TYPE");
        let port = env_line(&env_content, "PORT");
        let fc_pid = env_line(&env_content, "FIRECRACKER_PID");
        let slirp_pid = env_line(&env_content, "SLIRP_PID");

        let claw_type = claw_type.as_deref().unwrap_or("?");
        let port = port.as_deref().unwrap_or("?");
        let fc_pid = fc_pid.as_deref().unwrap_or("0");
        let slirp_pid = slirp_pid.as_deref().unwrap_or("0");

        let fc_running = pid_alive(fc_pid.parse().unwrap_or(0));
        let slirp_running = pid_alive(slirp_pid.parse().unwrap_or(0));

        let state = if fc_running && slirp_running {
            "running"
        } else if fc_running {
            "degraded(no-slirp)"
        } else {
            "stopped"
        };

        println!(
            "{name}  type={claw_type}  port={port}  state={state}  fc_pid={fc_pid}  slirp_pid={slirp_pid}"
        );
    }

    if !any {
        if let Some(f) = filter {
            eprintln!("[fc-ssh] status: instance not found: {f}");
            std::process::exit(1);
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn resolve_state_dir() -> PathBuf {
    if let Ok(d) = std::env::var("FIRECRACKER_STATE_DIR") {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home).join("firecracker/instances")
}

fn resolve_ssh_key() -> PathBuf {
    if let Ok(k) = std::env::var("FIRECRACKER_SSH_KEY") {
        return PathBuf::from(k);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home).join("firecracker/assets/ubuntu-24.04-root.id_rsa")
}

/// Load SSH port from instance.env, exit with error if not found.
fn resolve_instance(container: &str) -> (PathBuf, u16) {
    let state_dir = resolve_state_dir();
    let inst_env = state_dir.join(container).join("instance.env");
    let ssh_key = resolve_ssh_key();

    let port = match read_instance_field(&inst_env, "SSH_PORT") {
        Ok(v) => match v.parse::<u16>() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[fc-ssh] bad SSH_PORT in {}: {e}", inst_env.display());
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("[fc-ssh] {e}");
            std::process::exit(1);
        }
    };

    (ssh_key, port)
}

fn read_instance_field(env_path: &Path, field: &str) -> Result<String, String> {
    core_rs::env::read_env_field(env_path, field)
        .ok_or_else(|| format!("{field} not found in {}", env_path.display()))
}

fn env_line(content: &str, key: &str) -> Option<String> {
    core_rs::env::read_env_field_from_str(content, key)
}

fn pid_alive(pid: u32) -> bool {
    core_rs::os::is_pid_running(pid)
}

fn build_ssh_opts<'a>(ssh_key: &'a Path, port: &'a str) -> Vec<&'a str> {
    vec![
        "-i",
        ssh_key.to_str().unwrap_or(""),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "ConnectTimeout=4",
        "-o",
        "ServerAliveInterval=120",
        "-o",
        "ServerAliveCountMax=3",
        "-p",
        port,
    ]
}

/// Resolve the path to the `ssh` binary.
///
/// Priority: `SSH_BIN` env var > PATH lookup > `/run/current-system/sw/bin/ssh` (NixOS).
/// Falls back to bare `"ssh"` as a last resort (will rely on execvp PATH search).
fn resolve_ssh_bin() -> String {
    // 1. Explicit env override
    if let Ok(bin) = std::env::var("SSH_BIN") {
        return bin;
    }
    // 2. Check PATH directly — works when run from a user shell or NixOS systemd
    if let Some(p) = core_rs::os::which_binary("ssh") {
        return p.to_string_lossy().into_owned();
    }
    // 3. NixOS well-known location (covers systemd services with restricted PATH)
    let nixos_path = "/run/current-system/sw/bin/ssh";
    if Path::new(nixos_path).exists() {
        return nixos_path.to_string();
    }
    // 4. Last resort — bare name, relies on execvp PATH search at exec time
    "ssh".to_string()
}

/// Validate a tmux session name: `[a-zA-Z0-9_-]` only, 1-64 chars.
///
/// Defense-in-depth: the HTTP handler validates first; this catches direct
/// `fc-ssh` invocations with bad input.
fn sanitize_tmux_name(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("session name is empty".to_string());
    }
    if name.len() > 64 {
        return Err(format!(
            "session name too long ({} chars, max 64)",
            name.len()
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(format!("session name contains invalid characters: {name}"));
    }
    Ok(name.to_string())
}

/// POSIX shell quoting: wrap in single quotes, escape embedded single quotes.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!(
        "  fc-ssh exec          <CONTAINER> <COMMAND>       # Run command via SSH, exit code propagated"
    );
    eprintln!(
        "  fc-ssh pty           <CONTAINER> <SESSION_NAME>  # Interactive SSH PTY via tmux (execvp)"
    );
    eprintln!("  fc-ssh pty           <CONTAINER> <SESSION_NAME> --grouped <BASE>");
    eprintln!(
        "                                                    # Grouped tmux session (independent dims)"
    );
    eprintln!(
        "  fc-ssh capture-pane  <CONTAINER> <SESSION_NAME>  # Capture tmux pane contents (best-effort)"
    );
    eprintln!(
        "  fc-ssh pane-pipe     <CONTAINER> <PANE_ID>       # Stream tmux pane via pipe-pane (numeric ID, e.g. 2 for %2)"
    );
    eprintln!(
        "  fc-ssh tmux-cleanup  <CONTAINER> [MAX_IDLE_H]    # Kill idle soyeht_ tmux sessions (default: 24h)"
    );
    eprintln!(
        "  fc-ssh logs          <CONTAINER> [TAIL]           # Print last N lines of serial.log (default 100)"
    );
    eprintln!(
        "  fc-ssh list                                       # List known instance containers"
    );
    eprintln!(
        "  fc-ssh status        [CONTAINER]                  # Show running state (all or one)"
    );
    eprintln!("  fc-ssh help                                       # Show this message");
    eprintln!();
    eprintln!("Environment:");
    eprintln!(
        "  FIRECRACKER_STATE_DIR   Instance state directory (default: ~/firecracker/instances)"
    );
    eprintln!(
        "  FIRECRACKER_SSH_KEY     SSH private key path (default: ~/firecracker/assets/ubuntu-24.04-root.id_rsa)"
    );
    eprintln!("  SSH_BIN                 Override ssh binary path (default: auto-detect)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(unsafe_code)]
    fn set_test_env_var(key: &str, value: &str) {
        // SAFETY: test-only helper; callers restore the previous value after
        // exercising the narrow code path under test.
        unsafe { std::env::set_var(key, value) };
    }

    #[allow(unsafe_code)]
    fn remove_test_env_var(key: &str) {
        // SAFETY: paired with `set_test_env_var` in the test module only.
        unsafe { std::env::remove_var(key) };
    }

    /// `SSH_BIN` env override is respected.
    #[test]
    fn test_resolve_ssh_bin_env_override_fc_ssh() {
        let prev = std::env::var("SSH_BIN").ok();
        set_test_env_var("SSH_BIN", "/custom/test/path/to/ssh");
        let result = resolve_ssh_bin();
        match prev {
            Some(v) => set_test_env_var("SSH_BIN", &v),
            None => remove_test_env_var("SSH_BIN"),
        }
        assert_eq!(result, "/custom/test/path/to/ssh");
    }

    /// Without `SSH_BIN`, the function must return an absolute path — proving
    /// it found the binary via PATH or NixOS fallback (not bare "ssh").
    #[test]
    fn test_resolve_ssh_bin_finds_absolute_path_fc_ssh() {
        let prev = std::env::var("SSH_BIN").ok();
        remove_test_env_var("SSH_BIN");
        let result = resolve_ssh_bin();
        if let Some(v) = prev {
            set_test_env_var("SSH_BIN", &v);
        }
        assert!(
            result.starts_with('/'),
            "resolve_ssh_bin() returned '{result}' — expected absolute path, not bare 'ssh'"
        );
    }

    // ── sanitize_tmux_name tests ─────────────────────────────────────────

    #[test]
    fn test_sanitize_tmux_name_valid() {
        assert!(sanitize_tmux_name("soyeht_abc-123").is_ok());
        assert!(sanitize_tmux_name("main").is_ok());
        assert!(sanitize_tmux_name("soyeht_550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(sanitize_tmux_name("a").is_ok());
        assert!(sanitize_tmux_name("A_B-c_0").is_ok());
    }

    #[test]
    fn test_sanitize_tmux_name_empty() {
        let err = sanitize_tmux_name("").unwrap_err();
        assert!(err.contains("empty"), "expected 'empty' in: {err}");
    }

    #[test]
    fn test_sanitize_tmux_name_too_long() {
        let long = "a".repeat(65);
        let err = sanitize_tmux_name(&long).unwrap_err();
        assert!(err.contains("too long"), "expected 'too long' in: {err}");
    }

    #[test]
    fn test_sanitize_tmux_name_max_length_ok() {
        let exactly_64 = "a".repeat(64);
        assert!(sanitize_tmux_name(&exactly_64).is_ok());
    }

    #[test]
    fn test_sanitize_tmux_name_injection_semicolon() {
        let err = sanitize_tmux_name("foo; rm -rf /").unwrap_err();
        assert!(
            err.contains("invalid characters"),
            "expected 'invalid characters' in: {err}"
        );
    }

    #[test]
    fn test_sanitize_tmux_name_injection_backtick() {
        assert!(sanitize_tmux_name("`whoami`").is_err());
    }

    #[test]
    fn test_sanitize_tmux_name_injection_dollar() {
        assert!(sanitize_tmux_name("$(id)").is_err());
    }

    #[test]
    fn test_sanitize_tmux_name_spaces() {
        assert!(sanitize_tmux_name("foo bar").is_err());
    }

    #[test]
    fn test_sanitize_tmux_name_dots() {
        // Dots are not in [a-zA-Z0-9_-], intentionally rejected.
        assert!(sanitize_tmux_name("foo.bar").is_err());
    }

    // ── grouped session name tests ──────────────────────────────────────

    #[test]
    fn test_grouped_session_name_valid() {
        // Grouped session: soyeht_{workspace_id}_c{client_id}
        assert!(sanitize_tmux_name("soyeht_abc123_cabcdef01").is_ok());
        // Base session: soyeht_{workspace_id}
        assert!(sanitize_tmux_name("soyeht_abc123").is_ok());
    }

    #[test]
    fn test_grouped_session_name_at_max_length() {
        // session_id=46 chars + "soyeht_" (7) + "_c" (2) + client_id (8) = 63 chars
        let session_id = "a".repeat(46);
        let client_id = "b".repeat(8);
        let grouped = format!("soyeht_{session_id}_c{client_id}");
        assert_eq!(grouped.len(), 63);
        assert!(sanitize_tmux_name(&grouped).is_ok());

        // At exactly 64 chars.
        let session_id = "a".repeat(47);
        let grouped = format!("soyeht_{session_id}_c{client_id}");
        assert_eq!(grouped.len(), 64);
        assert!(sanitize_tmux_name(&grouped).is_ok());
    }

    #[test]
    fn test_grouped_session_name_over_max_length() {
        let session_id = "a".repeat(48);
        let client_id = "b".repeat(8);
        let grouped = format!("soyeht_{session_id}_c{client_id}");
        assert_eq!(grouped.len(), 65);
        assert!(sanitize_tmux_name(&grouped).is_err());
    }

    // ── has_active_grouped_clients tests ────────────────────────────────

    #[test]
    fn test_has_active_grouped_clients_with_clients() {
        let names = vec![
            "soyeht_abc123",
            "soyeht_abc123_cabcdef01",
            "soyeht_abc123_c12345678",
        ];
        assert!(has_active_grouped_clients("soyeht_abc123", &names));
    }

    #[test]
    fn test_has_active_grouped_clients_without_clients() {
        let names = vec!["soyeht_abc123", "soyeht_other_c12345678"];
        assert!(!has_active_grouped_clients("soyeht_abc123", &names));
    }

    #[test]
    fn test_has_active_grouped_clients_empty() {
        let names: Vec<&str> = vec![];
        assert!(!has_active_grouped_clients("soyeht_abc123", &names));
    }

    #[test]
    fn test_has_active_grouped_clients_no_false_prefix_match() {
        // soyeht_abc should NOT match soyeht_abc123_c... (different base)
        let names = vec!["soyeht_abc123_cabcdef01"];
        assert!(!has_active_grouped_clients("soyeht_abc", &names));
    }
}
