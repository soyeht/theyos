//! `theyos-ssh` — macOS SSH wrapper that replaces `fc-ssh` for VZ VMs.
//!
//! Queries the vmrunner IPC subprocess for the VM's DHCP IP, then `execvp`s
//! into SSH, replacing the current process.
//!
//! # Subcommands
//!
//! ```text
//! theyos-ssh pty <container> <session>
//!   Opens an interactive PTY session inside the VM, attached to a named tmux session.
//!   The session is created or reattached with `tmux new-session -A -s <session>`.
//!
//! theyos-ssh exec <container> <command> [args...]
//!   Runs a command inside the VM and returns its output.
//! ```
//!
//! # Environment
//!
//! - `THEYOS_VMRUNNER_SOCK`: path to the vmrunner IPC Unix socket (required)
//! - `THEYOS_SSH_KEY`: override SSH private key path (default: `~/.theyos/keys/id_ed25519`)

// This binary needs `unsafe` for direct libc calls (getuid/getpwnam/setuid/setgid)
// and for `std::env::set_var`. All sites have SAFETY comments documenting invariants.
#![allow(unsafe_code)]

use std::os::unix::process::CommandExt;
use std::path::PathBuf;

#[allow(clippy::too_many_lines)] // Dispatch table — splitting hurts readability
fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: theyos-ssh pty <container> <session>");
        eprintln!("       theyos-ssh exec <container> <command> [args...]");
        std::process::exit(1);
    }

    let subcommand = &args[1];
    let container = &args[2];

    // mac-host: skip SSH entirely and run tmux/commands on the host Mac directly.
    if container == "mac-host" {
        exec_mac_host(subcommand, &args);
    }

    // Resolve VM IP via IPC status query.
    let vm_ip = match get_vm_ip(container) {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("theyos-ssh: cannot resolve IP for container '{container}': {e}");
            std::process::exit(1);
        }
    };

    let ssh_key = ssh_key_path();
    let user_at_host = format!("root@{vm_ip}");

    match subcommand.as_str() {
        "pty" => {
            if args.len() < 4 {
                eprintln!("Usage: theyos-ssh pty <container> <session> [--grouped <base>]");
                std::process::exit(1);
            }
            // v2: tmux removed from the guest. The backend owns the PTY master and
            // handles scrollback/replay. `session` and `--grouped` args accepted for
            // CLI compatibility but ignored.
            let remote_cmd = "export PATH=/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH; \
                 export TERM=xterm-256color LANG=C.UTF-8 COLORTERM=truecolor; \
                 if command -v bash >/dev/null 2>&1; then exec bash -l -i; \
                 elif command -v zsh >/dev/null 2>&1; then exec zsh -l; \
                 else exec sh -l; fi";
            // -tt forces PTY allocation even if stdin is not a terminal.
            let err = std::process::Command::new("ssh")
                .args([
                    "-tt",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "ConnectTimeout=10",
                    "-i",
                    ssh_key.to_str().unwrap_or("/tmp/id_ed25519"),
                    &user_at_host,
                    remote_cmd,
                ])
                .exec();
            eprintln!("theyos-ssh: exec failed: {err}");
            std::process::exit(1);
        }
        "exec" => {
            if args.len() < 4 {
                eprintln!("Usage: theyos-ssh exec <container> <command> [args...]");
                std::process::exit(1);
            }
            // Prepend PATH so brew-installed tools are found in non-login SSH.
            let user_cmd = args[3..].join(" ");
            let remote_cmd = format!(
                "export PATH=/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH; {user_cmd}"
            );
            let err = std::process::Command::new("ssh")
                .args([
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "ConnectTimeout=10",
                    "-i",
                    ssh_key.to_str().unwrap_or("/tmp/id_ed25519"),
                    &user_at_host,
                    &remote_cmd,
                ])
                .exec();
            eprintln!("theyos-ssh: exec failed: {err}");
            std::process::exit(1);
        }
        "pane-pipe" => {
            if args.len() < 4 {
                eprintln!("Usage: theyos-ssh pane-pipe <container> <pane_id>");
                std::process::exit(1);
            }
            let pane_id = &args[3];
            if pane_id.is_empty() || !pane_id.chars().all(|c| c.is_ascii_digit()) {
                eprintln!("theyos-ssh: invalid pane id: {pane_id}");
                std::process::exit(1);
            }
            let pane_target = format!("%{pane_id}");
            // No -tt: raw byte stream from pipe-pane, no remote PTY.
            let remote_script = format!(
                "export PATH=/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH; \
                 PANE='{pane_target}'; \
                 FIFO=\"/tmp/pp_$$_$RANDOM\"; \
                 mkfifo \"$FIFO\" || exit 1; \
                 trap 'tmux pipe-pane -t \"$PANE\" 2>/dev/null; rm -f \"$FIFO\"' EXIT INT TERM; \
                 tmux capture-pane -t \"$PANE\" -e -p -S -500; \
                 tmux pipe-pane -t \"$PANE\" \"cat > $FIFO\"; \
                 exec cat < \"$FIFO\""
            );
            let err = std::process::Command::new("ssh")
                .args([
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "ConnectTimeout=10",
                    "-i",
                    ssh_key.to_str().unwrap_or("/tmp/id_ed25519"),
                    &user_at_host,
                    &remote_script,
                ])
                .exec();
            eprintln!("theyos-ssh: pane-pipe exec failed: {err}");
            std::process::exit(1);
        }
        other => {
            eprintln!("theyos-ssh: unknown subcommand '{other}'");
            std::process::exit(1);
        }
    }
}

/// Passwd entry fields needed to drop privileges.
struct UserEntry {
    uid: u32,
    gid: u32,
    home: String,
    shell: String,
}

/// Look up the console user and return their passwd entry.
/// Falls back to `None` if already running as a non-root user or lookup fails.
fn console_user_entry() -> Option<UserEntry> {
    // SAFETY: getuid is always safe — no pointers, no state mutation.
    if unsafe { libc::getuid() } != 0 {
        return None;
    }
    let name_out = std::process::Command::new("stat")
        .args(["-f", "%Su", "/dev/console"])
        .output()
        .ok()?;
    let name = String::from_utf8(name_out.stdout).ok()?.trim().to_string();
    if name.is_empty() || name == "root" {
        return None;
    }
    let c_name = std::ffi::CString::new(name).ok()?;
    // SAFETY: getpwnam returns a pointer into a static buffer; we read it
    // immediately and copy fields out before any subsequent libc call.
    let pw = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    // SAFETY: null check above; pointer valid until next libc call, which is
    // not made before the reads below.
    let pw = unsafe { &*pw };
    // SAFETY: pw_dir is a C string from libc owned memory, valid as long as `pw`.
    let home = unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: pw_shell is a C string from libc owned memory, valid as long as `pw`.
    let shell = unsafe { std::ffi::CStr::from_ptr(pw.pw_shell) }
        .to_string_lossy()
        .into_owned();
    Some(UserEntry {
        uid: pw.pw_uid,
        gid: pw.pw_gid,
        home,
        shell,
    })
}

/// Drop root privileges to `entry` via setgid + setuid. Must be called before
/// exec. Returns false on failure (caller should fall through to root exec).
fn drop_privileges(entry: &UserEntry) -> bool {
    // SAFETY: setgid/setuid are always safe libc calls; return values checked.
    unsafe { libc::setgid(entry.gid) == 0 && libc::setuid(entry.uid) == 0 }
}

/// Run `pty` or `exec` subcommands directly on the host Mac without SSH.
/// Used when `container == "mac-host"`. Never returns.
fn exec_mac_host(subcommand: &str, args: &[String]) -> ! {
    let path_prefix = "export PATH=/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH";

    // When the server runs as root, drop to the GUI user so tmux sessions land
    // in the user's home directory and shell environment.
    let user_entry = console_user_entry();

    match subcommand {
        "pty" => {
            if args.len() < 4 {
                eprintln!("Usage: theyos-ssh pty mac-host <session> [--grouped <base>]");
                std::process::exit(1);
            }
            // v2: tmux removed; launch the user's login shell directly.
            let cmd = format!(
                "{path_prefix}; \
                 export TERM=xterm-256color LANG=en_US.UTF-8 COLORTERM=truecolor; \
                 exec $SHELL -l -i"
            );
            if let Some(ref entry) = user_entry {
                // Set HOME/SHELL so the login shell finds the correct rc files.
                // SAFETY: single-threaded at this point; no concurrent env reads.
                unsafe {
                    std::env::set_var("HOME", &entry.home);
                    std::env::set_var("SHELL", &entry.shell);
                }
                drop_privileges(entry);
            }
            let err = std::process::Command::new("sh").arg("-c").arg(&cmd).exec();
            eprintln!("theyos-ssh: mac-host pty exec failed: {err}");
        }
        "exec" => {
            if args.len() < 4 {
                eprintln!("Usage: theyos-ssh exec mac-host <command> [args...]");
                std::process::exit(1);
            }
            let user_cmd = args[3..].join(" ");
            let cmd = format!("{path_prefix}; {user_cmd}");
            if let Some(ref entry) = user_entry {
                // SAFETY: single-threaded at this point; no concurrent env reads.
                unsafe {
                    std::env::set_var("HOME", &entry.home);
                }
                drop_privileges(entry);
            }
            let err = std::process::Command::new("sh").arg("-c").arg(&cmd).exec();
            eprintln!("theyos-ssh: mac-host exec failed: {err}");
        }
        other => {
            eprintln!("theyos-ssh: mac-host does not support subcommand '{other}'");
        }
    }
    std::process::exit(1)
}

/// Query the vmrunner IPC for the VM IP.
///
/// Sends a `Status` request to the socket at `THEYOS_VMRUNNER_SOCK` and
/// extracts `vm_ip` from the response.
fn get_vm_ip(container: &str) -> Result<String, String> {
    let sock_path = std::env::var("THEYOS_VMRUNNER_SOCK")
        .unwrap_or_else(|_| "/tmp/vmrunner-macos.sock".to_string());

    // Try socket-based IPC first (when vmrunner is running as a socket server).
    // Fall back to reading persisted vm_ip file from instance directory.
    if let Ok(ip) = read_persisted_ip(container) {
        return Ok(ip);
    }

    // Try IPC via Unix socket (JSON line protocol).
    query_ipc_socket(&sock_path, container).or_else(|_| read_persisted_ip(container))
}

/// Read the persisted VM IP from the instance's `vm_ip` file.
fn read_persisted_ip(container: &str) -> Result<String, String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let ip_path = PathBuf::from(home)
        .join("Library/Application Support/theyos/vms")
        .join(container)
        .join("vm_ip");

    std::fs::read_to_string(&ip_path)
        .map(|s| s.trim().to_string())
        .map_err(|_| format!("vm_ip file not found at {}", ip_path.display()))
}

/// Send a `Status` JSON request to the vmrunner IPC socket.
fn query_ipc_socket(sock_path: &str, container: &str) -> Result<String, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let mut stream =
        UnixStream::connect(sock_path).map_err(|e| format!("connect to {sock_path}: {e}"))?;

    let req = serde_json::json!({
        "method": "Status",
        "params": { "container": container }
    });
    let req_str = req.to_string() + "\n";
    stream
        .write_all(req_str.as_bytes())
        .map_err(|e| format!("write IPC request: {e}"))?;

    let mut line = String::new();
    BufReader::new(&stream)
        .read_line(&mut line)
        .map_err(|e| format!("read IPC response: {e}"))?;

    let resp: serde_json::Value =
        serde_json::from_str(&line).map_err(|e| format!("parse IPC response: {e}"))?;

    if resp["ok"].as_bool() != Some(true) {
        return Err(resp["error"]
            .as_str()
            .unwrap_or("unknown error")
            .to_string());
    }

    resp["result"]["vm_ip"]
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| "vm_ip not in IPC response".to_string())
}

/// Return the SSH private key path.
fn ssh_key_path() -> PathBuf {
    if let Ok(key) = std::env::var("THEYOS_SSH_KEY") {
        return PathBuf::from(key);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".theyos/keys/id_ed25519")
}
