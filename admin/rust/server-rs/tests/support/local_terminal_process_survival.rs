//! Process-isolated engine HTTP adapter + broker + real interactive workload.
//! This tests the production terminal handlers, not installed launchd labels,
//! the complete engine startup path, or the Mac emulator's rendering.

use super::fixture_with_supervisor;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use terminal_rs::supervisor_client::SupervisorClient;
use terminal_rs::supervisor_wire::Control;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Message};

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct OwnedProcess(Child);
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn component_process_helper() {
    let Ok(root) = std::env::var("SOYEHT_PTY_PROCESS_FIXTURE") else {
        return;
    };
    let root = PathBuf::from(root);
    match std::env::var("SOYEHT_PTY_PROCESS_ROLE").unwrap().as_str() {
        "broker" => {
            terminal_rs::supervisor::serve(&root.join("socket"), &root.join("state"))
                .await
                .unwrap();
        }
        "engine" => {
            let (app, _) =
                fixture_with_supervisor(Some(SupervisorClient::new(root.join("socket"))));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let ready =
                json!({"pid": std::process::id(), "port": listener.local_addr().unwrap().port()});
            std::fs::write(
                root.join("engine.next"),
                serde_json::to_vec(&ready).unwrap(),
            )
            .unwrap();
            std::fs::rename(root.join("engine.next"), root.join("engine.json")).unwrap();
            core_rs::product_a_phase0::serve_with_connect_info::<_, std::net::SocketAddr>(
                listener, app,
            )
            .await
            .unwrap();
        }
        _ => panic!("unknown disposable process role"),
    }
}

fn spawn(root: &Path, role: &str) -> OwnedProcess {
    OwnedProcess(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process_survival::component_process_helper",
                "--nocapture",
            ])
            .env("SOYEHT_PTY_PROCESS_FIXTURE", root)
            .env("SOYEHT_PTY_PROCESS_ROLE", role)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

async fn engine_ready(root: &Path, process: &mut OwnedProcess) -> String {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "engine helper exited before readiness"
            );
            if let Ok(bytes) = std::fs::read(root.join("engine.json")) {
                let ready: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(ready["pid"].as_u64().unwrap(), u64::from(process.0.id()));
                return format!("http://127.0.0.1:{}", ready["port"]);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("engine process readiness")
}

fn identity(pid: u32) -> String {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "pid=,pgid=,tty=,lstart="])
        .output()
        .unwrap();
    assert!(output.status.success(), "process {pid} disappeared");
    let value = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    assert!(!value.is_empty());
    value
}

fn foreground_group(tty: &str) -> u32 {
    let output = Command::new("/bin/ps")
        .args(["-t", tty.trim_start_matches("/dev/"), "-o", "pgid=,stat="])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.len() == 2 && fields[1].contains('+')).then(|| fields[0].parse().unwrap())
        })
        .expect("TTY has a foreground process group")
}

async fn json_response(request: reqwest::RequestBuilder) -> Value {
    let response = request.send().await.unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "HTTP {status}: {body}");
    serde_json::from_str(&body).unwrap()
}

async fn attach(base: &str, session: &Value, cursor: u64) -> Socket {
    let url = format!(
        "{}/api/v1/terminals/local/process-pane/pty?session_instance_id={}&stream_protocol=1&next_offset={cursor}",
        base.replacen("http:", "ws:", 1),
        session["session_instance_id"].as_str().unwrap()
    );
    let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let Message::Text(event) = socket.next().await.unwrap().unwrap() else {
        panic!("missing attached control")
    };
    assert_eq!(
        serde_json::from_str::<Value>(&event).unwrap()["type"],
        "attached"
    );
    socket
}

async fn input(socket: &mut Socket, data: &str) {
    // The JSON input shape is the actual Mac path, not a binary-only shortcut.
    socket
        .send(Message::Text(
            json!({"type": "input", "data": data}).to_string().into(),
        ))
        .await
        .unwrap();
}

async fn until(socket: &mut Socket, cursor: &mut u64, marker: &str) -> String {
    let mut output = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match socket.next().await.expect("stream ended").unwrap() {
                Message::Binary(bytes) => {
                    let prefix = server_rs::supervised_terminals::OUTPUT_PREFIX;
                    assert!(bytes.starts_with(prefix));
                    let offset = u64::from_be_bytes(
                        bytes[prefix.len()..prefix.len() + 8].try_into().unwrap(),
                    );
                    assert_eq!(offset, *cursor, "no skipped or duplicated output");
                    let data = &bytes[prefix.len() + 8..];
                    *cursor += data.len() as u64;
                    output.extend_from_slice(data);
                    if output
                        .windows(marker.len())
                        .any(|bytes| bytes == marker.as_bytes())
                    {
                        return String::from_utf8_lossy(&output).into_owned();
                    }
                }
                Message::Text(event) => {
                    assert_eq!(
                        serde_json::from_str::<Value>(&event).unwrap()["type"],
                        "replay_end"
                    );
                }
                other => panic!("unexpected terminal event {other:?}"),
            }
        }
    })
    .await;
    result.unwrap_or_else(|_| {
        panic!(
            "interactive output deadline waiting for {marker}; received {:?}",
            String::from_utf8_lossy(&output)
        )
    })
}

fn marked_pid(output: &str, marker: &str) -> u32 {
    output
        .split(marker)
        .nth(1)
        .expect("missing process identity marker")
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap()
}

const TUI: &str = r"import os, select, sys, termios, tty, time
gate, done = sys.argv[1:]
previous = termios.tcgetattr(0)
tty.setraw(0)
try:
    print('\x1b[?1049hTUI_READY:%d\r' % os.getpid(), flush=True)
    pending = b''
    emitted = False
    while True:
        if not emitted and os.path.exists(gate):
            for number in range(1, 65):
                print('ABSENT:%03d\r' % number, flush=True)
                time.sleep(0.01)
            with open(done, 'w') as handle: handle.write('64')
            emitted = True
        if not select.select([0], [], [], 0.02)[0]: continue
        pending += os.read(0, 4096)
        while b'\n' in pending:
            line, pending = pending.split(b'\n', 1)
            if line == b'quit':
                print('\x1b[?1049lTUI_EXIT\r', flush=True)
                sys.exit(0)
            if line.startswith(b'challenge:'):
                print('TUI_IO:' + line[10:].decode() + '\r', flush=True)
finally:
    termios.tcsetattr(0, termios.TCSADRAIN, previous)
";

#[tokio::test]
async fn engine_process_sigkill_preserves_shell_tui_job_and_absent_output() {
    exercise_process_survival(false).await;
}

#[tokio::test]
async fn negative_control_broker_death_loses_the_same_instrumented_workload() {
    exercise_process_survival(true).await;
}

async fn exercise_process_survival(kill_broker: bool) {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::Builder::new()
        .prefix("pty-engine-")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(root.path().join("tui.py"), TUI).unwrap();
    let mut broker = spawn(root.path(), "broker");
    let broker_client = SupervisorClient::new(root.path().join("socket"));
    tokio::time::timeout(Duration::from_secs(10), async {
        while broker_client.request(Control::List).await.is_err() {
            assert!(broker.0.try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let broker_identity = identity(broker.0.id());
    let mut engine = spawn(root.path(), "engine");
    let base = engine_ready(root.path(), &mut engine).await;
    let engine_identity = identity(engine.0.id());
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let ticket = json_response(http.post(format!(
        "{base}/api/v1/terminals/local/process-pane/intents"
    )))
    .await;
    let session = json_response(http.post(format!("{base}/api/v1/terminals/local")).json(&json!({
        "conversation_id": "process-pane", "intent_id": ticket["intent_id"],
        "argv": ["/bin/bash", "--noprofile", "--norc", "-i"],
        "cwd": root.path(), "env": [["TERM", "xterm-256color"], ["PATH", "/usr/bin:/bin"], ["HISTFILE", "/dev/null"]], "cols": 80, "rows": 24,
    }))).await;
    let shell_pid = u32::try_from(session["pid"].as_u64().unwrap()).unwrap();
    let shell_identity = identity(shell_pid);
    let tty = session["slave_tty_path"].as_str().unwrap();
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let mut socket = attach(&base, &session, 0).await;
    let mut cursor = 0;
    input(&mut socket, &format!("set +H; stty -echo; SOYEHT_NONCE='{nonce}'; export -n SOYEHT_NONCE; /bin/sleep 120 &\nprintf 'JOB_PID:%s\\n' \"$!\"; /usr/bin/python3 -u tui.py absent.trigger absent.done\n")).await;
    let armed = until(&mut socket, &mut cursor, "TUI_READY:").await;
    // Read through a separate response so the PID suffix cannot be truncated
    // at the marker boundary by the PTY's arbitrary chunking.
    input(&mut socket, "challenge:armed\n").await;
    let armed = armed + &until(&mut socket, &mut cursor, "TUI_IO:armed").await;
    let job_pid = marked_pid(&armed, "JOB_PID:");
    let tui_pid = marked_pid(&armed, "TUI_READY:");
    let job_identity = identity(job_pid);
    let tui_identity = identity(tui_pid);
    assert_eq!(foreground_group(tty), tui_pid);
    assert!(!armed.contains("ABSENT:001"));

    if kill_broker {
        // Calibration uses the very same armed workload and observations.
        // Losing the exclusive PTY owner must not be reported as survival.
        broker.0.kill().unwrap();
        broker.0.wait().unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut all_gone = true;
                for pid in [shell_pid, job_pid, tui_pid] {
                    let output = Command::new("/bin/ps")
                        .args(["-p", &pid.to_string(), "-o", "pid="])
                        .output()
                        .unwrap();
                    all_gone &= output.stdout.is_empty();
                }
                if all_gone {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("negative control must lose shell, TUI and job");
        std::fs::write(root.path().join("absent.trigger"), b"owner is absent").unwrap();
        assert!(!root.path().join("absent.done").exists());
        assert_eq!(identity(engine.0.id()), engine_identity);
        return;
    }

    engine.0.kill().unwrap();
    engine.0.wait().unwrap();
    assert!(
        Command::new("/bin/ps")
            .args(["-p", &engine.0.id().to_string(), "-o", "pid="])
            .output()
            .unwrap()
            .stdout
            .is_empty()
    );
    assert!(
        http.get(format!("{base}/api/v1/terminals/local"))
            .send()
            .await
            .is_err()
    );
    drop(socket);
    std::fs::write(root.path().join("absent.trigger"), b"engine is absent").unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !root.path().join("absent.done").exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("output must be produced while the engine is absent");
    assert_eq!(
        std::fs::read(root.path().join("absent.done")).unwrap(),
        b"64"
    );
    assert_eq!(identity(shell_pid), shell_identity);
    assert_eq!(identity(job_pid), job_identity);
    assert_eq!(identity(tui_pid), tui_identity);
    assert_eq!(foreground_group(tty), tui_pid);
    assert_eq!(identity(broker.0.id()), broker_identity);

    std::fs::remove_file(root.path().join("engine.json")).unwrap();
    let mut replacement = spawn(root.path(), "engine");
    let base = engine_ready(root.path(), &mut replacement).await;
    assert_ne!(identity(replacement.0.id()), engine_identity);
    let restored =
        json_response(http.get(format!("{base}/api/v1/terminals/local/process-pane"))).await;
    assert_eq!(
        restored["session_instance_id"],
        session["session_instance_id"]
    );
    assert_eq!(restored["pid"], session["pid"]);
    let mut socket = attach(&base, &session, cursor).await;
    let challenge = uuid::Uuid::new_v4().simple().to_string();
    input(&mut socket, &format!("challenge:{challenge}\n")).await;
    let after = until(&mut socket, &mut cursor, &format!("TUI_IO:{challenge}")).await;
    for number in 1..=64 {
        assert_eq!(after.matches(&format!("ABSENT:{number:03}")).count(), 1);
    }
    input(&mut socket, "quit\n").await;
    until(&mut socket, &mut cursor, "TUI_EXIT").await;
    input(&mut socket, &format!("printf 'AFTER:%s\\n' \"$SOYEHT_NONCE\"; env | grep '^SOYEHT_NONCE='; jobs -l; printf 'SHELL_IO:%s\\n' '{challenge}'\n")).await;
    let after = until(&mut socket, &mut cursor, &format!("SHELL_IO:{challenge}")).await;
    assert!(after.contains(&format!("AFTER:{nonce}")));
    assert!(!after.contains(&format!("SOYEHT_NONCE={nonce}")));
    assert!(after.contains(&job_pid.to_string()));
    assert_eq!(identity(job_pid), job_identity);
    assert_eq!(foreground_group(tty), shell_pid);
    let response = http
        .delete(format!("{base}/api/v1/terminals/local/process-pane"))
        .header(
            "If-Match",
            format!("\"{}\"", session["session_instance_id"].as_str().unwrap()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
}
