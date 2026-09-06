//! Real binary + PTY + disposable client process. Never uses launchd, the
//! installed engine, or an existing terminal. All paths live under /tmp.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use terminal_rs::supervisor_wire::{self as wire, Control, Frame, SessionInfo, SpawnRequest};
use tokio::net::UnixStream;
use uuid::Uuid;

struct Daemon {
    child: Child,
    socket: PathBuf,
    state: PathBuf,
    root: tempfile::TempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    async fn start() -> Self {
        let root = tempfile::Builder::new()
            .prefix("ptyd-")
            .tempdir_in("/tmp")
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.path().join("socket");
        let state = root.path().join("state");
        let child = spawn_daemon(&socket, &state);
        let mut daemon = Self {
            child,
            socket,
            state,
            root,
        };
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if connect(&daemon.socket).await.is_ok() {
                    break;
                }
                assert!(
                    daemon.child.try_wait().unwrap().is_none(),
                    "daemon exited before readiness"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("daemon ready deadline");
        daemon
    }

    async fn request(&self, message: Control) -> Control {
        let mut stream = connect(&self.socket).await.unwrap();
        wire::send_control(&mut stream, 2, message).await.unwrap();
        control(&mut stream).await
    }
}

fn spawn_daemon(socket: &Path, state: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_soyeht-ptyd"))
        .arg("--socket")
        .arg(socket)
        .arg("--state-dir")
        .arg(state)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

#[tokio::test]
async fn cancelling_service_closes_workers_before_releasing_ownership() {
    let root = tempfile::Builder::new()
        .prefix("ptyd-")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.path().join("socket");
    let state = root.path().join("state");
    let service_socket = socket.clone();
    let service_state = state.clone();
    let service = tokio::spawn(async move {
        terminal_rs::supervisor::serve(&service_socket, &service_state).await
    });
    let mut stream = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(stream) = connect(&socket).await {
                break stream;
            }
            assert!(!service.is_finished(), "service exited before readiness");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    wire::send_control(
        &mut stream,
        2,
        Control::Create {
            request: spawn_request(),
        },
    )
    .await
    .unwrap();
    let Control::Created { info, .. } = control(&mut stream).await else {
        panic!("session expected");
    };
    service.abort();
    assert!(service.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let process = Command::new("/bin/ps")
                .args(["-p", &info.pid.to_string(), "-o", "pid="])
                .output()
                .unwrap();
            if !socket.exists() && process.stdout.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("service workers and child must stop after cancellation");
    assert!(wire::read_frame(&mut stream).await.is_err());
    let mut replacement = spawn_daemon(&socket, &state);
    let ready = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if connect(&socket).await.is_ok() {
                break;
            }
            assert!(replacement.try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    replacement.kill().unwrap();
    replacement.wait().unwrap();
    ready.expect("replacement acquires released socket and state");
}

async fn connect(socket: &Path) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(socket).await?;
    wire::send_control(
        &mut stream,
        1,
        Control::Hello {
            supported_versions: vec![wire::VERSION],
        },
    )
    .await?;
    match wire::read_frame(&mut stream).await? {
        Frame::Control {
            message:
                Control::Welcome {
                    selected_version: wire::VERSION,
                    ..
                },
            ..
        } => Ok(stream),
        _ => Err(io::Error::other("version negotiation failed")),
    }
}

async fn control(stream: &mut UnixStream) -> Control {
    match tokio::time::timeout(Duration::from_secs(10), wire::read_frame(stream))
        .await
        .unwrap()
        .unwrap()
    {
        Frame::Control { message, .. } => message,
        other @ Frame::Data { .. } => panic!("control expected, got {other:?}"),
    }
}

fn spawn_request() -> SpawnRequest {
    SpawnRequest {
        intent_id: Uuid::new_v4().to_string(),
        conversation_id: "test-pane".into(),
        argv: vec![
            "/bin/bash".into(),
            "--noprofile".into(),
            "--norc".into(),
            "-i".into(),
        ],
        cwd: "/tmp".into(),
        env: vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("PS1".into(), String::new()),
        ],
        cols: 80,
        rows: 24,
    }
}

async fn create(daemon: &Daemon, request: SpawnRequest) -> SessionInfo {
    let Control::Created { info, .. } = daemon.request(Control::Create { request }).await else {
        panic!("create failed")
    };
    info
}

async fn write(daemon: &Daemon, session: &SessionInfo, bytes: Vec<u8>) {
    assert!(matches!(
        daemon
            .request(Control::Write {
                conversation_id: session.conversation_id.clone(),
                session_instance_id: session.session_instance_id.clone(),
                bytes,
            })
            .await,
        Control::Ok
    ));
}

async fn attach(daemon: &Daemon, session: &SessionInfo, next_offset: u64) -> UnixStream {
    let mut stream = connect(&daemon.socket).await.unwrap();
    wire::send_control(
        &mut stream,
        3,
        Control::Attach {
            conversation_id: session.conversation_id.clone(),
            session_instance_id: session.session_instance_id.clone(),
            next_offset,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        control(&mut stream).await,
        Control::Attached { .. }
    ));
    stream
}

async fn read_until(stream: &mut UnixStream, needle: &[u8], cursor: &mut u64) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut result = Vec::new();
        loop {
            match wire::read_frame(stream).await.unwrap() {
                Frame::Data {
                    start_offset,
                    bytes,
                    ..
                } => {
                    assert_eq!(
                        start_offset, *cursor,
                        "replay/live must not duplicate or skip bytes"
                    );
                    *cursor += bytes.len() as u64;
                    result.extend(bytes);
                    if result.windows(needle.len()).any(|part| part == needle) {
                        return result;
                    }
                }
                Frame::Control {
                    message: Control::ReplayEnd { .. },
                    ..
                } => {}
                other @ Frame::Control { .. } => panic!("unexpected stream event {other:?}"),
            }
        }
    })
    .await
    .expect("output deadline")
}

fn process_identity(pid: u32) -> String {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "pid=,lstart=,tty=,pgid="])
        .output()
        .unwrap();
    assert!(output.status.success());
    let identity = String::from_utf8(output.stdout).unwrap();
    assert!(!identity.trim().is_empty());
    identity
}

#[tokio::test]
async fn client_process_helper() {
    let Ok(socket) = std::env::var("SOYEHT_TEST_PTY_SOCKET") else {
        return;
    };
    let mut stream = connect(Path::new(&socket)).await.unwrap();
    wire::send_control(
        &mut stream,
        3,
        Control::Attach {
            conversation_id: "test-pane".into(),
            session_instance_id: std::env::var("SOYEHT_TEST_PTY_INSTANCE").unwrap(),
            next_offset: 0,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        control(&mut stream).await,
        Control::Attached { .. }
    ));
    std::fs::write(std::env::var("SOYEHT_TEST_PTY_READY").unwrap(), b"attached").unwrap();
    loop {
        wire::read_frame(&mut stream).await.unwrap();
    }
}

#[tokio::test]
async fn shell_state_and_absent_output_survive_killed_client_process() {
    let daemon = Daemon::start().await;
    let session = create(&daemon, spawn_request()).await;
    let before = process_identity(session.pid);
    let daemon_before = process_identity(daemon.child.id());
    let nonce = Uuid::new_v4().to_string();
    let mut stream = attach(&daemon, &session, 0).await;
    let mut cursor = 0;
    write(&daemon, &session, format!("stty -echo; SOYEHT_NONCE='{nonce}'; export -n SOYEHT_NONCE; printf '\\nREADY:%s\\n' \"$SOYEHT_NONCE\"\n").into_bytes()).await;
    read_until(
        &mut stream,
        format!("READY:{nonce}").as_bytes(),
        &mut cursor,
    )
    .await;
    drop(stream);
    let ready = daemon.root.path().join("client-ready");
    let mut client = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "client_process_helper", "--nocapture"])
        .env("SOYEHT_TEST_PTY_SOCKET", &daemon.socket)
        .env("SOYEHT_TEST_PTY_INSTANCE", &session.session_instance_id)
        .env("SOYEHT_TEST_PTY_READY", &ready)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    client.kill().unwrap();
    client.wait().unwrap();
    // RPC returns before the shell runs this command. It then produces all
    // numbered output with no attached output subscriber.
    write(
        &daemon,
        &session,
        b"for n in {1..64}; do printf 'ABSENT:%03d\\n' \"$n\"; done\n".to_vec(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    let mut stream = attach(&daemon, &session, cursor).await;
    let mut replay = read_until(&mut stream, b"ABSENT:064", &mut cursor).await;
    write(&daemon, &session, b"printf 'AFTER:%s\\n' \"$SOYEHT_NONCE\"; env | /usr/bin/grep '^SOYEHT_NONCE='; printf 'IO-CHALLENGE-DONE\\n'\n".to_vec()).await;
    let output = read_until(&mut stream, b"IO-CHALLENGE-DONE", &mut cursor).await;
    // Count replay through a subsequent shell response, not only the first
    // occurrence of the final numbered line. Offset continuity is also checked
    // by read_until for every frame consumed across this boundary.
    replay.extend_from_slice(&output);
    let replay = String::from_utf8(replay).unwrap();
    for n in 1..=64 {
        assert_eq!(replay.matches(&format!("ABSENT:{n:03}")).count(), 1);
    }
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains(&format!("AFTER:{nonce}")));
    assert!(!output.contains(&format!("SOYEHT_NONCE={nonce}")));
    assert_eq!(process_identity(session.pid), before);
    assert_eq!(process_identity(daemon.child.id()), daemon_before);
    assert!(matches!(
        daemon
            .request(Control::Close {
                conversation_id: session.conversation_id,
                session_instance_id: session.session_instance_id
            })
            .await,
        Control::Ok
    ));
}

#[tokio::test]
async fn duplicate_create_and_stale_mutations_never_target_a_new_instance() {
    let daemon = Daemon::start().await;
    let request = spawn_request();
    let first = create(&daemon, request.clone()).await;
    let duplicate = create(&daemon, request.clone()).await;
    assert_eq!(first.session_instance_id, duplicate.session_instance_id);
    assert!(matches!(
        daemon
            .request(Control::Close {
                conversation_id: first.conversation_id.clone(),
                session_instance_id: first.session_instance_id.clone()
            })
            .await,
        Control::Ok
    ));
    let second = create(&daemon, spawn_request()).await;
    assert_ne!(first.session_instance_id, second.session_instance_id);
    for message in [
        Control::Close {
            conversation_id: first.conversation_id.clone(),
            session_instance_id: first.session_instance_id.clone(),
        },
        Control::Write {
            conversation_id: first.conversation_id.clone(),
            session_instance_id: first.session_instance_id.clone(),
            bytes: b"exit\n".to_vec(),
        },
        Control::Resize {
            conversation_id: first.conversation_id.clone(),
            session_instance_id: first.session_instance_id.clone(),
            cols: 1,
            rows: 1,
        },
    ] {
        assert!(
            matches!(daemon.request(message).await, Control::Error { code } if code == "instance_mismatch")
        );
    }
    assert!(
        matches!(daemon.request(Control::Create { request }).await, Control::Error { code } if code == "intent_consumed")
    );
    assert!(
        matches!(daemon.request(Control::Get { conversation_id: second.conversation_id.clone() }).await,
        Control::Session { info } if info.session_instance_id == second.session_instance_id && !info.closed)
    );
    daemon
        .request(Control::Close {
            conversation_id: second.conversation_id,
            session_instance_id: second.session_instance_id,
        })
        .await;
}

#[tokio::test]
async fn second_daemon_and_wrong_version_do_not_disturb_the_owner() {
    let daemon = Daemon::start().await;
    let session = create(&daemon, spawn_request()).await;
    let before = process_identity(session.pid);
    let mut duplicate = spawn_daemon(&daemon.socket, &daemon.state);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = duplicate.try_wait().unwrap() {
                assert!(!status.success());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let mut invalid = UnixStream::connect(&daemon.socket).await.unwrap();
    wire::send_control(
        &mut invalid,
        1,
        Control::Hello {
            supported_versions: vec![u16::MAX],
        },
    )
    .await
    .unwrap();
    assert!(
        matches!(control(&mut invalid).await, Control::Error { code } if code == "version_mismatch")
    );
    assert_eq!(process_identity(session.pid), before);
    assert!(connect(&daemon.socket).await.is_ok());
    daemon
        .request(Control::Close {
            conversation_id: session.conversation_id,
            session_instance_id: session.session_instance_id,
        })
        .await;
}

#[tokio::test]
async fn consumed_intent_survives_supervisor_restart_without_respawning() {
    let mut daemon = Daemon::start().await;
    let request = spawn_request();
    let original = create(&daemon, request.clone()).await;
    daemon.child.kill().unwrap();
    daemon.child.wait().unwrap();
    daemon.child = spawn_daemon(&daemon.socket, &daemon.state);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if connect(&daemon.socket).await.is_ok() {
                break;
            }
            assert!(daemon.child.try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(daemon.request(Control::Create { request }).await,
        Control::Error { code } if code == "intent_consumed"));
    let fresh = create(&daemon, spawn_request()).await;
    assert_ne!(fresh.session_instance_id, original.session_instance_id);
    daemon
        .request(Control::Close {
            conversation_id: fresh.conversation_id,
            session_instance_id: fresh.session_instance_id,
        })
        .await;
}

#[tokio::test]
async fn cancellation_fences_both_create_orders_without_closing_a_replacement() {
    let daemon = Daemon::start().await;
    let request = spawn_request();
    let cancel = Control::CancelCreate {
        conversation_id: request.conversation_id.clone(),
        intent_id: request.intent_id.clone(),
    };
    for _ in 0..2 {
        assert!(matches!(daemon.request(cancel.clone()).await, Control::Ok));
    }
    assert!(matches!(daemon.request(Control::Create { request }).await,
        Control::Error { code } if code == "intent_consumed"));
    let first_request = spawn_request();
    let first = create(&daemon, first_request.clone()).await;
    let cancel_first = Control::CancelCreate {
        conversation_id: first.conversation_id.clone(),
        intent_id: first.intent_id.clone(),
    };
    assert!(matches!(
        daemon.request(cancel_first.clone()).await,
        Control::Ok
    ));
    assert!(
        matches!(daemon.request(Control::Create { request: first_request }).await,
        Control::Error { code } if code == "intent_consumed")
    );
    let replacement = create(&daemon, spawn_request()).await;
    let replacement_identity = process_identity(replacement.pid);
    // Neither a duplicate old cancellation nor one that never created a
    // process may choose the current process merely by conversation ID.
    for cancellation in [
        cancel_first,
        cancel,
        Control::CancelCreate {
            conversation_id: replacement.conversation_id.clone(),
            intent_id: Uuid::new_v4().to_string(),
        },
    ] {
        assert!(matches!(daemon.request(cancellation).await, Control::Ok));
        let Control::Session { info } = daemon
            .request(Control::Get {
                conversation_id: replacement.conversation_id.clone(),
            })
            .await
        else {
            panic!("replacement disappeared")
        };
        assert!(!info.closed);
        assert_eq!(info.session_instance_id, replacement.session_instance_id);
        assert_eq!(process_identity(info.pid), replacement_identity);
    }
    assert_eq!(
        std::fs::read_dir(daemon.state.join("intents"))
            .unwrap()
            .count(),
        4
    );
    daemon
        .request(Control::Close {
            conversation_id: replacement.conversation_id,
            session_instance_id: replacement.session_instance_id,
        })
        .await;
}
