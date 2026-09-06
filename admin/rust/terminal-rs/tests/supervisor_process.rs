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
    let mut request = spawn_request();
    wire::send_control(
        &mut stream,
        2,
        Control::IssueIntent {
            conversation_id: request.conversation_id.clone(),
        },
    )
    .await
    .unwrap();
    let Control::IntentIssued { intent_id, .. } = control(&mut stream).await else {
        panic!("ticket expected")
    };
    request.intent_id = intent_id;
    wire::send_control(&mut stream, 2, Control::Create { request })
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

async fn issued_request(daemon: &Daemon) -> SpawnRequest {
    let mut request = spawn_request();
    let Control::IntentIssued {
        intent_id,
        conversation_id,
    } = daemon
        .request(Control::IssueIntent {
            conversation_id: request.conversation_id.clone(),
        })
        .await
    else {
        panic!("ticket issuance failed")
    };
    assert_eq!(conversation_id, request.conversation_id);
    request.intent_id = intent_id;
    request
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
    let session = create(&daemon, issued_request(&daemon).await).await;
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
    let request = issued_request(&daemon).await;
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
    let second = create(&daemon, issued_request(&daemon).await).await;
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
    let session = create(&daemon, issued_request(&daemon).await).await;
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
    let request = issued_request(&daemon).await;
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
    let fresh = create(&daemon, issued_request(&daemon).await).await;
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
    let request = issued_request(&daemon).await;
    let cancel = Control::CancelCreate {
        conversation_id: request.conversation_id.clone(),
        intent_id: request.intent_id.clone(),
    };
    for _ in 0..2 {
        assert!(matches!(daemon.request(cancel.clone()).await, Control::Ok));
    }
    assert!(matches!(daemon.request(Control::Create { request }).await,
        Control::Error { code } if code == "intent_consumed"));
    let first_request = issued_request(&daemon).await;
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
    let replacement = create(&daemon, issued_request(&daemon).await).await;
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
        3
    );
    daemon
        .request(Control::Close {
            conversation_id: replacement.conversation_id,
            session_instance_id: replacement.session_instance_id,
        })
        .await;
}

#[tokio::test]
async fn ticket_pressure_keeps_live_sessions_and_never_reexecutes_collected_requests() {
    let daemon = Daemon::start().await;
    let canary = daemon.root.path().join("executions");
    let mut old = spawn_request();
    old.conversation_id = "retired-pane".into();
    old.argv = vec![
        "/bin/sh".into(),
        "-c".into(),
        "printf x >> \"$1\"".into(),
        "fixture".into(),
        canary.to_string_lossy().into_owned(),
    ];
    let Control::IntentIssued { intent_id, .. } = daemon
        .request(Control::IssueIntent {
            conversation_id: old.conversation_id.clone(),
        })
        .await
    else {
        panic!("ticket required")
    };
    old.intent_id = intent_id;
    let ended = create(&daemon, old.clone()).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let Control::Session { info } = daemon
                .request(Control::Get {
                    conversation_id: ended.conversation_id.clone(),
                })
                .await
            else {
                panic!("session required")
            };
            if info.closed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(std::fs::read(&canary).unwrap(), b"x");
    let live = create(&daemon, issued_request(&daemon).await).await;
    let identity = process_identity(live.pid);
    let mut stream = connect(&daemon.socket).await.unwrap();
    tokio::time::timeout(Duration::from_secs(120), async {
        for _ in 0..4200 {
            wire::send_control(
                &mut stream,
                2,
                Control::IssueIntent {
                    conversation_id: "unused-pane".into(),
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                control(&mut stream).await,
                Control::IntentIssued { .. }
            ));
        }
    })
    .await
    .expect("bounded ticket pressure test");
    assert!(
        std::fs::read_dir(daemon.state.join("intents"))
            .unwrap()
            .count()
            <= 4096
    );
    assert!(
        matches!(daemon.request(Control::Create { request: old }).await,
        Control::Error { code } if code == "intent_expired")
    );
    assert_eq!(std::fs::read(&canary).unwrap(), b"x");
    assert_eq!(process_identity(live.pid), identity);
    assert!(daemon.state.join("intents").join(&live.intent_id).exists());
    let mut attached = attach(&daemon, &live, 0).await;
    write(
        &daemon,
        &live,
        b"printf '\\120\\122\\105\\123\\105\\122\\126\\105\\104\\n'\n".to_vec(),
    )
    .await;
    read_until(&mut attached, b"PRESERVED", &mut 0).await;
    assert!(matches!(
        daemon
            .request(Control::CancelCreate {
                conversation_id: live.conversation_id,
                intent_id: live.intent_id,
            })
            .await,
        Control::Ok
    ));
}

#[tokio::test]
async fn archived_instances_are_bounded_while_a_live_shell_keeps_its_history() {
    let daemon = Daemon::start().await;
    let mut live_request = spawn_request();
    live_request.conversation_id = "protected-shell".into();
    let Control::IntentIssued { intent_id, .. } = daemon
        .request(Control::IssueIntent {
            conversation_id: live_request.conversation_id.clone(),
        })
        .await
    else {
        panic!("live ticket missing")
    };
    live_request.intent_id = intent_id;
    let live = create(&daemon, live_request).await;
    let identity = process_identity(live.pid);
    let mut live_stream = attach(&daemon, &live, 0).await;
    let mut live_cursor = 0;
    write(
        &daemon,
        &live,
        b"printf '\\120\\122\\117\\124\\105\\103\\124\\105\\104\\n'\n".to_vec(),
    )
    .await;
    read_until(&mut live_stream, b"PROTECTED", &mut live_cursor).await;
    for _ in 0..80 {
        let mut request = issued_request(&daemon).await;
        request.argv = vec!["/bin/sh".into(), "-c".into(), "printf archive".into()];
        let session = create(&daemon, request).await;
        let mut stream = attach(&daemon, &session, 0).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Frame::Control {
                    message: Control::Exit { .. },
                    ..
                } = wire::read_frame(&mut stream).await.unwrap()
                {
                    break;
                }
            }
        })
        .await
        .expect("archive child must finish");
    }
    // Another allocation collects the final completed entry as well.
    let final_session = create(&daemon, issued_request(&daemon).await).await;
    // Count actual instance directories across all conversations, excluding
    // the two still-live owners, rather than trusting broker accounting.
    let mut count = 0;
    let mut bytes = 0_u64;
    for conversation in std::fs::read_dir(daemon.state.join("sessions")).unwrap() {
        for instance in std::fs::read_dir(conversation.unwrap().path()).unwrap() {
            let instance = instance.unwrap();
            if instance.file_name() == live.session_instance_id.as_str()
                || instance.file_name() == final_session.session_instance_id.as_str()
            {
                continue;
            }
            count += 1;
            for file in std::fs::read_dir(instance.path()).unwrap() {
                bytes += file.unwrap().metadata().unwrap().len();
            }
        }
    }
    assert_eq!(
        count, 64,
        "archive pressure must actually collect older instances"
    );
    assert!(bytes <= 256 * 1024 * 1024);
    assert_eq!(process_identity(live.pid), identity);
    let mut replay = attach(&daemon, &live, 0).await;
    read_until(&mut replay, b"PROTECTED", &mut 0).await;
    write(
        &daemon,
        &live,
        b"printf '\\101\\106\\124\\105\\122\\055\\107\\103\\n'\n".to_vec(),
    )
    .await;
    read_until(&mut live_stream, b"AFTER-GC", &mut live_cursor).await;
}

#[tokio::test]
async fn slow_reader_cannot_block_rotation_and_reattach_reports_retained_gap() {
    let daemon = Daemon::start().await;
    let completed = daemon.root.path().join("producer-finished");
    let mut request = issued_request(&daemon).await;
    request.argv = vec!["/bin/sh".into(), "-c".into(),
        "stty -echo; printf READY; read trigger; dd if=/dev/zero bs=65536 count=640 2>/dev/null; printf OUTPUT-END; printf done > \"$1\"; read finish; printf IO-CHALLENGE".into(),
        "producer".into(), completed.to_string_lossy().into_owned()];
    let session = create(&daemon, request).await;
    let identity = process_identity(session.pid);
    let mut slow = attach(&daemon, &session, 0).await;
    read_until(&mut slow, b"READY", &mut 0).await;
    write(&daemon, &session, b"start\n".to_vec()).await;
    // Stop consuming the attached stream. The producer must still finish
    // forty MiB, well beyond both the socket buffer and retention budget.
    tokio::time::timeout(Duration::from_secs(30), async {
        while !completed.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("slow reader blocked PTY producer");
    assert_eq!(std::fs::read(&completed).unwrap(), b"done");
    assert_eq!(process_identity(session.pid), identity);
    let directory = daemon
        .state
        .join("sessions")
        .join(&session.conversation_id)
        .join(&session.session_instance_id);
    let bytes: u64 = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum();
    assert!(
        bytes <= 32 * 1024 * 1024,
        "physical output retention exceeded budget: {bytes}"
    );
    drop(slow);
    let mut replay = attach(&daemon, &session, 0).await;
    let Control::Gap { from, to, .. } = control(&mut replay).await else {
        panic!("retention silently changed the requested cursor")
    };
    assert_eq!(from, 0);
    assert!(to > 0);
    let mut cursor = to;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match wire::read_frame(&mut replay).await.unwrap() {
                Frame::Data {
                    start_offset,
                    bytes,
                    ..
                } => {
                    assert_eq!(start_offset, cursor);
                    cursor += bytes.len() as u64;
                }
                Frame::Control {
                    message: Control::ReplayEnd { offset },
                    ..
                } => {
                    assert_eq!(cursor, offset);
                    assert!(cursor >= 40 * 1024 * 1024);
                    break;
                }
                other @ Frame::Control { .. } => panic!("unexpected replay event {other:?}"),
            }
        }
    })
    .await
    .expect("retained replay deadline");
    write(&daemon, &session, b"finish\n".to_vec()).await;
    read_until(&mut replay, b"IO-CHALLENGE", &mut cursor).await;
}

#[tokio::test]
async fn rotation_write_failure_reports_exact_final_output_and_recovers_committed_log() {
    let mut daemon = Daemon::start().await;
    let mut request = issued_request(&daemon).await;
    request.argv = vec!["/bin/sh".into(), "-c".into(),
        "stty -echo; printf READY; read trigger; dd if=/dev/zero bs=65536 count=32 2>/dev/null; read finish".into()];
    let session = create(&daemon, request).await;
    let directory = daemon
        .state
        .join("sessions")
        .join(&session.conversation_id)
        .join(&session.session_instance_id);
    let mut stream = attach(&daemon, &session, 0).await;
    let mut cursor = 0;
    read_until(&mut stream, b"READY", &mut cursor).await;
    // An actual filesystem refusal at the next rotation, without filling the
    // developer's disk or changing any installed service or global permission.
    std::fs::create_dir(directory.join(".next")).unwrap();
    write(&daemon, &session, b"rotate\n".to_vec()).await;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match wire::read_frame(&mut stream).await.unwrap() {
                Frame::Data {
                    start_offset,
                    bytes,
                    ..
                } => {
                    assert_eq!(start_offset, cursor);
                    cursor += bytes.len() as u64;
                }
                Frame::Control {
                    message: Control::ReplayEnd { .. },
                    ..
                } => {}
                Frame::Control {
                    message:
                        Control::Exit {
                            final_offset,
                            reason,
                            ..
                        },
                    ..
                } => {
                    assert_eq!(reason, "log_write_failed");
                    assert_eq!(final_offset, cursor);
                    assert!(cursor > 5 && cursor < 512 * 1024);
                    break;
                }
                other @ Frame::Control { .. } => panic!("unexpected failure event {other:?}"),
            }
        }
    })
    .await
    .expect("log failure must produce a terminal outcome");
    // The broker remains reachable; only the session unable to record output
    // was stopped. Recovery below addresses its immutable committed prefix.
    assert!(matches!(
        daemon.request(Control::List).await,
        Control::Sessions { .. }
    ));
    drop(stream);
    daemon.child.kill().unwrap();
    daemon.child.wait().unwrap();
    std::fs::remove_dir(directory.join(".next")).unwrap();
    let log = terminal_rs::segmented_log::SegmentedLog::open(
        &directory,
        terminal_rs::segmented_log::LogLimits::default(),
    )
    .unwrap();
    assert_eq!(log.bounds().unwrap(), (0, cursor));
    let mut replayed = 0;
    while replayed < cursor {
        let terminal_rs::segmented_log::ReplayRead::Data(chunk) =
            log.read(replayed, 65536).unwrap()
        else {
            panic!("committed prefix lost")
        };
        assert_eq!(chunk.start_offset, replayed);
        replayed += chunk.bytes.len() as u64;
    }
    assert_eq!(replayed, cursor);
}
