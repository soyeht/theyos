//! The Mac Host instance route serves a supervisor-owned shell in the
//! instance framing the iPhone and the Mac already speak.
//!
//! A real supervisor (`theyos-engine ptyd`) runs; a fake `theyos-ssh` stands
//! in for the login shell so the test can read a known banner. What is
//! asserted: the shell's parent is the supervisor daemon, not this test
//! process (the stand-in for the engine); a client sees `replay_start`,
//! banner, `replay_done`, typed input echoes back; a second attach replays
//! the banner; and the shell dying ends with `session_ended`.

use axum::extract::{Query, State, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use axum_test::TestServer;
use serde::Deserialize;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use terminal_rs::supervisor_client::SupervisorClient;
use terminal_rs::supervisor_wire::Control;

const CTL_PREFIX: &[u8] = b"\x00\x01CTL:";

fn ctl_marker(name: &str) -> Vec<u8> {
    let mut bytes = CTL_PREFIX.to_vec();
    bytes.extend_from_slice(name.as_bytes());
    bytes
}

struct Daemon {
    child: Child,
    root: PathBuf,
    socket: PathBuf,
    ctl: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

async fn start_daemon(tag: &str) -> (Daemon, SupervisorClient) {
    let root = std::env::temp_dir().join(format!("mh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let socket = root.join("c.sock");
    let ctl = root.join("fake-theyos-ssh");
    // Same argv the engine hands to the real helper: `pty mac-host <session>`.
    std::fs::write(
        &ctl,
        "#!/bin/sh\nprintf 'READY %s %s\\n' \"$2\" \"$3\"\nexec /bin/sh\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let child = Command::new(env!("CARGO_BIN_EXE_server"))
        .args(["ptyd", "--socket"])
        .arg(&socket)
        .arg("--state-dir")
        .arg(root.join("state"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let client = SupervisorClient::new(socket.clone());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match client.status().await {
            Ok(_) => break,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await
            }
            Err(error) => panic!("supervisor never answered: {error:?}"),
        }
    }
    (
        Daemon {
            child,
            root,
            socket,
            ctl,
        },
        client,
    )
}

#[derive(Clone)]
struct Fixture {
    client: SupervisorClient,
    ctl: String,
}

#[derive(Deserialize)]
struct PtyQuery {
    session: String,
    #[serde(default)]
    cols: u16,
    #[serde(default)]
    rows: u16,
    #[serde(default)]
    full_replay: bool,
}

async fn pty(
    State(fx): State<Arc<Fixture>>,
    Query(q): Query<PtyQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    server_rs::mac_host_supervised::serve(
        fx.client.clone(),
        fx.ctl.clone(),
        q.session,
        q.cols,
        q.rows,
        q.full_replay,
        ws,
    )
    .await
}

fn server(daemon: &Daemon, client: &SupervisorClient) -> TestServer {
    let app = Router::new()
        .route("/pty", get(pty))
        .with_state(Arc::new(Fixture {
            client: client.clone(),
            ctl: daemon.ctl.to_string_lossy().into_owned(),
        }));
    TestServer::builder()
        .http_transport()
        .build(app)
        .expect("test server")
}

/// Reads from `replay_start` through `replay_done`, returning whether
/// `replay_truncated` was seen and the content bytes in between.
async fn drain_replay(ws: &mut axum_test::TestWebSocket) -> (bool, Vec<u8>) {
    let first = ws.receive_bytes().await;
    assert_eq!(first.as_ref(), ctl_marker("replay_start").as_slice());
    let mut truncated = false;
    let mut content = Vec::new();
    loop {
        let msg = ws.receive_bytes().await;
        if msg.as_ref() == ctl_marker("replay_truncated").as_slice() {
            truncated = true;
            continue;
        }
        if msg.as_ref() == ctl_marker("replay_done").as_slice() {
            break;
        }
        content.extend_from_slice(&msg);
    }
    (truncated, content)
}

async fn read_until(ws: &mut axum_test::TestWebSocket, needle: &[u8]) -> Vec<u8> {
    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let msg = tokio::time::timeout(Duration::from_secs(2), ws.receive_bytes()).await;
        let Ok(msg) = msg else { continue };
        seen.extend_from_slice(&msg);
        if seen.windows(needle.len()).any(|w| w == needle) {
            return seen;
        }
    }
    panic!(
        "never saw {:?} in {:?}",
        String::from_utf8_lossy(needle),
        String::from_utf8_lossy(&seen)
    );
}

fn parent_of(pid: u32) -> u32 {
    let out = Command::new("ps")
        .args(["-o", "ppid=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

#[tokio::test]
async fn mac_host_shell_is_a_child_of_the_supervisor_and_speaks_the_instance_framing() {
    let (daemon, client) = start_daemon("owner").await;
    let server = server(&daemon, &client);

    let response = server
        .get_websocket("/pty?session=s1&cols=100&rows=30")
        .await;
    assert_eq!(
        response.status_code(),
        101,
        "not upgraded: {}",
        response.text()
    );
    let mut ws = response.into_websocket().await;
    let (truncated, content) = drain_replay(&mut ws).await;
    assert!(!truncated, "a fresh session has nothing to truncate");
    let banner = read_until(&mut ws, b"READY mac-host s1").await;
    assert!(content.is_empty() || banner.len() >= content.len());

    // The process that owns the shell is the daemon, not the engine.
    let info = match client
        .request(Control::Get {
            conversation_id: "s1".into(),
        })
        .await
        .unwrap()
    {
        Control::Session { info } => info,
        other => panic!("unexpected reply: {other:?}"),
    };
    assert_eq!(
        parent_of(info.pid),
        daemon.child.id(),
        "shell must hang off the supervisor"
    );
    assert_ne!(
        parent_of(info.pid),
        std::process::id(),
        "and never off this process"
    );
    assert_eq!((info.cols, info.rows), (100, 30));

    // Typed input in the instance route's JSON reaches the shell and echoes.
    ws.send_message(axum_test::WsMessage::Text(
        r#"{"type":"input","data":"echo ROUTE_$((20+22))\n"}"#.into(),
    ))
    .await;
    read_until(&mut ws, b"ROUTE_42").await;

    // Resize in the same framing lands on the supervised PTY.
    ws.send_message(axum_test::WsMessage::Text(
        r#"{"type":"resize","cols":132,"rows":40}"#.into(),
    ))
    .await;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let reply = client
            .request(Control::Get {
                conversation_id: "s1".into(),
            })
            .await
            .unwrap();
        if let Control::Session { info } = &reply {
            if (info.cols, info.rows) == (132, 40) {
                break;
            }
        }
        assert!(Instant::now() < deadline, "resize never applied: {reply:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    ws.close().await;

    // A second client reattaches to the same live shell and replays its past.
    let mut again = server
        .get_websocket("/pty?session=s1&cols=132&rows=40")
        .await
        .into_websocket()
        .await;
    let (_, replay) = drain_replay(&mut again).await;
    let replay = String::from_utf8_lossy(&replay);
    assert!(replay.contains("READY mac-host s1"), "replay: {replay}");
    assert!(replay.contains("ROUTE_42"), "replay: {replay}");
    let same = match client
        .request(Control::Get {
            conversation_id: "s1".into(),
        })
        .await
        .unwrap()
    {
        Control::Session { info } => info,
        other => panic!("unexpected reply: {other:?}"),
    };
    assert_eq!(same.pid, info.pid, "reattach must not spawn a second shell");

    // The shell exiting ends the stream the way the instance route always did.
    again
        .send_message(axum_test::WsMessage::Text(
            r#"{"type":"input","data":"exit\n"}"#.into(),
        ))
        .await;
    read_until(&mut again, ctl_marker("session_ended").as_slice()).await;
    drop(daemon);
}

#[tokio::test]
async fn a_client_arriving_after_the_shell_died_gets_a_fresh_shell() {
    let (daemon, client) = start_daemon("fresh").await;
    let server = server(&daemon, &client);
    let mut ws = server
        .get_websocket("/pty?session=s2&cols=80&rows=24")
        .await
        .into_websocket()
        .await;
    drain_replay(&mut ws).await;
    read_until(&mut ws, b"READY mac-host s2").await;
    let first = match client
        .request(Control::Get {
            conversation_id: "s2".into(),
        })
        .await
        .unwrap()
    {
        Control::Session { info } => info.pid,
        other => panic!("unexpected reply: {other:?}"),
    };
    ws.send_message(axum_test::WsMessage::Text(
        r#"{"type":"input","data":"exit\n"}"#.into(),
    ))
    .await;
    read_until(&mut ws, ctl_marker("session_ended").as_slice()).await;
    ws.close().await;

    let mut next = server
        .get_websocket("/pty?session=s2&cols=80&rows=24")
        .await
        .into_websocket()
        .await;
    drain_replay(&mut next).await;
    read_until(&mut next, b"READY mac-host s2").await;
    let second = match client
        .request(Control::Get {
            conversation_id: "s2".into(),
        })
        .await
        .unwrap()
    {
        Control::Session { info } => info.pid,
        other => panic!("unexpected reply: {other:?}"),
    };
    assert_ne!(first, second, "a dead shell is replaced, not resurrected");
    drop(daemon);
}
