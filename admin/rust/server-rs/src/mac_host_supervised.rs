//! Mac Host instance sessions owned by the PTY supervisor.
//!
//! WHY THIS EXISTS. `GET /api/v1/terminals/{container}/pty` is the instance
//! route: the iPhone's "New session", the Mac's New Conversation sheet, the
//! empty-pane picker's agent rows and the Claw Store all reach it. For every
//! remote container the shell lives inside that machine's tmux, so an engine
//! restart costs nothing. For the seeded `mac-host` container the engine used
//! to spawn the login shell inside its own process — the one place the PTY
//! supervisor was built to take out of the engine's lifetime. Measured
//! 2026-09-09: `launchctl kickstart -k` on the engine killed such a shell on
//! the spot while the supervisor sat next to it with zero sessions.
//!
//! WHAT IT DOES. When the container is `mac-host` and a supervisor is
//! configured, the session is created in (or reattached from) the supervisor
//! and bridged to the client in the instance route's existing framing: raw
//! output bytes, `CTL:` markers, JSON `input`/`resize` messages. Clients do
//! not change; only the shell's parent does.
//!
//! The spawned program is exactly what the in-process path spawned —
//! `theyos-ssh pty mac-host <session>` with the engine's environment — so the
//! shell a person lands in is the same one, just owned by a process that
//! survives the engine.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use terminal_rs::supervisor_client::{AttachedStream, ClientError, SupervisorClient};
use terminal_rs::supervisor_wire::{self as wire, Control, Frame, SessionInfo, SpawnRequest};
use tokio::sync::Mutex;

use crate::supervised_terminals::reject;

/// The seeded instance that is this Mac itself. `theyos-ssh` matches the
/// same literal to skip SSH and run the login shell locally.
pub const MAC_HOST_CONTAINER: &str = "mac-host";

/// Who holds the shell process of a session on `container`. Surfaced on
/// every creation and listing response so a caller can tell a session that
/// outlives the engine from one that does not, instead of finding out at
/// the next update.
#[must_use]
pub fn session_owner(container: &str, supervisor_configured: bool) -> &'static str {
    if container != MAC_HOST_CONTAINER {
        return "remote";
    }
    if supervisor_configured {
        "supervisor"
    } else {
        "engine_process"
    }
}

/// Default replay window on attach, mirroring the in-process route.
const TAIL_REPLAY_BYTES: u64 = 2 * 1024 * 1024;
const CTL_PREFIX: &[u8] = b"\x00\x01CTL:";
const SEND_TIMEOUT: Duration = Duration::from_secs(5);
const PING_EVERY: Duration = Duration::from_secs(30);
const PONG_DEADLINE: Duration = Duration::from_secs(90);

type Output = Arc<Mutex<futures_util::stream::SplitSink<WebSocket, Message>>>;

/// The spawn the in-process route performed, expressed for the supervisor.
/// Visible so a test can assert the argv without a WebSocket.
#[must_use]
pub fn spawn_request(
    ctl_path: &str,
    session_id: &str,
    intent_id: String,
    cols: u16,
    rows: u16,
) -> SpawnRequest {
    let mut env: Vec<(String, String)> = std::env::vars().collect();
    env.retain(|(key, _)| key != "TERM");
    env.push(("TERM".to_owned(), "xterm-256color".to_owned()));
    let cwd = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("/"))
        .to_string_lossy()
        .into_owned();
    SpawnRequest {
        intent_id,
        conversation_id: session_id.to_owned(),
        argv: vec![
            ctl_path.to_owned(),
            "pty".to_owned(),
            MAC_HOST_CONTAINER.to_owned(),
            session_id.to_owned(),
        ],
        cwd,
        env,
        cols: if cols == 0 { 80 } else { cols },
        rows: if rows == 0 { 24 } else { rows },
    }
}

fn unavailable(error: &ClientError) -> Response {
    match error {
        ClientError::Protocol => reject(StatusCode::BAD_GATEWAY, "supervisor_protocol_mismatch"),
        // The supervisor's own code travels to the client: "spawn_failed"
        // and "session_limit" call for different actions.
        ClientError::Rejected(code) => reject(StatusCode::CONFLICT, code),
        _ => reject(StatusCode::SERVICE_UNAVAILABLE, "supervisor_unavailable"),
    }
}

/// Returns the live supervised session for `session_id`, creating it when
/// none is live. Idempotent like the in-process route: a second WebSocket on
/// the same session shares the shell.
pub async fn ensure_session(
    client: &SupervisorClient,
    ctl_path: &str,
    session_id: &str,
    cols: u16,
    rows: u16,
) -> Result<SessionInfo, Response> {
    match client
        .request(Control::Get {
            conversation_id: session_id.to_owned(),
        })
        .await
    {
        Ok(Control::Session { info }) if !info.closed => return Ok(info),
        // A closed or unknown session is the normal "spawn one" case; the
        // client surfaces both as rejections, not as a `Session` reply.
        Ok(Control::Session { .. }) => {}
        Err(ClientError::Rejected(code))
            if code == "session_not_found" || code == "session_closed" => {}
        Ok(_) => return Err(unavailable(&ClientError::Protocol)),
        Err(error) => return Err(unavailable(&error)),
    }
    let intent_id = match client
        .request(Control::IssueIntent {
            conversation_id: session_id.to_owned(),
        })
        .await
    {
        Ok(Control::IntentIssued { intent_id, .. }) => intent_id,
        Ok(_) => return Err(unavailable(&ClientError::Protocol)),
        Err(error) => return Err(unavailable(&error)),
    };
    let request = spawn_request(ctl_path, session_id, intent_id, cols, rows);
    match client.request(Control::Create { request }).await {
        Ok(Control::Created { info, .. }) => Ok(info),
        Ok(_) => Err(unavailable(&ClientError::Protocol)),
        Err(error) => Err(unavailable(&error)),
    }
}

/// Serves one instance-route WebSocket for a Mac Host session from the
/// supervisor. `full_replay` mirrors the in-process query flag.
pub async fn serve(
    client: SupervisorClient,
    ctl_path: String,
    session_id: String,
    cols: u16,
    rows: u16,
    full_replay: bool,
    ws: WebSocketUpgrade,
) -> Response {
    let info = match ensure_session(&client, &ctl_path, &session_id, cols, rows).await {
        Ok(info) => info,
        Err(response) => return response,
    };
    // First attach reads the retained bounds; a tail attach then starts near
    // the end, like the in-process route's 2 MiB window. Both are cheap UDS
    // connections and the supervisor keeps no state per attach.
    let probe = match client
        .attach(session_id.clone(), info.session_instance_id.clone(), 0)
        .await
    {
        Ok(attached) => attached,
        Err(error) => return unavailable(&error),
    };
    let base = probe.base_offset;
    let end = probe.replay_end;
    let start = if full_replay {
        base
    } else {
        base.max(end.saturating_sub(TAIL_REPLAY_BYTES))
    };
    let attached = if start == 0 {
        probe
    } else {
        drop(probe);
        match client
            .attach(session_id.clone(), info.session_instance_id.clone(), start)
            .await
        {
            Ok(attached) => attached,
            Err(error) => return unavailable(&error),
        }
    };
    let truncated = start > base;
    if (cols, rows) != (0, 0) && (info.cols, info.rows) != (cols, rows) {
        let _ = client
            .request(Control::Resize {
                conversation_id: session_id.clone(),
                session_instance_id: info.session_instance_id.clone(),
                cols: cols.max(1),
                rows: rows.max(1),
            })
            .await;
    }
    ws.on_upgrade(move |socket| bridge_legacy(socket, client, attached, truncated))
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ClientMessageType {
    Input,
    Resize,
    Init,
}

#[derive(Deserialize)]
struct ClientMessage {
    #[serde(rename = "type")]
    msg_type: ClientMessageType,
    #[serde(default)]
    data: String,
    #[serde(default)]
    cols: u16,
    #[serde(default)]
    rows: u16,
}

async fn send(output: &Output, message: Message) -> Result<(), ()> {
    tokio::time::timeout(SEND_TIMEOUT, async {
        output.lock().await.send(message).await.map_err(|_| ())
    })
    .await
    .map_err(|_| ())?
}

async fn marker(output: &Output, name: &[u8]) -> Result<(), ()> {
    let mut bytes = Vec::with_capacity(CTL_PREFIX.len() + name.len());
    bytes.extend_from_slice(CTL_PREFIX);
    bytes.extend_from_slice(name);
    send(output, Message::Binary(bytes.into())).await
}

/// Translates supervisor frames into the instance route's wire and back.
///
/// Output frames become raw binary. `Gap` becomes `replay_truncated`,
/// `ReplayEnd` becomes `replay_done`, `Exit` becomes `session_ended`, and a
/// resync demand becomes `subscriber_lagged`, the marker the in-process route
/// already uses to tell a client to reconnect. Input is the JSON the clients
/// send today. Frame reading and socket reading are two whole futures, never
/// a per-iteration select, so a keystroke cannot cancel a half-read frame.
async fn bridge_legacy(
    socket: WebSocket,
    client: SupervisorClient,
    mut attached: AttachedStream,
    truncated: bool,
) {
    let (output, mut input) = socket.split();
    let output: Output = Arc::new(Mutex::new(output));
    let conversation_id = attached.info.conversation_id.clone();
    let session_instance_id = attached.info.session_instance_id.clone();
    let last_pong = Arc::new(AtomicU64::new(0));
    let started = tokio::time::Instant::now();

    if marker(&output, b"replay_start").await.is_err() {
        return;
    }
    if truncated && marker(&output, b"replay_truncated").await.is_err() {
        return;
    }

    let outgoing = {
        let output = Arc::clone(&output);
        async move {
            let mut gap_reported = truncated;
            loop {
                let frame = wire::read_frame(&mut attached.stream)
                    .await
                    .map_err(|_| ())?;
                match frame {
                    Frame::Data { id: 2, bytes, .. } => {
                        if !bytes.is_empty() {
                            send(&output, Message::Binary(bytes.into())).await?;
                        }
                    }
                    Frame::Control { id: 2, message } => match message {
                        Control::Gap { .. } => {
                            if !gap_reported {
                                gap_reported = true;
                                marker(&output, b"replay_truncated").await?;
                            }
                        }
                        Control::ReplayEnd { .. } => marker(&output, b"replay_done").await?,
                        Control::Exit { .. } => {
                            let _ = marker(&output, b"session_ended").await;
                            return Ok::<(), ()>(());
                        }
                        Control::ResyncRequired { .. } => {
                            let _ = marker(&output, b"subscriber_lagged").await;
                            return Ok(());
                        }
                        Control::Error { .. } => {
                            let _ = marker(&output, b"session_ended").await;
                            return Ok(());
                        }
                        _ => {}
                    },
                    _ => return Err(()),
                }
            }
        }
    };

    let incoming = {
        let output = Arc::clone(&output);
        let last_pong = Arc::clone(&last_pong);
        async move {
            while let Some(message) = input.next().await {
                let command = match message.map_err(|_| ())? {
                    Message::Text(text) => {
                        let Ok(parsed) = serde_json::from_str::<ClientMessage>(&text) else {
                            tracing::debug!("[mac-host-ws] unknown client message");
                            continue;
                        };
                        match parsed.msg_type {
                            ClientMessageType::Input if parsed.data.is_empty() => continue,
                            ClientMessageType::Input => Control::Write {
                                conversation_id: conversation_id.clone(),
                                session_instance_id: session_instance_id.clone(),
                                bytes: parsed.data.into_bytes(),
                            },
                            ClientMessageType::Resize | ClientMessageType::Init => {
                                Control::Resize {
                                    conversation_id: conversation_id.clone(),
                                    session_instance_id: session_instance_id.clone(),
                                    cols: parsed.cols.max(1),
                                    rows: parsed.rows.max(1),
                                }
                            }
                        }
                    }
                    Message::Ping(bytes) => {
                        send(&output, Message::Pong(bytes)).await?;
                        continue;
                    }
                    Message::Pong(_) => {
                        last_pong.store(started.elapsed().as_secs(), Ordering::Relaxed);
                        continue;
                    }
                    Message::Close(_) => return Ok::<(), ()>(()),
                    Message::Binary(_) => continue,
                };
                if !matches!(client.request(command).await, Ok(Control::Ok)) {
                    let _ = marker(&output, b"session_ended").await;
                    return Err(());
                }
            }
            Ok(())
        }
    };

    let keepalive = {
        let output = Arc::clone(&output);
        let last_pong = Arc::clone(&last_pong);
        async move {
            let mut ticker = tokio::time::interval(PING_EVERY);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let silent = started.elapsed().as_secs() - last_pong.load(Ordering::Relaxed);
                if silent > PONG_DEADLINE.as_secs() + PING_EVERY.as_secs() {
                    tracing::warn!("[mac-host-ws] pong timeout, closing stale connection");
                    return;
                }
                if send(&output, Message::Ping(Vec::new().into()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    };

    tokio::select! {
        _ = outgoing => {}
        _ = incoming => {}
        () = keepalive => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_names_the_process_that_holds_the_shell() {
        assert_eq!(session_owner("mac-host", true), "supervisor");
        assert_eq!(session_owner("mac-host", false), "engine_process");
        assert_eq!(session_owner("claw-7", true), "remote");
    }

    #[test]
    fn spawn_request_is_the_in_process_spawn_expressed_for_the_supervisor() {
        let request = spawn_request("/x/theyos-ssh", "s1", "i1".into(), 0, 0);
        assert_eq!(request.argv, ["/x/theyos-ssh", "pty", "mac-host", "s1"]);
        assert_eq!((request.cols, request.rows), (80, 24));
        assert!(request
            .env
            .iter()
            .any(|(k, v)| k == "TERM" && v == "xterm-256color"));
        assert_eq!(request.env.iter().filter(|(k, _)| k == "TERM").count(), 1);
        assert!(request.cwd.starts_with('/'));
    }
}
