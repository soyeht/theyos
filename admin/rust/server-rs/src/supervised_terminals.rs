//! HTTP/WebSocket adapter for supervisor-owned local sessions. This module
//! never spawns, closes on disconnect, retries input, or selects a fallback.

use axum::Json;
use axum::extract::ws::{Message, WebSocket};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use terminal_rs::supervisor_client::{AttachedStream, ClientError, SupervisorClient};
use terminal_rs::supervisor_wire::{self as wire, Control, Frame, SessionInfo, SpawnRequest};
use tokio::sync::Mutex;

pub const OUTPUT_PREFIX: &[u8] = b"\0\x02PTY:";
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

#[must_use]
pub fn reject(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({"error": code, "code": code}))).into_response()
}

fn unavailable(error: ClientError) -> Response {
    if matches!(error, ClientError::Protocol) {
        return reject(StatusCode::BAD_GATEWAY, "supervisor_protocol_mismatch");
    }
    let ClientError::Rejected(code) = error else {
        return reject(StatusCode::SERVICE_UNAVAILABLE, "supervisor_unavailable");
    };
    let status = match code.as_str() {
        "session_not_found" => StatusCode::NOT_FOUND,
        "instance_mismatch" => StatusCode::PRECONDITION_FAILED,
        "session_closed" | "intent_consumed" | "intent_expired" => StatusCode::GONE,
        "intent_mismatch" | "session_exists" => StatusCode::CONFLICT,
        "session_limit" | "intent_limit" => StatusCode::TOO_MANY_REQUESTS,
        "invalid_spawn" | "invalid_size" | "input_too_large" => StatusCode::BAD_REQUEST,
        "storage_unavailable" | "registry_unavailable" => StatusCode::SERVICE_UNAVAILABLE,
        "spawn_failed" | "write_failed" | "resize_failed" => StatusCode::INTERNAL_SERVER_ERROR,
        _ => return reject(StatusCode::BAD_GATEWAY, "supervisor_protocol_mismatch"),
    };
    reject(status, &code)
}

/// Only one exact strong `ETag` is accepted. Wildcards and lists cannot prove
/// the identity of the particular session the caller intended to destroy.
pub fn expected_instance(headers: &HeaderMap) -> Result<String, &'static str> {
    let values: Vec<_> = headers
        .get_all(axum::http::header::IF_MATCH)
        .iter()
        .collect();
    let value = values.first().and_then(|value| value.to_str().ok());
    let instance = value.and_then(|value| value.strip_prefix('"')?.strip_suffix('"'));
    match instance {
        Some(id) if values.len() == 1 && wire::valid_instance_id(id) => Ok(id.to_owned()),
        _ => Err("session_instance_required"),
    }
}

fn metadata(info: &SessionInfo) -> Value {
    json!({
        "conversation_id": info.conversation_id,
        "session_instance_id": info.session_instance_id,
        "intent_id": info.intent_id,
        "backend": "supervisor",
        "stream_protocol": 1,
        "slave_tty_path": info.slave_tty_path,
        "pid": info.pid,
        "pgid": info.pgid,
        "cwd": info.cwd,
        "is_connected": !info.closed,
        "ws_path": format!("/api/v1/terminals/local/{}/pty", info.conversation_id),
    })
}

fn session_response(info: &SessionInfo, body: Value) -> Response {
    let mut response = Json(body).into_response();
    if let Ok(etag) = format!("\"{}\"", info.session_instance_id).parse() {
        response
            .headers_mut()
            .insert(axum::http::header::ETAG, etag);
    }
    response
}

pub async fn create(
    client: &SupervisorClient,
    req: crate::handlers_terminal::LocalTerminalCreateRequest,
) -> Response {
    let Some(intent_id) = req.intent_id else {
        return reject(StatusCode::PRECONDITION_FAILED, "create_intent_required");
    };
    let Some(cwd) = req.cwd else {
        return reject(StatusCode::BAD_REQUEST, "absolute_cwd_required");
    };
    let request = SpawnRequest {
        intent_id,
        conversation_id: req.conversation_id,
        argv: req.argv,
        cwd,
        env: req.env,
        cols: if req.cols == 0 { 80 } else { req.cols },
        rows: if req.rows == 0 { 24 } else { req.rows },
    };
    match client.request(Control::Create { request }).await {
        Ok(Control::Created { info, reconnected }) => {
            let mut body = metadata(&info);
            body["reconnected"] = json!(reconnected);
            session_response(&info, body)
        }
        Ok(_) => unavailable(ClientError::Protocol),
        Err(error) => unavailable(error),
    }
}

pub async fn issue_intent(client: &SupervisorClient, conversation_id: String) -> Response {
    match client
        .request(Control::IssueIntent { conversation_id })
        .await
    {
        Ok(Control::IntentIssued {
            intent_id,
            conversation_id,
        }) => Json(json!({
            "backend": "supervisor", "intent_id": intent_id, "conversation_id": conversation_id,
        }))
        .into_response(),
        Ok(_) => unavailable(ClientError::Protocol),
        Err(error) => unavailable(error),
    }
}

pub async fn get(client: &SupervisorClient, conversation_id: String) -> Response {
    match client.request(Control::Get { conversation_id }).await {
        Ok(Control::Session { info }) => session_response(&info, metadata(&info)),
        Ok(_) => unavailable(ClientError::Protocol),
        Err(error) => unavailable(error),
    }
}

pub async fn list(client: &SupervisorClient) -> Response {
    match client.request(Control::List).await {
        Ok(Control::Sessions { sessions }) => Json(json!({
            "data": sessions.iter().map(metadata).collect::<Vec<_>>(),
            "has_more": false, "next_cursor": null,
        }))
        .into_response(),
        Ok(_) => unavailable(ClientError::Protocol),
        Err(error) => unavailable(error),
    }
}

pub async fn close(
    client: &SupervisorClient,
    conversation_id: String,
    headers: HeaderMap,
) -> Response {
    let session_instance_id = match expected_instance(&headers) {
        Ok(id) => id,
        Err(code) => return reject(StatusCode::PRECONDITION_FAILED, code),
    };
    match client
        .request(Control::Close {
            conversation_id,
            session_instance_id,
        })
        .await
    {
        Ok(Control::Ok) => StatusCode::NO_CONTENT.into_response(),
        Ok(_) => unavailable(ClientError::Protocol),
        Err(error) => unavailable(error),
    }
}

pub async fn attach(
    client: &SupervisorClient,
    conversation_id: String,
    instance: Option<String>,
    protocol: Option<u16>,
    offset: Option<u64>,
) -> Result<AttachedStream, Response> {
    let Some(instance) = instance.filter(|id| wire::valid_instance_id(id)) else {
        return Err(reject(
            StatusCode::PRECONDITION_FAILED,
            "session_instance_required",
        ));
    };
    if protocol != Some(1) {
        return Err(reject(
            StatusCode::PRECONDITION_FAILED,
            "stream_protocol_required",
        ));
    }
    let Some(offset) = offset else {
        return Err(reject(
            StatusCode::PRECONDITION_FAILED,
            "replay_cursor_required",
        ));
    };
    client
        .attach(conversation_id, instance, offset)
        .await
        .map_err(unavailable)
}

pub async fn cancel_create(
    client: &SupervisorClient,
    conversation_id: String,
    intent_id: String,
) -> Response {
    match client
        .request(Control::CancelCreate {
            conversation_id,
            intent_id,
        })
        .await
    {
        Ok(Control::Ok) => StatusCode::NO_CONTENT.into_response(),
        Ok(_) => unavailable(ClientError::Protocol),
        Err(error) => unavailable(error),
    }
}

type Output = Arc<Mutex<futures_util::stream::SplitSink<WebSocket, Message>>>;

async fn send(output: &Output, message: Message) -> Result<(), ()> {
    tokio::time::timeout(SEND_TIMEOUT, async {
        output.lock().await.send(message).await.map_err(|_| ())
    })
    .await
    .map_err(|_| ())?
}

async fn control(output: &Output, message: &Control) -> Result<(), ()> {
    let encoded = serde_json::to_string(message).map_err(|_| ())?;
    send(output, Message::Text(encoded.into())).await
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum InputControl {
    Input { data: String },
    Resize { cols: u16, rows: u16 },
}

/// Keep the byte-stream reader alive across WebSocket input. Cancelling
/// `read_frame` on each keystroke could discard a partially read frame header.
pub async fn bridge(socket: WebSocket, client: SupervisorClient, mut attached: AttachedStream) {
    let (output, mut input) = socket.split();
    let output = Arc::new(Mutex::new(output));
    let conversation_id = attached.info.conversation_id.clone();
    let session_instance_id = attached.info.session_instance_id.clone();
    if control(
        &output,
        &Control::Attached {
            info: attached.info.clone(),
            base_offset: attached.base_offset,
            replay_end: attached.replay_end,
        },
    )
    .await
    .is_err()
    {
        return;
    }
    let outgoing = async {
        loop {
            let frame = wire::read_frame(&mut attached.stream)
                .await
                .map_err(|_| ())?;
            match frame {
                Frame::Data {
                    id: 2,
                    start_offset,
                    bytes,
                } => {
                    let mut encoded = Vec::with_capacity(OUTPUT_PREFIX.len() + 8 + bytes.len());
                    encoded.extend_from_slice(OUTPUT_PREFIX);
                    encoded.extend_from_slice(&start_offset.to_be_bytes());
                    encoded.extend_from_slice(&bytes);
                    send(&output, Message::Binary(encoded.into())).await?;
                }
                Frame::Control { id: 2, message } => {
                    let terminal = matches!(
                        message,
                        Control::Exit { .. }
                            | Control::ResyncRequired { .. }
                            | Control::Error { .. }
                    );
                    control(&output, &message).await?;
                    if terminal {
                        return Ok::<(), ()>(());
                    }
                }
                _ => return Err(()),
            }
        }
    };
    let incoming = async {
        while let Some(message) = input.next().await {
            let command = match message.map_err(|_| ())? {
                Message::Binary(bytes) => Control::Write {
                    conversation_id: conversation_id.clone(),
                    session_instance_id: session_instance_id.clone(),
                    bytes: bytes.to_vec(),
                },
                Message::Text(text) => {
                    match serde_json::from_str::<InputControl>(&text).map_err(|_| ())? {
                        InputControl::Input { data } => Control::Write {
                            conversation_id: conversation_id.clone(),
                            session_instance_id: session_instance_id.clone(),
                            bytes: data.into_bytes(),
                        },
                        InputControl::Resize { cols, rows } => Control::Resize {
                            conversation_id: conversation_id.clone(),
                            session_instance_id: session_instance_id.clone(),
                            cols,
                            rows,
                        },
                    }
                }
                Message::Ping(bytes) => {
                    send(&output, Message::Pong(bytes)).await?;
                    continue;
                }
                Message::Pong(_) => continue,
                Message::Close(_) => return Ok(()),
            };
            // Exactly one submission, even if its ACK is lost. Never replay
            // uncertain keystrokes into the surviving shell.
            if !matches!(client.request(command).await, Ok(Control::Ok)) {
                control(
                    &output,
                    &Control::Error {
                        code: "input_delivery_uncertain".into(),
                    },
                )
                .await?;
                return Err(());
            }
        }
        Ok::<(), ()>(())
    };
    tokio::select! { _ = outgoing => {}, _ = incoming => {} }
    // Transport teardown is never session teardown, including engine shutdown.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destructive_precondition_requires_one_strong_instance() {
        let id = "00000000-0000-4000-8000-000000000001";
        for value in [
            "*".to_owned(),
            id.to_owned(),
            format!("W/\"{id}\""),
            format!("\"{id}\", \"{id}\""),
            "\"not-an-instance\"".into(),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(axum::http::header::IF_MATCH, value.parse().unwrap());
            assert!(expected_instance(&headers).is_err());
        }
        let mut headers = HeaderMap::new();
        assert!(expected_instance(&headers).is_err());
        headers.insert(
            axum::http::header::IF_MATCH,
            format!("\"{id}\"").parse().unwrap(),
        );
        assert_eq!(expected_instance(&headers), Ok(id.into()));
        headers.append(
            axum::http::header::IF_MATCH,
            format!("\"{id}\"").parse().unwrap(),
        );
        assert!(expected_instance(&headers).is_err());
    }

    #[test]
    fn unknown_broker_errors_are_protocol_failures_not_availability() {
        assert_eq!(
            unavailable(ClientError::Rejected("future_unknown_error".into())).status(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            unavailable(ClientError::Protocol).status(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            unavailable(ClientError::Rejected("storage_unavailable".into())).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
