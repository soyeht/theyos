use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use tokio::time::{Instant, sleep, timeout};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest, http::HeaderValue};

use crate::error::E2eError;

const CONNECT_RETRY_DELAY: Duration = Duration::from_secs(2);
const SESSION_TIMEOUT: Duration = Duration::from_secs(20);

/// # Errors
/// Returns `E2eError::Terminal` if the PTY round-trip fails after all retries.
pub fn terminal_roundtrip_blocking(
    base_url: &str,
    session_cookie: &str,
    container: &str,
    session_id: &str,
    purpose: &str,
    overall_timeout: Duration,
) -> Result<(), E2eError> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(terminal_roundtrip(
            base_url,
            session_cookie,
            container,
            session_id,
            purpose,
            overall_timeout,
        ))
    })
}

async fn terminal_roundtrip(
    base_url: &str,
    session_cookie: &str,
    container: &str,
    session_id: &str,
    purpose: &str,
    overall_timeout: Duration,
) -> Result<(), E2eError> {
    let deadline = Instant::now() + overall_timeout;
    let mut last_error = String::from("terminal round-trip did not start");
    let mut attempt = 0_u32;

    while Instant::now() < deadline {
        attempt += 1;
        let marker = marker(container, purpose, attempt);
        let remaining = deadline.saturating_duration_since(Instant::now());
        let per_attempt = remaining.min(SESSION_TIMEOUT);

        match timeout(
            per_attempt,
            single_roundtrip(base_url, session_cookie, container, session_id, &marker),
        )
        .await
        {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(E2eError::Terminal { reason, .. })) => last_error = reason,
            Ok(Err(other)) => return Err(other),
            Err(_) => last_error = format!("attempt {attempt} timed out after {per_attempt:?}"),
        }

        if Instant::now() >= deadline {
            break;
        }
        sleep(CONNECT_RETRY_DELAY).await;
    }

    Err(E2eError::Terminal {
        container: container.to_string(),
        reason: format!("{purpose} terminal round-trip failed: {last_error}"),
    })
}

async fn single_roundtrip(
    base_url: &str,
    session_cookie: &str,
    container: &str,
    session: &str,
    marker: &str,
) -> Result<(), E2eError> {
    let ws_url = ws_url(base_url, container, session)?;
    let mut request = ws_url
        .into_client_request()
        .map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("build websocket request: {e}"),
        })?;
    request.headers_mut().insert(
        "Cookie",
        HeaderValue::from_str(session_cookie).map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("invalid websocket cookie header: {e}"),
        })?,
    );

    let (mut stream, _) = connect_async(request)
        .await
        .map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("connect websocket: {e}"),
        })?;

    stream
        .send(Message::Text(
            serde_json::json!({
                "type": "resize",
                "cols": 120,
                "rows": 32,
            })
            .to_string()
            .into(),
        ))
        .await
        .map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("send resize: {e}"),
        })?;

    stream
        .send(Message::Text(
            serde_json::json!({
                "type": "input",
                "data": format!("printf '{marker}\\n'\r"),
            })
            .to_string()
            .into(),
        ))
        .await
        .map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("send terminal input: {e}"),
        })?;

    let mut transcript = String::new();

    loop {
        let Some(message) = stream.next().await else {
            break;
        };

        match message.map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("read websocket frame: {e}"),
        })? {
            Message::Text(text) => {
                transcript.push_str(text.as_ref());
                trim_transcript(&mut transcript);
                if transcript.contains(marker) {
                    let _ = stream.close(None).await;
                    return Ok(());
                }
            }
            Message::Binary(bytes) => {
                transcript.push_str(&String::from_utf8_lossy(&bytes));
                trim_transcript(&mut transcript);
                if transcript.contains(marker) {
                    let _ = stream.close(None).await;
                    return Ok(());
                }
            }
            Message::Close(frame) => {
                let detail = frame.as_ref().map_or_else(
                    || "server closed websocket".to_string(),
                    |f| format!("{} {}", u16::from(f.code), f.reason),
                );
                return Err(E2eError::Terminal {
                    container: container.to_string(),
                    reason: format!("websocket closed before marker: {detail}"),
                });
            }
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }

    Err(E2eError::Terminal {
        container: container.to_string(),
        reason: format!(
            "marker '{marker}' not observed in PTY output; tail={}",
            tail(&transcript, 240)
        ),
    })
}

fn ws_url(base_url: &str, container: &str, session: &str) -> Result<String, E2eError> {
    let base_url = base_url.trim_end_matches('/');
    let ws_base = if let Some(rest) = base_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        return Err(E2eError::Terminal {
            container: container.to_string(),
            reason: format!("unsupported base URL for websocket: {base_url}"),
        });
    };

    Ok(format!(
        "{ws_base}/api/v1/terminals/{container}/pty?session={session}"
    ))
}

fn marker(container: &str, purpose: &str, attempt: u32) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("__THEYOS_TTY_OK_{container}_{purpose}_{attempt}_{now}__")
}

// ── Terminal persistence test ─────────────────────────────────────────────────
//
// Validates that tmux-backed sessions survive WebSocket disconnection:
// 1. Connect with a session ID, set an env var in the shell
// 2. Disconnect the WebSocket
// 3. Reconnect with the SAME session ID
// 4. Verify the env var is still set (proving tmux kept the session alive)

/// # Errors
/// Returns `E2eError::Terminal` if the persistence round-trip fails.
pub fn terminal_persistence_blocking(
    base_url: &str,
    session_cookie: &str,
    container: &str,
    session_id: &str,
    overall_timeout: Duration,
) -> Result<(), E2eError> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(terminal_persistence(
            base_url,
            session_cookie,
            container,
            session_id,
            overall_timeout,
        ))
    })
}

async fn terminal_persistence(
    base_url: &str,
    session_cookie: &str,
    container: &str,
    session_id: &str,
    overall_timeout: Duration,
) -> Result<(), E2eError> {
    let deadline = Instant::now() + overall_timeout;

    // Use the workspace-backed session ID for both connections — same
    // session_id → same tmux session inside the VM.
    let session = session_id.to_string();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let persist_value = format!("__PERSIST_{container}_{now}__");

    // Phase 1: Connect, set env var, wait for ack, then disconnect.
    let ack_marker = format!("__PERSIST_ACK_{container}_{now}__");
    let set_cmd = format!("export PERSIST_VAR={persist_value}; printf '{ack_marker}\\n'\r");
    let remaining = deadline.saturating_duration_since(Instant::now());
    timeout(
        remaining.min(SESSION_TIMEOUT),
        persist_phase1(
            base_url,
            session_cookie,
            container,
            &session,
            &set_cmd,
            &ack_marker,
        ),
    )
    .await
    .map_err(|_| E2eError::Terminal {
        container: container.to_string(),
        reason: "phase 1 (set env var) timed out".to_string(),
    })??;

    // Brief pause to let the server clean up the PTY host-side.
    sleep(Duration::from_secs(2)).await;

    // Phase 2: Reconnect with the SAME session ID and verify env var.
    let verify_marker = format!("__VERIFY_{container}_{now}__");
    let verify_cmd = format!("printf \"%s\\n\" \"$PERSIST_VAR\" && printf '{verify_marker}\\n'\r");
    let remaining = deadline.saturating_duration_since(Instant::now());
    timeout(
        remaining.min(SESSION_TIMEOUT),
        persist_phase2(
            base_url,
            session_cookie,
            container,
            &session,
            &verify_cmd,
            &verify_marker,
            &persist_value,
        ),
    )
    .await
    .map_err(|_| E2eError::Terminal {
        container: container.to_string(),
        reason: "phase 2 (verify env var) timed out".to_string(),
    })?
}

/// Phase 1: connect, send the env-var export command, wait for ack, then close.
async fn persist_phase1(
    base_url: &str,
    session_cookie: &str,
    container: &str,
    session: &str,
    set_cmd: &str,
    ack_marker: &str,
) -> Result<(), E2eError> {
    let ws_url = ws_url(base_url, container, session)?;
    let mut request = ws_url
        .into_client_request()
        .map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("build ws request: {e}"),
        })?;
    request.headers_mut().insert(
        "Cookie",
        HeaderValue::from_str(session_cookie).map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("cookie header: {e}"),
        })?,
    );

    let (mut stream, _) = connect_async(request)
        .await
        .map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("connect phase1: {e}"),
        })?;

    stream
        .send(Message::Text(
            serde_json::json!({"type": "resize", "cols": 120, "rows": 32})
                .to_string()
                .into(),
        ))
        .await
        .map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("send resize: {e}"),
        })?;

    sleep(Duration::from_millis(500)).await;

    stream
        .send(Message::Text(
            serde_json::json!({"type": "input", "data": set_cmd})
                .to_string()
                .into(),
        ))
        .await
        .map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("send export: {e}"),
        })?;

    // Wait for the ack marker to appear in the output, proving the shell
    // processed the export before we close the connection.
    let mut transcript = String::new();
    loop {
        let Some(message) = stream.next().await else {
            break;
        };
        match message.map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("read frame phase1: {e}"),
        })? {
            Message::Text(text) => {
                transcript.push_str(text.as_ref());
                trim_transcript(&mut transcript);
                if transcript.contains(ack_marker) {
                    let _ = stream.close(None).await;
                    return Ok(());
                }
            }
            Message::Binary(bytes) => {
                transcript.push_str(&String::from_utf8_lossy(&bytes));
                trim_transcript(&mut transcript);
                if transcript.contains(ack_marker) {
                    let _ = stream.close(None).await;
                    return Ok(());
                }
            }
            Message::Close(_) => {
                return Err(E2eError::Terminal {
                    container: container.to_string(),
                    reason: "ws closed in phase1 before ack marker".to_string(),
                });
            }
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }

    Err(E2eError::Terminal {
        container: container.to_string(),
        reason: format!(
            "phase1 ack marker not found; tail={}",
            tail(&transcript, 240)
        ),
    })
}

/// Phase 2: reconnect with the same session, send a verify command,
/// and check that the env var value appears in the output.
async fn persist_phase2(
    base_url: &str,
    session_cookie: &str,
    container: &str,
    session: &str,
    verify_cmd: &str,
    verify_marker: &str,
    persist_value: &str,
) -> Result<(), E2eError> {
    let ws_url = ws_url(base_url, container, session)?;
    let mut request = ws_url
        .into_client_request()
        .map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("build ws request phase2: {e}"),
        })?;
    request.headers_mut().insert(
        "Cookie",
        HeaderValue::from_str(session_cookie).map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("cookie header: {e}"),
        })?,
    );

    let (mut stream, _) = connect_async(request)
        .await
        .map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("connect phase2: {e}"),
        })?;

    stream
        .send(Message::Text(
            serde_json::json!({"type": "resize", "cols": 120, "rows": 32})
                .to_string()
                .into(),
        ))
        .await
        .map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("send resize phase2: {e}"),
        })?;

    sleep(Duration::from_millis(500)).await;

    stream
        .send(Message::Text(
            serde_json::json!({"type": "input", "data": verify_cmd})
                .to_string()
                .into(),
        ))
        .await
        .map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("send verify cmd: {e}"),
        })?;

    let mut transcript = String::new();

    loop {
        let Some(message) = stream.next().await else {
            break;
        };
        match message.map_err(|e| E2eError::Terminal {
            container: container.to_string(),
            reason: format!("read frame phase2: {e}"),
        })? {
            Message::Text(text) => {
                transcript.push_str(text.as_ref());
                trim_transcript(&mut transcript);
                if transcript.contains(verify_marker) {
                    if transcript.contains(persist_value) {
                        let _ = stream.close(None).await;
                        return Ok(());
                    }
                    let _ = stream.close(None).await;
                    return Err(E2eError::Terminal {
                        container: container.to_string(),
                        reason: format!(
                            "verify marker found but env var '{persist_value}' missing; \
                             tmux session did not persist; tail={}",
                            tail(&transcript, 400)
                        ),
                    });
                }
            }
            Message::Binary(bytes) => {
                transcript.push_str(&String::from_utf8_lossy(&bytes));
                trim_transcript(&mut transcript);
            }
            Message::Close(_) => {
                return Err(E2eError::Terminal {
                    container: container.to_string(),
                    reason: "ws closed in phase2 before verify marker".to_string(),
                });
            }
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }

    Err(E2eError::Terminal {
        container: container.to_string(),
        reason: format!(
            "persistence verify marker not found; tail={}",
            tail(&transcript, 400)
        ),
    })
}

fn trim_transcript(transcript: &mut String) {
    const MAX_TRANSCRIPT_CHARS: usize = 64 * 1024;
    let char_count = transcript.chars().count();
    if char_count > MAX_TRANSCRIPT_CHARS {
        let drop_chars = char_count - MAX_TRANSCRIPT_CHARS;
        let drop_idx = transcript
            .char_indices()
            .nth(drop_chars)
            .map_or_else(|| transcript.len(), |(idx, _)| idx);
        transcript.drain(..drop_idx);
    }
}

fn tail(text: &str, max_len: usize) -> String {
    let tail_chars: Vec<char> = text.chars().rev().take(max_len).collect();
    if tail_chars.len() < max_len {
        return text.to_string();
    }
    tail_chars.into_iter().rev().collect()
}
