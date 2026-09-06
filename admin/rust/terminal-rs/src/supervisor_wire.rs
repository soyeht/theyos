//! PTY supervisor v2. Each connection negotiates before issuing operations.
//! Frames: u32 BE body length, u8 kind, u64 BE request/stream ID, payload.
//! Control payloads are CBOR. Output payloads are u64 BE offset + raw bytes.

use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: u16 = 2;
pub const MAX_FRAME: usize = 1024 * 1024;

#[must_use]
pub fn valid_instance_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpawnRequest {
    pub intent_id: String,
    pub conversation_id: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: Vec<(String, String)>,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub conversation_id: String,
    pub session_instance_id: String,
    pub intent_id: String,
    pub slave_tty_path: String,
    pub pgid: i32,
    pub pid: u32,
    pub cwd: String,
    pub cols: u16,
    pub rows: u16,
    pub closed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    Hello {
        supported_versions: Vec<u16>,
    },
    Welcome {
        selected_version: u16,
        broker_boot_id: String,
        max_frame: u32,
    },
    Create {
        request: SpawnRequest,
    },
    IssueIntent {
        conversation_id: String,
    },
    IntentIssued {
        intent_id: String,
        conversation_id: String,
    },
    Get {
        conversation_id: String,
    },
    List,
    Session {
        info: SessionInfo,
    },
    Created {
        info: SessionInfo,
        reconnected: bool,
    },
    Sessions {
        sessions: Vec<SessionInfo>,
    },
    Attach {
        conversation_id: String,
        session_instance_id: String,
        next_offset: u64,
    },
    Attached {
        info: SessionInfo,
        base_offset: u64,
        replay_end: u64,
    },
    Write {
        conversation_id: String,
        session_instance_id: String,
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    Resize {
        conversation_id: String,
        session_instance_id: String,
        cols: u16,
        rows: u16,
    },
    Close {
        conversation_id: String,
        session_instance_id: String,
    },
    CancelCreate {
        conversation_id: String,
        intent_id: String,
    },
    Ok,
    ReplayEnd {
        offset: u64,
    },
    Gap {
        from: u64,
        to: u64,
        reason: String,
    },
    ResyncRequired {
        base_offset: u64,
        end_offset: u64,
        reason: String,
    },
    Exit {
        session_instance_id: String,
        final_offset: u64,
        exit_code: Option<i32>,
        reason: String,
    },
    Error {
        code: String,
    },
}

#[derive(Debug)]
pub enum Frame {
    Control {
        id: u64,
        message: Control,
    },
    Data {
        id: u64,
        start_offset: u64,
        bytes: Vec<u8>,
    },
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Frame> {
    let len = reader.read_u32().await? as usize;
    if !(9..=MAX_FRAME).contains(&len) {
        return Err(invalid("invalid frame length"));
    }
    // Check the bound before allocation, including malicious length prefixes.
    let mut body = vec![0; len];
    reader.read_exact(&mut body).await?;
    let id = u64::from_be_bytes(body[1..9].try_into().map_err(|_| invalid("frame ID"))?);
    match body[0] {
        0 => {
            let mut payload = &body[9..];
            let message = ciborium::from_reader(&mut payload)
                .map_err(|_| invalid("invalid control frame"))?;
            if !payload.is_empty() {
                return Err(invalid("trailing control bytes"));
            }
            Ok(Frame::Control { id, message })
        }
        1 if len >= 17 => Ok(Frame::Data {
            id,
            start_offset: u64::from_be_bytes(
                body[9..17].try_into().map_err(|_| invalid("data offset"))?,
            ),
            bytes: body[17..].to_vec(),
        }),
        _ => Err(invalid("unknown frame kind")),
    }
}

pub async fn write_frame(writer: &mut (impl AsyncWrite + Unpin), frame: &Frame) -> io::Result<()> {
    let mut body = Vec::new();
    match frame {
        Frame::Control { id, message } => {
            body.push(0);
            body.extend_from_slice(&id.to_be_bytes());
            ciborium::into_writer(message, &mut body)
                .map_err(|_| invalid("cannot encode control frame"))?;
        }
        Frame::Data {
            id,
            start_offset,
            bytes,
        } => {
            if bytes.len() > MAX_FRAME - 17 {
                return Err(invalid("output frame too large"));
            }
            body.push(1);
            body.extend_from_slice(&id.to_be_bytes());
            body.extend_from_slice(&start_offset.to_be_bytes());
            body.extend_from_slice(bytes);
        }
    }
    if body.len() > MAX_FRAME {
        return Err(invalid("control frame too large"));
    }
    let len = u32::try_from(body.len()).map_err(|_| invalid("frame length overflow"))?;
    writer.write_u32(len).await?;
    writer.write_all(&body).await
}

pub async fn send_control(
    writer: &mut (impl AsyncWrite + Unpin),
    id: u64,
    message: Control,
) -> io::Result<()> {
    write_frame(writer, &Frame::Control { id, message }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fragmented_raw_output_round_trips_without_utf8_conversion() {
        let (mut client, mut server) = tokio::io::duplex(3);
        let sender = tokio::spawn(async move {
            write_frame(
                &mut client,
                &Frame::Data {
                    id: 7,
                    start_offset: u64::MAX - 3,
                    bytes: vec![0xff, 0, 0xc3],
                },
            )
            .await
            .unwrap();
        });
        let Frame::Data {
            id,
            start_offset,
            bytes,
        } = read_frame(&mut server).await.unwrap()
        else {
            panic!("data required")
        };
        assert_eq!(
            (id, start_offset, bytes),
            (7, u64::MAX - 3, vec![0xff, 0, 0xc3])
        );
        sender.await.unwrap();
    }

    #[tokio::test]
    async fn oversize_prefix_is_rejected_without_waiting_for_body() {
        let prefix = u32::MAX.to_be_bytes();
        assert!(read_frame(&mut prefix.as_slice()).await.is_err());
    }
}
