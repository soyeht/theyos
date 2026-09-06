//! Transport-only client. No process spawning, signal handling, retry of
//! uncertain writes, or child-killing Drop implementation belongs here.

use crate::supervisor_wire::{self as wire, Control, Frame, SessionInfo};
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixStream;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("PTY supervisor transport unavailable: {0}")]
    Transport(#[from] std::io::Error),
    #[error("PTY supervisor rejected operation: {0}")]
    Rejected(String),
    #[error("PTY supervisor protocol mismatch")]
    Protocol,
    #[error("PTY supervisor request timed out; delivery may be uncertain")]
    Timeout,
}

#[derive(Clone)]
pub struct SupervisorClient {
    socket: PathBuf,
}

pub struct AttachedStream {
    pub stream: UnixStream,
    pub info: SessionInfo,
    pub base_offset: u64,
    pub replay_end: u64,
}

impl SupervisorClient {
    #[must_use]
    pub fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    async fn connect(&self) -> Result<UnixStream, ClientError> {
        let mut stream = UnixStream::connect(&self.socket).await?;
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
                id: 1,
                message:
                    Control::Welcome {
                        selected_version: wire::VERSION,
                        ..
                    },
            } => Ok(stream),
            Frame::Control {
                message: Control::Error { code },
                ..
            } => Err(ClientError::Rejected(code)),
            _ => Err(ClientError::Protocol),
        }
    }

    /// Exactly one attempt. In particular, WRITE must never be retried after
    /// an ambiguous transport failure: the shell may have consumed the input.
    pub async fn request(&self, message: Control) -> Result<Control, ClientError> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = self.connect().await?;
            wire::send_control(&mut stream, 2, message).await?;
            match wire::read_frame(&mut stream).await? {
                Frame::Control {
                    id: 2,
                    message: Control::Error { code },
                } => Err(ClientError::Rejected(code)),
                Frame::Control { id: 2, message } => Ok(message),
                _ => Err(ClientError::Protocol),
            }
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    pub async fn attach(
        &self,
        conversation_id: String,
        session_instance_id: String,
        next_offset: u64,
    ) -> Result<AttachedStream, ClientError> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = self.connect().await?;
            wire::send_control(
                &mut stream,
                2,
                Control::Attach {
                    conversation_id: conversation_id.clone(),
                    session_instance_id: session_instance_id.clone(),
                    next_offset,
                },
            )
            .await?;
            match wire::read_frame(&mut stream).await? {
                Frame::Control {
                    id: 2,
                    message:
                        Control::Attached {
                            info,
                            base_offset,
                            replay_end,
                        },
                } if info.conversation_id == conversation_id
                    && info.session_instance_id == session_instance_id
                    && base_offset <= replay_end =>
                {
                    Ok(AttachedStream {
                        stream,
                        info,
                        base_offset,
                        replay_end,
                    })
                }
                Frame::Control {
                    id: 2,
                    message: Control::Error { code },
                } => Err(ClientError::Rejected(code)),
                _ => Err(ClientError::Protocol),
            }
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }
}
