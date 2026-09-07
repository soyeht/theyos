//! Transport-only client. No process spawning, signal handling, retry of
//! uncertain writes, or child-killing Drop implementation belongs here.

use crate::supervisor_wire::{self as wire, Control, Frame, SessionInfo};
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixStream;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("PTY supervisor transport unavailable: {0}")]
    Transport(std::io::Error),
    #[error("PTY supervisor rejected operation: {0}")]
    Rejected(String),
    #[error("PTY supervisor protocol mismatch")]
    Protocol,
    #[error("PTY supervisor request timed out; delivery may be uncertain")]
    Timeout,
}

impl From<std::io::Error> for ClientError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::InvalidData {
            Self::Protocol
        } else {
            Self::Transport(error)
        }
    }
}

#[derive(Clone)]
pub struct SupervisorClient {
    socket: PathBuf,
}

/// Read-only installation probe. Identity and inventory come from the same
/// connection, so a restart between two RPCs cannot combine two brokers.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SupervisorStatus {
    pub protocol_version: u16,
    pub broker_boot_id: String,
    /// Kernel-reported peer PID, not a value supplied by the server. None on
    /// platforms without this credential; installers must not invent it.
    pub broker_pid: Option<u32>,
    pub live_sessions: usize,
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
        self.connect_identified().await.map(|(stream, _)| stream)
    }

    async fn connect_identified(&self) -> Result<(UnixStream, String), ClientError> {
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
                        broker_boot_id,
                        ..
                    },
            } if wire::valid_instance_id(&broker_boot_id) => Ok((stream, broker_boot_id)),
            Frame::Control {
                message: Control::Error { code },
                ..
            } if code == "version_mismatch" => Err(ClientError::Protocol),
            Frame::Control {
                message: Control::Error { code },
                ..
            } => Err(ClientError::Rejected(code)),
            _ => Err(ClientError::Protocol),
        }
    }

    /// Never starts a daemon, emits a ticket, or changes a session.
    pub async fn status(&self) -> Result<SupervisorStatus, ClientError> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (mut stream, broker_boot_id) = self.connect_identified().await?;
            let broker_pid = stream
                .peer_cred()?
                .pid()
                .and_then(|pid| u32::try_from(pid).ok());
            wire::send_control(&mut stream, 2, Control::List).await?;
            match wire::read_frame(&mut stream).await? {
                Frame::Control {
                    id: 2,
                    message: Control::Sessions { sessions },
                } => Ok(SupervisorStatus {
                    protocol_version: wire::VERSION,
                    broker_boot_id,
                    broker_pid,
                    live_sessions: sessions.iter().filter(|session| !session.closed).count(),
                }),
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn rejected_or_malformed_handshake_is_protocol_failure_without_retry() {
        for malformed in [false, true] {
            let root = tempfile::Builder::new()
                .prefix("pty-client-")
                .tempdir_in("/tmp")
                .unwrap();
            let socket = root.path().join("socket");
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            let server = tokio::spawn(async move {
                let (mut peer, _) = listener.accept().await.unwrap();
                assert!(matches!(
                    wire::read_frame(&mut peer).await.unwrap(),
                    Frame::Control {
                        message: Control::Hello { .. },
                        ..
                    }
                ));
                if malformed {
                    peer.write_all(&1_u32.to_be_bytes()).await.unwrap();
                } else {
                    wire::send_control(
                        &mut peer,
                        1,
                        Control::Error {
                            code: "version_mismatch".into(),
                        },
                    )
                    .await
                    .unwrap();
                }
                // No command is allowed after a rejected handshake.
                assert!(matches!(wire::read_frame(&mut peer).await,
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof));
                assert!(
                    tokio::time::timeout(Duration::from_millis(100), listener.accept())
                        .await
                        .is_err()
                );
            });
            assert!(matches!(
                SupervisorClient::new(socket).request(Control::List).await,
                Err(ClientError::Protocol)
            ));
            server.await.unwrap();
        }
    }
}
