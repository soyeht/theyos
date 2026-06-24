//! Trust-free Product A `relay_stream` Noise transport primitives.
//!
//! C7c-2c-2b moved these primitives here so the guest (friend-cli) can dial the
//! relay without depending on the engine crate. The initiator derives its
//! prologue from an audience-verified `RelayStreamOfferContract`; the responder
//! is PROLOGUE-DRIVEN — it takes a `RelayStreamNoisePrologue` plus a static key
//! and knows nothing about household issuer trust. The engine-side trust gate
//! (machine-issuer verification → prologue) stays in server-rs, which derives
//! the prologue before calling the prologue-driven responder handshake. Bytes
//! decoded with `from_canonical_bytes` are a format concern only and are not an
//! authentication anchor.

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use snow::{Builder, params::NoiseParams};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use zeroize::Zeroize;

use crate::claw_share_relay_stream_contract::{
    RelayStreamClawStaticPublicKey, RelayStreamContractError, RelayStreamNoisePrologue,
    RelayStreamOfferContract,
};
use crate::keys::P256PublicKey;

pub const RELAY_STREAM_NOISE_PROTOCOL: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

const RELAY_STREAM_NOISE_KEY_LEN: usize = RelayStreamClawStaticPublicKey::LEN;
const RELAY_STREAM_NOISE_TAG_LEN: usize = 16;
pub const RELAY_STREAM_NOISE_MAX_FRAME_LEN: usize = 65_535;
pub const RELAY_STREAM_NOISE_MAX_PLAINTEXT_RECORD_LEN: usize =
    RELAY_STREAM_NOISE_MAX_FRAME_LEN - RELAY_STREAM_NOISE_TAG_LEN;
const RELAY_STREAM_NOISE_FRAME_HEADER_LEN: usize = 4;

pub struct RelayStreamNoiseStaticPrivateKey {
    bytes: [u8; RELAY_STREAM_NOISE_KEY_LEN],
}

impl RelayStreamNoiseStaticPrivateKey {
    pub fn try_new(bytes: impl AsRef<[u8]>) -> Result<Self, RelayStreamNoiseError> {
        let bytes = bytes.as_ref();
        if bytes.len() != RELAY_STREAM_NOISE_KEY_LEN {
            return Err(RelayStreamNoiseError::StaticPrivateKeyMalformed {
                actual: bytes.len(),
            });
        }
        let mut out = [0u8; RELAY_STREAM_NOISE_KEY_LEN];
        out.copy_from_slice(bytes);
        Ok(Self { bytes: out })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; RELAY_STREAM_NOISE_KEY_LEN] {
        &self.bytes
    }
}

impl Drop for RelayStreamNoiseStaticPrivateKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for RelayStreamNoiseStaticPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RelayStreamNoiseStaticPrivateKey(len={RELAY_STREAM_NOISE_KEY_LEN}, redacted)"
        )
    }
}

pub struct RelayStreamNoiseStaticKeypair {
    private: RelayStreamNoiseStaticPrivateKey,
    public: RelayStreamClawStaticPublicKey,
}

impl RelayStreamNoiseStaticKeypair {
    #[must_use]
    pub fn from_parts(
        private: RelayStreamNoiseStaticPrivateKey,
        public: RelayStreamClawStaticPublicKey,
    ) -> Self {
        Self { private, public }
    }

    #[must_use]
    pub fn private_key(&self) -> &RelayStreamNoiseStaticPrivateKey {
        &self.private
    }

    #[must_use]
    pub fn public_key(&self) -> &RelayStreamClawStaticPublicKey {
        &self.public
    }
}

impl fmt::Debug for RelayStreamNoiseStaticKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamNoiseStaticKeypair")
            .field("private", &"RelayStreamNoiseStaticPrivateKey(redacted)")
            .field("public", &self.public)
            .finish()
    }
}

pub fn generate_relay_stream_noise_static_keypair()
-> Result<RelayStreamNoiseStaticKeypair, RelayStreamNoiseError> {
    let keypair = noise_builder()?.generate_keypair()?;
    Ok(RelayStreamNoiseStaticKeypair {
        private: RelayStreamNoiseStaticPrivateKey::try_new(&keypair.private)?,
        public: RelayStreamClawStaticPublicKey::try_new(&keypair.public)?,
    })
}

pub struct RelayStreamNoiseInitiator {
    handshake: Option<snow::HandshakeState>,
}

impl RelayStreamNoiseInitiator {
    pub fn new(
        offer: &RelayStreamOfferContract,
        expected_owner_pub: &P256PublicKey,
        expected_guest_device_pub: &P256PublicKey,
        now_unix: u64,
    ) -> Result<Self, RelayStreamNoiseError> {
        let prologue = offer.to_noise_prologue_for_audience(
            expected_owner_pub,
            expected_guest_device_pub,
            now_unix,
        )?;
        let handshake = noise_builder()?
            .prologue(prologue.as_bytes())?
            .remote_public_key(offer.payload.claw_static_pub.as_bytes())?
            .build_initiator()?;
        Ok(Self {
            handshake: Some(handshake),
        })
    }

    pub fn write_message_1(&mut self) -> Result<Vec<u8>, RelayStreamNoiseError> {
        let handshake = self
            .handshake
            .as_mut()
            .ok_or(RelayStreamNoiseError::StateConsumed)?;
        let mut out = vec![0u8; RELAY_STREAM_NOISE_MAX_FRAME_LEN];
        let len = handshake.write_message(&[], &mut out)?;
        out.truncate(len);
        Ok(out)
    }

    pub fn read_message_2(
        mut self,
        message: &[u8],
    ) -> Result<RelayStreamNoiseSession, RelayStreamNoiseError> {
        let mut handshake = self
            .handshake
            .take()
            .ok_or(RelayStreamNoiseError::StateConsumed)?;
        let mut payload = vec![0u8; RELAY_STREAM_NOISE_MAX_FRAME_LEN];
        let payload_len = handshake.read_message(message, &mut payload)?;
        if payload_len != 0 {
            return Err(RelayStreamNoiseError::UnexpectedHandshakePayload);
        }
        Ok(RelayStreamNoiseSession {
            transport: handshake.into_transport_mode()?,
        })
    }
}

impl fmt::Debug for RelayStreamNoiseInitiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamNoiseInitiator")
            .field("state", &"redacted")
            .finish()
    }
}

pub struct RelayStreamNoiseResponder {
    handshake: Option<snow::HandshakeState>,
}

impl RelayStreamNoiseResponder {
    /// Builds a responder from an already-derived prologue.
    ///
    /// The prologue is trust-free input here: the caller (engine-side) must have
    /// derived it from a verified offer — for machine-issuer trust that is
    /// `RelayStreamIssuerTrust::to_noise_prologue` in server-rs. This primitive
    /// only consumes the resulting bytes, so it carries no issuer-trust seam.
    pub fn new(
        prologue: &RelayStreamNoisePrologue,
        static_private_key: &RelayStreamNoiseStaticPrivateKey,
    ) -> Result<Self, RelayStreamNoiseError> {
        let handshake = noise_builder()?
            .prologue(prologue.as_bytes())?
            .local_private_key(static_private_key.as_bytes())?
            .build_responder()?;
        Ok(Self {
            handshake: Some(handshake),
        })
    }

    pub fn read_message_1(&mut self, message: &[u8]) -> Result<(), RelayStreamNoiseError> {
        let handshake = self
            .handshake
            .as_mut()
            .ok_or(RelayStreamNoiseError::StateConsumed)?;
        let mut payload = vec![0u8; RELAY_STREAM_NOISE_MAX_FRAME_LEN];
        let payload_len = handshake.read_message(message, &mut payload)?;
        if payload_len != 0 {
            return Err(RelayStreamNoiseError::UnexpectedHandshakePayload);
        }
        Ok(())
    }

    pub fn write_message_2(
        mut self,
    ) -> Result<(Vec<u8>, RelayStreamNoiseSession), RelayStreamNoiseError> {
        let mut handshake = self
            .handshake
            .take()
            .ok_or(RelayStreamNoiseError::StateConsumed)?;
        let mut out = vec![0u8; RELAY_STREAM_NOISE_MAX_FRAME_LEN];
        let len = handshake.write_message(&[], &mut out)?;
        out.truncate(len);
        Ok((
            out,
            RelayStreamNoiseSession {
                transport: handshake.into_transport_mode()?,
            },
        ))
    }
}

impl fmt::Debug for RelayStreamNoiseResponder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamNoiseResponder")
            .field("state", &"redacted")
            .finish()
    }
}

pub struct RelayStreamNoiseSession {
    transport: snow::TransportState,
}

impl RelayStreamNoiseSession {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, RelayStreamNoiseError> {
        if plaintext.len() > RELAY_STREAM_NOISE_MAX_PLAINTEXT_RECORD_LEN {
            return Err(snow::Error::Input.into());
        }
        let mut out = vec![0u8; plaintext.len() + RELAY_STREAM_NOISE_TAG_LEN];
        let len = self.transport.write_message(plaintext, &mut out)?;
        out.truncate(len);
        Ok(out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, RelayStreamNoiseError> {
        if ciphertext.len() > RELAY_STREAM_NOISE_MAX_FRAME_LEN {
            return Err(snow::Error::Input.into());
        }
        let mut out = vec![0u8; ciphertext.len()];
        let len = self.transport.read_message(ciphertext, &mut out)?;
        out.truncate(len);
        Ok(out)
    }
}

impl fmt::Debug for RelayStreamNoiseSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamNoiseSession")
            .field("transport", &"redacted")
            .finish()
    }
}

pub struct RelayStreamNoiseFramed<T> {
    stream: T,
    session: RelayStreamNoiseSession,
}

impl<T> RelayStreamNoiseFramed<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn initiator_handshake(
        mut stream: T,
        offer: &RelayStreamOfferContract,
        expected_owner_pub: &P256PublicKey,
        expected_guest_device_pub: &P256PublicKey,
        now_unix: u64,
    ) -> Result<Self, RelayStreamNoiseError> {
        let mut initiator = RelayStreamNoiseInitiator::new(
            offer,
            expected_owner_pub,
            expected_guest_device_pub,
            now_unix,
        )?;
        let message_1 = initiator.write_message_1()?;
        write_noise_frame(&mut stream, &message_1).await?;
        stream.flush().await?;
        let message_2 = read_noise_frame(&mut stream).await?;
        let session = initiator.read_message_2(&message_2)?;
        Ok(Self { stream, session })
    }

    pub async fn responder_handshake_with_prologue(
        mut stream: T,
        prologue: &RelayStreamNoisePrologue,
        static_private_key: &RelayStreamNoiseStaticPrivateKey,
    ) -> Result<Self, RelayStreamNoiseError> {
        let mut responder = RelayStreamNoiseResponder::new(prologue, static_private_key)?;
        let message_1 = read_noise_frame(&mut stream).await?;
        responder.read_message_1(&message_1)?;
        let (message_2, session) = responder.write_message_2()?;
        write_noise_frame(&mut stream, &message_2).await?;
        stream.flush().await?;
        Ok(Self { stream, session })
    }

    pub async fn write_frame_plaintext(
        &mut self,
        plaintext: &[u8],
    ) -> Result<(), RelayStreamNoiseError> {
        let ciphertext = self.session.encrypt(plaintext)?;
        write_noise_frame(&mut self.stream, &ciphertext).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn write_all_encrypted(
        &mut self,
        plaintext: &[u8],
    ) -> Result<(), RelayStreamNoiseError> {
        for chunk in plaintext.chunks(RELAY_STREAM_NOISE_MAX_PLAINTEXT_RECORD_LEN) {
            let ciphertext = self.session.encrypt(chunk)?;
            write_noise_frame(&mut self.stream, &ciphertext).await?;
        }
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn read_frame_plaintext(&mut self) -> Result<Vec<u8>, RelayStreamNoiseError> {
        let ciphertext = read_noise_frame(&mut self.stream).await?;
        self.session.decrypt(&ciphertext)
    }

    pub async fn read_exact_encrypted(
        &mut self,
        len: usize,
    ) -> Result<Vec<u8>, RelayStreamNoiseError> {
        let mut out = Vec::with_capacity(len.min(RELAY_STREAM_NOISE_MAX_PLAINTEXT_RECORD_LEN));
        while out.len() < len {
            let plaintext = self.read_frame_plaintext().await?;
            if plaintext.is_empty() {
                return Err(RelayStreamNoiseError::EmptyPlaintextRecord);
            }
            if out.len() + plaintext.len() > len {
                return Err(RelayStreamNoiseError::PlaintextRecordTooLarge {
                    expected_remaining: len - out.len(),
                    actual: plaintext.len(),
                });
            }
            out.extend_from_slice(&plaintext);
        }
        Ok(out)
    }

    pub fn into_inner(self) -> (T, RelayStreamNoiseSession) {
        (self.stream, self.session)
    }

    pub fn into_async_stream(self) -> RelayStreamNoiseAsyncStream<T> {
        RelayStreamNoiseAsyncStream::new(self.stream, self.session)
    }
}

impl<T> fmt::Debug for RelayStreamNoiseFramed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamNoiseFramed")
            .field("stream", &"redacted")
            .field("session", &self.session)
            .finish()
    }
}

pub struct RelayStreamNoiseAsyncStream<T> {
    stream: T,
    session: RelayStreamNoiseSession,
    read_state: RelayStreamNoiseReadState,
    read_plaintext: VecDeque<u8>,
    write_state: Option<RelayStreamNoiseWriteState>,
}

impl<T> RelayStreamNoiseAsyncStream<T> {
    fn new(stream: T, session: RelayStreamNoiseSession) -> Self {
        Self {
            stream,
            session,
            read_state: RelayStreamNoiseReadState::default(),
            read_plaintext: VecDeque::new(),
            write_state: None,
        }
    }

    pub fn into_inner(self) -> (T, RelayStreamNoiseSession) {
        (self.stream, self.session)
    }
}

impl<T> fmt::Debug for RelayStreamNoiseAsyncStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamNoiseAsyncStream")
            .field("stream", &"redacted")
            .field("session", &self.session)
            .field("read_buffered_plaintext_len", &self.read_plaintext.len())
            .field(
                "write_buffered_ciphertext_len",
                &self
                    .write_state
                    .as_ref()
                    .map_or(0, RelayStreamNoiseWriteState::remaining),
            )
            // `read_state` holds in-flight frame buffers; intentionally summarized
            // above rather than dumped verbatim.
            .finish_non_exhaustive()
    }
}

enum RelayStreamNoiseReadState {
    Header {
        buf: [u8; RELAY_STREAM_NOISE_FRAME_HEADER_LEN],
        filled: usize,
    },
    Body {
        len: usize,
        buf: Vec<u8>,
        filled: usize,
    },
}

impl Default for RelayStreamNoiseReadState {
    fn default() -> Self {
        Self::Header {
            buf: [0u8; RELAY_STREAM_NOISE_FRAME_HEADER_LEN],
            filled: 0,
        }
    }
}

struct RelayStreamNoiseWriteState {
    frame: Vec<u8>,
    written: usize,
}

impl RelayStreamNoiseWriteState {
    fn new(frame: Vec<u8>) -> Self {
        Self { frame, written: 0 }
    }

    fn remaining(&self) -> usize {
        self.frame.len().saturating_sub(self.written)
    }
}

impl<T> AsyncRead for RelayStreamNoiseAsyncStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if dst.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if drain_plaintext(&mut this.read_plaintext, dst) {
            return Poll::Ready(Ok(()));
        }

        loop {
            match &mut this.read_state {
                RelayStreamNoiseReadState::Header { buf, filled } => {
                    let before = *filled;
                    let mut header_dst = ReadBuf::new(&mut buf[*filled..]);
                    match Pin::new(&mut this.stream).poll_read(cx, &mut header_dst) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Ready(Ok(())) => {
                            let read = header_dst.filled().len();
                            if read == 0 {
                                if before == 0 {
                                    return Poll::Ready(Ok(()));
                                }
                                return Poll::Ready(Err(io::Error::new(
                                    ErrorKind::UnexpectedEof,
                                    "relay stream Noise frame header ended early",
                                )));
                            }
                            *filled += read;
                            if *filled < RELAY_STREAM_NOISE_FRAME_HEADER_LEN {
                                continue;
                            }

                            let len = u32::from_be_bytes(*buf);
                            if len == 0 {
                                return Poll::Ready(Err(noise_error_to_io(
                                    RelayStreamNoiseError::EmptyFrame,
                                )));
                            }
                            if u64::from(len) > RELAY_STREAM_NOISE_MAX_FRAME_LEN as u64 {
                                return Poll::Ready(Err(noise_error_to_io(
                                    RelayStreamNoiseError::FrameTooLarge {
                                        actual: u64::from(len),
                                        max: RELAY_STREAM_NOISE_MAX_FRAME_LEN,
                                    },
                                )));
                            }
                            let len = usize::try_from(len).map_err(|_| {
                                RelayStreamNoiseError::FrameTooLarge {
                                    actual: u64::from(len),
                                    max: RELAY_STREAM_NOISE_MAX_FRAME_LEN,
                                }
                            });
                            match len {
                                Ok(len) => {
                                    this.read_state = RelayStreamNoiseReadState::Body {
                                        len,
                                        buf: vec![0u8; len],
                                        filled: 0,
                                    };
                                }
                                Err(err) => return Poll::Ready(Err(noise_error_to_io(err))),
                            }
                        }
                    }
                }
                RelayStreamNoiseReadState::Body { len, buf, filled } => {
                    let mut body_dst = ReadBuf::new(&mut buf[*filled..]);
                    match Pin::new(&mut this.stream).poll_read(cx, &mut body_dst) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Ready(Ok(())) => {
                            let read = body_dst.filled().len();
                            if read == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    ErrorKind::UnexpectedEof,
                                    "relay stream Noise frame body ended early",
                                )));
                            }
                            *filled += read;
                            if *filled < *len {
                                continue;
                            }

                            let plaintext = this.session.decrypt(buf).map_err(noise_error_to_io)?;
                            this.read_state = RelayStreamNoiseReadState::default();
                            if plaintext.is_empty() {
                                return Poll::Ready(Err(noise_error_to_io(
                                    RelayStreamNoiseError::EmptyPlaintextRecord,
                                )));
                            }
                            this.read_plaintext.extend(plaintext);
                            let _ = drain_plaintext(&mut this.read_plaintext, dst);
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
            }
        }
    }
}

impl<T> AsyncWrite for RelayStreamNoiseAsyncStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_state.is_some() {
            match poll_drain_pending_frame(this, cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let accepted = buf.len().min(RELAY_STREAM_NOISE_MAX_PLAINTEXT_RECORD_LEN);
        let ciphertext = this
            .session
            .encrypt(&buf[..accepted])
            .map_err(noise_error_to_io)?;
        let frame = encode_noise_frame(&ciphertext).map_err(noise_error_to_io)?;
        this.write_state = Some(RelayStreamNoiseWriteState::new(frame));

        match poll_drain_pending_frame(this, cx) {
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(accepted)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(poll_drain_pending_frame(this, cx))?;
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(poll_drain_pending_frame(this, cx))?;
        ready!(Pin::new(&mut this.stream).poll_flush(cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

fn drain_plaintext(buffer: &mut VecDeque<u8>, dst: &mut ReadBuf<'_>) -> bool {
    let before = dst.filled().len();
    while dst.remaining() > 0 {
        let Some(byte) = buffer.pop_front() else {
            break;
        };
        dst.put_slice(&[byte]);
    }
    dst.filled().len() > before
}

fn poll_drain_pending_frame<T>(
    this: &mut RelayStreamNoiseAsyncStream<T>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>>
where
    T: AsyncWrite + Unpin,
{
    while let Some(pending) = &mut this.write_state {
        while pending.written < pending.frame.len() {
            let written = ready!(
                Pin::new(&mut this.stream).poll_write(cx, &pending.frame[pending.written..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "relay stream Noise frame write made no progress",
                )));
            }
            pending.written += written;
        }
        this.write_state = None;
    }
    Poll::Ready(Ok(()))
}

fn encode_noise_frame(message: &[u8]) -> Result<Vec<u8>, RelayStreamNoiseError> {
    if message.is_empty() {
        return Err(RelayStreamNoiseError::EmptyFrame);
    }
    if message.len() > RELAY_STREAM_NOISE_MAX_FRAME_LEN {
        return Err(RelayStreamNoiseError::FrameTooLarge {
            actual: message.len() as u64,
            max: RELAY_STREAM_NOISE_MAX_FRAME_LEN,
        });
    }
    let len = u32::try_from(message.len()).map_err(|_| RelayStreamNoiseError::FrameTooLarge {
        actual: message.len() as u64,
        max: RELAY_STREAM_NOISE_MAX_FRAME_LEN,
    })?;
    let mut frame = Vec::with_capacity(RELAY_STREAM_NOISE_FRAME_HEADER_LEN + message.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(message);
    Ok(frame)
}

fn noise_error_to_io(error: RelayStreamNoiseError) -> io::Error {
    match error {
        RelayStreamNoiseError::Io(error) => error,
        RelayStreamNoiseError::EmptyFrame
        | RelayStreamNoiseError::FrameTooLarge { .. }
        | RelayStreamNoiseError::UnexpectedHandshakePayload
        | RelayStreamNoiseError::EmptyPlaintextRecord
        | RelayStreamNoiseError::PlaintextRecordTooLarge { .. }
        | RelayStreamNoiseError::Snow(_) => io::Error::new(ErrorKind::InvalidData, error),
        RelayStreamNoiseError::Contract(_)
        | RelayStreamNoiseError::StaticPrivateKeyMalformed { .. }
        | RelayStreamNoiseError::StateConsumed => io::Error::other(error),
    }
}

async fn write_noise_frame<W>(writer: &mut W, message: &[u8]) -> Result<(), RelayStreamNoiseError>
where
    W: AsyncWrite + Unpin,
{
    let frame = encode_noise_frame(message)?;
    writer.write_all(&frame).await?;
    Ok(())
}

async fn read_noise_frame<R>(reader: &mut R) -> Result<Vec<u8>, RelayStreamNoiseError>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes);
    if len == 0 {
        return Err(RelayStreamNoiseError::EmptyFrame);
    }
    if u64::from(len) > RELAY_STREAM_NOISE_MAX_FRAME_LEN as u64 {
        return Err(RelayStreamNoiseError::FrameTooLarge {
            actual: u64::from(len),
            max: RELAY_STREAM_NOISE_MAX_FRAME_LEN,
        });
    }
    let len = usize::try_from(len).map_err(|_| RelayStreamNoiseError::FrameTooLarge {
        actual: u64::from(len),
        max: RELAY_STREAM_NOISE_MAX_FRAME_LEN,
    })?;
    let mut frame = vec![0u8; len];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}

fn noise_builder() -> Result<Builder<'static>, RelayStreamNoiseError> {
    let params: NoiseParams = RELAY_STREAM_NOISE_PROTOCOL.parse()?;
    Ok(Builder::new(params))
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamNoiseError {
    #[error("relay stream offer contract rejected")]
    Contract(#[from] RelayStreamContractError),

    #[error("relay stream Noise static private key malformed: {actual} bytes")]
    StaticPrivateKeyMalformed { actual: usize },

    #[error("relay stream Noise frame is empty")]
    EmptyFrame,

    #[error("relay stream Noise frame too large: {actual} bytes (max {max})")]
    FrameTooLarge { actual: u64, max: usize },

    #[error("relay stream Noise handshake included unexpected payload")]
    UnexpectedHandshakePayload,

    #[error("relay stream Noise plaintext record is empty")]
    EmptyPlaintextRecord,

    #[error(
        "relay stream Noise plaintext record too large: {actual} bytes for {expected_remaining} bytes remaining"
    )]
    PlaintextRecordTooLarge {
        expected_remaining: usize,
        actual: usize,
    },

    #[error("relay stream Noise state was already consumed")]
    StateConsumed,

    #[error("relay stream Noise I/O failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("relay stream Noise operation failed: {0}")]
    Snow(#[from] snow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claw_share::SlotId;
    use crate::claw_share_relay_stream_contract::{
        RelayStreamExpectedPath, RelayStreamOfferPayload, RelayStreamResource,
    };
    use crate::claw_share_rendezvous_token::RendezvousToken;
    use crate::keys::{IdentityKey, P256Keypair};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    /// Builds the responder prologue trust-free for these transport tests:
    /// owner-verified instead of machine-issuer-trust verified (the trust seam
    /// is server-rs). It is byte-identical to the initiator's audience prologue
    /// for the same offer, so the handshake still succeeds.
    fn responder_prologue(offer: &RelayStreamOfferContract) -> RelayStreamNoisePrologue {
        offer
            .to_noise_prologue_owner_verified(&owner_pub(), NOW)
            .unwrap()
    }

    const NOW: u64 = 1_800_000_000;
    const NOT_AFTER: u64 = NOW + 60;

    fn signer() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap()
    }

    fn attacker() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x55; 32]).unwrap()
    }

    fn owner_pub() -> P256PublicKey {
        signer().public()
    }

    fn guest_pub() -> P256PublicKey {
        P256Keypair::from_secret_scalar(&[0x33; 32])
            .unwrap()
            .public()
    }

    fn other_guest_pub() -> P256PublicKey {
        P256Keypair::from_secret_scalar(&[0x44; 32])
            .unwrap()
            .public()
    }

    fn token(label: u8) -> RendezvousToken {
        RendezvousToken::try_new(vec![label; 16]).unwrap()
    }

    fn payload_with(
        claw_static_pub: RelayStreamClawStaticPublicKey,
        edit: impl FnOnce(&mut RelayStreamOfferPayload),
    ) -> RelayStreamOfferPayload {
        let mut payload = RelayStreamOfferPayload::new(
            token(0x42),
            "claw_alpha".to_string(),
            SlotId([0x22; 16]),
            guest_pub(),
            RelayStreamResource::Pty,
            RelayStreamExpectedPath::RelayStream,
            "relay-stream://127.0.0.1:49152".to_string(),
            claw_static_pub,
            NOT_AFTER,
        );
        edit(&mut payload);
        payload
    }

    fn signed_offer_with(
        keypair: &RelayStreamNoiseStaticKeypair,
        edit: impl FnOnce(&mut RelayStreamOfferPayload),
    ) -> RelayStreamOfferContract {
        RelayStreamOfferContract::sign(payload_with(keypair.public_key().clone(), edit), &signer())
            .unwrap()
    }

    fn signed_offer(keypair: &RelayStreamNoiseStaticKeypair) -> RelayStreamOfferContract {
        signed_offer_with(keypair, |_| {})
    }

    fn handshake_pair(
        offer: &RelayStreamOfferContract,
        keypair: &RelayStreamNoiseStaticKeypair,
    ) -> (RelayStreamNoiseSession, RelayStreamNoiseSession) {
        let mut initiator =
            RelayStreamNoiseInitiator::new(offer, &owner_pub(), &guest_pub(), NOW).unwrap();
        let mut responder =
            RelayStreamNoiseResponder::new(&responder_prologue(offer), keypair.private_key())
                .unwrap();
        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();
        let (msg2, responder_session) = responder.write_message_2().unwrap();
        let initiator_session = initiator.read_message_2(&msg2).unwrap();
        (initiator_session, responder_session)
    }

    async fn framed_pair(
        offer: &RelayStreamOfferContract,
        keypair: &RelayStreamNoiseStaticKeypair,
    ) -> (
        RelayStreamNoiseFramed<DuplexStream>,
        RelayStreamNoiseFramed<DuplexStream>,
    ) {
        let (initiator_io, responder_io) = duplex(1_000_000);
        let owner = owner_pub();
        let guest = guest_pub();
        let prologue = responder_prologue(offer);
        tokio::try_join!(
            RelayStreamNoiseFramed::initiator_handshake(initiator_io, offer, &owner, &guest, NOW,),
            RelayStreamNoiseFramed::responder_handshake_with_prologue(
                responder_io,
                &prologue,
                keypair.private_key(),
            )
        )
        .unwrap()
    }

    async fn async_stream_pair(
        offer: &RelayStreamOfferContract,
        keypair: &RelayStreamNoiseStaticKeypair,
    ) -> (
        RelayStreamNoiseAsyncStream<DuplexStream>,
        RelayStreamNoiseAsyncStream<DuplexStream>,
    ) {
        let (initiator, responder) = framed_pair(offer, keypair).await;
        (initiator.into_async_stream(), responder.into_async_stream())
    }

    #[test]
    fn relay_contract_noise_handshake_nk_succeeds_with_same_offer_prologue_and_key() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer(&keypair);

        let (_initiator_session, _responder_session) = handshake_pair(&offer, &keypair);
    }

    #[test]
    fn relay_contract_noise_encrypt_decrypt_roundtrip_after_handshake() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer(&keypair);
        let (mut initiator_session, mut responder_session) = handshake_pair(&offer, &keypair);

        let secret_plaintext = b"relay stream plaintext stays inside transport state";
        let ciphertext = initiator_session.encrypt(secret_plaintext).unwrap();
        assert_ne!(ciphertext, secret_plaintext);
        let decrypted = responder_session.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, secret_plaintext);

        let reply = b"reply plaintext stays inside transport state";
        let reply_ciphertext = responder_session.encrypt(reply).unwrap();
        let reply_decrypted = initiator_session.decrypt(&reply_ciphertext).unwrap();
        assert_eq!(reply_decrypted, reply);
    }

    #[test]
    fn relay_contract_noise_divergent_token_prologue_fails_handshake() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let initiator_offer =
            signed_offer_with(&keypair, |payload| payload.rendezvous_token = token(0x43));
        let responder_offer = signed_offer(&keypair);

        let mut initiator =
            RelayStreamNoiseInitiator::new(&initiator_offer, &owner_pub(), &guest_pub(), NOW)
                .unwrap();
        let mut responder = RelayStreamNoiseResponder::new(
            &responder_prologue(&responder_offer),
            keypair.private_key(),
        )
        .unwrap();
        let msg1 = initiator.write_message_1().unwrap();

        assert!(matches!(
            responder.read_message_1(&msg1),
            Err(RelayStreamNoiseError::Snow(_))
        ));
    }

    #[test]
    fn relay_contract_noise_wrong_responder_static_key_fails_handshake() {
        let expected_keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let wrong_keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer(&expected_keypair);

        let mut initiator =
            RelayStreamNoiseInitiator::new(&offer, &owner_pub(), &guest_pub(), NOW).unwrap();
        let mut responder = RelayStreamNoiseResponder::new(
            &responder_prologue(&offer),
            wrong_keypair.private_key(),
        )
        .unwrap();
        let msg1 = initiator.write_message_1().unwrap();

        assert!(matches!(
            responder.read_message_1(&msg1),
            Err(RelayStreamNoiseError::Snow(_))
        ));
    }

    #[test]
    fn relay_contract_noise_attacker_signed_offer_does_not_start_handshake() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = RelayStreamOfferContract::sign(
            payload_with(keypair.public_key().clone(), |_| {}),
            &attacker(),
        )
        .unwrap();

        assert!(matches!(
            RelayStreamNoiseInitiator::new(&offer, &owner_pub(), &guest_pub(), NOW),
            Err(RelayStreamNoiseError::Contract(
                RelayStreamContractError::SignerMismatch
            ))
        ));
        // Trust-free responder prologue derivation rejects the attacker signer
        // (owner-verify). The machine-issuer-trust IssuerUnauthorized path is
        // covered engine-side in server-rs claw_share_relay_stream_noise.
        assert!(matches!(
            offer.to_noise_prologue_owner_verified(&owner_pub(), NOW),
            Err(RelayStreamContractError::SignerMismatch)
        ));
    }

    #[test]
    fn relay_contract_noise_expired_offer_does_not_start_handshake() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer_with(&keypair, |payload| payload.not_after = NOW);

        assert!(matches!(
            RelayStreamNoiseInitiator::new(&offer, &owner_pub(), &guest_pub(), NOW),
            Err(RelayStreamNoiseError::Contract(
                RelayStreamContractError::Expired
            ))
        ));
        assert!(matches!(
            offer.to_noise_prologue_owner_verified(&owner_pub(), NOW),
            Err(RelayStreamContractError::Expired)
        ));
    }

    #[test]
    fn relay_contract_noise_wrong_guest_audience_does_not_start_initiator() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer(&keypair);

        assert!(matches!(
            RelayStreamNoiseInitiator::new(&offer, &owner_pub(), &other_guest_pub(), NOW),
            Err(RelayStreamNoiseError::Contract(
                RelayStreamContractError::AudienceMismatch
            ))
        ));
        // The responder prologue does not bind the guest audience — that check is
        // the initiator/guest's job — so it builds for any audience.
        assert!(
            RelayStreamNoiseResponder::new(&responder_prologue(&offer), keypair.private_key())
                .is_ok()
        );
    }

    #[test]
    fn relay_contract_noise_debug_does_not_leak_private_key_token_or_plaintext() {
        let private =
            RelayStreamNoiseStaticPrivateKey::try_new([0x41; RELAY_STREAM_NOISE_KEY_LEN]).unwrap();
        let private_debug = format!("{private:?}");
        assert!(!private_debug.contains("414141"));
        assert!(!private_debug.contains("AAAA"));
        assert!(private_debug.contains("redacted"));

        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer_with(&keypair, |payload| {
            payload.rendezvous_token = RendezvousToken::try_new(b"0123456789abcdef").unwrap();
        });
        let mut initiator =
            RelayStreamNoiseInitiator::new(&offer, &owner_pub(), &guest_pub(), NOW).unwrap();
        let mut responder =
            RelayStreamNoiseResponder::new(&responder_prologue(&offer), keypair.private_key())
                .unwrap();
        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();
        let (msg2, responder_session) = responder.write_message_2().unwrap();
        let initiator_session = initiator.read_message_2(&msg2).unwrap();

        let debug = format!("{initiator_session:?} {responder_session:?}");
        assert!(!debug.contains("0123456789abcdef"));
        assert!(!debug.contains("30313233343536373839616263646566"));
        assert!(!debug.contains("relay stream plaintext stays inside transport state"));
        assert!(debug.contains("redacted"));
    }

    #[tokio::test]
    async fn relay_contract_noise_framed_handshake_and_bidirectional_plaintext() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer(&keypair);
        let (mut initiator, mut responder) = framed_pair(&offer, &keypair).await;

        let to_responder = b"guest-to-claw framed plaintext";
        let to_initiator = b"claw-to-guest framed plaintext";
        let initiator_task = async {
            initiator.write_all_encrypted(to_responder).await?;
            initiator.read_exact_encrypted(to_initiator.len()).await
        };
        let responder_task = async {
            let received = responder.read_exact_encrypted(to_responder.len()).await?;
            responder.write_all_encrypted(to_initiator).await?;
            Ok::<_, RelayStreamNoiseError>(received)
        };

        let (reply, request) = tokio::try_join!(initiator_task, responder_task).unwrap();
        assert_eq!(request, to_responder);
        assert_eq!(reply, to_initiator);
    }

    #[tokio::test]
    async fn relay_contract_noise_framed_chunks_large_plaintext_and_reconstructs() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer(&keypair);
        let (mut initiator, mut responder) = framed_pair(&offer, &keypair).await;
        let plaintext_len = RELAY_STREAM_NOISE_MAX_PLAINTEXT_RECORD_LEN * 2 + 123;
        let plaintext = (0..plaintext_len)
            .map(|idx| u8::try_from(idx % 251).unwrap())
            .collect::<Vec<_>>();

        let writer = async { initiator.write_all_encrypted(&plaintext).await };
        let reader = async { responder.read_exact_encrypted(plaintext.len()).await };

        let ((), received) = tokio::try_join!(writer, reader).unwrap();
        assert_eq!(received, plaintext);
    }

    #[tokio::test]
    async fn relay_contract_noise_framed_oversized_and_empty_frames_are_rejected() {
        let (mut writer, mut reader) = duplex(8);
        let oversized = u32::try_from(RELAY_STREAM_NOISE_MAX_FRAME_LEN + 1).unwrap();
        writer.write_all(&oversized.to_be_bytes()).await.unwrap();

        assert!(matches!(
            read_noise_frame(&mut reader).await,
            Err(RelayStreamNoiseError::FrameTooLarge { actual, max })
                if actual == u64::from(oversized) && max == RELAY_STREAM_NOISE_MAX_FRAME_LEN
        ));

        let (mut writer, mut reader) = duplex(8);
        writer.write_all(&0u32.to_be_bytes()).await.unwrap();

        assert!(matches!(
            read_noise_frame(&mut reader).await,
            Err(RelayStreamNoiseError::EmptyFrame)
        ));
    }

    #[tokio::test]
    async fn relay_contract_noise_framed_unexpected_handshake_payload_is_rejected() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer(&keypair);
        let prologue = offer.to_noise_prologue(&owner_pub(), NOW).unwrap();
        let mut malicious_initiator = noise_builder()
            .unwrap()
            .prologue(prologue.as_bytes())
            .unwrap()
            .remote_public_key(offer.payload.claw_static_pub.as_bytes())
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut message = vec![0u8; RELAY_STREAM_NOISE_MAX_FRAME_LEN];
        let len = malicious_initiator
            .write_message(b"unexpected-handshake-payload", &mut message)
            .unwrap();
        message.truncate(len);

        let (mut initiator_io, responder_io) = duplex(4096);
        let writer = async { write_noise_frame(&mut initiator_io, &message).await };
        let prologue = responder_prologue(&offer);
        let responder = RelayStreamNoiseFramed::responder_handshake_with_prologue(
            responder_io,
            &prologue,
            keypair.private_key(),
        );

        let (write_result, responder_result) = tokio::join!(writer, responder);
        write_result.unwrap();
        assert!(matches!(
            responder_result,
            Err(RelayStreamNoiseError::UnexpectedHandshakePayload)
        ));
    }

    #[tokio::test]
    async fn relay_contract_noise_framed_divergent_prologue_and_wrong_key_fail() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let initiator_offer =
            signed_offer_with(&keypair, |payload| payload.rendezvous_token = token(0x43));
        let responder_offer = signed_offer(&keypair);
        let (initiator_io, responder_io) = duplex(4096);
        let owner = owner_pub();
        let guest = guest_pub();
        let prologue = responder_prologue(&responder_offer);
        let result = tokio::try_join!(
            RelayStreamNoiseFramed::initiator_handshake(
                initiator_io,
                &initiator_offer,
                &owner,
                &guest,
                NOW,
            ),
            RelayStreamNoiseFramed::responder_handshake_with_prologue(
                responder_io,
                &prologue,
                keypair.private_key(),
            )
        );

        assert!(matches!(result, Err(RelayStreamNoiseError::Snow(_))));

        let expected_keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let wrong_keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer(&expected_keypair);
        let (initiator_io, responder_io) = duplex(4096);
        let owner = owner_pub();
        let guest = guest_pub();
        let prologue = responder_prologue(&offer);
        let result = tokio::try_join!(
            RelayStreamNoiseFramed::initiator_handshake(initiator_io, &offer, &owner, &guest, NOW,),
            RelayStreamNoiseFramed::responder_handshake_with_prologue(
                responder_io,
                &prologue,
                wrong_keypair.private_key(),
            )
        );

        assert!(matches!(result, Err(RelayStreamNoiseError::Snow(_))));
    }

    #[tokio::test]
    async fn relay_contract_noise_framed_attacker_and_expired_contracts_do_not_start() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let attacker_offer = RelayStreamOfferContract::sign(
            payload_with(keypair.public_key().clone(), |_| {}),
            &attacker(),
        )
        .unwrap();
        let (stream, _peer) = duplex(1024);
        let owner = owner_pub();
        let guest = guest_pub();

        assert!(matches!(
            RelayStreamNoiseFramed::initiator_handshake(
                stream,
                &attacker_offer,
                &owner,
                &guest,
                NOW,
            )
            .await,
            Err(RelayStreamNoiseError::Contract(
                RelayStreamContractError::SignerMismatch
            ))
        ));

        let expired_offer = signed_offer_with(&keypair, |payload| payload.not_after = NOW);

        assert!(matches!(
            expired_offer.to_noise_prologue_owner_verified(&owner_pub(), NOW),
            Err(RelayStreamContractError::Expired)
        ));
    }

    #[tokio::test]
    async fn relay_contract_noise_framed_debug_does_not_leak_secret_material() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer_with(&keypair, |payload| {
            payload.rendezvous_token = RendezvousToken::try_new(b"0123456789abcdef").unwrap();
        });
        let (initiator, responder) = framed_pair(&offer, &keypair).await;
        let debug = format!("{initiator:?} {responder:?}");

        assert!(!debug.contains("0123456789abcdef"));
        assert!(!debug.contains("30313233343536373839616263646566"));
        assert!(!debug.contains("guest-to-claw framed plaintext"));
        assert!(debug.contains("redacted"));
    }

    #[tokio::test]
    async fn relay_contract_noise_async_stream_bidirectional_async_read_write() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer(&keypair);
        let (mut initiator, mut responder) = async_stream_pair(&offer, &keypair).await;

        let to_responder = b"guest-to-claw async stream plaintext";
        let to_initiator = b"claw-to-guest async stream plaintext";
        let initiator_task = async {
            initiator.write_all(to_responder).await?;
            initiator.flush().await?;
            let mut reply = vec![0u8; to_initiator.len()];
            initiator.read_exact(&mut reply).await?;
            Ok::<_, io::Error>(reply)
        };
        let responder_task = async {
            let mut request = vec![0u8; to_responder.len()];
            responder.read_exact(&mut request).await?;
            responder.write_all(to_initiator).await?;
            responder.flush().await?;
            Ok::<_, io::Error>(request)
        };

        let (reply, request) = tokio::try_join!(initiator_task, responder_task).unwrap();
        assert_eq!(request, to_responder);
        assert_eq!(reply, to_initiator);
    }

    #[tokio::test]
    async fn relay_contract_noise_async_stream_hides_record_boundaries() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer(&keypair);
        let (mut initiator, mut responder) = async_stream_pair(&offer, &keypair).await;
        let large = (0..(RELAY_STREAM_NOISE_MAX_PLAINTEXT_RECORD_LEN + 777))
            .map(|idx| u8::try_from(idx % 251).unwrap())
            .collect::<Vec<_>>();
        let mut expected = b"a".to_vec();
        expected.extend_from_slice(b"bc");
        expected.extend_from_slice(&large);
        let expected_for_reader = expected.clone();

        let writer = async move {
            initiator.write_all(b"a").await?;
            initiator.write_all(b"bc").await?;
            initiator.write_all(&large).await?;
            initiator.flush().await
        };
        let reader = async move {
            let mut received = vec![0u8; expected_for_reader.len()];
            responder.read_exact(&mut received).await?;
            Ok::<_, io::Error>(received)
        };

        let ((), received) = tokio::try_join!(writer, reader).unwrap();
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn relay_contract_noise_async_stream_partial_reads_work() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer(&keypair);
        let (mut initiator, mut responder) = async_stream_pair(&offer, &keypair).await;
        let plaintext = b"partial reads see a continuous stream";

        let writer = async {
            initiator.write_all(plaintext).await?;
            initiator.flush().await
        };
        let reader = async {
            let mut received = Vec::with_capacity(plaintext.len());
            for _ in 0..plaintext.len() {
                let mut one = [0u8; 1];
                responder.read_exact(&mut one).await?;
                received.push(one[0]);
            }
            Ok::<_, io::Error>(received)
        };

        let ((), received) = tokio::try_join!(writer, reader).unwrap();
        assert_eq!(received, plaintext);
    }

    #[tokio::test]
    async fn relay_contract_noise_async_stream_rejects_empty_plaintext_record() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer(&keypair);
        let (mut initiator, responder) = framed_pair(&offer, &keypair).await;
        let mut responder = responder.into_async_stream();

        initiator.write_frame_plaintext(&[]).await.unwrap();
        let mut one = [0u8; 1];
        let err = responder.read(&mut one).await.unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("plaintext record is empty"));
    }

    #[tokio::test]
    async fn relay_contract_noise_async_stream_shutdown_eof_does_not_hang() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer(&keypair);
        let (mut initiator, mut responder) = async_stream_pair(&offer, &keypair).await;

        let writer = async {
            initiator.write_all(b"bye").await?;
            initiator.shutdown().await
        };
        let reader = async {
            let mut received = [0u8; 3];
            responder.read_exact(&mut received).await?;
            let mut extra = [0u8; 1];
            let read = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                responder.read(&mut extra),
            )
            .await
            .expect("EOF read should not hang")?;
            Ok::<_, io::Error>((received, read))
        };

        let ((), (received, read)) = tokio::try_join!(writer, reader).unwrap();
        assert_eq!(&received, b"bye");
        assert_eq!(read, 0);
    }

    #[tokio::test]
    async fn relay_contract_noise_async_stream_wrong_key_fails_before_adapter() {
        let expected_keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let wrong_keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer(&expected_keypair);
        let (initiator_io, responder_io) = duplex(4096);
        let owner = owner_pub();
        let guest = guest_pub();
        let prologue = responder_prologue(&offer);

        let result = tokio::try_join!(
            RelayStreamNoiseFramed::initiator_handshake(initiator_io, &offer, &owner, &guest, NOW,),
            RelayStreamNoiseFramed::responder_handshake_with_prologue(
                responder_io,
                &prologue,
                wrong_keypair.private_key(),
            )
        );

        assert!(matches!(result, Err(RelayStreamNoiseError::Snow(_))));
    }

    #[tokio::test]
    async fn relay_contract_noise_async_stream_debug_does_not_leak_secret_material() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = signed_offer_with(&keypair, |payload| {
            payload.rendezvous_token = RendezvousToken::try_new(b"0123456789abcdef").unwrap();
        });
        let (mut initiator, mut responder) = async_stream_pair(&offer, &keypair).await;
        let secret_plaintext = b"async stream buffered plaintext secret";

        let writer = async {
            initiator.write_all(secret_plaintext).await?;
            initiator.flush().await
        };
        let reader = async {
            let mut one = [0u8; 1];
            responder.read_exact(&mut one).await?;
            Ok::<_, io::Error>(responder)
        };
        let ((), responder) = tokio::try_join!(writer, reader).unwrap();
        let debug = format!("{responder:?}");

        assert!(!debug.contains("0123456789abcdef"));
        assert!(!debug.contains("30313233343536373839616263646566"));
        assert!(!debug.contains("async stream buffered plaintext secret"));
        assert!(debug.contains("redacted"));
    }
}
