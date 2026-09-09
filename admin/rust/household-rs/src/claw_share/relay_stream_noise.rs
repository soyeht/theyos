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

use crate::claw_share::relay_stream_contract::{
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
mod tests;
