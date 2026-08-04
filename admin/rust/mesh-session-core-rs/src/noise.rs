//! Noise XX session-static setup (Fila 1 item 2).
//!
//! B-SESSAO v6 §1: `Noise_XX_25519_ChaChaPoly_BLAKE2s`, a fresh
//! `Builder::generate_keypair()` per connection, the generated private key
//! zeroized (via `Zeroizing`, covering every early-return path from the
//! moment it exists), `get_handshake_hash()` copied out before
//! `into_transport_mode()` consumes the handshake state, and a prologue
//! that is *only* `domain || version` — never hh_id, IP, or path.
//!
//! This module drives the 3 XX flights using the item-1 wire framing. It
//! does not implement anything past `is_handshake_finished()` — no
//! post-handshake frame types (those are auth-frame schemas, out of this
//! crate's scope; see delegation.rs's module doc for the same boundary on
//! signing).
//!
//! Every item here is `pub(crate)`, called only by `auth_state_machine`,
//! which is itself `pub(crate)` pending a real D-1/D-9 admission authority
//! (see its module doc) — so a plain (non-test) build of this crate has no
//! production caller for any of it yet, and would otherwise warn on every
//! item as dead code. `#![allow(dead_code)]` reflects that this is the
//! expected, intentional current state, not an oversight; `cargo test`
//! exercises all of it via `auth_state_machine`'s test suite.
#![allow(dead_code)]

use std::io::{Read, Write};

use snow::{Builder, HandshakeState, TransportState};
use zeroize::Zeroizing;

use crate::error::NoiseSetupError;
use crate::wire::{self, MAX_NOISE_HANDSHAKE_MESSAGE_LEN};

pub const PROTOCOL_NAME: &str = "soyeht/mesh-session/v1";
pub const PROTOCOL_VERSION_BYTE: u8 = 0x01;
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// `prologue = "soyeht/mesh-session/v1" || 0x01` — domain and version only.
/// Takes no parameters so nothing else (hh_id, IP, path) can be smuggled
/// in by a future caller.
pub fn prologue() -> Vec<u8> {
    let mut p = Vec::with_capacity(PROTOCOL_NAME.len() + 1);
    p.extend_from_slice(PROTOCOL_NAME.as_bytes());
    p.push(PROTOCOL_VERSION_BYTE);
    p
}

/// Build a fresh `HandshakeState` with a freshly generated (CSPRNG)
/// session-static X25519 keypair. The private key exists only inside a
/// `Zeroizing<Vec<u8>>` from the moment `generate_keypair()` returns, so
/// every `?` between here and the end of this function zeroizes it on the
/// way out rather than leaking it in a dropped, unzeroized `Vec`. Never
/// calls snow's `fixed_ephemeral_key_for_testing_only` — that method is not
/// referenced anywhere in this crate.
fn build_handshake_state(role: Role) -> Result<HandshakeState, NoiseSetupError> {
    let params = NOISE_PATTERN
        .parse()
        .expect("NOISE_PATTERN is a valid, fixed Noise pattern string");
    let builder = Builder::new(params);
    let keypair = builder.generate_keypair()?;
    let private_key = Zeroizing::new(keypair.private);
    let prologue_bytes = prologue();
    let builder = builder
        .local_private_key(&private_key)?
        .prologue(&prologue_bytes)?;
    let handshake = match role {
        Role::Initiator => builder.build_initiator()?,
        Role::Responder => builder.build_responder()?,
    };
    // `private_key` (Zeroizing) drops here on every path, including the
    // `?` early returns above — zeroized either way.
    Ok(handshake)
}

/// The output of a completed handshake: the transport state to encrypt/
/// decrypt with, and the handshake hash captured *before*
/// `into_transport_mode()` consumed the handshake state (snow does not
/// expose the hash afterward).
///
/// **`pub(crate)` on purpose (hardened 2026-08-04, independent audit of
/// `911409eb`):** an earlier version exposed this and `run_xx_handshake`
/// publicly, which let any external caller reach `transport` directly and
/// start encrypting application data immediately after the 3 XX flights —
/// completely bypassing the 5-frame auth ceremony v6 §13 requires before
/// DATA is allowed. Only this crate's own auth state machine may drive a
/// handshake and hold a raw `TransportState`; the external-facing result
/// of a successful handshake is whatever opaque "Active" session type the
/// auth state machine returns after ActivateAck, not this.
#[derive(Debug)]
pub(crate) struct HandshakeOutcome {
    pub(crate) transport: TransportState,
    pub(crate) handshake_hash: Vec<u8>,
}

/// Drive the 3 XX flights over `stream`, each framed per item 1
/// (`[4-byte BE length][handshake bytes]`, payload empty as required by
/// v6 §1). Returns once the handshake is finished, transport mode has been
/// entered, and the handshake hash has been captured. `pub(crate)` — see
/// [`HandshakeOutcome`].
pub(crate) fn run_xx_handshake<S: Read + Write>(
    stream: &mut S,
    role: Role,
) -> Result<HandshakeOutcome, NoiseSetupError> {
    let mut handshake = build_handshake_state(role)?;
    // Scratch buffer sized to the same ceiling the wire layer enforces on
    // read; snow requires an output buffer at least as large as the
    // message it is about to write.
    let mut buf = vec![0u8; MAX_NOISE_HANDSHAKE_MESSAGE_LEN as usize];

    let mut send =
        |handshake: &mut HandshakeState, stream: &mut S| -> Result<(), NoiseSetupError> {
            let len = handshake.write_message(&[], &mut buf)?;
            wire::write_handshake_flight(stream, &buf[..len])?;
            Ok(())
        };
    // v6 §1: "Payload dos 3 flights é vazio obrigatório." snow's
    // read_message returns the number of PAYLOAD bytes it recovered —
    // discarding that return value (as an earlier version of this
    // function did) silently accepts a peer that smuggles payload data
    // into a handshake flight. Any nonzero length is rejected.
    let recv = |handshake: &mut HandshakeState,
                stream: &mut S,
                buf: &mut [u8]|
     -> Result<(), NoiseSetupError> {
        let msg = wire::read_handshake_flight(stream)?;
        let payload_len = handshake.read_message(&msg, buf)?;
        if payload_len != 0 {
            return Err(NoiseSetupError::NonEmptyHandshakePayload(payload_len));
        }
        Ok(())
    };

    match role {
        Role::Initiator => {
            send(&mut handshake, stream)?; // -> e
            let mut scratch = vec![0u8; MAX_NOISE_HANDSHAKE_MESSAGE_LEN as usize];
            recv(&mut handshake, stream, &mut scratch)?; // <- e, ee, s, es
            send(&mut handshake, stream)?; // -> s, se
        }
        Role::Responder => {
            let mut scratch = vec![0u8; MAX_NOISE_HANDSHAKE_MESSAGE_LEN as usize];
            recv(&mut handshake, stream, &mut scratch)?; // <- e
            send(&mut handshake, stream)?; // -> e, ee, s, es
            recv(&mut handshake, stream, &mut scratch)?; // <- s, se
        }
    }

    if !handshake.is_handshake_finished() {
        return Err(NoiseSetupError::HandshakeNotFinished);
    }
    // Copy the hash out BEFORE into_transport_mode() consumes handshake —
    // snow does not expose get_handshake_hash() on TransportState.
    let handshake_hash = handshake.get_handshake_hash().to_vec();
    let transport = handshake.into_transport_mode()?;
    Ok(HandshakeOutcome {
        transport,
        handshake_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn nonempty_handshake_payload_is_rejected() {
        use std::io::Cursor;
        // A "fake initiator" that writes flight 1 (-> e) with a nonzero
        // payload, exactly what build_handshake_state's real flow never
        // does (it always passes &[]). Same params/prologue so the Noise
        // math itself is compatible; only the payload differs.
        let mut fake_initiator = build_handshake_state(Role::Initiator).unwrap();
        let mut buf = vec![0u8; MAX_NOISE_HANDSHAKE_MESSAGE_LEN as usize];
        let len = fake_initiator
            .write_message(b"unexpected payload", &mut buf)
            .unwrap();

        let mut framed = Vec::new();
        wire::write_handshake_flight(&mut framed, &buf[..len]).unwrap();
        let mut stream = Cursor::new(framed);

        let err = run_xx_handshake(&mut stream, Role::Responder).unwrap_err();
        assert!(
            matches!(err, NoiseSetupError::NonEmptyHandshakePayload(n) if n == b"unexpected payload".len())
        );
    }

    #[test]
    fn prologue_is_exactly_domain_and_version_byte() {
        let p = prologue();
        assert_eq!(p.len(), PROTOCOL_NAME.len() + 1);
        assert_eq!(&p[..PROTOCOL_NAME.len()], PROTOCOL_NAME.as_bytes());
        assert_eq!(p[PROTOCOL_NAME.len()], 0x01);
    }

    #[test]
    fn xx_handshake_completes_over_a_real_socket_and_hashes_match() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            run_xx_handshake(&mut sock, Role::Responder).unwrap()
        });

        let mut initiator_sock = TcpStream::connect(addr).unwrap();
        let initiator_outcome = run_xx_handshake(&mut initiator_sock, Role::Initiator).unwrap();
        let responder_outcome = responder.join().unwrap();

        // Both sides must agree on the transcript hash — this is what
        // later gets embedded as h_final in the auth frames (out of scope
        // here, but the hash itself is item 2's deliverable).
        assert_eq!(
            initiator_outcome.handshake_hash,
            responder_outcome.handshake_hash
        );
        assert_eq!(initiator_outcome.handshake_hash.len(), 32); // BLAKE2s digest size
    }

    #[test]
    fn transport_state_can_encrypt_and_decrypt_after_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            run_xx_handshake(&mut sock, Role::Responder).unwrap()
        });

        let mut initiator_sock = TcpStream::connect(addr).unwrap();
        let mut initiator_outcome = run_xx_handshake(&mut initiator_sock, Role::Initiator).unwrap();
        let mut responder_outcome = responder.join().unwrap();

        let plaintext = b"post-handshake application data";
        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let ct_len = initiator_outcome
            .transport
            .write_message(plaintext, &mut ciphertext)
            .unwrap();

        let mut recovered = vec![0u8; plaintext.len()];
        let pt_len = responder_outcome
            .transport
            .read_message(&ciphertext[..ct_len], &mut recovered)
            .unwrap();
        assert_eq!(&recovered[..pt_len], plaintext);
    }

    #[test]
    fn oversize_handshake_flight_prefix_is_rejected_before_snow_ever_sees_it() {
        // Reuses the item-1 wire ceiling directly — a peer that lies about
        // the flight length never reaches snow::read_message at all.
        use std::io::Cursor;
        let mut evil = Vec::new();
        evil.extend_from_slice(&65_536u32.to_be_bytes());
        let mut cursor = Cursor::new(evil);
        let err = wire::read_handshake_flight(&mut cursor).unwrap_err();
        assert!(matches!(
            err,
            crate::error::WireError::OversizeFrame {
                declared: 65_536,
                ..
            }
        ));
    }
}
