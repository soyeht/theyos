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
use crate::ingress::CeremonyDeadline;
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
pub(crate) fn run_xx_handshake<S: Read + Write + wire::DeadlineBoundedIo>(
    stream: &mut S,
    role: Role,
    deadline: &CeremonyDeadline,
) -> Result<HandshakeOutcome, NoiseSetupError> {
    let mut handshake = build_handshake_state(role)?;
    // Scratch buffer sized to the same ceiling the wire layer enforces on
    // read; snow requires an output buffer at least as large as the
    // message it is about to write.
    let mut buf = vec![0u8; MAX_NOISE_HANDSHAKE_MESSAGE_LEN as usize];

    let mut send =
        |handshake: &mut HandshakeState, stream: &mut S| -> Result<(), NoiseSetupError> {
            let len = handshake.write_message(&[], &mut buf)?;
            wire::write_handshake_flight(stream, &buf[..len], deadline)?;
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
        let msg = wire::read_handshake_flight(stream, deadline)?;
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
    use std::time::{Duration, Instant};

    fn far_future_deadline() -> CeremonyDeadline {
        CeremonyDeadline::for_test(Instant::now(), Duration::from_secs(3600))
    }

    // ─── Conformance against an implementation that is not ours ────────────
    //
    // The plan's M1 carried an interop test against the kernel's WireGuard. We
    // do not implement WireGuard, so that test does not apply — but its REASON
    // does, and the plan states it better than anything else in it: *two of
    // your own programs agreeing prove nothing.* A real TUN round trip does not
    // satisfy it either; both ends there are ours.
    //
    // This drives the REAL `run_xx_handshake` against a pure-Python responder
    // that shares no code, no state and no cryptography with `snow`. Agreement
    // on the handshake hash is then evidence about the protocol rather than
    // about our own wiring.

    /// The independent implementation this conformance claim is made against.
    ///
    /// PINNED, and it is part of the vector rather than tooling hygiene: with
    /// an unpinned `--with noiseprotocol`, a later run agrees with a *different*
    /// implementation than the one the claim was measured against, and nothing
    /// in the repository changes. A floating comparand silently changes the
    /// subject of the assertion.
    ///
    /// Advancing it is a deliberate act: change this constant, and the peer's
    /// reported version must match or the test fails.
    const PEER_NOISE_VERSION: &str = "0.3.1";

    /// Kills and reaps the peer on every exit path, including a panic.
    ///
    /// `std::process::Child` does not kill on drop, so an assertion failing
    /// mid-test used to leave the peer alive until its own 30 s socket timeout
    /// retired it. That leaks a process and a port for half a minute per
    /// failure, which is how a suite that fails once starts failing its
    /// neighbours for unrelated reasons.
    struct PeerGuard(Option<std::process::Child>);

    impl PeerGuard {
        /// Wait for a clean exit and assert it. Consumes the guard, so the
        /// `Drop` path below is only ever the abnormal one.
        fn expect_clean_exit(mut self) {
            let mut child = self.0.take().expect("peer is taken exactly once");
            let status = child.wait().expect("peer terminates");
            assert!(
                status.success(),
                "the peer exited unsuccessfully ({status}); its handshake claims cannot be trusted"
            );
        }
    }

    impl PeerGuard {
        /// Kill the peer FIRST, then drain its stderr for a panic message.
        ///
        /// Order matters: reading a live child's stderr blocks until the child
        /// closes it, which for this peer means waiting out its own 30 s socket
        /// timeout. Killing first closes the pipe, so a broken run fails in
        /// milliseconds with the diagnostic attached instead of stalling.
        fn diagnose(&mut self, stderr: &mut std::process::ChildStderr) -> String {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            let mut captured = String::new();
            let _ = std::io::Read::read_to_string(stderr, &mut captured);
            captured.trim().to_string()
        }
    }

    impl Drop for PeerGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    /// Repo-relative path to the independent peer.
    fn peer_script() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../scripts/noise-conformance-peer.py")
    }

    #[test]
    fn handshake_agrees_with_an_independent_noise_implementation() {
        use std::io::{BufRead, BufReader, Read};
        use std::process::{Command, Stdio};

        // Port 0: the CHILD binds and reports what it got. Picking a port here
        // and handing it over would be a TOCTOU against the two sibling tests
        // in this binary that also bind `:0` — and because a lost race looks
        // like "peer produced no output", it would erode coverage silently
        // rather than flaking visibly.
        let spawned = Command::new("uv")
            .args(["run", "--quiet", "--with"])
            .arg(format!("noiseprotocol=={PEER_NOISE_VERSION}"))
            .arg("python")
            .arg(peer_script())
            .arg("0")
            .stdout(Stdio::piped())
            // stderr is CAPTURED, not discarded: a nulled stderr makes a
            // renamed script, a syntax error and an unresolvable dependency
            // all look identical to "no Python on this machine", which is the
            // one thing this test is allowed to skip for.
            .stderr(Stdio::piped())
            .spawn();

        let Ok(mut peer) = spawned else {
            // No `uv` on this machine. A skip must be loud and refusable:
            // without the escape hatch, a CI job that lost its Python would
            // report the same green as one that proved interoperability.
            assert!(
                std::env::var_os("THEYOS_REQUIRE_NOISE_INTEROP").is_none(),
                "THEYOS_REQUIRE_NOISE_INTEROP is set but `uv` could not be spawned, \
                 so the independent-implementation proof cannot run"
            );
            eprintln!(
                "SKIP handshake_agrees_with_an_independent_noise_implementation: `uv` \
                 not available. Set THEYOS_REQUIRE_NOISE_INTEROP=1 to make this skip \
                 a failure."
            );
            return;
        };

        let mut stderr_pipe = peer.stderr.take().expect("peer stderr is piped");
        let mut lines = BufReader::new(peer.stdout.take().expect("peer stdout is piped")).lines();
        // From here on every exit path — including a panicking assertion — kills
        // and reaps the peer, instead of leaving it to its own 30 s timeout.
        let mut peer = PeerGuard(Some(peer));

        // The peer's FIRST line is one of exactly two things, and it is read as
        // a two-variant enum rather than as a version line that might also be
        // something else. An earlier version consumed this line unconditionally
        // as `PEER_VERSIONS`, which made the script's own `PEER_UNAVAILABLE`
        // sentinel UNREACHABLE: the import fails at module top, before any
        // version can be reported, so the sentinel arrived here, was swallowed
        // as a version line, and the run then panicked on the missing
        // `LISTENING` instead of skipping. The "no uv" control never caught it
        // because that control measures a spawn failure, which is a different
        // path entirely — two skip mechanisms, one of them tested.
        let first = lines.next().and_then(Result::ok);

        if first
            .as_deref()
            .is_some_and(|line| line.starts_with("PEER_UNAVAILABLE"))
        {
            let line = first.expect("checked above");
            drop(peer);
            assert!(
                std::env::var_os("THEYOS_REQUIRE_NOISE_INTEROP").is_none(),
                "THEYOS_REQUIRE_NOISE_INTEROP is set but the peer is unavailable: {line}"
            );
            eprintln!("SKIP handshake_agrees_with_an_independent_noise_implementation: {line}");
            return;
        }

        // Not the sentinel, so it MUST be the version line. An unrecognised
        // first line is a hard failure: letting it through is how a peer that
        // is not the one we think it is gets to make claims.
        let versions = first.unwrap_or_else(|| {
            let diagnostic = peer.diagnose(&mut stderr_pipe);
            panic!(
                "the peer produced no output at all. Only the PEER_UNAVAILABLE \
                 sentinel may skip. peer stderr: {diagnostic}"
            )
        });
        let reported = versions.strip_prefix("PEER_VERSIONS ").unwrap_or_else(|| {
            let diagnostic = peer.diagnose(&mut stderr_pipe);
            panic!(
                "expected PEER_VERSIONS or PEER_UNAVAILABLE as the peer's first \
                 line, got {versions:?}; peer stderr: {diagnostic}"
            )
        });

        // Token equality, not `contains`. `contains("noiseprotocol=0.3.1")` is
        // also satisfied by 0.3.10, so a substring test would accept a
        // different implementation than the pinned one.
        let expected = format!("noiseprotocol={PEER_NOISE_VERSION}");
        assert!(
            reported.split_whitespace().any(|token| token == expected),
            "the peer is not the pinned implementation this claim was measured \
             against: expected {expected:?}, peer reported {reported:?}"
        );
        // `cryptography` is reported and deliberately not asserted — see
        // `report_versions` in the peer for why. It is on the record either way.
        eprintln!("interop peer: {reported}");

        let ready = lines.next().and_then(Result::ok);

        // ONLY the script's own sentinel counts as "this environment cannot run
        // the peer". Absent output is a broken test, not a missing interpreter,
        // and treating the two alike is how a test reports success having
        // proven nothing.
        let ready = ready.unwrap_or_else(|| {
            let diagnostic = peer.diagnose(&mut stderr_pipe);
            panic!(
                "the peer announced its versions and then stopped before binding \
                 a port. peer stderr: {diagnostic}"
            )
        });

        // The child owns the port. Parsing it back also proves the peer really
        // bound one, rather than us assuming a port it never reached.
        let port: u16 = ready
            .strip_prefix("LISTENING ")
            .unwrap_or_else(|| {
                let mut diagnostic = String::new();
                let _ = stderr_pipe.read_to_string(&mut diagnostic);
                panic!(
                    "expected `LISTENING <port>`, got {ready:?}; peer stderr: {}",
                    diagnostic.trim()
                )
            })
            .trim()
            .parse()
            .expect("peer announces a numeric port");

        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the peer");

        // The production entry point, not a re-implementation of it. This is
        // the whole point: a scratch harness that redoes the same sequence with
        // `snow` would prove the parameters and leave this function untested.
        let outcome = run_xx_handshake(&mut stream, Role::Initiator, &far_future_deadline())
            .expect("XX handshake completes against the independent peer");
        let ours = outcome
            .handshake_hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        let reported = lines
            .next()
            .and_then(Result::ok)
            .expect("peer reports its handshake hash");
        let theirs = reported
            .strip_prefix("HANDSHAKE_HASH ")
            .unwrap_or_else(|| panic!("expected HANDSHAKE_HASH, got {reported:?}"));

        assert_eq!(
            ours, theirs,
            "two independent implementations must derive the same handshake hash"
        );

        // A handshake that agrees but cannot carry a record would be agreement
        // about nothing, so the transport is exercised in both directions.
        let mut transport = outcome.transport;
        let mut buf = vec![0u8; MAX_NOISE_HANDSHAKE_MESSAGE_LEN as usize];
        let len = transport
            .write_message(b"ping-from-production-endpoint", &mut buf)
            .expect("encrypt a transport record");
        // The production framing, not a hand-rolled copy of it. An earlier
        // draft wrote the length prefix inline and read the reply with
        // `read_exact` into `vec![0u8; declared]`, which dropped the ceiling
        // `read_length_prefixed_frame` enforces BEFORE allocating: a peer-
        // controlled u32 then sized the allocation, and a mutated peer sending
        // a little-endian prefix made the test allocate ~576 MiB from a 36-byte
        // record. It also meant the transport framing the auth ceremony will
        // actually use was the one part NOT proven against the peer.
        wire::write_transport_record(&mut stream, &buf[..len], &far_future_deadline())
            .expect("write the record through the production framing");

        let echoed = lines
            .next()
            .and_then(Result::ok)
            .expect("peer reports what it decrypted");
        assert_eq!(
            echoed, "DECRYPTED ping-from-production-endpoint",
            "the independent peer must recover our plaintext exactly"
        );

        let reply = wire::read_transport_record(&mut stream, &far_future_deadline())
            .expect("read the reply through the production framing");
        let plain_len = transport
            .read_message(&reply, &mut buf)
            .expect("decrypt the peer's record");
        assert_eq!(
            &buf[..plain_len],
            b"pong-from-independent-implementation",
            "we must recover the independent peer's plaintext exactly"
        );

        // Not `let _ = wait()`: a peer that reached the end of its script but
        // exited nonzero would otherwise let this test pass on claims made by a
        // process that then failed.
        peer.expect_clean_exit();
    }

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
        wire::write_handshake_flight(&mut framed, &buf[..len], &far_future_deadline()).unwrap();
        let mut stream = Cursor::new(framed);

        let err =
            run_xx_handshake(&mut stream, Role::Responder, &far_future_deadline()).unwrap_err();
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
            run_xx_handshake(&mut sock, Role::Responder, &far_future_deadline()).unwrap()
        });

        let mut initiator_sock = TcpStream::connect(addr).unwrap();
        let initiator_outcome =
            run_xx_handshake(&mut initiator_sock, Role::Initiator, &far_future_deadline()).unwrap();
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
            run_xx_handshake(&mut sock, Role::Responder, &far_future_deadline()).unwrap()
        });

        let mut initiator_sock = TcpStream::connect(addr).unwrap();
        let mut initiator_outcome =
            run_xx_handshake(&mut initiator_sock, Role::Initiator, &far_future_deadline()).unwrap();
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
        let err = wire::read_handshake_flight(&mut cursor, &far_future_deadline()).unwrap_err();
        assert!(matches!(
            err,
            crate::error::WireError::OversizeFrame {
                declared: 65_536,
                ..
            }
        ));
    }
}
