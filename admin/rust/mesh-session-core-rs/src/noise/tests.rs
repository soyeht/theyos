#![cfg(test)]

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
        self.kill_tree();
        let mut captured = String::new();
        let _ = std::io::Read::read_to_string(stderr, &mut captured);
        captured.trim().to_string()
    }

    /// Kill the whole process GROUP, not just the child we hold.
    ///
    /// The child is `uv`, and `uv run python …` runs the interpreter as a
    /// further child of its own. `Child::kill` reaps `uv` and leaves the
    /// interpreter alive holding the stderr pipe open, so a subsequent
    /// `read_to_string` still blocks until the peer's own 30 s socket
    /// timeout — measured: a malformed-readiness control failed in 30.10 s
    /// with the child "killed". Killing the group is what actually makes it
    /// fast; the process group exists because `process_group(0)` is set at
    /// spawn.
    /// IDEMPOTENT by taking ownership: after `diagnose` kills the group,
    /// `self.0` used to stay `Some`, so the panic's `Drop` ran `kill_tree`
    /// a second time against a PID that no longer existed — measured, it
    /// printed `kill: -<pid>: No such process` into the test output. Noise
    /// is the small cost; the real one is that a PID/PGID can be recycled
    /// between the two calls, and the second `SIGKILL` would then land on
    /// an unrelated process group.
    fn kill_tree(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        let _ = std::process::Command::new("/bin/kill")
            .arg("-KILL")
            .arg(format!("-{}", child.id()))
            // Silenced: the normal path reaches here with the group already
            // gone, and `kill`'s complaint about that is not a finding —
            // printing it would train readers to skim the test's output.
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        self.kill_tree();
    }
}

// Runtime test inputs must be literals so the coverage gate can inventory
// them and include_bytes! adds the same dependency edge to Cargo's depfile.
macro_rules! repo_test_file {
    ($path:literal) => {{
        const _: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../", $path));
        $path
    }};
}

/// Repo-relative path to the independent peer.
fn peer_script() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../")
        .join(repo_test_file!("scripts/noise-conformance-peer.py"))
}

#[test]
fn handshake_agrees_with_an_independent_noise_implementation() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::CommandExt;
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
        // Its own process group, so `kill_tree` can reap the interpreter
        // `uv` spawns underneath itself and not just `uv`.
        .process_group(0)
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

    // `strip_prefix("PEER_UNAVAILABLE ")` with a non-empty reason, NOT
    // `starts_with`: the latter also accepts `PEER_UNAVAILABLE_BOGUS`, so a
    // line that merely resembles the sentinel could buy a skip. A near-miss
    // falls through and is rejected as an unrecognised first line, which is
    // the safe direction — the enum described in the comment above is only
    // an enum if the grammar is exact.
    if first
        .as_deref()
        .and_then(|line| line.strip_prefix("PEER_UNAVAILABLE "))
        .is_some_and(|reason| !reason.trim().is_empty())
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
            let diagnostic = peer.diagnose(&mut stderr_pipe);
            panic!("expected `LISTENING <port>`, got {ready:?}; peer stderr: {diagnostic}")
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

    let err = run_xx_handshake(&mut stream, Role::Responder, &far_future_deadline()).unwrap_err();
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
