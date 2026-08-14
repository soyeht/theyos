//! M1a(a): deterministic Noise vectors, in an isolated harness.
//!
//! M1a is split because byte-exactness and fresh keys are incompatible by
//! construction, and the plan's answer to that is not to weaken the core:
//!
//!   (b) LIVE interop, fresh keys, agreement on the handshake hash. Closed:
//!       `noise.rs`'s `handshake_agrees_with_an_independent_noise_implementation`
//!       drives the REAL `run_xx_handshake` against `noiseprotocol`.
//!   (a) THIS file. Fixed test keys, so the transcript is stable enough to
//!       freeze; an independent implementation must reproduce it byte for
//!       byte; and each negative must be refused by BOTH sides.
//!
//! WHY THIS IS A `tests/` TARGET AND NOT `mod tests`. The plan forbids adding
//! `fixed_ephemeral_key_for_testing_only` -- or any fixed-key seam -- to the
//! MESH-SESSION production surface or flow: this core generates a fresh keypair
//! per connection and does not expose that seam, and that is a property, not an
//! accident. So the fixed keys live here, in a target Cargo builds only under
//! `cargo test`, and the seam used is `snow`'s own upstream `Builder` method,
//! reached from a `Builder` this file constructs. This commit changes no byte
//! under `src/`. What is MECHANIZED is narrower than that and is named for what
//! it is: `no_literal_seam_reference_outside_the_allowlisted_mention` checks
//! that the identifier appears under `mesh-session-core-rs/src` exactly once,
//! byte-for-byte, in the single allowlisted TEXTUAL occurrence -- which in this
//! object happens to be a doc-comment, though the check proves neither its
//! lexical category nor its position. It is a
//! TEXTUAL check. It does not parse, does not expand macros, and does not
//! reason about reachability -- indirection through a macro defined elsewhere
//! would leave no literal occurrence and would not be seen. Other crates and
//! other protocols are outside the scan entirely.
//!
//! WHAT IS REUSED FROM PRODUCTION. Exactly two symbols, imported rather than
//! retyped, so a change to either fails here instead of silently making the
//! vectors describe a protocol we no longer speak: `NOISE_PATTERN` and
//! `prologue()`.
//!
//! PROVENANCE OF THE CORPUS. The frozen file is generated from THIS tree's
//! code and pins (`snow` from this crate's `Cargo.lock`, `noiseprotocol`
//! pinned below), reviewed, and then committed. The test regenerates and
//! checks it field by field under an EXHAUSTIVE key set, so an added, renamed
//! or dropped field fails rather than being skipped by a lookup that simply
//! does not find it. It is deliberately NOT copied from any earlier tree: a
//! corpus whose provenance is old literals proves the old tree, not this one.
//!
//! HOW THE PEER IS RUN. Every invocation is bounded by its own deadline, with
//! stdout and stderr drained concurrently so neither pipe can wedge the other,
//! and the process GROUP killed on timeout. Only the direct child is reaped:
//! a descendant is not this process's child, so it cannot be waited on here --
//! it is killed and then observed gone, which is what the survivor check
//! establishes and all that is claimed. The outcome is
//! classified fail-closed: only a spawn failure or the peer's exact
//! `PEER_UNAVAILABLE` sentinel may be skipped when
//! `THEYOS_REQUIRE_NOISE_INTEROP` is unset. A timeout, a non-zero exit,
//! malformed output, or a negative the peer ACCEPTED are failures always --
//! otherwise a broken peer buys a green suite that proved nothing.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use mesh_session_core_rs::noise::{NOISE_PATTERN, prologue};
use snow::Builder;

/// The independent implementation this claim is made against.
///
/// PINNED, and part of the vector rather than tooling hygiene: with an
/// unpinned `--with noiseprotocol` a later run agrees with a *different*
/// implementation than the one the claim was measured against, and nothing in
/// the repository changes. Same constant, same reasoning, as the live half.
const PEER_NOISE_VERSION: &str = "0.3.1";

/// Ceiling for one peer invocation. Generous, because a cold runner resolves
/// and downloads `noiseprotocol` inside this window; the point is not speed
/// but that a wedged peer fails BOUNDED instead of consuming the job's own
/// timeout, taking every later test's evidence with it.
const PEER_DEADLINE: Duration = Duration::from_secs(180);

/// Stderr is drained in full (a pipe nobody reads is a deadlock) but only this
/// much is kept for diagnostics.
const STDERR_KEEP_BYTES: usize = 64 * 1024;

/// Fixed TEST keys. Deliberately recognisable so a leak into any non-test
/// artifact is obvious on sight, and never exported from this target.
const INITIATOR_STATIC: [u8; 32] = [0x11; 32];
const INITIATOR_EPHEMERAL: [u8; 32] = [0x22; 32];
const RESPONDER_STATIC: [u8; 32] = [0x33; 32];
const RESPONDER_EPHEMERAL: [u8; 32] = [0x44; 32];

/// The plaintexts whose first transport records are pinned, one per
/// direction, distinguishable so a swapped pair is a mismatch and not a
/// coincidence. The corpus repeats them and the corpus test proves the two
/// agree, so the peer script and this file cannot drift apart silently.
const RECORD_I2R_PLAINTEXT: &[u8] = b"m1a-i2r";
const RECORD_R2I_PLAINTEXT: &[u8] = b"m1a-r2i";

/// Repo-relative paths, as literals, so `include_bytes!` adds the same
/// dependency edge to Cargo's depfile that the live half relies on: touching
/// either file rebuilds this test rather than leaving it stale, and DELETING
/// either one fails the build instead of skipping quietly.
macro_rules! repo_test_file {
    ($path:literal) => {{
        const _: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../", $path));
        $path
    }};
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../")
}

fn peer_script() -> std::path::PathBuf {
    repo_root().join(repo_test_file!("scripts/noise-vectors-peer.py"))
}

fn corpus_path() -> std::path::PathBuf {
    repo_root().join(repo_test_file!(
        "admin/contracts/mesh-session/v1/m1a_noise_vectors_v1.json"
    ))
}

/// The transcript both implementations must agree on, and what the corpus
/// freezes. Hex throughout: the corpus is read by humans in review, and by a
/// Python peer that has no notion of Rust byte arrays.
#[derive(Debug, PartialEq, Eq)]
struct Transcript {
    prologue: String,
    flight1: String,
    flight2: String,
    flight3: String,
    handshake_hash: String,
    record_i2r: String,
    record_r2i: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Derive the transcript with `snow`, driving the 3 XX flights with the fixed
/// keys. This is the exporter: the corpus is its output, reviewed and frozen.
fn derive_with_snow() -> Transcript {
    let params = NOISE_PATTERN.parse().expect("production pattern parses");
    let prologue_bytes = prologue();

    let mut initiator = Builder::new(params)
        .local_private_key(&INITIATOR_STATIC)
        .expect("fixed initiator static key")
        .fixed_ephemeral_key_for_testing_only(&INITIATOR_EPHEMERAL)
        .prologue(&prologue_bytes)
        .expect("production prologue")
        .build_initiator()
        .expect("initiator builds");

    let params = NOISE_PATTERN.parse().expect("production pattern parses");
    let mut responder = Builder::new(params)
        .local_private_key(&RESPONDER_STATIC)
        .expect("fixed responder static key")
        .fixed_ephemeral_key_for_testing_only(&RESPONDER_EPHEMERAL)
        .prologue(&prologue_bytes)
        .expect("production prologue")
        .build_responder()
        .expect("responder builds");

    let mut buf = [0u8; 1024];
    let mut read_buf = [0u8; 1024];

    let n = initiator.write_message(&[], &mut buf).expect("flight 1");
    let flight1 = buf[..n].to_vec();
    responder
        .read_message(&flight1, &mut read_buf)
        .expect("responder reads flight 1");

    let n = responder.write_message(&[], &mut buf).expect("flight 2");
    let flight2 = buf[..n].to_vec();
    initiator
        .read_message(&flight2, &mut read_buf)
        .expect("initiator reads flight 2");

    let n = initiator.write_message(&[], &mut buf).expect("flight 3");
    let flight3 = buf[..n].to_vec();
    responder
        .read_message(&flight3, &mut read_buf)
        .expect("responder reads flight 3");

    assert!(initiator.is_handshake_finished(), "initiator finished");
    assert!(responder.is_handshake_finished(), "responder finished");

    // Captured BEFORE into_transport_mode consumes the handshake state, the
    // same ordering production depends on -- snow does not expose the hash
    // afterward.
    let handshake_hash = initiator.get_handshake_hash().to_vec();
    assert_eq!(
        handshake_hash,
        responder.get_handshake_hash(),
        "both ends must derive the same handshake hash"
    );
    assert_eq!(handshake_hash.len(), 32, "BLAKE2s digest size");

    let mut initiator = initiator
        .into_transport_mode()
        .expect("initiator transport mode");
    let mut responder = responder
        .into_transport_mode()
        .expect("responder transport mode");

    let n = initiator
        .write_message(RECORD_I2R_PLAINTEXT, &mut buf)
        .expect("first i2r record");
    let record_i2r = buf[..n].to_vec();
    let n = responder
        .write_message(RECORD_R2I_PLAINTEXT, &mut buf)
        .expect("first r2i record");
    let record_r2i = buf[..n].to_vec();

    Transcript {
        prologue: hex(&prologue_bytes),
        flight1: hex(&flight1),
        flight2: hex(&flight2),
        flight3: hex(&flight3),
        handshake_hash: hex(&handshake_hash),
        record_i2r: hex(&record_i2r),
        record_r2i: hex(&record_r2i),
    }
}

// ── the peer runner: bounded, drained, and fail-closed ────────────────────

/// What one bounded invocation produced.
///
/// The split is the whole point. `Unavailable` is the ONLY outcome a missing
/// toolchain may produce, and the only one that a run without
/// `THEYOS_REQUIRE_NOISE_INTEROP` is allowed to skip on. Everything else --
/// timeout, non-zero exit, malformed output, a negative the peer ACCEPTED --
/// is `Failed` and fails the test unconditionally, because those are evidence
/// about the claim rather than about the machine.
#[derive(Debug)]
enum PeerOutcome {
    Ok(Vec<String>),
    Unavailable(String),
    Failed(String),
}

/// The survivor probe's executable, pinned to an absolute path.
///
/// Resolving `pgrep` through `PATH` was fail-open, and was demonstrated so
/// against this file rather than argued: with a `pgrep` earlier in `PATH`
/// resolving to `/usr/bin/false`, the probe answered "nobody" for every group
/// -- exit 1, both streams empty -- and the survivor check went green in about
/// two seconds. A failure to look read as an absence.
///
/// Measured at this path on both platforms this suite runs on: macOS
/// (root:wheel, 0755) and Debian/procps. The pin does NOT authenticate the
/// binary; nothing in this file does. It selects the one in the rootfs
/// instead of whatever the environment resolves to. That is a real reduction
/// of authority under a premise this file states rather than proves -- that
/// the rootfs is trusted and not writable by the user running the test.
///
/// This pin is load-bearing on its own, and not merely defence in depth. The
/// two demonstrated substitutions are closed by DIFFERENT mechanisms:
///
///   /bin/ps          exit 1 WITH output   -> caught by the clean-no-match rule
///   /usr/bin/false   exit 1, both streams
///                    empty                -> passes that rule; caught ONLY here
///
/// So replacing this absolute path with a bare `"pgrep"` would reopen the
/// `/usr/bin/false` route silently, and the clean-no-match rule would not
/// notice. If this line is ever "simplified", that is the regression.
#[cfg(unix)]
const PGREP: &str = "/usr/bin/pgrep";

/// The pids currently in a process group, or a panic. Never a silent zero.
#[cfg(unix)]
fn probe_group(pgid: &str) -> Vec<u32> {
    let out = match Command::new(PGREP).arg("-g").arg(pgid).output() {
        Ok(out) => out,
        Err(e) => {
            panic!("the survivor probe ({PGREP}) could not run, so absence was never observed: {e}")
        }
    };
    let stdout = std::str::from_utf8(&out.stdout).unwrap_or_else(|e| {
        panic!("the survivor probe returned non-UTF-8 output; not counting it as zero: {e}")
    });
    let stderr = String::from_utf8_lossy(&out.stderr);
    match out.status.code() {
        // A clean no-match, and "clean" is load-bearing. Measured on both
        // platforms as exit 1 with BOTH streams empty, so both are required.
        // Exit 1 that says anything at all is a diagnostic, not an absence:
        // `/bin/ps -g <n>` produces exactly that shape -- status 1 with a
        // complaint on a stream -- and reading it as "nobody is there" is how
        // a binary that never answered the question gets to decide the
        // verdict.
        Some(1) if stdout.is_empty() && stderr.is_empty() => Vec::new(),
        Some(1) => panic!(
            "the survivor probe exited 1, which promises a CLEAN no-match, but wrote \
             {} byte(s) to stdout and {} to stderr; that is a diagnostic, not an \
             absence, and absence was not established. stdout: {stdout:?}; stderr: {:?}",
            out.stdout.len(),
            out.stderr.len(),
            stderr.trim()
        ),
        Some(0) => {
            let pids: Vec<u32> = stdout
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(|l| {
                    l.parse::<u32>().unwrap_or_else(|e| {
                        panic!("the survivor probe printed {l:?}, which is not a pid: {e}")
                    })
                })
                .collect();
            // Exit 0 is the promise that it matched at least one process.
            // Zero pids alongside it is a malformed answer, not an absence:
            // a stub that exits 0 and prints nothing would otherwise read as
            // a clean count of zero. Refuse it.
            assert!(
                !pids.is_empty(),
                "the survivor probe exited 0, which promises a match, but printed no \
                 pid; that is a malformed answer and absence was not established"
            );
            pids
        }
        other => panic!(
            "the survivor probe exited with {other:?}, which is neither a match nor a \
             clean no-match; absence was not established. stderr: {}",
            stderr.trim()
        ),
    }
}

/// How many processes are still in a process group, or a panic.
#[cfg(unix)]
fn process_group_members(pgid: &str) -> usize {
    probe_group(pgid).len()
}

/// A live process alone in a process group of its own, so the probe can be
/// asked a question whose answer is known while it answers one whose answer is
/// not.
///
/// `Drop` kills and reaps it, because every check around it panics on failure
/// and a panic must not leave a sleeper behind.
#[cfg(unix)]
struct Sentinel {
    child: std::process::Child,
}

#[cfg(unix)]
impl Sentinel {
    /// No shell, so the group holds EXACTLY this one process and the expected
    /// answer is a one-element set rather than "at least one".
    fn spawn() -> Sentinel {
        use std::os::unix::process::CommandExt;
        let child = Command::new("/bin/sleep")
            .arg("120")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("the sentinel spawns");
        Sentinel { child }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The control is only worth its answer while its subject is alive.
    fn assert_alive(&mut self) {
        match self.child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => panic!(
                "the sentinel exited ({status}) before it could be observed, so the \
                 control established nothing"
            ),
            Err(e) => panic!("could not tell whether the sentinel is alive: {e}"),
        }
    }

    /// The probe must see this group as EXACTLY this pid.
    ///
    /// `>= 1` would be satisfied by a program that ignores `-g` and lists
    /// every process on the machine -- the shape that looks capable while
    /// being unable to answer the question actually asked.
    fn assert_probe_sees_exactly_me(&self) {
        let seen = probe_group(&self.pid().to_string());
        assert_eq!(
            seen,
            vec![self.pid()],
            "the probe must see the sentinel's group as exactly its own pid; \
             it saw {seen:?}, so its answers about any other group are not evidence"
        );
    }
}

#[cfg(unix)]
impl Drop for Sentinel {
    fn drop(&mut self) {
        kill_process_group(self.child.id());
        // The group kill's exit status is deliberately tolerated, so it cannot
        // be the only thing between a panicking assertion and a `wait` that
        // blocks for the sentinel's full 120s. The direct child is reachable
        // without it, and killing it twice is harmless -- the same belt the
        // bounded runner already wears.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Believe an absence only from a probe that answered a KNOWN question
/// correctly on both sides of the unknown one.
///
/// What this closes: accidental substitution of the executable, a program that
/// ignores `-g`, and a transient failure that happens to land on the single
/// query that matters. What it does NOT close, stated because a control that
/// oversells itself is the same defect one level up: a binary that
/// discriminates by argument -- answering truthfully about the sentinel and
/// falsely about the target -- is not distinguished by any number of samples.
/// No single black box establishes its own identity. That would need a hash or
/// no `pgrep` at all, and that is a larger predicate than this file.
#[cfg(unix)]
fn assert_group_is_absent(target_pgid: &str, why: &str) {
    let mut sentinel = Sentinel::spawn();
    // Pid reuse: if the sentinel landed on the very group being proven empty,
    // the control would REPOPULATE it and manufacture a false red. The old
    // sentinel is still alive while the replacement spawns, so it cannot hand
    // its own pid back.
    let mut attempts = 0;
    while sentinel.pid().to_string() == target_pgid {
        attempts += 1;
        assert!(
            attempts < 8,
            "the sentinel kept landing on the target group {target_pgid}"
        );
        sentinel = Sentinel::spawn();
    }

    sentinel.assert_alive();
    sentinel.assert_probe_sees_exactly_me();

    let survivors = probe_group(target_pgid);

    sentinel.assert_alive();
    sentinel.assert_probe_sees_exactly_me();

    assert!(
        survivors.is_empty(),
        "{why}; the probe still sees {survivors:?} in group {target_pgid}"
    );
}

/// Kill a process GROUP by the leader's pid, as a callable contract.
///
/// Lifted out of `run_command_bounded` so the contract can be exercised
/// directly: the composite state its own call sites reach -- child gone,
/// reader timed out, group already empty -- cannot be produced on demand,
/// but the contract can, against a group proven absent beforehand.
#[cfg(unix)]
fn kill_process_group(pid: u32) {
    // `--` is load-bearing, not tidiness. A negative pid means "the process
    // group" to kill(2), but the argument still has to reach the target
    // list: procps-ng takes a bare `-1234` as an option bundle, kills
    // nothing, prints nothing, and exits 0. BSD kill accepts it either way,
    // which is why this read as working on one platform while doing nothing
    // on the other. Measured on both, with a group id that cannot exist:
    //
    //   procps-ng 4.0.4   `-KILL -99999`      silent, exit 0
    //                     `-KILL -- -99999`   "No such process"
    //   BSD               both forms          "No such process"
    //
    // Note what this cost: the failure had no observable. Exit status was
    // 0 and stderr was empty, so checking either would have proved nothing.
    // Only a test that looks for the survivor can see it.
    // Spawning is fatal; the exit status deliberately is not.
    //
    // A missing binary means the kill never happened and nothing else here
    // would notice, so that fails closed. The status cannot carry the same
    // weight. `kill` exits 1 when the group is already gone -- a legitimate,
    // expected outcome at several of this function's call sites, not a
    // failure: the one that runs after the child has already exited and been
    // reaped, the control that deliberately kills a group proven empty, and
    // the sentinel cleanup, which runs whether or not the sentinel is still
    // there. It also exits 1 on a genuine failure, and neither platform
    // distinguishes the two by code, so a non-zero rule would convert a
    // routine state into a flake.
    //
    // It would also buy nothing: the defect this replaced exited ZERO --
    // `-1234` read as an option bundle killed nothing and reported success.
    // No status rule could have caught it.
    //
    // So the status is recorded for diagnosis and the verdict is left where
    // it can be established: the survivor probe below.
    let out = Command::new("/bin/kill")
        .arg("-KILL")
        .arg("--")
        .arg(format!("-{pid}"))
        .output()
        .unwrap_or_else(|e| panic!("the group kill could not run, so it did not happen: {e}"));
    if !out.status.success() {
        eprintln!(
            "note: group kill for {pid} exited {:?} ({}); expected when the group is \
             already empty. The survivor check is the verdict.",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
}

/// Run a command bounded by `deadline`, feeding `stdin_payload`, draining
/// stdout AND stderr concurrently, and on timeout killing the process GROUP
/// and reaping the direct child.
///
/// Only the DIRECT child is reaped. A descendant is not this process's child,
/// so it cannot be waited on here: it is killed and then observed gone by the
/// survivor probe. That is the weaker claim, and it is the true one.
///
/// Two pipes and one reader is a deadlock waiting for a verbose child: the
/// child blocks writing stderr while we block reading stdout. Each pipe
/// therefore gets its own thread. The group (not just the child) is killed
/// because the child is `uv`, which runs the interpreter as a further child;
/// killing only the handle we hold leaves the interpreter alive holding the
/// pipes open.
fn run_command_bounded(
    program: &str,
    args: &[String],
    stdin_payload: &str,
    deadline: Duration,
) -> PeerOutcome {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        // A missing toolchain is the one legitimate "this machine cannot run
        // the claim" -- and even that is fatal under REQUIRE.
        Err(e) => return PeerOutcome::Unavailable(format!("`{program}` could not be spawned: {e}")),
    };
    let pid = child.id();

    let kill_group = || kill_process_group(pid);

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(stdin_payload.as_bytes());
        // Dropped here: the peer's readline returns instead of waiting for
        // input that will never come.
    }

    let (out_tx, out_rx) = mpsc::channel();
    let stdout = child.stdout.take().expect("stdout is piped");
    std::thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) => lines.push(line),
                Err(_) => break,
            }
        }
        let _ = out_tx.send(lines);
    });

    let (err_tx, err_rx) = mpsc::channel();
    let stderr = child.stderr.take().expect("stderr is piped");
    std::thread::spawn(move || {
        // Drain everything (an unread pipe wedges the child) but keep a bound.
        let mut kept = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut reader = stderr;
        while let Ok(n) = reader.read(&mut chunk) {
            if n == 0 {
                break;
            }
            if kept.len() < STDERR_KEEP_BYTES {
                let room = STDERR_KEEP_BYTES - kept.len();
                kept.extend_from_slice(&chunk[..n.min(room)]);
            }
        }
        let _ = err_tx.send(String::from_utf8_lossy(&kept).into_owned());
    });

    // Poll for exit rather than blocking, so the deadline is enforceable.
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started.elapsed() >= deadline {
                    kill_group();
                    let _ = child.kill();
                    let _ = child.wait();
                    return PeerOutcome::Failed(format!(
                        "the peer did not finish within {deadline:?}; killed process group {pid}"
                    ));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                kill_group();
                return PeerOutcome::Failed(format!("could not wait for the peer: {e}"));
            }
        }
    };

    // The pipes close when the child exits, so the readers finish promptly;
    // the small grace is only for scheduling, and expiring it is a failure
    // rather than a silent empty result.
    let grace = Duration::from_secs(10);
    let lines = match out_rx.recv_timeout(grace) {
        Ok(lines) => lines,
        Err(_) => {
            kill_group();
            return PeerOutcome::Failed("the peer's stdout reader did not finish".into());
        }
    };
    let stderr_text = err_rx.recv_timeout(grace).unwrap_or_default();

    // The EXACT sentinel, as a whole first token: `PEER_UNAVAILABLE_BOGUS` is
    // a different word and must not buy a skip.
    if let Some(line) = lines
        .iter()
        .find(|l| l.split_whitespace().next() == Some("PEER_UNAVAILABLE"))
    {
        return PeerOutcome::Unavailable(line.clone());
    }

    if !status.success() {
        return PeerOutcome::Failed(format!(
            "the peer exited unsuccessfully ({status}); stdout: {lines:?}; stderr: {}",
            stderr_text.trim()
        ));
    }
    PeerOutcome::Ok(lines)
}

fn peer_stdin_keys() -> String {
    format!(
        "{} {} {} {}\n",
        hex(&INITIATOR_STATIC),
        hex(&INITIATOR_EPHEMERAL),
        hex(&RESPONDER_STATIC),
        hex(&RESPONDER_EPHEMERAL),
    )
}

fn run_peer(extra_args: &[&str]) -> PeerOutcome {
    let mut args = vec![
        "run".to_string(),
        "--with".to_string(),
        format!("noiseprotocol=={PEER_NOISE_VERSION}"),
        "python".to_string(),
        peer_script().to_string_lossy().into_owned(),
    ];
    args.extend(extra_args.iter().map(|a| a.to_string()));
    run_command_bounded("uv", &args, &peer_stdin_keys(), PEER_DEADLINE)
}

/// Resolve an outcome into the lines, or end the test.
///
/// `Failed` panics regardless of the environment. `Unavailable` panics under
/// `THEYOS_REQUIRE_NOISE_INTEROP` and skips otherwise -- the only skip in this
/// file, and CI sets that variable, so the skip cannot reach a gated run.
fn lines_or_skip(outcome: PeerOutcome, test: &str) -> Option<Vec<String>> {
    match outcome {
        PeerOutcome::Ok(lines) => Some(lines),
        PeerOutcome::Failed(reason) => panic!("{test}: the peer failed: {reason}"),
        PeerOutcome::Unavailable(reason) => {
            assert!(
                std::env::var_os("THEYOS_REQUIRE_NOISE_INTEROP").is_none(),
                "THEYOS_REQUIRE_NOISE_INTEROP is set but the peer is unavailable: {reason}"
            );
            eprintln!("SKIP {test}: {reason}");
            None
        }
    }
}

fn field<'a>(lines: &'a [String], prefix: &str) -> &'a str {
    lines
        .iter()
        .find_map(|l| l.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("the peer printed no {prefix} line; got: {lines:?}"))
        .trim()
}

// ── D: the independent implementation reproduces the transcript ───────────

#[test]
fn an_independent_implementation_reproduces_the_vectors() {
    let ours = derive_with_snow();

    let Some(lines) = lines_or_skip(
        run_peer(&[]),
        "an_independent_implementation_reproduces_the_vectors",
    ) else {
        return;
    };

    // Token equality, not `contains`: `contains("noiseprotocol=0.3.1")` is also
    // true of "0.3.10", and the comparand's identity is the claim.
    let versions = lines
        .iter()
        .find(|l| l.starts_with("PEER_VERSIONS "))
        .unwrap_or_else(|| panic!("no PEER_VERSIONS line; got: {lines:?}"));
    let expected = format!("noiseprotocol={PEER_NOISE_VERSION}");
    assert!(
        versions.split_whitespace().any(|t| t == expected),
        "the peer must be exactly {expected}; it reported: {versions}"
    );

    // VECTORS_OK is a terminator: without it a peer killed mid-transcript
    // would look like a short but well-formed answer.
    assert!(
        lines.iter().any(|l| l == "VECTORS_OK"),
        "the peer did not finish the transcript; got: {lines:?}"
    );

    assert_eq!(field(&lines, "FLIGHT1 "), ours.flight1, "flight 1 differs");
    assert_eq!(field(&lines, "FLIGHT2 "), ours.flight2, "flight 2 differs");
    assert_eq!(field(&lines, "FLIGHT3 "), ours.flight3, "flight 3 differs");
    assert_eq!(
        field(&lines, "HANDSHAKE_HASH "),
        ours.handshake_hash,
        "handshake hash differs -- the two implementations do not agree"
    );
    assert_eq!(
        field(&lines, "RECORD_I2R "),
        ours.record_i2r,
        "first initiator->responder record differs"
    );
    assert_eq!(
        field(&lines, "RECORD_R2I "),
        ours.record_r2i,
        "first responder->initiator record differs"
    );

    eprintln!("interop peer: noiseprotocol={PEER_NOISE_VERSION} (deterministic vectors)");
}

// ── C: the frozen corpus, checked exhaustively ────────────────────────────

/// Parse the corpus strictly: every content line must be exactly one
/// `"key": "value"` pair, and a duplicate key is an error rather than a
/// last-one-wins overwrite.
///
/// Strict because the failure this replaces was a lookup that simply did not
/// find what it wanted and passed anyway: a mutated `snow_version` and a
/// falsified plaintext both survived. A parse that rejects what it does not
/// understand, plus an exhaustive key set, turns "not found" into RED.
fn parse_corpus(raw: &str) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "{" || trimmed == "}" {
            continue;
        }
        let body = trimmed.strip_suffix(',').unwrap_or(trimmed);
        let (key, value) = body
            .split_once(": ")
            .unwrap_or_else(|| panic!("corpus line {} is not a `\"key\": \"value\"` pair: {trimmed}", i + 1));
        let key = key
            .strip_prefix('"')
            .and_then(|k| k.strip_suffix('"'))
            .unwrap_or_else(|| panic!("corpus line {} has an unquoted key: {trimmed}", i + 1));
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or_else(|| panic!("corpus line {} has an unquoted value: {trimmed}", i + 1));
        assert!(
            !fields.iter().any(|(k, _)| k == key),
            "corpus key {key} appears more than once; a duplicate would let the last one win"
        );
        fields.push((key.to_string(), value.to_string()));
    }
    fields
}

/// The `snow` version actually resolved for THIS crate, read from its own
/// lockfile -- so the corpus's pin is proven against the build rather than
/// against a copy of itself.
fn snow_version_from_lockfile() -> String {
    let lock = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"),
    )
    .expect("this crate has its own Cargo.lock");
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line.trim() == "name = \"snow\"" {
            for next in lines.by_ref() {
                if let Some(v) = next.trim().strip_prefix("version = ") {
                    return v.trim_matches('"').to_string();
                }
                if next.trim().starts_with("[[package]]") {
                    break;
                }
            }
        }
    }
    panic!("Cargo.lock has no snow package");
}

#[test]
fn regenerating_matches_the_frozen_corpus() {
    let ours = derive_with_snow();
    let raw = std::fs::read_to_string(corpus_path()).expect("the frozen corpus is committed");
    let fields = parse_corpus(&raw);

    let get = |key: &str| -> &str {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("the corpus has no {key} field"))
    };

    // EXHAUSTIVE: every expected key present, and no unexpected key. A renamed
    // or dropped field is RED here instead of being quietly skipped, and a new
    // one has to be classified rather than ignored.
    let expected_keys = [
        "about",
        "provenance",
        "authority_status",
        "scope",
        "pattern",
        "peer_noise_version",
        "snow_version",
        "keys_are_test_only",
        "initiator_static",
        "initiator_ephemeral",
        "responder_static",
        "responder_ephemeral",
        "record_i2r_plaintext",
        "record_r2i_plaintext",
        "prologue",
        "flight1",
        "flight2",
        "flight3",
        "handshake_hash",
        "record_i2r",
        "record_r2i",
        "negatives",
    ];
    let mut present: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
    present.sort_unstable();
    let mut want: Vec<&str> = expected_keys.to_vec();
    want.sort_unstable();
    assert_eq!(
        present, want,
        "the corpus key set changed; classify the difference instead of letting a lookup miss it"
    );

    // The transcript itself.
    assert_eq!(get("prologue"), ours.prologue, "prologue drifted");
    assert_eq!(get("flight1"), ours.flight1, "flight 1 drifted");
    assert_eq!(get("flight2"), ours.flight2, "flight 2 drifted");
    assert_eq!(get("flight3"), ours.flight3, "flight 3 drifted");
    assert_eq!(
        get("handshake_hash"),
        ours.handshake_hash,
        "handshake hash drifted"
    );
    assert_eq!(get("record_i2r"), ours.record_i2r, "i2r record drifted");
    assert_eq!(get("record_r2i"), ours.record_r2i, "r2i record drifted");

    // The inputs that produced it, so a key change cannot keep old bytes.
    assert_eq!(get("initiator_static"), hex(&INITIATOR_STATIC));
    assert_eq!(get("initiator_ephemeral"), hex(&INITIATOR_EPHEMERAL));
    assert_eq!(get("responder_static"), hex(&RESPONDER_STATIC));
    assert_eq!(get("responder_ephemeral"), hex(&RESPONDER_EPHEMERAL));
    assert_eq!(
        get("record_i2r_plaintext").as_bytes(),
        RECORD_I2R_PLAINTEXT,
        "the corpus and this test disagree on the i2r plaintext"
    );
    assert_eq!(
        get("record_r2i_plaintext").as_bytes(),
        RECORD_R2I_PLAINTEXT,
        "the corpus and this test disagree on the r2i plaintext"
    );

    // The pins, each proven against its real source rather than against a copy
    // of itself: the pattern against production, the peer against this file's
    // constant, and `snow` against the crate's own lockfile.
    assert_eq!(get("pattern"), NOISE_PATTERN, "pattern drifted");
    assert_eq!(get("peer_noise_version"), PEER_NOISE_VERSION);
    assert_eq!(
        get("snow_version"),
        snow_version_from_lockfile(),
        "the corpus's snow pin does not match the version this crate actually resolves"
    );

    // Identity fields: the corpus must keep saying what it is, so it cannot be
    // quietly promoted to an authority it is not.
    assert_eq!(get("authority_status"), "synthetic-test-only-non-authoritative");
    assert_eq!(get("scope"), "cross-language-handshake-witness");
    for prose in ["about", "provenance", "keys_are_test_only", "negatives"] {
        assert!(
            !get(prose).trim().is_empty(),
            "the corpus's {prose} note must not be emptied"
        );
    }
}

// ── E: every negative is refused, on BOTH sides, by category ──────────────

/// Our own implementation's refusal, as a stable class. snow's error *text*
/// varies by version; the class is the claim.
fn snow_refusal_category(e: &snow::Error) -> &'static str {
    match e {
        snow::Error::Decrypt => "decrypt",
        _ => "handshake",
    }
}

/// Drive the two ends up to flight 2, then hand the caller the pieces a
/// negative needs to corrupt.
fn handshake_through_flight2() -> (snow::HandshakeState, Vec<u8>, Vec<u8>) {
    let params = NOISE_PATTERN.parse().expect("pattern");
    let prologue_bytes = prologue();
    let mut initiator = Builder::new(params)
        .local_private_key(&INITIATOR_STATIC)
        .expect("static")
        .fixed_ephemeral_key_for_testing_only(&INITIATOR_EPHEMERAL)
        .prologue(&prologue_bytes)
        .expect("prologue")
        .build_initiator()
        .expect("initiator");

    let params = NOISE_PATTERN.parse().expect("pattern");
    let mut responder = Builder::new(params)
        .local_private_key(&RESPONDER_STATIC)
        .expect("static")
        .fixed_ephemeral_key_for_testing_only(&RESPONDER_EPHEMERAL)
        .prologue(&prologue_bytes)
        .expect("prologue")
        .build_responder()
        .expect("responder");

    let mut buf = [0u8; 1024];
    let mut read_buf = [0u8; 1024];
    let n = initiator.write_message(&[], &mut buf).expect("flight 1");
    let flight1 = buf[..n].to_vec();
    responder
        .read_message(&flight1, &mut read_buf)
        .expect("responder reads flight 1");
    let n = responder.write_message(&[], &mut buf).expect("flight 2");
    let flight2 = buf[..n].to_vec();
    (initiator, flight1, flight2)
}

#[test]
fn our_own_implementation_refuses_every_negative() {
    let mut read_buf = [0u8; 1024];
    let mut buf = [0u8; 1024];

    // bitflip: one bit of flight 2's AEAD tag.
    let (mut initiator, _f1, flight2) = handshake_through_flight2();
    let mut corrupted = flight2.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0x01;
    let err = initiator
        .read_message(&corrupted, &mut read_buf)
        .expect_err("a flipped bit must be refused");
    assert_eq!(snow_refusal_category(&err), "decrypt", "bitflip category");

    // replay: flight 1 replayed where flight 2 belongs.
    //
    // MEASURED, and the two implementations differ here in a way that is
    // correct on both sides: `snow` refuses this at the state machine
    // (category `handshake`) because a replayed flight 1 is the wrong LENGTH
    // for the flight 2 it arrives as, so it never reaches decryption; the
    // Python peer gets as far as the AEAD tag and refuses with `decrypt`.
    // Both refuse; the categories are pinned per implementation rather than
    // forced equal, because forcing them equal would assert a property of the
    // implementations that is not true and would break on either's internals.
    let (mut initiator, flight1, _f2) = handshake_through_flight2();
    let err = initiator
        .read_message(&flight1, &mut read_buf)
        .expect_err("a replayed flight must be refused");
    assert_eq!(snow_refusal_category(&err), "handshake", "replay category");

    // reorder: flight 3 delivered where flight 2 belongs. Built by running a
    // full handshake to obtain a real flight 3, then feeding it to a fresh
    // initiator that has only sent flight 1. Same measured split as `replay`:
    // `snow` refuses at the state machine, the Python peer at the AEAD tag.
    let (mut initiator, _f1, flight2) = handshake_through_flight2();
    initiator
        .read_message(&flight2, &mut read_buf)
        .expect("initiator reads flight 2");
    let n = initiator.write_message(&[], &mut buf).expect("flight 3");
    let flight3 = buf[..n].to_vec();
    let (mut fresh_initiator, _f1, _f2) = handshake_through_flight2();
    let err = fresh_initiator
        .read_message(&flight3, &mut read_buf)
        .expect_err("an out-of-order flight must be refused");
    assert_eq!(snow_refusal_category(&err), "handshake", "reorder category");

    // prologue: a responder under a different prologue. Refused at flight 2 --
    // XX's first message carries no authenticated material, so the divergence
    // is invisible until the first AEAD tag over the handshake hash.
    let params = NOISE_PATTERN.parse().expect("pattern");
    let prologue_bytes = prologue();
    let mut other = prologue_bytes.clone();
    other.push(b'!');
    let mut initiator = Builder::new(params)
        .local_private_key(&INITIATOR_STATIC)
        .expect("static")
        .fixed_ephemeral_key_for_testing_only(&INITIATOR_EPHEMERAL)
        .prologue(&prologue_bytes)
        .expect("prologue")
        .build_initiator()
        .expect("initiator");
    let params = NOISE_PATTERN.parse().expect("pattern");
    let mut responder = Builder::new(params)
        .local_private_key(&RESPONDER_STATIC)
        .expect("static")
        .fixed_ephemeral_key_for_testing_only(&RESPONDER_EPHEMERAL)
        .prologue(&other)
        .expect("prologue")
        .build_responder()
        .expect("responder");
    let n = initiator.write_message(&[], &mut buf).expect("flight 1");
    let flight1 = buf[..n].to_vec();
    responder
        .read_message(&flight1, &mut read_buf)
        .expect("flight 1 carries no authenticated material");
    let n = responder.write_message(&[], &mut buf).expect("flight 2");
    let flight2 = buf[..n].to_vec();
    let err = initiator
        .read_message(&flight2, &mut read_buf)
        .expect_err("a mismatched prologue must be refused");
    assert_eq!(snow_refusal_category(&err), "decrypt", "prologue category");
}

#[test]
fn the_independent_implementation_refuses_every_negative() {
    for kind in ["bitflip", "replay", "reorder", "prologue"] {
        let Some(lines) = lines_or_skip(
            run_peer(&["--negative", kind]),
            "the_independent_implementation_refuses_every_negative",
        ) else {
            return;
        };
        let verdict = lines
            .iter()
            .find(|l| l.starts_with("NEGATIVE "))
            .unwrap_or_else(|| panic!("the peer printed no NEGATIVE line for {kind}: {lines:?}"));
        assert_eq!(
            verdict,
            &format!("NEGATIVE {kind} REFUSED decrypt"),
            "the independent implementation must refuse {kind} by category"
        );
    }
}

// ── the runner's own guarantees, proven rather than asserted ──────────────

/// A hung child fails BOUNDED and leaves nothing behind.
///
/// Without this the runner read stdout to EOF before waiting, so a wedged
/// peer held the test until the job's own timeout and took every later test's
/// evidence with it. Driven with a synthetic sleeper rather than the real
/// peer: the claim is about the runner.
#[test]
#[cfg(unix)]
fn a_hung_child_fails_bounded_and_leaks_nothing() {
    // The child deliberately leaves a DESCENDANT in its process group, and the
    // shell then `exec`s so the direct child is a sleeper too. Both halves
    // matter: `child.kill()` reaches only the direct child, so without a
    // descendant nothing here can distinguish killing the child from killing
    // the GROUP, and the claim in this test's name would be untestable. With
    // `exec`, the arrangement is the same on platforms whose `sh` execs a lone
    // command and on those whose `sh` forks -- measured as two group members on
    // both.
    let marker = std::env::temp_dir().join(format!("m1a-descendant-{}.pid", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let started = Instant::now();
    let outcome = run_command_bounded(
        "/bin/sh",
        &[
            "-c".to_string(),
            format!(
                "sleep 120 & printf %s \"$!\" > {} ; exec sleep 120",
                marker.display()
            ),
        ],
        "",
        Duration::from_secs(2),
    );
    let elapsed = started.elapsed();

    // Deterministic proof that the descendant existed BEFORE the kill. Without
    // it a slow spawn would leave one process in the group, the survivor check
    // would pass, and the pass would mean nothing: the group-kill claim would
    // be satisfied vacuously by an arrangement that never arose.
    let descendant = std::fs::read_to_string(&marker).unwrap_or_default();
    let _ = std::fs::remove_file(&marker);
    assert!(
        descendant.trim().parse::<u32>().is_ok(),
        "setup failure, not a runner result: the child never recorded its \
         descendant, so this run could not have exercised the group kill; got {descendant:?}"
    );

    let reason = match outcome {
        PeerOutcome::Failed(reason) => {
            assert!(
                reason.contains("did not finish"),
                "a timeout must say so; got: {reason}"
            );
            reason
        }
        other => panic!("a hung child must be Failed, never skippable; got: {other:?}"),
    };
    assert!(
        elapsed < Duration::from_secs(30),
        "the deadline must bound the wait; took {elapsed:?}"
    );

    // Nothing survives, checked by process GROUP id rather than by command
    // name: `pgrep -f 'sleep 120'` would also match an unrelated sleeper
    // belonging to someone else on the machine, which is both a false failure
    // and, worse, a false pass if our own survivor were miscounted among them.
    // The group id is exact and ours alone.
    let pgid = reason
        .rsplit_once("process group ")
        .map(|(_, id)| id.trim().to_string())
        .expect("the timeout message carries the process group it killed");
    // The probe that establishes "no survivor" must not be able to report
    // absence when what happened was a failure to look. `pgrep -g N | wc -l`
    // could: with no pipefail a missing or erroring `pgrep` still leaves `wc`
    // printing 0 and the shell exiting 0, and a lenient parse turned any
    // unexpected output into 0 as well. Both routes end at "zero survivors",
    // which is the one answer this test must never produce by accident.
    //
    // So: no shell, no pipeline, and every outcome named. `pgrep` exits 0 when
    // it matched (pids on stdout, one per line), 1 when nothing matched, and
    // 2 or 3 on syntax or fatal errors. Anything that is not a clean match or a
    // clean no-match -- failing to spawn, an unexpected status, output that is
    // not a list of pids -- panics rather than counting as zero.
    //
    // Naming the outcomes was not enough, and the correction is worth keeping
    // because the first fix looked complete. Closing the exit-0 route left the
    // exit-1 route wide: `Command::new("pgrep")` resolves through `PATH`, and
    // exit 1 was read as "nobody" without establishing WHO answered. A `pgrep`
    // resolving to `/usr/bin/false` reported every group empty and this test
    // passed; `/bin/ps` exited 1 while printing a complaint, and it passed
    // too. Hence the pinned path, the requirement that a no-match be silent on
    // BOTH streams, and -- because neither of those makes the binary prove
    // itself -- the sentinel sandwich in `assert_group_is_absent`.
    let members = process_group_members;

    // Sampled until it converges, not once. A single sample cannot distinguish
    // a process that is on its way out from one that is staying: both read as a
    // non-zero count at that instant, and which one you get depends on
    // scheduling. That ambiguity is the defect -- not any particular story
    // about why a given run saw a straggler.
    //
    // Convergence resolves it, with a bound a real survivor cannot slip
    // through: this group was told to sleep for 120s, so anything still there
    // after seconds is staying. If the group kill failed, the count never
    // reaches zero and the assertion below fails with the time it waited.
    let converge_by = Duration::from_secs(10);
    let waited_from = Instant::now();
    let mut count = members(&pgid);
    while count != 0 && waited_from.elapsed() < converge_by {
        std::thread::sleep(Duration::from_millis(50));
        count = members(&pgid);
    }
    // The verdict is not the loop's last sample. Convergence answers "is it
    // gone", but a probe that cannot see anything converges to zero
    // immediately and answers it wrongly, which is exactly what a `PATH`
    // substitution produced here. So the zero is re-established through the
    // sentinel sandwich, which requires the probe to get a known answer right
    // on both sides of this one.
    assert_group_is_absent(
        &pgid,
        &format!(
            "the killed process group {pgid} must leave no survivor after {:?}, \
             so this is a survivor and not a straggler",
            waited_from.elapsed()
        ),
    );
}

/// The group kill's contract, exercised directly against a group proven empty.
///
/// The state its own call sites reach -- child exited, reader timed out, group
/// already empty -- cannot be produced on demand: for the reader to time out
/// something must still hold the pipe, and that something is a live descendant,
/// which means the group is not empty. So the composite is not fabricated. What
/// is exercised is the contract that matters there: killing a group that is
/// already gone must return, not fail.
///
/// Absence is established ONLY through `assert_group_is_absent`, so this
/// control cannot pass by failing to look: the probe has to answer a question
/// whose answer is known, on both sides of the one whose answer is not. That
/// is the same property the probe exists to give the survivor check, and this
/// control would be worthless without it -- a probe that sees nothing would
/// otherwise hand it a free "the group is empty" and let it exercise the kill
/// against a group it never established anything about.
#[test]
#[cfg(unix)]
fn killing_an_already_empty_group_is_not_a_failure() {
    use std::os::unix::process::CommandExt;

    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .expect("the short-lived child spawns");
    let pgid = child.id().to_string();
    child.wait().expect("the child is reaped");

    let converge_by = Duration::from_secs(10);
    let waited_from = Instant::now();
    let mut n = process_group_members(&pgid);
    while n != 0 && waited_from.elapsed() < converge_by {
        std::thread::sleep(Duration::from_millis(50));
        n = process_group_members(&pgid);
    }
    assert_group_is_absent(
        &pgid,
        &format!(
            "this control requires an EMPTY group before it exercises anything, \
             and group {pgid} is not empty after {:?}",
            waited_from.elapsed()
        ),
    );

    // The contract. A status rule here would panic on the ESRCH this group is
    // guaranteed to produce, which is precisely the flake this control pins.
    kill_process_group(pgid.parse().expect("the pgid is numeric"));
}

/// A child that floods stderr still completes: both pipes are drained
/// concurrently, so neither can wedge the other.
#[test]
#[cfg(unix)]
fn a_stderr_flood_does_not_wedge_the_runner() {
    let outcome = run_command_bounded(
        "/bin/sh",
        &[
            "-c".to_string(),
            "head -c 4000000 /dev/zero | tr '\\0' 'x' >&2; echo DONE".to_string(),
        ],
        "",
        Duration::from_secs(60),
    );
    match outcome {
        PeerOutcome::Ok(lines) => assert!(
            lines.iter().any(|l| l == "DONE"),
            "stdout must survive a stderr flood; got: {lines:?}"
        ),
        other => panic!("a stderr flood must not fail the run; got: {other:?}"),
    }
}

/// Peer failures are never skippable, and the sentinel is exact.
///
/// Each row is a way the old classifier bought green: any non-zero exit became
/// `Unavailable`, so a negative the peer ACCEPTED, a protocol error, or a
/// syntax error all skipped when `THEYOS_REQUIRE_NOISE_INTEROP` was unset.
#[test]
#[cfg(unix)]
fn only_a_genuinely_unavailable_toolchain_is_skippable() {
    // A negative the peer ACCEPTED: the loudest possible finding.
    let accepted = run_command_bounded(
        "/bin/sh",
        &[
            "-c".to_string(),
            "echo 'NEGATIVE bitflip ACCEPTED'; exit 5".to_string(),
        ],
        "",
        Duration::from_secs(30),
    );
    assert!(
        matches!(accepted, PeerOutcome::Failed(_)),
        "an accepted negative must fail, never skip; got: {accepted:?}"
    );

    // A protocol/usage error.
    let protocol = run_command_bounded(
        "/bin/sh",
        &[
            "-c".to_string(),
            "echo 'PEER_ERROR keys must be hex'; exit 2".to_string(),
        ],
        "",
        Duration::from_secs(30),
    );
    assert!(
        matches!(protocol, PeerOutcome::Failed(_)),
        "a protocol error must fail, never skip; got: {protocol:?}"
    );

    // A NEAR MISS of the sentinel must not buy a skip.
    let near_miss = run_command_bounded(
        "/bin/sh",
        &[
            "-c".to_string(),
            "echo 'PEER_UNAVAILABLE_BOGUS pretending'; exit 3".to_string(),
        ],
        "",
        Duration::from_secs(30),
    );
    assert!(
        matches!(near_miss, PeerOutcome::Failed(_)),
        "only the exact PEER_UNAVAILABLE token may be unavailable; got: {near_miss:?}"
    );

    // The real sentinel, which the peer prints when `noiseprotocol` is absent.
    let sentinel = run_command_bounded(
        "/bin/sh",
        &[
            "-c".to_string(),
            "echo 'PEER_UNAVAILABLE noiseprotocol is not installed'; exit 3".to_string(),
        ],
        "",
        Duration::from_secs(30),
    );
    assert!(
        matches!(sentinel, PeerOutcome::Unavailable(_)),
        "the exact sentinel is the one legitimate unavailable; got: {sentinel:?}"
    );

    // A missing program is the other one.
    let missing = run_command_bounded(
        "/definitely/not/a/program",
        &[],
        "",
        Duration::from_secs(30),
    );
    assert!(
        matches!(missing, PeerOutcome::Unavailable(_)),
        "a missing toolchain is unavailable; got: {missing:?}"
    );

    // And under REQUIRE even that is fatal -- asserted on the resolver, which
    // is what CI actually exercises.
    if std::env::var_os("THEYOS_REQUIRE_NOISE_INTEROP").is_some() {
        let resolved = std::panic::catch_unwind(|| {
            lines_or_skip(
                PeerOutcome::Unavailable("synthetic".into()),
                "only_a_genuinely_unavailable_toolchain_is_skippable",
            )
        });
        assert!(
            resolved.is_err(),
            "under THEYOS_REQUIRE_NOISE_INTEROP an unavailable peer must fail"
        );
    }
}

// ── B: the prohibition, mechanized ────────────────────────────────────────

#[test]
fn no_literal_seam_reference_outside_the_allowlisted_mention() {
    // The seam's identifier, assembled at runtime.
    //
    // What keeps this test from flagging itself is SCOPE, not spelling: the
    // scan walks src/ only, and this file lives in tests/. It does contain the
    // literal, six times, in its own Builder calls -- that is the harness, and
    // pretending otherwise would be the overclaim. The runtime assembly buys
    // one narrower thing: the matcher is not itself another occurrence, so if
    // the scanned set is ever widened, the guard does not trip on its own
    // matching string and get "fixed" with a self-exemption, which is where
    // such guards go to die. Widening would still have to reckon with the
    // Builder calls deliberately.
    let seam = format!("fixed_ephemeral_key{}", "_for_testing_only");

    // A LITERAL-REFERENCE PROHIBITION WITH A PINNED ALLOWLIST OF ONE.
    //
    // What this checks, exactly and no more: that the identifier appears in
    // `src/` in exactly one place, and that the place is byte-for-byte the one
    // occurrence allowlisted below. NOT lexical analysis, NOT semantic
    // analysis, NOT macro expansion, NOT reachability.
    //
    // Say precisely what the allowlist is, because the obvious shorthand is
    // already an overclaim. This allowlists one exact TEXTUAL occurrence. In
    // the current object that occurrence happens to be a doc-comment, but the
    // checker proves NEITHER its lexical category NOR its position: it compares
    // bytes, counts them, and names the file. Calling it "the documentary
    // mention" would attribute a category nothing here establishes -- the same
    // half-step-past-the-mechanism that broke the two previous versions of this
    // guard, in the comment rather than in the code.
    //
    // There is NO exemption rule. Two earlier versions had one and both were
    // broken by review, in the same way each time -- the exemption needed to
    // know something about the language, and deciding that by hand is a lexer:
    //
    //   v1 stripped comments with `line.split("//").next()`. A `//` inside a
    //      STRING LITERAL truncated the line and hid the call after it:
    //          let u = "https://example.invalid"; let _ = b.SEAM(&k);
    //          scanned:  let u = "https:
    //
    //   v2 exempted any line whose `trim_start()` began with `//`, on the
    //      argument that such a line is a comment to its end. That argument
    //      silently assumed the lexical state ENTERING the line, which a
    //      line-based scan cannot know. With a raw string opened above, the
    //      `//` is string CONTENT, the raw string closes mid-line, and what
    //      follows is executed code:
    //          let _s = r#"
    //          // "#; let _ = builder.SEAM(&[0u8; 32]);
    //      Valid Rust. Compiles. Calls the seam. v2 exempted the line.
    //
    // Both were reproduced and compiled by review, not argued. The lesson is
    // that ANY exemption reintroduces the lexer, so there is none: the rule is
    // presence, and the only tolerated presence is one exact known line.
    //
    // The declared cost is false POSITIVES, and it is now total: any new
    // mention anywhere under `src/`, in code or prose or a string, is RED.
    // Adding one is a review event, which is what a ratchet is for.
    //
    // What is pinned: the file, the line's exact bytes, and the count. What is
    // deliberately NOT pinned is the line NUMBER -- moving the mention within
    // its own file leaves it inert prose, and pinning the number would fire on
    // every unrelated edit above it, which trains people to "fix" the guard.
    //
    // LIMIT, stated here because it is invisible from the outside: a textual
    // rule cannot see indirection. A macro defined outside `src/` that expands
    // to the seam call leaves no literal occurrence at its call site, and this
    // guard will not see it. That is not closed here and is not claimed to be.
    let allowed_file = "noise.rs";
    let allowed_line = format!("/// calls snow's `{seam}` — that method is not");

    // A file's identity, and the ONLY spelling of it that enters the tuple:
    // its path relative to `src`, joined with `/`.
    //
    // `file_name()` was here and was a real defect, found in review: it keeps
    // only the basename, so `src/noise.rs` and `src/nested/noise.rs` produce
    // the identical tuple and the allowlist accepts either. The pin said "by
    // file" while the stored value did not identify a file.
    //
    // Relative, so the tuple cannot depend on where the repository is checked
    // out. Every rejection below is fail-closed on purpose: a path that does
    // not sit under `src`, a `.`/`..`/root component, or a non-UTF-8 name has
    // no canonical key here, and inventing one would be the same mistake in a
    // new spelling.
    fn rel_key(path: &std::path::Path, src: &std::path::Path) -> String {
        use std::path::Component;
        let rel = path
            .strip_prefix(src)
            .unwrap_or_else(|e| panic!("path {path:?} is not under {src:?}: {e}"));
        let mut parts = Vec::new();
        for c in rel.components() {
            match c {
                Component::Normal(os) => match os.to_str() {
                    Some(part) => parts.push(part.to_string()),
                    None => panic!("non-UTF-8 component in {rel:?}; refusing to key it"),
                },
                other => panic!("non-normal path component {other:?} in {rel:?}; refusing to key it"),
            }
        }
        assert!(!parts.is_empty(), "the relative key of {path:?} is empty");
        parts.join("/")
    }

    // The walk, as a callable function taking its ROOT, so the controls below
    // can point it at a directory they build and exercise the same code the
    // real scan runs -- not a second copy of it that could drift.
    fn scan_root(root: &std::path::Path, seam: &str) -> (usize, Vec<(String, usize, String)>) {
        let mut scanned = 0usize;
        let mut occurrences: Vec<(String, usize, String)> = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("the scanned root is readable") {
                let entry = entry.expect("entry");
                let path = entry.path();
                // `file_type()` on the DirEntry does NOT follow links. A
                // symlink makes "what was scanned" depend on where it points,
                // and this scan has no coverage story for that, so it is
                // refused -- never traversed, never silently skipped.
                let kind = entry.file_type().expect("file type is readable");
                assert!(
                    !kind.is_symlink(),
                    "symlink under the scanned root at {path:?}: coverage is not established \
                     for symlinked entries, so this fails rather than guessing"
                );
                if kind.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("source is utf-8");
                scanned += 1;
                let rel = rel_key(&path, root);
                for (i, line) in text.lines().enumerate() {
                    if line.contains(seam) {
                        occurrences.push((rel.clone(), i + 1, line.to_string()));
                    }
                }
            }
        }
        (scanned, occurrences)
    }

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let (scanned, occurrences) = scan_root(&src, &seam);

    assert!(scanned > 3, "the scan must actually reach src/; saw {scanned}");

    // The verdict, as a CALLABLE contract rather than inline assertions, so the
    // controls below exercise the same function the scan just fed. Three things
    // are pinned and each can fail alone: how many occurrences exist, which
    // file holds the permitted one, and its exact bytes.
    let verdict = |occ: &[(String, usize, String)]| -> Result<(), String> {
        if occ.len() != 1 {
            return Err(format!(
                "expected exactly ONE literal reference to the fixed-key seam under src/ -- \
                 the single allowlisted TEXTUAL occurrence -- and found {}: {:#?}",
                occ.len(),
                occ.iter()
                    .map(|(f, n, l)| format!("{f}:{n}: {l:?}"))
                    .collect::<Vec<_>>()
            ));
        }
        let (file, no, line) = &occ[0];
        if file != allowed_file {
            return Err(format!(
                "the one permitted reference moved out of {allowed_file} to {file}:{no}"
            ));
        }
        if line != &allowed_line {
            return Err(format!(
                "the one permitted reference at {file}:{no} is no longer byte-identical to the \
                 allowlisted line; anything appended to it, or any drift in it, changes the only \
                 tolerated occurrence and must be reviewed rather than absorbed. found: {line:?}"
            ));
        }
        Ok(())
    };

    if let Err(why) = verdict(&occurrences) {
        panic!(
            "{why}\n\nAny other literal reference to the seam identifier under src/ -- in code, \
             in prose, or inside a string -- is forbidden on the MESH-SESSION production surface. \
             This check is TEXTUAL: it does not parse, expand macros, or reason about \
             reachability."
        );
    }

    // ---- Controls -------------------------------------------------------
    //
    // Two layers, because two different things can be wrong: what the scan
    // COUNTS as an occurrence, and what the verdict DOES with the counts.

    // Layer 1: the scan's own predicate -- raw containment, no exemption of any
    // kind -- on the exact shapes review used to break the two earlier
    // versions. Both are valid Rust that compiles and calls the seam.
    let sees = |line: &str| line.contains(&seam);

    assert!(
        sees(&format!("let _ = builder.{seam}(&[0u8; 32]);")),
        "the scan cannot see a planted seam call"
    );

    // v1 was defeated by a `//` inside a STRING LITERAL: `split("//")`
    // truncated the line and dropped the call after it.
    assert!(
        sees(&format!(
            "let _u = \"https://example.invalid\"; let _ = builder.{seam}(&[0u8; 32]);"
        )),
        "a `//` inside a string literal must not hide a seam reference"
    );

    // v2 was defeated by lexical state carried from the PREVIOUS line. With a
    // raw string opened above, this line's leading `//` is string CONTENT, the
    // raw string closes mid-line, and the rest is executed code. Reproduced and
    // compiled in review against the real `snow::Builder`. v2 exempted it for
    // looking like a comment; there is no exemption left to fool.
    let v2_bypass = format!("    // \"#; let _ = builder.{seam}(&[0u8; 32]);");
    assert!(
        v2_bypass.trim_start().starts_with("//"),
        "this control is only meaningful while the line LOOKS like a comment"
    );
    assert!(
        sees(&v2_bypass),
        "a leading `//` that is really raw-string content must not exempt a line"
    );

    // Layer 2: the verdict, against the exact allowlist and against each way of
    // breaking it. The permitted shape must pass; everything else must not.
    let permitted = vec![(
        allowed_file.to_string(),
        59usize,
        allowed_line.clone(),
    )];
    assert!(
        verdict(&permitted).is_ok(),
        "the exact allowlisted mention must be accepted"
    );

    // Moving it within its own file is deliberately NOT an offence: it stays
    // inert prose, and pinning the line number would fire on every unrelated
    // edit above it.
    let moved_in_file = vec![(allowed_file.to_string(), 999usize, allowed_line.clone())];
    assert!(
        verdict(&moved_in_file).is_ok(),
        "the line number is deliberately not pinned"
    );

    // Duplicated: cardinality is load-bearing.
    let duplicated = vec![permitted[0].clone(), permitted[0].clone()];
    assert!(
        verdict(&duplicated).is_err(),
        "a duplicate of the permitted line must be refused"
    );

    // Moved to another file, the easy case: a different basename.
    let moved_file = vec![("lib.rs".to_string(), 59usize, allowed_line.clone())];
    assert!(
        verdict(&moved_file).is_err(),
        "the permitted line must not be accepted from another file"
    );

    // Moved to another file with the SAME BASENAME. This is the load-bearing
    // one: it is the case that `file_name()` could not distinguish, so the
    // easy control above passed while the pin did not hold.
    let same_basename = vec![(
        "nested/noise.rs".to_string(),
        59usize,
        allowed_line.clone(),
    )];
    assert!(
        verdict(&same_basename).is_err(),
        "a file sharing the allowlisted file's basename must not be accepted"
    );
    assert_ne!(
        rel_key(
            std::path::Path::new("/tmp/x/src/nested/noise.rs"),
            std::path::Path::new("/tmp/x/src")
        ),
        rel_key(
            std::path::Path::new("/tmp/x/src/noise.rs"),
            std::path::Path::new("/tmp/x/src")
        ),
        "the key must separate two files that differ only by directory"
    );

    // Root-independence: the same file under two different checkout roots must
    // produce the same key, or the verdict would be a function of where the
    // repository happens to live.
    assert_eq!(
        rel_key(
            std::path::Path::new("/tmp/root-a/src/noise.rs"),
            std::path::Path::new("/tmp/root-a/src")
        ),
        rel_key(
            std::path::Path::new("/other/root-b/src/noise.rs"),
            std::path::Path::new("/other/root-b/src")
        ),
        "the key must not depend on the checkout root"
    );
    assert_eq!(
        rel_key(
            std::path::Path::new("/tmp/root-a/src/noise.rs"),
            std::path::Path::new("/tmp/root-a/src")
        ),
        allowed_file,
        "the allowlisted key is the relative path under src"
    );

    // A symlink under the scanned root must FAIL the scan -- not be followed,
    // not be quietly skipped. Exercised against a directory this test builds,
    // through the same `scan_root` the real scan uses.
    //
    // The link's target deliberately contains NO seam. That is what makes this
    // control discriminate the mechanism instead of an accident: if the scan
    // panics here it can only be because it met the symlink, since there is
    // nothing in the tree for it to find. Remove the refusal and the scan
    // returns an empty result instead of panicking, and this assertion fails.
    #[cfg(unix)]
    {
        let tmp = std::env::temp_dir().join(format!(
            "m1a-symlink-control-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("the control's temp root is creatable");
        let target = tmp.join("plain.rs");
        std::fs::write(&target, "pub fn nothing_of_interest() {}\n").expect("target is writable");
        std::os::unix::fs::symlink(&target, tmp.join("linked.rs")).expect("symlink is creatable");

        let probed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scan_root(&tmp, &seam)
        }));
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(
            probed.is_err(),
            "a symlink under the scanned root must fail the scan; it returned {probed:?} \
             instead, which means the entry was followed or skipped"
        );
    }

    // Fail-closed rejections. Each of these has no canonical key, and inventing
    // one would be the same defect in a new spelling.
    for (label, path, root) in [
        ("outside src", "/tmp/root-a/elsewhere/noise.rs", "/tmp/root-a/src"),
        ("parent escape", "/tmp/root-a/src/../noise.rs", "/tmp/root-a/src"),
    ] {
        let caught = std::panic::catch_unwind(|| {
            rel_key(std::path::Path::new(path), std::path::Path::new(root))
        });
        assert!(
            caught.is_err(),
            "{label}: {path} must be refused, not keyed"
        );
    }

    // Code appended to the permitted line: the bytes are load-bearing, and this
    // is the shape that would smuggle a call in behind an accepted prefix.
    let appended = vec![(
        allowed_file.to_string(),
        59usize,
        format!("{allowed_line} let _ = builder.{seam}(&[0u8; 32]);"),
    )];
    assert!(
        verdict(&appended).is_err(),
        "code appended to the permitted line must be refused"
    );

    // Whitespace drift: still not byte-identical, still refused. Reflowing the
    // comment is a review event, not something the guard absorbs.
    let drifted = vec![(
        allowed_file.to_string(),
        59usize,
        format!("{allowed_line} "),
    )];
    assert!(
        verdict(&drifted).is_err(),
        "whitespace drift in the permitted line must be refused"
    );

    // Absent entirely: zero is not one. If the mention is deleted, the guard
    // must fail rather than quietly pass on an empty set -- otherwise deleting
    // the allowlist would look like compliance.
    assert!(
        verdict(&[]).is_err(),
        "an empty occurrence set must be refused, not read as compliance"
    );
}
