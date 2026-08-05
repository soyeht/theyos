//! S0 capacity harness for the opaque rendezvous relay (plan §7.5, spike S0).
//!
//! CLIENT ONLY. It speaks the relay's own rendezvous hello and nothing else —
//! no offer, no credential, no Noise, no Product A/nvpn. That is possible
//! because the relay is blind after pairing: it splices opaque bytes and never
//! parses them, so a pair of raw TCP connections sharing a token is a *real*
//! pair by the relay's own definition, not a simulation of one.
//!
//! # What this measures, and what it must never be quoted as
//!
//! It measures the RELAY's sustainable paired capacity and the **relay-path
//! round-trip latency** — the full guest→relay→claw→relay→guest time.
//!
//! That is deliberately not called "added latency": this harness has no
//! direct-path baseline to subtract, so it cannot attribute any part of the
//! measurement to the relay's own overhead. A collector may compute overhead
//! later by taking a separate baseline, but the number in this JSON is the
//! end-to-end path and must be quoted as such.
//!
//! It also does **not** measure product traffic: the 1 KiB echo is a probe
//! chosen to be small and uniform, so the byte counters it produces describe
//! the harness, not any real session. §7.4's "bytes per session p50/p95" must
//! come from production telemetry, never from this file.
//!
//! # Why establish and probe are two separate phases
//!
//! Load-bearing for the p95 to mean anything. If each pair were probed as it
//! was created, the first pairs would be timed against an almost-empty relay
//! and the last against a full one — the resulting p95 would describe a ramp,
//! not the rung. So ALL pairs of the rung are established first, and only then
//! is every open pair probed. The reported p95 is therefore latency at the
//! rung's full occupancy, which is the number S0 asks for.
//!
//! # Two ceilings you will hit before capacity
//!
//! Measured on the deployed relay, and the reason a rung can fail without the
//! relay being at fault:
//!
//! - `max_pending_per_source` (16 by default) — a source may hold only 16
//!   connections that have said hello and are parked waiting for their peer.
//!   This is the limit a guest sits under while it waits for its claw, so with
//!   C concurrent tasks up to C guests occupy it at once. That is why
//!   `--concurrency` defaults to 16 — see [`DEFAULT_CONCURRENCY`].
//! - `max_unpaired_active_per_source` (also 16 by default) — held only between
//!   accept and the parked hello, then handed back. Transient, but a burst of C
//!   accepts can occupy C of these before their hellos park, so it bounds the
//!   same C from the other side.
//! - `max_paired_splices_per_source` (128 by default) — a single source IP may
//!   hold only 128 concurrent paired splices. Rungs above that need multiple
//!   source addresses; from one host they will fail, and that is a limit
//!   measurement, not a capacity measurement.
//!
//! # Usage
//!
//! ```text
//! cargo run --release --example relay_stream_s0_load -- \
//!     --addr 127.0.0.1:49152 --pairs 100 --hold-secs 5
//! ```
//!
//! `--concurrency` is omitted on purpose: the default (16) is the highest
//! value that runs against a default-configured relay. Passing a larger one
//! without first raising BOTH `max_pending_per_source` and
//! `max_unpaired_active_per_source` will fail the run.
//!
//! stdout is a single JSON object and nothing else. A progress marker is
//! written to **stderr** so a collector can bracket its `/status` and `/proc`
//! samples to the exact steady-state window. Tokens and payload bytes are
//! never printed anywhere.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use server_rs::claw_share_rendezvous_stream_relay::{
    RendezvousHello, RendezvousRole, RendezvousToken,
};

/// Bytes echoed per pair. Small and uniform on purpose: this is a latency
/// probe, not a throughput or product-traffic measurement.
const PROBE_BYTES: usize = 1024;

/// Token length. The relay accepts 16..=128; 16 CSPRNG bytes is the minimum
/// that is still collision-free for any rung we run.
const TOKEN_BYTES: usize = 16;

/// Default in-flight operations, chosen to equal the relay's per-source
/// admission limits (both 16) rather than for throughput.
///
/// Building a pair as guest-then-its-own-claw bounds per-source occupancy
/// **per task**, not globally: with C tasks running, up to C guests are
/// waiting for their claws at once. The limit that guest sits under is
/// `max_pending_per_source`, not `max_unpaired_active_per_source` — a
/// connection takes an unpaired permit on accept, but once its hello parks
/// awaiting a peer it acquires a *pending* permit and hands the unpaired one
/// back (see `release_unpaired`/`attach_pending` in the relay listener). The
/// unpaired limit still bounds the accept-to-parked-hello window, so a burst
/// of C accepts touches it too; both default to 16, and at C = 16 the worst
/// case exactly meets each.
///
/// Raising `--concurrency` above this therefore requires raising BOTH limits
/// on the relay under test — raising only the unpaired one leaves the run
/// failing on `PendingLimit`. The isolated S0 run does that explicitly, and it
/// must never be done to a shared or production relay to make a harness go
/// faster.
const DEFAULT_CONCURRENCY: usize = 16;

// ─── configuration ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Config {
    addr: SocketAddr,
    pairs: usize,
    hold: Duration,
    /// How many operations are in flight at once, in BOTH phases. Explicit and
    /// echoed back in the output: a hidden concurrency limit would let a run
    /// silently serialise and report a latency no concurrent load ever saw.
    concurrency: usize,
    connect_timeout: Duration,
    probe_timeout: Duration,
}

#[derive(Debug, PartialEq, Eq)]
enum ConfigError {
    UnknownFlag(String),
    MissingValue(&'static str),
    BadValue(&'static str),
    MissingRequired(&'static str),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownFlag(flag) => write!(f, "unknown flag: {flag}"),
            Self::MissingValue(flag) => write!(f, "flag {flag} needs a value"),
            Self::BadValue(flag) => write!(f, "flag {flag} has an invalid value"),
            Self::MissingRequired(flag) => write!(f, "missing required flag {flag}"),
        }
    }
}

fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Config, ConfigError> {
    let mut addr: Option<SocketAddr> = None;
    let mut pairs: Option<usize> = None;
    let mut hold_secs: u64 = 0;
    let mut concurrency: usize = DEFAULT_CONCURRENCY;
    let mut connect_timeout_secs: u64 = 10;
    let mut probe_timeout_secs: u64 = 10;

    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--addr" => {
                let raw = it.next().ok_or(ConfigError::MissingValue("--addr"))?;
                addr = Some(raw.parse().map_err(|_| ConfigError::BadValue("--addr"))?);
            }
            "--pairs" => {
                let raw = it.next().ok_or(ConfigError::MissingValue("--pairs"))?;
                let value: usize = raw.parse().map_err(|_| ConfigError::BadValue("--pairs"))?;
                if value == 0 {
                    return Err(ConfigError::BadValue("--pairs"));
                }
                pairs = Some(value);
            }
            "--hold-secs" => {
                let raw = it.next().ok_or(ConfigError::MissingValue("--hold-secs"))?;
                hold_secs = raw
                    .parse()
                    .map_err(|_| ConfigError::BadValue("--hold-secs"))?;
            }
            "--concurrency" => {
                let raw = it
                    .next()
                    .ok_or(ConfigError::MissingValue("--concurrency"))?;
                let value: usize = raw
                    .parse()
                    .map_err(|_| ConfigError::BadValue("--concurrency"))?;
                if value == 0 {
                    return Err(ConfigError::BadValue("--concurrency"));
                }
                concurrency = value;
            }
            "--connect-timeout-secs" => {
                let raw = it
                    .next()
                    .ok_or(ConfigError::MissingValue("--connect-timeout-secs"))?;
                connect_timeout_secs = raw
                    .parse()
                    .map_err(|_| ConfigError::BadValue("--connect-timeout-secs"))?;
            }
            "--probe-timeout-secs" => {
                let raw = it
                    .next()
                    .ok_or(ConfigError::MissingValue("--probe-timeout-secs"))?;
                probe_timeout_secs = raw
                    .parse()
                    .map_err(|_| ConfigError::BadValue("--probe-timeout-secs"))?;
            }
            other => return Err(ConfigError::UnknownFlag(other.to_owned())),
        }
    }

    Ok(Config {
        addr: addr.ok_or(ConfigError::MissingRequired("--addr"))?,
        pairs: pairs.ok_or(ConfigError::MissingRequired("--pairs"))?,
        hold: Duration::from_secs(hold_secs),
        concurrency,
        connect_timeout: Duration::from_secs(connect_timeout_secs),
        probe_timeout: Duration::from_secs(probe_timeout_secs),
    })
}

// ─── failure classes ─────────────────────────────────────────────────────────

/// Why one pair did not complete.
///
/// Note what is deliberately NOT here: an `Admission` class. The rendezvous
/// protocol has no admission ACK — the relay accepts the TCP connection,
/// reads the hello, and simply drops the connection if a per-source or global
/// cap refuses it. From the client that is indistinguishable from an early
/// close or an ordinary I/O error, so naming a class "admission" would assert
/// a cause this harness cannot observe.
///
/// **The authority for admission refusals is the relay's own `/status`
/// `drops` block** (`source_paired_splice_limit`, `global_active_limit`, …),
/// sampled by the collector. `HelloOrEarlyClose` here means only "the socket
/// died at or just after hello", and a run must be read together with those
/// counters before any ceiling is claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairFailure {
    Connect,
    HelloOrEarlyClose,
    Timeout,
    Io,
    Mismatch,
}

impl PairFailure {
    fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::HelloOrEarlyClose => "hello_or_early_close",
            Self::Timeout => "timeout",
            Self::Io => "io",
            Self::Mismatch => "mismatch",
        }
    }
}

// ─── percentile ──────────────────────────────────────────────────────────────

/// Nearest-rank percentile over already-sorted microsecond samples.
///
/// Nearest-rank rather than interpolation because the sample count at the
/// small rungs (1 pair!) is far too low for interpolation to mean anything,
/// and because a reported p95 should always be a value that actually occurred.
/// Returns `None` for an empty sample so a failed rung reports null instead of
/// a fabricated zero.
/// Integer arithmetic throughout: a float rank would need three lossy casts
/// (`usize`→`f64`→`usize`) to compute an index, and there is no reason to
/// leave a truncation question in a number that decides which sample gets
/// reported.
fn percentile_us(sorted: &[u128], pct: u32) -> Option<u128> {
    if sorted.is_empty() {
        return None;
    }
    if pct == 0 {
        return sorted.first().copied();
    }
    if pct >= 100 {
        return sorted.last().copied();
    }
    let len = sorted.len();
    // Nearest rank = ceil(pct/100 × len), done without leaving the integers.
    let rank = (pct as usize * len).div_ceil(100);
    let index = rank.saturating_sub(1).min(len - 1);
    Some(sorted[index])
}

// ─── in-flight gauge ─────────────────────────────────────────────────────────

/// Tracks how many operations were genuinely in flight at once.
///
/// Exists because "concurrency" is otherwise unfalsifiable from the output: a
/// harness that silently serialised would report the same counts and a much
/// better p95. `peak` is emitted in the JSON, and a serial implementation can
/// never push it above 1.
#[derive(Default)]
struct InFlight {
    current: AtomicUsize,
    peak: AtomicUsize,
}

impl InFlight {
    fn enter(&self) {
        let now = self.current.fetch_add(1, Ordering::AcqRel) + 1;
        self.peak.fetch_max(now, Ordering::AcqRel);
    }

    fn leave(&self) {
        self.current.fetch_sub(1, Ordering::AcqRel);
    }

    fn peak(&self) -> usize {
        self.peak.load(Ordering::Acquire)
    }
}

// ─── one pair ────────────────────────────────────────────────────────────────

fn random_token() -> Vec<u8> {
    let mut token = vec![0_u8; TOKEN_BYTES];
    rand::thread_rng().fill_bytes(&mut token);
    token
}

/// Connect one side and send its hello.
async fn connect_side(
    addr: SocketAddr,
    role: RendezvousRole,
    token: &[u8],
    connect_timeout: Duration,
) -> Result<TcpStream, PairFailure> {
    let mut stream = tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| PairFailure::Connect)?
        .map_err(|_| PairFailure::Connect)?;
    stream.set_nodelay(true).map_err(|_| PairFailure::Io)?;

    let token = RendezvousToken::try_new(token).map_err(|_| PairFailure::Mismatch)?;
    let hello = RendezvousHello::new(role, token).encode();

    // A refusal (per-source cap, global semaphore) surfaces here as a dead
    // socket, indistinguishable from an early close — hence the class name.
    tokio::time::timeout(connect_timeout, stream.write_all(&hello))
        .await
        .map_err(|_| PairFailure::Timeout)?
        .map_err(|_| PairFailure::HelloOrEarlyClose)?;
    tokio::time::timeout(connect_timeout, stream.flush())
        .await
        .map_err(|_| PairFailure::Timeout)?
        .map_err(|_| PairFailure::HelloOrEarlyClose)?;
    Ok(stream)
}

/// PHASE 1 for one pair: connect both sides and say both hellos. No probe —
/// see the module docs on why measurement is deferred to full occupancy.
async fn establish_pair(
    addr: SocketAddr,
    connect_timeout: Duration,
) -> Result<(TcpStream, TcpStream), PairFailure> {
    let token = random_token();
    // Guest then its OWN claw, immediately: never all guests first.
    let guest = connect_side(addr, RendezvousRole::Guest, &token, connect_timeout).await?;
    let claw = connect_side(addr, RendezvousRole::Claw, &token, connect_timeout).await?;
    Ok((guest, claw))
}

/// PHASE 2 for one pair: 1 KiB out and echoed back, timed. Runs only once the
/// whole rung is open, so this RTT is a full-occupancy measurement.
/// Witnesses how much of the rung was established at the instant each probe
/// actually began.
///
/// This exists because the ordering property cannot be checked from a field
/// computed after phase 1 returns: `open_before_probe` is `open.len()` read
/// once establish is over, so it reports the full rung even if probes ran
/// early. A mutant that probes mid-establish leaves that field untouched and
/// passes. The observation therefore has to happen inside `probe_pair`, bound
/// to the operation whose ordering is in question — not to a number derived
/// afterwards.
#[derive(Debug, Default)]
struct ProbeWitness {
    /// Pairs finished establishing so far.
    established: AtomicUsize,
    /// Smallest `established` seen by any probe at its start. Stays
    /// `usize::MAX` if nothing was ever probed.
    min_established_at_probe: AtomicUsize,
}

impl ProbeWitness {
    fn new() -> Self {
        Self {
            established: AtomicUsize::new(0),
            min_established_at_probe: AtomicUsize::new(usize::MAX),
        }
    }

    fn record_established(&self) {
        self.established.fetch_add(1, Ordering::SeqCst);
    }

    /// Called at the top of every probe, before any bytes move.
    fn observe_probe_start(&self) {
        let now = self.established.load(Ordering::SeqCst);
        self.min_established_at_probe
            .fetch_min(now, Ordering::SeqCst);
    }

    /// `None` when no probe ran.
    fn min_at_probe(&self) -> Option<usize> {
        match self.min_established_at_probe.load(Ordering::SeqCst) {
            usize::MAX => None,
            value => Some(value),
        }
    }
}

async fn probe_pair(
    guest: &mut TcpStream,
    claw: &mut TcpStream,
    probe_timeout: Duration,
    witness: &ProbeWitness,
) -> Result<u128, PairFailure> {
    witness.observe_probe_start();

    // Fixed non-zero pattern so a truncated or zero-filled read cannot pass.
    let probe = vec![0xa5_u8; PROBE_BYTES];
    let mut echoed = vec![0_u8; PROBE_BYTES];
    let mut returned = vec![0_u8; PROBE_BYTES];

    let started = Instant::now();
    tokio::time::timeout(probe_timeout, guest.write_all(&probe))
        .await
        .map_err(|_| PairFailure::Timeout)?
        .map_err(|_| PairFailure::Io)?;
    tokio::time::timeout(probe_timeout, guest.flush())
        .await
        .map_err(|_| PairFailure::Timeout)?
        .map_err(|_| PairFailure::Io)?;
    tokio::time::timeout(probe_timeout, claw.read_exact(&mut echoed))
        .await
        .map_err(|_| PairFailure::Timeout)?
        .map_err(|_| PairFailure::Io)?;
    tokio::time::timeout(probe_timeout, claw.write_all(&echoed))
        .await
        .map_err(|_| PairFailure::Timeout)?
        .map_err(|_| PairFailure::Io)?;
    tokio::time::timeout(probe_timeout, claw.flush())
        .await
        .map_err(|_| PairFailure::Timeout)?
        .map_err(|_| PairFailure::Io)?;
    tokio::time::timeout(probe_timeout, guest.read_exact(&mut returned))
        .await
        .map_err(|_| PairFailure::Timeout)?
        .map_err(|_| PairFailure::Io)?;
    let rtt_us = started.elapsed().as_micros();

    if returned != probe {
        return Err(PairFailure::Mismatch);
    }
    Ok(rtt_us)
}

// ─── run ─────────────────────────────────────────────────────────────────────

struct RunReport {
    established: usize,
    rtts_us: Vec<u128>,
    failures: Vec<PairFailure>,
    establish_wall_ms: u128,
    probe_wall_ms: u128,
    peak_inflight_establish: usize,
    peak_inflight_probe: usize,
    /// Pairs open at the moment the probe phase began. Equal to the rung size
    /// on a clean run — this is what makes the reported p95 a full-occupancy
    /// number, and it is recorded rather than inferred so the claim is
    /// checkable from the output alone.
    ///
    /// NOTE: on its own this field cannot prove the ordering, because it is
    /// read after phase 1 returns. See [`min_established_at_probe`].
    open_before_probe: usize,
    /// Smallest number of established pairs observed by any probe *at the
    /// instant that probe started*, or `None` if nothing was probed.
    ///
    /// This is the field that actually carries the full-occupancy claim: it is
    /// sampled inside `probe_pair`, so a probe that runs before the rung is
    /// complete lowers it no matter where in the code that probe was issued.
    min_established_at_probe: Option<usize>,
}

async fn run(cfg: &Config) -> RunReport {
    let mut failures = Vec::new();
    let witness = Arc::new(ProbeWitness::new());

    // ── phase 1: establish the whole rung, genuinely concurrently ──
    let establish_gauge = Arc::new(InFlight::default());
    let establish_started = Instant::now();
    let mut open: Vec<(TcpStream, TcpStream)> = Vec::with_capacity(cfg.pairs);
    {
        let mut set: JoinSet<Result<(TcpStream, TcpStream), PairFailure>> = JoinSet::new();
        let mut launched = 0_usize;
        while launched < cfg.pairs || !set.is_empty() {
            while launched < cfg.pairs && set.len() < cfg.concurrency {
                let addr = cfg.addr;
                let timeout = cfg.connect_timeout;
                let gauge = Arc::clone(&establish_gauge);
                set.spawn(async move {
                    gauge.enter();
                    let result = establish_pair(addr, timeout).await;
                    gauge.leave();
                    result
                });
                launched += 1;
            }
            if let Some(joined) = set.join_next().await {
                match joined {
                    Ok(Ok(pair)) => {
                        witness.record_established();
                        open.push(pair);
                    }
                    Ok(Err(failure)) => failures.push(failure),
                    Err(_) => failures.push(PairFailure::Io),
                }
            }
        }
    }
    let establish_wall_ms = establish_started.elapsed().as_millis();

    // Every pair of the rung is now open, but the probe has not run yet, so
    // this is NOT the quiet window. Emitted for collectors that want to
    // bracket the probe itself (e.g. to attribute the CPU it costs).
    let open_before_probe = open.len();
    eprintln!(
        "rung_established established={} failed={}",
        open_before_probe,
        failures.len()
    );

    // ── phase 2: probe at FULL occupancy ──
    let probe_gauge = Arc::new(InFlight::default());
    let probe_started = Instant::now();
    let mut rtts_us = Vec::with_capacity(open.len());
    let mut held: Vec<(TcpStream, TcpStream)> = Vec::with_capacity(open.len());
    {
        let mut set: JoinSet<(Result<u128, PairFailure>, (TcpStream, TcpStream))> = JoinSet::new();
        let mut queue = open.into_iter();
        let mut exhausted = false;
        while !exhausted || !set.is_empty() {
            while set.len() < cfg.concurrency {
                let Some((mut guest, mut claw)) = queue.next() else {
                    exhausted = true;
                    break;
                };
                let timeout = cfg.probe_timeout;
                let gauge = Arc::clone(&probe_gauge);
                let witness = Arc::clone(&witness);
                set.spawn(async move {
                    gauge.enter();
                    let result = probe_pair(&mut guest, &mut claw, timeout, &witness).await;
                    gauge.leave();
                    (result, (guest, claw))
                });
            }
            if let Some(joined) = set.join_next().await {
                match joined {
                    Ok((Ok(rtt), pair)) => {
                        rtts_us.push(rtt);
                        held.push(pair);
                    }
                    Ok((Err(failure), pair)) => {
                        failures.push(failure);
                        held.push(pair);
                    }
                    Err(_) => failures.push(PairFailure::Io),
                }
            }
        }
    }
    let probe_wall_ms = probe_started.elapsed().as_millis();

    // ── phase 3: hold, then close cleanly ──
    //
    // THIS is the quiet steady-state window: the whole rung is open and no
    // probe traffic is flowing. **Collect stable RSS, FD count and `ss -m` on
    // this marker**, not on `rung_established` — sampling there would catch
    // the probe's own CPU and buffer churn and attribute it to idle occupancy.
    eprintln!(
        "hold_started established={} failed={} hold_secs={}",
        held.len(),
        failures.len(),
        cfg.hold.as_secs()
    );
    if !cfg.hold.is_zero() {
        tokio::time::sleep(cfg.hold).await;
    }
    for (mut guest, mut claw) in held.drain(..) {
        let _ = guest.shutdown().await;
        let _ = claw.shutdown().await;
    }

    rtts_us.sort_unstable();
    RunReport {
        established: rtts_us.len(),
        rtts_us,
        failures,
        establish_wall_ms,
        probe_wall_ms,
        peak_inflight_establish: establish_gauge.peak(),
        peak_inflight_probe: probe_gauge.peak(),
        open_before_probe,
        min_established_at_probe: witness.min_at_probe(),
    }
}

fn report_json(cfg: &Config, report: &RunReport) -> serde_json::Value {
    let mut by_class = serde_json::Map::new();
    for class in [
        PairFailure::Connect,
        PairFailure::HelloOrEarlyClose,
        PairFailure::Timeout,
        PairFailure::Io,
        PairFailure::Mismatch,
    ] {
        let count = report.failures.iter().filter(|f| **f == class).count();
        by_class.insert(class.as_str().to_owned(), serde_json::json!(count));
    }

    serde_json::json!({
        "harness": "relay_stream_s0_load",
        "measures": "relay paired capacity and relay-path round-trip latency at full rung occupancy; NOT product bytes per session",
        "latency_note": "end-to-end guest->relay->claw->relay->guest; no direct-path baseline is taken, so this is NOT relay overhead",
        "admission_authority": "relay /status drops block — this harness cannot observe admission refusals directly",
        "config": {
            "addr": cfg.addr.to_string(),
            "pairs_requested": cfg.pairs,
            "hold_secs": cfg.hold.as_secs(),
            "concurrency": cfg.concurrency,
            "connect_timeout_secs": cfg.connect_timeout.as_secs(),
            "probe_timeout_secs": cfg.probe_timeout.as_secs(),
            "probe_bytes": PROBE_BYTES,
        },
        "result": {
            "pairs_probed_ok": report.established,
            "failures": report.failures.len(),
            "open_before_probe": report.open_before_probe,
            "min_established_at_probe": report.min_established_at_probe,
            "establish_wall_ms": report.establish_wall_ms,
            "probe_wall_ms": report.probe_wall_ms,
            "peak_inflight_establish": report.peak_inflight_establish,
            "peak_inflight_probe": report.peak_inflight_probe,
            "failures_by_class": by_class,
        },
        "rtt_us": {
            "note": "relay-path RTT, measured after the whole rung was established, so this is full-occupancy latency",
            "samples": report.rtts_us.len(),
            "min": percentile_us(&report.rtts_us, 0),
            "p50": percentile_us(&report.rtts_us, 50),
            "p95": percentile_us(&report.rtts_us, 95),
            "p99": percentile_us(&report.rtts_us, 99),
            "max": percentile_us(&report.rtts_us, 100),
        },
    })
}

#[tokio::main]
async fn main() {
    let cfg = match parse_args(std::env::args().skip(1)) {
        Ok(cfg) => cfg,
        Err(error) => {
            eprintln!("relay_stream_s0_load: {error}");
            eprintln!(
                "usage: --addr HOST:PORT --pairs N [--hold-secs S] [--concurrency N] \
                 [--connect-timeout-secs S] [--probe-timeout-secs S]"
            );
            std::process::exit(2);
        }
    };

    let report = run(&cfg).await;
    println!("{}", report_json(&cfg, &report));

    // Non-zero exit when the rung did not fully complete, so a scripted sweep
    // cannot record a partial rung as a clean one.
    if report.established < cfg.pairs {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use server_rs::claw_share_relay_stream_abuse::RelayAbuseConfig;
    use server_rs::claw_share_rendezvous_stream_relay_listener::{
        RendezvousStreamRelayListenerConfig, serve_rendezvous_stream_relay,
    };

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn test_relay_config() -> RendezvousStreamRelayListenerConfig {
        RendezvousStreamRelayListenerConfig {
            hello_timeout: Duration::from_secs(2),
            token_ttl: Duration::from_secs(30),
            max_pending: 64,
            max_active_connections: 64,
            reaper_interval: Duration::from_millis(50),
            splice_idle_timeout: Duration::from_secs(10),
            splice_max_lifetime: Duration::from_secs(60),
            splice_max_bytes_per_direction: None,
            abuse: RelayAbuseConfig::default(),
        }
    }

    #[test]
    fn hello_encodes_the_wire_shape_the_relay_decodes() {
        let token = vec![0x11_u8; TOKEN_BYTES];
        let hello = RendezvousHello::new(
            RendezvousRole::Guest,
            RendezvousToken::try_new(&token).unwrap(),
        );
        let bytes = hello.encode();

        assert_eq!(bytes[0], 1, "hello version");
        assert_eq!(bytes[1], 1, "Guest wire role");
        assert_eq!(
            u16::from_be_bytes([bytes[2], bytes[3]]) as usize,
            TOKEN_BYTES
        );
        assert_eq!(&bytes[4..], &token[..]);

        // Round-trips through the relay's OWN decoder, so this fails if the
        // relay's wire shape ever moves — the harness must not drift into
        // speaking a dialect the relay no longer accepts.
        let decoded = RendezvousHello::decode(&bytes).expect("relay must decode our hello");
        assert_eq!(decoded, hello);

        let claw = RendezvousHello::new(
            RendezvousRole::Claw,
            RendezvousToken::try_new(&token).unwrap(),
        )
        .encode();
        assert_eq!(claw[1], 2, "Claw wire role");
    }

    #[test]
    fn negative_control_relay_rejects_malformed_hellos() {
        assert!(RendezvousToken::try_new(vec![0_u8; 15]).is_err());
        assert!(RendezvousToken::try_new(Vec::new()).is_err());
        assert!(RendezvousToken::try_new(vec![0_u8; 129]).is_err());

        let mut bytes = RendezvousHello::new(
            RendezvousRole::Guest,
            RendezvousToken::try_new(vec![0_u8; TOKEN_BYTES]).unwrap(),
        )
        .encode();
        bytes[1] = 9;
        assert!(RendezvousHello::decode(&bytes).is_err(), "unknown role");
    }

    #[test]
    fn percentile_is_nearest_rank_and_never_invents_a_value() {
        let sorted: Vec<u128> = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        assert_eq!(percentile_us(&sorted, 50), Some(50));
        assert_eq!(percentile_us(&sorted, 95), Some(100));
        assert_eq!(percentile_us(&sorted, 0), Some(10));
        assert_eq!(percentile_us(&sorted, 100), Some(100));

        // Interpolation would have produced 95 here, which no pair measured.
        for pct in [1, 25, 50, 75, 95, 99] {
            let value = percentile_us(&sorted, pct).unwrap();
            assert!(sorted.contains(&value), "p{pct} invented {value}");
        }

        assert_eq!(percentile_us(&[], 95), None);
        assert_eq!(percentile_us(&[42], 95), Some(42));
    }

    #[test]
    fn args_parse_and_reject_precisely() {
        let cfg = parse_args(args(&[
            "--addr",
            "127.0.0.1:49152",
            "--pairs",
            "100",
            "--hold-secs",
            "5",
            "--concurrency",
            "7",
        ]))
        .expect("valid args");
        assert_eq!(cfg.pairs, 100);
        assert_eq!(cfg.hold, Duration::from_secs(5));
        // 7 is deliberately NOT the default, so this proves the flag is read
        // rather than silently ignored.
        assert_eq!(cfg.concurrency, 7);

        // The default must not exceed the relay's per-source limits (both 16):
        // C concurrent tasks park C guests under `max_pending_per_source` while
        // they wait for their claws, so a larger default would make the
        // copy-pasteable command fail against a stock relay. Pinned exactly,
        // not `<=`, so that raising it is a deliberate edit here and not a
        // silent drift.
        let defaulted = parse_args(args(&["--addr", "127.0.0.1:1", "--pairs", "1"])).unwrap();
        assert_eq!(defaulted.concurrency, 16);

        assert_eq!(
            parse_args(args(&["--pairs", "1"])),
            Err(ConfigError::MissingRequired("--addr"))
        );
        assert_eq!(
            parse_args(args(&["--addr", "127.0.0.1:1"])),
            Err(ConfigError::MissingRequired("--pairs"))
        );
        assert_eq!(
            parse_args(args(&["--addr", "not-an-addr", "--pairs", "1"])),
            Err(ConfigError::BadValue("--addr"))
        );
        assert_eq!(
            parse_args(args(&["--addr", "127.0.0.1:1", "--pairs", "0"])),
            Err(ConfigError::BadValue("--pairs"))
        );
        assert_eq!(
            parse_args(args(&[
                "--addr",
                "127.0.0.1:1",
                "--pairs",
                "1",
                "--concurrency",
                "0"
            ])),
            Err(ConfigError::BadValue("--concurrency"))
        );
        assert_eq!(
            parse_args(args(&["--addr"])),
            Err(ConfigError::MissingValue("--addr"))
        );
        assert_eq!(
            parse_args(args(&["--nope"])),
            Err(ConfigError::UnknownFlag("--nope".to_owned()))
        );
    }

    /// End to end against a REAL relay listener: pairing, splice and echo all
    /// actually happen, so the harness is proven against the thing it measures.
    #[tokio::test]
    async fn establishes_a_real_pair_against_a_live_relay_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = serve_rendezvous_stream_relay(listener, test_relay_config());

        let cfg = Config {
            addr,
            pairs: 1,
            hold: Duration::ZERO,
            concurrency: 1,
            connect_timeout: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(5),
        };

        let report = run(&cfg).await;
        assert_eq!(
            report.established, 1,
            "one real pair must establish and echo; failures: {:?}",
            report.failures
        );
        assert_eq!(report.failures.len(), 0);
        assert_eq!(report.rtts_us.len(), 1);
        // Non-vacuity: an RTT of exactly zero would mean nothing was timed.
        assert!(report.rtts_us[0] > 0, "RTT must be a real measurement");

        let json = report_json(&cfg, &report);
        assert_eq!(json["result"]["pairs_probed_ok"], 1);
        assert!(json["rtt_us"]["p95"].is_number());
        let rendered = json.to_string();
        assert!(!rendered.contains("a5a5"), "payload must not be printed");
        assert!(!rendered.contains("\"token\""), "token must not be printed");

        server.abort();
    }

    /// THE concurrency test. `--concurrency` must actually keep more than one
    /// operation in flight; a sequential implementation (e.g. awaiting each
    /// future in a loop, which is what lazy futures do) can never push either
    /// peak above 1, so reverting to that turns this RED.
    #[tokio::test]
    async fn concurrency_is_real_in_both_phases_not_decorative() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = serve_rendezvous_stream_relay(listener, test_relay_config());

        let cfg = Config {
            addr,
            pairs: 8,
            hold: Duration::ZERO,
            concurrency: 8,
            connect_timeout: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(5),
        };

        let report = run(&cfg).await;
        assert_eq!(
            report.established, 8,
            "all 8 pairs must complete; failures: {:?}",
            report.failures
        );
        assert!(
            report.peak_inflight_establish > 1,
            "establish ran serially: peak in-flight was {}",
            report.peak_inflight_establish
        );
        assert!(
            report.peak_inflight_probe > 1,
            "probe ran serially: peak in-flight was {}",
            report.peak_inflight_probe
        );

        server.abort();
    }

    /// The measurement-validity property, pinned DIRECTLY rather than
    /// inferred: `open_before_probe` records how many pairs were open at the
    /// instant the probe phase started, so asserting it equals the rung size
    /// is exactly the claim "no RTT was sampled at partial occupancy".
    ///
    /// Deliberately not argued from `peak_inflight_probe` alone — a peak above
    /// 1 shows the probe phase is concurrent and separate, which is necessary
    /// but does not by itself establish how many pairs the relay was holding.
    /// The counter states that; the peak does not.
    #[tokio::test]
    async fn probe_happens_after_the_whole_rung_is_established() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = serve_rendezvous_stream_relay(listener, test_relay_config());

        let cfg = Config {
            addr,
            pairs: 4,
            hold: Duration::ZERO,
            concurrency: 4,
            connect_timeout: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(5),
        };

        let report = run(&cfg).await;
        assert_eq!(report.established, 4);
        // THE property: the whole rung was already open when probing began.
        assert_eq!(
            report.open_before_probe, cfg.pairs,
            "every pair must be open before the first RTT is sampled"
        );
        // THE ordering assert. `open_before_probe` above is read after phase 1
        // returns, so it cannot distinguish "probed late" from "probed early
        // and reported late" — a mid-establish probe leaves it at cfg.pairs.
        // This one is sampled inside `probe_pair`, so the earliest probe in
        // the whole run has to have seen a complete rung.
        assert_eq!(
            report.min_established_at_probe,
            Some(cfg.pairs),
            "some probe started before the rung was fully established"
        );
        assert_eq!(
            report.rtts_us.len(),
            4,
            "every pair of the rung must be probed"
        );
        // And it is visible in the output, not only internal state.
        let json = report_json(&cfg, &report);
        assert_eq!(json["result"]["open_before_probe"], 4);

        server.abort();
    }
}
