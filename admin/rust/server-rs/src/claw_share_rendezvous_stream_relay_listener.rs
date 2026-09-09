//! Test-only/local TCP listener for the rendezvous stream relay core.
//!
//! This layer intentionally has no Noise, no confidentiality, and is test-only
//! until the Noise cut lands. It must not be wired into production bootstrap.

use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{interval, sleep, timeout};

use crate::claw_share_relay_stream_abuse::{
    RelayAbuseConfig, RelayAbusePermit, RelayAbuseState, RelayAdmissionOutcome, RelayRejectReason,
    RelaySourceBucket,
};
use crate::claw_share_rendezvous_stream_relay::{
    MAX_RENDEZVOUS_TOKEN_LEN, RendezvousHello, RendezvousOfferOutcome, RendezvousTokenTable,
    RendezvousTokenTableConfig, SpliceByteCapDirection, SpliceByteLedger,
    splice_opaque_streams_capped,
};
use crate::claw_share_rendezvous_stream_relay_status::{
    RelayStatusAbuseGateFailure, RelayStatusHelloErrorKind, RendezvousStreamRelayStatusHandle,
};

type RelayTcpStream = PermitTrackedStream<TcpStream>;
type SharedAbuseState = Arc<StdMutex<RelayAbuseState>>;
type SharedTokenTable = Arc<Mutex<RendezvousTokenTable<RelayTcpStream>>>;

pub const RENDEZVOUS_RELAY_BIND_ADDR_ENV: &str = "THEYOS_RENDEZVOUS_RELAY_BIND_ADDR";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousStreamRelayListenerConfig {
    pub hello_timeout: Duration,
    pub token_ttl: Duration,
    pub max_pending: usize,
    pub max_active_connections: usize,
    pub reaper_interval: Duration,
    pub splice_idle_timeout: Duration,
    pub splice_max_lifetime: Duration,
    /// Per-direction byte budget for the blind splice. The relay counts
    /// forwarded bytes (never parses them); byte B+1 hard-closes the splice.
    /// `None` is the legacy unlimited behavior — the byte cap is a policy of
    /// the PUBLIC relay, not of this listener, so the generic default stays
    /// unlimited and legacy callers are byte-identical.
    pub splice_max_bytes_per_direction: Option<u64>,
    pub abuse: RelayAbuseConfig,
}

impl Default for RendezvousStreamRelayListenerConfig {
    fn default() -> Self {
        Self {
            hello_timeout: Duration::from_secs(5),
            token_ttl: Duration::from_secs(60),
            max_pending: 1024,
            max_active_connections: 2048,
            reaper_interval: Duration::from_secs(10),
            splice_idle_timeout: Duration::from_secs(300),
            splice_max_lifetime: Duration::from_secs(60 * 60),
            splice_max_bytes_per_direction: None,
            abuse: RelayAbuseConfig::default(),
        }
    }
}

/// Spawn the rendezvous relay listener bound to an explicit loopback address.
///
/// Validates the address is loopback (fail-closed while the listener is
/// test-only), binds it, and starts the blind splicer with the default config.
/// This is the explicit-address core; [`spawn_rendezvous_stream_relay_from_env`]
/// is the env-reading wrapper. A dev caller (e.g. the standalone relay bin) can
/// pass its own single-source endpoint without mutating process env.
pub async fn spawn_rendezvous_stream_relay(bind_addr: &str) -> io::Result<JoinHandle<()>> {
    let bind_addr = bind_addr.trim();
    validate_loopback_bind_addr(bind_addr).await?;
    let listener = TcpListener::bind(bind_addr).await?;
    Ok(serve_rendezvous_stream_relay(
        listener,
        RendezvousStreamRelayListenerConfig::default(),
    ))
}

/// Spawn the rendezvous relay listener bound to a NON-loopback (public) address.
///
/// TEST-ONLY. This is the opt-in escape hatch for a remote/CGNAT smoke (C7d-2):
/// it skips the loopback fail-closed check so the relay can bind a public
/// `IP:port` while a guest behind CGNAT and a claw both dial it from outside.
/// It is otherwise byte-for-byte identical to [`spawn_rendezvous_stream_relay`]:
/// same blind splicer, same default [`RendezvousStreamRelayListenerConfig`] caps
/// (pending/active/TTL/idle), no new hardening, no Noise on its own wire (the
/// guest<->claw payload is Noise end-to-end; the relay only sees the plaintext
/// hello and opaque ciphertext, logs neither token nor payload).
///
/// This path has NO production hardening (no auth on the bind, no rate limit
/// beyond the in-memory caps, no TLS on the rendezvous hello). It MUST be reached
/// only behind an explicit opt-in flag by a dev caller, only for the duration of
/// a supervised test window, and MUST NOT be wired into bootstrap, the engine, or
/// production. The loopback default ([`spawn_rendezvous_stream_relay`]) stays the
/// safe path; this variant exists so enabling the public bind is a deliberate,
/// greppable call and never an accidental flag flip on the default path.
pub async fn spawn_rendezvous_stream_relay_allow_public(
    bind_addr: &str,
) -> io::Result<JoinHandle<()>> {
    let bind_addr = bind_addr.trim();
    let listener = TcpListener::bind(bind_addr).await?;
    Ok(serve_rendezvous_stream_relay(
        listener,
        RendezvousStreamRelayListenerConfig::default(),
    ))
}

pub async fn spawn_rendezvous_stream_relay_from_env() -> io::Result<Option<JoinHandle<()>>> {
    let addr = match std::env::var(RENDEZVOUS_RELAY_BIND_ADDR_ENV) {
        Ok(addr) if addr.trim().is_empty() => return Ok(None),
        Ok(addr) => addr,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "rendezvous relay bind addr env is not unicode",
            ));
        }
    };
    Ok(Some(spawn_rendezvous_stream_relay(addr.trim()).await?))
}

async fn validate_loopback_bind_addr(addr: &str) -> io::Result<()> {
    let resolved: Vec<_> = tokio::net::lookup_host(addr)
        .await
        .map_err(|error| {
            io::Error::new(
                ErrorKind::InvalidInput,
                format!("invalid rendezvous relay bind addr: {error}"),
            )
        })?
        .collect();
    if resolved.is_empty() || !resolved.iter().all(|addr| addr.ip().is_loopback()) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "rendezvous relay bind addr must be loopback while listener is test-only",
        ));
    }
    Ok(())
}

pub fn serve_rendezvous_stream_relay(
    listener: TcpListener,
    config: RendezvousStreamRelayListenerConfig,
) -> JoinHandle<()> {
    let bind_addr = listener
        .local_addr()
        .map_or_else(|_| "unknown".to_string(), |addr| addr.to_string());
    let status = RendezvousStreamRelayStatusHandle::new(bind_addr, false, &config);
    serve_rendezvous_stream_relay_with_status(listener, config, status)
}

pub fn serve_rendezvous_stream_relay_with_status(
    listener: TcpListener,
    config: RendezvousStreamRelayListenerConfig,
    status: RendezvousStreamRelayStatusHandle,
) -> JoinHandle<()> {
    let table = Arc::new(Mutex::new(RendezvousTokenTable::new(
        RendezvousTokenTableConfig {
            max_pending: config.max_pending,
            token_ttl_secs: duration_secs(config.token_ttl),
            max_consumed: RendezvousTokenTableConfig::default().max_consumed,
        },
    )));
    let abuse_state = Arc::new(StdMutex::new(RelayAbuseState::new(config.abuse.clone())));

    tokio::spawn(async move {
        let active_connections = Arc::new(Semaphore::new(config.max_active_connections.max(1)));
        let reaper_interval = nonzero_duration_or(config.reaper_interval, Duration::from_secs(10));
        let mut reaper = interval(reaper_interval);
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, peer_addr) = match accepted {
                        Ok(pair) => pair,
                        Err(error) => {
                            tracing::warn!(
                                stage = "claw_share.rendezvous_stream_relay.accept_failed",
                                error = %error,
                            );
                            continue;
                        }
                    };
                    let permit = if let Ok(permit) = Arc::clone(&active_connections).try_acquire_owned() { ActiveConnectionPermit::new(permit, status.clone()) } else {
                        status.record_global_active_limit_drop();
                        tracing::debug!(
                            stage = "claw_share.rendezvous_stream_relay.active_connection_limit",
                        );
                        continue;
                    };
                    let source_bucket = RelaySourceBucket::from_ip(
                        peer_addr.ip(),
                        config.abuse.ipv6_source_prefix_len,
                    );
                    let source_permit = match acquire_abuse_permit(
                        &abuse_state,
                        &status,
                        |state, now| state.try_acquire_unpaired_active(source_bucket, now),
                    ) {
                        Ok(permit) => permit,
                        Err(failure) => {
                            log_abuse_gate_failure(
                                "claw_share.rendezvous_stream_relay.source_unpaired_rejected",
                                failure,
                                &status,
                            );
                            continue;
                        }
                    };
                    tokio::spawn(handle_rendezvous_stream(
                        PermitTrackedStream::new(
                            stream,
                            permit,
                            source_bucket,
                            Arc::clone(&abuse_state),
                            source_permit,
                        ),
                        Arc::clone(&table),
                        status.clone(),
                        config.clone(),
                    ));
                }
                _ = reaper.tick() => {
                    let expired = {
                        let mut table = table.lock().await;
                        let expired = table.prune_expired(now_unix());
                        status.set_pending_tokens(table.pending_len());
                        expired
                    };
                    if let Ok(mut abuse) = abuse_state.lock() {
                        let pruned = abuse.prune_idle_buckets(Instant::now());
                        status.set_source_buckets(abuse.source_bucket_count());
                        status.record_source_buckets_pruned(pruned);
                    }
                    if expired > 0 {
                        status.record_pending_expired(expired);
                        tracing::debug!(
                            stage = "claw_share.rendezvous_stream_relay.reaped",
                            expired,
                        );
                    }
                }
            }
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbuseGateFailure {
    Rejected(RelayRejectReason),
    StateUnavailable,
    UnexpectedPermit,
}

impl AbuseGateFailure {
    fn for_status(self) -> RelayStatusAbuseGateFailure {
        match self {
            Self::Rejected(reason) => RelayStatusAbuseGateFailure::Rejected(reason),
            Self::StateUnavailable => RelayStatusAbuseGateFailure::StateUnavailable,
            Self::UnexpectedPermit => RelayStatusAbuseGateFailure::UnexpectedPermit,
        }
    }
}

fn acquire_abuse_permit(
    state: &SharedAbuseState,
    status: &RendezvousStreamRelayStatusHandle,
    apply: impl FnOnce(&mut RelayAbuseState, Instant) -> RelayAdmissionOutcome,
) -> Result<AbusePermitGuard, AbuseGateFailure> {
    let state_handle = Arc::clone(state);
    let mut state = state
        .lock()
        .map_err(|_| AbuseGateFailure::StateUnavailable)?;
    let outcome = apply(&mut state, Instant::now());
    status.set_source_buckets(state.source_bucket_count());
    match outcome {
        RelayAdmissionOutcome::Accepted {
            permit: Some(permit),
        } => Ok(AbusePermitGuard::new(state_handle, permit)),
        RelayAdmissionOutcome::Accepted { permit: None } => Err(AbuseGateFailure::StateUnavailable),
        RelayAdmissionOutcome::Rejected { reason } => Err(AbuseGateFailure::Rejected(reason)),
    }
}

fn run_abuse_gate(
    state: &SharedAbuseState,
    status: &RendezvousStreamRelayStatusHandle,
    apply: impl FnOnce(&mut RelayAbuseState, Instant) -> RelayAdmissionOutcome,
) -> Result<(), AbuseGateFailure> {
    let mut state = state
        .lock()
        .map_err(|_| AbuseGateFailure::StateUnavailable)?;
    let outcome = apply(&mut state, Instant::now());
    status.set_source_buckets(state.source_bucket_count());
    match outcome {
        RelayAdmissionOutcome::Accepted { permit: None } => Ok(()),
        RelayAdmissionOutcome::Accepted {
            permit: Some(permit),
        } => {
            state.release(permit, Instant::now());
            Err(AbuseGateFailure::UnexpectedPermit)
        }
        RelayAdmissionOutcome::Rejected { reason } => Err(AbuseGateFailure::Rejected(reason)),
    }
}

fn log_abuse_gate_failure(
    stage: &'static str,
    failure: AbuseGateFailure,
    status: &RendezvousStreamRelayStatusHandle,
) {
    status.record_abuse_gate_failure(failure.for_status());
    match failure {
        AbuseGateFailure::Rejected(reason) => {
            tracing::debug!(stage = stage, reason = ?reason);
        }
        AbuseGateFailure::StateUnavailable => {
            tracing::warn!(stage = stage);
        }
        AbuseGateFailure::UnexpectedPermit => {
            tracing::warn!(stage = stage, reason = "unexpected_abuse_permit");
        }
    }
}

fn record_failed_hello(stream: &RelayTcpStream, status: &RendezvousStreamRelayStatusHandle) {
    if let Err(failure) = run_abuse_gate(&stream.abuse_state, status, |state, now| {
        state.record_hello_failure(stream.source_bucket, now)
    }) {
        log_abuse_gate_failure(
            "claw_share.rendezvous_stream_relay.failed_hello_record_rejected",
            failure,
            status,
        );
    }
}

fn record_successful_pair(stream: &RelayTcpStream, status: &RendezvousStreamRelayStatusHandle) {
    if let Ok(mut state) = stream.abuse_state.lock() {
        state.record_successful_pair(stream.source_bucket, Instant::now());
        status.set_source_buckets(state.source_bucket_count());
    } else {
        status.record_abuse_gate_failure(RelayStatusAbuseGateFailure::StateUnavailable);
        tracing::warn!(stage = "claw_share.rendezvous_stream_relay.abuse_state_unavailable");
    }
}

fn acquire_paired_splice(
    stream: &mut RelayTcpStream,
    status: &RendezvousStreamRelayStatusHandle,
) -> Result<(), AbuseGateFailure> {
    let permit = acquire_abuse_permit(&stream.abuse_state, status, |state, now| {
        state.try_acquire_paired_splice(stream.source_bucket, now)
    })?;
    stream.attach_paired(permit);
    Ok(())
}

async fn handle_rendezvous_stream(
    mut stream: RelayTcpStream,
    table: SharedTokenTable,
    status: RendezvousStreamRelayStatusHandle,
    config: RendezvousStreamRelayListenerConfig,
) {
    if let Err(failure) = run_abuse_gate(&stream.abuse_state, &status, |state, now| {
        state.check_failed_hello_budget(stream.source_bucket, now)
    }) {
        log_abuse_gate_failure(
            "claw_share.rendezvous_stream_relay.failed_hello_budget_rejected",
            failure,
            &status,
        );
        return;
    }

    if let Err(failure) = run_abuse_gate(&stream.abuse_state, &status, |state, now| {
        state.record_hello_attempt(stream.source_bucket, now)
    }) {
        log_abuse_gate_failure(
            "claw_share.rendezvous_stream_relay.hello_attempt_rejected",
            failure,
            &status,
        );
        return;
    }

    let hello = match read_bounded_hello(&mut stream, config.hello_timeout).await {
        Ok(hello) => hello,
        Err(error) => {
            let kind = if error.kind() == ErrorKind::TimedOut {
                RelayStatusHelloErrorKind::Timeout
            } else {
                RelayStatusHelloErrorKind::Malformed
            };
            status.record_hello_error(kind);
            record_failed_hello(&stream, &status);
            tracing::debug!(
                stage = "claw_share.rendezvous_stream_relay.hello_rejected",
                error = %error,
            );
            return;
        }
    };
    let role = hello.role;
    let outcome = {
        let mut table = table.lock().await;
        let now_secs = now_unix();
        match table.offer_would_park(&hello.token, role, now_secs) {
            Ok(true) => match acquire_abuse_permit(&stream.abuse_state, &status, |state, now| {
                state.try_acquire_pending(stream.source_bucket, now)
            }) {
                Ok(permit) => {
                    stream.release_unpaired();
                    stream.attach_pending(permit);
                }
                Err(failure) => {
                    record_failed_hello(&stream, &status);
                    log_abuse_gate_failure(
                        "claw_share.rendezvous_stream_relay.source_pending_rejected",
                        failure,
                        &status,
                    );
                    return;
                }
            },
            Ok(false) => {}
            Err(reason) => {
                status.record_offer_rejected(reason);
                status.set_pending_tokens(table.pending_len());
                record_failed_hello(&stream, &status);
                tracing::debug!(
                    stage = "claw_share.rendezvous_stream_relay.offer_precheck_rejected",
                    reason = ?reason,
                );
                return;
            }
        }
        let outcome = table.offer(hello.token, role, stream, now_secs);
        status.set_pending_tokens(table.pending_len());
        outcome
    };

    match outcome {
        RendezvousOfferOutcome::Parked => {
            status.record_parked();
            tracing::debug!(
                stage = "claw_share.rendezvous_stream_relay.parked",
                role = ?role,
            );
        }
        RendezvousOfferOutcome::Paired {
            mut guest,
            mut claw,
        } => {
            status.record_pair();
            tracing::debug!(stage = "claw_share.rendezvous_stream_relay.paired");
            record_successful_pair(&guest, &status);
            record_successful_pair(&claw, &status);
            guest.release_unpaired();
            guest.release_pending();
            claw.release_unpaired();
            claw.release_pending();
            match acquire_paired_splice(&mut guest, &status) {
                Ok(()) => {}
                Err(failure) => {
                    log_abuse_gate_failure(
                        "claw_share.rendezvous_stream_relay.source_paired_rejected",
                        failure,
                        &status,
                    );
                    return;
                }
            }
            match acquire_paired_splice(&mut claw, &status) {
                Ok(()) => {}
                Err(failure) => {
                    log_abuse_gate_failure(
                        "claw_share.rendezvous_stream_relay.source_paired_rejected",
                        failure,
                        &status,
                    );
                    return;
                }
            }
            tokio::spawn(async move {
                match splice_opaque_streams_until_idle(
                    guest,
                    claw,
                    nonzero_duration_or(config.splice_idle_timeout, Duration::from_secs(300)),
                    nonzero_duration_or(config.splice_max_lifetime, Duration::from_secs(60 * 60)),
                    config.splice_max_bytes_per_direction,
                )
                .await
                {
                    Ok(RendezvousSpliceOutcome::Closed {
                        guest_to_claw,
                        claw_to_guest,
                    }) => {
                        status.record_splice_closed(guest_to_claw, claw_to_guest);
                        tracing::debug!(
                            stage = "claw_share.rendezvous_stream_relay.splice_closed",
                            guest_to_claw,
                            claw_to_guest,
                        );
                    }
                    Ok(RendezvousSpliceOutcome::ByteCapExceeded {
                        direction,
                        guest_to_claw,
                        claw_to_guest,
                    }) => {
                        status.record_splice_byte_cap_exceeded(
                            direction,
                            guest_to_claw,
                            claw_to_guest,
                        );
                        tracing::debug!(
                            stage = "claw_share.rendezvous_stream_relay.splice_byte_cap_exceeded",
                            direction = ?direction,
                            guest_to_claw,
                            claw_to_guest,
                        );
                    }
                    // KNOWN DEBT, deliberately not fixed in this slice: an I/O
                    // failure mid-splice (peer reset, broken pipe) reports NO
                    // bytes, because every `?` inside the pump discards its
                    // local outcome and this arm has no ledger in scope. The
                    // shared ledger added here would make it recoverable, but
                    // doing so means widening `io::Result` into a typed
                    // error-with-bytes, which is explicitly out of scope. So a
                    // high-volume transfer killed by a reset still under-counts
                    // by its whole length. Recorded so this reads as a decision,
                    // not an oversight.
                    Err(error) => {
                        status.record_splice_failed();
                        tracing::debug!(
                            stage = "claw_share.rendezvous_stream_relay.splice_failed",
                            error = %error,
                        );
                    }
                    Ok(RendezvousSpliceOutcome::IdleTimedOut {
                        guest_to_claw,
                        claw_to_guest,
                    }) => {
                        status.record_splice_idle_timeout(guest_to_claw, claw_to_guest);
                        tracing::debug!(
                            stage = "claw_share.rendezvous_stream_relay.splice_idle_timeout",
                            guest_to_claw,
                            claw_to_guest,
                        );
                    }
                    Ok(RendezvousSpliceOutcome::LifetimeElapsed {
                        guest_to_claw,
                        claw_to_guest,
                    }) => {
                        status.record_splice_lifetime_elapsed(guest_to_claw, claw_to_guest);
                        tracing::debug!(
                            stage = "claw_share.rendezvous_stream_relay.splice_lifetime_elapsed",
                            guest_to_claw,
                            claw_to_guest,
                        );
                    }
                }
            });
        }
        RendezvousOfferOutcome::Rejected { reason, stream } => {
            status.record_offer_rejected(reason);
            record_failed_hello(&stream, &status);
            tracing::debug!(
                stage = "claw_share.rendezvous_stream_relay.offer_rejected",
                reason = ?reason,
            );
        }
    }
}

async fn read_bounded_hello(
    stream: &mut (impl AsyncRead + Unpin),
    hello_timeout: Duration,
) -> io::Result<RendezvousHello> {
    timeout(hello_timeout, async {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        let token_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        if token_len > MAX_RENDEZVOUS_TOKEN_LEN {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "rendezvous hello token too large",
            ));
        }

        let mut encoded = Vec::with_capacity(4 + token_len);
        encoded.extend_from_slice(&header);
        let mut token = vec![0u8; token_len];
        stream.read_exact(&mut token).await?;
        encoded.extend_from_slice(&token);

        RendezvousHello::decode(&encoded).map_err(|error| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("invalid rendezvous hello: {error}"),
            )
        })
    })
    .await
    .map_err(|_| io::Error::new(ErrorKind::TimedOut, "rendezvous hello timed out"))?
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RendezvousSpliceOutcome {
    Closed {
        guest_to_claw: u64,
        claw_to_guest: u64,
    },
    ByteCapExceeded {
        direction: SpliceByteCapDirection,
        guest_to_claw: u64,
        claw_to_guest: u64,
    },
    /// Bytes come from the shared observational ledger, not from the pump's
    /// return value: on this path the pump future lost the `select!` and was
    /// dropped, so its local outcome no longer exists to be read.
    IdleTimedOut {
        guest_to_claw: u64,
        claw_to_guest: u64,
    },
    /// Same as `IdleTimedOut`: cancelled, so the bytes come from the ledger.
    LifetimeElapsed {
        guest_to_claw: u64,
        claw_to_guest: u64,
    },
}

async fn splice_opaque_streams_until_idle<A, B>(
    guest: A,
    claw: B,
    idle_timeout: Duration,
    max_lifetime: Duration,
    max_bytes_per_direction: Option<u64>,
) -> io::Result<RendezvousSpliceOutcome>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let last_activity = Arc::new(StdMutex::new(Instant::now()));
    let tracked_guest = ActivityTrackedStream::new(guest, Arc::clone(&last_activity));
    let tracked_claw = ActivityTrackedStream::new(claw, Arc::clone(&last_activity));
    // Lives OUTSIDE the racing future on purpose: the two timer arms below win
    // by cancelling the pump, which destroys its local counters. Observational
    // only — the pump's own budget/hard-close never consults it.
    let ledger = SpliceByteLedger::new();

    tokio::select! {
        spliced = splice_opaque_streams_capped(
            tracked_guest,
            tracked_claw,
            max_bytes_per_direction,
            &ledger,
        ) => {
            // The pump returned, so its local counters are authoritative and
            // exact here; the ledger is not consulted on this path.
            spliced.map(|outcome| match outcome.capped_direction {
                Some(direction) => RendezvousSpliceOutcome::ByteCapExceeded {
                    direction,
                    guest_to_claw: outcome.guest_to_claw,
                    claw_to_guest: outcome.claw_to_guest,
                },
                None => RendezvousSpliceOutcome::Closed {
                    guest_to_claw: outcome.guest_to_claw,
                    claw_to_guest: outcome.claw_to_guest,
                },
            })
        }
        () = wait_for_idle(last_activity, idle_timeout) => {
            let (guest_to_claw, claw_to_guest) = ledger.snapshot();
            Ok(RendezvousSpliceOutcome::IdleTimedOut { guest_to_claw, claw_to_guest })
        }
        () = sleep(max_lifetime) => {
            let (guest_to_claw, claw_to_guest) = ledger.snapshot();
            Ok(RendezvousSpliceOutcome::LifetimeElapsed { guest_to_claw, claw_to_guest })
        }
    }
}

async fn wait_for_idle(last_activity: Arc<StdMutex<Instant>>, idle_timeout: Duration) {
    loop {
        let elapsed = last_activity
            .lock()
            .map_or(idle_timeout, |last_activity| last_activity.elapsed());
        if elapsed >= idle_timeout {
            return;
        }
        sleep(idle_timeout.checked_sub(elapsed).unwrap()).await;
    }
}

struct ActivityTrackedStream<S> {
    inner: S,
    last_activity: Arc<StdMutex<Instant>>,
}

impl<S> ActivityTrackedStream<S> {
    fn new(inner: S, last_activity: Arc<StdMutex<Instant>>) -> Self {
        Self {
            inner,
            last_activity,
        }
    }

    fn mark_activity(&self) {
        if let Ok(mut last_activity) = self.last_activity.lock() {
            *last_activity = Instant::now();
        }
    }
}

struct AbusePermitGuard {
    state: SharedAbuseState,
    permit: Option<RelayAbusePermit>,
}

impl AbusePermitGuard {
    fn new(state: SharedAbuseState, permit: RelayAbusePermit) -> Self {
        Self {
            state,
            permit: Some(permit),
        }
    }
}

impl Drop for AbusePermitGuard {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        if let Ok(mut state) = self.state.lock() {
            state.release(permit, Instant::now());
        }
    }
}

struct ActiveConnectionPermit {
    _permit: OwnedSemaphorePermit,
    status: RendezvousStreamRelayStatusHandle,
}

impl ActiveConnectionPermit {
    fn new(permit: OwnedSemaphorePermit, status: RendezvousStreamRelayStatusHandle) -> Self {
        status.record_connection_opened();
        Self {
            _permit: permit,
            status,
        }
    }
}

impl Drop for ActiveConnectionPermit {
    fn drop(&mut self) {
        self.status.record_connection_closed();
    }
}

struct PermitTrackedStream<S> {
    inner: S,
    _global_permit: ActiveConnectionPermit,
    source_bucket: RelaySourceBucket,
    abuse_state: SharedAbuseState,
    unpaired_permit: Option<AbusePermitGuard>,
    pending_permit: Option<AbusePermitGuard>,
    paired_permit: Option<AbusePermitGuard>,
}

impl<S> PermitTrackedStream<S> {
    fn new(
        inner: S,
        global_permit: ActiveConnectionPermit,
        source_bucket: RelaySourceBucket,
        abuse_state: SharedAbuseState,
        unpaired_permit: AbusePermitGuard,
    ) -> Self {
        Self {
            inner,
            _global_permit: global_permit,
            source_bucket,
            abuse_state,
            unpaired_permit: Some(unpaired_permit),
            pending_permit: None,
            paired_permit: None,
        }
    }

    fn attach_pending(&mut self, permit: AbusePermitGuard) {
        self.pending_permit = Some(permit);
    }

    fn attach_paired(&mut self, permit: AbusePermitGuard) {
        self.paired_permit = Some(permit);
    }

    fn release_unpaired(&mut self) {
        self.unpaired_permit.take();
    }

    fn release_pending(&mut self) {
        self.pending_permit.take();
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PermitTrackedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PermitTrackedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ActivityTrackedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled_before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result
            && buf.filled().len() > filled_before
        {
            self.mark_activity();
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ActivityTrackedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(bytes_written)) = &result
            && *bytes_written > 0
        {
            self.mark_activity();
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn duration_secs(duration: Duration) -> u64 {
    duration.as_secs().max(1)
}

fn nonzero_duration_or(duration: Duration, fallback: Duration) -> Duration {
    if duration.is_zero() {
        fallback
    } else {
        duration
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests;
