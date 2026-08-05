//! Isolated rendezvous relay core for the future Product A `relay_stream` path.
//!
//! This module deliberately does not expose a public listener, does not alter
//! claim/ack wire schema, and does not implement Noise. It only owns the
//! relay-visible mechanics that are safe to unit-test in isolation: redacted
//! rendezvous tokens, a minimal hello shape, one-time guest/claw pairing, and
//! opaque byte splicing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// RendezvousToken/Role/Hello (+ their errors + length bounds + hello version)
// moved to household-rs (C7c-2a token leaf, C7c-2c-2a hello codec) so the guest
// can share them; re-exported here so this module's table/pairing/splicer and
// the types' external importers (e.g. the listener) keep the same path. Only the
// leaf codec moved - the relay mechanics stay in this module.
pub use household_rs::claw_share_rendezvous_hello::{
    RENDEZVOUS_HELLO_VERSION, RendezvousHello, RendezvousHelloError, RendezvousRole,
};
pub use household_rs::claw_share_rendezvous_token::{
    MAX_RENDEZVOUS_TOKEN_LEN, MIN_RENDEZVOUS_TOKEN_LEN, RendezvousToken, RendezvousTokenError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RendezvousTokenTableConfig {
    pub max_pending: usize,
    pub token_ttl_secs: u64,
    pub max_consumed: usize,
}

impl Default for RendezvousTokenTableConfig {
    fn default() -> Self {
        Self {
            max_pending: 1024,
            token_ttl_secs: 60,
            max_consumed: 4096,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendezvousRejectReason {
    TokenConsumed,
    DuplicateRole,
    Expired,
    CapacityExceeded,
    /// The consumed table is full of UNEXPIRED spend evidence, so a new
    /// pairing cannot be recorded. Fail-closed by design: a live consumed
    /// entry is never evicted to make room, because that would let a spent
    /// token pair again inside its cooldown.
    ConsumedCapacityExceeded,
}

/// Counters proving the consumed table's fail-closed discipline. The two
/// counters are separate on purpose: a capacity reject is an admission
/// decision, an expired GC is routine hygiene. A live eviction — trading a
/// spent token's replay protection for capacity — is structurally
/// impossible: `mark_consumed` only ever inserts or rejects (see its doc
/// comment), so there is no code path left to instrument for it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RendezvousConsumedTableStats {
    /// Pairings rejected because the consumed table was full of live entries.
    pub capacity_rejects: u64,
    /// Expired consumed entries removed by GC.
    pub expired_gc: u64,
}

pub enum RendezvousOfferOutcome<S> {
    Parked,
    Paired {
        guest: S,
        claw: S,
    },
    Rejected {
        reason: RendezvousRejectReason,
        stream: S,
    },
}

struct PendingRendezvous<S> {
    inserted_at: u64,
    guest: Option<S>,
    claw: Option<S>,
}

impl<S> PendingRendezvous<S> {
    fn new(inserted_at: u64, role: RendezvousRole, stream: S) -> Self {
        match role {
            RendezvousRole::Guest => Self {
                inserted_at,
                guest: Some(stream),
                claw: None,
            },
            RendezvousRole::Claw => Self {
                inserted_at,
                guest: None,
                claw: Some(stream),
            },
        }
    }

    fn is_expired(&self, now_secs: u64, ttl_secs: u64) -> bool {
        now_secs >= self.inserted_at.saturating_add(ttl_secs)
    }
}

/// In-memory one-time rendezvous token table.
pub struct RendezvousTokenTable<S> {
    config: RendezvousTokenTableConfig,
    pending: HashMap<RendezvousToken, PendingRendezvous<S>>,
    consumed: HashMap<RendezvousToken, u64>,
    stats: RendezvousConsumedTableStats,
}

impl<S> RendezvousTokenTable<S> {
    #[must_use]
    pub fn new(config: RendezvousTokenTableConfig) -> Self {
        let config = RendezvousTokenTableConfig {
            // Keep one-time replay protection enabled even with a zero override.
            max_consumed: config.max_consumed.max(1),
            ..config
        };
        Self {
            config,
            pending: HashMap::new(),
            consumed: HashMap::new(),
            stats: RendezvousConsumedTableStats::default(),
        }
    }

    #[must_use]
    pub fn with_limits(max_pending: usize, token_ttl_secs: u64) -> Self {
        Self::new(RendezvousTokenTableConfig {
            max_pending,
            token_ttl_secs,
            max_consumed: RendezvousTokenTableConfig::default().max_consumed,
        })
    }

    #[must_use]
    pub fn with_consumed_limits(
        max_pending: usize,
        token_ttl_secs: u64,
        max_consumed: usize,
    ) -> Self {
        Self::new(RendezvousTokenTableConfig {
            max_pending,
            token_ttl_secs,
            max_consumed,
        })
    }

    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn consumed_len(&self) -> usize {
        self.consumed.len()
    }

    #[must_use]
    pub fn consumed_stats(&self) -> RendezvousConsumedTableStats {
        self.stats
    }

    pub fn prune_expired(&mut self, now_secs: u64) -> usize {
        self.prune_expired_consumed(now_secs);
        let expired: Vec<RendezvousToken> = self
            .pending
            .iter()
            .filter(|&(_token, pending)| pending.is_expired(now_secs, self.config.token_ttl_secs))
            .map(|(token, _pending)| token.clone())
            .collect();
        let expired_count = expired.len();
        for token in expired {
            self.pending.remove(&token);
            self.mark_consumed_best_effort(token, now_secs);
        }
        expired_count
    }

    fn prune_expired_consumed(&mut self, now_secs: u64) -> usize {
        let expired: Vec<RendezvousToken> = self
            .consumed
            .iter()
            .filter(|&(_token, consumed_until_secs)| now_secs >= *consumed_until_secs)
            .map(|(token, _consumed_until_secs)| token.clone())
            .collect();
        let expired_count = expired.len();
        for token in expired {
            self.consumed.remove(&token);
        }
        self.stats.expired_gc = self
            .stats
            .expired_gc
            .saturating_add(u64::try_from(expired_count).unwrap_or(u64::MAX));
        expired_count
    }

    fn is_consumed(&mut self, token: &RendezvousToken, now_secs: u64) -> bool {
        self.prune_expired_consumed(now_secs);
        self.consumed
            .get(token)
            .is_some_and(|consumed_until_secs| now_secs < *consumed_until_secs)
    }

    /// Whether a NEW consumed entry fits right now (after expired GC). The
    /// check and the subsequent `mark_consumed` in the same `&mut self` call
    /// are one atomic section: no other offer can interleave between them.
    fn consumed_has_capacity(&mut self, now_secs: u64) -> bool {
        self.prune_expired_consumed(now_secs);
        self.consumed.len() < self.config.max_consumed
    }

    /// Record spend evidence. NEVER evicts a live entry: when the table is
    /// full of unexpired evidence this returns `false` and records nothing, so
    /// the caller fails the admission closed instead of trading a spent
    /// token's replay protection for capacity.
    fn mark_consumed(&mut self, token: RendezvousToken, now_secs: u64) -> bool {
        self.prune_expired_consumed(now_secs);

        let consumed_until_secs = now_secs.saturating_add(self.config.token_ttl_secs);
        if !self.consumed.contains_key(&token) && self.consumed.len() >= self.config.max_consumed {
            return false;
        }
        self.consumed.insert(token, consumed_until_secs);
        true
    }

    /// Best-effort spend evidence for a token that expired while parked and so
    /// was NEVER paired. Unlike a completed pairing there is no spend to
    /// protect, so when the table is full the mark is simply skipped (the
    /// Noise/offer layer remains the authorization boundary). Completed
    /// pairings always go through the capacity-checked path in `offer`.
    fn mark_consumed_best_effort(&mut self, token: RendezvousToken, now_secs: u64) {
        let _ = self.mark_consumed(token, now_secs);
    }

    pub fn offer(
        &mut self,
        token: RendezvousToken,
        role: RendezvousRole,
        stream: S,
        now_secs: u64,
    ) -> RendezvousOfferOutcome<S> {
        if self.is_consumed(&token, now_secs) {
            return RendezvousOfferOutcome::Rejected {
                reason: RendezvousRejectReason::TokenConsumed,
                stream,
            };
        }

        if self
            .pending
            .get(&token)
            .is_some_and(|pending| pending.is_expired(now_secs, self.config.token_ttl_secs))
        {
            self.pending.remove(&token);
            self.mark_consumed_best_effort(token, now_secs);
            return RendezvousOfferOutcome::Rejected {
                reason: RendezvousRejectReason::Expired,
                stream,
            };
        }

        self.prune_expired(now_secs);

        if self.is_consumed(&token, now_secs) {
            return RendezvousOfferOutcome::Rejected {
                reason: RendezvousRejectReason::TokenConsumed,
                stream,
            };
        }

        if let Some(mut pending) = self.pending.remove(&token) {
            if pending.is_expired(now_secs, self.config.token_ttl_secs) {
                self.mark_consumed_best_effort(token, now_secs);
                return RendezvousOfferOutcome::Rejected {
                    reason: RendezvousRejectReason::Expired,
                    stream,
                };
            }

            let duplicate = match role {
                RendezvousRole::Guest => pending.guest.is_some(),
                RendezvousRole::Claw => pending.claw.is_some(),
            };
            if duplicate {
                self.pending.insert(token, pending);
                return RendezvousOfferOutcome::Rejected {
                    reason: RendezvousRejectReason::DuplicateRole,
                    stream,
                };
            }

            let completes_pair = match role {
                RendezvousRole::Guest => pending.claw.is_some(),
                RendezvousRole::Claw => pending.guest.is_some(),
            };
            if completes_pair {
                // Atomic with the mark below (same &mut self call): the
                // capacity check, the rejection, or the spend record cannot
                // interleave with another offer.
                if !self.consumed_has_capacity(now_secs) {
                    self.stats.capacity_rejects = self.stats.capacity_rejects.saturating_add(1);
                    self.pending.insert(token, pending);
                    return RendezvousOfferOutcome::Rejected {
                        reason: RendezvousRejectReason::ConsumedCapacityExceeded,
                        stream,
                    };
                }
                let parked = match role {
                    RendezvousRole::Guest => pending.claw.take(),
                    RendezvousRole::Claw => pending.guest.take(),
                };
                let recorded = self.mark_consumed(token, now_secs);
                debug_assert!(recorded, "capacity was confirmed atomically above");
                return match (role, parked) {
                    (RendezvousRole::Guest, Some(claw)) => RendezvousOfferOutcome::Paired {
                        guest: stream,
                        claw,
                    },
                    (RendezvousRole::Claw, Some(guest)) => RendezvousOfferOutcome::Paired {
                        guest,
                        claw: stream,
                    },
                    _ => unreachable!("completes_pair guarantees the opposite role is parked"),
                };
            }

            match role {
                RendezvousRole::Guest => pending.guest = Some(stream),
                RendezvousRole::Claw => pending.claw = Some(stream),
            }
            self.pending.insert(token, pending);
            return RendezvousOfferOutcome::Parked;
        }

        if self.pending.len() >= self.config.max_pending {
            return RendezvousOfferOutcome::Rejected {
                reason: RendezvousRejectReason::CapacityExceeded,
                stream,
            };
        }

        self.pending
            .insert(token, PendingRendezvous::new(now_secs, role, stream));
        RendezvousOfferOutcome::Parked
    }

    /// Return whether an offer would park a new stream rather than pair.
    ///
    /// This mirrors the preconditions in [`Self::offer`] while the caller still
    /// owns the stream, allowing the public listener to acquire a source pending
    /// permit only for streams that will actually be parked. The method may
    /// prune expired entries or mark an expired token as consumed, but it does
    /// not insert the caller's stream.
    pub fn offer_would_park(
        &mut self,
        token: &RendezvousToken,
        role: RendezvousRole,
        now_secs: u64,
    ) -> Result<bool, RendezvousRejectReason> {
        if self.is_consumed(token, now_secs) {
            return Err(RendezvousRejectReason::TokenConsumed);
        }

        if self
            .pending
            .get(token)
            .is_some_and(|pending| pending.is_expired(now_secs, self.config.token_ttl_secs))
        {
            self.pending.remove(token);
            self.mark_consumed_best_effort(token.clone(), now_secs);
            return Err(RendezvousRejectReason::Expired);
        }

        self.prune_expired(now_secs);

        if self.is_consumed(token, now_secs) {
            return Err(RendezvousRejectReason::TokenConsumed);
        }

        if let Some(pending) = self.pending.get(token) {
            if pending.is_expired(now_secs, self.config.token_ttl_secs) {
                self.pending.remove(token);
                self.mark_consumed_best_effort(token.clone(), now_secs);
                return Err(RendezvousRejectReason::Expired);
            }
            let completes_pair = match role {
                RendezvousRole::Guest if pending.guest.is_some() => {
                    return Err(RendezvousRejectReason::DuplicateRole);
                }
                RendezvousRole::Claw if pending.claw.is_some() => {
                    return Err(RendezvousRejectReason::DuplicateRole);
                }
                RendezvousRole::Guest => pending.claw.is_some(),
                RendezvousRole::Claw => pending.guest.is_some(),
            };
            if completes_pair && !self.consumed_has_capacity(now_secs) {
                // Mirrors `offer`: a pairing that cannot record its spend
                // evidence must fail closed here, before the caller acquires
                // any per-source permit for the stream.
                self.stats.capacity_rejects = self.stats.capacity_rejects.saturating_add(1);
                return Err(RendezvousRejectReason::ConsumedCapacityExceeded);
            }
            return Ok(false);
        }

        if self.pending.len() >= self.config.max_pending {
            return Err(RendezvousRejectReason::CapacityExceeded);
        }

        Ok(true)
    }
}

impl<S> Default for RendezvousTokenTable<S> {
    fn default() -> Self {
        Self::new(RendezvousTokenTableConfig::default())
    }
}

/// Direction that first exceeded the per-direction splice byte cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceByteCapDirection {
    GuestToClaw,
    ClawToGuest,
}

/// Terminal state of a capped splice: how many bytes were forwarded in each
/// direction, and which direction (if any) hit the byte cap and forced the
/// hard close. `capped_direction == None` is an ordinary EOF close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpliceCappedOutcome {
    pub guest_to_claw: u64,
    pub claw_to_guest: u64,
    pub capped_direction: Option<SpliceByteCapDirection>,
}

/// OBSERVATIONAL byte ledger, shared with the caller. Telemetry only.
///
/// It exists because a splice can end by CANCELLATION: the caller races this
/// pump against idle/lifetime timers in a `select!`, and when a timer wins the
/// pump's future is dropped, taking its local [`SpliceCappedOutcome`] with it.
/// Anything the caller wants to report on those paths has to live outside the
/// future. This is that outside.
///
/// **It is not the enforcement ledger and must never become one.** The budget
/// and the hard close are decided exclusively from the pump's LOCAL counters
/// (see `splice_opaque_streams_capped`), so zeroing, resetting, or entirely
/// losing this ledger cannot move the byte at which the cap fires. Reading it
/// to make an admission decision would re-couple the two and reintroduce a
/// fail-OPEN: a telemetry reset would hand the direction a fresh budget.
#[derive(Debug, Default)]
pub struct SpliceByteLedger {
    guest_to_claw: AtomicU64,
    claw_to_guest: AtomicU64,
}

impl SpliceByteLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes forwarded so far, per direction. Safe to call at any time,
    /// including while the pump is still running — that is the point.
    #[must_use]
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.guest_to_claw.load(AtomicOrdering::Relaxed),
            self.claw_to_guest.load(AtomicOrdering::Relaxed),
        )
    }

    fn add_guest_to_claw(&self, bytes: u64) {
        self.guest_to_claw.fetch_add(bytes, AtomicOrdering::Relaxed);
    }

    fn add_claw_to_guest(&self, bytes: u64) {
        self.claw_to_guest.fetch_add(bytes, AtomicOrdering::Relaxed);
    }

    /// Mutation instrument: wipe the observational ledger mid-splice. Test-only
    /// because production has no reason to reset telemetry — its whole purpose
    /// is to prove that doing so does NOT disturb enforcement.
    #[cfg(test)]
    pub(crate) fn reset(&self) {
        self.guest_to_claw.store(0, AtomicOrdering::Relaxed);
        self.claw_to_guest.store(0, AtomicOrdering::Relaxed);
    }
}

/// Which direction a write through [`LedgerCountingStream`] belongs to.
#[derive(Debug, Clone, Copy)]
enum LedgerDirection {
    GuestToClaw,
    ClawToGuest,
}

/// Mirrors every ACCEPTED write into the observational ledger at `poll_write`
/// granularity.
///
/// Counting after `write_all().await?` instead would be wrong on exactly the
/// paths this ledger exists for: `write_all` is a loop over `poll_write` and is
/// NOT cancellation-safe, so when an idle/lifetime timer wins the `select!`
/// mid-write, every byte an earlier `poll_write` already accepted is dropped
/// along with the future — invisible forever. Counting per poll keeps that
/// tail.
///
/// "Accepted" is the honest ceiling here: it means this `AsyncWrite`
/// took the bytes, NOT that the peer or the application consumed them. Flush is
/// deliberately not the boundary — it would both under-count (a cancel between
/// write and flush loses the same tail) and over-promise.
///
/// Reads pass straight through, untouched and uncounted.
struct LedgerCountingStream<'a, S> {
    inner: S,
    ledger: &'a SpliceByteLedger,
    direction: LedgerDirection,
}

impl<S: AsyncRead + Unpin> AsyncRead for LedgerCountingStream<'_, S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for LedgerCountingStream<'_, S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let poll = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(written)) = &poll {
            let written = u64::try_from(*written).unwrap_or(u64::MAX);
            match self.direction {
                LedgerDirection::GuestToClaw => self.ledger.add_guest_to_claw(written),
                LedgerDirection::ClawToGuest => self.ledger.add_claw_to_guest(written),
            }
        }
        poll
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

const SPLICE_CHUNK: usize = 16 * 1024;

/// Splice two already-protected opaque streams with an optional per-direction
/// byte cap.
///
/// The relay stays blind: bytes are counted, never parsed. `None` is the
/// legacy unlimited behavior (byte-identical to `copy_bidirectional`); the cap
/// is a POLICY of the public relay, not of this transport. When set, the cap
/// counts FORWARDED bytes per direction, checked BEFORE forwarding: a
/// direction may deliver exactly the cap; the arrival of byte B+1 delivers
/// nothing more and hard-closes the whole splice with the offending direction
/// attributed in the outcome. EOF on one side shuts down the opposite writer
/// and drains the other direction, mirroring `copy_bidirectional`.
pub async fn splice_opaque_streams_capped<A, B>(
    guest: A,
    claw: B,
    max_bytes_per_direction: Option<u64>,
    ledger: &SpliceByteLedger,
) -> io::Result<SpliceCappedOutcome>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    // Writes are counted at poll granularity by these wrappers, NOT after
    // `write_all` returns — see `LedgerCountingStream`. A write INTO `claw` is
    // guest->claw traffic, and vice versa.
    let mut guest = LedgerCountingStream {
        inner: guest,
        ledger,
        direction: LedgerDirection::ClawToGuest,
    };
    let mut claw = LedgerCountingStream {
        inner: claw,
        ledger,
        direction: LedgerDirection::GuestToClaw,
    };
    let mut guest_buf = vec![0_u8; SPLICE_CHUNK];
    let mut claw_buf = vec![0_u8; SPLICE_CHUNK];
    let mut outcome = SpliceCappedOutcome {
        guest_to_claw: 0,
        claw_to_guest: 0,
        capped_direction: None,
    };
    let mut guest_eof = false;
    let mut claw_eof = false;

    loop {
        if guest_eof && claw_eof {
            return Ok(outcome);
        }
        tokio::select! {
            read = guest.read(&mut guest_buf), if !guest_eof => {
                let n = read?;
                if n == 0 {
                    guest_eof = true;
                    claw.shutdown().await?;
                    continue;
                }
                // ENFORCEMENT reads the LOCAL counter, never the shared ledger.
                // That is what keeps a telemetry reset from handing this
                // direction a fresh budget.
                let forward = match max_bytes_per_direction {
                    Some(cap) => usize::try_from(cap.saturating_sub(outcome.guest_to_claw))
                        .unwrap_or(usize::MAX)
                        .min(n),
                    None => n,
                };
                if forward > 0 {
                    claw.write_all(&guest_buf[..forward]).await?;
                    claw.flush().await?;
                    // ENFORCEMENT only. The observational ledger was already
                    // credited per accepted poll_write inside the wrapper, so
                    // it is deliberately NOT touched here — doing both would
                    // double-count.
                    outcome.guest_to_claw += u64::try_from(forward).unwrap_or(u64::MAX);
                }
                if forward < n {
                    outcome.capped_direction = Some(SpliceByteCapDirection::GuestToClaw);
                    return Ok(outcome);
                }
            }
            read = claw.read(&mut claw_buf), if !claw_eof => {
                let n = read?;
                if n == 0 {
                    claw_eof = true;
                    guest.shutdown().await?;
                    continue;
                }
                // Same rule as the opposite direction: enforcement is local.
                let forward = match max_bytes_per_direction {
                    Some(cap) => usize::try_from(cap.saturating_sub(outcome.claw_to_guest))
                        .unwrap_or(usize::MAX)
                        .min(n),
                    None => n,
                };
                if forward > 0 {
                    guest.write_all(&claw_buf[..forward]).await?;
                    guest.flush().await?;
                    // Enforcement only; the wrapper already credited telemetry.
                    outcome.claw_to_guest += u64::try_from(forward).unwrap_or(u64::MAX);
                }
                if forward < n {
                    outcome.capped_direction = Some(SpliceByteCapDirection::ClawToGuest);
                    return Ok(outcome);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Spawn the pump with its own observational ledger, handing back both so a
    /// test can compare what the ledger saw against the outcome the pump
    /// returned. The `Arc` is moved INTO the task so the spawned future stays
    /// `'static` while the caller keeps a handle on the same ledger.
    fn spawn_capped_splice<A, B>(
        guest: A,
        claw: B,
        cap: Option<u64>,
    ) -> (
        tokio::task::JoinHandle<io::Result<SpliceCappedOutcome>>,
        Arc<SpliceByteLedger>,
    )
    where
        A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let ledger = Arc::new(SpliceByteLedger::new());
        let task_ledger = Arc::clone(&ledger);
        let handle = tokio::spawn(async move {
            splice_opaque_streams_capped(guest, claw, cap, &task_ledger).await
        });
        (handle, ledger)
    }

    /// Splice two already-protected opaque streams, with no byte cap.
    ///
    /// Test-only: the production public relay must never expose an uncapped
    /// splice entry point (see `splice_opaque_streams_capped`, which is what
    /// every real caller — `splice_opaque_streams_until_idle` in the
    /// listener — actually uses). This exists solely so
    /// `rendezvous_stream_splice_passes_opaque_bytes_both_directions` below
    /// can exercise the transport's blind byte-forwarding behavior without
    /// the cap machinery in the way.
    async fn splice_opaque_streams<A, B>(mut guest: A, mut claw: B) -> io::Result<(u64, u64)>
    where
        A: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::io::copy_bidirectional(&mut guest, &mut claw).await
    }

    fn token(label: u8) -> RendezvousToken {
        RendezvousToken::try_new(vec![label; 16]).unwrap()
    }

    fn pair_token(
        table: &mut RendezvousTokenTable<&'static str>,
        token: RendezvousToken,
        now: u64,
    ) {
        assert!(matches!(
            table.offer(token.clone(), RendezvousRole::Guest, "guest", now),
            RendezvousOfferOutcome::Parked
        ));
        assert!(matches!(
            table.offer(token, RendezvousRole::Claw, "claw", now + 1),
            RendezvousOfferOutcome::Paired { .. }
        ));
    }

    #[test]
    fn rendezvous_stream_token_empty_and_too_large_rejected() {
        assert_eq!(
            RendezvousToken::try_new([]).unwrap_err(),
            RendezvousTokenError::Empty
        );
        assert_eq!(
            RendezvousToken::try_new(vec![0x11; MIN_RENDEZVOUS_TOKEN_LEN - 1]).unwrap_err(),
            RendezvousTokenError::TooSmall {
                actual: MIN_RENDEZVOUS_TOKEN_LEN - 1,
                min: MIN_RENDEZVOUS_TOKEN_LEN,
            }
        );
        assert_eq!(
            RendezvousToken::try_new(vec![0x11; MAX_RENDEZVOUS_TOKEN_LEN + 1]).unwrap_err(),
            RendezvousTokenError::TooLarge {
                actual: MAX_RENDEZVOUS_TOKEN_LEN + 1,
                max: MAX_RENDEZVOUS_TOKEN_LEN,
            }
        );
    }

    #[test]
    fn rendezvous_stream_token_debug_and_display_are_redacted() {
        let raw = b"0123456789abcdef0123456789abcdef";
        let token = RendezvousToken::try_new(raw).unwrap();
        let debug = format!("{token:?}");
        let display = token.to_string();
        let raw_text = String::from_utf8_lossy(raw);

        assert!(!debug.contains(raw_text.as_ref()));
        assert!(!display.contains(raw_text.as_ref()));
        assert!(debug.contains("redacted"));
        assert!(display.contains("redacted"));
    }

    #[test]
    fn rendezvous_stream_guest_and_claw_same_token_pair() {
        let mut table = RendezvousTokenTable::with_limits(8, 60);
        let token = token(0x01);

        assert!(matches!(
            table.offer(token.clone(), RendezvousRole::Guest, "guest", 100),
            RendezvousOfferOutcome::Parked
        ));
        match table.offer(token, RendezvousRole::Claw, "claw", 101) {
            RendezvousOfferOutcome::Paired { guest, claw } => {
                assert_eq!(guest, "guest");
                assert_eq!(claw, "claw");
            }
            _ => panic!("guest and claw should pair"),
        }
        assert_eq!(table.pending_len(), 0);
        assert_eq!(table.consumed_len(), 1);
    }

    #[test]
    fn rendezvous_stream_duplicate_same_role_rejected_without_consuming_pending() {
        let mut table = RendezvousTokenTable::with_limits(8, 60);
        let token = token(0x02);

        assert!(matches!(
            table.offer(token.clone(), RendezvousRole::Claw, "claw-a", 100),
            RendezvousOfferOutcome::Parked
        ));
        match table.offer(token.clone(), RendezvousRole::Claw, "claw-b", 101) {
            RendezvousOfferOutcome::Rejected { reason, stream } => {
                assert_eq!(reason, RendezvousRejectReason::DuplicateRole);
                assert_eq!(stream, "claw-b");
            }
            _ => panic!("duplicate claw should reject"),
        }
        match table.offer(token, RendezvousRole::Guest, "guest", 102) {
            RendezvousOfferOutcome::Paired { guest, claw } => {
                assert_eq!(guest, "guest");
                assert_eq!(claw, "claw-a");
            }
            _ => panic!("pending original claw should still pair"),
        }
    }

    #[test]
    fn rendezvous_stream_token_expires_and_does_not_pair() {
        let mut table = RendezvousTokenTable::with_limits(8, 5);
        let token = token(0x03);

        assert!(matches!(
            table.offer(token.clone(), RendezvousRole::Claw, "claw", 100),
            RendezvousOfferOutcome::Parked
        ));
        match table.offer(token.clone(), RendezvousRole::Guest, "guest", 105) {
            RendezvousOfferOutcome::Rejected { reason, stream } => {
                assert_eq!(reason, RendezvousRejectReason::Expired);
                assert_eq!(stream, "guest");
            }
            _ => panic!("expired token must reject"),
        }
        match table.offer(token, RendezvousRole::Claw, "claw-reuse", 106) {
            RendezvousOfferOutcome::Rejected { reason, stream } => {
                assert_eq!(reason, RendezvousRejectReason::TokenConsumed);
                assert_eq!(stream, "claw-reuse");
            }
            _ => panic!("expired token must not be reusable"),
        }
    }

    #[test]
    fn rendezvous_stream_capacity_limit_is_enforced() {
        let mut table = RendezvousTokenTable::with_limits(1, 60);

        assert!(matches!(
            table.offer(token(0x04), RendezvousRole::Guest, "guest-a", 100),
            RendezvousOfferOutcome::Parked
        ));
        match table.offer(token(0x05), RendezvousRole::Guest, "guest-b", 101) {
            RendezvousOfferOutcome::Rejected { reason, stream } => {
                assert_eq!(reason, RendezvousRejectReason::CapacityExceeded);
                assert_eq!(stream, "guest-b");
            }
            _ => panic!("second pending token should exceed capacity"),
        }
    }

    #[test]
    fn rendezvous_stream_offer_would_park_matches_table_preconditions() {
        let mut table = RendezvousTokenTable::with_limits(1, 5);
        let parked = token(0x44);

        assert_eq!(
            table.offer_would_park(&parked, RendezvousRole::Guest, 100),
            Ok(true)
        );
        assert!(matches!(
            table.offer(parked.clone(), RendezvousRole::Guest, "guest-a", 100),
            RendezvousOfferOutcome::Parked
        ));
        assert_eq!(
            table.offer_would_park(&parked, RendezvousRole::Claw, 101),
            Ok(false)
        );
        assert_eq!(
            table.offer_would_park(&parked, RendezvousRole::Guest, 101),
            Err(RendezvousRejectReason::DuplicateRole)
        );
        assert_eq!(
            table.offer_would_park(&token(0x45), RendezvousRole::Guest, 101),
            Err(RendezvousRejectReason::CapacityExceeded)
        );
        assert_eq!(
            table.offer_would_park(&parked, RendezvousRole::Claw, 106),
            Err(RendezvousRejectReason::Expired)
        );
        assert_eq!(
            table.offer_would_park(&parked, RendezvousRole::Guest, 107),
            Err(RendezvousRejectReason::TokenConsumed)
        );
    }

    #[test]
    fn rendezvous_stream_paired_token_cannot_be_reused() {
        let mut table = RendezvousTokenTable::with_limits(8, 60);
        let token = token(0x06);

        assert!(matches!(
            table.offer(token.clone(), RendezvousRole::Guest, "guest", 100),
            RendezvousOfferOutcome::Parked
        ));
        assert!(matches!(
            table.offer(token.clone(), RendezvousRole::Claw, "claw", 101),
            RendezvousOfferOutcome::Paired { .. }
        ));
        match table.offer(token, RendezvousRole::Guest, "guest-reuse", 102) {
            RendezvousOfferOutcome::Rejected { reason, stream } => {
                assert_eq!(reason, RendezvousRejectReason::TokenConsumed);
                assert_eq!(stream, "guest-reuse");
            }
            _ => panic!("paired token must not be reusable"),
        }
    }

    #[test]
    fn rendezvous_stream_zero_max_consumed_still_rejects_replay() {
        let mut table = RendezvousTokenTable::with_consumed_limits(8, 60, 0);
        let token = token(0x07);

        pair_token(&mut table, token.clone(), 100);
        assert_eq!(table.consumed_len(), 1);

        match table.offer(token, RendezvousRole::Guest, "guest-reuse", 102) {
            RendezvousOfferOutcome::Rejected { reason, stream } => {
                assert_eq!(reason, RendezvousRejectReason::TokenConsumed);
                assert_eq!(stream, "guest-reuse");
            }
            _ => panic!("zero max_consumed override must not disable one-time replay protection"),
        }
    }

    #[test]
    fn rendezvous_stream_consumed_tokens_are_pruned_and_bounded() {
        let mut table = RendezvousTokenTable::with_consumed_limits(8, 5, 2);
        pair_token(&mut table, token(0x08), 100);
        assert_eq!(table.consumed_len(), 1);

        assert!(matches!(
            table.offer(token(0x09), RendezvousRole::Guest, "guest-new", 106),
            RendezvousOfferOutcome::Parked
        ));
        assert_eq!(table.consumed_len(), 0);

        // Bounded by fail-closed capacity, never by live eviction: the third
        // pairing is REFUSED and both earlier tokens keep rejecting.
        let mut table = RendezvousTokenTable::with_consumed_limits(8, 60, 2);
        pair_token(&mut table, token(0x0a), 202);
        pair_token(&mut table, token(0x0b), 204);
        match table.offer(token(0x0c), RendezvousRole::Guest, "guest-c", 206) {
            RendezvousOfferOutcome::Parked => {}
            _ => panic!("first side of the third token must still park"),
        }
        match table.offer(token(0x0c), RendezvousRole::Claw, "claw-c", 207) {
            RendezvousOfferOutcome::Rejected { reason, stream } => {
                assert_eq!(reason, RendezvousRejectReason::ConsumedCapacityExceeded);
                assert_eq!(stream, "claw-c");
            }
            _ => panic!("third pairing beyond live capacity must fail closed"),
        }
        assert_eq!(table.consumed_len(), 2);
        for spent in [token(0x0a), token(0x0b)] {
            match table.offer(spent, RendezvousRole::Guest, "guest-reuse", 208) {
                RendezvousOfferOutcome::Rejected { reason, .. } => {
                    assert_eq!(reason, RendezvousRejectReason::TokenConsumed);
                }
                _ => panic!("every live consumed token must keep rejecting"),
            }
        }
    }

    /// The deterministic successor of the redial-evidence RED (test H): a
    /// two-entry consumed table, three pairings, no clock manipulation. The
    /// OLD implementation evicted the victim's cooldown entry and let it pair
    /// again 6s into a 3600s cooldown; this test is RED against that behavior
    /// on every one of the eight conditions.
    #[test]
    fn consumed_table_fails_closed_at_capacity_and_never_evicts_live() {
        let mut table = RendezvousTokenTable::with_consumed_limits(8, 3600, 2);
        let victim = token(0xa0);
        let other = token(0xb0);
        let late = token(0xc0);

        // 1. Victim A consumed at t=100.
        pair_token(&mut table, victim.clone(), 100);
        // 2. A rejected at t=101.
        match table.offer(victim.clone(), RendezvousRole::Guest, "reuse-101", 101) {
            RendezvousOfferOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, RendezvousRejectReason::TokenConsumed)
            }
            _ => panic!("victim must reject inside its cooldown"),
        }
        // 3. B admitted and consumed.
        pair_token(&mut table, other.clone(), 102);
        assert_eq!(table.consumed_len(), 2);
        // 4. Admitting C beyond capacity returns the explicit fail-closed
        //    reason, on BOTH the precheck and the offer paths. (C parks at
        //    t=200 so its pending outlives both cooldowns below.)
        assert_eq!(
            table.offer_would_park(&late, RendezvousRole::Guest, 200),
            Ok(true)
        );
        assert!(matches!(
            table.offer(late.clone(), RendezvousRole::Guest, "guest-c", 200),
            RendezvousOfferOutcome::Parked
        ));
        assert_eq!(
            table.offer_would_park(&late, RendezvousRole::Claw, 201),
            Err(RendezvousRejectReason::ConsumedCapacityExceeded)
        );
        match table.offer(late.clone(), RendezvousRole::Claw, "claw-c", 201) {
            RendezvousOfferOutcome::Rejected { reason, stream } => {
                assert_eq!(reason, RendezvousRejectReason::ConsumedCapacityExceeded);
                assert_eq!(stream, "claw-c");
            }
            _ => panic!("pairing beyond live consumed capacity must fail closed"),
        }
        // 5. No LIVE entry was evicted: both spent tokens are still recorded.
        assert_eq!(table.consumed_len(), 2);
        // 6. A still rejected at t=106 (6s into a 3600s cooldown).
        match table.offer(victim.clone(), RendezvousRole::Guest, "reuse-106", 106) {
            RendezvousOfferOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, RendezvousRejectReason::TokenConsumed)
            }
            _ => panic!("victim must still reject at +6s of a 3600s cooldown"),
        }
        // 6b. The rejected pairing preserved the parked half: after GC frees
        //     capacity, the SAME parked guest can complete the pair.
        // 7. After A's REAL expiry, GC removes expired entries only, and a
        //    fresh admission succeeds. A's cooldown ends at 3700, B's at
        //    3702; C's pending (parked at t=200, ttl 3600) is still alive.
        let after_expiry = 102 + 3600 + 1;
        table.prune_expired(after_expiry);
        assert_eq!(table.consumed_len(), 0);
        match table.offer(late, RendezvousRole::Claw, "claw-c-retry", after_expiry) {
            RendezvousOfferOutcome::Paired { guest, claw } => {
                assert_eq!(guest, "guest-c");
                assert_eq!(claw, "claw-c-retry");
            }
            _ => panic!("parked half must pair once expired GC frees capacity"),
        }
        // 8. Counters prove the two disciplines separately.
        let stats = table.consumed_stats();
        assert_eq!(stats.capacity_rejects, 2, "precheck + offer rejections");
        assert!(
            stats.expired_gc >= 2,
            "expired GC collected the two spent tokens"
        );
    }

    #[test]
    fn consumed_capacity_boundary_is_exact() {
        let mut table = RendezvousTokenTable::with_consumed_limits(8, 60, 1);
        // len == max - 1: the pairing fits and is recorded.
        pair_token(&mut table, token(0xd0), 100);
        assert_eq!(table.consumed_len(), 1);
        // len == max: the next pairing is the one that fails closed.
        assert!(matches!(
            table.offer(token(0xd1), RendezvousRole::Guest, "guest", 101),
            RendezvousOfferOutcome::Parked
        ));
        match table.offer(token(0xd1), RendezvousRole::Claw, "claw", 102) {
            RendezvousOfferOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, RendezvousRejectReason::ConsumedCapacityExceeded)
            }
            _ => panic!("the entry AT the boundary must fail closed"),
        }
    }

    #[tokio::test]
    async fn consumed_capacity_holds_under_concurrent_offers() {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let table = Arc::new(Mutex::new(RendezvousTokenTable::with_consumed_limits(
            64, 3600, 2,
        )));
        let mut tasks = Vec::new();
        for index in 0u8..8 {
            let table = Arc::clone(&table);
            tasks.push(tokio::spawn(async move {
                let guest_token = token(0xe0 + index);
                let mut table = table.lock().await;
                // Park + pair inside ONE lock hold, mirroring the listener's
                // would_park -> offer critical section.
                let parked = table.offer(
                    guest_token.clone(),
                    RendezvousRole::Guest,
                    format!("guest-{index}"),
                    100,
                );
                let paired = table.offer(
                    guest_token,
                    RendezvousRole::Claw,
                    format!("claw-{index}"),
                    101,
                );
                (matches!(parked, RendezvousOfferOutcome::Parked), paired)
            }));
        }
        let mut pairings = 0;
        let mut capacity_rejects = 0;
        for task in tasks {
            let (parked, paired) = task.await.unwrap();
            assert!(parked, "every first side must park");
            match paired {
                RendezvousOfferOutcome::Paired { .. } => pairings += 1,
                RendezvousOfferOutcome::Rejected { reason, .. } => {
                    assert_eq!(reason, RendezvousRejectReason::ConsumedCapacityExceeded);
                    capacity_rejects += 1;
                }
                _ => panic!("concurrent offers must either pair or fail closed"),
            }
        }
        let table = table.lock().await;
        assert_eq!(pairings, 2, "exactly max_consumed pairings may succeed");
        assert_eq!(capacity_rejects, 6);
        let stats = table.consumed_stats();
        assert_eq!(stats.capacity_rejects, 6);
        assert_eq!(table.consumed_len(), 2);
    }

    #[tokio::test]
    async fn rendezvous_stream_splice_passes_opaque_bytes_both_directions() {
        let (mut guest_client, guest_relay) = tokio::io::duplex(128);
        let (claw_relay, mut claw_client) = tokio::io::duplex(128);
        let splice = tokio::spawn(splice_opaque_streams(guest_relay, claw_relay));

        let guest_payload = b"\x00opaque-from-guest\xff";
        guest_client.write_all(guest_payload).await.unwrap();
        let mut from_guest = vec![0; guest_payload.len()];
        claw_client.read_exact(&mut from_guest).await.unwrap();
        assert_eq!(from_guest, guest_payload);

        let claw_payload = b"\xfeopaque-from-claw\x00";
        claw_client.write_all(claw_payload).await.unwrap();
        let mut from_claw = vec![0; claw_payload.len()];
        guest_client.read_exact(&mut from_claw).await.unwrap();
        assert_eq!(from_claw, claw_payload);

        guest_client.shutdown().await.unwrap();
        claw_client.shutdown().await.unwrap();
        let copied = tokio::time::timeout(std::time::Duration::from_secs(2), splice)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(copied.0 >= guest_payload.len() as u64);
        assert!(copied.1 >= claw_payload.len() as u64);
    }

    // Exactly B bytes in a direction flows; EOF closes cleanly, nothing capped.
    #[tokio::test]
    async fn splice_capped_forwards_exactly_cap_and_closes_on_eof() {
        let cap = 1024_u64;
        let (mut guest_client, guest_relay) = tokio::io::duplex(4096);
        let (claw_relay, mut claw_client) = tokio::io::duplex(4096);
        let (splice, ledger) = spawn_capped_splice(guest_relay, claw_relay, Some(cap));

        guest_client.write_all(&vec![0xaa; 1024]).await.unwrap();
        guest_client.shutdown().await.unwrap();
        let mut received = Vec::new();
        claw_client.read_to_end(&mut received).await.unwrap();
        claw_client.shutdown().await.unwrap();

        assert_eq!(received.len(), 1024);
        let outcome = splice.await.unwrap().unwrap();
        assert_eq!(outcome.guest_to_claw, 1024);
        assert_eq!(outcome.claw_to_guest, 0);
        assert_eq!(outcome.capped_direction, None);
        // The observational ledger mirrors the enforcement counters exactly.
        // Asserted on every pump test so a drifting mirror is caught here,
        // where the cause is obvious, rather than at the status layer.
        assert_eq!(
            ledger.snapshot(),
            (outcome.guest_to_claw, outcome.claw_to_guest)
        );
    }

    // Byte B+1 (guest -> claw) is never delivered: exactly B arrive, hard
    // close, direction attributed.
    #[tokio::test]
    async fn splice_capped_never_delivers_byte_b_plus_one_guest_to_claw() {
        let cap = 1024_u64;
        let (mut guest_client, guest_relay) = tokio::io::duplex(4096);
        let (claw_relay, mut claw_client) = tokio::io::duplex(4096);
        let (splice, ledger) = spawn_capped_splice(guest_relay, claw_relay, Some(cap));

        guest_client.write_all(&vec![0xbb; 1025]).await.unwrap();
        let mut received = vec![0_u8; 1024];
        claw_client.read_exact(&mut received).await.unwrap();
        assert!(received.iter().all(|byte| *byte == 0xbb));
        // Hard close: nothing more, ever — the B+1 byte did not cross.
        let mut extra = [0_u8; 1];
        let n = claw_client.read(&mut extra).await.unwrap();
        assert_eq!(n, 0, "byte B+1 must never be delivered");

        let outcome = splice.await.unwrap().unwrap();
        assert_eq!(outcome.guest_to_claw, 1024);
        assert_eq!(outcome.claw_to_guest, 0);
        assert_eq!(
            outcome.capped_direction,
            Some(SpliceByteCapDirection::GuestToClaw)
        );
        assert_eq!(
            ledger.snapshot(),
            (outcome.guest_to_claw, outcome.claw_to_guest),
            "the ledger must stop where enforcement stopped: byte B+1 is in neither"
        );
    }

    // Same cap, opposite direction (claw -> guest).
    #[tokio::test]
    async fn splice_capped_never_delivers_byte_b_plus_one_claw_to_guest() {
        let cap = 1024_u64;
        let (mut guest_client, guest_relay) = tokio::io::duplex(4096);
        let (mut claw_relay_client, claw_relay) = tokio::io::duplex(4096);
        let (splice, ledger) = spawn_capped_splice(guest_relay, claw_relay, Some(cap));

        claw_relay_client
            .write_all(&vec![0xcc; 1025])
            .await
            .unwrap();
        let mut received = vec![0_u8; 1024];
        guest_client.read_exact(&mut received).await.unwrap();
        assert!(received.iter().all(|byte| *byte == 0xcc));
        let mut extra = [0_u8; 1];
        let n = guest_client.read(&mut extra).await.unwrap();
        assert_eq!(n, 0, "byte B+1 must never be delivered");

        let outcome = splice.await.unwrap().unwrap();
        assert_eq!(outcome.guest_to_claw, 0);
        assert_eq!(outcome.claw_to_guest, 1024);
        assert_eq!(
            outcome.capped_direction,
            Some(SpliceByteCapDirection::ClawToGuest)
        );
        assert_eq!(
            ledger.snapshot(),
            (outcome.guest_to_claw, outcome.claw_to_guest),
            "same in the opposite direction"
        );
    }

    /// A writer that accepts exactly `accept_first` bytes on its first
    /// `poll_write` and then blocks forever. Reproduces the partial-write
    /// shape a real socket produces under backpressure, which a cooperative
    /// `duplex` never does.
    struct FragmentThenBlockWriter {
        accept_first: usize,
        accepted: bool,
    }

    impl AsyncRead for FragmentThenBlockWriter {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            // Never EOF, never data: keeps the pump alive so the timer decides.
            std::task::Poll::Pending
        }
    }

    impl AsyncWrite for FragmentThenBlockWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            if self.accepted {
                return std::task::Poll::Pending;
            }
            self.accepted = true;
            std::task::Poll::Ready(Ok(self.accept_first.min(buf.len())))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    /// ADVERSARIAL: a partial write that is then CANCELLED must still be
    /// visible in telemetry.
    ///
    /// `write_all` is a loop over `poll_write` and is not cancellation-safe.
    /// The writer here accepts a 300-byte fragment and then blocks, so
    /// `write_all` is still in flight when the timer wins the `select!` and
    /// drops the pump. Counting after `write_all` returns — the shape this
    /// slice originally shipped — reports 0 for that splice and loses the
    /// fragment permanently. Counting per accepted `poll_write` keeps it.
    #[tokio::test]
    async fn a_cancelled_partial_write_still_reaches_the_ledger() {
        let (mut guest_client, guest_relay) = tokio::io::duplex(8192);
        let claw = FragmentThenBlockWriter {
            accept_first: 300,
            accepted: false,
        };
        let ledger = SpliceByteLedger::new();

        // More than the writer will ever accept, so write_all cannot complete.
        guest_client.write_all(&vec![0x5a; 4096]).await.unwrap();

        let outcome = tokio::select! {
            spliced = splice_opaque_streams_capped(guest_relay, claw, None, &ledger) => {
                Some(spliced)
            }
            () = tokio::time::sleep(std::time::Duration::from_millis(120)) => None,
        };

        assert!(
            outcome.is_none(),
            "the timer must win: the writer blocks forever, so the pump cannot finish"
        );
        assert_eq!(
            ledger.snapshot(),
            (300, 0),
            "the accepted fragment must survive the cancellation"
        );
    }

    // THE load-bearing separation test. Wiping the observational ledger while
    // the splice is running must not move the byte at which the cap fires.
    //
    // This is what stops anyone later "simplifying" the two ledgers back into
    // one: if enforcement read the shared ledger, the reset below would hand
    // guest->claw a fresh budget and the pump would forward MORE than the cap
    // — a fail-open. The assertions are on the enforcement side (delivered
    // bytes and the capped direction), so a single-ledger implementation
    // cannot pass them no matter what the telemetry says afterwards.
    #[tokio::test]
    async fn resetting_the_telemetry_ledger_midsplice_does_not_move_the_hard_close() {
        let cap = 1024_u64;
        let (mut guest_client, guest_relay) = tokio::io::duplex(8192);
        let (claw_relay, mut claw_client) = tokio::io::duplex(8192);
        let (splice, ledger) = spawn_capped_splice(guest_relay, claw_relay, Some(cap));

        // First half of the budget, drained so the pump has definitely
        // accounted for it before the reset lands.
        guest_client.write_all(&vec![0x11; 512]).await.unwrap();
        let mut first = vec![0_u8; 512];
        claw_client.read_exact(&mut first).await.unwrap();
        assert_eq!(
            ledger.snapshot().0,
            512,
            "precondition: the ledger really is tracking, so the reset is not a no-op"
        );

        // The mutation: telemetry is wiped mid-flight.
        ledger.reset();
        assert_eq!(ledger.snapshot(), (0, 0));

        // Offer cap + 1 more. The extra byte is what makes this test terminate
        // under BOTH implementations instead of hanging under one:
        //  - correct: 512 of the budget remain, so 512 pass and byte 513 trips
        //    the cap, which closes the splice;
        //  - collapsed-ledger mutant: it believes 0 are spent, forwards 1024,
        //    and byte 1025 trips the cap — so it also closes.
        // Both return, and the assertions below then differ finitely (512 vs
        // 1024) instead of one side waiting forever for an EOF that a
        // still-open client never sends.
        guest_client.write_all(&vec![0x22; 1025]).await.unwrap();
        let mut second = Vec::new();
        claw_client.read_to_end(&mut second).await.unwrap();

        let outcome = splice.await.unwrap().unwrap();
        assert_eq!(
            second.len(),
            512,
            "the cap must still fire at the ORIGINAL budget, not a reset one"
        );
        assert_eq!(
            outcome.guest_to_claw, 1024,
            "enforcement counted the full budget across the reset"
        );
        assert_eq!(
            outcome.capped_direction,
            Some(SpliceByteCapDirection::GuestToClaw)
        );
        // Telemetry, by contrast, legitimately under-reports after a wipe —
        // that is the cost of it being observational, and is exactly why it
        // must never be the enforcement source.
        assert_eq!(ledger.snapshot().0, 512);
    }

    // The budgets are independent: a capped direction does not touch the
    // other direction's counter, and exactly-B in BOTH directions closes
    // clean.
    #[tokio::test]
    async fn splice_capped_direction_budgets_are_independent() {
        let cap = 1024_u64;
        let (mut guest_client, guest_relay) = tokio::io::duplex(4096);
        let (mut claw_relay_client, claw_relay) = tokio::io::duplex(4096);
        let (splice, ledger) = spawn_capped_splice(guest_relay, claw_relay, Some(cap));

        claw_relay_client.write_all(&vec![0xdd; 10]).await.unwrap();
        let mut from_claw = vec![0_u8; 10];
        guest_client.read_exact(&mut from_claw).await.unwrap();
        assert!(from_claw.iter().all(|byte| *byte == 0xdd));
        guest_client.write_all(&vec![0xee; 1025]).await.unwrap();
        let mut from_guest = vec![0_u8; 1024];
        claw_relay_client.read_exact(&mut from_guest).await.unwrap();

        let outcome = splice.await.unwrap().unwrap();
        assert_eq!(outcome.guest_to_claw, 1024);
        assert_eq!(outcome.claw_to_guest, 10);
        assert_eq!(
            ledger.snapshot(),
            (outcome.guest_to_claw, outcome.claw_to_guest),
            "one capped direction must not disturb the other in the ledger either"
        );
        assert_eq!(
            outcome.capped_direction,
            Some(SpliceByteCapDirection::GuestToClaw)
        );

        // Both directions at exactly B: no cap trip, clean EOF close.
        let (mut guest_client, guest_relay) = tokio::io::duplex(4096);
        let (mut claw_relay_client, claw_relay) = tokio::io::duplex(4096);
        let (splice, both_ledger) = spawn_capped_splice(guest_relay, claw_relay, Some(cap));
        guest_client.write_all(&vec![1; 1024]).await.unwrap();
        claw_relay_client.write_all(&vec![2; 1024]).await.unwrap();
        guest_client.shutdown().await.unwrap();
        claw_relay_client.shutdown().await.unwrap();
        let outcome = splice.await.unwrap().unwrap();
        assert_eq!(outcome.guest_to_claw, 1024);
        assert_eq!(outcome.claw_to_guest, 1024);
        assert_eq!(outcome.capped_direction, None);
        assert_eq!(
            both_ledger.snapshot(),
            (outcome.guest_to_claw, outcome.claw_to_guest)
        );
    }
}
