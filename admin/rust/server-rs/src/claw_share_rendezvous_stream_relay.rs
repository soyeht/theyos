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
pub use household_rs::claw_share::rendezvous_hello::{
    RENDEZVOUS_HELLO_VERSION, RendezvousHello, RendezvousHelloError, RendezvousRole,
};
pub use household_rs::claw_share::rendezvous_token::{
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
mod tests;
