#![cfg(test)]

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
    let handle =
        tokio::spawn(
            async move { splice_opaque_streams_capped(guest, claw, cap, &task_ledger).await },
        );
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

fn pair_token(table: &mut RendezvousTokenTable<&'static str>, token: RendezvousToken, now: u64) {
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
