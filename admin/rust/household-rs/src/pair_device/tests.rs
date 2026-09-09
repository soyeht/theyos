#![cfg(test)]

use super::*;
use crate::keys::IdentityKey;
use crate::keys::P256Keypair;

fn fake_hh_pub() -> P256PublicKey {
    P256Keypair::generate().public()
}

/// Stand-in for an admitted machine cert fingerprint in tests that are not
/// about the fingerprint itself.
const FAKE_M_CERT_FP: [u8; 32] = [7u8; 32];

/// Every caller of a freshly-opened window must walk away with the same
/// token. `current_token()` on a miss followed by `mint_token()` does not
/// give that: the two calls are separate, `mint_token` replaces whatever
/// is stored, and both callers then return — leaving one of them holding
/// a nonce the window no longer has.
///
/// The race is real, not theoretical. The same harness run against the
/// two-step sequence observes divergence on the first round, every time
/// (measured 2026-07-31, 5/5 runs); that control is not checked in
/// because asserting *that a race happens* is inherently flaky. This
/// direction is deterministic: `get_or_mint` holds one write lock across
/// the check and the mint, so the answer is always one nonce.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn get_or_mint_hands_every_racing_caller_the_same_token() {
    const RACERS: usize = 64;
    for round in 0..40 {
        let w = PairDeviceWindow::new();
        let barrier = Arc::new(tokio::sync::Barrier::new(RACERS));
        let mut handles = Vec::with_capacity(RACERS);
        for _ in 0..RACERS {
            let w = w.clone();
            let b = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                b.wait().await;
                w.get_or_mint(Duration::from_secs(60), None)
                    .await
                    .unwrap()
                    .0
                    .nonce
                    .as_b64()
            }));
        }
        let mut nonces = std::collections::BTreeSet::new();
        for h in handles {
            nonces.insert(h.await.unwrap());
        }
        assert_eq!(
            nonces.len(),
            1,
            "round {round}: {RACERS} racing callers received {} distinct nonces; \
                 all but one of those pairing URIs is already dead",
            nonces.len()
        );
    }
}

/// The persistent path has a second racer the 64-caller test above cannot
/// see, because that one uses a non-persistent window: the snapshot
/// watcher. It calls [`PairDeviceWindow::install_token_from_current_snapshot`],
/// which takes the same write lock and then decides by re-reading the
/// file. So publishing the new token to memory and writing the file
/// afterwards is not enough — the watcher can take the lock in that gap,
/// still see the old file, and reinstall the old token, leaving memory and
/// the URI this call returns naming different nonces.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_or_mint_never_returns_a_token_memory_does_not_hold() {
    for round in 0..50 {
        let td = tempfile::tempdir().unwrap();
        let w = PairDeviceWindow::with_persistence(td.path().to_path_buf()).unwrap();

        // A snapshot on disk with nothing in memory: the state a daemon
        // restart leaves behind for the watcher to pick up.
        let stale = PairToken::mint(Duration::from_secs(60), None).unwrap();
        let namespace = w.namespace().unwrap().unwrap();
        let snap = stale.to_snapshot(namespace.generation());
        namespace.write_pair_device(&snap).unwrap();

        let watcher = {
            let w = w.clone();
            tokio::spawn(async move {
                let _ = w.install_token_from_current_snapshot(stale, &snap).await;
            })
        };
        let (served, _) = w.get_or_mint(Duration::from_secs(60), None).await.unwrap();
        watcher.await.unwrap();

        // Whoever won, memory and the answer must name the same token: if
        // the watcher went first, `get_or_mint` reuses its token; if
        // `get_or_mint` went first, the watcher re-reads a file that
        // already moved on and declines. There is no third outcome.
        let held = w.current_token().await.expect("a window must be open");
        assert_eq!(
            held.nonce.as_b64(),
            served.nonce.as_b64(),
            "round {round}: returned a URI naming a nonce the window does not hold — \
                 the snapshot watcher won the gap between the memory write and the file write"
        );
    }
}

/// `mint_token` publishes through the same helper, so it inherits the same
/// watcher race and is held to the same invariant. Keeping this test
/// separate rather than parameterising the one above means the pre-existing
/// caller (`post_pair_device_reissue`) keeps its own teeth.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mint_token_never_returns_a_token_memory_does_not_hold() {
    for round in 0..50 {
        let td = tempfile::tempdir().unwrap();
        let w = PairDeviceWindow::with_persistence(td.path().to_path_buf()).unwrap();
        let stale = PairToken::mint(Duration::from_secs(60), None).unwrap();
        let namespace = w.namespace().unwrap().unwrap();
        let snap = stale.to_snapshot(namespace.generation());
        namespace.write_pair_device(&snap).unwrap();

        let watcher = {
            let w = w.clone();
            tokio::spawn(async move {
                let _ = w.install_token_from_current_snapshot(stale, &snap).await;
            })
        };
        let minted = w.mint_token(Duration::from_secs(60), None).await.unwrap();
        watcher.await.unwrap();

        let held = w.current_token().await.expect("a window must be open");
        assert_eq!(
            held.nonce.as_b64(),
            minted.nonce.as_b64(),
            "round {round}: mint_token returned a nonce the window does not hold"
        );
    }
}

#[tokio::test]
async fn get_or_mint_reports_whether_it_opened_the_window() {
    let w = PairDeviceWindow::new();
    let (first, minted) = w.get_or_mint(Duration::from_secs(60), None).await.unwrap();
    assert!(minted, "the first call opens the window");
    let (second, minted_again) = w.get_or_mint(Duration::from_secs(60), None).await.unwrap();
    assert!(!minted_again, "the second call must reuse, not re-mint");
    assert_eq!(first.nonce.as_b64(), second.nonce.as_b64());
}

#[tokio::test]
async fn mint_then_consume() {
    let w = PairDeviceWindow::new();
    let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();
    let uri = token.to_uri(&fake_hh_pub(), &FAKE_M_CERT_FP);
    assert!(uri.starts_with("soyeht://household/pair-device?"));
    assert!(uri.contains("&hh_pub="));
    assert!(uri.contains("&ttl="));
    assert!(!uri.contains("&exp="));
    assert!(w.is_open().await);

    w.consume_token(&token.nonce).await.unwrap();
    assert!(!w.is_open().await);
}

#[tokio::test]
async fn every_uri_variant_carries_the_critical_machine_cert_fingerprint() {
    // RFC 5737 documentation address — the same one `PairDeviceQR.swift`
    // uses in its frozen examples. No real or tailnet address in fixtures.
    const DOC_HOST: &str = "192.0.2.10:8091";

    let fp: [u8; 32] = [
        0x9a, 0x3f, 0x01, 0xff, 0x10, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0x1e,
        0x2d, 0x3c,
    ];
    let w = PairDeviceWindow::new();
    let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();
    let hh = fake_hh_pub();

    // Every entry point, not just the widest one: `to_uri` and
    // `to_uri_with_host` delegate today, but a future edit could give one
    // of them its own body and silently drop the critical field.
    assert_ios_pair_device_qr_contract(&token.to_uri(&hh, &fp), &fp);
    assert_ios_pair_device_qr_contract(&token.to_uri_with_host(&hh, Some(DOC_HOST), &fp), &fp);
    assert_ios_pair_device_qr_contract(
        &token.to_uri_with_host_and_name(&hh, Some(DOC_HOST), Some("Home"), &fp),
        &fp,
    );
}

#[tokio::test]
async fn uri_with_host_and_name_percent_encodes_household_name() {
    let w = PairDeviceWindow::new();
    let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();
    let uri = token.to_uri_with_host_and_name(
        &fake_hh_pub(),
        Some("100.82.47.115:8091"),
        Some("Sample Home"),
        &FAKE_M_CERT_FP,
    );
    assert!(uri.contains("&host=100.82.47.115:8091"));
    assert!(uri.contains("&house_name=Sample%20Home"));
}

/// Reject exactly what `PairDeviceQR.swift` on soyeht-ios rejects.
///
/// Mirrored from the frozen client, not from our own intuition about what
/// "carries a fingerprint" ought to mean:
///
/// - `m_cert_fp` present exactly once (`duplicateField` otherwise);
/// - `crit` present exactly once with value **exactly** `m_cert_fp` — the
///   client tests `critItems.count == 1 && critItems[0].value ==
///   "m_cert_fp"`, so a comma list that merely *contains* it is refused;
/// - the value decodes as base64url to exactly 32 bytes;
/// - re-encoding those bytes reproduces the query value byte for byte.
///
/// That last one is the silent-failure class: a non-canonical encoding
/// still decodes to the right 32 bytes, so every server-side assertion
/// about "the fingerprint" passes while the device refuses the QR.
fn assert_ios_pair_device_qr_contract(uri: &str, expected_fp: &[u8; 32]) {
    let query = uri.split_once('?').expect("uri has a query").1;
    let pairs: Vec<(&str, &str)> = query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .collect();

    let fps: Vec<&str> = pairs
        .iter()
        .filter(|(k, _)| *k == "m_cert_fp")
        .map(|(_, v)| *v)
        .collect();
    assert_eq!(fps.len(), 1, "m_cert_fp must appear exactly once in {uri}");

    let crits: Vec<&str> = pairs
        .iter()
        .filter(|(k, _)| *k == "crit")
        .map(|(_, v)| *v)
        .collect();
    assert_eq!(crits.len(), 1, "crit must appear exactly once in {uri}");
    assert_eq!(
        crits[0], "m_cert_fp",
        "crit must be exactly `m_cert_fp`, not a list containing it"
    );

    let decoded = B64
        .decode(fps[0])
        .expect("m_cert_fp must be base64url-decodable");
    assert_eq!(decoded.len(), 32, "m_cert_fp must decode to 32 bytes");
    assert_eq!(
        decoded.as_slice(),
        expected_fp.as_slice(),
        "m_cert_fp must carry the admitted machine cert fingerprint"
    );
    assert_eq!(
        B64.encode(&decoded),
        fps[0],
        "m_cert_fp must be canonical base64url — the client re-encodes and compares"
    );
}

#[tokio::test]
async fn second_consume_returns_not_open() {
    let w = PairDeviceWindow::new();
    let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();
    w.consume_token(&token.nonce).await.unwrap();
    match w.consume_token(&token.nonce).await {
        Err(ConsumeError::NotOpen) => {}
        other => panic!("expected NotOpen, got {other:?}"),
    }
}

#[tokio::test]
async fn wrong_nonce_rejected() {
    let w = PairDeviceWindow::new();
    let _ = w.mint_token(Duration::from_secs(60), None).await.unwrap();
    let bogus = PairNonce::random();
    match w.consume_token(&bogus).await {
        Err(ConsumeError::WrongNonce) => {}
        other => panic!("expected WrongNonce, got {other:?}"),
    }
}

#[tokio::test]
async fn ttl_expiry_closes_window() {
    let w = PairDeviceWindow::new();
    let _ = w.mint_token(Duration::from_millis(50), None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(!w.is_open().await);
}

#[tokio::test]
async fn current_token_returns_active_only() {
    let w = PairDeviceWindow::new();
    assert!(w.current_token().await.is_none());
    let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();
    let live = w.current_token().await.expect("active");
    assert_eq!(live.nonce.0, token.nonce.0);
}

#[tokio::test]
async fn from_snapshot_caps_remaining_ttl() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let snap = PairDeviceWindowSnapshot {
        version: PAIR_DEVICE_SNAPSHOT_VERSION,
        nonce_b64: PairNonce::random().as_b64(),
        // Far-future expiry — would be unbounded sleep without clamping.
        expires_at_unix: now + 10_000_000,
        p_id_hint: None,
        lifecycle_generation: ByteBuf::from(vec![0_u8; 32]),
    };
    let token = PairToken::from_snapshot(&snap)
        .expect("decode")
        .expect("not expired");
    assert!(token.expires_at_unix - now <= MAX_PAIR_DEVICE_WINDOW_TTL_SECS);
}

#[tokio::test]
async fn mint_persists_snapshot_when_state_dir_set() {
    let td = tempfile::tempdir().unwrap();
    let w = PairDeviceWindow::with_persistence(td.path().to_path_buf()).unwrap();
    let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();

    // Persisted snapshot should carry the same nonce.
    let namespace = w.namespace().unwrap().unwrap();
    let path = namespace.pair_device_snapshot_path();
    let snap: PairDeviceWindowSnapshot = namespace.read_pair_device().unwrap().unwrap();
    assert_eq!(snap.nonce_b64, token.nonce.as_b64());

    // Consuming the token must wipe the persisted snapshot.
    w.consume_token(&token.nonce).await.unwrap();
    let stale: Option<PairDeviceWindowSnapshot> =
        crate::storage::read_optional_cbor(&path).unwrap();
    assert!(stale.is_none(), "persisted snapshot leaked after consume");
}

#[tokio::test]
async fn stale_snapshot_token_is_not_reinstalled_after_consume() {
    let td = tempfile::tempdir().unwrap();
    let w = PairDeviceWindow::with_persistence(td.path().to_path_buf()).unwrap();
    let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();
    let snap = token.to_snapshot(w.namespace().unwrap().unwrap().generation());

    w.consume_token(&token.nonce).await.unwrap();

    let decoded = PairToken::from_snapshot(&snap)
        .expect("decode")
        .expect("snapshot still unexpired");
    let installed = w
        .install_token_from_current_snapshot(decoded, &snap)
        .await
        .expect("install check");
    assert!(!installed);
    assert!(w.current_token().await.is_none());
}

#[tokio::test]
async fn stale_generation_ttl_cannot_delete_current_generation_window() {
    let td = tempfile::tempdir().unwrap();
    let lifecycle =
        crate::household_lifecycle::HouseholdLifecycleLock::open_verified(td.path()).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();
    let old = PairDeviceWindow::with_persistence_under_lifecycle(td.path().to_path_buf(), &guard)
        .unwrap();
    old.mint_token_under_lifecycle(Duration::from_millis(20), None, &guard)
        .await
        .unwrap();
    guard.rotate_lifecycle_generation().unwrap();
    let current =
        PairDeviceWindow::with_persistence_under_lifecycle(td.path().to_path_buf(), &guard)
            .unwrap();
    let current_token = current
        .mint_token_under_lifecycle(Duration::from_secs(5), None, &guard)
        .await
        .unwrap();
    drop(guard);
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        old.current_token().await.is_none(),
        "stale-generation TTL must close its in-memory authority even when deletion is refused"
    );
    assert_eq!(
        current.current_token().await.unwrap().nonce.0,
        current_token.nonce.0
    );
    assert!(
        current
            .namespace()
            .unwrap()
            .unwrap()
            .pair_device_snapshot_path()
            .exists()
    );
}

#[tokio::test]
async fn identical_window_content_from_an_old_generation_is_not_adopted() {
    let td = tempfile::tempdir().unwrap();
    let lifecycle =
        crate::household_lifecycle::HouseholdLifecycleLock::open_verified(td.path()).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();
    let old = PairDeviceWindow::with_persistence_under_lifecycle(td.path().to_path_buf(), &guard)
        .unwrap();
    let token = old
        .mint_token_under_lifecycle(Duration::from_secs(30), None, &guard)
        .await
        .unwrap();
    let old_snapshot = old
        .read_persisted_snapshot_under_lifecycle(&guard)
        .unwrap()
        .unwrap();

    guard.rotate_lifecycle_generation().unwrap();
    let current =
        PairDeviceWindow::with_persistence_under_lifecycle(td.path().to_path_buf(), &guard)
            .unwrap();
    let mut same_content_current_generation = old_snapshot.clone();
    same_content_current_generation.lifecycle_generation = ByteBuf::from(
        current
            .namespace()
            .unwrap()
            .unwrap()
            .generation()
            .token_bytes()
            .to_vec(),
    );
    current
        .namespace()
        .unwrap()
        .unwrap()
        .write_pair_device_under_lifecycle(&same_content_current_generation, &guard)
        .unwrap();
    drop(guard);

    assert!(
        !current
            .install_token_from_current_snapshot(token, &old_snapshot)
            .await
            .unwrap()
    );
    assert!(current.current_token().await.is_none());
}

#[tokio::test]
async fn stale_generation_consume_fails_closed_without_deleting_current_window() {
    let td = tempfile::tempdir().unwrap();
    let lifecycle =
        crate::household_lifecycle::HouseholdLifecycleLock::open_verified(td.path()).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();
    let old = PairDeviceWindow::with_persistence_under_lifecycle(td.path().to_path_buf(), &guard)
        .unwrap();
    let old_token = old
        .mint_token_under_lifecycle(Duration::from_secs(30), None, &guard)
        .await
        .unwrap();
    guard.rotate_lifecycle_generation().unwrap();
    let current =
        PairDeviceWindow::with_persistence_under_lifecycle(td.path().to_path_buf(), &guard)
            .unwrap();
    let current_token = current
        .mint_token_under_lifecycle(Duration::from_secs(30), None, &guard)
        .await
        .unwrap();
    drop(guard);

    assert!(matches!(
        old.consume_token(&old_token.nonce).await,
        Err(ConsumeError::Storage(_))
    ));
    assert!(old.current_token().await.is_none());
    assert_eq!(
        current.current_token().await.unwrap().nonce.0,
        current_token.nonce.0
    );
    assert!(
        current
            .namespace()
            .unwrap()
            .unwrap()
            .pair_device_snapshot_path()
            .exists()
    );
}
