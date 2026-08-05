//! T035 unit tests — candidate-side install preparation.
//!
//! These tests validate `prepare_candidate` end-to-end on a temp state
//! dir + force-software keystore: nonce randomness, signature
//! self-verification, fingerprint determinism, window persistence, URI
//! shape. The full install-CLI integration (PATH parsing, OS hostname
//! sanitization, addr resolution) is tested in server-rs.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use household_rs::KeyBackingPolicy;
use household_rs::keys::P256PublicKey;
use household_rs::machine_cert::Platform;
use household_rs::pair_machine::{
    JoinTransport, PairMachineState, PairMachineWindow, PrepareCandidateOpts, WindowError,
    prepare_candidate, verify_join_request,
};

#[tokio::test]
async fn prepares_a_signed_join_request_and_persists_window() {
    let td = tempfile::tempdir().unwrap();
    let window = PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap();

    let prepared = prepare_candidate(
        &window,
        PrepareCandidateOpts {
            state_dir: td.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: "100.1.2.3:8091".into(),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: std::time::Duration::from_secs(300),
            now_unix: 1_700_000_000,
        },
    )
    .await
    .unwrap();

    // The signed request must self-verify.
    verify_join_request(&prepared.join_request).unwrap();

    // The fingerprint is a 6-word lowercase ASCII string.
    let words: Vec<&str> = prepared.fingerprint.split(' ').collect();
    assert_eq!(words.len(), 6);
    for w in &words {
        assert!(!w.is_empty());
        assert!(w.chars().all(|c| c.is_ascii_lowercase()));
    }

    // Window persisted in `staging` with cached_join_request bytes.
    let snap = window.snapshot().await;
    assert_eq!(snap.state, PairMachineState::Staging);
    assert!(snap.cached_join_request.is_some());
    assert_eq!(
        snap.cached_join_request.as_ref().unwrap().to_vec(),
        prepared.join_request_cbor
    );
    // The window stamps expiry from its own wall clock; the
    // `PreparedCandidate` surfaces that exact value as `ttl_unix` so
    // the two artifacts stay byte-equivalent.
    assert_eq!(snap.expiry, Some(prepared.ttl_unix));

    // The on-disk snapshot survives a daemon-side reload.
    let reload = PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap();
    let reload_snap = reload.snapshot().await;
    assert_eq!(reload_snap.state, PairMachineState::Staging);
    assert_eq!(reload_snap.m_pub, snap.m_pub);
    assert_eq!(reload_snap.nonce, snap.nonce);
    assert_eq!(reload_snap.cached_join_request, snap.cached_join_request);
}

#[tokio::test]
async fn re_running_install_invalidates_the_prior_qr() {
    let td = tempfile::tempdir().unwrap();
    let window = PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap();

    let first = prepare_candidate(
        &window,
        PrepareCandidateOpts {
            state_dir: td.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: "100.1.2.3:8091".into(),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: std::time::Duration::from_secs(300),
            now_unix: 1_700_000_000,
        },
    )
    .await
    .unwrap();

    let second = prepare_candidate(
        &window,
        PrepareCandidateOpts {
            state_dir: td.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: "100.1.2.3:8091".into(),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: std::time::Duration::from_secs(300),
            now_unix: 1_700_000_000,
        },
    )
    .await
    .unwrap();

    // Same M_priv (idempotent keystore via marker), same fingerprint.
    assert_eq!(first.m_pub_sec1, second.m_pub_sec1);
    assert_eq!(first.fingerprint, second.fingerprint);

    // But fresh nonce + fresh signature → different request bytes.
    assert_ne!(
        first.join_request.nonce.as_ref(),
        second.join_request.nonce.as_ref()
    );
    assert_ne!(
        first.join_request.challenge_sig.as_ref(),
        second.join_request.challenge_sig.as_ref()
    );
    assert_ne!(first.join_request_cbor, second.join_request_cbor);
}

#[tokio::test]
async fn uri_round_trips_every_field() {
    let td = tempfile::tempdir().unwrap();
    let window = PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap();

    let prepared = prepare_candidate(
        &window,
        PrepareCandidateOpts {
            state_dir: td.path().to_path_buf(),
            transport: JoinTransport::Lan,
            addr: "192.168.1.5:8091".into(),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: std::time::Duration::from_secs(120),
            now_unix: 1_700_000_000,
        },
    )
    .await
    .unwrap();

    let uri = prepared.join_request.to_pair_machine_uri(prepared.ttl_unix);
    assert!(uri.starts_with("soyeht://household/pair-machine?v=1"));
    assert!(uri.contains("&platform=linux-nix"));
    assert!(uri.contains("&transport=lan"));
    // base64url no-pad encoding of 33-byte SEC1 m_pub is exactly 44 chars
    let m_pub_param = uri
        .split("&m_pub=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    assert_eq!(m_pub_param.len(), 44);

    // Decode the m_pub from the URI and assert it matches the
    // PreparedCandidate's m_pub_sec1 (proves the URI builder doesn't
    // reorder bytes).
    let decoded = URL_SAFE_NO_PAD.decode(m_pub_param).unwrap();
    assert_eq!(decoded, prepared.m_pub_sec1);

    // The fingerprint computed from the round-tripped m_pub matches.
    let m_pub_arr: [u8; 33] = decoded.as_slice().try_into().unwrap();
    let _ = P256PublicKey::from_bytes(&m_pub_arr).unwrap();
    assert_eq!(
        household_rs::fingerprint::fingerprint(&m_pub_arr),
        prepared.fingerprint
    );

    // ttl param matches the window's expiry (sourced from wall-clock).
    assert!(uri.contains(&format!("&ttl={}", prepared.ttl_unix)));
    let snap = window.snapshot().await;
    assert_eq!(snap.expiry, Some(prepared.ttl_unix));
}

#[tokio::test]
async fn sign_path_is_self_consistent() {
    let td = tempfile::tempdir().unwrap();
    let window = PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap();
    let prepared = prepare_candidate(
        &window,
        PrepareCandidateOpts {
            state_dir: td.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: "100.1.2.3:8091".into(),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: std::time::Duration::from_secs(60),
            now_unix: 1_700_000_000,
        },
    )
    .await
    .unwrap();
    // Re-derive the m_pub from the IdentityKey handle and confirm it
    // matches the SEC1 bytes embedded in the request.
    assert_eq!(prepared.m_priv.public().as_bytes(), &prepared.m_pub_sec1);
}

/// Regression for the B7 liveness bug surfaced in PR #28 R4: the
/// in-memory pin must NOT survive a persist failure, otherwise an
/// idempotent retry of `pin_household_anchor` would short-circuit
/// against an in-memory pin that never reached disk, and a daemon
/// restart before `local/finalize` would then surface as
/// `trust_anchor_missing` because the on-disk snapshot has no pin.
#[cfg(unix)]
#[tokio::test]
async fn pin_household_anchor_rolls_back_in_memory_state_on_persist_failure() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let td = tempfile::tempdir().unwrap();
    let window = PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap();

    // Drive the window into Staging so household_dir exists and a
    // baseline snapshot is on disk.
    let _ = prepare_candidate(
        &window,
        PrepareCandidateOpts {
            state_dir: td.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: "100.1.2.3:8091".into(),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl: std::time::Duration::from_secs(60),
            now_unix: 1_700_000_000,
        },
    )
    .await
    .unwrap();
    assert_eq!(window.snapshot().await.state, PairMachineState::Staging);

    // Revoke write permission on the directory the subject ACTUALLY writes to,
    // DERIVED from the tree rather than hardcoded by layout.
    //
    // This used to chmod `household/`, which was correct while the pair-machine
    // window lived at `household/pair_machine_window.cbor`. The B-1 change moved
    // that write into a generation-scoped `PairWindowNamespaceV2`, a SIBLING of
    // `household/`. The chmod then covered a directory the subject no longer
    // touched, so persist stopped failing and this test went red claiming
    // something false -- "persist must fail when household_dir is read-only",
    // where household_dir had become irrelevant.
    //
    // Worse, the skip-probe below wrote to `household/` too: still blocked, so
    // it did NOT skip, while the subject wrote elsewhere and did not fail. The
    // precondition and the operation had come to point at different paths, and a
    // skip evaluated somewhere other than the operation is worse than no skip --
    // it certifies an environment nobody checked.
    //
    // Deriving the target keeps the observation bound to the operation, so the
    // next relocation cannot silently repeat this.
    let hh_dir = fs::read_dir(td.path())
        .expect("state dir readable")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(".pair-windows-v2."))
        })
        .expect(
            "pair-window namespace must exist after staging -- if this fires, the \
             subject's write target moved again and this test must follow it",
        );
    let restore_perm = fs::metadata(&hh_dir).unwrap().permissions();
    let mut ro = restore_perm.clone();
    ro.set_mode(0o500);
    fs::set_permissions(&hh_dir, ro).unwrap();

    // Probe: skip the test if write still works (e.g., running as root,
    // where mode 0o500 cannot deny writes).
    let probe = hh_dir.join(".write_probe");
    if fs::write(&probe, b"x").is_ok() {
        let _ = fs::remove_file(&probe);
        fs::set_permissions(&hh_dir, restore_perm).unwrap();
        eprintln!("skipping persist-failure test: writes still succeed under 0o500 (root?)");
        return;
    }

    let hh_pub = [0xAB; 33];
    let hh_id = "hh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    let result = window.pin_household_anchor(hh_id.clone(), hh_pub).await;

    // Restore write perms before assertions so the tempdir cleanup
    // and any later test setup succeed regardless of outcome.
    fs::set_permissions(&hh_dir, restore_perm).unwrap();

    let err = result.expect_err("persist must fail when household_dir is read-only");
    assert!(
        matches!(err, WindowError::Storage(_)),
        "expected Storage error, got {err:?}"
    );

    // The in-memory snapshot MUST be rolled back. Without rollback the
    // idempotent retry would short-circuit and skip persist forever.
    let snap = window.snapshot().await;
    assert!(
        snap.pinned_hh_pub.is_none(),
        "pinned_hh_pub must be None after persist failure"
    );
    assert!(
        snap.pinned_hh_id.is_none(),
        "pinned_hh_id must be None after persist failure"
    );

    // Retrying with valid permissions must persist the pin to disk.
    window
        .pin_household_anchor(hh_id.clone(), hh_pub)
        .await
        .unwrap();
    let reload = PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap();
    let reload_snap = reload.snapshot().await;
    assert_eq!(
        reload_snap.pinned_hh_id.as_deref(),
        Some(hh_id.as_str()),
        "after retry under healthy filesystem, pin must reach disk"
    );
    assert_eq!(
        reload_snap.pinned_hh_pub.as_ref().map(|b| b.to_vec()),
        Some(hh_pub.to_vec())
    );
}
