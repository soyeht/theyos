//! Phase 3 — observability audit (T093).
//!
//! Captures every `tracing` event emitted across a happy-path Story 1
//! ceremony and asserts two complementary properties:
//!
//! 1. **Positive coverage** — at least one event is emitted for each of
//!    the canonical Phase 3 checkpoints: `pair_machine.window_opened`,
//!    `join_request.accepted`, `pair_machine.owner_prompt_forwarded`,
//!    `owner_events.approve.accepted`,
//!    `pair_machine.shamir_transition_committed`,
//!    `owner_events.long_poll.timeout`, plus an APNS success or skip
//!    path. A regression that silently removes a log line at one of
//!    these checkpoints fails this audit. A second test
//!    (`test_owner_timeout_aborts_window_and_emits_tracing`) covers
//!    FR-019's "owner timed out" stage — the active window-TTL-expiry
//!    path that the runtime watchdog (`spawn_owner_timeout_watchdog`)
//!    drives, distinct from the HTTP long-poll keep-alive timeout.
//! 2. **No leakage** — the captured byte buffer (which contains every
//!    span debug-text and field value rendered by the formatting
//!    layer) does NOT contain any 32-byte window that bit-equals the
//!    founder `hh_priv`, the founder/candidate `m_priv`, the join
//!    request nonce, or either side's plaintext Shamir shard
//!    (recovered post-commit from `shamir/self_shard.cbor` via
//!    `decrypt_self`). A regression that adds `priv_key = ?` or
//!    `nonce = ?` to a span field, or that logs an entire
//!    `Zeroizing<Vec<u8>>`, fails this audit.
//!
//! T093 specifies the test file path as
//! `admin/rust/server-rs/tests/observability_audit.rs`. The audit
//! lives here under `e2e-rs/tests/` instead so it can drive a real
//! 2PC commit through the existing `phase3_support` helpers — the
//! `Shamir transition committed` checkpoint is otherwise only
//! reachable via a full-ceremony harness that server-rs/tests/ does
//! not have.

mod phase3_support;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use household_rs::KeyBackingPolicy;
use household_rs::owner_events::{OwnerEventPayload, OwnerEventType};
use household_rs::pair_machine::{JoinTransport, PairMachineState};
use server_rs::handlers_owner_events::{OwnerEventsRouterState, spawn_owner_timeout_watchdog};
use subtle::ConstantTimeEq;
use tokio::sync::watch;
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::fmt;

use phase3_support::{
    JOIN_REQUEST_PATH, OWNER_EVENTS_PATH, OwnerApprovalAck, OwnerEventsResponse, candidate_harness,
    cursor_param, founder_harness, get_cbor, post_cbor, post_local_anchor, post_owner_approval,
};

#[derive(Clone)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> fmt::MakeWriter<'a> for CaptureWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn install_capture() -> (Arc<Mutex<Vec<u8>>>, DefaultGuard) {
    let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let writer = CaptureWriter(buf.clone());
    // Plain (text) format keeps every field's `Debug` rendering
    // verbatim — JSON would escape non-ASCII bytes and could mask a
    // raw byte leak under a `\uXXXX` rewrite. Defense-in-depth: read
    // the buffer as if it were the production stderr surface.
    let subscriber = fmt::Subscriber::builder()
        .with_writer(writer)
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (buf, guard)
}

fn contains_constant_time(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| bool::from(w.ct_eq(needle)))
}

const OWNER_TIMEOUT_QUARANTINE_CUTOFF: u64 = 1_787_011_200;

fn quarantine_is_live(now: u64, cutoff: u64) -> bool {
    now < cutoff
}

fn workflow_job_block<'a>(workflow: &'a str, job: &str) -> &'a str {
    let marker = format!("\n  {job}:\n");
    let start = workflow
        .find(&marker)
        .map(|index| index + 1)
        .unwrap_or_else(|| panic!("workflow job {job} is present"));
    let after_start = &workflow[start..];
    let end = after_start
        .match_indices('\n')
        .filter_map(|(index, _)| {
            after_start
                .get(index + 1..)
                .map(|remainder| (index, remainder))
        })
        .find_map(|(index, remainder)| {
            let line = remainder.lines().next().unwrap_or_default();
            (line.starts_with("  ") && !line.starts_with("    ") && line.trim_end().ends_with(':'))
                .then_some(index)
        })
        .unwrap_or(after_start.len());
    &after_start[..end]
}

fn quarantine_probe_is_in_required_linux_job(workflow: &str) -> bool {
    workflow_job_block(workflow, "build-and-test-linux")
        .contains("      - name: Quarantine probe (issue #470)")
}

fn quarantine_probe_step(workflow: &str) -> &str {
    let linux_job = workflow_job_block(workflow, "build-and-test-linux");
    let start = linux_job
        .find("      - name: Quarantine probe (issue #470)")
        .expect("issue #470 probe step is present in required Linux job");
    let after_start = &linux_job[start..];
    let end = after_start
        .find("\n      - name:")
        .unwrap_or(after_start.len());
    &after_start[..end]
}

fn active_lines(input: &str) -> impl Iterator<Item = &str> {
    input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

fn quarantine_probe_command(step: &str) -> Option<String> {
    let lines: Vec<_> = active_lines(step).collect();
    let starts: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            line.starts_with("python3 scripts/quarantine_probe.py")
                .then_some(index)
        })
        .collect();
    let [start] = starts.as_slice() else {
        return None;
    };

    let mut command = Vec::new();
    for line in &lines[*start..] {
        let continues = line.ends_with('\\');
        command.push(line.trim_end_matches('\\').trim());
        if !continues {
            return Some(command.join(" "));
        }
    }
    None
}

fn quarantine_probe_guard_is_intact(step: &str) -> bool {
    let active: Vec<_> = active_lines(step).collect();
    let Some(command) = quarantine_probe_command(step) else {
        return false;
    };
    let command_tokens: Vec<_> = command.split_whitespace().collect();
    active
        == [
            "- name: Quarantine probe (issue #470)",
            "run: |",
            "python3 scripts/test_quarantine_probe.py",
            "python3 scripts/quarantine_probe.py \\",
            "--issue 470 \\",
            "--attempts 5 \\",
            "--attempt-timeout-seconds 120 \\",
            "--package e2e-rs \\",
            "--test-target phase3_observability_audit \\",
            "--test test_owner_timeout_aborts_window_and_emits_tracing \\",
            "--require-pass",
        ]
        && command_tokens
            == [
                "python3",
                "scripts/quarantine_probe.py",
                "--issue",
                "470",
                "--attempts",
                "5",
                "--attempt-timeout-seconds",
                "120",
                "--package",
                "e2e-rs",
                "--test-target",
                "phase3_observability_audit",
                "--test",
                "test_owner_timeout_aborts_window_and_emits_tracing",
                "--require-pass",
            ]
}

#[tokio::test]
async fn test_phase3_happy_path_observability_is_complete_and_leak_free() {
    let (buf, _guard) = install_capture();

    let founder = founder_harness();
    let candidate = candidate_harness().await;

    // Drive the ceremony inline (mirrors phase3_support::run_remote_ceremony
    // but does not assert SC-001 timing — this test cares about the log
    // trace only).
    let (status, _, body) = post_cbor(
        founder.router.clone(),
        JOIN_REQUEST_PATH,
        candidate.prepared.join_request_cbor.clone(),
        Some(&founder.owner),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let accepted: phase3_support::JoinRequestAccepted =
        household_rs::cbor::from_canonical_slice(&body).expect("decode accepted");

    let owner_events_uri = format!("{OWNER_EVENTS_PATH}?since={}", cursor_param(0));
    let (_, _, body) = get_cbor(founder.router.clone(), &owner_events_uri, &founder.owner).await;
    let events: OwnerEventsResponse =
        household_rs::cbor::from_canonical_slice(&body).expect("decode events");
    assert_eq!(events.events.len(), 1);

    post_local_anchor(&candidate, &founder, &candidate.prepared.anchor_secret).await;

    let (status, _, body) = post_owner_approval(
        &founder,
        &candidate.prepared.join_request,
        accepted.owner_event_cursor,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let _: OwnerApprovalAck =
        household_rs::cbor::from_canonical_slice(&body).expect("decode approval ack");

    // Wait briefly for any spawned APNS dispatch task to flush its
    // `tracing::info!` event.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Trigger the long-poll timeout branch so its observability event
    // lands in the captured buffer. `since=99` is past the head; the
    // 50ms timeout configured by `founder_harness` then returns 204.
    let timeout_path = format!("{OWNER_EVENTS_PATH}?since={}", cursor_param(99));
    let (timeout_status, _, _) =
        get_cbor(founder.router.clone(), &timeout_path, &founder.owner).await;
    assert_eq!(timeout_status, StatusCode::NO_CONTENT);

    let captured = buf.lock().unwrap().clone();
    let captured_str = String::from_utf8_lossy(&captured);

    // ── Positive coverage ───────────────────────────────────────────
    let required_stages = [
        "pair_machine.window_opened",
        "join_request.accepted",
        "pair_machine.owner_prompt_forwarded",
        "owner_events.approve.accepted",
        "pair_machine.shamir_transition_committed",
        "owner_events.long_poll.timeout",
    ];
    for stage in &required_stages {
        assert!(
            captured_str.contains(stage),
            "missing required tracing stage `{stage}` in captured log:\n---\n{captured_str}\n---"
        );
    }
    // APNS path: at least one of dispatched / skipped fires after the
    // owner-event broadcast lands. The ceremony does not register a
    // push token, so `apns.skipped` is the expected branch — but we
    // accept either as evidence the broadcaster's APNS hook runs.
    let saw_apns_branch = captured_str.contains("owner_events.apns.dispatched")
        || captured_str.contains("owner_events.apns.skipped");
    assert!(
        saw_apns_branch,
        "expected at least one APNS branch event:\n---\n{captured_str}\n---"
    );

    // ── No leakage ──────────────────────────────────────────────────
    let founder_hh_priv: Vec<u8> = founder
        .identity
        .hh_priv
        .as_deref()
        .expect("single-machine hh_priv")
        .as_software_secret()
        .expect("software-backed hh_priv exposes scalar")
        .to_vec();
    let founder_m_priv: Vec<u8> = founder
        .identity
        .m_priv
        .as_software_secret()
        .expect("software-backed founder m_priv exposes scalar")
        .to_vec();
    let candidate_m_priv: Vec<u8> = candidate
        .prepared
        .m_priv
        .as_software_secret()
        .expect("software-backed candidate m_priv exposes scalar")
        .to_vec();
    let nonce: Vec<u8> = candidate.prepared.join_request.nonce.as_ref().to_vec();

    // Recover both sides' plaintext Shamir shards from disk and add
    // them to the forbidden list. After a successful 1→2 commit,
    // `shamir/self_shard.cbor` is encrypted under the holder's
    // m_priv; we decrypt it here ONLY to materialize the plaintext
    // bytes for the leak-scan. T093 requires "full shards" be in
    // scope.
    use household_rs::pair_machine::shamir_self_shard_path;
    use household_rs::shard_at_rest::{EncryptedShard, decrypt_self};
    use household_rs::storage::read_optional_cbor;

    let founder_encrypted: EncryptedShard =
        read_optional_cbor(&shamir_self_shard_path(founder.dir.path()))
            .expect("read founder shard")
            .expect("founder shard exists post-commit");
    let founder_shard_plaintext = {
        let scalar = founder
            .identity
            .m_priv
            .as_software_secret()
            .expect("software-backed founder m_priv");
        let m_pub = &founder.identity.cert.m_pub;
        let m_id = founder.identity.cert.m_id.to_string();
        let pt = decrypt_self(&founder_encrypted, scalar, m_pub, &m_id)
            .expect("decrypt founder self-shard");
        pt.to_vec()
    };
    let candidate_encrypted: EncryptedShard =
        read_optional_cbor(&shamir_self_shard_path(candidate.dir.path()))
            .expect("read candidate shard")
            .expect("candidate shard exists post-commit");
    let candidate_shard_plaintext = {
        let scalar = candidate
            .prepared
            .m_priv
            .as_software_secret()
            .expect("software-backed candidate m_priv");
        let m_pub = household_rs::keys::P256PublicKey::from_bytes(&candidate.prepared.m_pub_sec1)
            .expect("decode candidate m_pub");
        let m_id = candidate.prepared.m_id.to_string();
        let pt = decrypt_self(&candidate_encrypted, scalar, &m_pub, &m_id)
            .expect("decrypt candidate self-shard");
        pt.to_vec()
    };

    let forbidden: Vec<(&str, Vec<u8>)> = vec![
        ("founder.hh_priv", founder_hh_priv),
        ("founder.m_priv", founder_m_priv),
        ("candidate.m_priv", candidate_m_priv),
        ("join_request.nonce", nonce),
        ("founder.shard_plaintext", founder_shard_plaintext),
        ("candidate.shard_plaintext", candidate_shard_plaintext),
    ];

    for (label, needle) in &forbidden {
        // Substring scan is sufficient because tracing's text formatter
        // emits raw bytes via `Debug` of `&[u8]` (e.g., `[0x..]`),
        // hex-coded in lower-case nibbles by the typical formatter; a
        // direct memcmp pass would miss a hex-encoded leak. So we run
        // BOTH a constant-time byte-exact scan AND a hex-encoded
        // lower-case scan.
        assert!(
            !contains_constant_time(&captured, needle),
            "{label} ({} bytes) leaked verbatim into tracing buffer",
            needle.len()
        );
        let hex_lower: String = needle.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        });
        assert!(
            !captured_str.contains(&hex_lower),
            "{label} ({} bytes) leaked as lowercase hex into tracing buffer",
            needle.len()
        );
    }

    // Defense-in-depth marker: assert the capture is non-trivial.
    assert!(
        captured.len() > 256,
        "tracing buffer appears empty — subscriber may not have been set"
    );
}

#[test]
fn owner_timeout_quarantine_has_not_expired() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs();
    assert!(
        quarantine_is_live(now, OWNER_TIMEOUT_QUARANTINE_CUTOFF),
        "issue #470 quarantine for @gloria expired at 2026-08-18T00:00:00Z; re-evaluate test_owner_timeout_aborts_window_and_emits_tracing"
    );
}

#[test]
fn owner_timeout_quarantine_cutoff_is_exclusive() {
    assert!(quarantine_is_live(
        OWNER_TIMEOUT_QUARANTINE_CUTOFF - 1,
        OWNER_TIMEOUT_QUARANTINE_CUTOFF
    ));
    assert!(!quarantine_is_live(
        OWNER_TIMEOUT_QUARANTINE_CUTOFF,
        OWNER_TIMEOUT_QUARANTINE_CUTOFF
    ));
}

#[test]
fn owner_timeout_quarantine_probe_contract_is_enforced() {
    let workflow = include_str!("../../../../.github/workflows/backend-ci.yml");
    assert!(
        quarantine_probe_is_in_required_linux_job(workflow),
        "issue #470 probe must remain inside the required build-and-test-linux job"
    );
    let probe = quarantine_probe_step(workflow);

    assert!(
        probe.contains("# QUARANTINE_PROBE_470_BEGIN")
            && probe.contains("# QUARANTINE_PROBE_470_END"),
        "issue #470 probe markers must remain inside the probe step"
    );
    assert!(
        quarantine_probe_guard_is_intact(probe),
        "issue #470 required probe must use the validated integration-test selector, make five attempts, reject invalid instruments, and require at least one pass"
    );
}

#[test]
fn owner_timeout_quarantine_guard_rejects_required_probe_mutations() {
    let workflow = include_str!("../../../../.github/workflows/backend-ci.yml");
    let probe = quarantine_probe_step(workflow);

    let step_level_continue = probe.replacen(
        "        run:",
        "        continue-on-error: true\n        run:",
        1,
    );
    assert!(step_level_continue.contains("continue-on-error"));
    assert!(!quarantine_probe_guard_is_intact(&step_level_continue));

    for required_argument in [
        "python3 scripts/test_quarantine_probe.py",
        "python3 scripts/quarantine_probe.py",
        "--issue 470",
        "--attempts 5",
        "--attempt-timeout-seconds 120",
        "--package e2e-rs",
        "--test-target phase3_observability_audit",
        "--test test_owner_timeout_aborts_window_and_emits_tracing",
        "--require-pass",
    ] {
        let mutation = probe.replacen(required_argument, "", 1);
        assert!(
            !quarantine_probe_guard_is_intact(&mutation),
            "removing {required_argument} must break the required probe contract"
        );
    }

    let detached_required_policy = probe
        .replacen(
            "            --test test_owner_timeout_aborts_window_and_emits_tracing \\",
            "            --test test_owner_timeout_aborts_window_and_emits_tracing",
            1,
        )
        .replacen(
            "            --require-pass",
            "          echo --require-pass",
            1,
        );
    assert!(detached_required_policy.contains("echo --require-pass"));
    assert!(!quarantine_probe_guard_is_intact(&detached_required_policy));

    let dead_branch = probe
        .replacen(
            "          python3 scripts/quarantine_probe.py \\\n",
            "          if false; then\n          python3 scripts/quarantine_probe.py \\\n",
            1,
        )
        .replacen(
            "            --require-pass\n",
            "            --require-pass\n          fi\n",
            1,
        );
    assert!(dead_branch.contains("if false; then"));
    assert!(dead_branch.contains("\n          fi\n"));
    assert_eq!(
        quarantine_probe_command(&dead_branch),
        quarantine_probe_command(probe),
        "the dead-branch mutant must preserve the exact harness command"
    );
    assert!(
        !quarantine_probe_guard_is_intact(&dead_branch),
        "an exact command hidden in a dead shell branch must break the required probe contract"
    );

    let without_required_probe = workflow.replacen(probe, "", 1);
    let moved_to_non_required =
        without_required_probe.replacen("    steps:\n", &format!("    steps:\n{probe}"), 1);
    assert!(moved_to_non_required.contains("Quarantine probe (issue #470)"));
    assert!(
        !quarantine_probe_is_in_required_linux_job(&moved_to_non_required),
        "moving the intact probe text outside the required Linux job must break containment"
    );
}

/// FR-019 "owner timed out" coverage — the active half. Distinct from
/// `owner_events.long_poll.timeout` (HTTP keep-alive returning 204):
/// THIS test exercises the runtime watchdog that fires when the
/// `PairMachineWindow` TTL elapses without owner action. The window
/// MUST transition `awaiting_owner → aborted`, append a
/// `JoinCancelled{reason="timeout"}` owner event so the iPhone's
/// long-poll wakes up with the cancellation, and emit
/// `pair_machine.owner_timed_out` for the audit trail.
///
/// Issue #470 quarantine: 4 of 23 hosted-Linux verdict-bearing attempts failed
/// across 20 runs; the exact cause and rate remain unisolated.
/// Attempt Wilson95 is [7.0%, 37.1%]; run-cluster Wilson95 is [8.1%, 41.6%].
/// Three rerun second attempts passed. Owner: @gloria. Expiry: 2026-08-17.
/// Separately, Saira's macOS-local sweep of predecessor 9e27e8ec had one
/// failure followed by four passes; fe159617 had five passes. Neither result is
/// included in the hosted-Linux count, and the macOS cause and rate are not
/// established.
/// The expiry guard below makes the quarantine fail closed on 2026-08-18.
/// 0/5 detects total breakage immediately but partial degradation more slowly;
/// the mandatory expiry review covers that middle range. A green probe run is
/// not evidence that the flake rate stayed constant.
#[ignore = "issue #470: owner-timeout flake observed across environments; expires 2026-08-17"]
#[tokio::test]
async fn test_owner_timeout_aborts_window_and_emits_tracing() {
    let (buf, _guard) = install_capture();

    let founder = founder_harness();

    // Build an OwnerEventsRouterState mirroring what
    // household_bootstrap.rs constructs in production. The router
    // created by `founder_harness` already mounts its own internal
    // OwnerEventsRouterState; this parallel one shares the same Arcs
    // (window, event_log, broadcaster, household) so the watchdog
    // observes the same live state.
    let owner_state = OwnerEventsRouterState::with_timeout(
        founder.pair_state.household.clone(),
        Arc::clone(&founder.window),
        Arc::clone(&founder.event_log),
        founder.pair_state.event_broadcaster.clone(),
        founder.dir.path().to_path_buf(),
        KeyBackingPolicy::ForceSoftware,
        Duration::from_millis(50),
    );
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let watchdog = spawn_owner_timeout_watchdog(owner_state, cancel_rx);

    // Drive the window directly to AwaitingOwner with a 1-second TTL.
    // Bypassing the router lets the test set a TTL short enough to
    // observe expiry inside CI without flaking — the production
    // handler currently hardcodes 300s. The watchdog reacts to the
    // window state regardless of how it was set.
    let dummy_m_pub: [u8; 33] = [0x02; 33];
    let dummy_nonce: [u8; 32] = [0x33; 32];
    founder
        .window
        .enter_staging(
            dummy_m_pub,
            dummy_nonce,
            JoinTransport::Tailscale,
            "127.0.0.1:0".to_string(),
            "alpha bravo charlie delta echo foxtrot".to_string(),
            vec![0x80],
            1,
            None,
        )
        .await
        .expect("enter_staging");
    founder
        .window
        .enter_awaiting_owner(0)
        .await
        .expect("enter_awaiting_owner");

    // Wait for the watchdog to fire. 1s TTL + slack for the tokio
    // scheduler tick + abort_with_cancel_event's IO. Polled rather
    // than fixed-sleep so the test is not artificially slow.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if founder.window.snapshot().await.state == PairMachineState::Aborted {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "watchdog did not fire within 3s of TTL expiry"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Allow the post-abort owner-event append + tracing flush.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Owner-event log must contain a `JoinCancelled` with
    // `reason="timeout"` so the iPhone long-poll observes the abort
    // semantically (this is the wake-up signal, not just an internal
    // state flip).
    let founder_read = founder
        .lifecycle
        .lock_shared()
        .expect("lock lifecycle shared");
    let events = founder
        .event_log
        .read_since(&founder_read, 0)
        .expect("read events");
    drop(founder_read);
    let saw_timeout = events.iter().any(|e| {
        matches!(e.event_type, OwnerEventType::JoinCancelled)
            && matches!(
                &e.payload,
                OwnerEventPayload::JoinCancelled(p) if p.reason == "timeout"
            )
    });
    assert!(
        saw_timeout,
        "expected JoinCancelled timeout event, got: {events:?}"
    );

    // Tracing must include both the positive owner_timed_out stage
    // AND the downstream ceremony_aborted that abort_with_cancel_event
    // emits. The audit's positive coverage thereby covers FR-019's
    // "owner timed out" AND "ceremony aborted" simultaneously.
    let captured = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
    assert!(
        captured.contains("pair_machine.owner_timed_out"),
        "missing pair_machine.owner_timed_out in:\n---\n{captured}\n---"
    );
    assert!(
        captured.contains("pair_machine.ceremony_aborted"),
        "missing pair_machine.ceremony_aborted (chained via abort_with_cancel_event) in:\n---\n{captured}\n---"
    );

    // Graceful shutdown via the watch::channel hook — this is the
    // supported teardown path. The latched primitive avoids the
    // lost-wakeup race that an edge-triggered `Notify` would have
    // had: even if `send(true)` lands while the watchdog is
    // suspended on a non-`select!` await (snapshot, household
    // current, abort_with_cancel_event), the next sticky
    // `*cancel_rx.borrow()` check at the top of the loop observes
    // the cancel.
    cancel_tx.send(true).expect("cancel_tx send");
    watchdog
        .await
        .expect("watchdog returns cleanly on shutdown");
}
