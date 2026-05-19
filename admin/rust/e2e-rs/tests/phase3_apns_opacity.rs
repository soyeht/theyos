//! Phase 3 Story 3 — APNS payload opacity audit (T078).
//!
//! End-to-end gate that drives the full Story 1 ceremony with an APNS
//! spy transport plugged in via `apns_dispatcher::install_transport`,
//! captures every body the dispatcher would have transmitted to Apple,
//! and asserts:
//!
//! 1. Each captured body is byte-equal to `APNS_TICKLE_BODY`
//!    (`{"aps":{"content-available":1}}`).
//! 2. None of the captured surface — body, transport `topic`, or
//!    `push_token` bytes — contains a household-derived substring
//!    (`hh_*`, `m_*`, `p_*`, hostname, full fingerprint phrase).
//!
//! Constitution III is enforced by three independent layers (compile-
//! time API shape, source-level lint, runtime spy). T078 is the last
//! layer: it observes the dispatcher in the context of a real Phase 3
//! ceremony, so a future regression that wires household metadata
//! through some indirect path (event-derived envelope, tracing-shadow
//! body, alternate dispatch helper) is caught by an assertion that
//! actually drives owner-event appends.

mod phase3_support;

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use household_rs::owner_events::OwnerDevicePushToken;
use serde_bytes::ByteBuf;
use server_rs::apns_dispatcher::{APNS_TICKLE_BODY, ApnsError, ApnsTransport, install_transport};

use phase3_support::{
    OwnerApprovalAck, OwnerEventsResponse, candidate_harness, cursor_param, founder_harness,
    get_cbor, owner_approval_body, post_cbor, post_local_anchor, unix_now,
};

// Use non-textual bytes so the opacity assertion cannot collide with a
// randomly-generated BIP-39 fingerprint word such as "device".
const PUSH_TOKEN_BYTES: &[u8] = &[
    0x93, 0x4f, 0x08, 0xd1, 0xaa, 0x77, 0x1c, 0x50, 0xe2, 0x6b, 0x39, 0x04, 0xbe, 0x18, 0xc6, 0x7d,
    0x22, 0xf0, 0x9a, 0x31, 0x85, 0x4c, 0xd3, 0x0e, 0x69, 0xb7, 0x14, 0xfd, 0x40, 0x8c, 0x2a, 0xe5,
];

/// Process-wide spy transport.
///
/// `apns_dispatcher::install_transport` wraps a `OnceLock`, so the spy
/// MUST be installed once per test binary and never replaced. Tests
/// that need to inspect captures across multiple ceremonies share this
/// single instance and rely on `clear()` to reset between runs.
struct SpyTransport {
    captured_bodies: Mutex<Vec<Vec<u8>>>,
    captured_push_tokens: Mutex<Vec<Vec<u8>>>,
}

impl ApnsTransport for SpyTransport {
    fn topic(&self) -> &'static str {
        // Fixed, build-time-style value. Returned to the production
        // dispatcher path where it would otherwise become the
        // `apns-topic` header. Asserted not to contain household-
        // derived substrings.
        "test.theyos.apns"
    }

    fn send<'a>(
        &'a self,
        push_token: &'a [u8],
        body: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), ApnsError>> + Send + 'a>> {
        let body_bytes = body.to_vec();
        let token_bytes = push_token.to_vec();
        Box::pin(async move {
            self.captured_bodies.lock().unwrap().push(body_bytes);
            self.captured_push_tokens.lock().unwrap().push(token_bytes);
            Ok(())
        })
    }
}

static SPY_TRANSPORT: OnceLock<Arc<SpyTransport>> = OnceLock::new();

fn install_spy() -> Arc<SpyTransport> {
    Arc::clone(SPY_TRANSPORT.get_or_init(|| {
        let spy = Arc::new(SpyTransport {
            captured_bodies: Mutex::new(Vec::new()),
            captured_push_tokens: Mutex::new(Vec::new()),
        });
        let transport: Arc<dyn ApnsTransport> = spy.clone();
        let _ = install_transport(transport);
        spy
    }))
}

fn forbidden_household_substrings(
    founder: &phase3_support::FounderHarness,
    candidate: &phase3_support::CandidateHarness,
) -> Vec<Vec<u8>> {
    // Pull the actually-rendered identifiers from the live ceremony so
    // a regression that leaks them into the dispatch surface is caught
    // structurally — not against a frozen hardcoded list that could
    // drift from the bootstrap-derived ids.
    let m1_id = founder.identity.cert.m_id.to_string();
    let m2_id = candidate.prepared.m_id.to_string();
    let hh_id = founder.identity.record.hh_id.to_string();
    let p_id = founder.owner.auth.owner_person_cert.p_id.0.clone();
    let mut needles: Vec<Vec<u8>> = vec![
        m1_id.into_bytes(),
        m2_id.into_bytes(),
        hh_id.into_bytes(),
        p_id.into_bytes(),
        b"hh_".to_vec(),
        b"m_".to_vec(),
        b"p_".to_vec(),
        candidate
            .prepared
            .join_request
            .hostname
            .clone()
            .into_bytes(),
    ];
    // Check the full phrase, not individual BIP-39 words. Single words like
    // "lab" or "device" can legitimately appear inside fixed non-household
    // APNS surfaces such as `content-available` or arbitrary device tokens.
    needles.push(candidate.prepared.fingerprint.as_bytes().to_vec());
    // The candidate's own SEC1 m_pub bytes — the dispatcher must never
    // hand these to the push provider either.
    needles.push(candidate.prepared.m_pub_sec1.to_vec());
    needles
}

fn contains_subseq(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn test_no_household_data_in_apns() {
    let spy = install_spy();
    spy.captured_bodies.lock().unwrap().clear();
    spy.captured_push_tokens.lock().unwrap().clear();

    let founder = founder_harness();
    let candidate = candidate_harness().await;

    // Persist a registered push token directly so the broadcaster can
    // resolve `get_owner_push_token` at dispatch time. The token's
    // `p_id` is forced to the ACTUAL household-paired person id so a
    // hypothetical regression that smuggles `p_id` into the body or
    // headers would surface against `forbidden_household_substrings`.
    let token = OwnerDevicePushToken {
        version: 1,
        p_id: founder.owner.auth.owner_person_cert.p_id.0.clone(),
        platform: "ios".into(),
        push_token: ByteBuf::from(PUSH_TOKEN_BYTES.to_vec()),
        updated_at: unix_now(),
    };
    household_rs::owner_events::put_owner_push_token(founder.dir.path(), &token)
        .expect("put owner push token");

    // Stage the JoinRequest. The append fires an OwnerEvent whose
    // broadcaster sees zero subscribers (no long-poll active yet) and
    // dispatches a tickle through the installed spy transport.
    let (status, _, body) = post_cbor(
        founder.router.clone(),
        "/api/v1/household/join-request",
        candidate.prepared.join_request_cbor.clone(),
        Some(&founder.owner),
    )
    .await;
    assert_eq!(status.as_u16(), 201, "join-request should accept");
    let accepted: phase3_support::JoinRequestAccepted =
        household_rs::cbor::from_canonical_slice(&body).expect("decode accepted");

    // Briefly catch up the long-poll just to surface the JoinRequest
    // event's cursor; the call returns immediately because the head is
    // already ahead of `since=0`.
    let owner_events_uri = format!("/api/v1/household/owner-events?since={}", cursor_param(0));
    let (_, _, body) = get_cbor(founder.router.clone(), &owner_events_uri, &founder.owner).await;
    let events: OwnerEventsResponse =
        household_rs::cbor::from_canonical_slice(&body).expect("decode events");
    assert_eq!(events.events.len(), 1);

    post_local_anchor(&candidate, &founder, &candidate.prepared.anchor_secret).await;

    let approve_path = format!(
        "/api/v1/household/owner-events/{}/approve",
        accepted.owner_event_cursor
    );
    let approval_body = owner_approval_body(
        &founder,
        &candidate.prepared.join_request,
        accepted.owner_event_cursor,
        unix_now(),
    );
    let (status, _, body) = post_cbor(
        founder.router.clone(),
        &approve_path,
        approval_body,
        Some(&founder.owner),
    )
    .await;
    assert_eq!(status.as_u16(), 200);
    let _: OwnerApprovalAck = household_rs::cbor::from_canonical_slice(&body).expect("decode ack");

    // Wait for the spawned APNS dispatch tasks to drain. Each event
    // append spawns a `tokio::spawn(...)` — by the time we reach this
    // point the 2PC commit has already returned, but the spawned tasks
    // may still be in-flight. A small bounded yield loop avoids the
    // race without resorting to a fixed sleep.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let n = spy.captured_bodies.lock().unwrap().len();
        if n >= 1 {
            // Give a final tick for any still-pending dispatch.
            tokio::time::sleep(Duration::from_millis(20)).await;
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no APNS dispatch observed within 2s"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let bodies = spy.captured_bodies.lock().unwrap().clone();
    let push_tokens = spy.captured_push_tokens.lock().unwrap().clone();
    assert!(
        !bodies.is_empty(),
        "expected at least one APNS dispatch during a Phase 3 ceremony"
    );
    assert_eq!(bodies.len(), push_tokens.len());

    // Body byte-equality: every dispatched body must equal the canonical
    // `{"aps":{"content-available":1}}` slice exactly. This is the heart
    // of FR-005c / SC-NA: the push provider sees a constant.
    for (i, body) in bodies.iter().enumerate() {
        assert_eq!(
            body.as_slice(),
            APNS_TICKLE_BODY,
            "dispatch #{i} body diverged from canonical"
        );
    }

    // Push-token bytes: must equal the bytes we registered (random
    // APNS device token, NOT household-derived). Asserts the spy is
    // wired to the live broadcaster path, not just exercised in
    // isolation.
    for token_bytes in &push_tokens {
        assert_eq!(token_bytes.as_slice(), PUSH_TOKEN_BYTES);
    }

    // Header / topic surface: assert the transport-exposed `topic` and
    // every captured byte slice is free of household-derived markers.
    let needles = forbidden_household_substrings(&founder, &candidate);
    let topic_bytes = spy.topic().as_bytes().to_vec();
    for needle in &needles {
        assert!(
            !contains_subseq(&topic_bytes, needle),
            "APNS topic leaked household substring {:?}",
            String::from_utf8_lossy(needle)
        );
        for body in &bodies {
            assert!(
                !contains_subseq(body, needle),
                "APNS body leaked household substring {:?}",
                String::from_utf8_lossy(needle)
            );
        }
        for tok in &push_tokens {
            // The push_token surface is end-user-controlled (Apple
            // device token), but defense-in-depth: ensure the
            // dispatcher does not append household-derived bytes onto
            // it (e.g., a future regression that concatenates p_id).
            assert!(
                !contains_subseq(tok, needle),
                "APNS push_token surface leaked household substring {:?}",
                String::from_utf8_lossy(needle)
            );
        }
    }
}
