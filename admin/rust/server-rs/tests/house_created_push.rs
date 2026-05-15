//! T088b spy-transport tests for the `house_created` APNs push client.
//!
//! Tests cover:
//! - Payload shape conformance against the house_created_push.json fixture (T088c).
//! - Retry on transient (5xx) failures followed by success.
//! - Immediate abort on permanent (4xx) failures.
//! - Retry exhaustion with no successful response.
//! - Success on first attempt.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use server_rs::apns_push::{
    DispatchAttemptError, HouseCreatedError, HouseCreatedEvent, HouseCreatedTransport,
    build_house_created_json, dispatch_house_created_with_delays,
};

// ── Spy transport ────────────────────────────────────────────────────────────

struct SpyTransport {
    calls: Mutex<Vec<(String, String)>>,
    responses: Mutex<Vec<Result<(), DispatchAttemptError>>>,
}

impl SpyTransport {
    fn with_responses(responses: Vec<Result<(), DispatchAttemptError>>) -> Self {
        Self {
            calls: Mutex::default(),
            responses: Mutex::new(responses),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl HouseCreatedTransport for SpyTransport {
    fn topic(&self) -> &str {
        "com.soyeht.iSoyehtTerm.test"
    }

    fn send_push<'a>(
        &'a self,
        token_hex: &'a str,
        json_body: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DispatchAttemptError>> + Send + 'a>> {
        let token = token_hex.to_owned();
        let body = json_body.to_owned();
        Box::pin(async move {
            self.calls.lock().unwrap().push((token, body));
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                Ok(())
            } else {
                responses.remove(0)
            }
        })
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn test_event(hh_name: &str) -> HouseCreatedEvent {
    HouseCreatedEvent {
        apns_device_token: [0xabu8; 32],
        hh_id: "hh_test_id".into(),
        hh_name: hh_name.into(),
        machine_id: "m_test_machine".into(),
        machine_label: "Test Mac".into(),
        pair_qr_uri: "soyeht://pair?hh=test&anchor=deadbeef".into(),
        ts: 1_746_921_600,
    }
}

// ── Payload shape tests ───────────────────────────────────────────────────────

/// Verify build_house_created_json output against each fixture entry.
#[test]
fn payload_shape_matches_fixture() {
    let fixture: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/house_created_push.json"))
            .expect("fixture parse");

    for case in &fixture {
        let input = &case["input"];
        let expected = &case["expected"];

        let event = HouseCreatedEvent {
            apns_device_token: [0u8; 32],
            hh_id: input["hh_id"].as_str().unwrap().into(),
            hh_name: input["hh_name"].as_str().unwrap().into(),
            machine_id: input["machine_id"].as_str().unwrap().into(),
            machine_label: input["machine_label"].as_str().unwrap().into(),
            pair_qr_uri: input["pair_qr_uri"].as_str().unwrap().into(),
            ts: input["ts"].as_u64().unwrap(),
        };

        let json = build_house_created_json(&event);
        let actual: serde_json::Value = serde_json::from_str(&json).expect("valid JSON output");
        assert_eq!(
            actual, *expected,
            "payload mismatch for hh_name={}",
            event.hh_name
        );
    }
}

// ── Transport / retry tests ───────────────────────────────────────────────────

#[tokio::test]
async fn success_on_first_attempt() {
    let spy = Arc::new(SpyTransport::with_responses(vec![Ok(())]));
    let event = test_event("Success Home");

    let result = dispatch_house_created_with_delays(spy.as_ref(), &event, &[]).await;
    assert!(result.is_ok());
    assert_eq!(spy.call_count(), 1);
}

#[tokio::test]
async fn abort_on_4xx() {
    let spy = Arc::new(SpyTransport::with_responses(vec![Err(
        DispatchAttemptError::Permanent("BadDeviceToken".into()),
    )]));
    let event = test_event("4xx Home");

    let result = dispatch_house_created_with_delays(spy.as_ref(), &event, &[0, 0, 0]).await;
    assert!(
        matches!(result, Err(HouseCreatedError::Permanent(_))),
        "expected Permanent, got {result:?}"
    );
    assert_eq!(spy.call_count(), 1, "must not retry on 4xx");
}

#[tokio::test]
async fn retry_on_5xx_then_success() {
    // Two transient failures, then success. Zero-ms delays so test is instant.
    let spy = Arc::new(SpyTransport::with_responses(vec![
        Err(DispatchAttemptError::Transient("ServiceUnavailable".into())),
        Err(DispatchAttemptError::Transient(
            "InternalServerError".into(),
        )),
        Ok(()),
    ]));
    let event = test_event("Retry Home");

    let result = dispatch_house_created_with_delays(spy.as_ref(), &event, &[0, 0]).await;
    assert!(result.is_ok(), "expected Ok after retries, got {result:?}");
    assert_eq!(spy.call_count(), 3, "expected 3 total attempts");
}

#[tokio::test]
async fn exhausts_retries_on_persistent_5xx() {
    // Delay schedule has 2 entries → max 3 total attempts.
    let spy = Arc::new(SpyTransport::with_responses(vec![
        Err(DispatchAttemptError::Transient("5xx".into())),
        Err(DispatchAttemptError::Transient("5xx".into())),
        Err(DispatchAttemptError::Transient("5xx".into())),
    ]));
    let event = test_event("Exhausted Home");

    let result = dispatch_house_created_with_delays(spy.as_ref(), &event, &[0, 0]).await;
    assert!(
        matches!(result, Err(HouseCreatedError::ExhaustedRetries(_))),
        "expected ExhaustedRetries, got {result:?}"
    );
    assert_eq!(spy.call_count(), 3);
}

#[tokio::test]
async fn token_hex_encoding_is_correct() {
    let spy = Arc::new(SpyTransport::with_responses(vec![Ok(())]));
    let mut event = test_event("Token Home");
    event.apns_device_token = [
        0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ];

    dispatch_house_created_with_delays(spy.as_ref(), &event, &[])
        .await
        .unwrap();

    let calls = spy.calls.lock().unwrap();
    let (token_hex, _) = &calls[0];
    assert!(
        token_hex.starts_with("deadbeef"),
        "token hex should start with deadbeef, got {token_hex}"
    );
}
