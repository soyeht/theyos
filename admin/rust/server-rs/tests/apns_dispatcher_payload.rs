//! T026 + T078 runtime spy assertion: the APNS dispatcher emits a
//! body that is byte-equal to `APNS_TICKLE_BODY`
//! (`{"aps":{"content-available":1}}` — the Apple silent-push canonical
//! shape) and never any household-derived value. The spy
//! implementation in this file captures every body the dispatcher
//! would have transmitted to Apple, then asserts byte-equality with
//! the canonical constant.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use household_rs::owner_events::OwnerDevicePushToken;
use serde_bytes::ByteBuf;
use server_rs::apns_dispatcher::{
    APNS_TICKLE_BODY, ApnsError, ApnsTransport, dispatch_tickle_with,
};

#[derive(Default)]
struct SpyTransport {
    captured: Mutex<Vec<Vec<u8>>>,
}

impl ApnsTransport for SpyTransport {
    fn topic(&self) -> &str {
        const TOPIC: &str = "test.theyos.apns";
        TOPIC
    }

    fn send<'a>(
        &'a self,
        _push_token: &'a [u8],
        body: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), ApnsError>> + Send + 'a>> {
        let captured = body.to_vec();
        Box::pin(async move {
            self.captured.lock().unwrap().push(captured);
            Ok(())
        })
    }
}

fn token() -> OwnerDevicePushToken {
    OwnerDevicePushToken {
        version: 1,
        p_id: "p_test_owner".into(),
        platform: "ios".into(),
        push_token: ByteBuf::from(vec![0u8; 32]),
        updated_at: 0,
    }
}

#[tokio::test]
async fn dispatch_emits_only_canonical_tickle_body() {
    let spy = Arc::new(SpyTransport::default());
    let token = token();
    for _ in 0..10 {
        dispatch_tickle_with(spy.as_ref(), &token).await.unwrap();
    }
    let captured = spy.captured.lock().unwrap().clone();
    assert_eq!(captured.len(), 10);
    for body in &captured {
        assert_eq!(body.as_slice(), APNS_TICKLE_BODY);
    }
}

#[tokio::test]
async fn dispatched_body_contains_no_household_bytes() {
    let spy = Arc::new(SpyTransport::default());
    let token = OwnerDevicePushToken {
        version: 1,
        p_id: "p_uniq_marker_owner".into(),
        platform: "ios".into(),
        push_token: ByteBuf::from(b"distinctive-push-token-marker".to_vec()),
        updated_at: 0,
    };
    dispatch_tickle_with(spy.as_ref(), &token).await.unwrap();
    let captured = spy.captured.lock().unwrap().clone();
    let forbidden_substrings: [&[u8]; 3] = [
        b"p_uniq_marker_owner",
        b"distinctive-push-token-marker",
        b"hh_",
    ];
    for body in &captured {
        for needle in &forbidden_substrings {
            assert!(
                !contains_subseq(body, needle),
                "leaked {:?} in dispatched APNS body {:?}",
                std::str::from_utf8(needle).unwrap_or("<bytes>"),
                String::from_utf8_lossy(body)
            );
        }
    }
}

fn contains_subseq(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
