//! Concrete owner-event APNS "tickle" transport (silent background push).
//!
//! This is the real-provider implementation of
//! [`crate::apns_dispatcher::ApnsTransport`]. It lives OUTSIDE
//! `apns_dispatcher.rs` on purpose: that file is the Constitution III guarded
//! surface ("no household metadata reaches the push provider") and must stay
//! pure — only the canonical silent-push body, a fixed `pub` set, and no
//! body-source machinery. Concrete transports (like
//! [`crate::apns_push::A2Transport`]) belong in their own modules. This
//! transport only forwards the canonical body it is handed by the dispatcher,
//! plus addressing (device token + topic); it never constructs household
//! metadata of its own.

use std::fs::File;
use std::future::Future;
use std::pin::Pin;

use crate::apns_dispatcher::{APNS_TOPIC_ENV, ApnsError, ApnsTransport};
use crate::apns_push::{
    APNS_PUSH_KEY_ID_ENV, APNS_PUSH_KEY_PATH_ENV, APNS_PUSH_TEAM_ID_ENV, apns_endpoint_from_env,
};

pub struct A2TickleTransport {
    client: a2::Client,
    topic: &'static str,
}

impl A2TickleTransport {
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let key_path = std::env::var(APNS_PUSH_KEY_PATH_ENV).ok()?;
        let key_id = std::env::var(APNS_PUSH_KEY_ID_ENV).ok()?;
        let team_id = std::env::var(APNS_PUSH_TEAM_ID_ENV).ok()?;
        let topic_str = std::env::var(APNS_TOPIC_ENV).ok()?;

        let mut key_file = File::open(&key_path)
            .map_err(|e| {
                tracing::error!(
                    stage = "apns.tickle.key_open_failed",
                    path = %key_path,
                    error = %e,
                );
            })
            .ok()?;

        let config = a2::ClientConfig::new(apns_endpoint_from_env());
        let client = a2::Client::token(&mut key_file, key_id, team_id, config)
            .map_err(|e| tracing::error!(stage = "apns.tickle.client_init_failed", error = %e))
            .ok()?;

        let topic: &'static str = Box::leak(topic_str.into_boxed_str());
        Some(Self { client, topic })
    }
}

impl ApnsTransport for A2TickleTransport {
    fn topic(&self) -> &str {
        self.topic
    }

    fn send<'a>(
        &'a self,
        push_token: &'a [u8],
        body: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), ApnsError>> + Send + 'a>> {
        Box::pin(async move {
            let json_body = std::str::from_utf8(body).map_err(|_| ApnsError::TransportRejected)?;
            let payload = A2TicklePayload {
                device_token_hex: hex::encode(push_token),
                json_body: json_body.to_string(),
                options: a2::NotificationOptions {
                    apns_topic: Some(self.topic),
                    apns_push_type: Some(a2::PushType::Background),
                    apns_priority: Some(a2::Priority::Normal),
                    ..Default::default()
                },
            };
            self.client
                .send(payload)
                .await
                .map(|_| ())
                .map_err(|_| ApnsError::TransportRejected)
        })
    }
}

#[derive(serde::Serialize, Debug)]
struct A2TicklePayload {
    #[serde(skip)]
    device_token_hex: String,
    #[serde(skip)]
    json_body: String,
    #[serde(skip)]
    options: a2::NotificationOptions<'static>,
}

impl a2::request::payload::PayloadLike for A2TicklePayload {
    fn get_device_token(&self) -> &str {
        &self.device_token_hex
    }

    fn get_options(&self) -> &a2::NotificationOptions<'_> {
        &self.options
    }

    fn to_json_string(&self) -> Result<String, a2::Error> {
        Ok(self.json_body.clone())
    }
}
