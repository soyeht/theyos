//! T088b: `house_created` APNs push client.
//!
//! Unlike the Phase 3 silent tickle (Constitution III), this push carries
//! rich household data — accepted risk per contracts/push-events.md §Security.
//! The payload contains the household name, IDs, and pair QR URI shown in the
//! iOS onboarding UI.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use thiserror::Error;

// ── Env keys ────────────────────────────────────────────────────────────────

pub const APNS_PUSH_KEY_PATH_ENV: &str = "THEYOS_APNS_KEY_PATH";
pub const APNS_PUSH_KEY_ID_ENV: &str = "THEYOS_APNS_KEY_ID";
pub const APNS_PUSH_TEAM_ID_ENV: &str = "THEYOS_APNS_TEAM_ID";
pub const APNS_PUSH_TOPIC_ENV: &str = "THEYOS_APNS_TOPIC";

/// Shared kill-switch with the Phase 3 dispatcher. When set to `1`,
/// [`dispatch_fire_and_forget`] logs at info level and returns early without
/// reaching Apple. Used in CI and developer sandboxes.
pub const PUSH_DISABLED_ENV: &str = "THEYOS_PUSH_DISABLED";

// ── Retry schedule ───────────────────────────────────────────────────────────

/// Wait durations (in milliseconds) between successive retry attempts on
/// transient (5xx / network) failures. Six entries → 7 total attempts.
pub const RETRY_DELAYS_MS: &[u64] = &[1_000, 2_000, 4_000, 8_000, 16_000, 30_000];

// ── Event payload ────────────────────────────────────────────────────────────

/// All fields required to build and dispatch a `house_created` APNs push.
pub struct HouseCreatedEvent {
    pub apns_device_token: [u8; 32],
    pub hh_id: String,
    pub hh_name: String,
    pub machine_id: String,
    pub machine_label: String,
    pub pair_qr_uri: String,
    pub ts: u64,
}

/// Build the JSON body for a `house_created` push.
///
/// Pure function — no I/O, no side effects. Called from the retry loop and
/// exercised directly in `tests/house_created_push.rs` against the fixture.
#[must_use]
pub fn build_house_created_json(event: &HouseCreatedEvent) -> String {
    serde_json::json!({
        "aps": {
            "alert": {
                "title-loc-key": "house_created_title",
                "loc-key": "house_created_body",
                "loc-args": [event.hh_name],
            },
            "sound": "house-created.caf",
            "mutable-content": 1,
            "interruption-level": "active",
            "thread-id": "house-events",
        },
        "soyeht": {
            "v": 1,
            "type": "house_created",
            "hh_id": event.hh_id,
            "hh_name": event.hh_name,
            "machine_id": event.machine_id,
            "machine_label": event.machine_label,
            "pair_qr_uri": event.pair_qr_uri,
            "ts": event.ts,
        }
    })
    .to_string()
}

// ── Transport abstraction ────────────────────────────────────────────────────

/// Error classification returned by a single send attempt.
#[derive(Debug)]
pub enum DispatchAttemptError {
    /// 5xx or network error — retry is appropriate.
    Transient(String),
    /// 4xx or other non-retryable failure.
    Permanent(String),
}

impl fmt::Display for DispatchAttemptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transient(m) | Self::Permanent(m) => f.write_str(m),
        }
    }
}

/// Abstracts the HTTP/2 APNs client so tests can inject a spy without opening
/// a real network connection.
pub trait HouseCreatedTransport: Send + Sync + 'static {
    fn topic(&self) -> &str;
    fn send_push<'a>(
        &'a self,
        token_hex: &'a str,
        json_body: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DispatchAttemptError>> + Send + 'a>>;
}

// ── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum HouseCreatedError {
    #[error("permanent APNs rejection: {0}")]
    Permanent(String),
    #[error("all retries exhausted: {0}")]
    ExhaustedRetries(String),
}

// ── Retry loop ───────────────────────────────────────────────────────────────

/// Dispatch a single `house_created` push, retrying on transient failures per
/// [`RETRY_DELAYS_MS`]. Aborts immediately on permanent (4xx) errors.
pub async fn dispatch_house_created_with(
    transport: &dyn HouseCreatedTransport,
    event: &HouseCreatedEvent,
) -> Result<(), HouseCreatedError> {
    dispatch_house_created_with_delays(transport, event, RETRY_DELAYS_MS).await
}

/// Like [`dispatch_house_created_with`] but with an injectable retry-delay
/// schedule. Pass `&[]` for zero retries. Used by tests to avoid real sleeps.
pub async fn dispatch_house_created_with_delays(
    transport: &dyn HouseCreatedTransport,
    event: &HouseCreatedEvent,
    retry_delays_ms: &[u64],
) -> Result<(), HouseCreatedError> {
    let token_hex = hex::encode(event.apns_device_token);
    let json_body = build_house_created_json(event);

    let mut delay_iter = retry_delays_ms.iter();
    let mut attempt: u32 = 0;

    loop {
        match transport.send_push(&token_hex, &json_body).await {
            Ok(()) => return Ok(()),
            Err(DispatchAttemptError::Permanent(msg)) => {
                tracing::warn!(stage = "apns.push.permanent_error", attempt, error = %msg);
                return Err(HouseCreatedError::Permanent(msg));
            }
            Err(DispatchAttemptError::Transient(msg)) => {
                if let Some(&delay_ms) = delay_iter.next() {
                    tracing::warn!(
                        stage = "apns.push.transient_retrying",
                        attempt,
                        delay_ms,
                        error = %msg,
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    attempt += 1;
                } else {
                    tracing::warn!(stage = "apns.push.exhausted", attempt, error = %msg);
                    return Err(HouseCreatedError::ExhaustedRetries(msg));
                }
            }
        }
    }
}

// ── Production A2 transport ──────────────────────────────────────────────────

/// Production transport backed by the `a2` HTTP/2 APNs client.
pub struct A2Transport {
    client: a2::Client,
    topic: &'static str,
}

impl A2Transport {
    /// Build from environment variables. Returns `None` if any required env
    /// var is missing or the key file cannot be opened/parsed.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let key_path = std::env::var(APNS_PUSH_KEY_PATH_ENV).ok()?;
        let key_id = std::env::var(APNS_PUSH_KEY_ID_ENV).ok()?;
        let team_id = std::env::var(APNS_PUSH_TEAM_ID_ENV).ok()?;
        let topic_str = std::env::var(APNS_PUSH_TOPIC_ENV).ok()?;

        let mut key_file = std::fs::File::open(&key_path)
            .map_err(|e| {
                tracing::error!(
                    stage = "apns.push.key_open_failed",
                    path = %key_path,
                    error = %e,
                );
            })
            .ok()?;

        let config = a2::ClientConfig::new(a2::Endpoint::Production);
        let client = a2::Client::token(&mut key_file, key_id, team_id, config)
            .map_err(|e| tracing::error!(stage = "apns.push.client_init_failed", error = %e))
            .ok()?;

        // One-time leak so the topic can be stored as `&'static str` and
        // satisfy the `NotificationOptions<'static>` lifetime requirement.
        let topic: &'static str = Box::leak(topic_str.into_boxed_str());
        Some(Self { client, topic })
    }
}

impl HouseCreatedTransport for A2Transport {
    fn topic(&self) -> &str {
        self.topic
    }

    fn send_push<'a>(
        &'a self,
        token_hex: &'a str,
        json_body: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DispatchAttemptError>> + Send + 'a>> {
        Box::pin(async move {
            let options = a2::NotificationOptions {
                apns_topic: Some(self.topic),
                apns_push_type: Some(a2::PushType::Alert),
                apns_priority: Some(a2::Priority::High),
                ..Default::default()
            };
            let payload = A2Payload {
                device_token_hex: token_hex.to_owned(),
                json_body: json_body.to_owned(),
                options,
            };
            match self.client.send(payload).await {
                Ok(_) => Ok(()),
                Err(a2::Error::ResponseError(resp)) if resp.code >= 400 && resp.code < 500 => Err(
                    DispatchAttemptError::Permanent(format!("APNs 4xx: {}", resp.code)),
                ),
                Err(e) => Err(DispatchAttemptError::Transient(format!("a2: {e}"))),
            }
        })
    }
}

// A2Payload carries the pre-built JSON body and overrides PayloadLike::to_json_string()
// so fields absent from a2's APS struct (thread-id, interruption-level) are included.
#[derive(serde::Serialize, Debug)]
struct A2Payload {
    #[serde(skip)]
    device_token_hex: String,
    // a2 calls to_json_string() which we override, so serde serialization of
    // json_body is never used in practice — skip it to keep the struct's
    // Serialize output clean.
    #[serde(skip)]
    json_body: String,
    #[serde(skip)]
    options: a2::NotificationOptions<'static>,
}

impl a2::request::payload::PayloadLike for A2Payload {
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

// ── Process-global transport slot ────────────────────────────────────────────

static HOUSE_CREATED_TRANSPORT: OnceLock<Arc<dyn HouseCreatedTransport>> = OnceLock::new();

/// Install the production transport. Must be called at most once per process.
/// Returns the supplied transport back if a transport was already installed.
pub fn install_transport(
    transport: Arc<dyn HouseCreatedTransport>,
) -> Result<(), Arc<dyn HouseCreatedTransport>> {
    HOUSE_CREATED_TRANSPORT.set(transport)
}

/// Spawn a background task to deliver the `house_created` push. Returns
/// immediately; dispatch failures are logged at warn level but do not affect
/// the caller.
///
/// No-ops (with an info log) when no transport is installed or when
/// `THEYOS_PUSH_DISABLED=1`.
pub fn dispatch_fire_and_forget(event: HouseCreatedEvent) {
    if std::env::var(PUSH_DISABLED_ENV).as_deref() == Ok("1") {
        tracing::info!(
            stage = "apns.push.disabled_at_runtime",
            "skipped house_created push"
        );
        return;
    }
    let Some(transport) = HOUSE_CREATED_TRANSPORT.get().cloned() else {
        tracing::info!(
            stage = "apns.push.no_transport",
            "APNS push transport not installed - skipping house_created push",
        );
        return;
    };
    tokio::spawn(async move {
        match dispatch_house_created_with(transport.as_ref(), &event).await {
            Ok(()) => tracing::info!(stage = "apns.push.sent", hh_id = %event.hh_id),
            Err(e) => tracing::warn!(
                stage = "apns.push.failed",
                hh_id = %event.hh_id,
                error = %e,
            ),
        }
    });
}
