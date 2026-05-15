//! Phase 3 opaque APNS dispatcher (T025-T028).
//!
//! Constitution III ("no household metadata reaches the push provider")
//! is enforced **structurally**, not by reviewer vigilance. Three
//! independent layers police the property:
//!
//! 1. **API shape (this file)** — only one payload-producing surface
//!    is exported, taking exactly `&OwnerDevicePushToken` and yielding
//!    `Result<(), ApnsError>`. The body is a `pub const` byte slice
//!    (`APNS_TICKLE_BODY`). A compile-time assertion at the bottom of
//!    this file pins the function signature.
//! 2. **Runtime spy test** — `apns_dispatcher_payload.rs` injects a
//!    spy [`ApnsTransport`] and asserts the dispatched body is
//!    byte-equal to [`APNS_TICKLE_BODY`].
//! 3. **Source-level lint** — `admin/rust/scripts/lint-apns-payload.sh`
//!    rejects builds whose dispatcher source contains forbidden body
//!    sources (`format!`, `serde_json::*`, etc.) or whose `pub` set
//!    diverges from the declared four items.
//!
//! All three layers are independent. A leak would have to subvert all
//! three in the same PR to ship.

use std::future::Future;
use std::pin::Pin;

use household_rs::owner_events::OwnerDevicePushToken;
use thiserror::Error;

/// The single canonical APNS background-tickle payload.
///
/// Two requirements pin the bytes:
///
/// 1. Constitution III demands the body be a `pub const` (not a
///    `format!`-built string) so the dispatcher cannot leak household
///    metadata via the body.
/// 2. Apple's silent / background push spec requires `aps.content-available
///    == 1` for the system to wake a backgrounded app. The earlier
///    `{"v":1}` payload satisfied (1) but **not** (2): the iPhone never
///    woke, so the long-poll never re-checked the owner-events log.
///
/// `aps.content-available` is the only field set; no badge, no alert,
/// no sound, no household-derived bytes. The `mutable-content` and
/// `category` keys are intentionally omitted — neither is required for
/// silent wakes and both would broaden the surface for accidental leaks.
pub const APNS_TICKLE_BODY: &[u8] = b"{\"aps\":{\"content-available\":1}}";

/// `apns-topic` build-time configuration. Resolved at startup from
/// `THEYOS_APNS_TOPIC` (the iSoyehtTerm bundle id) by the server's
/// process bootstrap. Production builds MUST set this; tests inject a
/// fixed value via [`ApnsTransport::topic`].
pub const APNS_TOPIC_ENV: &str = "THEYOS_APNS_TOPIC";

/// Runtime kill-switch. When set to `1`, [`dispatch_tickle`] short-
/// circuits to a `tracing::info!` log and returns `Ok(())` without
/// reaching Apple. Used in CI and developer sandboxes.
pub const PUSH_DISABLED_ENV: &str = "THEYOS_PUSH_DISABLED";

/// Errors observable from the dispatch path. Generic by design — the
/// failure surface MUST NOT leak any household-derived bytes.
#[derive(Debug, Error)]
pub enum ApnsError {
    #[error("APNS topic is not configured (set {APNS_TOPIC_ENV} at build time)")]
    TopicMissing,
    #[error("APNS HTTP/2 transport rejected the request")]
    TransportRejected,
    #[error("APNS HTTP/2 transport timed out")]
    Timeout,
}

/// Abstracts the HTTP/2 client so the runtime spy test can inject a
/// recorder. Implementations MUST consume `body` byte-equal to
/// [`APNS_TICKLE_BODY`]; the trait's contract is "the request body
/// you send to Apple is exactly the bytes I hand you".
pub trait ApnsTransport: Send + Sync + 'static {
    fn topic(&self) -> &str;
    fn send<'a>(
        &'a self,
        push_token: &'a [u8],
        body: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), ApnsError>> + Send + 'a>>;
}

/// Dispatch a single APNS tickle. The body is **always**
/// [`APNS_TICKLE_BODY`] — there is no parameter that could let a
/// caller substitute different bytes.
///
/// When `THEYOS_PUSH_DISABLED=1`, this short-circuits to an info-level
/// `tracing` log and returns `Ok(())` without touching the transport.
///
/// The transport implementation is supplied by the server's process
/// state. Tests inject a spy directly via [`dispatch_tickle_with`].
pub async fn dispatch_tickle(token: &OwnerDevicePushToken) -> Result<(), ApnsError> {
    if std::env::var(PUSH_DISABLED_ENV).as_deref() == Ok("1") {
        tracing::info!(stage = "apns.disabled_at_runtime", "skipped APNS dispatch");
        return Ok(());
    }
    let transport = transport_state().ok_or(ApnsError::TopicMissing)?;
    dispatch_tickle_with(transport.as_ref(), token).await
}

/// Variant of [`dispatch_tickle`] that takes an explicit transport.
/// Used by the runtime spy test (T026) so a `&dyn ApnsTransport`
/// stand-in can capture every body the dispatcher emits without
/// actually opening an HTTP/2 connection. The body is **always**
/// [`APNS_TICKLE_BODY`].
pub async fn dispatch_tickle_with(
    transport: &dyn ApnsTransport,
    token: &OwnerDevicePushToken,
) -> Result<(), ApnsError> {
    transport
        .send(token.push_token.as_ref(), APNS_TICKLE_BODY)
        .await
}

// Process-wide transport slot. Set by the server bootstrap once at
// startup; never mutated thereafter.
static APNS_TRANSPORT: std::sync::OnceLock<std::sync::Arc<dyn ApnsTransport>> =
    std::sync::OnceLock::new();

/// Install the production APNS transport. May only be called once
/// per process.
///
/// # Errors
///
/// Returns the supplied `transport` back to the caller if a transport
/// was already installed.
pub fn install_transport(
    transport: std::sync::Arc<dyn ApnsTransport>,
) -> Result<(), std::sync::Arc<dyn ApnsTransport>> {
    APNS_TRANSPORT.set(transport)
}

fn transport_state() -> Option<std::sync::Arc<dyn ApnsTransport>> {
    APNS_TRANSPORT.get().cloned()
}

// -----------------------------------------------------------------------
// Compile-time API-shape assertion (T025).
//
// If the public signature of `dispatch_tickle` ever drifts, this
// const item fails to compile. The closure body is never executed —
// it exists solely to apply a `Fn(&OwnerDevicePushToken) -> Future<…>`
// constraint to the function item.
// -----------------------------------------------------------------------

// Compile-time API-shape pin: assigning `dispatch_tickle` to a fn
// pointer with the exact `&OwnerDevicePushToken` input type fails to
// compile if the input drifts (e.g., a new `event: &OwnerEvent`
// parameter). The async return type is opaque and therefore not
// nameable in a fn-pointer position, so the **return-shape** half of
// the assertion lives in the source-level lint
// (`admin/rust/scripts/lint-apns-payload.sh`) and the **byte-level**
// invariant lives in the runtime spy test
// (`tests/apns_dispatcher_payload.rs`). Together the three layers
// enforce Constitution III's "no household metadata reaches the push
// provider" property structurally.
#[allow(dead_code, clippy::used_underscore_items)]
const _SIG_CHECK_INPUT_ARITY: fn() = || {
    fn accept_one_token_ref<F>(_: F)
    where
        F: for<'a> Fn(
            &'a OwnerDevicePushToken,
        ) -> Pin<Box<dyn Future<Output = Result<(), ApnsError>> + Send + 'a>>,
    {
    }
    accept_one_token_ref(
        |t: &OwnerDevicePushToken| -> Pin<Box<dyn Future<Output = Result<(), ApnsError>> + Send + '_>> {
            Box::pin(dispatch_tickle(t))
        },
    );
};
