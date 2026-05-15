//! Compile-time API-shape audit for the APNS dispatcher.
//!
//! The dispatcher must not accept `OwnerEvent`, fingerprints, machine IDs, or
//! any other household-scoped data. Its public entry point is pinned to exactly
//! one input: `&OwnerDevicePushToken`.

use std::future::Future;
use std::pin::Pin;

use household_rs::owner_events::OwnerDevicePushToken;
use server_rs::apns_dispatcher::{ApnsError, dispatch_tickle};

fn accept_only_push_token<F>(_: F)
where
    F: for<'a> Fn(
        &'a OwnerDevicePushToken,
    ) -> Pin<Box<dyn Future<Output = Result<(), ApnsError>> + Send + 'a>>,
{
}

#[test]
fn dispatch_tickle_accepts_only_owner_device_push_token() {
    accept_only_push_token(
        |token: &OwnerDevicePushToken| -> Pin<
            Box<dyn Future<Output = Result<(), ApnsError>> + Send + '_>,
        > { Box::pin(dispatch_tickle(token)) },
    );
}
