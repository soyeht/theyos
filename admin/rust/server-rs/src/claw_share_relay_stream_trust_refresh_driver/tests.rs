#![cfg(test)]

use super::*;
use std::sync::atomic::AtomicBool;

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use household_rs::LoadedIdentity;
use household_rs::claw_share::SlotId;
use household_rs::household_mesh_log::{LogEntry, MeshEvent};
use household_rs::household_record::HouseholdRecord;
use household_rs::ids::{MachineId, derive_household_id, derive_machine_id};
use household_rs::issuer_trust::MachineIssuerError;
use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
use household_rs::machine_cert::{MachineCert, Platform, SignOptions};

use crate::claw_share_relay_stream_contract::{
    RelayStreamClawStaticPublicKey, RelayStreamContractError, RelayStreamExpectedPath,
    RelayStreamOfferContract, RelayStreamOfferPayload, RelayStreamResource,
};
use crate::claw_share_relay_stream_trust_context_health::{
    RelayStreamTrustContextHealthError, RelayStreamTrustContextRefreshPolicy,
};
use crate::claw_share_rendezvous_stream_relay::RendezvousToken;

const NOW: u64 = 1_800_000_000;

// Household root distinct from the machine signer, mirroring the health-module
// fixtures: trust acceptance is via cert + membership, not the root fallback.
fn hh() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0xAA; 32]).unwrap()
}

fn machine() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap()
}

fn other_machine() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0xCC; 32]).unwrap()
}

fn guest_pub() -> P256PublicKey {
    P256Keypair::from_secret_scalar(&[0x33; 32])
        .unwrap()
        .public()
}

fn machine_cert() -> MachineCert {
    MachineCert::sign(
        &hh(),
        &machine().public(),
        &SignOptions {
            hh_id: derive_household_id(&hh().public()),
            hostname: "engine-mac".to_string(),
            platform: Platform::Macos,
            joined_at: NOW - 1_000,
        },
    )
    .unwrap()
}

fn record_with(members: Vec<MachineId>) -> HouseholdRecord {
    HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: derive_household_id(&hh().public()),
        hh_pub: hh().public(),
        name: "home".to_string(),
        created_at: 0,
        shamir_k: 1,
        shamir_n: 1,
        members,
        is_follower: false,
    }
}

fn member_record() -> HouseholdRecord {
    record_with(vec![derive_machine_id(&machine().public())])
}

fn identity_with(record: HouseholdRecord) -> Arc<LoadedIdentity> {
    Arc::new(LoadedIdentity {
        record,
        cert: machine_cert(),
        hh_priv: None,
        m_priv: Box::new(machine()),
        backing: "software",
    })
}

fn household_with(record: HouseholdRecord) -> HouseholdState {
    HouseholdState::loaded(identity_with(record))
}

fn offer() -> RelayStreamOfferContract {
    let payload = RelayStreamOfferPayload::new(
        RendezvousToken::try_new(vec![0x42; 16]).unwrap(),
        "claw_alpha".to_string(),
        SlotId([0x22; 16]),
        guest_pub(),
        RelayStreamResource::Pty,
        RelayStreamExpectedPath::RelayStream,
        "relay-stream://127.0.0.1:49152".to_string(),
        RelayStreamClawStaticPublicKey::try_new([0x77; 32]).unwrap(),
        NOW + 600,
    );
    RelayStreamOfferContract::sign(payload, &machine()).unwrap()
}

fn append_device_removed(mesh_log: &MeshLogStore, device: &P256PublicKey) {
    let entry = LogEntry::sign(
        NOW,
        hh().public(),
        MeshEvent::DirectoryDeviceRemoved {
            device_pub: device.clone(),
        },
        &hh(),
    )
    .unwrap();
    mesh_log.append(entry).unwrap();
}

async fn runtime_with(
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
    max_stale_secs: u64,
    max_consecutive_failures: u32,
    now: u64,
) -> Arc<RelayStreamTrustContextRuntime> {
    let policy = RelayStreamTrustContextRefreshPolicy::new(
        Duration::from_secs(max_stale_secs),
        max_consecutive_failures,
    )
    .unwrap();
    Arc::new(
        RelayStreamTrustContextRuntime::load(household, mesh_log, now, policy)
            .await
            .unwrap(),
    )
}

// A now_unix that returns a controllable logical clock AND counts each call.
// The driver calls now_unix exactly once per refresh attempt, so the counter
// is the number of refresh attempts started.
fn clocked_now(
    clock: Arc<AtomicU64>,
    counter: Arc<AtomicUsize>,
) -> Arc<dyn Fn() -> Option<u64> + Send + Sync> {
    Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        Some(clock.load(Ordering::SeqCst))
    })
}

async fn wait_for_refreshes(counter: &Arc<AtomicUsize>, at_least: usize) {
    for _ in 0..400 {
        if counter.load(Ordering::SeqCst) >= at_least {
            return;
        }
        sleep(Duration::from_millis(5)).await;
    }
    panic!(
        "expected at least {at_least} refreshes, saw {}",
        counter.load(Ordering::SeqCst)
    );
}

async fn wait_until<F: Fn() -> bool>(predicate: F) {
    for _ in 0..400 {
        if predicate() {
            return;
        }
        sleep(Duration::from_millis(5)).await;
    }
    panic!("condition not met in time");
}

// `MachineIssuerError` is not `PartialEq`, so callers pass a matcher closure.
fn offer_rejected(
    runtime: &RelayStreamTrustContextRuntime,
    is_expected: impl Fn(&MachineIssuerError) -> bool,
) -> bool {
    match runtime.issuer_trust_if_healthy(NOW) {
        Ok(trust) => match trust.verify_offer(&offer(), NOW) {
            Err(RelayStreamContractError::IssuerUnauthorized(got)) => is_expected(&got),
            _ => false,
        },
        Err(_) => false,
    }
}

#[tokio::test]
async fn tick_keeps_runtime_healthy_past_max_stale() {
    let household = household_with(member_record());
    let mesh_log = Arc::new(MeshLogStore::new());
    // max_stale = 2s: without refresh, the runtime is stale at NOW+5.
    let runtime = runtime_with(&household, &mesh_log, 2, 2, NOW).await;
    let clock = Arc::new(AtomicU64::new(NOW));
    let counter = Arc::new(AtomicUsize::new(0));
    let trigger = Arc::new(Notify::new());

    let handle = spawn_relay_stream_trust_refresh_driver(
        Arc::clone(&runtime),
        household.clone(),
        Arc::clone(&mesh_log),
        RelayStreamTrustRefreshConfig::new(Duration::from_millis(30)),
        Arc::clone(&trigger),
        clocked_now(Arc::clone(&clock), Arc::clone(&counter)),
    )
    .unwrap();

    // Bump the logical clock past max_stale before the first 30ms tick. The
    // tick keeps refreshing at the current clock, so last_success keeps pace
    // and the gate stays healthy at NOW+5 (it would be stale without it).
    clock.store(NOW + 5, Ordering::SeqCst);
    wait_until(|| runtime.ensure_healthy(NOW + 5).is_ok()).await;

    runtime.ensure_healthy(NOW + 5).unwrap();
    drop(handle);
}

#[tokio::test]
async fn trigger_forces_refresh_before_tick() {
    let household = household_with(member_record());
    let mesh_log = Arc::new(MeshLogStore::new());
    let runtime = runtime_with(&household, &mesh_log, 20, 2, NOW).await;
    let clock = Arc::new(AtomicU64::new(NOW));
    let counter = Arc::new(AtomicUsize::new(0));
    let trigger = Arc::new(Notify::new());

    // A 10s tick will not fire during this sub-second test, so any refresh is
    // driven solely by the trigger.
    let handle = spawn_relay_stream_trust_refresh_driver(
        Arc::clone(&runtime),
        household.clone(),
        Arc::clone(&mesh_log),
        RelayStreamTrustRefreshConfig::new(Duration::from_secs(10)),
        Arc::clone(&trigger),
        clocked_now(Arc::clone(&clock), Arc::clone(&counter)),
    )
    .unwrap();

    trigger.notify_one();
    wait_for_refreshes(&counter, 1).await;
    assert!(counter.load(Ordering::SeqCst) >= 1);
    drop(handle);
}

#[tokio::test]
async fn member_removal_propagates_after_trigger() {
    let household = household_with(member_record());
    let mesh_log = Arc::new(MeshLogStore::new());
    let runtime = runtime_with(&household, &mesh_log, 20, 2, NOW).await;
    // Initially the machine-signed offer is accepted.
    runtime
        .issuer_trust_if_healthy(NOW)
        .unwrap()
        .verify_offer(&offer(), NOW)
        .unwrap();

    let clock = Arc::new(AtomicU64::new(NOW));
    let counter = Arc::new(AtomicUsize::new(0));
    let trigger = Arc::new(Notify::new());
    let handle = spawn_relay_stream_trust_refresh_driver(
        Arc::clone(&runtime),
        household.clone(),
        Arc::clone(&mesh_log),
        RelayStreamTrustRefreshConfig::new(Duration::from_secs(10)),
        Arc::clone(&trigger),
        clocked_now(Arc::clone(&clock), Arc::clone(&counter)),
    )
    .unwrap();

    // Remove the machine from members, then trigger: the refresh re-reads the
    // record and the live trust now rejects the offer (runtime stays healthy).
    household
        .set_loaded(identity_with(record_with(vec![derive_machine_id(
            &other_machine().public(),
        )])))
        .await;
    trigger.notify_one();
    wait_until(|| offer_rejected(&runtime, |e| matches!(e, MachineIssuerError::NonMember))).await;
    drop(handle);
}

#[tokio::test]
async fn directory_device_removed_propagates_after_trigger() {
    let household = household_with(member_record());
    let mesh_log = Arc::new(MeshLogStore::new());
    let runtime = runtime_with(&household, &mesh_log, 20, 2, NOW).await;
    runtime
        .issuer_trust_if_healthy(NOW)
        .unwrap()
        .verify_offer(&offer(), NOW)
        .unwrap();

    let clock = Arc::new(AtomicU64::new(NOW));
    let counter = Arc::new(AtomicUsize::new(0));
    let trigger = Arc::new(Notify::new());
    let handle = spawn_relay_stream_trust_refresh_driver(
        Arc::clone(&runtime),
        household.clone(),
        Arc::clone(&mesh_log),
        RelayStreamTrustRefreshConfig::new(Duration::from_secs(10)),
        Arc::clone(&trigger),
        clocked_now(Arc::clone(&clock), Arc::clone(&counter)),
    )
    .unwrap();

    // Append a DirectoryDeviceRemoved for the machine to the SAME mesh log the
    // driver holds, then trigger: the refreshed projection rejects the offer.
    append_device_removed(&mesh_log, &machine().public());
    trigger.notify_one();
    wait_until(|| offer_rejected(&runtime, |e| matches!(e, MachineIssuerError::DeviceRemoved)))
        .await;
    drop(handle);
}

#[tokio::test]
async fn refresh_error_is_tolerated_and_stops_serving_after_limit() {
    let household = household_with(member_record());
    let mesh_log = Arc::new(MeshLogStore::new());
    // max_consecutive_failures = 2.
    let runtime = runtime_with(&household, &mesh_log, 20, 2, NOW).await;
    runtime.issuer_trust_if_healthy(NOW).unwrap();

    let clock = Arc::new(AtomicU64::new(NOW));
    let counter = Arc::new(AtomicUsize::new(0));
    let trigger = Arc::new(Notify::new());
    let handle = spawn_relay_stream_trust_refresh_driver(
        Arc::clone(&runtime),
        household.clone(),
        Arc::clone(&mesh_log),
        RelayStreamTrustRefreshConfig::new(Duration::from_secs(10)),
        Arc::clone(&trigger),
        clocked_now(Arc::clone(&clock), Arc::clone(&counter)),
    )
    .unwrap();

    // Clear the held household so every refresh now returns Err. Trigger twice
    // (each consumed before the next), reaching the failure limit. The driver
    // must keep running, and the runtime must stop serving.
    household.clear().await;
    trigger.notify_one();
    wait_for_refreshes(&counter, 1).await;
    trigger.notify_one();
    wait_for_refreshes(&counter, 2).await;
    wait_until(|| {
        matches!(
            runtime.issuer_trust_if_healthy(NOW),
            Err(RelayStreamTrustContextHealthError::RefreshFailing { .. })
        )
    })
    .await;

    // Driver survived the errors: a further trigger still drives an attempt.
    trigger.notify_one();
    wait_for_refreshes(&counter, 3).await;
    drop(handle);
}

#[tokio::test]
async fn clock_recovery_requires_a_green_refresh_not_just_a_plausible_reading() {
    // The real driver sequence, which calling `clear_clock_unusable()`
    // directly cannot prove: an unusable clock marks the context unhealthy;
    // the clock coming BACK is not enough on its own, because clearing the
    // flag before a successful refresh would serve the last-good context
    // again; only a plausible reading AND a green refresh recover.
    let household = household_with(member_record());
    let mesh_log = Arc::new(MeshLogStore::new());
    let runtime = runtime_with(&household, &mesh_log, 20, 5, NOW).await;
    runtime.issuer_trust_if_healthy(NOW).unwrap();

    // The seam returns `None` until flipped, so the driver sees an unusable
    // wall clock.
    let usable = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicUsize::new(0));
    let seam_usable = Arc::clone(&usable);
    let seam_counter = Arc::clone(&counter);
    let now_unix: Arc<dyn Fn() -> Option<u64> + Send + Sync> = Arc::new(move || {
        seam_counter.fetch_add(1, Ordering::SeqCst);
        seam_usable.load(Ordering::SeqCst).then_some(NOW)
    });

    let trigger = Arc::new(Notify::new());
    let handle = spawn_relay_stream_trust_refresh_driver(
        Arc::clone(&runtime),
        household.clone(),
        Arc::clone(&mesh_log),
        RelayStreamTrustRefreshConfig::new(Duration::from_secs(10)),
        Arc::clone(&trigger),
        now_unix,
    )
    .unwrap();

    // 1. Unusable clock => unhealthy.
    trigger.notify_one();
    wait_until(|| {
        matches!(
            runtime.issuer_trust_if_healthy(NOW),
            Err(RelayStreamTrustContextHealthError::ClockUnusable)
        )
    })
    .await;

    // 2. Clock comes back BUT the refresh fails: must STILL be unusable.
    //    Clearing the flag before the refresh would wrongly recover here.
    household.clear().await;
    usable.store(true, Ordering::SeqCst);
    let before = counter.load(Ordering::SeqCst);
    trigger.notify_one();
    wait_for_refreshes(&counter, before + 1).await;
    assert!(
        matches!(
            runtime.issuer_trust_if_healthy(NOW),
            Err(RelayStreamTrustContextHealthError::ClockUnusable)
        ),
        "a plausible clock with a FAILING refresh must not recover",
    );

    // 3. Only now, with BOTH a plausible clock and a refresh that succeeds,
    //    may the runtime serve again.
    household.set_loaded(identity_with(member_record())).await;
    let before = counter.load(Ordering::SeqCst);
    trigger.notify_one();
    wait_for_refreshes(&counter, before + 1).await;
    wait_until(|| runtime.issuer_trust_if_healthy(NOW).is_ok()).await;

    drop(handle);
}

#[tokio::test]
async fn shutdown_stops_refreshing() {
    let household = household_with(member_record());
    let mesh_log = Arc::new(MeshLogStore::new());
    let runtime = runtime_with(&household, &mesh_log, 20, 2, NOW).await;
    let clock = Arc::new(AtomicU64::new(NOW));
    let counter = Arc::new(AtomicUsize::new(0));
    let trigger = Arc::new(Notify::new());
    let handle = spawn_relay_stream_trust_refresh_driver(
        Arc::clone(&runtime),
        household.clone(),
        Arc::clone(&mesh_log),
        RelayStreamTrustRefreshConfig::new(Duration::from_secs(10)),
        Arc::clone(&trigger),
        clocked_now(Arc::clone(&clock), Arc::clone(&counter)),
    )
    .unwrap();

    trigger.notify_one();
    wait_for_refreshes(&counter, 1).await;
    sleep(Duration::from_millis(30)).await; // let the refresh settle, loop re-park
    handle.shutdown();
    sleep(Duration::from_millis(50)).await; // let the loop observe cancel and break
    let after_shutdown = counter.load(Ordering::SeqCst);

    // No further triggers drive a refresh once shut down.
    for _ in 0..5 {
        trigger.notify_one();
    }
    sleep(Duration::from_millis(100)).await;
    assert_eq!(counter.load(Ordering::SeqCst), after_shutdown);
    drop(handle);
}

#[tokio::test]
async fn drop_stops_refreshing() {
    let household = household_with(member_record());
    let mesh_log = Arc::new(MeshLogStore::new());
    let runtime = runtime_with(&household, &mesh_log, 20, 2, NOW).await;
    let clock = Arc::new(AtomicU64::new(NOW));
    let counter = Arc::new(AtomicUsize::new(0));
    let trigger = Arc::new(Notify::new());
    let handle = spawn_relay_stream_trust_refresh_driver(
        Arc::clone(&runtime),
        household.clone(),
        Arc::clone(&mesh_log),
        RelayStreamTrustRefreshConfig::new(Duration::from_secs(10)),
        Arc::clone(&trigger),
        clocked_now(Arc::clone(&clock), Arc::clone(&counter)),
    )
    .unwrap();

    trigger.notify_one();
    wait_for_refreshes(&counter, 1).await;
    sleep(Duration::from_millis(30)).await; // let the refresh settle, loop re-park
    let before_drop = counter.load(Ordering::SeqCst);

    drop(handle); // aborts the task
    sleep(Duration::from_millis(50)).await;
    for _ in 0..5 {
        trigger.notify_one();
    }
    sleep(Duration::from_millis(100)).await;
    assert_eq!(counter.load(Ordering::SeqCst), before_drop);
}

#[tokio::test]
async fn config_rejects_zero_and_too_large_tick() {
    let household = household_with(member_record());
    let mesh_log = Arc::new(MeshLogStore::new());
    // max_stale = 10s.
    let runtime = runtime_with(&household, &mesh_log, 10, 2, NOW).await;
    let counter = Arc::new(AtomicUsize::new(0));
    let now = clocked_now(Arc::new(AtomicU64::new(NOW)), Arc::clone(&counter));
    let trigger = Arc::new(Notify::new());

    assert!(matches!(
        spawn_relay_stream_trust_refresh_driver(
            Arc::clone(&runtime),
            household.clone(),
            Arc::clone(&mesh_log),
            RelayStreamTrustRefreshConfig::new(Duration::ZERO),
            Arc::clone(&trigger),
            Arc::clone(&now),
        ),
        Err(RelayStreamTrustRefreshConfigError::TickZero)
    ));
    // tick == max_stale rejected: must be strictly below.
    assert!(matches!(
        spawn_relay_stream_trust_refresh_driver(
            Arc::clone(&runtime),
            household.clone(),
            Arc::clone(&mesh_log),
            RelayStreamTrustRefreshConfig::new(Duration::from_secs(10)),
            Arc::clone(&trigger),
            Arc::clone(&now),
        ),
        Err(RelayStreamTrustRefreshConfigError::TickNotBelowMaxStale { .. })
    ));
    // tick > max_stale rejected.
    assert!(matches!(
        spawn_relay_stream_trust_refresh_driver(
            Arc::clone(&runtime),
            household.clone(),
            Arc::clone(&mesh_log),
            RelayStreamTrustRefreshConfig::new(Duration::from_secs(11)),
            Arc::clone(&trigger),
            Arc::clone(&now),
        ),
        Err(RelayStreamTrustRefreshConfigError::TickNotBelowMaxStale { .. })
    ));

    // No task was spawned, so now_unix was never called.
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}
