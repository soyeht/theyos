#![cfg(test)]

use super::*;
use std::sync::Arc;

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
use crate::claw_share_rendezvous_stream_relay::RendezvousToken;

const NOW: u64 = 1_800_000_000;

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

// Household root distinct from the machine signer, so trust acceptance is via
// cert + membership, not the root fallback.
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

fn mesh_log_removing(device: &P256PublicKey) -> MeshLogStore {
    let mesh_log = MeshLogStore::new();
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
    mesh_log
}

fn policy() -> RelayStreamTrustContextRefreshPolicy {
    RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(60), 2).unwrap()
}

#[test]
fn policy_rejects_subsecond_or_zero_bounds() {
    // Zero and sub-second max_stale both round to 0 whole seconds and are
    // rejected; exactly 1 second is the smallest valid bound.
    assert!(matches!(
        RelayStreamTrustContextRefreshPolicy::new(Duration::ZERO, 1),
        Err(RelayStreamTrustContextPolicyError::MaxStaleZero)
    ));
    assert!(matches!(
        RelayStreamTrustContextRefreshPolicy::new(Duration::from_millis(1), 1),
        Err(RelayStreamTrustContextPolicyError::MaxStaleZero)
    ));
    assert!(matches!(
        RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(30), 0),
        Err(RelayStreamTrustContextPolicyError::MaxConsecutiveFailuresZero)
    ));
    assert!(RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(1), 1).is_ok());
}

#[tokio::test]
async fn load_with_empty_household_fails_closed() {
    let result = RelayStreamTrustContextRuntime::load(
        &HouseholdState::empty(),
        &MeshLogStore::new(),
        NOW,
        policy(),
    )
    .await;

    assert!(matches!(
        result,
        Err(RelayStreamTrustContextCacheError::HouseholdUnavailable)
    ));
}

#[tokio::test]
async fn healthy_runtime_serves_machine_signed_offer() {
    let household = household_with(member_record());
    let runtime =
        RelayStreamTrustContextRuntime::load(&household, &MeshLogStore::new(), NOW, policy())
            .await
            .unwrap();

    let trust = runtime.issuer_trust_if_healthy(NOW).unwrap();
    trust.verify_offer(&offer(), NOW).unwrap();
}

#[tokio::test]
async fn clock_unusable_stops_serving_immediately_not_after_max_stale() {
    // A clock failure must make the context unhealthy AT ONCE. Merely
    // skipping the refresh would leave the last-good context serving until
    // `max_stale` — handled-looking while still admitting.
    let household = household_with(member_record());
    let runtime =
        RelayStreamTrustContextRuntime::load(&household, &MeshLogStore::new(), NOW, policy())
            .await
            .unwrap();
    // Healthy first, at a time well inside `max_stale`.
    runtime.ensure_healthy(NOW).unwrap();

    runtime.mark_clock_unusable();

    assert!(matches!(
        runtime.ensure_healthy(NOW),
        Err(RelayStreamTrustContextHealthError::ClockUnusable)
    ));
    // And it must refuse to hand out the trust seam at all.
    assert!(runtime.issuer_trust_if_healthy(NOW).is_err());
}

#[tokio::test]
async fn clock_recovery_restores_serving() {
    // A plausible reading again must allow recovery, otherwise a transient
    // clock glitch would permanently wedge the engine.
    let household = household_with(member_record());
    let runtime =
        RelayStreamTrustContextRuntime::load(&household, &MeshLogStore::new(), NOW, policy())
            .await
            .unwrap();
    runtime.mark_clock_unusable();
    assert!(runtime.ensure_healthy(NOW).is_err());

    runtime.clear_clock_unusable();

    runtime.ensure_healthy(NOW).unwrap();
    runtime.issuer_trust_if_healthy(NOW).unwrap();
}

#[tokio::test]
async fn successful_refresh_with_backwards_clock_does_not_make_stale() {
    let household = household_with(member_record());
    let mesh_log = MeshLogStore::new();
    let runtime = RelayStreamTrustContextRuntime::load(&household, &mesh_log, NOW, policy())
        .await
        .unwrap();

    // A successful refresh observed with a clock that went backwards must not
    // move last_success backward; the runtime stays healthy at NOW.
    runtime
        .refresh_now(&household, &mesh_log, NOW - 1_000)
        .await
        .unwrap();

    runtime.issuer_trust_if_healthy(NOW).unwrap();
}

#[tokio::test]
async fn consecutive_refresh_failures_stop_serving() {
    let household = household_with(member_record());
    let mesh_log = MeshLogStore::new();
    let runtime = RelayStreamTrustContextRuntime::load(&household, &mesh_log, NOW, policy())
        .await
        .unwrap();

    // First failure (limit is 2): still healthy, still serves the old cache.
    let empty = HouseholdState::empty();
    assert!(runtime.refresh_now(&empty, &mesh_log, NOW).await.is_err());
    runtime.issuer_trust_if_healthy(NOW).unwrap();

    // Second failure reaches the limit: stop serving.
    assert!(runtime.refresh_now(&empty, &mesh_log, NOW).await.is_err());
    assert!(matches!(
        runtime.issuer_trust_if_healthy(NOW),
        Err(RelayStreamTrustContextHealthError::RefreshFailing { .. })
    ));
}

#[tokio::test]
async fn stale_context_stops_serving_without_new_failures() {
    let household = household_with(member_record());
    let runtime =
        RelayStreamTrustContextRuntime::load(&household, &MeshLogStore::new(), NOW, policy())
            .await
            .unwrap();

    runtime.issuer_trust_if_healthy(NOW).unwrap();
    assert!(matches!(
        runtime.issuer_trust_if_healthy(NOW + 61),
        Err(RelayStreamTrustContextHealthError::Stale { .. })
    ));
}

#[tokio::test]
async fn clock_backwards_is_treated_as_fresh() {
    let household = household_with(member_record());
    let runtime =
        RelayStreamTrustContextRuntime::load(&household, &MeshLogStore::new(), NOW, policy())
            .await
            .unwrap();

    // now < last_success must not panic and must read as fresh.
    runtime.ensure_healthy(NOW - 1_000).unwrap();
}

#[tokio::test]
async fn successful_refresh_resets_failures() {
    let household = household_with(member_record());
    let mesh_log = MeshLogStore::new();
    let runtime = RelayStreamTrustContextRuntime::load(&household, &mesh_log, NOW, policy())
        .await
        .unwrap();

    let empty = HouseholdState::empty();
    assert!(runtime.refresh_now(&empty, &mesh_log, NOW).await.is_err());
    assert!(runtime.refresh_now(&empty, &mesh_log, NOW).await.is_err());
    assert!(runtime.issuer_trust_if_healthy(NOW).is_err());

    // A successful refresh clears the failure counter and restores serving.
    runtime
        .refresh_now(&household, &mesh_log, NOW)
        .await
        .unwrap();
    runtime.issuer_trust_if_healthy(NOW).unwrap();
}

#[tokio::test]
async fn refresh_after_member_removed_serves_but_rejects_offer() {
    let household = household_with(member_record());
    let mesh_log = MeshLogStore::new();
    let runtime = RelayStreamTrustContextRuntime::load(&household, &mesh_log, NOW, policy())
        .await
        .unwrap();
    runtime
        .issuer_trust_if_healthy(NOW)
        .unwrap()
        .verify_offer(&offer(), NOW)
        .unwrap();

    // Remove the machine from members and refresh: the runtime stays healthy
    // (refresh succeeded), but the live trust now rejects the offer.
    household
        .set_loaded(identity_with(record_with(vec![derive_machine_id(
            &other_machine().public(),
        )])))
        .await;
    runtime
        .refresh_now(&household, &mesh_log, NOW)
        .await
        .unwrap();

    let trust = runtime.issuer_trust_if_healthy(NOW).unwrap();
    assert!(matches!(
        trust.verify_offer(&offer(), NOW),
        Err(RelayStreamContractError::IssuerUnauthorized(
            MachineIssuerError::NonMember
        ))
    ));
}

#[tokio::test]
async fn refresh_after_directory_device_removed_serves_but_rejects_offer() {
    let household = household_with(member_record());
    let runtime =
        RelayStreamTrustContextRuntime::load(&household, &MeshLogStore::new(), NOW, policy())
            .await
            .unwrap();
    runtime
        .issuer_trust_if_healthy(NOW)
        .unwrap()
        .verify_offer(&offer(), NOW)
        .unwrap();

    runtime
        .refresh_now(&household, &mesh_log_removing(&machine().public()), NOW)
        .await
        .unwrap();

    let trust = runtime.issuer_trust_if_healthy(NOW).unwrap();
    assert!(matches!(
        trust.verify_offer(&offer(), NOW),
        Err(RelayStreamContractError::IssuerUnauthorized(
            MachineIssuerError::DeviceRemoved
        ))
    ));
}

#[tokio::test]
async fn debug_and_errors_do_not_leak_secret() {
    let household = household_with(member_record());
    let runtime =
        RelayStreamTrustContextRuntime::load(&household, &MeshLogStore::new(), NOW, policy())
            .await
            .unwrap();

    let debug = format!("{runtime:?}");
    assert!(debug.contains("redacted"));
    assert!(!debug.contains("private"));
    assert!(!debug.contains("secret"));

    for text in [
        format!("{:?}", RelayStreamTrustContextPolicyError::MaxStaleZero),
        format!(
            "{}",
            RelayStreamTrustContextHealthError::Stale {
                stale_secs: 99,
                max_stale_secs: 60
            }
        ),
    ] {
        assert!(!text.contains("private"));
        assert!(!text.contains("secret"));
        assert!(!text.contains("token"));
    }
}
