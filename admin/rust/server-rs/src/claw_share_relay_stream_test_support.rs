//! Shared test fixtures for Product A `relay_stream` modules.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use household_rs::LoadedIdentity;
use household_rs::claw_share::{
    ClawShareSlotStore, GuestCredential, MAX_CREDENTIAL_TTL_SECS, SLOT_ID_LEN, SlotId, SlotRecord,
    SlotState,
};
use household_rs::claw_share_data_tunnel::{ReplayGuard, SessionAuthToken, TcpStreamRouter};
use household_rs::household_mesh_log::{MeshLogStore, ProjectedState};
use household_rs::household_record::HouseholdRecord;
use household_rs::ids::{derive_household_id, derive_machine_id};
use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
use household_rs::machine_cert::{MachineCert, Platform, SignOptions};
use household_rs::person_cert::derive_person_id;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::claw_share_relay_stream_admission::RelayStreamAdmission;
use crate::claw_share_relay_stream_contract::{
    RelayStreamClawStaticPublicKey, RelayStreamExpectedPath, RelayStreamOfferContract,
    RelayStreamOfferPayload, RelayStreamResource,
};
use crate::claw_share_relay_stream_issuer_trust::{
    RelayStreamIssuerTrust, RelayStreamTrustContext,
};
use crate::claw_share_relay_stream_noise::RelayStreamNoiseStaticKeypair;
use crate::claw_share_relay_stream_responder::ResponderDataTunnelDeps;
use crate::claw_share_relay_stream_responder_params::RelayStreamResponderParams;
use crate::claw_share_relay_stream_trust_context_health::{
    RelayStreamTrustContextRefreshPolicy, RelayStreamTrustContextRuntime,
};
use crate::claw_share_rendezvous_stream_relay::RendezvousToken;
use crate::household_state::HouseholdState;

pub(crate) const DATA_TUNNEL_SLOT: SlotId = SlotId([0x22u8; SLOT_ID_LEN]);
pub(crate) const DATA_TUNNEL_CLAW_ID: &str = "claw_test";
pub(crate) const RELAY_STREAM_CLAW_ID: &str = "claw_alpha";
pub(crate) const RELAY_STREAM_ENDPOINT: &str = "relay-stream://127.0.0.1:49152";
pub(crate) const RELAY_STREAM_BIND_ADDR: &str = "127.0.0.1:49152";

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn owner_signer() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap()
}

pub(crate) fn owner_pub() -> P256PublicKey {
    owner_signer().public()
}

pub(crate) fn household_root_signer() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0xAA; 32]).unwrap()
}

// MachineCert for `owner_signer()` signed by the distinct household root, so
// trust acceptance is via cert + membership (not the root fallback).
pub(crate) fn relay_stream_machine_cert() -> MachineCert {
    let hh = household_root_signer();
    MachineCert::sign(
        &hh,
        &owner_signer().public(),
        &SignOptions {
            hh_id: derive_household_id(&hh.public()),
            hostname: "engine-mac".to_string(),
            platform: Platform::Macos,
            joined_at: 0,
        },
    )
    .unwrap()
}

// Household record whose root is distinct from `owner_signer()` and lists it as
// the sole member machine.
pub(crate) fn relay_stream_household_record() -> HouseholdRecord {
    let hh = household_root_signer();
    HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: derive_household_id(&hh.public()),
        hh_pub: hh.public(),
        name: "home".to_string(),
        created_at: 0,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![derive_machine_id(&owner_signer().public())],
        is_follower: false,
    }
}

// Machine-issuer trust seam authorizing the offer signer `owner_signer()` (the
// engine machine key). Empty projection = no revocation. Drives the Claw-side
// trust path in noise/contract tests that need a bare seam.
pub(crate) fn relay_stream_issuer_trust() -> RelayStreamIssuerTrust {
    RelayStreamIssuerTrust::new(|| RelayStreamTrustContext {
        record: relay_stream_household_record(),
        cert: relay_stream_machine_cert(),
        projection: ProjectedState::default(),
    })
}

// A loaded household whose identity authorizes `owner_signer()` as the machine
// issuer, for building a trust runtime/admission.
pub(crate) fn relay_stream_household_state() -> HouseholdState {
    HouseholdState::loaded(Arc::new(LoadedIdentity {
        record: relay_stream_household_record(),
        cert: relay_stream_machine_cert(),
        hh_priv: None,
        m_priv: Box::new(owner_signer()),
        backing: "software",
    }))
}

// Admission factory over a healthy trust runtime authorizing `owner_signer()`.
// Generous policy so the runtime stays healthy across a normal test run.
pub(crate) async fn relay_stream_admission() -> RelayStreamAdmission {
    let policy = RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(3_600), 3).unwrap();
    let runtime = RelayStreamTrustContextRuntime::load(
        &relay_stream_household_state(),
        &MeshLogStore::new(),
        now_unix(),
        policy,
    )
    .await
    .unwrap();
    RelayStreamAdmission::new(Arc::new(runtime))
}

pub(crate) fn guest_signer() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x33; 32]).unwrap()
}

pub(crate) fn guest_pub() -> P256PublicKey {
    guest_signer().public()
}

pub(crate) fn attacker_signer() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x55; 32]).unwrap()
}

pub(crate) fn rendezvous_token(label: u8) -> RendezvousToken {
    RendezvousToken::try_new(vec![label; 16]).unwrap()
}

pub(crate) fn relay_stream_offer_for_static_pub(
    rendezvous_token: RendezvousToken,
    claw_static_pub: RelayStreamClawStaticPublicKey,
    signer: &dyn IdentityKey,
) -> RelayStreamOfferContract {
    let payload = RelayStreamOfferPayload::new(
        rendezvous_token,
        RELAY_STREAM_CLAW_ID.to_string(),
        DATA_TUNNEL_SLOT,
        guest_pub(),
        RelayStreamResource::Pty,
        RelayStreamExpectedPath::RelayStream,
        RELAY_STREAM_ENDPOINT.to_string(),
        claw_static_pub,
        now_unix() + 60,
    );
    RelayStreamOfferContract::sign(payload, signer).unwrap()
}

pub(crate) fn relay_stream_offer_signed_by(
    rendezvous_token: RendezvousToken,
    keypair: &RelayStreamNoiseStaticKeypair,
    signer: &dyn IdentityKey,
) -> RelayStreamOfferContract {
    relay_stream_offer_for_static_pub(rendezvous_token, keypair.public_key().clone(), signer)
}

pub(crate) fn relay_stream_offer(
    rendezvous_token: RendezvousToken,
    keypair: &RelayStreamNoiseStaticKeypair,
) -> RelayStreamOfferContract {
    relay_stream_offer_signed_by(rendezvous_token, keypair, &owner_signer())
}

pub(crate) async fn relay_stream_responder_params(
    keypair: RelayStreamNoiseStaticKeypair,
    auth_deadline: Duration,
) -> RelayStreamResponderParams {
    RelayStreamResponderParams {
        bind_addr: RELAY_STREAM_BIND_ADDR.parse::<SocketAddr>().unwrap(),
        auth_deadline,
        idle_timeout: Duration::from_secs(60),
        admission: relay_stream_admission().await,
        noise_keypair: keypair,
    }
}

pub(crate) fn data_tunnel_credential() -> GuestCredential {
    let owner = owner_signer();
    data_tunnel_credential_with_owner(owner.public(), &owner)
}

pub(crate) fn data_tunnel_credential_with_owner(
    owner_pub: P256PublicKey,
    owner_key: &dyn IdentityKey,
) -> GuestCredential {
    let issued_at = now_unix().saturating_sub(60);
    GuestCredential::sign(
        derive_household_id(&owner_pub),
        derive_person_id(&owner_pub),
        owner_pub,
        DATA_TUNNEL_CLAW_ID.to_string(),
        guest_signer().public(),
        DATA_TUNNEL_SLOT,
        issued_at,
        issued_at + MAX_CREDENTIAL_TTL_SECS.min(86_400),
        owner_key,
    )
    .unwrap()
}

pub(crate) fn data_tunnel_store() -> Arc<ClawShareSlotStore> {
    let store = ClawShareSlotStore::new();
    store
        .insert(SlotRecord {
            slot_id: DATA_TUNNEL_SLOT,
            claw_id: DATA_TUNNEL_CLAW_ID.to_string(),
            expires_at: now_unix() + 86_400,
            state: SlotState::Open,
        })
        .unwrap();
    store
        .consume_atomic(
            &DATA_TUNNEL_SLOT,
            DATA_TUNNEL_CLAW_ID,
            guest_signer().public(),
            now_unix(),
        )
        .unwrap();
    Arc::new(store)
}

pub(crate) fn data_tunnel_token_signed(
    audience: &str,
    credential_cbor: &[u8],
    signer: &P256Keypair,
    nonce: &[u8],
) -> SessionAuthToken {
    SessionAuthToken::sign(
        audience.to_string(),
        credential_cbor,
        "relay-stream".to_string(),
        DATA_TUNNEL_CLAW_ID.to_string(),
        nonce.to_vec(),
        now_unix() + 60,
        signer,
    )
    .unwrap()
}

pub(crate) fn data_tunnel_token(
    audience: &str,
    credential_cbor: &[u8],
    nonce: &[u8],
) -> SessionAuthToken {
    data_tunnel_token_signed(audience, credential_cbor, &guest_signer(), nonce)
}

pub(crate) fn data_tunnel_deps(
    slots: Arc<ClawShareSlotStore>,
    replay: Arc<ReplayGuard>,
    target_addr: String,
) -> ResponderDataTunnelDeps<TcpStreamRouter> {
    ResponderDataTunnelDeps::new(
        derive_household_id(&owner_pub()),
        slots,
        replay,
        TcpStreamRouter::new(target_addr),
    )
}

pub(crate) fn data_tunnel_deps_arc(
    target_addr: String,
) -> Arc<ResponderDataTunnelDeps<TcpStreamRouter>> {
    Arc::new(data_tunnel_deps(
        data_tunnel_store(),
        Arc::new(ReplayGuard::new()),
        target_addr,
    ))
}

pub(crate) async fn spawn_ack_target() -> String {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = target.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (mut sock, _) = target.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        loop {
            let n = match sock.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut reply = b"ACK:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            if sock.write_all(&reply).await.is_err() {
                break;
            }
            let _ = sock.flush().await;
        }
    });
    addr
}
