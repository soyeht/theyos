//! Dev-only standalone CLAW responder for the Product A `relay_stream` PUBLIC smoke.
//!
//! Mirror of `relay_stream_relay_dev.rs`, but for the CLAW side. It runs ONLY the
//! claw responder — no full engine (no `THEYOS_BASE_DOMAIN`, firecracker, `SQLite`,
//! warm pool) — and reverse-connects to a live public relay (the blind splicer),
//! so a real off-LAN guest (`friend-cli relay-offer-dial --offer-file`) reaches it
//! over the real network with NO gated box deploy: everything runs on the operator's
//! own machine plus the relay.
//!
//! NOT wired into the engine, `household_bootstrap`, or `main`: it runs only when
//! invoked explicitly AND `THEYOS_RELAY_STREAM_CLAW_DEV=1` — default-off by
//! construction and by env gate. It builds a THROWAWAY self-consistent household
//! (fixed dev scalars; a pure test identity, never production), mints a PUBLIC
//! `relay_stream` offer for an env-supplied `CLAW_ID` + `GUEST_DEVICE_PUB`,
//! publishes the claw in its own in-memory mesh-log projection so the LIVE Public
//! Rev gate (`check_relay_stream_public`) opens, writes the offer CBOR to
//! `OFFER_OUT` for out-of-band transfer to the guest, then reverse-connects to
//! `RELAY_ENDPOINT` and serves the credential-less PTY responder (the Public path
//! of half B). It reuses the production responder / verifier / reverse-connect /
//! mint / PTY-router unchanged — only the household and the offer source are the
//! throwaway dev fixtures.
//!
//! Env:
//! - `THEYOS_RELAY_STREAM_CLAW_DEV=1` — the gate (default-off).
//! - `CLAW_ID` — the claw id to publish + mint for.
//! - `GUEST_DEVICE_PUB` — hex SEC1 of the dialing device key (from
//!   `friend-cli relay-offer-dial --device-secret`); the offer is minted for it.
//! - `RELAY_ENDPOINT` — `IP:port` of the live relay the claw reverse-connects to
//!   AND the address the offer points the guest at (single source).
//! - `OFFER_OUT` — path to write the offer CBOR (default `offer.cbor`).
//! - `OFFER_TTL_SECS` — offer lifetime (default 600).
//!
//! Dialing a NON-loopback (public) relay is allowed because the binary is already
//! gated by `THEYOS_RELAY_STREAM_CLAW_DEV=1`; it prints a loud warning. The relay
//! wire carries only the plaintext rendezvous hello and then end-to-end
//! Noise-encrypted ciphertext, spliced blind.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use household_rs::LoadedIdentity;
use household_rs::cbor;
use household_rs::claw_share::{ClawShareSlotStore, SLOT_ID_LEN, SlotId};
use household_rs::claw_share_data_tunnel::ReplayGuard;
use household_rs::claw_share_relay_stream_contract::{
    RelayStreamClawStaticPublicKey, RelayStreamOfferContract, RelayStreamResource,
    mint_relay_stream_public_offer,
};
use household_rs::household_mesh_log::{MeshLogStore, build_claw_site_published_event};
use household_rs::household_record::HouseholdRecord;
use household_rs::ids::{derive_household_id, derive_machine_id};
use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
use household_rs::machine_cert::{MachineCert, Platform, SignOptions};

use server_rs::claw_share_pty_target::{PtyPolicy, PtyTargetRouter};
use server_rs::claw_share_relay_stream_admission::RelayStreamAdmission;
use server_rs::claw_share_relay_stream_noise::generate_relay_stream_noise_static_keypair;
use server_rs::claw_share_relay_stream_responder::ResponderDataTunnelDeps;
use server_rs::claw_share_relay_stream_responder_params::RelayStreamResponderParams;
use server_rs::claw_share_relay_stream_responder_reverse_connect::{
    RelayStreamResponderReverseConnectConfig, serve_relay_stream_responder_reverse_connect,
};
use server_rs::claw_share_relay_stream_trust_context_health::{
    RelayStreamTrustContextRefreshPolicy, RelayStreamTrustContextRuntime,
};
use server_rs::claw_share_rendezvous_stream_relay::RendezvousToken;
use server_rs::household_state::HouseholdState;

const CLAW_DEV_GATE_ENV: &str = "THEYOS_RELAY_STREAM_CLAW_DEV";

// Fixed dev scalars for the THROWAWAY household (a pure test identity — NOT secret,
// NEVER production). The owner scalar is the engine machine key = the offer signer;
// the root scalar signs the machine cert (distinct from the machine key, so trust
// acceptance is via cert + membership, mirroring the relay_stream fixtures).
const DEV_OWNER_SCALAR: [u8; 32] = [0x11; 32];
const DEV_HOUSEHOLD_ROOT_SCALAR: [u8; 32] = [0xAA; 32];

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Re-arm backoff base: the delay after a successful pairing and the first retry.
const REARM_BACKOFF_BASE: Duration = Duration::from_millis(500);
/// Re-arm backoff ceiling: consecutive unpaired attempts never wait longer than this.
const REARM_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Exponential re-arm backoff between reverse-connect attempts: the base after a
/// pairing (`consecutive_failures == 0`) or the first failure, doubling per
/// consecutive failure, capped at `REARM_BACKOFF_MAX`. Keeps the dev claw from
/// hammering the relay (and tripping its rate limits) when no guest is dialing,
/// while re-arming promptly right after a real pairing.
fn rearm_delay(consecutive_failures: u32) -> Duration {
    if consecutive_failures == 0 {
        return REARM_BACKOFF_BASE;
    }
    let shift = (consecutive_failures - 1).min(8);
    (REARM_BACKOFF_BASE * 2u32.pow(shift)).min(REARM_BACKOFF_MAX)
}

fn dev_owner_signer() -> P256Keypair {
    P256Keypair::from_secret_scalar(&DEV_OWNER_SCALAR).expect("dev owner scalar is valid")
}

fn dev_household_root() -> P256Keypair {
    P256Keypair::from_secret_scalar(&DEV_HOUSEHOLD_ROOT_SCALAR).expect("dev root scalar is valid")
}

fn dev_machine_cert(owner_pub: &P256PublicKey) -> MachineCert {
    let root = dev_household_root();
    MachineCert::sign(
        &root,
        owner_pub,
        &SignOptions {
            hh_id: derive_household_id(&root.public()),
            hostname: "claw-dev-mac-alpha".to_string(),
            platform: Platform::Macos,
            joined_at: 0,
        },
    )
    .expect("sign dev machine cert")
}

fn dev_household_record(owner_pub: &P256PublicKey) -> HouseholdRecord {
    let root = dev_household_root();
    HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: derive_household_id(&root.public()),
        hh_pub: root.public(),
        name: "claw-dev".to_string(),
        created_at: 0,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![derive_machine_id(owner_pub)],
        is_follower: false,
    }
}

/// A loaded throwaway household whose identity authorizes `dev_owner_signer()` as
/// the active machine issuer (so `verify_offer_with_context` accepts offers it
/// signs).
fn dev_household_state(owner_pub: &P256PublicKey) -> HouseholdState {
    HouseholdState::loaded(Arc::new(LoadedIdentity {
        record: dev_household_record(owner_pub),
        cert: dev_machine_cert(owner_pub),
        hh_priv: None,
        m_priv: Box::new(dev_owner_signer()),
        backing: "software",
    }))
}

/// An in-memory mesh-log with `claw_id` PUBLISHED (a self-signed `ClawSitePublished`),
/// so the projection the trust runtime serves opens the Public Rev gate.
fn dev_published_mesh_log(claw_id: &str, owner: &P256Keypair, now: u64) -> MeshLogStore {
    let mesh_log = MeshLogStore::new();
    let entry = build_claw_site_published_event(claw_id.to_string(), now, owner.public(), owner)
        .expect("build ClawSitePublished");
    mesh_log.append(entry).expect("append ClawSitePublished");
    mesh_log
}

/// The claw-side admission over a healthy trust runtime built from the throwaway
/// household + the published mesh-log. The admitted seam drives the live Rev gate.
async fn dev_admission(
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
    now: u64,
) -> RelayStreamAdmission {
    let policy = RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(3_600), 3)
        .expect("refresh policy is valid");
    let runtime = RelayStreamTrustContextRuntime::load(household, mesh_log, now, policy)
        .await
        .expect("load trust runtime");
    RelayStreamAdmission::new(Arc::new(runtime))
}

#[allow(clippy::too_many_arguments)]
fn dev_public_offer(
    claw_id: &str,
    guest_device_pub: P256PublicKey,
    claw_static_pub: RelayStreamClawStaticPublicKey,
    relay_endpoint: String,
    not_after: u64,
    now: u64,
    owner: &P256Keypair,
) -> RelayStreamOfferContract {
    mint_relay_stream_public_offer(
        RendezvousToken::try_new(vec![0x42; 16]).expect("rendezvous token"),
        SlotId([0u8; SLOT_ID_LEN]), // unused for the Public audience
        guest_device_pub,
        claw_id.to_string(),
        RelayStreamResource::Pty,
        relay_endpoint,
        claw_static_pub,
        not_after,
        now,
        owner,
    )
    .expect("mint public offer")
}

fn env_required(key: &str) -> String {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => {
            eprintln!("relay_stream claw dev: required env {key} is missing or empty");
            std::process::exit(2);
        }
    }
}

fn decode_guest_device_pub(hex_str: &str) -> P256PublicKey {
    let bytes = hex::decode(hex_str).unwrap_or_else(|error| {
        eprintln!("relay_stream claw dev: GUEST_DEVICE_PUB is not valid hex: {error}");
        std::process::exit(2);
    });
    P256PublicKey::from_bytes(&bytes).unwrap_or_else(|error| {
        eprintln!("relay_stream claw dev: GUEST_DEVICE_PUB is not a valid P-256 key: {error}");
        std::process::exit(2);
    })
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let gated = std::env::var(CLAW_DEV_GATE_ENV)
        .map(|value| value.trim() == "1")
        .unwrap_or(false);
    if !gated {
        eprintln!(
            "{CLAW_DEV_GATE_ENV} != 1 — relay_stream claw dev is default-OFF. \
             Set {CLAW_DEV_GATE_ENV}=1 to run (test machine only)."
        );
        return Ok(());
    }

    let claw_id = env_required("CLAW_ID");
    let guest_device_pub = decode_guest_device_pub(&env_required("GUEST_DEVICE_PUB"));
    let relay_endpoint_env = env_required("RELAY_ENDPOINT");
    let offer_out = std::env::var("OFFER_OUT")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "offer.cbor".to_string());
    let ttl_secs: u64 = std::env::var("OFFER_TTL_SECS")
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(600);

    let relay_addr: SocketAddr = relay_endpoint_env.parse().unwrap_or_else(|error| {
        eprintln!(
            "relay_stream claw dev: RELAY_ENDPOINT '{relay_endpoint_env}' is not an IP:port: {error}"
        );
        std::process::exit(2);
    });

    let now = now_unix();
    let owner = dev_owner_signer();
    let owner_pub = owner.public();
    let not_after = now.saturating_add(ttl_secs);

    // Throwaway household + a mesh-log that PUBLISHES the claw → the live Public
    // Rev gate opens for this claw on this engine only.
    let mesh_log = dev_published_mesh_log(&claw_id, &owner, now);
    let household = dev_household_state(&owner_pub);
    let admission = dev_admission(&household, &mesh_log, now).await;

    // Claw Noise static key; the offer's claw_static_pub == this key's public.
    let noise_keypair = generate_relay_stream_noise_static_keypair().expect("noise keypair");
    let claw_static_pub = noise_keypair.public_key().clone();

    // Mint the PUBLIC offer. relay_endpoint points the guest at the SAME relay this
    // claw reverse-connects to (single source, no divergence).
    let relay_endpoint = format!("relay-stream://{relay_endpoint_env}");
    let offer = dev_public_offer(
        &claw_id,
        guest_device_pub,
        claw_static_pub,
        relay_endpoint.clone(),
        not_after,
        now,
        &owner,
    );

    let offer_bytes = cbor::to_canonical_vec(&offer).expect("encode offer");
    std::fs::write(&offer_out, &offer_bytes)?;
    eprintln!(
        "relay_stream claw dev: wrote {} offer bytes to {offer_out} \
         (claw_id={claw_id} resource=Pty audience=Public relay_endpoint={relay_endpoint} not_after={not_after})",
        offer_bytes.len()
    );
    eprintln!(
        "  transfer {offer_out} to the off-LAN guest, then run: \
         THEYOS_RELAY_STREAM_DIAL=1 friend-cli relay-offer-dial --device-secret <hex> --offer-file {offer_out}"
    );

    // Responder params + deps. slots is empty: the Public audience consumes no slot.
    let params = Arc::new(RelayStreamResponderParams {
        bind_addr: "127.0.0.1:49152"
            .parse()
            .expect("dummy bind addr (unused in reverse-connect)"),
        auth_deadline: Duration::from_secs(60),
        idle_timeout: Duration::from_secs(300),
        admission,
        noise_keypair,
    });
    let deps = Arc::new(ResponderDataTunnelDeps::new(
        derive_household_id(&owner_pub),
        Arc::new(ClawShareSlotStore::new()),
        Arc::new(ReplayGuard::new()),
        PtyTargetRouter::new(PtyPolicy::from_env()),
    ));

    let allow_non_loopback = !relay_addr.ip().is_loopback();
    if allow_non_loopback {
        eprintln!(
            "WARNING: reverse-connecting to a NON-loopback (public) relay {relay_addr}. \
             This is a TEST-ONLY claw responder gated by {CLAW_DEV_GATE_ENV}=1, with a \
             throwaway household. Run it only for the smoke window and stop it afterward."
        );
    }
    let config = RelayStreamResponderReverseConnectConfig {
        relay_addr,
        connect_timeout: Duration::from_secs(10),
        hello_timeout: Duration::from_secs(10),
        allow_non_loopback_relay_addr: allow_non_loopback,
    };

    let offer = Arc::new(offer);
    eprintln!(
        "relay_stream claw dev: reverse-connecting to relay {relay_addr} and serving the PTY \
         responder; each guest dial pairs one reverse-connect attempt. Ctrl-C to stop."
    );

    // Re-arm a reverse-connect for each guest dial. An unpaired attempt ends fast
    // (early EOF — no guest on the token); back off exponentially between
    // CONSECUTIVE failures so the dev claw never hammers the relay, and reset to the
    // base after a successful pairing so the next guest is served promptly.
    let mut consecutive_failures: u32 = 0;
    loop {
        match serve_relay_stream_responder_reverse_connect(
            config,
            Arc::clone(&offer),
            Arc::clone(&params),
            Arc::clone(&deps),
        )
        .await
        {
            Ok(()) => {
                eprintln!("relay_stream claw dev: reverse-connect session completed");
                consecutive_failures = 0;
            }
            Err(error) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                eprintln!(
                    "relay_stream claw dev: reverse-connect attempt ended ({error}); backing off \
                     {:?} (consecutive failures: {consecutive_failures})",
                    rearm_delay(consecutive_failures)
                );
            }
        }
        tokio::time::sleep(rearm_delay(consecutive_failures)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use server_rs::claw_share_relay_stream_session::relay_stream_offer_session_revoked;

    #[test]
    fn rearm_backoff_starts_at_base_doubles_caps_and_resets_on_pairing() {
        // 0 = post-pairing reset (and the first failure) → base.
        assert_eq!(rearm_delay(0), REARM_BACKOFF_BASE);
        assert_eq!(rearm_delay(1), Duration::from_millis(500));
        // Doubles per consecutive failure.
        assert_eq!(rearm_delay(2), Duration::from_secs(1));
        assert_eq!(rearm_delay(3), Duration::from_secs(2));
        assert_eq!(rearm_delay(4), Duration::from_secs(4));
        // Then caps (would be 8s) and stays capped — no overflow at large counts.
        assert_eq!(rearm_delay(5), REARM_BACKOFF_MAX);
        assert_eq!(rearm_delay(50), REARM_BACKOFF_MAX);
        // A pairing resets the loop counter to 0 → back to the base.
        assert_eq!(rearm_delay(0), REARM_BACKOFF_BASE);
    }

    // The throwaway household + a mesh-log that publishes the claw must open the
    // LIVE Public Rev gate for that claw (issuer active + not expired + published),
    // and keep it CLOSED for an unpublished claw (fail-closed). This is the
    // security-relevant wiring the dev bin depends on, proven with no network.
    #[tokio::test]
    async fn published_claw_opens_public_live_gate_unpublished_stays_closed() {
        let now = 1_900_000_000u64;
        let owner = dev_owner_signer();
        let guest = P256Keypair::from_secret_scalar(&[0x33; 32]).unwrap();
        let noise = generate_relay_stream_noise_static_keypair().unwrap();

        let mesh_log = dev_published_mesh_log("claw_smoke", &owner, now);
        let household = dev_household_state(&owner.public());
        let admission = dev_admission(&household, &mesh_log, now).await;
        let trust = admission.admit(now).expect("admit healthy runtime");

        let live = dev_public_offer(
            "claw_smoke",
            guest.public(),
            noise.public_key().clone(),
            "relay-stream://127.0.0.1:49152".to_string(),
            now + 600,
            now,
            &owner,
        );
        assert!(
            !relay_stream_offer_session_revoked(&live, &trust, now),
            "the published claw's public offer must be LIVE (gate open)"
        );

        let unpublished = dev_public_offer(
            "claw_unpublished",
            guest.public(),
            noise.public_key().clone(),
            "relay-stream://127.0.0.1:49152".to_string(),
            now + 600,
            now,
            &owner,
        );
        assert!(
            relay_stream_offer_session_revoked(&unpublished, &trust, now),
            "an unpublished claw must fail closed (gate shut)"
        );

        // Past not_after → fail closed even for the published claw.
        assert!(
            relay_stream_offer_session_revoked(&live, &trust, now + 601),
            "an expired offer must fail closed"
        );
    }
}
