//! friend-cli — Mac/Linux friend-side client for the claw-share moment.
//!
//! Subcommands:
//!   claim <invite-uri> --engine <base-url>
//!         Decode the invite URI, generate a fresh P-256 device key,
//!         POST a signed claim to the engine, verify the returned
//!         credential, print the tunnel handle.
//!
//!   claim-relay <invite-uri>
//!         Same claim, but over the Nostr relay store-and-forward path.
//!
//!   relay-offer / relay-offer-dial
//!         Request / dial a `relay_stream` offer (the community-relay
//!         Plane-1 guest client): challenge → device proof-of-possession
//!         → signed `RelayStreamOfferContract`, then the Noise NK dial.
//!
//! This crate is the MESH-FREE relay-stream guest. The legacy L3 VPN
//! subcommands (mesh-up, connect-mesh, open-product-a) are intentionally
//! NOT present here.
//!
//! Production binding to Secure Enclave + persistent guest key storage
//! is iOS-specific (slice 9); the CLI uses an in-process ephemeral key
//! per invocation.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use household_rs::cbor;
use household_rs::claw_share::{
    CLAW_SHARE_GROUP_ACK_VERSION, ClaimNonce, ClawShareAck, ClawShareClaim, ClawShareGroupAck,
    ClawShareInvite, GroupClaimRequest, GuestCredential, TunnelHandle,
};
use household_rs::claw_share_data_tunnel::{
    HEALTH_PROBE, SessionAuthToken, TargetExit, TunnelAck, TunnelFrame, client_authenticate,
    client_health, client_open_stream, recv_frame, send_frame,
};
use household_rs::claw_share_relay_stream_contract::{
    RelayStreamExpectedPath, RelayStreamOfferContract, RelayStreamResource,
};
use household_rs::claw_share_relay_stream_endpoint::parse_relay_endpoint;
use household_rs::claw_share_relay_stream_noise::{
    RelayStreamNoiseAsyncStream, RelayStreamNoiseFramed,
};
use household_rs::claw_share_rendezvous_hello::{RendezvousHello, RendezvousRole};
use household_rs::keys::{
    IdentityKey, P256Keypair, P256PublicKey, P256Signature, verify_signature,
};
use household_rs::member_identity::MemberDeviceBinding;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Parser, Debug)]
#[command(name = "friend-cli", version, about = "Claw-share friend client")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Redeem a claw-share invite against the engine via HTTP
    /// (fast-path, requires direct reachability).
    Claim {
        /// Invite URI (begins with `soyeht://claw-share/v1?e=`).
        uri: String,
        /// Engine base URL — e.g. `http://mac-alpha.local:8091`.
        #[arg(long)]
        engine: String,
        /// Print full credential + tunnel JSON instead of a summary.
        #[arg(long)]
        verbose: bool,
    },
    /// Redeem a claw-share invite via the Nostr relay store-and-forward
    /// path. Uses `owner_engine_npub` + `claim_relays` from the invite.
    /// Works even when the engine is offline at the moment of tap —
    /// the relay queues the encrypted claim until the engine
    /// reconnects.
    ClaimRelay {
        /// Invite URI (begins with `soyeht://claw-share/v1?e=`).
        uri: String,
        /// Override the relay URL set in the invite. Useful for
        /// dev / smoke tests; production reads `claim_relays`.
        #[arg(long)]
        relay: Option<String>,
        /// Max seconds to wait for the ack on the relay. Defaults to
        /// 60s; persistent claims (engine truly offline at tap)
        /// outlive this window — the friend's outbox layer re-polls.
        #[arg(long, default_value_t = 60)]
        ack_timeout_secs: u64,
        #[arg(long)]
        verbose: bool,
    },
    /// Fase E2.5/E3: request a `relay_stream` offer for a GROUP membership or a
    /// PUBLIC site from the engine's loopback/mesh relay-offer endpoints
    /// (challenge → device proof-of-possession → signed `RelayStreamOfferContract`).
    /// This is the REQUEST half; dialing the returned offer is gated on the
    /// Group/Public data-tunnel auth design (separate step).
    RelayOffer {
        /// Engine base URL reachable over loopback or the secure overlay — e.g.
        /// `http://127.0.0.1:8091`. The relay-offer endpoints refuse other peers.
        #[arg(long)]
        engine: String,
        /// The claw to request access to.
        #[arg(long)]
        claw: String,
        /// Request a PUBLIC site offer (no membership). Exclusive with --group.
        #[arg(long)]
        public: bool,
        /// Request a GROUP offer for this group id (needs --member-secret + --npub).
        #[arg(long)]
        group: Option<String>,
        /// Member secret scalar (64 hex chars) — the long-lived member key whose
        /// `member_id` the engine has enrolled in the group. Dev/smoke input; the
        /// production member key lives in the Keychain/Secure Enclave.
        #[arg(long)]
        member_secret: Option<String>,
        /// The mesh npub this device routes under (recorded in the binding).
        #[arg(long)]
        npub: Option<String>,
        /// Requested offer lifetime in seconds (the engine caps it).
        #[arg(long)]
        ttl_secs: Option<u64>,
        #[arg(long)]
        verbose: bool,
    },
    /// Fase E2.5/E3: dial a PRE-MINTED `relay_stream` offer read from a file (canonical
    /// CBOR of a `RelayStreamOfferContract`). The offer is obtained out-of-band (e.g.
    /// `dev-mint-relay-offer mode=public` on the engine over loopback → file → off-LAN
    /// guest), so no mesh/engine reachability is needed to get it. With `--offer-file`,
    /// dials when `THEYOS_RELAY_STREAM_DIAL=1`; without it, just prints the dialing
    /// device's public key (to feed the offer mint).
    RelayOfferDial {
        /// Dialing device secret scalar (64 hex chars). Its public key MUST equal the
        /// offer's `guest_device_pub` (the key the offer was minted for). Dev/smoke
        /// input; production device keys are ephemeral/Secure-Enclave.
        #[arg(long)]
        device_secret: String,
        /// Path to the pre-minted offer (canonical CBOR). Omit to only print the
        /// device public key for the mint step.
        #[arg(long)]
        offer_file: Option<PathBuf>,
        #[arg(long)]
        verbose: bool,
    },
    /// Path A: acquire a GROUP `relay_stream` offer fully off-LAN over the Nostr
    /// relay store-and-forward path (CGNAT-immune). Self-authenticating: a
    /// member-signed `MemberDeviceBinding` + device proof-of-possession ride inside
    /// the `ClawShareClaim`'s `group_request`, so it needs no invite slot and no
    /// engine challenge round-trip — the claim's own nonce IS the group challenge.
    /// The engine replies with a credential-less `ClawShareGroupAck` carrying the
    /// signed offer; with `THEYOS_RELAY_STREAM_DIAL=1` the returned offer is dialed.
    GroupClaimRelay {
        /// Relay URL to publish the claim on (`ws://` or `wss://`).
        #[arg(long)]
        relay: String,
        /// Engine Nostr receive pubkey — x-only hex or bech32 npub — the
        /// `owner_engine_npub` the engine's relay loop subscribes on.
        #[arg(long)]
        engine_npub: String,
        /// Group id the member is enrolled in.
        #[arg(long)]
        group: String,
        /// Claw id the group has been granted.
        #[arg(long)]
        claw: String,
        /// Member secret scalar (64 hex chars) whose `member_id` the engine has
        /// enrolled in the group. Dev/smoke input; the production member key lives
        /// in the Keychain/Secure Enclave.
        #[arg(long)]
        member_secret: String,
        /// Device secret scalar (64 hex chars). Its public key threads the whole
        /// flow: it signs the device `PoP`, is bound in the `MemberDeviceBinding`, is
        /// the claim's `guest_device_pub`, and is the offer's dial key. Dev/smoke
        /// input; production device keys are ephemeral / Secure-Enclave.
        #[arg(long)]
        device_secret: String,
        /// The per-device mesh npub recorded in the binding.
        #[arg(long)]
        npub: String,
        /// Requested offer lifetime in seconds (the engine caps it at 600).
        #[arg(long)]
        ttl_secs: Option<u64>,
        /// Max seconds to wait for the group ack on the relay.
        #[arg(long, default_value_t = 60)]
        ack_timeout_secs: u64,
        #[arg(long)]
        verbose: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Claim {
            uri,
            engine,
            verbose,
        } => run_claim(&uri, &engine, verbose).await,
        Cmd::ClaimRelay {
            uri,
            relay,
            ack_timeout_secs,
            verbose,
        } => run_claim_via_relay(&uri, relay.as_deref(), ack_timeout_secs, verbose).await,
        Cmd::RelayOffer {
            engine,
            claw,
            public,
            group,
            member_secret,
            npub,
            ttl_secs,
            verbose,
        } => {
            run_relay_offer(RelayOfferArgs {
                engine,
                claw,
                public,
                group,
                member_secret,
                npub,
                ttl_secs,
                verbose,
            })
            .await
        }
        Cmd::RelayOfferDial {
            device_secret,
            offer_file,
            verbose,
        } => run_relay_offer_dial(&device_secret, offer_file.as_deref(), verbose).await,
        Cmd::GroupClaimRelay {
            relay,
            engine_npub,
            group,
            claw,
            member_secret,
            device_secret,
            npub,
            ttl_secs,
            ack_timeout_secs,
            verbose,
        } => {
            run_group_claim_via_relay(GroupClaimRelayArgs {
                relay,
                engine_npub,
                group,
                claw,
                member_secret,
                device_secret,
                npub,
                ttl_secs,
                ack_timeout_secs,
                verbose,
            })
            .await
        }
    }
}

async fn run_claim_via_relay(
    uri: &str,
    relay_override: Option<&str>,
    ack_timeout_secs: u64,
    verbose: bool,
) -> Result<()> {
    use nostr_relay_rs::nostr::prelude::*;
    use nostr_relay_rs::{
        CLAW_SHARE_RELAY_KIND, NostrRelayClient, decrypt_claim_payload, publish_encrypted_claim,
    };
    use std::time::Duration;

    let invite = ClawShareInvite::from_uri(uri).context("decode invite URI")?;
    let now = current_unix();
    invite
        .verify(now)
        .context("invite signature/expiry check failed")?;
    println!("invite ok: claw_id={}", invite.claw_id);
    if invite.owner_engine_npub.is_empty() {
        bail!("invite has no owner_engine_npub — engine has not enabled the relay path");
    }
    let engine_pub = PublicKey::from_hex(&invite.owner_engine_npub)
        .or_else(|_| {
            // Tolerate npub bech32 too.
            PublicKey::parse(&invite.owner_engine_npub)
        })
        .context("parse owner_engine_npub")?;

    let relay_url = match relay_override {
        Some(r) => r.to_string(),
        None => invite
            .claim_relays
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("invite has no claim_relays and --relay not set"))?,
    };

    // Fresh Nostr keys for the friend per claim. Production iOS uses
    // the SE-backed device identity; the CLI is a smoke-test tool.
    let friend_keys = Keys::generate();

    // Subscribe BEFORE publishing so we don't race the ack.
    let client = NostrRelayClient::connect(&relay_url)
        .await
        .context("connect relay")?;
    let ack_filter = Filter::new()
        .kind(Kind::Custom(CLAW_SHARE_RELAY_KIND))
        .pubkey(friend_keys.public_key());
    let mut sub = client
        .subscribe("friend-ack", &ack_filter)
        .await
        .context("subscribe for ack")?;
    // Drain the relay's initial EOSE before publishing. Fast local relays can
    // deliver the ack within milliseconds; draining after publish races and can
    // discard the ack itself.
    let _ = tokio::time::timeout(Duration::from_millis(500), sub.recv()).await;

    let guest_key = P256Keypair::generate();
    let claim = ClawShareClaim::sign(
        invite.slot_id.clone(),
        guest_key.public(),
        ClaimNonce::random(),
        now,
        &guest_key as &dyn IdentityKey,
    )
    .context("sign claim envelope")?;
    let claim_cbor = cbor::to_canonical_vec(&claim).context("encode claim CBOR")?;

    publish_encrypted_claim(&client, &friend_keys, &engine_pub, &claim_cbor)
        .await
        .context("publish encrypted claim")?;
    println!(
        "claim published to {} (target_npub={})",
        relay_url, invite.owner_engine_npub
    );
    println!("waiting up to {ack_timeout_secs}s for ack...");

    let Some(event) = tokio::time::timeout(Duration::from_secs(ack_timeout_secs), sub.recv())
        .await
        .context("ack timeout")?
    else {
        bail!("relay closed before ack arrived");
    };

    let payload = decrypt_claim_payload(&friend_keys, &event).context("decrypt ack payload")?;
    let ack: ClawShareAck = cbor::from_canonical_slice(&payload).context("decode CBOR ack")?;
    ack.credential
        .verify(current_unix())
        .context("credential signature/expiry")?;
    if ack.credential.owner_p_pub != invite.owner_p_pub {
        bail!("credential issuer mismatch");
    }
    if ack.credential.guest_device_pub != guest_key.public() {
        bail!("credential guest_device_pub mismatch — engine swapped our key");
    }
    println!("credential ok:");
    println!("  claw_id      {}", ack.credential.claw_id);
    println!("  expires_at   {}", ack.credential.expires_at);
    if verbose {
        println!("\nfull credential:\n{:#?}", ack.credential);
        println!("\ntunnel:\n{:#?}", ack.tunnel);
    }

    // Optional, default-off relay_stream guest dial (C7c-2c-3b). The claim has
    // already succeeded and `credential ok` is printed above; the dial is
    // best-effort and bounded by an overall timeout, so a relay that connects but
    // never pairs the guest with the claw cannot hang the command. A missing or
    // invalid offer never fails the claim.
    if let Some(offer) = verify_relay_stream_offer(&ack, &guest_key, current_unix()) {
        if relay_stream_dial_enabled() {
            run_relay_stream_dial(&offer, &guest_key, &ack.credential).await;
        }
    }
    Ok(())
}

// ─── Group claim flow (Path A: off-LAN GROUP offer over the Nostr relay) ──────

struct GroupClaimRelayArgs {
    relay: String,
    engine_npub: String,
    group: String,
    claw: String,
    member_secret: String,
    device_secret: String,
    npub: String,
    ttl_secs: Option<u64>,
    ack_timeout_secs: u64,
    verbose: bool,
}

/// Build the self-authenticating GROUP claim: the member-signed binding + a device
/// proof-of-possession wrapped in a `ClawShareClaim` whose OUTER nonce IS the group
/// challenge (the engine asserts `group_request.challenge == claim.nonce`, so no
/// engine challenge round-trip is needed — the loopback challenge endpoint is
/// unreachable off-LAN, and freshness rides this single-use nonce). Pure (no I/O)
/// so the construction is unit-tested without a live relay.
fn build_group_claim(
    binding: MemberDeviceBinding,
    device_key: &P256Keypair,
    group_id: String,
    claw_id: String,
    ttl_secs: Option<u64>,
    nonce: ClaimNonce,
    now: u64,
) -> Result<ClawShareClaim> {
    let device_pub = device_key.public();
    let challenge = nonce.0.to_vec();
    let group_request = GroupClaimRequest::sign(
        binding,
        group_id,
        claw_id,
        challenge,
        ttl_secs,
        device_key as &dyn IdentityKey,
    )
    .context("sign group claim request")?;
    ClawShareClaim::sign_group(
        device_pub,
        nonce,
        now,
        group_request,
        device_key as &dyn IdentityKey,
    )
    .context("sign group claim envelope")
}

/// Path A: acquire a GROUP `relay_stream` offer fully off-LAN over the Nostr relay
/// store-and-forward path, then (optionally) dial it. The claim self-authenticates
/// via a member-signed `MemberDeviceBinding` + device `PoP` carried inside
/// `ClawShareClaim.group_request`; the engine replies with a credential-less
/// `ClawShareGroupAck` carrying the signed offer, which is dialed with the SAME
/// device key when `THEYOS_RELAY_STREAM_DIAL=1`.
async fn run_group_claim_via_relay(args: GroupClaimRelayArgs) -> Result<()> {
    use nostr_relay_rs::nostr::prelude::*;
    use nostr_relay_rs::{
        CLAW_SHARE_RELAY_KIND, NostrRelayClient, decrypt_claim_payload, publish_encrypted_claim,
    };
    use std::time::Duration;

    let now = current_unix();

    // Engine Nostr receive key — raw x-only hex or bech32 npub (same tolerance as
    // the device-claim relay path).
    let engine_pub = PublicKey::from_hex(&args.engine_npub)
        .or_else(|_| PublicKey::parse(&args.engine_npub))
        .context("parse --engine-npub")?;

    // ONE device key threads the whole flow: it signs the device PoP, is bound in
    // the MemberDeviceBinding, is the claim's guest_device_pub, and is the offer's
    // dial key. The member key only signs the binding. The SAME two secrets fed to
    // /dev-group-op reproduce the byte-identical member_id + device_pub the live
    // membership gate checks.
    let member_key = member_key_from_hex(&args.member_secret).context("--member-secret")?;
    let device_key = member_key_from_hex(&args.device_secret).context("--device-secret")?;
    let device_pub = device_key.public();
    let device_pub_hex = device_pub
        .as_bytes()
        .iter()
        .fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        });

    // Build the binding once so we can surface the derived member_id — it MUST
    // match the /dev-group-op enrollment for the membership gate to pass.
    let binding = MemberDeviceBinding::sign(
        &member_key as &dyn IdentityKey,
        device_pub.clone(),
        args.npub.clone(),
        now,
    )
    .context("sign member device binding")?;
    println!(
        "member_id (must match the /dev-group-op enrollment): {}",
        binding.member_id
    );
    println!("device_pub: {device_pub_hex}");

    let nonce = ClaimNonce::random();
    let claim = build_group_claim(
        binding,
        &device_key,
        args.group.clone(),
        args.claw.clone(),
        args.ttl_secs,
        nonce,
        now,
    )?;
    let claim_cbor = cbor::to_canonical_vec(&claim).context("encode group claim CBOR")?;

    // Fresh Nostr identity per claim; subscribe BEFORE publishing and drain the
    // relay's initial EOSE so a fast ack is not raced away.
    let friend_keys = Keys::generate();
    let client = NostrRelayClient::connect(&args.relay)
        .await
        .context("connect relay")?;
    let ack_filter = Filter::new()
        .kind(Kind::Custom(CLAW_SHARE_RELAY_KIND))
        .pubkey(friend_keys.public_key());
    let mut sub = client
        .subscribe("group-ack", &ack_filter)
        .await
        .context("subscribe for group ack")?;
    let _ = tokio::time::timeout(Duration::from_millis(500), sub.recv()).await;

    publish_encrypted_claim(&client, &friend_keys, &engine_pub, &claim_cbor)
        .await
        .context("publish encrypted group claim")?;
    println!(
        "group claim published to {} (engine_npub={})",
        args.relay, args.engine_npub
    );
    println!("waiting up to {}s for group ack...", args.ack_timeout_secs);

    let Some(event) = tokio::time::timeout(Duration::from_secs(args.ack_timeout_secs), sub.recv())
        .await
        .context("group ack timeout")?
    else {
        bail!("relay closed before group ack arrived");
    };

    let payload =
        decrypt_claim_payload(&friend_keys, &event).context("decrypt group ack payload")?;
    let ack: ClawShareGroupAck =
        cbor::from_canonical_slice(&payload).context("decode CBOR group ack")?;
    if ack.v != CLAW_SHARE_GROUP_ACK_VERSION {
        bail!(
            "group ack version mismatch: got {}, expected {}",
            ack.v,
            CLAW_SHARE_GROUP_ACK_VERSION
        );
    }

    // Credential-less: the group ack carries ONLY the signed relay_stream offer
    // (opaque canonical CBOR of a RelayStreamOfferContract), no GuestCredential.
    let offer = RelayStreamOfferContract::from_canonical_bytes(&ack.relay_stream_offer)
        .context("decode relay_stream offer from group ack")?;
    if offer.payload.guest_device_pub != device_pub {
        bail!("offer guest_device_pub mismatch — engine minted it for a different device");
    }
    println!("group ack ok — relay_stream offer received:");
    println!("  claw_id        {}", offer.payload.claw_id);
    println!("  resource       {:?}", offer.payload.resource);
    println!("  audience       {:?}", offer.payload.audience());
    println!("  expected_path  {:?}", offer.payload.expected_path);
    println!("  relay_endpoint {}", offer.payload.relay_endpoint);
    println!("  not_after      {}", offer.payload.not_after);
    if args.verbose {
        println!("  signer_pub     {:?}", offer.signer_pub);
    }

    // Credential-less Group dial (default OFF; the gated smoke sets
    // THEYOS_RELAY_STREAM_DIAL=1). Best-effort — the offer is already obtained.
    if relay_stream_dial_enabled() {
        run_relay_offer_session_dial(&offer, &device_key).await;
    } else {
        println!("note: dialing is OFF; set THEYOS_RELAY_STREAM_DIAL=1 to dial this offer.");
    }
    Ok(())
}

#[cfg(test)]
mod group_claim_tests {
    use super::*;

    #[test]
    fn build_group_claim_produces_engine_acceptable_claim() {
        // The friend-cli construction must satisfy every LOCAL invariant the
        // engine's verify_group_claim re-checks, so a correctly-built claim is only
        // ever rejected for membership/replay — never for shape.
        let member = P256Keypair::from_secret_scalar(&[0x55u8; 32]).unwrap();
        let device = P256Keypair::from_secret_scalar(&[0x33u8; 32]).unwrap();
        let now = 1_800_000_000u64;
        let nonce = ClaimNonce::random();
        let nonce_bytes = nonce.0;
        let binding =
            MemberDeviceBinding::sign(&member, device.public(), "npub_hex".into(), now).unwrap();
        let member_id = binding.member_id.clone();

        let claim = build_group_claim(
            binding,
            &device,
            "g".into(),
            "claw_a".into(),
            Some(600),
            nonce,
            now,
        )
        .expect("build group claim");

        // Outer device signature verifies (engine check #1).
        claim.verify(now).expect("outer device signature verifies");
        let gr = claim.group_request.as_ref().expect("group_request present");
        // challenge == the claim's own nonce (engine check #3 — no round-trip).
        assert_eq!(gr.challenge.as_slice(), &nonce_bytes[..]);
        // ONE device key: binding.device_pub == claim.guest_device_pub == PoP signer.
        assert_eq!(gr.binding.device_pub, claim.guest_device_pub);
        assert_eq!(gr.binding.device_pub, device.public());
        gr.binding
            .verify()
            .expect("member binding verifies (check #5)");
        gr.verify_device_pop()
            .expect("device PoP verifies (check #6)");
        // member_id is cryptographically derived, never free-form.
        assert_eq!(gr.binding.member_id, member_id);
        // Group sentinel: no participant_npub (engine check #9).
        assert!(claim.participant_npub.is_none());
        // Wire-stable canonical CBOR round-trip.
        let bytes = cbor::to_canonical_vec(&claim).unwrap();
        let decoded: ClawShareClaim = cbor::from_canonical_slice(&bytes).unwrap();
        assert_eq!(decoded, claim);
    }
}

// ─── Claim flow ──────────────────────────────────────────────────────────────

async fn run_claim(uri: &str, engine_base: &str, verbose: bool) -> Result<()> {
    let invite = ClawShareInvite::from_uri(uri).context("decode invite URI")?;
    let now = current_unix();
    invite
        .verify(now)
        .context("invite signature/expiry check failed")?;
    println!("invite ok: claw_id={}", invite.claw_id);

    let guest_key = P256Keypair::generate();
    let claim = ClawShareClaim::sign(
        invite.slot_id.clone(),
        guest_key.public(),
        ClaimNonce::random(),
        now,
        &guest_key as &dyn IdentityKey,
    )
    .context("sign claim envelope")?;

    let body = cbor::to_canonical_vec(&claim).context("encode claim CBOR")?;

    let url = format!(
        "{}/api/v1/claw-share/claim",
        engine_base.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .build()
        .context("build http client")?;
    let resp = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .header(reqwest::header::ACCEPT, "application/cbor")
        .body(body)
        .send()
        .await
        .context("post claim")?;

    let status = resp.status();
    let resp_bytes = resp.bytes().await.context("read response body")?;
    if !status.is_success() {
        // The engine emits a typed CBOR error envelope on failure;
        // try to surface it.
        if let Ok(v) = cbor::from_canonical_slice::<serde_json::Value>(&resp_bytes) {
            bail!("engine rejected claim ({status}): {v}");
        }
        bail!("engine rejected claim with status {status}");
    }

    let ack: ClawShareAck = cbor::from_canonical_slice(&resp_bytes).context("decode CBOR ack")?;
    let now_post = current_unix();
    ack.credential
        .verify(now_post)
        .context("credential signature/expiry check")?;
    if ack.credential.owner_p_pub != invite.owner_p_pub {
        bail!(
            "credential issuer mismatch: invite.owner_p_pub={:?} ack.owner_p_pub={:?}",
            invite.owner_p_pub,
            ack.credential.owner_p_pub
        );
    }
    if ack.credential.claw_id != invite.claw_id {
        bail!(
            "credential claw_id mismatch: invite={} ack={}",
            invite.claw_id,
            ack.credential.claw_id
        );
    }
    if ack.credential.guest_device_pub != guest_key.public() {
        bail!("credential guest_device_pub mismatch — engine swapped our key");
    }
    if ack.credential.slot_id != invite.slot_id {
        bail!("credential slot_id mismatch");
    }
    // Defense in depth — re-verify the credential signature locally
    // even though `verify` already did. Catches accidental dual-impl
    // drift if the canonical bytes ever diverge.
    let signing = household_rs::cbor::to_canonical_vec(&CredentialBody {
        v: ack.credential.v,
        kind: &ack.credential.kind,
        hh_id: &ack.credential.hh_id,
        owner_p_id: &ack.credential.owner_p_id,
        owner_p_pub: &ack.credential.owner_p_pub,
        claw_id: &ack.credential.claw_id,
        guest_device_pub: &ack.credential.guest_device_pub,
        slot_id: &ack.credential.slot_id,
        issued_at: ack.credential.issued_at,
        expires_at: ack.credential.expires_at,
    })
    .context("re-encode credential body")?;
    verify_signature(
        &ack.credential.owner_p_pub,
        &signing,
        &ack.credential.owner_signature,
    )
    .context("credential signature re-check")?;

    let _ = verify_relay_stream_offer(&ack, &guest_key, now_post);

    println!("credential ok:");
    println!("  claw_id      {}", ack.credential.claw_id);
    println!("  expires_at   {}", ack.credential.expires_at);
    println!(
        "  guest_pub    {} (len {})",
        hex_short(&ack.credential.guest_device_pub.0),
        ack.credential.guest_device_pub.0.len()
    );
    match &ack.tunnel {
        TunnelHandle::Loopback { channel } => {
            println!("  tunnel       Loopback {{ channel: {channel} }}");
            println!(
                "  warning: engine returned a loopback tunnel — this only \
                 works in-process. Cross-machine tests require the relay-stream \
                 community-relay path."
            );
        }
        TunnelHandle::Direct { host, port } => {
            println!("  tunnel       Direct {{ host: {host}, port: {port} }}");
        }
    }
    if verbose {
        println!("\nfull credential:\n{:#?}", ack.credential);
    }
    Ok(())
}

/// One-shot PTY payload over an open, authenticated data tunnel: type the
/// command, then `exit`, and collect the target's output until it exits or the
/// stream closes (15s deadline). Generic over the byte stream so it runs over
/// the `relay_stream` Noise transport.
async fn run_pty_command<T>(stream: &mut T, pty_cmd: &str) -> Result<String>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    send_frame(
        stream,
        &TunnelFrame::Data(format!("{pty_cmd}\n").into_bytes()),
    )
    .await
    .context("send command")?;
    send_frame(stream, &TunnelFrame::Data(b"exit\n".to_vec()))
        .await
        .context("send exit")?;
    let mut out = String::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, recv_frame(stream)).await {
            Ok(Ok(TunnelFrame::Data(d))) => out.push_str(&String::from_utf8_lossy(&d)),
            Ok(Ok(TunnelFrame::Exit(e))) => println!("PTY exit: {}", exit_label(e)),
            Ok(Ok(TunnelFrame::Error(r))) => bail!("PTY stream error: {r}"),
            // Clean close (Close frame) or read deadline reached (timeout Err).
            Ok(Ok(TunnelFrame::Close)) | Err(_) => break,
            Ok(Ok(_)) => {}
            Ok(Err(e)) => bail!("recv frame: {e}"),
        }
    }
    Ok(out)
}

/// Send a fixed HTTP/1.1 GET over the open `relay_stream` tunnel to the claw's
/// `ClawSite` backend and collect the response. Mirrors [`run_pty_command`]: the
/// request and response ride `TunnelFrame::Data` frames; the engine splices them
/// to/from the claw's site backend. `Connection: close` lets the backend signal
/// end-of-response by closing, which surfaces as `TunnelFrame::Close`. A
/// configurable request (method/path/host) is a follow-up.
async fn run_http_request<T>(stream: &mut T) -> Result<String>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let request = "GET / HTTP/1.1\r\nHost: clawsite.local\r\nConnection: close\r\n\r\n";
    send_frame(stream, &TunnelFrame::Data(request.as_bytes().to_vec()))
        .await
        .context("send ClawSite HTTP request")?;
    let mut out = String::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, recv_frame(stream)).await {
            Ok(Ok(TunnelFrame::Data(d))) => out.push_str(&String::from_utf8_lossy(&d)),
            Ok(Ok(TunnelFrame::Error(r))) => bail!("ClawSite stream error: {r}"),
            // Clean close (Close frame) or read deadline reached (timeout Err).
            Ok(Ok(TunnelFrame::Close)) | Err(_) => break,
            Ok(Ok(_)) => {}
            Ok(Err(e)) => bail!("recv frame: {e}"),
        }
    }
    Ok(out)
}

fn exit_label(e: TargetExit) -> String {
    match e {
        TargetExit::Code(c) => format!("code {c}"),
        TargetExit::Signal(s) => format!("signal {s}"),
        TargetExit::Lost => "lost".to_string(),
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn hex_short(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut h = String::with_capacity(20);
    for b in bytes.iter().take(8) {
        let _ = write!(h, "{b:02x}");
    }
    h.push('…');
    h
}

/// Parse + audience-verify a `relay_stream` offer optionally attached to a claim
/// ack (C7c-2b — the no-NEX guest path).
///
/// The engine MAY attach an opaque canonical-CBOR `RelayStreamOfferContract` to
/// the ack. Every call site has already verified the credential, so we pin the
/// offer's expected signer to the credential owner and require the offer to be
/// addressed to this guest device. In 2b we only parse, verify, and log it; the
/// dial / Noise handshake consumes the returned offer in 2c.
///
/// A missing offer is a clean no-op (today nothing emits one). A present but
/// invalid offer is logged opaquely and dropped — it MUST NOT fail the claim,
/// which already succeeded on the credential above. The rendezvous token is
/// never logged.
fn verify_relay_stream_offer(
    ack: &ClawShareAck,
    guest_key: &P256Keypair,
    now: u64,
) -> Option<RelayStreamOfferContract> {
    let bytes = ack.relay_stream_offer.as_ref()?;
    let Ok(offer) = RelayStreamOfferContract::from_canonical_bytes(&bytes[..]) else {
        eprintln!("warning: relay_stream offer present but could not be decoded; ignoring");
        return None;
    };
    if offer
        .verify_for_audience(&ack.credential.owner_p_pub, &guest_key.public(), now)
        .is_err()
    {
        eprintln!("warning: relay_stream offer failed verification; ignoring");
        return None;
    }
    if offer.payload.expected_path != RelayStreamExpectedPath::RelayStream {
        eprintln!(
            "warning: relay_stream offer expected_path is {:?}, not relay_stream; ignoring",
            offer.payload.expected_path
        );
        return None;
    }
    println!("relay_stream offer ok:");
    println!("  claw_id        {}", offer.payload.claw_id);
    println!(
        "  slot_id        {}",
        hex_short(offer.payload.slot_id.as_bytes())
    );
    println!("  resource       {:?}", offer.payload.resource);
    println!("  expected_path  {:?}", offer.payload.expected_path);
    println!("  relay_endpoint {}", offer.payload.relay_endpoint);
    println!("  not_after      {}", offer.payload.not_after);
    Some(offer)
}

fn parse_dial_flag(value: Option<&str>) -> bool {
    matches!(value.map(str::trim), Some("1" | "true" | "TRUE"))
}

/// Whether the optional `relay_stream` guest dial is enabled. Default OFF — the
/// existing direct path is unchanged unless `THEYOS_RELAY_STREAM_DIAL` is set.
fn relay_stream_dial_enabled() -> bool {
    parse_dial_flag(std::env::var("THEYOS_RELAY_STREAM_DIAL").ok().as_deref())
}

/// Establish the encrypted `relay_stream` transport to the claw, via the relay.
///
/// C7c-2c-3 (transport half): parse the offer's `relay-stream://` endpoint, dial
/// the relay over TCP, send the rendezvous hello so the relay can pair this guest
/// with the claw on the shared token, then run the Noise NK initiator handshake.
/// The prologue is derived from the audience-verified offer (the same offer the
/// 2b helper returned), pinning the credential owner as the expected signer and
/// this guest device as the audience. Returns the encrypted async stream ready
/// for the data-tunnel client (authenticate / open — wired in 2c-3b). The
/// rendezvous token is never logged.
async fn connect_relay_stream_transport(
    offer: &RelayStreamOfferContract,
    guest_key: &P256Keypair,
    credential: &GuestCredential,
    now: u64,
) -> Result<RelayStreamNoiseAsyncStream<tokio::net::TcpStream>> {
    use tokio::net::TcpStream;

    let (host, port) = parse_relay_endpoint(&offer.payload.relay_endpoint)
        .context("parse relay_stream endpoint")?;
    println!(
        "relay_stream dial: connecting to relay {host}:{port} (claw_id={}, resource={:?})",
        offer.payload.claw_id, offer.payload.resource
    );

    let mut stream = match tokio::time::timeout(
        std::time::Duration::from_secs(4),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return Err(error).context("tcp connect to relay_stream relay"),
        Err(_) => bail!("tcp connect to relay_stream relay timed out"),
    };

    // Rendezvous: announce role + token so the relay pairs us with the claw.
    let hello = RendezvousHello::new(
        RendezvousRole::Guest,
        offer.payload.rendezvous_token.clone(),
    );
    stream
        .write_all(&hello.encode())
        .await
        .context("send rendezvous hello")?;
    stream.flush().await.context("flush rendezvous hello")?;

    let framed = RelayStreamNoiseFramed::initiator_handshake(
        stream,
        offer,
        &credential.owner_p_pub,
        &guest_key.public(),
        now,
    )
    .await
    .context("relay_stream Noise handshake")?;
    println!("relay_stream Noise handshake ok; encrypted transport established");
    Ok(framed.into_async_stream())
}

/// Best-effort `relay_stream` dial, bounded by an overall timeout. Logs the
/// outcome; never returns an error to the caller because the claim has already
/// succeeded — a failed or hung dial (e.g. the relay connects but the claw never
/// pairs) must not affect the claim result or block the command.
async fn run_relay_stream_dial(
    offer: &RelayStreamOfferContract,
    guest_key: &P256Keypair,
    credential: &GuestCredential,
) {
    let now = current_unix();
    match tokio::time::timeout(
        // 30s backstop for the whole dial: TCP connect (<=4s) + rendezvous hello
        // + Noise handshake + auth/health/open + the PTY payload's own 15s
        // deadline can exceed 20s, so the outer budget must clear that sum.
        std::time::Duration::from_secs(30),
        dial_relay_stream(offer, guest_key, credential, now),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!("warning: relay_stream dial failed (claim already succeeded): {error}");
        }
        Err(_) => {
            eprintln!(
                "warning: relay_stream dial timed out (claim already succeeded); the relay \
                 connected but the tunnel did not complete"
            );
        }
    }
}

/// Full guest dial over the `relay_stream` transport: establish the encrypted
/// channel, then authenticate and open the data tunnel with the EXISTING
/// household data-tunnel client (no auth/frame reimplementation). The
/// `SessionAuthToken` is a proof-of-possession signed by the SAME guest key that
/// signed the claim, with `target_id = claw_id`. On the open stream it runs the
/// resource payload: a PTY smoke command (`Pty`) or a fixed HTTP/1.1 GET to the
/// claw's site backend (`ClawSite`). Configurable command/request are follow-ups.
async fn dial_relay_stream(
    offer: &RelayStreamOfferContract,
    guest_key: &P256Keypair,
    credential: &GuestCredential,
    now: u64,
) -> Result<()> {
    let tunnel = connect_relay_stream_transport(offer, guest_key, credential, now).await?;
    let mut tunnel =
        authenticate_open_relay_stream(tunnel, offer, guest_key, credential, now).await?;
    match offer.payload.resource {
        RelayStreamResource::Pty => {
            // Fixed smoke command for now; a configurable command is a follow-up.
            let output = run_pty_command(&mut tunnel, "echo relay-stream-ok")
                .await
                .context("relay_stream PTY payload")?;
            if output.contains("relay-stream-ok") {
                println!("relay_stream PTY payload ok: marker echoed");
            } else {
                bail!("relay_stream PTY payload did not echo the expected marker");
            }
        }
        RelayStreamResource::ClawSite => {
            let response = run_http_request(&mut tunnel)
                .await
                .context("relay_stream ClawSite payload")?;
            let status = response.lines().next().unwrap_or_default();
            if response.starts_with("HTTP/") {
                println!("relay_stream ClawSite payload ok: {status}");
            } else {
                bail!(
                    "relay_stream ClawSite payload did not return an HTTP response \
                     (got {} bytes)",
                    response.len()
                );
            }
        }
    }
    Ok(())
}

/// Authenticate + open the data tunnel over an already-established (Noise)
/// stream, using the EXISTING household data-tunnel client. Split out from the
/// connect/transport step so it is generic over the byte stream and can be
/// driven in-process against `serve_connection_io` without a live relay.
///
/// Mints a `SessionAuthToken` proof-of-possession signed by the SAME guest key
/// that signed the claim, bound to `target_id = claw_id`, with a CSPRNG nonce
/// (so two dials in the same process/second cannot collide) and an `now + 60`
/// TTL. Then runs `client_authenticate` → `client_health` → `client_open_stream`, in
/// that order. The nonce and rendezvous token are never logged.
async fn authenticate_open_relay_stream<T>(
    mut stream: T,
    offer: &RelayStreamOfferContract,
    guest_key: &P256Keypair,
    credential: &GuestCredential,
    now: u64,
) -> Result<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let credential_cbor = cbor::to_canonical_vec(credential).context("encode credential cbor")?;
    let mut nonce = vec![0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let token = SessionAuthToken::sign(
        format!("friend-relay-stream-{}-{now}", std::process::id()),
        &credential_cbor,
        offer.payload.relay_endpoint.clone(),
        offer.payload.claw_id.clone(),
        nonce,
        now + 60,
        guest_key as &dyn IdentityKey,
    )
    .context("mint relay_stream session auth token (proof-of-possession)")?;

    match client_authenticate(&mut stream, &credential_cbor, token)
        .await
        .context("relay_stream authenticate")?
    {
        TunnelAck::Ok { session_id, .. } => {
            println!("relay_stream auth ok: session_id={session_id}");
        }
        TunnelAck::Rejected { reason } => bail!("relay_stream auth rejected: {reason}"),
    }

    let echo = client_health(&mut stream, HEALTH_PROBE)
        .await
        .context("relay_stream health probe")?;
    if echo != HEALTH_PROBE {
        bail!("relay_stream health echo mismatch");
    }

    client_open_stream(&mut stream)
        .await
        .context("relay_stream open stream")?;
    println!("relay_stream tunnel open and authenticated");
    Ok(stream)
}

// ── Production relay-offer request client (Fase E2.5 / E3) ────────────────────
//
// Client for the engine's loopback/mesh relay-offer endpoints: GET a single-use
// challenge, then POST a Group (member binding + device proof-of-possession) or
// Public (dialer device key) request, and receive a signed
// `RelayStreamOfferContract`. Dialing that offer (the Group/Public data-tunnel
// auth) is a SEPARATE step gated on design approval; this is the request half.
//
// The `RelayOffer*` structs below are local mirrors of the engine's PRIVATE
// request/response types (server-rs::handlers_claw_share). Keep field names +
// `serde_bytes` byte-string framing + the device-PoP signed view in lock step
// with the engine (same precedent as `CredentialBody`). Canonical CBOR sorts map
// keys, so field order is irrelevant, but names/types/byte-framing must match.

const RELAY_OFFER_REQ_VERSION: u8 = 1;

#[derive(serde::Serialize)]
struct RelayOfferChallengeReq {
    v: u8,
}

#[derive(serde::Deserialize)]
struct RelayOfferChallengeResp {
    #[allow(dead_code)]
    v: u8,
    #[serde(with = "serde_bytes")]
    challenge: Vec<u8>,
    #[allow(dead_code)]
    not_after: u64,
}

#[derive(serde::Serialize)]
struct RelayOfferGroupReq {
    v: u8,
    #[serde(with = "serde_bytes")]
    challenge: Vec<u8>,
    binding: MemberDeviceBinding,
    group_id: String,
    claw_id: String,
    device_pop: P256Signature,
    ttl_secs: Option<u64>,
}

/// EXACT mirror of the engine's `RelayOfferGroupReqUnsigned` — the device
/// proof-of-possession signs over this canonical view, binding the request to the
/// fresh challenge + the exact group/claw/ttl. Verified under `binding.device_pub`.
#[derive(serde::Serialize)]
struct RelayOfferGroupReqUnsigned<'a> {
    v: u8,
    #[serde(with = "serde_bytes")]
    challenge: &'a [u8],
    group_id: &'a str,
    claw_id: &'a str,
    ttl_secs: Option<u64>,
}

#[derive(serde::Serialize)]
struct RelayOfferPublicReq {
    v: u8,
    #[serde(with = "serde_bytes")]
    challenge: Vec<u8>,
    dialer_device_pub: P256PublicKey,
    claw_id: String,
    ttl_secs: Option<u64>,
}

/// Build a signed Group offer request: a member-self-signed `MemberDeviceBinding`
/// for the dialing device + a device proof-of-possession over the challenge-bound
/// request view. Pure (no I/O) so it is unit-tested without a live engine.
#[allow(clippy::too_many_arguments)]
fn build_relay_offer_group_request(
    challenge: Vec<u8>,
    member_key: &dyn IdentityKey,
    device_key: &P256Keypair,
    participant_npub: String,
    group_id: String,
    claw_id: String,
    ttl_secs: Option<u64>,
    issued_at: u64,
) -> Result<RelayOfferGroupReq> {
    let binding =
        MemberDeviceBinding::sign(member_key, device_key.public(), participant_npub, issued_at)
            .context("sign member device binding")?;
    let unsigned = RelayOfferGroupReqUnsigned {
        v: RELAY_OFFER_REQ_VERSION,
        challenge: &challenge,
        group_id: &group_id,
        claw_id: &claw_id,
        ttl_secs,
    };
    let pop_bytes =
        cbor::to_canonical_vec(&unsigned).context("encode relay-offer group PoP bytes")?;
    let device_pop = (device_key as &dyn IdentityKey)
        .sign(&pop_bytes)
        .context("sign relay-offer group device proof-of-possession")?;
    Ok(RelayOfferGroupReq {
        v: RELAY_OFFER_REQ_VERSION,
        challenge,
        binding,
        group_id,
        claw_id,
        device_pop,
        ttl_secs,
    })
}

/// Build a Public offer request (no membership / no credential): the dialing
/// device's own key, the claw, and the fresh challenge.
fn build_relay_offer_public_request(
    challenge: Vec<u8>,
    dialer_device_pub: P256PublicKey,
    claw_id: String,
    ttl_secs: Option<u64>,
) -> RelayOfferPublicReq {
    RelayOfferPublicReq {
        v: RELAY_OFFER_REQ_VERSION,
        challenge,
        dialer_device_pub,
        claw_id,
        ttl_secs,
    }
}

/// POST canonical-CBOR `body` to `url`, returning the CBOR response bytes or a
/// surfaced engine error envelope.
async fn post_relay_offer_cbor(
    client: &reqwest::Client,
    url: &str,
    body: Vec<u8>,
    what: &str,
) -> Result<Vec<u8>> {
    let resp = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .header(reqwest::header::ACCEPT, "application/cbor")
        .body(body)
        .send()
        .await
        .with_context(|| format!("post {what}"))?;
    let status = resp.status();
    let bytes = resp.bytes().await.context("read response body")?;
    if !status.is_success() {
        if let Ok(v) = cbor::from_canonical_slice::<serde_json::Value>(&bytes) {
            bail!("engine rejected {what} ({status}): {v}");
        }
        bail!("engine rejected {what} with status {status}");
    }
    Ok(bytes.to_vec())
}

/// Fetch a single-use relay-offer challenge from the engine.
async fn fetch_relay_offer_challenge(
    client: &reqwest::Client,
    engine_base: &str,
) -> Result<Vec<u8>> {
    let url = format!(
        "{}/api/v1/claw-share/relay-offer/challenge",
        engine_base.trim_end_matches('/')
    );
    let body = cbor::to_canonical_vec(&RelayOfferChallengeReq {
        v: RELAY_OFFER_REQ_VERSION,
    })
    .context("encode relay-offer challenge request")?;
    let resp_bytes = post_relay_offer_cbor(client, &url, body, "relay-offer challenge").await?;
    let resp: RelayOfferChallengeResp =
        cbor::from_canonical_slice(&resp_bytes).context("decode relay-offer challenge response")?;
    Ok(resp.challenge)
}

struct RelayOfferArgs {
    engine: String,
    claw: String,
    public: bool,
    group: Option<String>,
    member_secret: Option<String>,
    npub: Option<String>,
    ttl_secs: Option<u64>,
    verbose: bool,
}

/// Parse a 64-hex-char secret scalar into a member key. Dev/smoke input only;
/// the production member key is persisted in the Keychain/Secure Enclave.
fn member_key_from_hex(hex: &str) -> Result<P256Keypair> {
    let hex = hex.trim();
    if hex.len() != 64 {
        bail!(
            "--member-secret must be 64 hex chars (32-byte scalar), got {}",
            hex.len()
        );
    }
    let mut scalar = [0u8; 32];
    for (i, byte) in scalar.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .context("--member-secret is not valid hex")?;
    }
    P256Keypair::from_secret_scalar(&scalar).context("derive member key from secret scalar")
}

/// Dial a received Group/Public `relay_stream` offer (Fase E2.5/E3). No credential:
/// the Noise prologue pins the offer's OWN signer (`offer.signer_pub` — the machine
/// issuer the claw verifies, so the prologue is byte-identical to the claw side),
/// and the data-tunnel `SessionAuthToken` is a proof-of-possession under the dialing
/// DEVICE key bound to `blake3(canonical offer)` + `claw_id` — exactly what the
/// claw's credential-less verifier checks. Same resource payload as the Device dial.
async fn dial_relay_stream_offer_session(
    offer: &RelayStreamOfferContract,
    device_key: &P256Keypair,
    now: u64,
) -> Result<()> {
    use tokio::net::TcpStream;

    let (host, port) = parse_relay_endpoint(&offer.payload.relay_endpoint)
        .context("parse relay_stream endpoint")?;
    println!(
        "relay_stream group/public dial: connecting to relay {host}:{port} \
         (claw_id={}, audience={:?}, resource={:?})",
        offer.payload.claw_id,
        offer.payload.audience(),
        offer.payload.resource
    );
    let mut stream = match tokio::time::timeout(
        std::time::Duration::from_secs(4),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return Err(error).context("tcp connect to relay_stream relay"),
        Err(_) => bail!("tcp connect to relay_stream relay timed out"),
    };
    // Rendezvous: announce role + token so the relay pairs us with the claw.
    let hello = RendezvousHello::new(
        RendezvousRole::Guest,
        offer.payload.rendezvous_token.clone(),
    );
    stream
        .write_all(&hello.encode())
        .await
        .context("send rendezvous hello")?;
    stream.flush().await.context("flush rendezvous hello")?;
    // Noise NK initiator; prologue pinned to the offer's signer (no credential owner).
    let framed = RelayStreamNoiseFramed::initiator_handshake(
        stream,
        offer,
        &offer.signer_pub,
        &device_key.public(),
        now,
    )
    .await
    .context("relay_stream Noise handshake")?;
    println!("relay_stream Noise handshake ok; encrypted transport established");
    let tunnel = framed.into_async_stream();
    let mut tunnel = authenticate_open_relay_stream_session(tunnel, offer, device_key, now).await?;

    match offer.payload.resource {
        RelayStreamResource::Pty => {
            let output = run_pty_command(&mut tunnel, "echo relay-stream-ok")
                .await
                .context("relay_stream PTY payload")?;
            if output.contains("relay-stream-ok") {
                println!("relay_stream PTY payload ok: marker echoed");
            } else {
                bail!("relay_stream PTY payload did not echo the expected marker");
            }
        }
        RelayStreamResource::ClawSite => {
            let response = run_http_request(&mut tunnel)
                .await
                .context("relay_stream ClawSite payload")?;
            let status = response.lines().next().unwrap_or_default();
            if response.starts_with("HTTP/") {
                println!("relay_stream ClawSite payload ok: {status}");
            } else {
                bail!(
                    "relay_stream ClawSite payload did not return an HTTP response (got {} bytes)",
                    response.len()
                );
            }
        }
    }
    Ok(())
}

/// Authenticate + open the data tunnel for a Group/Public dial over an
/// already-established (Noise) stream, with a credential-less proof-of-possession. Split out
/// (like the Device `authenticate_open_relay_stream`) so it is generic over the
/// byte stream and can be driven in-process against `serve_connection_io` without
/// a live relay. The token binds to blake3(canonical offer) — what the claw
/// derives server-side from its OWN verified offer — and is signed by the dialing
/// device key; `credential_cbor` carries the offer bytes (the claw uses its own).
async fn authenticate_open_relay_stream_session<T>(
    mut stream: T,
    offer: &RelayStreamOfferContract,
    device_key: &P256Keypair,
    now: u64,
) -> Result<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let offer_cbor = offer
        .payload
        .to_canonical_bytes()
        .context("encode offer payload for session PoP")?;
    let mut nonce = vec![0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let token = SessionAuthToken::sign(
        format!("friend-relay-stream-session-{}-{now}", std::process::id()),
        &offer_cbor,
        offer.payload.relay_endpoint.clone(),
        offer.payload.claw_id.clone(),
        nonce,
        now + 60,
        device_key as &dyn IdentityKey,
    )
    .context("mint relay_stream session auth token (proof-of-possession)")?;

    match client_authenticate(&mut stream, &offer_cbor, token)
        .await
        .context("relay_stream session authenticate")?
    {
        TunnelAck::Ok { session_id, .. } => {
            println!("relay_stream group/public auth ok: session_id={session_id}");
        }
        TunnelAck::Rejected { reason } => {
            bail!("relay_stream group/public auth rejected: {reason}")
        }
    }
    let echo = client_health(&mut stream, HEALTH_PROBE)
        .await
        .context("relay_stream health probe")?;
    if echo != HEALTH_PROBE {
        bail!("relay_stream health echo mismatch");
    }
    client_open_stream(&mut stream)
        .await
        .context("relay_stream open stream")?;
    println!("relay_stream tunnel open and authenticated");
    Ok(stream)
}

/// Best-effort wrapper around the Group/Public dial, bounded by an overall
/// timeout. Logs the outcome; never returns an error (the offer was already
/// obtained), mirroring the Device `run_relay_stream_dial`.
async fn run_relay_offer_session_dial(offer: &RelayStreamOfferContract, device_key: &P256Keypair) {
    let now = current_unix();
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        dial_relay_stream_offer_session(offer, device_key, now),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("warning: relay_stream group/public dial failed: {error}"),
        Err(_) => eprintln!("warning: relay_stream group/public dial timed out"),
    }
}

async fn run_relay_offer(args: RelayOfferArgs) -> Result<()> {
    if args.public == args.group.is_some() {
        bail!("specify exactly one of --public or --group <id>");
    }
    let client = reqwest::Client::builder()
        .build()
        .context("build http client")?;
    let challenge = fetch_relay_offer_challenge(&client, &args.engine).await?;
    println!("relay-offer challenge ok ({} bytes)", challenge.len());

    // One ephemeral device key for BOTH the request and the dial — the offer is
    // minted for this key (offer.guest_device_pub == device_key.public()), and the
    // dial's PoP must be signed by it.
    let device_key = P256Keypair::generate();
    let offer_bytes = if args.public {
        let req = build_relay_offer_public_request(
            challenge,
            device_key.public(),
            args.claw.clone(),
            args.ttl_secs,
        );
        let body = cbor::to_canonical_vec(&req).context("encode public offer request")?;
        let url = format!(
            "{}/api/v1/claw-share/relay-offer/public",
            args.engine.trim_end_matches('/')
        );
        post_relay_offer_cbor(&client, &url, body, "relay-offer public").await?
    } else {
        let group_id = args.group.clone().expect("group is Some (checked above)");
        let secret = args
            .member_secret
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--group requires --member-secret <64-hex>"))?;
        let npub = args
            .npub
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--group requires --npub <mesh-npub>"))?;
        let member_key = member_key_from_hex(secret)?;
        let req = build_relay_offer_group_request(
            challenge,
            &member_key as &dyn IdentityKey,
            &device_key,
            npub,
            group_id,
            args.claw.clone(),
            args.ttl_secs,
            current_unix(),
        )?;
        let body = cbor::to_canonical_vec(&req).context("encode group offer request")?;
        let url = format!(
            "{}/api/v1/claw-share/relay-offer/group",
            args.engine.trim_end_matches('/')
        );
        post_relay_offer_cbor(&client, &url, body, "relay-offer group").await?
    };

    let offer = RelayStreamOfferContract::from_canonical_bytes(&offer_bytes)
        .context("decode relay_stream offer")?;
    println!("relay_stream offer received:");
    println!("  claw_id        {}", offer.payload.claw_id);
    println!("  resource       {:?}", offer.payload.resource);
    println!("  audience       {:?}", offer.payload.audience());
    println!("  expected_path  {:?}", offer.payload.expected_path);
    println!("  relay_endpoint {}", offer.payload.relay_endpoint);
    println!("  not_after      {}", offer.payload.not_after);
    if args.verbose {
        println!("  signer_pub     {:?}", offer.signer_pub);
    }

    // Optional dial of the received offer (default OFF; the gated smoke sets
    // THEYOS_RELAY_STREAM_DIAL=1). Best-effort: the offer is already obtained.
    if relay_stream_dial_enabled() {
        run_relay_offer_session_dial(&offer, &device_key).await;
    } else {
        println!("note: dialing is OFF; set THEYOS_RELAY_STREAM_DIAL=1 to dial this offer.");
    }
    Ok(())
}

/// Dial a PRE-MINTED `relay_stream` offer read from a file (canonical CBOR of a
/// `RelayStreamOfferContract`). The offer is obtained out-of-band (e.g.
/// `dev-mint-relay-offer mode=public` on the engine over loopback → file → off-LAN
/// guest), so the guest needs NO mesh/engine reachability to get it — only the
/// public relay to dial. Without `--offer-file`, prints the dialing device's public
/// key so the operator can mint an offer for it; with it, validates the device key
/// matches the offer and dials when `THEYOS_RELAY_STREAM_DIAL=1`.
async fn run_relay_offer_dial(
    device_secret: &str,
    offer_file: Option<&std::path::Path>,
    verbose: bool,
) -> Result<()> {
    let device_key = member_key_from_hex(device_secret)?;
    let device_pub_hex = device_key
        .public()
        .as_bytes()
        .iter()
        .fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        });
    println!("dialing device pub (SEC1; give this to the offer mint): {device_pub_hex}");

    let Some(offer_file) = offer_file else {
        println!(
            "no --offer-file: printed the device pub only. Mint an offer for it \
             (dev-mint-relay-offer mode=public device_pub=<above>), then re-run with --offer-file."
        );
        return Ok(());
    };

    let bytes = std::fs::read(offer_file)
        .with_context(|| format!("read offer file {}", offer_file.display()))?;
    let offer = RelayStreamOfferContract::from_canonical_bytes(&bytes)
        .context("decode relay_stream offer from file")?;
    if offer.payload.guest_device_pub != device_key.public() {
        bail!(
            "device key does not match the offer: it was minted for a different \
             guest_device_pub. Mint the offer for {device_pub_hex}."
        );
    }
    println!("relay_stream offer (from file):");
    println!("  claw_id        {}", offer.payload.claw_id);
    println!("  resource       {:?}", offer.payload.resource);
    println!("  audience       {:?}", offer.payload.audience());
    println!("  expected_path  {:?}", offer.payload.expected_path);
    println!("  relay_endpoint {}", offer.payload.relay_endpoint);
    println!("  not_after      {}", offer.payload.not_after);
    if verbose {
        println!("  signer_pub     {:?}", offer.signer_pub);
    }

    if relay_stream_dial_enabled() {
        run_relay_offer_session_dial(&offer, &device_key).await;
    } else {
        println!("note: dialing is OFF; set THEYOS_RELAY_STREAM_DIAL=1 to dial this offer.");
    }
    Ok(())
}

/// Mirror of `GuestCredentialUnsigned` from `household-rs::claw_share`.
/// Re-declared locally because the host-side struct is private. Keep
/// field set + serialization order in lock step with the canonical
/// signing bytes the engine produces.
#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialBody<'a> {
    v: u8,
    kind: &'a str,
    hh_id: &'a household_rs::ids::HouseholdId,
    owner_p_id: &'a household_rs::machine_cert::PersonId,
    owner_p_pub: &'a household_rs::keys::P256PublicKey,
    claw_id: &'a str,
    guest_device_pub: &'a household_rs::keys::P256PublicKey,
    slot_id: &'a household_rs::claw_share::SlotId,
    issued_at: u64,
    expires_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── C7c-2b: relay_stream offer parse + audience verification ─────────────

    use household_rs::claw_share::{GuestCredential, SlotId};
    use household_rs::claw_share_data_tunnel::{
        AuthEnvelope, ClawTargetRouter, DataTunnelError, DataTunnelSession, ReplayGuard,
        TargetSession, credential_hash, serve_connection_io,
        serve_connection_io_with_auth_deadline,
    };
    use household_rs::claw_share_relay_stream_contract::{
        RelayStreamAudience, RelayStreamClawStaticPublicKey, RelayStreamOfferMintInput,
        RelayStreamResource, mint_relay_stream_group_offer, mint_relay_stream_offer,
        mint_relay_stream_public_offer,
    };
    use household_rs::claw_share_rendezvous_token::RendezvousToken;
    use household_rs::ids::derive_household_id;
    use household_rs::keys::P256PublicKey;
    use household_rs::person_cert::derive_person_id;
    use tokio::io::{AsyncReadExt, duplex};

    const OFFER_NOW: u64 = 1_800_000_000;

    fn offer_kp(seed: u8) -> P256Keypair {
        P256Keypair::from_secret_scalar(&[seed; 32]).expect("p256 keypair")
    }

    fn offer_credential(owner: &P256Keypair, guest_pub: &P256PublicKey) -> GuestCredential {
        GuestCredential::sign(
            derive_household_id(&owner.public()),
            derive_person_id(&owner.public()),
            owner.public(),
            "claw_alpha".to_string(),
            guest_pub.clone(),
            SlotId([0x22; 16]),
            OFFER_NOW - 60,
            OFFER_NOW + 600,
            owner as &dyn IdentityKey,
        )
        .expect("sign guest credential")
    }

    fn mint_offer(
        owner: &P256Keypair,
        credential: &GuestCredential,
        expected_path: RelayStreamExpectedPath,
        not_after: u64,
    ) -> RelayStreamOfferContract {
        mint_relay_stream_offer(
            RelayStreamOfferMintInput {
                rendezvous_token: RendezvousToken::try_new(vec![0x42; 16]).unwrap(),
                credential,
                resource: RelayStreamResource::Pty,
                expected_path,
                relay_endpoint: "relay-stream://127.0.0.1:49152".to_string(),
                claw_static_pub: RelayStreamClawStaticPublicKey::try_new([0x33; 32]).unwrap(),
                not_after,
                now_unix: OFFER_NOW,
            },
            owner as &dyn IdentityKey,
        )
        .expect("mint relay stream offer")
    }

    fn ack_with_offer(
        credential: GuestCredential,
        offer: Option<&RelayStreamOfferContract>,
    ) -> ClawShareAck {
        ClawShareAck {
            v: 1,
            credential,
            tunnel: TunnelHandle::Loopback {
                channel: "test".to_string(),
            },
            relay_stream_offer: offer
                .map(|o| serde_bytes::ByteBuf::from(o.to_canonical_bytes().unwrap())),
        }
    }

    #[test]
    fn relay_stream_offer_absent_is_noop() {
        let owner = offer_kp(0x11);
        let guest = offer_kp(0x33);
        let ack = ack_with_offer(offer_credential(&owner, &guest.public()), None);

        assert!(verify_relay_stream_offer(&ack, &guest, OFFER_NOW).is_none());
    }

    #[test]
    fn relay_stream_offer_valid_parses_and_verifies() {
        let owner = offer_kp(0x11);
        let guest = offer_kp(0x33);
        let credential = offer_credential(&owner, &guest.public());
        let offer = mint_offer(
            &owner,
            &credential,
            RelayStreamExpectedPath::RelayStream,
            OFFER_NOW + 60,
        );
        let ack = ack_with_offer(credential, Some(&offer));

        let verified =
            verify_relay_stream_offer(&ack, &guest, OFFER_NOW).expect("valid offer accepted");
        assert_eq!(
            verified.payload.expected_path,
            RelayStreamExpectedPath::RelayStream
        );
        assert_eq!(verified.payload.guest_device_pub, guest.public());
    }

    #[test]
    fn relay_stream_offer_wrong_audience_is_rejected() {
        let owner = offer_kp(0x11);
        let guest = offer_kp(0x33);
        let other_guest = offer_kp(0x99);
        let credential = offer_credential(&owner, &guest.public());
        let offer = mint_offer(
            &owner,
            &credential,
            RelayStreamExpectedPath::RelayStream,
            OFFER_NOW + 60,
        );
        let ack = ack_with_offer(credential, Some(&offer));

        // Offer is addressed to `guest`; verifying as `other_guest` must drop it.
        assert!(verify_relay_stream_offer(&ack, &other_guest, OFFER_NOW).is_none());
    }

    #[test]
    fn relay_stream_offer_signer_mismatch_is_rejected() {
        let owner = offer_kp(0x11);
        let attacker = offer_kp(0x55);
        let guest = offer_kp(0x33);
        // Offer minted + signed under the attacker's own credential...
        let attacker_credential = offer_credential(&attacker, &guest.public());
        let attacker_offer = mint_offer(
            &attacker,
            &attacker_credential,
            RelayStreamExpectedPath::RelayStream,
            OFFER_NOW + 60,
        );
        // ...but delivered in an ack whose credential pins the real owner.
        let ack = ack_with_offer(
            offer_credential(&owner, &guest.public()),
            Some(&attacker_offer),
        );

        assert!(verify_relay_stream_offer(&ack, &guest, OFFER_NOW).is_none());
    }

    #[test]
    fn relay_stream_offer_wrong_expected_path_is_rejected() {
        let owner = offer_kp(0x11);
        let guest = offer_kp(0x33);
        let credential = offer_credential(&owner, &guest.public());
        let offer = mint_offer(
            &owner,
            &credential,
            RelayStreamExpectedPath::CommunityRelay,
            OFFER_NOW + 60,
        );
        let ack = ack_with_offer(credential, Some(&offer));

        assert!(verify_relay_stream_offer(&ack, &guest, OFFER_NOW).is_none());
    }

    #[test]
    fn relay_stream_offer_expired_is_rejected() {
        let owner = offer_kp(0x11);
        let guest = offer_kp(0x33);
        let credential = offer_credential(&owner, &guest.public());
        // not_after is in the future at mint time, but we verify well past it.
        let offer = mint_offer(
            &owner,
            &credential,
            RelayStreamExpectedPath::RelayStream,
            OFFER_NOW + 60,
        );
        let ack = ack_with_offer(credential, Some(&offer));

        assert!(verify_relay_stream_offer(&ack, &guest, OFFER_NOW + 120).is_none());
    }

    #[test]
    fn relay_stream_offer_malformed_bytes_is_rejected() {
        let owner = offer_kp(0x11);
        let guest = offer_kp(0x33);
        let mut ack = ack_with_offer(offer_credential(&owner, &guest.public()), None);
        ack.relay_stream_offer = Some(serde_bytes::ByteBuf::from(vec![0xff, 0x00, 0x13, 0x37]));

        assert!(verify_relay_stream_offer(&ack, &guest, OFFER_NOW).is_none());
    }

    #[test]
    fn relay_stream_dial_flag_parses_only_truthy_values() {
        assert!(parse_dial_flag(Some("1")));
        assert!(parse_dial_flag(Some("true")));
        assert!(parse_dial_flag(Some("TRUE")));
        assert!(parse_dial_flag(Some(" 1 ")));
        assert!(!parse_dial_flag(Some("0")));
        assert!(!parse_dial_flag(Some("false")));
        assert!(!parse_dial_flag(Some("")));
        assert!(!parse_dial_flag(None));
    }

    // Minimal data-tunnel target that just exists long enough for the client to
    // open then drop; the dropped duplex peer gives the target a clean EOF.
    struct NoopTargetRouter;

    impl ClawTargetRouter for NoopTargetRouter {
        async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
            let (target, _peer) = duplex(64);
            Ok(TargetSession::from_stream(target))
        }
    }

    // No-net composition test for the friend-cli guest dial: the generic
    // authenticate_open_relay_stream runs over a plain duplex straight into the
    // real household `serve_connection_io` (Noise/transport is covered by 2c-2b /
    // 2c-3a, so it is deliberately bypassed here). The light verify closure stands
    // in for the engine's authorize_session minus its slot-store / replay /
    // household checks, so a regression in what the guest mints — credential_cbor
    // (hash), token signature vs guest_device_pub, TTL, target_id == claw_id — or
    // in the auth → health → open order makes the server reject and the guest fail.
    #[tokio::test]
    async fn relay_stream_authenticate_open_round_trips_against_household_server() {
        let owner = offer_kp(0x11);
        let guest = offer_kp(0x33);
        let credential = offer_credential(&owner, &guest.public());
        let offer = mint_offer(
            &owner,
            &credential,
            RelayStreamExpectedPath::RelayStream,
            OFFER_NOW + 60,
        );

        let (guest_io, claw_io) = duplex(1 << 16);

        let verify = |envelope: &AuthEnvelope,
                      now: u64|
         -> Result<GuestCredential, DataTunnelError> {
            let cred: GuestCredential = cbor::from_canonical_slice(&envelope.credential_cbor)
                .map_err(|error| DataTunnelError::Cbor(error.to_string()))?;
            let expected = credential_hash(&envelope.credential_cbor);
            envelope
                .token
                .verify(&cred.guest_device_pub, &expected, now)?;
            if envelope.token.target_id != cred.claw_id {
                return Err(DataTunnelError::TokenRejected("target-mismatch".into()));
            }
            Ok(cred)
        };

        let claw = serve_connection_io(
            claw_io,
            OFFER_NOW,
            verify,
            &NoopTargetRouter,
            |_: &GuestCredential| false,
        );
        let guest_side =
            authenticate_open_relay_stream(guest_io, &offer, &guest, &credential, OFFER_NOW);

        let (claw_res, guest_res) =
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(claw, guest_side)
            })
            .await
            .expect("relay_stream auth round-trip should not hang");

        // The guest succeeding proves the server accepted the minted token and ran
        // auth → health → open. After open the guest drops the stream; the server
        // then ends on the client EOF.
        guest_res.expect("guest auth + health + open against household server");
        let _ = claw_res;
    }

    // Echo target: replies with whatever the guest sends (its "echo
    // relay-stream-ok" line), then closes so run_pty_command collects the marker
    // and stops promptly.
    struct PtyEchoTargetRouter;

    impl ClawTargetRouter for PtyEchoTargetRouter {
        async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
            let (server_side, mut target_side) = duplex(4096);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                if let Ok(n) = target_side.read(&mut buf).await {
                    if n > 0 {
                        let _ = target_side.write_all(&buf[..n]).await;
                        let _ = target_side.flush().await;
                    }
                }
                // Drop target_side -> EOF -> the server closes the client stream.
            });
            Ok(TargetSession::from_stream(server_side))
        }
    }

    // HTTP target: reads the guest's request, replies with a canned HTTP/1.1
    // response, then closes so run_http_request collects it and stops promptly.
    struct ClawSiteHttpTargetRouter;

    impl ClawTargetRouter for ClawSiteHttpTargetRouter {
        async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
            let (server_side, mut target_side) = duplex(4096);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                if let Ok(n) = target_side.read(&mut buf).await {
                    if n > 0 {
                        let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\
                                        Connection: close\r\n\r\nhello";
                        let _ = target_side.write_all(response.as_bytes()).await;
                        let _ = target_side.flush().await;
                    }
                }
                // Drop target_side -> EOF -> the server closes the client stream.
            });
            Ok(TargetSession::from_stream(server_side))
        }
    }

    // No-net composition test for the PTY payload over the relay_stream transport:
    // authenticate_open_relay_stream, then run_pty_command, over a plain duplex into
    // the real household serve_connection_io with an echo target. Locks the
    // friend-cli composition end to end (token mint + auth -> health -> open + the
    // PTY frame loop) and that the marker round-trips. Noise/transport is covered
    // by 2c-2b / 2c-3a, so it is bypassed here.
    #[tokio::test]
    async fn relay_stream_pty_payload_round_trips_against_household_server() {
        let owner = offer_kp(0x11);
        let guest = offer_kp(0x33);
        let credential = offer_credential(&owner, &guest.public());
        let offer = mint_offer(
            &owner,
            &credential,
            RelayStreamExpectedPath::RelayStream,
            OFFER_NOW + 60,
        );

        let (guest_io, claw_io) = duplex(1 << 16);

        let verify = |envelope: &AuthEnvelope,
                      now: u64|
         -> Result<GuestCredential, DataTunnelError> {
            let cred: GuestCredential = cbor::from_canonical_slice(&envelope.credential_cbor)
                .map_err(|error| DataTunnelError::Cbor(error.to_string()))?;
            let expected = credential_hash(&envelope.credential_cbor);
            envelope
                .token
                .verify(&cred.guest_device_pub, &expected, now)?;
            if envelope.token.target_id != cred.claw_id {
                return Err(DataTunnelError::TokenRejected("target-mismatch".into()));
            }
            Ok(cred)
        };

        let claw = serve_connection_io(
            claw_io,
            OFFER_NOW,
            verify,
            &PtyEchoTargetRouter,
            |_: &GuestCredential| false,
        );
        let guest_side = async {
            let mut tunnel =
                authenticate_open_relay_stream(guest_io, &offer, &guest, &credential, OFFER_NOW)
                    .await?;
            run_pty_command(&mut tunnel, "echo relay-stream-ok").await
        };

        let (claw_res, guest_res) =
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(claw, guest_side)
            })
            .await
            .expect("relay_stream PTY round-trip should not hang");

        let output = guest_res.expect("guest PTY payload over household server");
        assert!(
            output.contains("relay-stream-ok"),
            "expected marker in PTY output, got: {output:?}"
        );
        let _ = claw_res;
    }

    // No-net composition test for the ClawSite payload over the relay_stream
    // transport: authenticate_open_relay_stream, then run_http_request, over a
    // plain duplex into the real household serve_connection_io with an HTTP
    // target. Proves the guest's HTTP request and the backend's response splice
    // end to end over the open tunnel (the ClawSite analog of the PTY test).
    #[tokio::test]
    async fn relay_stream_clawsite_payload_round_trips_against_household_server() {
        let owner = offer_kp(0x11);
        let guest = offer_kp(0x33);
        let credential = offer_credential(&owner, &guest.public());
        let offer = mint_offer(
            &owner,
            &credential,
            RelayStreamExpectedPath::RelayStream,
            OFFER_NOW + 60,
        );

        let (guest_io, claw_io) = duplex(1 << 16);

        let verify = |envelope: &AuthEnvelope,
                      now: u64|
         -> Result<GuestCredential, DataTunnelError> {
            let cred: GuestCredential = cbor::from_canonical_slice(&envelope.credential_cbor)
                .map_err(|error| DataTunnelError::Cbor(error.to_string()))?;
            let expected = credential_hash(&envelope.credential_cbor);
            envelope
                .token
                .verify(&cred.guest_device_pub, &expected, now)?;
            if envelope.token.target_id != cred.claw_id {
                return Err(DataTunnelError::TokenRejected("target-mismatch".into()));
            }
            Ok(cred)
        };

        let claw = serve_connection_io(
            claw_io,
            OFFER_NOW,
            verify,
            &ClawSiteHttpTargetRouter,
            |_: &GuestCredential| false,
        );
        let guest_side = async {
            let mut tunnel =
                authenticate_open_relay_stream(guest_io, &offer, &guest, &credential, OFFER_NOW)
                    .await?;
            run_http_request(&mut tunnel).await
        };

        let (claw_res, guest_res) =
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(claw, guest_side)
            })
            .await
            .expect("relay_stream clawsite round-trip should not hang");

        let response = guest_res.expect("guest http request over household server");
        assert!(response.starts_with("HTTP/"), "got: {response:?}");
        assert!(response.contains("200 OK"), "got: {response:?}");
        assert!(response.contains("hello"), "got: {response:?}");
        let _ = claw_res;
    }

    // ── Fase E2.5/E3: relay-offer REQUEST client (no-net) ────────────────────

    #[test]
    fn relay_offer_group_request_is_accepted_by_server_checks() {
        // Build a Group request the way friend-cli does, then verify it the EXACT
        // way the engine's handle_relay_offer_group does: the member binding holds,
        // and the device PoP verifies under binding.device_pub over the canonical
        // RelayOfferGroupReqUnsigned view. Proves the client emits a request the
        // server accepts — without a live engine.
        let member = P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap();
        let device = P256Keypair::from_secret_scalar(&[0x22; 32]).unwrap();
        let challenge = vec![0x42u8; 32];
        let req = build_relay_offer_group_request(
            challenge,
            &member as &dyn IdentityKey,
            &device,
            "npub_member_device".to_string(),
            "g".to_string(),
            "claw_alpha".to_string(),
            Some(300),
            1_800_000_000,
        )
        .unwrap();

        // Server step 1: member binding self-signature + member_id derivation.
        req.binding.verify().expect("binding must verify");
        assert_eq!(req.binding.device_pub, device.public());

        // Server step 2: device PoP over the reconstructed unsigned view.
        let unsigned = RelayOfferGroupReqUnsigned {
            v: req.v,
            challenge: &req.challenge,
            group_id: &req.group_id,
            claw_id: &req.claw_id,
            ttl_secs: req.ttl_secs,
        };
        let pop_bytes = cbor::to_canonical_vec(&unsigned).unwrap();
        verify_signature(&req.binding.device_pub, &pop_bytes, &req.device_pop)
            .expect("device PoP must verify under the bound device key");

        // A PoP checked against any other key is rejected (wrong-device guard).
        let stranger = P256Keypair::from_secret_scalar(&[0x77; 32]).unwrap();
        assert!(verify_signature(&stranger.public(), &pop_bytes, &req.device_pop).is_err());

        // Changing the challenge-bound view breaks the PoP (anti-replay binding).
        let tampered = RelayOfferGroupReqUnsigned {
            v: req.v,
            challenge: &[0x00u8; 32],
            group_id: &req.group_id,
            claw_id: &req.claw_id,
            ttl_secs: req.ttl_secs,
        };
        let tampered_bytes = cbor::to_canonical_vec(&tampered).unwrap();
        assert!(
            verify_signature(&req.binding.device_pub, &tampered_bytes, &req.device_pop).is_err()
        );
    }

    #[test]
    fn relay_offer_group_request_none_ttl_pop_round_trips() {
        // ttl_secs = None must also produce a PoP the server verifies (it
        // reconstructs the unsigned view with req.ttl_secs = None).
        let member = P256Keypair::from_secret_scalar(&[0x33; 32]).unwrap();
        let device = P256Keypair::from_secret_scalar(&[0x44; 32]).unwrap();
        let req = build_relay_offer_group_request(
            vec![0x09u8; 32],
            &member as &dyn IdentityKey,
            &device,
            "npub".to_string(),
            "fam".to_string(),
            "claw_beta".to_string(),
            None,
            1_800_000_100,
        )
        .unwrap();
        let unsigned = RelayOfferGroupReqUnsigned {
            v: req.v,
            challenge: &req.challenge,
            group_id: &req.group_id,
            claw_id: &req.claw_id,
            ttl_secs: req.ttl_secs,
        };
        let pop_bytes = cbor::to_canonical_vec(&unsigned).unwrap();
        verify_signature(&req.binding.device_pub, &pop_bytes, &req.device_pop).unwrap();
    }

    #[test]
    fn relay_offer_public_request_carries_dialer_device_and_claw() {
        let device = P256Keypair::from_secret_scalar(&[0x55; 32]).unwrap();
        let req = build_relay_offer_public_request(
            vec![0x42u8; 32],
            device.public(),
            "claw_pub".to_string(),
            Some(120),
        );
        assert_eq!(req.v, RELAY_OFFER_REQ_VERSION);
        assert_eq!(req.dialer_device_pub, device.public());
        assert_eq!(req.claw_id, "claw_pub");
        assert_eq!(req.ttl_secs, Some(120));
        // Serializes to canonical CBOR (what the client POSTs).
        let bytes = cbor::to_canonical_vec(&req).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn member_key_from_hex_round_trips_and_rejects_bad_input() {
        let kp = P256Keypair::from_secret_scalar(&[0xAB; 32]).unwrap();
        let hex = "ab".repeat(32);
        let parsed = member_key_from_hex(&hex).unwrap();
        assert_eq!(parsed.public(), kp.public());
        assert!(member_key_from_hex("deadbeef").is_err()); // too short
        assert!(member_key_from_hex(&"zz".repeat(32)).is_err()); // not hex
    }

    // Group dial e2e (no-net): drive the credential-less auth + PTY payload over a
    // duplex into the household data-tunnel serve loop, with a server verifier that
    // faithfully mirrors the engine's verify_relay_stream_offer_session (PoP under
    // offer.guest_device_pub, hash = blake3(THIS offer), target == claw, replay).
    // Proves the friend-cli Group/Public dial produces a frame the claw accepts and
    // completes the PTY marker. (The REAL verifier is tested in server-rs half B;
    // the real responder over Noise is the gated hardware smoke.)
    #[tokio::test]
    async fn group_dial_authenticates_and_runs_pty_against_household_server() {
        // Server-side authorized session (credential-less; correlation only).
        struct TestSession;
        impl DataTunnelSession for TestSession {
            fn session_id(&self) -> String {
                "test-session".to_string()
            }
            fn mesh_ipv6(&self) -> String {
                "fd00:c1aw::1".to_string()
            }
        }

        let owner = offer_kp(0x11);
        let device = offer_kp(0x33);
        let offer = mint_relay_stream_group_offer(
            RendezvousToken::try_new(vec![0x42; 16]).unwrap(),
            SlotId([0x99; 16]),
            "g".to_string(),
            "g_a".to_string(),
            device.public(),
            "claw_alpha".to_string(),
            RelayStreamResource::Pty,
            "relay-stream://127.0.0.1:49152".to_string(),
            RelayStreamClawStaticPublicKey::try_new([0x33; 32]).unwrap(),
            OFFER_NOW + 60,
            OFFER_NOW,
            &owner as &dyn IdentityKey,
        )
        .expect("mint group offer");

        let (guest_io, claw_io) = duplex(1 << 16);
        let replay = ReplayGuard::new();
        let offer_bytes = offer.payload.to_canonical_bytes().unwrap();
        let server_guest_pub = offer.payload.guest_device_pub.clone();
        let server_claw_id = offer.payload.claw_id.clone();
        // Faithful mirror of verify_relay_stream_offer_session (server-rs).
        let verify =
            move |envelope: &AuthEnvelope, now: u64| -> Result<TestSession, DataTunnelError> {
                let expected = credential_hash(&offer_bytes);
                envelope.token.verify(&server_guest_pub, &expected, now)?;
                if envelope.token.target_id != server_claw_id {
                    return Err(DataTunnelError::TokenRejected("target-mismatch".into()));
                }
                replay.check_and_record(&envelope.token.nonce, envelope.token.expires_at, now)?;
                Ok(TestSession)
            };

        let claw = serve_connection_io_with_auth_deadline(
            claw_io,
            OFFER_NOW,
            verify,
            &PtyEchoTargetRouter,
            |_: &TestSession| false,
            std::time::Duration::from_secs(5),
        );
        let guest_side = async {
            let mut tunnel =
                authenticate_open_relay_stream_session(guest_io, &offer, &device, OFFER_NOW)
                    .await?;
            run_pty_command(&mut tunnel, "echo relay-stream-ok").await
        };

        let (claw_res, guest_res) =
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(claw, guest_side)
            })
            .await
            .expect("group dial round-trip should not hang");

        let output = guest_res.expect("guest PTY payload over household server");
        assert!(
            output.contains("relay-stream-ok"),
            "expected marker in PTY output, got: {output:?}"
        );
        let _ = claw_res;
    }

    #[test]
    fn relay_offer_dial_offer_file_validates_device_matches() {
        // run_relay_offer_dial decodes the offer from CBOR bytes (the --offer-file
        // contents) and requires the dialing device key to equal the offer's
        // guest_device_pub. A public offer minted for device A round-trips and matches
        // A, and is detectably wrong for B (the fail-fast guard before dialing).
        let owner = offer_kp(0x11);
        let device_a = offer_kp(0x33);
        let device_b = offer_kp(0x44);
        let offer = mint_relay_stream_public_offer(
            RendezvousToken::try_new(vec![0x42; 16]).unwrap(),
            SlotId([0x98; 16]),
            device_a.public(),
            "claw_alpha".to_string(),
            RelayStreamResource::Pty,
            "relay-stream://127.0.0.1:49152".to_string(),
            RelayStreamClawStaticPublicKey::try_new([0x33; 32]).unwrap(),
            OFFER_NOW + 60,
            OFFER_NOW,
            &owner as &dyn IdentityKey,
        )
        .expect("mint public offer");

        let bytes = offer.to_canonical_bytes().unwrap();
        let decoded = RelayStreamOfferContract::from_canonical_bytes(&bytes).expect("decode offer");
        assert_eq!(decoded.payload.audience(), RelayStreamAudience::Public);
        assert_eq!(decoded.payload.guest_device_pub, device_a.public()); // matches → dial
        assert_ne!(decoded.payload.guest_device_pub, device_b.public()); // mismatch → bail
    }
}
