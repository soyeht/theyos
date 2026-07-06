//! Dev-only Product A T1 `IpTunnel` runner boundary.
//!
//! This binary intentionally implements only offline offer validation for now.
//! It does not connect to a relay, open a tunnel interface, install routes,
//! spawn a packet pump, or touch production apps.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use household_rs::claw_share_relay_stream_contract::{
    RelayStreamAudience, RelayStreamExpectedPath, RelayStreamOfferContract, RelayStreamResource,
};
use household_rs::claw_share_relay_stream_endpoint::parse_relay_endpoint;

#[derive(Parser, Debug)]
#[command(
    name = "t1-iptunnel-dev-runner",
    version,
    about = "Dev-only T1 IpTunnel runner preparation tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Validate a pre-minted `IpTunnel` offer without connecting or opening a device.
    ValidateOffer {
        /// Canonical CBOR `RelayStreamOfferContract` file.
        #[arg(long)]
        offer_file: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedIpTunnelOffer;

fn validate_iptunnel_offer_file(path: &PathBuf) -> Result<ValidatedIpTunnelOffer> {
    let bytes = std::fs::read(path).context("read IpTunnel offer file")?;
    validate_iptunnel_offer_bytes(&bytes)
}

fn validate_iptunnel_offer_bytes(bytes: &[u8]) -> Result<ValidatedIpTunnelOffer> {
    let offer = RelayStreamOfferContract::from_canonical_bytes(bytes)
        .context("decode relay_stream offer")?;
    validate_iptunnel_offer(&offer)
}

fn validate_iptunnel_offer(offer: &RelayStreamOfferContract) -> Result<ValidatedIpTunnelOffer> {
    if offer.payload.resource != RelayStreamResource::IpTunnel {
        bail!("relay_stream offer resource is not IpTunnel");
    }
    if offer.payload.expected_path != RelayStreamExpectedPath::RelayStream {
        bail!("IpTunnel offer expected_path is not RelayStream");
    }

    let RelayStreamAudience::Group {
        group_id,
        member_id,
    } = offer.payload.audience()
    else {
        bail!("IpTunnel offer must be member-scoped group audience");
    };
    if group_id.trim().is_empty() {
        bail!("IpTunnel offer group id is empty");
    }
    if member_id.trim().is_empty() {
        bail!("IpTunnel offer member id is empty");
    }
    if offer.payload.claw_id.trim().is_empty() {
        bail!("IpTunnel offer claw id is empty");
    }

    parse_relay_endpoint(&offer.payload.relay_endpoint).context("validate relay endpoint shape")?;

    Ok(ValidatedIpTunnelOffer)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ValidateOffer { offer_file } => {
            validate_iptunnel_offer_file(&offer_file)?;
            println!(
                "OK: dev IpTunnel offer shape validated \
                 (group_present=true, member_present=true, claw_present=true, \
                 endpoint_shape_valid=true)"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use household_rs::claw_share::{GuestCredential, SlotId};
    use household_rs::claw_share_relay_stream_contract::{
        RelayStreamClawStaticPublicKey, RelayStreamOfferMintInput, mint_relay_stream_group_offer,
        mint_relay_stream_offer, mint_relay_stream_public_offer,
    };
    use household_rs::claw_share_rendezvous_token::RendezvousToken;
    use household_rs::ids::derive_household_id;
    use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
    use household_rs::person_cert::derive_person_id;

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn key(seed: u8) -> P256Keypair {
        P256Keypair::from_secret_scalar(&[seed; 32]).expect("p256 keypair")
    }

    fn claw_static_pub() -> RelayStreamClawStaticPublicKey {
        RelayStreamClawStaticPublicKey::try_new([0x33; 32]).expect("claw static key")
    }

    fn rendezvous_token() -> RendezvousToken {
        RendezvousToken::try_new(vec![0x42; 16]).expect("rendezvous token")
    }

    fn credential(owner: &P256Keypair, guest_pub: &P256PublicKey) -> GuestCredential {
        GuestCredential::sign(
            derive_household_id(&owner.public()),
            derive_person_id(&owner.public()),
            owner.public(),
            "claw-alpha".to_string(),
            guest_pub.clone(),
            SlotId([0x22; 16]),
            NOW - 60,
            NOW + 600,
            owner as &dyn IdentityKey,
        )
        .expect("guest credential")
    }

    fn member_iptunnel_offer() -> RelayStreamOfferContract {
        let owner = key(0x11);
        let device = key(0x33);
        mint_relay_stream_group_offer(
            rendezvous_token(),
            SlotId([0x99; 16]),
            "group-alpha".to_string(),
            "member-alpha".to_string(),
            device.public(),
            "claw-alpha".to_string(),
            RelayStreamResource::IpTunnel,
            "relay-stream://127.0.0.1:49152".to_string(),
            claw_static_pub(),
            NOW + 60,
            NOW,
            &owner as &dyn IdentityKey,
        )
        .expect("member IpTunnel offer")
    }

    #[test]
    fn accepts_member_scoped_iptunnel_offer_shape() {
        let offer = member_iptunnel_offer();
        let validated = validate_iptunnel_offer_bytes(&offer.to_canonical_bytes().unwrap())
            .expect("member-scoped IpTunnel offer accepted");

        assert_eq!(validated, ValidatedIpTunnelOffer);
    }

    #[test]
    fn rejects_non_iptunnel_offer() {
        let owner = key(0x11);
        let guest = key(0x33);
        let credential = credential(&owner, &guest.public());
        let offer = mint_relay_stream_offer(
            RelayStreamOfferMintInput {
                rendezvous_token: rendezvous_token(),
                credential: &credential,
                resource: RelayStreamResource::Pty,
                expected_path: RelayStreamExpectedPath::RelayStream,
                relay_endpoint: "relay-stream://127.0.0.1:49152".to_string(),
                claw_static_pub: claw_static_pub(),
                not_after: NOW + 60,
                now_unix: NOW,
            },
            &owner as &dyn IdentityKey,
        )
        .expect("PTY offer");

        let error = validate_iptunnel_offer(&offer).expect_err("PTY is not IpTunnel");
        assert!(error.to_string().contains("resource is not IpTunnel"));
    }

    #[test]
    fn rejects_device_scoped_iptunnel_offer() {
        let owner = key(0x11);
        let guest = key(0x33);
        let credential = credential(&owner, &guest.public());
        let offer = mint_relay_stream_offer(
            RelayStreamOfferMintInput {
                rendezvous_token: rendezvous_token(),
                credential: &credential,
                resource: RelayStreamResource::IpTunnel,
                expected_path: RelayStreamExpectedPath::RelayStream,
                relay_endpoint: "relay-stream://127.0.0.1:49152".to_string(),
                claw_static_pub: claw_static_pub(),
                not_after: NOW + 60,
                now_unix: NOW,
            },
            &owner as &dyn IdentityKey,
        )
        .expect("Device IpTunnel offer");

        let error = validate_iptunnel_offer(&offer).expect_err("Device offer must not validate");
        assert!(error.to_string().contains("member-scoped group audience"));
    }

    #[test]
    fn rejects_public_iptunnel_offer() {
        let owner = key(0x11);
        let device = key(0x33);
        let offer = mint_relay_stream_public_offer(
            rendezvous_token(),
            SlotId([0x98; 16]),
            device.public(),
            "claw-alpha".to_string(),
            RelayStreamResource::IpTunnel,
            "relay-stream://127.0.0.1:49152".to_string(),
            claw_static_pub(),
            NOW + 60,
            NOW,
            &owner as &dyn IdentityKey,
        )
        .expect("Public IpTunnel offer");

        let error = validate_iptunnel_offer(&offer).expect_err("Public offer must not validate");
        assert!(error.to_string().contains("member-scoped group audience"));
    }

    #[test]
    fn rejects_invalid_relay_endpoint_shape() {
        let mut offer = member_iptunnel_offer();
        offer.payload.relay_endpoint = "https://127.0.0.1:49152".to_string();

        let error = validate_iptunnel_offer(&offer).expect_err("endpoint scheme rejected");
        assert!(error.to_string().contains("validate relay endpoint shape"));
    }

    #[test]
    fn source_stays_offline_and_non_live() {
        let source = include_str!("main.rs");
        for forbidden in [
            concat!("Tcp", "Stream"),
            concat!("std::process::", "Command"),
            concat!("/dev/", "tun"),
            concat!("u", "tun"),
            concat!("route", " add"),
            concat!("ip ", "route"),
            concat!("if", "config"),
            concat!("Soyeht", ".app"),
            concat!("Soyeht", " Dev.app"),
        ] {
            assert!(
                !source.contains(forbidden),
                "dev offer validator must stay offline and non-live: {forbidden}"
            );
        }
    }
}
