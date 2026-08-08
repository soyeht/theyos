//! M0a NAT probe CLI.
//!
//! Prints one JSON object per run on stdout, and a human summary on stderr, so
//! `nat-probe >> samples.jsonl` accumulates a clean sample set while the
//! operator still sees what happened.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use nat_probe_rs::{DEFAULT_STUN_SERVERS, ProbeLabels, ProbeSettings, ServerOutcome, observe};

#[derive(Parser, Debug)]
#[command(
    name = "nat-probe",
    about = "M0a — record how two STUN servers see one UDP socket",
    long_about = "Records NAT mapping observations for relay planning.\n\n\
                  This reports what was observed, never whether a direct path \
                  is possible: mapping and filtering are different behaviours \
                  and both vary with load and destination (RFC 5780)."
)]
struct Cli {
    /// STUN server as `host:port`. Pass twice to override both defaults.
    #[arg(long = "server", value_name = "HOST:PORT")]
    servers: Vec<String>,

    /// ISO country code of this vantage point, e.g. `BR`.
    #[arg(long)]
    country: Option<String>,

    /// Autonomous system of the uplink, e.g. `AS28573`.
    #[arg(long)]
    asn: Option<String>,

    /// How this host is attached: `ethernet`, `wifi`, `wifi-cafe`, `5g`.
    #[arg(long = "network-type")]
    network_type: Option<String>,

    /// Per-server budget in milliseconds.
    #[arg(long, default_value_t = 3_000)]
    timeout_ms: u64,

    /// Binding requests per server before giving up.
    #[arg(long, default_value_t = 3)]
    attempts: u32,

    /// Also append the JSON line to this file.
    #[arg(long, value_name = "PATH")]
    append: Option<PathBuf>,
}

fn describe_port(port: Option<u16>) -> String {
    port.map_or_else(|| "none (no socket)".to_owned(), |port| port.to_string())
}

fn describe_consistency(consistent: Option<bool>) -> &'static str {
    match consistent {
        Some(true) => "true (good sign for hole punching, not a guarantee)",
        Some(false) => "false (direct is harder, not impossible)",
        None => "unknown (a server did not answer)",
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let servers = match cli.servers.len() {
        0 => [
            DEFAULT_STUN_SERVERS[0].to_owned(),
            DEFAULT_STUN_SERVERS[1].to_owned(),
        ],
        2 => [cli.servers[0].clone(), cli.servers[1].clone()],
        other => anyhow::bail!(
            "expected exactly two --server values (or none, for the defaults), got {other}"
        ),
    };

    let settings = ProbeSettings {
        servers,
        timeout: Duration::from_millis(cli.timeout_ms),
        attempts: cli.attempts,
    };
    let labels = ProbeLabels {
        country: cli.country,
        asn: cli.asn,
        network_type: cli.network_type,
    };

    let observation = observe(&settings, &labels).context("probe failed to run")?;
    let line = serde_json::to_string(&observation).context("failed to encode observation")?;

    println!("{line}");

    if let Some(path) = cli.append.as_ref() {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("failed to open {} for append", path.display()))?;
        writeln!(file, "{line}")
            .with_context(|| format!("failed to append to {}", path.display()))?;
    }

    for outcome in &observation.servers {
        match outcome {
            ServerOutcome::Observed {
                server,
                family,
                mapped,
                rtt_ms,
            } => eprintln!("  [{family:?}] {server}: mapped {mapped} in {rtt_ms:.1} ms"),
            ServerOutcome::Failed {
                server,
                family,
                reason,
            } => eprintln!("  [{family:?}] {server}: {reason}"),
        }
    }
    eprintln!(
        "  ipv6 address {}",
        if observation.ipv6_available {
            "present"
        } else {
            "absent"
        }
    );
    eprintln!(
        "  IPv4 port {} · mapping_consistent {}",
        describe_port(observation.local_port),
        describe_consistency(observation.mapping_consistent)
    );
    eprintln!(
        "  IPv6 port {} · mapping_consistent {}",
        describe_port(observation.local_port_v6),
        describe_consistency(observation.mapping_consistent_v6)
    );

    Ok(())
}
