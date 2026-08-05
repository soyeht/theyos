//! Network channel detection — probes the host environment for available access methods.
//!
//! Each channel detector has a short timeout (2s) and returns a structured status.
//! This module is read-only: it only detects what's available, never modifies state.

use crate::constants::DEFAULT_ADMIN_PORT;
use serde::Serialize;
use std::{
    net::{IpAddr, SocketAddr},
    process::{Command, Output, Stdio},
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

/// Status of a single network access channel.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelStatus {
    #[serde(rename = "type")]
    pub channel_type: String,
    pub configured: bool,
    pub detected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_dns: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_https: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_cert: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_serve: Option<bool>,
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_detail: Option<String>,
}

/// Status of the local Caddy reverse proxy.
#[derive(Debug, Clone, Serialize)]
pub struct CaddyStatus {
    pub installed: bool,
    pub running: bool,
    pub admin_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_detail: Option<String>,
}

/// Full network status with all detected channels.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkStatus {
    pub channels: Vec<ChannelStatus>,
    pub caddy: CaddyStatus,
}

/// Detect all available network channels.
///
/// Each detection uses short timeouts (1-2s) so this function completes quickly
/// even when services are unavailable.
#[must_use]
pub fn detect_network_status() -> NetworkStatus {
    let admin_port = admin_port_from_env();

    let mut channels = vec![detect_local(admin_port)];

    if let Some(lan) = detect_lan(admin_port) {
        channels.push(lan);
    }

    channels.push(detect_tailscale(admin_port));
    channels.push(detect_cloudflare());

    let caddy = detect_caddy();
    apply_effective_tailscale_https(&mut channels, caddy.running);

    NetworkStatus { channels, caddy }
}

fn apply_effective_tailscale_https(channels: &mut [ChannelStatus], caddy_running: bool) {
    if !caddy_running {
        return;
    }

    for ch in channels {
        if ch.channel_type != "tailscale" || !ch.detected || ch.has_https == Some(true) {
            continue;
        }
        ch.has_https = Some(true);
        if let Some(ref hostname) = ch.hostname {
            ch.urls.retain(|u| !u.contains(hostname));
            ch.urls.insert(0, format!("https://{hostname}"));
        }
    }
}

/// Find the Tailscale CLI binary.
///
/// Uses [`crate::os::resolve_binary`] to check `PATH` and platform fallback
/// locations (NixOS `/run/current-system/sw/bin/`, macOS `Tailscale.app`).
/// Returns the path only if the binary actually responds to `tailscale version`.
#[must_use]
pub fn find_tailscale_cli() -> Option<String> {
    crate::os::resolve_binary(
        "tailscale",
        &["/Applications/Tailscale.app/Contents/MacOS/Tailscale"],
    )
    .filter(|bin| command_succeeds(&bin.to_string_lossy(), &["version"], Duration::from_secs(1)))
    .map(|p| p.to_string_lossy().into_owned())
}

fn admin_port_from_env() -> u16 {
    admin_port_from_values(
        std::env::var("ADDR").ok().as_deref(),
        std::env::var("ADMIN_PORT").ok().as_deref(),
        std::env::var("PORT").ok().as_deref(),
    )
}

fn admin_port_from_values(addr: Option<&str>, admin_port: Option<&str>, port: Option<&str>) -> u16 {
    addr.and_then(|value| SocketAddr::from_str(value).ok().map(|socket| socket.port()))
        .or_else(|| admin_port.and_then(|value| value.parse::<u16>().ok()))
        .or_else(|| port.and_then(|value| value.parse::<u16>().ok()))
        .unwrap_or(DEFAULT_ADMIN_PORT)
}

fn run_command_capture(program: &str, args: &[&str], timeout: Duration) -> Option<Output> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let deadline = Instant::now() + timeout;

    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }

        thread::sleep(Duration::from_millis(25));
    }
}

fn command_succeeds(program: &str, args: &[&str], timeout: Duration) -> bool {
    run_command_capture(program, args, timeout).is_some_and(|output| output.status.success())
}

fn http_ok(url: &str, timeout: Duration) -> bool {
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    agent
        .get(url)
        .call()
        .is_ok_and(|response| response.status() == 200)
}

// ── Local ────────────────────────────────────────────────────────────────────

fn detect_local(port: u16) -> ChannelStatus {
    ChannelStatus {
        channel_type: "local".into(),
        configured: true,
        detected: true,
        ip: Some("127.0.0.1".into()),
        hostname: None,
        has_dns: None,
        has_https: None,
        has_cert: None,
        has_serve: None,
        urls: vec![format!("http://localhost:{port}")],
        status_detail: None,
    }
}

// ── LAN ──────────────────────────────────────────────────────────────────────

fn detect_lan(port: u16) -> Option<ChannelStatus> {
    let ips = get_lan_ips();
    if ips.is_empty() {
        return None;
    }
    let primary = ips[0].clone();
    let urls: Vec<String> = ips.iter().map(|ip| format!("http://{ip}:{port}")).collect();

    Some(ChannelStatus {
        channel_type: "lan".into(),
        configured: true,
        detected: true,
        ip: Some(primary),
        hostname: None,
        has_dns: None,
        has_https: None,
        has_cert: None,
        has_serve: None,
        urls,
        status_detail: None,
    })
}

/// Get non-loopback, non-link-local IPv4 addresses.
///
/// Tries `ip -4 addr show` first (available in systemd PATH via `iproute2`),
/// then falls back to `ifconfig` via [`crate::os::resolve_binary`] (for macOS).
fn get_lan_ips() -> Vec<String> {
    // Try `ip` first — always in the NixOS systemd PATH (iproute2 package)
    if let Some(output) = run_command_capture("ip", &["-4", "addr", "show"], Duration::from_secs(1))
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            let ips = parse_ip_addr_output(&text);
            if !ips.is_empty() {
                return ips;
            }
        }
    }

    // Fallback: ifconfig (for macOS or systems without iproute2)
    let ifconfig_bin = crate::os::resolve_binary("ifconfig", &[]);
    let output = ifconfig_bin
        .and_then(|bin| run_command_capture(&bin.to_string_lossy(), &[], Duration::from_secs(1)));

    let Some(output) = output else { return vec![] };
    if !output.status.success() {
        return vec![];
    }

    let text = String::from_utf8_lossy(&output.stdout);
    parse_ifconfig_output(&text)
}

/// Parse `ip -4 addr show` output, extracting non-loopback, non-Tailscale IPv4 addresses.
///
/// Expected format:
/// ```text
///     inet 192.0.2.8/24 brd 192.0.2.255 scope global ...
///     inet 100.103.223.26/32 scope global tailscale0
/// ```
fn parse_ip_addr_output(text: &str) -> Vec<String> {
    let mut ips = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            // Format: "inet 192.0.2.8/24 ..."
            let ip_str = rest.split('/').next().unwrap_or("");
            let ip_str = ip_str.split_whitespace().next().unwrap_or(ip_str);
            if let Ok(IpAddr::V4(v4)) = ip_str.parse::<IpAddr>() {
                if !v4.is_loopback() && !v4.is_link_local() {
                    let octets = v4.octets();
                    // Skip Tailscale CGNAT range (100.64.0.0/10)
                    if !(octets[0] == 100 && (64..128).contains(&octets[1])) {
                        ips.push(v4.to_string());
                    }
                }
            }
        }
    }
    ips
}

/// Parse `ifconfig` output, extracting non-loopback, non-Tailscale IPv4 addresses.
///
/// Expected format:
/// ```text
///     inet 192.0.2.8  netmask 255.255.255.0  broadcast 192.0.2.255
/// ```
fn parse_ifconfig_output(text: &str) -> Vec<String> {
    let mut ips = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            let ip_str = rest.split_whitespace().next().unwrap_or("");
            let ip_str = ip_str.split('/').next().unwrap_or(ip_str);
            if let Ok(IpAddr::V4(v4)) = ip_str.parse::<IpAddr>() {
                if !v4.is_loopback() && !v4.is_link_local() {
                    let octets = v4.octets();
                    if !(octets[0] == 100 && (64..128).contains(&octets[1])) {
                        ips.push(v4.to_string());
                    }
                }
            }
        }
    }
    ips
}

// ── Tailscale ────────────────────────────────────────────────────────────────

fn detect_tailscale(port: u16) -> ChannelStatus {
    let mut status = ChannelStatus {
        channel_type: "tailscale".into(),
        configured: false,
        detected: false,
        ip: None,
        hostname: None,
        has_dns: None,
        has_https: None,
        has_cert: None,
        has_serve: None,
        urls: vec![],
        status_detail: Some("Tailscale CLI not found".into()),
    };

    let Some(tailscale_bin) = find_tailscale_cli() else {
        return status;
    };

    status.configured = true;
    status.has_dns = Some(false);
    status.has_https = Some(false);
    status.status_detail = Some("Tailscale installed but not connected".into());

    let output = run_command_capture(
        &tailscale_bin,
        &["status", "--json"],
        Duration::from_secs(2),
    );

    let Some(output) = output else { return status };
    if !output.status.success() {
        return status;
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) else {
        return status;
    };

    // Extract Self node info
    let Some(self_node) = json.get("Self") else {
        return status;
    };
    status.detected = true;
    status.status_detail = None; // clear — connected and working

    // TailscaleIPs: array of IPs
    if let Some(ips) = self_node
        .get("TailscaleIPs")
        .and_then(|value| value.as_array())
    {
        // First IPv4 address
        for ip_val in ips {
            if let Some(ip_str) = ip_val.as_str() {
                if !ip_str.contains(':') {
                    status.ip = Some(ip_str.to_string());
                    break;
                }
            }
        }
    }

    // DNSName: "hostname.tailnet.ts.net."
    if let Some(dns) = self_node.get("DNSName").and_then(|value| value.as_str()) {
        let hostname = dns.trim_end_matches('.');
        if !hostname.is_empty() {
            status.hostname = Some(hostname.to_string());
            status.has_dns = Some(true);
        }
    }

    // CertDomains: available cert domains (tailnet-wide, NOT per-node HTTPS)
    if let Some(cert_domains) = json.get("CertDomains").and_then(|value| value.as_array()) {
        status.has_cert = Some(!cert_domains.is_empty());
    }

    // Check if tailscale serve is actively serving HTTPS on this node.
    // CertDomains alone is unreliable — it's a tailnet-wide setting.
    let serve_output =
        run_command_capture(&tailscale_bin, &["serve", "status"], Duration::from_secs(2));
    let has_serve = serve_output.as_ref().is_some_and(|o| {
        o.status.success() && !String::from_utf8_lossy(&o.stdout).contains("No serve config")
    });
    status.has_serve = Some(has_serve);

    // Provisional: has_https = has_serve (upgraded by Caddy post-processing in
    // detect_network_status if Caddy is running)
    status.has_https = Some(has_serve);

    // Build URLs
    if let Some(ref hostname) = status.hostname {
        if status.has_https == Some(true) {
            status.urls.push(format!("https://{hostname}"));
        } else {
            status.urls.push(format!("http://{hostname}:{port}"));
        }
    }
    if let Some(ref ip) = status.ip {
        status.urls.push(format!("http://{ip}:{port}"));
    }

    status
}

// ── Cloudflare ───────────────────────────────────────────────────────────────

fn detect_cloudflare() -> ChannelStatus {
    let cf_bin = std::env::var("THEYOS_CLOUDFLARE_RS_BIN").unwrap_or_default();
    let cf_zone = std::env::var("CF_ZONE_ID")
        .or_else(|_| std::env::var("CLOUDFLARE_ZONE_ID"))
        .unwrap_or_default();
    let cf_token = std::env::var("CF_API_TOKEN")
        .or_else(|_| std::env::var("CLOUDFLARE_API_TOKEN"))
        .unwrap_or_default();
    let base_domain = std::env::var("CF_DOMAIN")
        .or_else(|_| std::env::var("THEYOS_BASE_DOMAIN"))
        .unwrap_or_default();

    let configured = !cf_bin.is_empty() && !cf_zone.is_empty() && !cf_token.is_empty();

    // Use /proc scan instead of pgrep (no external binary needed)
    let process_running = !crate::os::find_pids_referencing_path("cloudflared").is_empty();
    let metrics_ready = http_ok("http://127.0.0.1:2000/ready", Duration::from_secs(1));

    let detected = process_running || metrics_ready;

    // Build status_detail explaining what's missing
    let status_detail = if detected {
        None
    } else if !configured {
        let mut missing = Vec::new();
        if cf_bin.is_empty() {
            missing.push("THEYOS_CLOUDFLARE_RS_BIN");
        }
        if cf_zone.is_empty() {
            missing.push("CF_ZONE_ID");
        }
        if cf_token.is_empty() {
            missing.push("CF_API_TOKEN");
        }
        Some(format!("Missing env: {}", missing.join(", ")))
    } else {
        Some("cloudflared process not running".into())
    };

    let hostname = if base_domain.is_empty() || (!configured && !detected) {
        None
    } else {
        Some(format!("admin.{base_domain}"))
    };
    let urls = if let Some(ref value) = hostname {
        vec![format!("https://{value}")]
    } else {
        vec![]
    };

    ChannelStatus {
        channel_type: "cloudflare".into(),
        configured,
        detected,
        ip: None,
        hostname,
        has_dns: None,
        has_https: if configured || detected {
            Some(true)
        } else {
            None
        },
        has_cert: None,
        has_serve: None,
        urls,
        status_detail,
    }
}

// ── Caddy ────────────────────────────────────────────────────────────────────

fn caddy_admin_healthy(admin_url: &str) -> bool {
    let config_url = format!("{}/config/", admin_url.trim_end_matches('/'));
    http_ok(&config_url, Duration::from_secs(1))
}

fn detect_caddy() -> CaddyStatus {
    let admin_url =
        std::env::var("CADDY_ADMIN_URL").unwrap_or_else(|_| "http://localhost:2019".into());

    let caddy_bin = crate::os::resolve_binary("caddy", &["/opt/homebrew/bin/caddy"]);
    let installed = caddy_bin.is_some_and(|ref bin| {
        command_succeeds(&bin.to_string_lossy(), &["version"], Duration::from_secs(1))
    });
    let running = caddy_admin_healthy(&admin_url);

    let status_detail = if running {
        None
    } else if !installed {
        Some("Caddy binary not found".into())
    } else {
        Some(format!("Caddy admin API not responding at {admin_url}"))
    };

    CaddyStatus {
        installed,
        running,
        admin_url,
        status_detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_port_prefers_addr_over_other_envs() {
        let port = admin_port_from_values(Some("0.0.0.0:9900"), Some("8892"), Some("7777"));
        assert_eq!(port, 9900);
    }

    #[test]
    fn admin_port_falls_back_through_known_envs() {
        assert_eq!(admin_port_from_values(None, Some("9901"), None), 9901);
        assert_eq!(admin_port_from_values(None, None, Some("9902")), 9902);
        assert_eq!(admin_port_from_values(None, None, None), DEFAULT_ADMIN_PORT);
    }

    #[test]
    fn admin_port_ignores_invalid_values() {
        let port = admin_port_from_values(Some("not-a-socket"), Some("bad"), Some("9903"));
        assert_eq!(port, 9903);
    }

    #[test]
    fn local_channel_always_detected() {
        let ch = detect_local(8892);
        assert_eq!(ch.channel_type, "local");
        assert!(ch.detected);
        assert_eq!(ch.urls, vec!["http://localhost:8892"]);
        assert!(ch.status_detail.is_none());
    }

    #[test]
    fn lan_ips_exclude_loopback_and_tailscale() {
        let ips = get_lan_ips();
        for ip in &ips {
            assert!(!ip.starts_with("127."));
            assert!(!ip.starts_with("169.254."));
            if ip.starts_with("100.") {
                let second: u8 = ip.split('.').nth(1).unwrap().parse().unwrap();
                assert!(!(64..128).contains(&second));
            }
        }
    }

    #[test]
    fn detect_status_returns_all_channels() {
        let status = detect_network_status();
        assert!(status.channels.len() >= 2);
        assert_eq!(status.channels[0].channel_type, "local");
    }

    #[test]
    fn caddy_upgrades_tailscale_https_and_urls() {
        let mut channels = vec![
            ChannelStatus {
                channel_type: "local".into(),
                configured: true,
                detected: true,
                ip: Some("127.0.0.1".into()),
                hostname: None,
                has_dns: None,
                has_https: None,
                has_cert: None,
                has_serve: None,
                urls: vec!["http://localhost:8892".into()],
                status_detail: None,
            },
            ChannelStatus {
                channel_type: "tailscale".into(),
                configured: true,
                detected: true,
                ip: Some("100.64.0.5".into()),
                hostname: Some("myhost.tail1234.ts.net".into()),
                has_dns: Some(true),
                has_https: Some(false),
                has_cert: Some(true),
                has_serve: Some(false),
                urls: vec![
                    "http://myhost.tail1234.ts.net:8892".into(),
                    "http://100.64.0.5:8892".into(),
                ],
                status_detail: None,
            },
        ];

        apply_effective_tailscale_https(&mut channels, true);

        let tailscale = channels
            .iter()
            .find(|ch| ch.channel_type == "tailscale")
            .unwrap();
        assert_eq!(tailscale.has_https, Some(true));
        assert_eq!(
            tailscale.urls.first().map(String::as_str),
            Some("https://myhost.tail1234.ts.net")
        );
        assert!(
            !tailscale
                .urls
                .contains(&"http://myhost.tail1234.ts.net:8892".to_string())
        );
        assert!(
            tailscale
                .urls
                .contains(&"http://100.64.0.5:8892".to_string())
        );
    }

    // ── parse_ip_addr_output ─────────────────────────────────────────────────

    #[test]
    fn parse_ip_addr_output_extracts_ips() {
        let fixture = "\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    inet 127.0.0.1/8 scope host lo
3: wlp58s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 192.0.2.8/24 brd 192.0.2.255 scope global dynamic noprefixroute wlp58s0
4: tailscale0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280
    inet 100.103.223.26/32 scope global tailscale0
5: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0";

        let ips = parse_ip_addr_output(fixture);
        assert_eq!(ips, vec!["192.0.2.8", "10.0.0.5"]);
    }

    // ── parse_ifconfig_output ────────────────────────────────────────────────

    #[test]
    fn parse_ifconfig_output_extracts_ips() {
        let fixture = "\
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
wlp58s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.0.2.8  netmask 255.255.255.0  broadcast 192.0.2.255
tailscale0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1280
        inet 100.103.223.26  netmask 255.255.255.255";

        let ips = parse_ifconfig_output(fixture);
        assert_eq!(ips, vec!["192.0.2.8"]);
    }

    // ── status_detail ────────────────────────────────────────────────────────

    #[test]
    fn detect_cloudflare_unconfigured_has_detail() {
        // With no env vars set, Cloudflare should report missing vars.
        // (This test relies on CI/dev not having CF env vars.)
        let ch = detect_cloudflare();
        if !ch.configured && !ch.detected {
            assert!(
                ch.status_detail.is_some(),
                "unconfigured Cloudflare should have status_detail"
            );
            let detail = ch.status_detail.as_deref().unwrap_or("");
            assert!(
                detail.contains("Missing env"),
                "detail should mention missing env: {detail}"
            );
        }
    }

    #[test]
    fn detect_caddy_has_detail_when_not_running() {
        let caddy = detect_caddy();
        if !caddy.running {
            assert!(
                caddy.status_detail.is_some(),
                "caddy not running should have status_detail"
            );
        }
    }

    #[test]
    fn channel_status_serializes_without_detail() {
        let ch = ChannelStatus {
            channel_type: "test".into(),
            configured: false,
            detected: false,
            ip: None,
            hostname: None,
            has_dns: None,
            has_https: None,
            has_cert: None,
            has_serve: None,
            urls: vec![],
            status_detail: None,
        };
        let json = serde_json::to_string(&ch).unwrap();
        assert!(
            !json.contains("status_detail"),
            "None status_detail should be omitted: {json}"
        );
    }

    #[test]
    fn channel_status_serializes_with_detail() {
        let ch = ChannelStatus {
            channel_type: "test".into(),
            configured: false,
            detected: false,
            ip: None,
            hostname: None,
            has_dns: None,
            has_https: None,
            has_cert: None,
            has_serve: None,
            urls: vec![],
            status_detail: Some("test detail".into()),
        };
        let json = serde_json::to_string(&ch).unwrap();
        assert!(
            json.contains("status_detail"),
            "Some status_detail should be present: {json}"
        );
        assert!(json.contains("test detail"));
    }
}
