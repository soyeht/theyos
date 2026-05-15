//! `soyeht pair` — generate a server-pairing QR code for the mobile app.

use std::path::Path;

/// Default bootstrap token path.
const DEFAULT_BOOTSTRAP_TOKEN_PATH: &str = "/var/lib/theyos/secrets/bootstrap-token";

/// Default admin backend URL.
const DEFAULT_ADMIN_URL: &str = "http://localhost:8892";

/// Maximum allowed TTL: 30 days.
const MAX_TTL_SECS: u64 = 30 * 24 * 3600;

/// Parse a human-readable duration string into seconds.
///
/// Accepted formats:
/// - `Nm` — N minutes (e.g., `30m`)
/// - `Nh` — N hours (e.g., `2h`)
/// - `Nd` — N days (e.g., `3d`)
/// - Bare number — minutes (e.g., `15` = 15 minutes)
///
/// # Errors
///
/// Returns an error string if the input is invalid, zero, or exceeds 30 days.
pub fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("duration cannot be empty".to_string());
    }

    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('d') {
        (n, 86400u64)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60u64)
    } else {
        // Bare number = minutes
        (s, 60u64)
    };

    let n: u64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration number: {num_str:?}"))?;

    if n == 0 {
        return Err("duration must be greater than zero".to_string());
    }

    let secs = n.checked_mul(multiplier).ok_or("duration overflow")?;

    if secs > MAX_TTL_SECS {
        return Err(format!(
            "duration exceeds maximum of 30 days ({secs}s > {MAX_TTL_SECS}s)"
        ));
    }

    Ok(secs)
}

/// Format seconds as a human-readable duration (e.g., "3 days", "2 hours", "15 minutes").
fn format_duration(secs: u64) -> String {
    if secs >= 86400 && secs % 86400 == 0 {
        let days = secs / 86400;
        if days == 1 {
            "1 day".to_string()
        } else {
            format!("{days} days")
        }
    } else if secs >= 3600 && secs % 3600 == 0 {
        let hours = secs / 3600;
        if hours == 1 {
            "1 hour".to_string()
        } else {
            format!("{hours} hours")
        }
    } else {
        let mins = secs / 60;
        if mins <= 1 {
            "1 minute".to_string()
        } else {
            format!("{mins} minutes")
        }
    }
}

/// Resolve the bootstrap token path from `THEYOS_BOOTSTRAP_TOKEN_PATH`, or a
/// platform-specific default (`~/.theyos/bootstrap-token` on macOS, the system
/// secrets dir on Linux).
fn resolve_token_path() -> String {
    std::env::var("THEYOS_BOOTSTRAP_TOKEN_PATH").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            format!("{home}/.theyos/bootstrap-token")
        } else {
            DEFAULT_BOOTSTRAP_TOKEN_PATH.to_string()
        }
    })
}

/// Build the user-facing error message (including hint) for a bootstrap token
/// read failure.
///
/// Separated from the actual print+exit so it can be unit-tested without
/// spawning a subprocess. Differentiates between:
/// - `PermissionDenied`: file exists but the current user lacks read
///   permission — almost always because the admin ran `soyeht pair` without
///   `sudo` on Linux, where the token is owned by the `soyeht` service
///   account. Hint: re-run with sudo.
/// - `NotFound`: the file has not been created yet. Hint: `install-nixos`
///   on Linux, `soyeht start` on macOS.
/// - Other: fall back to the raw error string.
fn format_token_read_error(token_path: &str, kind: std::io::ErrorKind, raw: &str) -> String {
    match kind {
        std::io::ErrorKind::PermissionDenied => {
            format!(
                "error: cannot read bootstrap token at {token_path}\n\
                 hint: this file is readable only by the service account. Re-run with sudo:\n  \
                 sudo soyeht pair"
            )
        }
        std::io::ErrorKind::NotFound => {
            if cfg!(target_os = "macos") {
                format!(
                    "error: bootstrap token not found at {token_path}\n\
                     hint: run 'soyeht start' first to generate the token, or:\n  \
                     openssl rand -base64 32 > ~/.theyos/bootstrap-token"
                )
            } else {
                format!(
                    "error: bootstrap token not found at {token_path}\n\
                     hint: run install-nixos first, or create the token manually:\n  \
                     sudo mkdir -p /var/lib/theyos/secrets\n  \
                     openssl rand -base64 32 | sudo tee /var/lib/theyos/secrets/bootstrap-token"
                )
            }
        }
        _ => format!("error: cannot read bootstrap token at {token_path}: {raw}"),
    }
}

/// Read the bootstrap token file, or print an actionable hint and exit(1).
///
/// Thin wrapper around `format_token_read_error` that handles the I/O side
/// effect. The message construction itself lives in the pure helper above
/// so it can be tested.
fn read_bootstrap_token_or_exit(token_path: &str) -> String {
    match std::fs::read_to_string(token_path) {
        Ok(t) => t.trim().to_string(),
        Err(e) => {
            eprintln!(
                "{}",
                format_token_read_error(token_path, e.kind(), &e.to_string())
            );
            std::process::exit(1);
        }
    }
}

pub fn run(_root: &Path, duration_secs: u64) {
    let token_path = resolve_token_path();
    let bootstrap_token = read_bootstrap_token_or_exit(&token_path);

    let admin_url =
        std::env::var("THEYOS_ADMIN_URL").unwrap_or_else(|_| DEFAULT_ADMIN_URL.to_string());

    let url = format!("{admin_url}/api/v1/mobile/pair-token");

    let human_dur = format_duration(duration_secs);
    eprintln!("Requesting pairing token from {url} (ttl: {human_dur}) ...");

    let body = serde_json::json!({ "ttl_secs": duration_secs });

    let resp = match ureq::post(&url)
        .set("Authorization", &format!("Bearer {bootstrap_token}"))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to request pairing token: {e}");
            eprintln!("hint: is the admin backend running? Try: curl {admin_url}/healthz");
            std::process::exit(1);
        }
    };

    let body: serde_json::Value = match resp.into_json() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: invalid response: {e}");
            std::process::exit(1);
        }
    };

    let deep_link = body["deep_link"].as_str().unwrap_or_default().to_string();

    if deep_link.is_empty() {
        eprintln!("error: server returned empty deep_link");
        eprintln!("response: {body}");
        std::process::exit(1);
    }

    // Show QR image URL (preferred — much easier for phones to scan than ASCII)
    if let Some(image_id) = body["image_id"].as_str() {
        let qr_url = format!("{admin_url}/qr/{image_id}");
        println!();
        println!("Open this URL in your browser to see the QR code:");
        println!("  {qr_url}");
        println!();
    }

    // ASCII fallback (for headless / no-browser environments)
    match qrcode::QrCode::new(&deep_link) {
        Ok(code) => {
            let qr_string = code
                .render::<char>()
                .quiet_zone(true)
                .module_dimensions(2, 1)
                .build();
            println!("ASCII fallback (open the URL above for a better QR code):");
            println!();
            println!("{qr_string}");
            println!();
        }
        Err(e) => {
            eprintln!("error: failed to generate QR code: {e}");
            eprintln!("deep link: {deep_link}");
            std::process::exit(1);
        }
    }

    println!("Scan the QR code with the theyOS mobile app.");
    println!();
    println!("Deep link: {deep_link}");
    if let Some(host) = body["host"].as_str() {
        println!("Server:    {host}");
    }
    if let Some(expires) = body["expires_at"].as_str() {
        println!("Expires:   {expires}");
    }
    println!();
    println!("The pairing token is single-use and expires in {human_dur}.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minutes() {
        assert_eq!(parse_duration("15m").unwrap(), 900);
        assert_eq!(parse_duration("1m").unwrap(), 60);
    }

    #[test]
    fn parse_hours() {
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("1h").unwrap(), 3600);
    }

    #[test]
    fn parse_days() {
        assert_eq!(parse_duration("3d").unwrap(), 259_200);
        assert_eq!(parse_duration("1d").unwrap(), 86400);
        assert_eq!(parse_duration("30d").unwrap(), 2_592_000);
    }

    #[test]
    fn parse_bare_number_is_minutes() {
        assert_eq!(parse_duration("15").unwrap(), 900);
        assert_eq!(parse_duration("60").unwrap(), 3600);
    }

    #[test]
    fn parse_zero_rejected() {
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("0m").is_err());
        assert!(parse_duration("0h").is_err());
        assert!(parse_duration("0d").is_err());
    }

    #[test]
    fn parse_exceeds_max_rejected() {
        assert!(parse_duration("31d").is_err());
        assert!(parse_duration("721h").is_err());
    }

    #[test]
    fn parse_invalid_rejected() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("m").is_err());
    }

    #[test]
    fn format_duration_display() {
        assert_eq!(format_duration(60), "1 minute");
        assert_eq!(format_duration(900), "15 minutes");
        assert_eq!(format_duration(3600), "1 hour");
        assert_eq!(format_duration(7200), "2 hours");
        assert_eq!(format_duration(86400), "1 day");
        assert_eq!(format_duration(259_200), "3 days");
    }

    // ── Bootstrap token error hints ─────────────────────────────────────────
    //
    // Regression coverage for two bugs fixed together:
    //
    //   1. `soyeht pair` failing with `Permission denied` used to emit the
    //      same "run install-nixos first" hint as the "file missing" case.
    //      That pointed admins at the wrong fix after commit 36cccd0c made
    //      `/var/lib/theyos/secrets/bootstrap-token` owned by `soyeht:soyeht`
    //      (0600). The new hint must explicitly ask the admin to re-run with
    //      `sudo`.
    //
    //   2. The "file missing" hint must still be preserved for the genuine
    //      NotFound case, and the text must match the platform (`install-nixos`
    //      on Linux, `soyeht start` on macOS) so a regression in the cfg!
    //      branch would be caught.
    //
    // These tests assert on the pure formatter so they don't spawn a
    // subprocess and don't touch the filesystem.

    #[test]
    fn format_error_permission_denied_tells_user_to_use_sudo() {
        let msg = format_token_read_error(
            "/var/lib/theyos/secrets/bootstrap-token",
            std::io::ErrorKind::PermissionDenied,
            "Permission denied (os error 13)",
        );
        assert!(
            msg.contains("/var/lib/theyos/secrets/bootstrap-token"),
            "should include the token path in the error: {msg}"
        );
        assert!(
            msg.contains("sudo soyeht pair"),
            "permission-denied hint MUST suggest `sudo soyeht pair`, got: {msg}"
        );
        // Must NOT point the user at reinstalling — that was the wrong hint.
        assert!(
            !msg.contains("install-nixos"),
            "permission-denied hint MUST NOT mention install-nixos, got: {msg}"
        );
        assert!(
            !msg.contains("openssl rand"),
            "permission-denied hint MUST NOT tell user to generate a new token, got: {msg}"
        );
    }

    #[test]
    fn format_error_not_found_keeps_install_hint() {
        let msg = format_token_read_error(
            "/var/lib/theyos/secrets/bootstrap-token",
            std::io::ErrorKind::NotFound,
            "No such file or directory",
        );
        assert!(
            msg.contains("not found"),
            "not-found message should say so explicitly: {msg}"
        );
        assert!(
            msg.contains("/var/lib/theyos/secrets/bootstrap-token"),
            "should include the token path in the error: {msg}"
        );
        // Platform-specific hint text.
        if cfg!(target_os = "macos") {
            assert!(
                msg.contains("soyeht start"),
                "macOS not-found hint should mention `soyeht start`: {msg}"
            );
        } else {
            assert!(
                msg.contains("install-nixos"),
                "Linux not-found hint should mention install-nixos: {msg}"
            );
            assert!(
                msg.contains("openssl rand -base64 32"),
                "Linux not-found hint should include the manual token command: {msg}"
            );
        }
        // Must NOT tell the user this is a permission problem.
        assert!(
            !msg.contains("sudo soyeht pair"),
            "not-found hint should not ask for sudo: {msg}"
        );
    }

    #[test]
    fn format_error_other_kind_falls_back_to_raw() {
        let msg = format_token_read_error(
            "/some/weird/path",
            std::io::ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        );
        assert!(msg.contains("/some/weird/path"), "got: {msg}");
        assert!(
            msg.contains("stream did not contain valid UTF-8"),
            "fallback must include the raw error: {msg}"
        );
        // Fallback should not accidentally show one of the curated hints.
        assert!(!msg.contains("sudo soyeht pair"), "got: {msg}");
        assert!(!msg.contains("install-nixos"), "got: {msg}");
    }

    #[test]
    fn read_bootstrap_token_trims_whitespace() {
        // Happy path: confirms the Ok branch of read_bootstrap_token_or_exit
        // still reads, decodes, and trims. Uses tempfile to avoid touching
        // real system paths.
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "  my-bearer-token-with-surrounding-whitespace  ").unwrap();
        f.flush().unwrap();
        let token = read_bootstrap_token_or_exit(f.path().to_str().unwrap());
        assert_eq!(token, "my-bearer-token-with-surrounding-whitespace");
    }
}
