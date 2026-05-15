//! Lightweight smoke test — verifies critical API routes in ~5s.
//!
//! Does NOT create real instances. Validates only:
//! 1. GET /healthz              → 200
//! 2. GET /readyz               → 200
//! 3. POST /api/v1/auth/login   → 200 + session cookie
//! 4. GET /api/v1/claw-types    → 200 + all 6 expected types present
//! 5. GET /api/v1/version       → 200
//! 6. GET /api/v1/instances     → 200 (authenticated)
//!
//! Returns `true` if all checks pass, `false` otherwise.

use std::time::Duration;

use serde::Deserialize;

use crate::runner::all_claw_types;

/// Run all smoke checks. Returns `true` iff every check passes.
///
/// Logs each check result to stderr.
#[must_use]
pub fn run_smoke(base_url: &str, user: &str, password: &str) -> bool {
    let mut all_ok = true;

    // Fast agent — short timeout, no cookie jar needed for public routes.
    let fast = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();

    // ── 1. GET /healthz ──────────────────────────────────────────────────────
    all_ok &= check(
        "GET /healthz",
        fast.get(&format!("{base_url}/healthz")).call(),
        |r| r.status() == 200,
    );

    // ── 2. GET /readyz ───────────────────────────────────────────────────────
    all_ok &= check(
        "GET /readyz",
        fast.get(&format!("{base_url}/readyz")).call(),
        |r| r.status() == 200,
    );

    // ── 3. POST /api/v1/auth/login ───────────────────────────────────────────
    // Use a cookie-aware agent so subsequent authenticated requests work.
    let auth_agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(15))
        .build();

    let login_ok = match auth_agent
        .post(&format!("{base_url}/api/v1/auth/login"))
        .set("Content-Type", "application/json")
        .send_json(serde_json::json!({
            "username": user,
            "password": password,
        })) {
        Ok(r) if r.status() == 200 => {
            eprintln!("[smoke] PASS  POST /api/v1/auth/login");
            true
        }
        Ok(r) => {
            eprintln!(
                "[smoke] FAIL  POST /api/v1/auth/login — HTTP {}",
                r.status()
            );
            false
        }
        Err(e) => {
            eprintln!("[smoke] FAIL  POST /api/v1/auth/login — {e}");
            false
        }
    };
    all_ok &= login_ok;

    // Only continue with authenticated checks if login succeeded.
    if !login_ok {
        eprintln!("[smoke] Skipping authenticated checks (login failed).");
        return false;
    }

    // ── 4. GET /api/v1/claw-types (legacy, will emit Deprecation header) ─────
    all_ok &= check_claw_types(&auth_agent, base_url);

    // ── 4a. GET /api/v1/claws (availability-aware catalog) ───────────────────
    all_ok &= check_claws(&auth_agent, base_url);

    // ── 5. GET /api/v1/version ───────────────────────────────────────────────
    all_ok &= check(
        "GET /api/v1/version",
        auth_agent.get(&format!("{base_url}/api/v1/version")).call(),
        |r| r.status() == 200,
    );

    // ── 6. GET /api/v1/instances ─────────────────────────────────────────────
    all_ok &= check(
        "GET /api/v1/instances",
        auth_agent
            .get(&format!("{base_url}/api/v1/instances"))
            .call(),
        |r| r.status() == 200,
    );

    if all_ok {
        eprintln!("[smoke] All checks passed.");
    } else {
        eprintln!("[smoke] One or more checks FAILED.");
    }

    all_ok
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Response shape for GET /api/v1/claw-types: `{"data": ["picoclaw", ...]}`
#[derive(Deserialize)]
struct ClawTypesResponse {
    data: Vec<String>,
}

/// Response shape for GET /api/v1/claws: each item is a full catalog entry
/// with install state and (new) availability projection. We only need the
/// name here to assert coverage.
#[derive(Deserialize)]
struct ClawsResponse {
    data: Vec<ClawsEntry>,
}

#[derive(Deserialize)]
struct ClawsEntry {
    name: String,
    #[serde(default)]
    #[allow(dead_code)]
    status: String,
}

/// Verify /api/v1/claws returns 200 with all expected claw names + install
/// state. This is the successor to /api/v1/claw-types and is what the
/// frontend + mobile app should be consuming.
fn check_claws(agent: &ureq::Agent, base_url: &str) -> bool {
    let label = "GET /api/v1/claws";
    match agent.get(&format!("{base_url}/api/v1/claws")).call() {
        Err(e) => {
            eprintln!("[smoke] FAIL  {label} — {e}");
            false
        }
        Ok(r) if r.status() != 200 => {
            eprintln!("[smoke] FAIL  {label} — HTTP {}", r.status());
            false
        }
        Ok(r) => match r.into_json::<ClawsResponse>() {
            Err(e) => {
                eprintln!("[smoke] FAIL  {label} — parse error: {e}");
                false
            }
            Ok(body) => {
                let returned: Vec<&str> = body.data.iter().map(|e| e.name.as_str()).collect();
                let known = all_claw_types();
                let missing: Vec<&&str> =
                    known.iter().filter(|ct| !returned.contains(ct)).collect();
                if missing.is_empty() {
                    eprintln!(
                        "[smoke] PASS  {label} — {} entries: {}",
                        returned.len(),
                        returned.join(", ")
                    );
                    true
                } else {
                    eprintln!(
                        "[smoke] FAIL  {label} — missing types: {}  (got: {})",
                        missing.iter().map(|s| **s).collect::<Vec<_>>().join(", "),
                        returned.join(", ")
                    );
                    false
                }
            }
        },
    }
}

/// Verify /api/v1/claw-types returns 200 with all 6 expected claw types.
fn check_claw_types(agent: &ureq::Agent, base_url: &str) -> bool {
    let label = "GET /api/v1/claw-types";
    match agent.get(&format!("{base_url}/api/v1/claw-types")).call() {
        Err(e) => {
            eprintln!("[smoke] FAIL  {label} — {e}");
            false
        }
        Ok(r) if r.status() != 200 => {
            eprintln!("[smoke] FAIL  {label} — HTTP {}", r.status());
            false
        }
        Ok(r) => match r.into_json::<ClawTypesResponse>() {
            Err(e) => {
                eprintln!("[smoke] FAIL  {label} — parse error: {e}");
                false
            }
            Ok(body) => {
                let returned: Vec<&str> = body.data.iter().map(String::as_str).collect();
                let known = all_claw_types();
                let missing: Vec<&&str> =
                    known.iter().filter(|ct| !returned.contains(ct)).collect();

                if missing.is_empty() {
                    eprintln!(
                        "[smoke] PASS  {label} — {} types: {}",
                        returned.len(),
                        returned.join(", ")
                    );
                    true
                } else {
                    eprintln!(
                        "[smoke] FAIL  {label} — missing types: {}  (got: {})",
                        missing.iter().map(|s| **s).collect::<Vec<_>>().join(", "),
                        returned.join(", ")
                    );
                    false
                }
            }
        },
    }
}

/// Generic check helper — logs PASS/FAIL and returns bool.
fn check<F>(label: &str, result: Result<ureq::Response, ureq::Error>, predicate: F) -> bool
where
    F: FnOnce(&ureq::Response) -> bool,
{
    match result {
        Ok(r) if predicate(&r) => {
            eprintln!("[smoke] PASS  {label}");
            true
        }
        Ok(r) => {
            eprintln!("[smoke] FAIL  {label} — HTTP {}", r.status());
            false
        }
        Err(e) => {
            eprintln!("[smoke] FAIL  {label} — {e}");
            false
        }
    }
}
