//! Contract tests — validates the inlined rate limiter against the shared
//! `admin/contracts/ratelimit/fixtures.json`.

#![allow(clippy::similar_names)]

use serde::Deserialize;
use server_rs::ratelimit::Limiter;
use std::path::PathBuf;

// ─── Fixture schema ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Fixture {
    id: String,
    #[allow(dead_code)]
    description: String,
    operation: String,
    input: serde_json::Value,
    expected: serde_json::Value,
}

fn load_fixtures() -> Vec<Fixture> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("contracts")
        .join("ratelimit")
        .join("fixtures.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixtures at {}: {e}", path.display()));
    serde_json::from_str(&data).expect("parse fixtures.json")
}

fn tmp_limiter(rph: i64) -> Limiter {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("contract.db");
    // Leak the tempdir so it lives for the duration of the test
    let db_str = db_path.to_str().unwrap().to_string();
    std::mem::forget(dir);
    Limiter::new(&db_str, rph).unwrap()
}

// ─── Test entry point ─────────────────────────────────────────────────────────

#[test]
fn contract_first_request_allowed() {
    let fixtures = load_fixtures();
    let f = fixtures
        .iter()
        .find(|f| f.id == "first_request_allowed")
        .unwrap();
    assert_eq!(f.operation, "check");

    let rph = f.input["requests_per_hour"].as_i64().unwrap();
    let user_id = f.input["user_id"].as_str().unwrap();
    let action = f.input["action"].as_str().unwrap();

    let limiter = tmp_limiter(rph);
    let allowed = limiter.check(user_id, action).unwrap();

    let exp_allowed = f.expected["allowed"].as_bool().unwrap();
    assert_eq!(allowed, exp_allowed, "fixture: {}", f.id);
}

#[test]
fn contract_under_limit_allowed() {
    let fixtures = load_fixtures();
    let f = fixtures
        .iter()
        .find(|f| f.id == "under_limit_allowed")
        .unwrap();
    assert_eq!(f.operation, "check_sequence");

    let rph = f.input["requests_per_hour"].as_i64().unwrap();
    let user_id = f.input["user_id"].as_str().unwrap();
    let action = f.input["action"].as_str().unwrap();
    let count = f.input["request_count"].as_i64().unwrap();

    let limiter = tmp_limiter(rph);
    let mut all_allowed = true;
    for _ in 0..count {
        if !limiter.check(user_id, action).unwrap() {
            all_allowed = false;
        }
    }

    let exp = f.expected["all_allowed"].as_bool().unwrap();
    assert_eq!(all_allowed, exp, "fixture: {}", f.id);
}

#[test]
fn contract_at_limit_denied() {
    let fixtures = load_fixtures();
    let f = fixtures.iter().find(|f| f.id == "at_limit_denied").unwrap();
    assert_eq!(f.operation, "check_over_limit");

    let rph = f.input["requests_per_hour"].as_i64().unwrap();
    let user_id = f.input["user_id"].as_str().unwrap();
    let action = f.input["action"].as_str().unwrap();

    let limiter = tmp_limiter(rph);

    // Fire rph requests — all should be allowed.
    for i in 0..rph {
        let allowed = limiter.check(user_id, action).unwrap();
        assert!(allowed, "request {i} should be allowed");
    }

    // The next request should be denied.
    let denied = !limiter.check(user_id, action).unwrap();
    let exp = f.expected["fourth_denied"].as_bool().unwrap();
    assert_eq!(denied, exp, "fixture: {}", f.id);
}

#[test]
fn contract_different_users_independent() {
    let fixtures = load_fixtures();
    let f = fixtures
        .iter()
        .find(|f| f.id == "different_users_independent")
        .unwrap();
    assert_eq!(f.operation, "check_independent_users");

    let rph = f.input["requests_per_hour"].as_i64().unwrap();
    let user_a = f.input["user_a"].as_str().unwrap();
    let user_b = f.input["user_b"].as_str().unwrap();
    let action = f.input["action"].as_str().unwrap();
    let user_a_reqs = f.input["user_a_requests"].as_i64().unwrap();
    let user_b_reqs = f.input["user_b_requests"].as_i64().unwrap();

    let limiter = tmp_limiter(rph);

    // Exhaust user A.
    for _ in 0..user_a_reqs {
        limiter.check(user_a, action).unwrap();
    }
    let a_denied = !limiter.check(user_a, action).unwrap();
    assert_eq!(
        a_denied,
        f.expected["user_a_third_denied"].as_bool().unwrap()
    );

    // User B should still be allowed.
    for _ in 0..user_b_reqs {
        limiter.check(user_b, action).unwrap();
    }
    let b_allowed = limiter.check(user_b, action).unwrap();
    assert_eq!(
        b_allowed,
        f.expected["user_b_second_allowed"].as_bool().unwrap()
    );
}

#[test]
fn contract_different_actions_independent() {
    let fixtures = load_fixtures();
    let f = fixtures
        .iter()
        .find(|f| f.id == "different_actions_independent")
        .unwrap();
    assert_eq!(f.operation, "check_independent_actions");

    let rph = f.input["requests_per_hour"].as_i64().unwrap();
    let user_id = f.input["user_id"].as_str().unwrap();
    let action_a = f.input["action_a"].as_str().unwrap();
    let action_b = f.input["action_b"].as_str().unwrap();
    let action_a_reqs = f.input["action_a_requests"].as_i64().unwrap();

    let limiter = tmp_limiter(rph);

    // Exhaust action A.
    for _ in 0..action_a_reqs {
        limiter.check(user_id, action_a).unwrap();
    }
    let a_denied = !limiter.check(user_id, action_a).unwrap();
    assert_eq!(
        a_denied,
        f.expected["action_a_third_denied"].as_bool().unwrap()
    );

    // Action B should be allowed.
    let b_allowed = limiter.check(user_id, action_b).unwrap();
    assert_eq!(
        b_allowed,
        f.expected["action_b_first_allowed"].as_bool().unwrap()
    );
}

#[test]
fn contract_remaining_fresh() {
    let fixtures = load_fixtures();
    let f = fixtures.iter().find(|f| f.id == "remaining_fresh").unwrap();
    assert_eq!(f.operation, "get_remaining");

    let rph = f.input["requests_per_hour"].as_i64().unwrap();
    let user_id = f.input["user_id"].as_str().unwrap();
    let action = f.input["action"].as_str().unwrap();
    let prior = f.input["prior_requests"].as_i64().unwrap();

    let limiter = tmp_limiter(rph);
    for _ in 0..prior {
        limiter.check(user_id, action).unwrap();
    }

    let remaining = limiter.get_remaining(user_id, action).unwrap();
    let exp = f.expected["remaining"].as_i64().unwrap();
    assert_eq!(remaining, exp, "fixture: {}", f.id);
}

#[test]
fn contract_remaining_after_requests() {
    let fixtures = load_fixtures();
    let f = fixtures
        .iter()
        .find(|f| f.id == "remaining_after_requests")
        .unwrap();
    assert_eq!(f.operation, "get_remaining");

    let rph = f.input["requests_per_hour"].as_i64().unwrap();
    let user_id = f.input["user_id"].as_str().unwrap();
    let action = f.input["action"].as_str().unwrap();
    let prior = f.input["prior_requests"].as_i64().unwrap();

    let limiter = tmp_limiter(rph);
    for _ in 0..prior {
        limiter.check(user_id, action).unwrap();
    }

    let remaining = limiter.get_remaining(user_id, action).unwrap();
    let exp = f.expected["remaining"].as_i64().unwrap();
    assert_eq!(remaining, exp, "fixture: {}", f.id);
}

#[test]
fn contract_remaining_at_zero() {
    let fixtures = load_fixtures();
    let f = fixtures
        .iter()
        .find(|f| f.id == "remaining_at_zero")
        .unwrap();
    assert_eq!(f.operation, "get_remaining");

    let rph = f.input["requests_per_hour"].as_i64().unwrap();
    let user_id = f.input["user_id"].as_str().unwrap();
    let action = f.input["action"].as_str().unwrap();
    let prior = f.input["prior_requests"].as_i64().unwrap();

    let limiter = tmp_limiter(rph);
    for _ in 0..prior {
        limiter.check(user_id, action).unwrap();
    }

    let remaining = limiter.get_remaining(user_id, action).unwrap();
    let exp = f.expected["remaining"].as_i64().unwrap();
    assert_eq!(remaining, exp, "fixture: {}", f.id);
}

// ─── Extra contract coverage ─────────────────────────────────────────────────

#[test]
fn contract_over_limit_remaining_is_zero() {
    // After exceeding the limit, remaining should clamp to 0.
    let limiter = tmp_limiter(2);
    for _ in 0..5 {
        limiter.check("over-user", "act").unwrap();
    }
    let remaining = limiter.get_remaining("over-user", "act").unwrap();
    assert_eq!(remaining, 0);
}

#[test]
fn contract_check_returns_false_not_error_at_limit() {
    // Verify that exceeding the limit returns Ok(false), not Err.
    let limiter = tmp_limiter(1);
    assert!(limiter.check("x", "a").unwrap()); // 1st allowed
    let result = limiter.check("x", "a");
    assert!(result.is_ok(), "should be Ok, not Err");
    assert!(!result.unwrap(), "should be false (denied)");
}

#[test]
fn contract_empty_user_and_action() {
    // Edge case: empty strings should still work as valid keys.
    let limiter = tmp_limiter(2);
    assert!(limiter.check("", "").unwrap());
    assert!(limiter.check("", "").unwrap());
    assert!(!limiter.check("", "").unwrap());
}

#[test]
fn contract_check_and_remaining_consistent() {
    // After N checks, remaining should be limit - N.
    let limiter = tmp_limiter(10);
    for _ in 0..4 {
        limiter.check("consistent-user", "act").unwrap();
    }
    let remaining = limiter.get_remaining("consistent-user", "act").unwrap();
    assert_eq!(remaining, 6);
}

#[test]
fn contract_multiple_actions_remaining_independent() {
    let limiter = tmp_limiter(5);
    for _ in 0..3 {
        limiter.check("multi-user", "action_x").unwrap();
    }
    limiter.check("multi-user", "action_y").unwrap();

    assert_eq!(limiter.get_remaining("multi-user", "action_x").unwrap(), 2);
    assert_eq!(limiter.get_remaining("multi-user", "action_y").unwrap(), 4);
}
