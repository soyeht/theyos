#![cfg(test)]

use super::*;

#[test]
fn extract_version_and_build_from_restore_url() {
    let url = "https://updates.cdn-apple.com/2026/UniversalMac_26.4_25E246_Restore.ipsw";
    assert_eq!(extract_macos_version_from_url(url).as_deref(), Some("26.4"));
    assert_eq!(extract_macos_build_from_url(url).as_deref(), Some("25E246"));
}

#[test]
fn expected_filename_uses_build_when_available() {
    assert_eq!(
        expected_restore_filename("26.4", Some("25E246")),
        "UniversalMac_26.4_25E246_Restore.ipsw"
    );
    assert_eq!(
        expected_restore_filename("26.4", None),
        "UniversalMac_26.4_<build>_Restore.ipsw"
    );
}

#[test]
fn incompatible_error_mentions_manual_override() {
    let err = incompatible_restore_image_error("26.4", Some("25E246"), "26.4.1");
    assert!(err.contains("26.4.1"));
    assert!(err.contains("25E246"));
    assert!(err.contains("--ipsw"));
}

fn fw(version: &str, build: &str, url: &str, signed: bool) -> IpswIndexFirmware {
    IpswIndexFirmware {
        version: version.to_string(),
        build_id: build.to_string(),
        url: url.to_string(),
        signed,
    }
}

#[test]
fn host_restore_candidates_prefers_exact_build_match() {
    let firmwares = vec![
        fw(
            "26.4",
            "25E246",
            "https://updates.cdn-apple.com/restore-26.4",
            true,
        ),
        fw(
            "26.4",
            "25E999",
            "https://updates.cdn-apple.com/restore-26.4-other",
            true,
        ),
    ];
    // "25E999" > host "25E246" → Tier 2 also rejects it. Only the exact match remains.
    let candidates = select_host_restore_candidates(&firmwares, "26.4", Some("25E246"));
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].build_id, "25E246");
}

#[test]
fn host_restore_candidates_unparseable_host_build_keeps_version_match() {
    let firmwares = vec![
        fw(
            "26.4",
            "25E246",
            "https://updates.cdn-apple.com/restore-26.4",
            true,
        ),
        fw(
            "26.4",
            "25E247",
            "https://updates.cdn-apple.com/restore-26.4-alt",
            false,
        ),
    ];
    // host_build "missing" doesn't parse → host_build_supports_image is optimistic
    // → Tier 2 includes 25E246 (signed). 25E247 unsigned excluded.
    let candidates = select_host_restore_candidates(&firmwares, "26.4", Some("missing"));
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].version, "26.4");
    assert_eq!(candidates[0].build_id, "25E246");
}

#[test]
fn matching_lookup_error_includes_issue_link_and_context() {
    let err = matching_restore_lookup_error(
        Some("Mac13,2"),
        "26.4",
        Some("25E246"),
        "26.4.1",
        "https://updates.cdn-apple.com/latest.ipsw",
        "no signed restore match found in host-build lookup",
    );
    assert!(err.contains(MACOS_RESTORE_ISSUE_URL));
    assert!(err.contains("host_model: Mac13,2"));
    assert!(err.contains("host_macos_build: 25E246"));
    assert!(err.contains("latest_supported_restore_version: 26.4.1"));
}

#[test]
fn same_version() {
    assert!(host_version_sufficient("26.4", "26.4"));
}

#[test]
fn host_newer_minor() {
    assert!(host_version_sufficient("26.5", "26.4"));
}

#[test]
fn host_older_minor() {
    assert!(!host_version_sufficient("26.3", "26.4"));
}

#[test]
fn host_newer_major() {
    assert!(host_version_sufficient("27.0", "26.4"));
}

#[test]
fn host_older_major() {
    assert!(!host_version_sufficient("25.0", "26.4"));
}

#[test]
fn patch_versions() {
    assert!(host_version_sufficient("26.4.1", "26.4"));
    assert!(!host_version_sufficient("26.3.9", "26.4"));
}

#[test]
fn unparseable_returns_true() {
    assert!(host_version_sufficient("unknown", "26.4"));
    assert!(host_version_sufficient("26.4", "unknown"));
}

#[test]
fn empty_returns_true() {
    assert!(host_version_sufficient("", "26.4"));
    assert!(host_version_sufficient("26.4", ""));
}

// ── parse_apple_build ────────────────────────────────────────────────

#[test]
fn parse_apple_build_standard() {
    assert_eq!(
        parse_apple_build("25E246"),
        Some((25, "E".into(), 246, String::new()))
    );
}

#[test]
fn parse_apple_build_long_build_number() {
    assert_eq!(
        parse_apple_build("24D2054"),
        Some((24, "D".into(), 2054, String::new()))
    );
}

#[test]
fn parse_apple_build_with_lowercase_suffix() {
    assert_eq!(
        parse_apple_build("25E246a"),
        Some((25, "E".into(), 246, "a".into()))
    );
}

#[test]
fn parse_apple_build_invalid_returns_none() {
    assert_eq!(parse_apple_build("foo"), None);
    assert_eq!(parse_apple_build(""), None);
    assert_eq!(parse_apple_build("25"), None);
    assert_eq!(parse_apple_build("E246"), None);
}

// ── cmp_apple_builds ─────────────────────────────────────────────────

#[test]
fn cmp_apple_builds_orders_within_train() {
    assert_eq!(cmp_apple_builds("25E236", "25E246"), Ordering::Less);
    assert_eq!(cmp_apple_builds("25E246", "25E236"), Ordering::Greater);
    assert_eq!(cmp_apple_builds("25E246", "25E246"), Ordering::Equal);
}

#[test]
fn cmp_apple_builds_numeric_not_lexicographic() {
    // The whole point: lex compare would say "25E99" > "25E100" because '9' > '1'.
    assert_eq!(cmp_apple_builds("25E99", "25E100"), Ordering::Less);
    assert_eq!(cmp_apple_builds("24D70", "24D2054"), Ordering::Less);
}

#[test]
fn cmp_apple_builds_cross_train() {
    assert_eq!(cmp_apple_builds("25E999", "25F100"), Ordering::Less);
    assert_eq!(cmp_apple_builds("25Z999", "26A001"), Ordering::Less);
}

#[test]
fn cmp_apple_builds_unparseable_is_optimistic() {
    assert_eq!(cmp_apple_builds("foo", "25E246"), Ordering::Equal);
    assert_eq!(cmp_apple_builds("25E246", "garbage"), Ordering::Equal);
}

// ── host_build_supports_image ────────────────────────────────────────

#[test]
fn host_build_supports_image_exact_match() {
    assert!(host_build_supports_image("25E236", "25E236"));
}

#[test]
fn host_build_supports_image_older_image_is_compatible() {
    assert!(host_build_supports_image("25E246", "25E236"));
}

#[test]
fn host_build_supports_image_newer_image_is_rejected() {
    // The bug we are fixing: image_build > host_build must return false.
    assert!(!host_build_supports_image("25E236", "25E246"));
}

#[test]
fn host_build_supports_image_numeric_not_lex() {
    assert!(host_build_supports_image("25E100", "25E99"));
    assert!(!host_build_supports_image("25E99", "25E100"));
}

#[test]
fn host_build_supports_image_optimistic_when_unknown() {
    assert!(host_build_supports_image("25E236", ""));
    assert!(host_build_supports_image("", "25E236"));
    assert!(host_build_supports_image("25E236", "garbage"));
    assert!(host_build_supports_image("garbage", "25E236"));
}

// ── cmp_macos_versions ───────────────────────────────────────────────

#[test]
fn cmp_macos_versions_basic() {
    assert_eq!(cmp_macos_versions("26.4", "26.3"), Ordering::Greater);
    assert_eq!(cmp_macos_versions("26.4.1", "26.4"), Ordering::Greater);
    assert_eq!(cmp_macos_versions("26.4", "26.4"), Ordering::Equal);
    assert_eq!(cmp_macos_versions("27", "26.99"), Ordering::Greater);
    assert_eq!(cmp_macos_versions("26.3.1", "26.3.0"), Ordering::Greater);
}

// ── select_host_restore_candidates: tier-by-tier ─────────────────────

#[test]
fn candidates_tier1_exact_first_then_tier2_skips_newer_build() {
    let firmwares = vec![
        fw("26.4", "25E246", "u-25E246", true),
        fw("26.4", "25E236", "u-25E236", true),
    ];
    let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
    // Tier 1 picks 25E236; Tier 2 must reject 25E246 because 25E246 > 25E236.
    let labels: Vec<&str> = cs.iter().map(|c| c.build_id.as_str()).collect();
    assert_eq!(labels, vec!["25E236"]);
}

#[test]
fn candidates_tier2_falls_back_to_older_build() {
    let firmwares = vec![
        fw("26.4", "25E246", "u-25E246", true),
        fw("26.4", "25E230", "u-25E230", true),
    ];
    let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
    let labels: Vec<&str> = cs.iter().map(|c| c.build_id.as_str()).collect();
    assert_eq!(labels, vec!["25E230"]);
}

#[test]
fn candidates_tier2_orders_largest_compatible_first() {
    let firmwares = vec![
        fw("26.4", "25E100", "u-100", true),
        fw("26.4", "25E230", "u-230", true),
    ];
    let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
    let labels: Vec<&str> = cs.iter().map(|c| c.build_id.as_str()).collect();
    assert_eq!(labels, vec!["25E230", "25E100"]);
}

#[test]
fn candidates_tier1_then_tier2_ordering() {
    let firmwares = vec![
        fw("26.4", "25E236", "u-236", true),
        fw("26.4", "25E230", "u-230", true),
    ];
    let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
    let labels: Vec<&str> = cs.iter().map(|c| c.build_id.as_str()).collect();
    assert_eq!(labels, vec!["25E236", "25E230"]);
}

#[test]
fn candidates_tier3_legacy_version() {
    let firmwares = vec![
        fw("26.4", "25E246", "u-26.4", true),
        fw("26.3", "25D70", "u-26.3", true),
    ];
    let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
    // Apple's 26.4/25E246 is too new (build > host); Tier 3 picks 26.3.
    let labels: Vec<(&str, &str)> = cs
        .iter()
        .map(|c| (c.version.as_str(), c.build_id.as_str()))
        .collect();
    assert_eq!(labels, vec![("26.3", "25D70")]);
}

#[test]
fn candidates_tier3_orders_newest_legacy_first() {
    let firmwares = vec![
        fw("26.4", "25E246", "u-26.4", true),
        fw("26.3.1", "25D199", "u-26.3.1", true),
        fw("26.3", "25D70", "u-26.3", true),
        fw("26.2", "25C100", "u-26.2", true),
    ];
    let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
    let pairs: Vec<(&str, &str)> = cs
        .iter()
        .map(|c| (c.version.as_str(), c.build_id.as_str()))
        .collect();
    assert_eq!(
        pairs,
        vec![("26.3.1", "25D199"), ("26.3", "25D70"), ("26.2", "25C100")]
    );
}

#[test]
fn candidates_tier1_tier2_tier3_combined() {
    let firmwares = vec![
        fw("26.4", "25E236", "u-236", true),
        fw("26.4", "25E230", "u-230", true),
        fw("26.3", "25D70", "u-26.3", true),
    ];
    let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
    let pairs: Vec<(&str, &str)> = cs
        .iter()
        .map(|c| (c.version.as_str(), c.build_id.as_str()))
        .collect();
    assert_eq!(
        pairs,
        vec![("26.4", "25E236"), ("26.4", "25E230"), ("26.3", "25D70")]
    );
}

#[test]
fn candidates_skip_unsigned() {
    let firmwares = vec![
        fw("26.4", "25E236", "u-236", false),
        fw("26.4", "25E230", "u-230", true),
    ];
    let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
    let labels: Vec<&str> = cs.iter().map(|c| c.build_id.as_str()).collect();
    assert_eq!(labels, vec!["25E230"]);
}

#[test]
fn candidates_no_match_when_only_newer_builds_signed() {
    let firmwares = vec![fw("27.0", "26A001", "u-27", true)];
    let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
    assert!(cs.is_empty());
}

#[test]
fn candidates_truncated_at_max() {
    let mut firmwares = Vec::new();
    // 10 compatible legacy entries — all valid Tier 3 candidates.
    for n in 0..10 {
        let build = format!("25D{:03}", 100 - n);
        let url = format!("u-{n}");
        firmwares.push(fw("26.3", &build, &url, true));
    }
    let cs = select_host_restore_candidates(&firmwares, "26.4", Some("25E236"));
    // MAX_LEGACY_VERSION_CANDIDATES = 3.
    assert_eq!(cs.len(), 3);
}

#[test]
fn candidates_unknown_host_build_keeps_version_match() {
    let firmwares = vec![
        fw("26.4", "25E246", "u-26.4", true),
        fw("26.3", "25D70", "u-26.3", true),
    ];
    let cs = select_host_restore_candidates(&firmwares, "26.4", None);
    let pairs: Vec<(&str, &str)> = cs
        .iter()
        .map(|c| (c.version.as_str(), c.build_id.as_str()))
        .collect();
    assert_eq!(pairs, vec![("26.4", "25E246"), ("26.3", "25D70")]);
}

#[test]
fn candidates_filename_extract_plus_compat_check_catches_bug() {
    // End-to-end check that the build extracted from a filename is rejected
    // when it's newer than the host's build (the original 25E246 vs 25E236 bug).
    let url = "https://updates.cdn-apple.com/UniversalMac_26.4_25E246_Restore.ipsw";
    let image_build = extract_macos_build_from_url(url);
    assert_eq!(image_build.as_deref(), Some("25E246"));
    assert!(!host_build_supports_image(
        "25E236",
        image_build.as_deref().unwrap()
    ));
}
