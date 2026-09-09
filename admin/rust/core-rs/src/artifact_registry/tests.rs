#![cfg(test)]

use super::*;

fn valid_manifest() -> ArtifactManifest {
    ArtifactManifest {
        manifest_version: 1,
        claw: "hermes-agent".into(),
        version: "0.7.0".into(),
        arch: "x86_64-linux".into(),
        fingerprint: "e".repeat(64),
        base_rootfs_version: "v2".into(),
        sha256: "a".repeat(64),
        size_bytes: 500_000_000,
        url: "https://r2.example.com/hermes-agent/x86_64-linux/0.7.0/rootfs.ext4.zst".into(),
        published_at: "2026-04-01T00:00:00Z".into(),
        channel: "stable".into(),
        base_rootfs_sha256: "b".repeat(64),
        installer_plan_sha256: "c".repeat(64),
        kernel_sha256: "d".repeat(64),
        kernel_version: Some(crate::guest_net::KERNEL_FILENAME.into()),
        firecracker_version: Some("v1.15.0".into()),
        runtime_min_version: None,
    }
}

// ── Serde round-trip ────────────────────────────────────────────────

#[test]
fn serde_roundtrip() {
    let m = valid_manifest();
    let json = serde_json::to_string_pretty(&m).expect("serialize");
    let parsed: ArtifactManifest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.claw, "hermes-agent");
    assert_eq!(parsed.manifest_version, 1);
    assert_eq!(parsed.sha256, "a".repeat(64));
    assert_eq!(
        parsed.kernel_version.as_deref(),
        Some(crate::guest_net::KERNEL_FILENAME)
    );
}

#[test]
fn serde_optional_fields_absent() {
    let mut m = valid_manifest();
    m.kernel_version = None;
    m.firecracker_version = None;
    m.runtime_min_version = None;
    let json = serde_json::to_string(&m).expect("serialize");
    assert!(!json.contains("kernel_version"));
    assert!(!json.contains("firecracker_version"));
    assert!(!json.contains("runtime_min_version"));

    let parsed: ArtifactManifest = serde_json::from_str(&json).expect("deserialize");
    assert!(parsed.kernel_version.is_none());
}

// ── Validation ──────────────────────────────────────────────────────

#[test]
fn validate_ok() {
    assert!(valid_manifest().validate().is_ok());
}

#[test]
fn validate_bad_version() {
    let mut m = valid_manifest();
    m.manifest_version = 2;
    assert_eq!(
        m.validate().unwrap_err(),
        ValidationError::UnsupportedVersion(2)
    );
}

#[test]
fn validate_sha256_wrong_length() {
    let mut m = valid_manifest();
    m.sha256 = "abc".into();
    assert_eq!(
        m.validate().unwrap_err(),
        ValidationError::InvalidSha256Length(3)
    );
}

#[test]
fn validate_sha256_non_hex() {
    let mut m = valid_manifest();
    m.sha256 = format!("{}zzzz", "a".repeat(60));
    assert_eq!(m.validate().unwrap_err(), ValidationError::InvalidSha256Hex);
}

#[test]
fn validate_empty_claw() {
    let mut m = valid_manifest();
    m.claw = String::new();
    assert_eq!(
        m.validate().unwrap_err(),
        ValidationError::EmptyField("claw")
    );
}

#[test]
fn validate_empty_url() {
    let mut m = valid_manifest();
    m.url = String::new();
    assert_eq!(
        m.validate().unwrap_err(),
        ValidationError::EmptyField("url")
    );
}

#[test]
fn validate_rejects_relative_url() {
    let mut m = valid_manifest();
    m.url = "/hermes-agent/x86_64-linux/0.7.0/rootfs.ext4.zst".into();
    assert_eq!(m.validate().unwrap_err(), ValidationError::InvalidUrlScheme);
}

#[test]
fn validate_rejects_invalid_fingerprint() {
    let mut m = valid_manifest();
    m.fingerprint = "short".into();
    assert_eq!(
        m.validate().unwrap_err(),
        ValidationError::InvalidDigestLength {
            field: "fingerprint",
            len: 5,
        }
    );
}

#[test]
fn validate_rejects_invalid_base_rootfs_sha256() {
    let mut m = valid_manifest();
    m.base_rootfs_sha256 = format!("{}zzzz", "b".repeat(60));
    assert_eq!(
        m.validate().unwrap_err(),
        ValidationError::InvalidDigestHex {
            field: "base_rootfs_sha256",
        }
    );
}

#[test]
fn validate_rejects_invalid_installer_plan_sha256() {
    let mut m = valid_manifest();
    m.installer_plan_sha256 = "abc".into();
    assert_eq!(
        m.validate().unwrap_err(),
        ValidationError::InvalidDigestLength {
            field: "installer_plan_sha256",
            len: 3,
        }
    );
}

#[test]
fn validate_rejects_invalid_kernel_sha256() {
    let mut m = valid_manifest();
    m.kernel_sha256 = format!("{}zzzz", "d".repeat(60));
    assert_eq!(
        m.validate().unwrap_err(),
        ValidationError::InvalidDigestHex {
            field: "kernel_sha256",
        }
    );
}

#[test]
fn validate_rejects_public_http_url() {
    let mut m = valid_manifest();
    m.url = "http://r2.example.com/hermes-agent/x86_64-linux/0.7.0/rootfs.ext4.zst".into();
    assert_eq!(
        m.validate().unwrap_err(),
        ValidationError::InsecureUrlScheme
    );
}

#[test]
fn validate_accepts_loopback_http_url() {
    let mut m = valid_manifest();
    m.url = "http://127.0.0.1:8080/rootfs.ext4.zst".into();
    assert!(m.validate().is_ok());
}

// ── URL scheme policy ───────────────────────────────────────────────

#[test]
fn secure_url_accepts_https() {
    assert!(is_secure_artifact_url(
        "https://example.com/rootfs.ext4.zst"
    ));
    assert!(is_secure_artifact_url("https://r2.example.com/a/b/c"));
    // https is accepted regardless of host, including loopback.
    assert!(is_secure_artifact_url("https://127.0.0.1:8443/x"));
}

#[test]
fn secure_url_accepts_loopback_http() {
    for url in [
        "http://127.0.0.1/rootfs.ext4.zst",
        "http://127.0.0.1:8080/rootfs.ext4.zst",
        "http://127.0.0.1:1",
        "http://localhost/x",
        "http://localhost:9000/x",
        "http://[::1]/rootfs.ext4.zst",
        "http://[::1]:8080/x",
    ] {
        assert!(
            is_secure_artifact_url(url),
            "loopback http should be allowed: {url}"
        );
    }
}

#[test]
fn secure_url_rejects_public_http() {
    for url in [
        "http://example.com/rootfs.ext4.zst",
        "http://r2.example.com/a/b",
        "http://8.8.8.8/x",
    ] {
        assert!(
            !is_secure_artifact_url(url),
            "public http should be rejected: {url}"
        );
    }
}

#[test]
fn secure_url_rejects_userinfo_authority_spoof() {
    // The real host is `evil.example`; the loopback string is only userinfo.
    assert!(!is_secure_artifact_url(
        "http://127.0.0.1@evil.example/rootfs.ext4.zst"
    ));
    assert!(!is_secure_artifact_url("http://localhost@evil.example/x"));
    assert!(!is_secure_artifact_url("http://[::1]@evil.example/x"));
}

#[test]
fn secure_url_rejects_loopback_lookalike_hostnames() {
    // `localhost` is a prefix but the host is `localhost.evil.example`.
    assert!(!is_secure_artifact_url(
        "http://localhost.evil.example/rootfs.ext4.zst"
    ));
    assert!(!is_secure_artifact_url("http://127.0.0.1.evil.example/x"));
    assert!(!is_secure_artifact_url("http://notlocalhost/x"));
}

#[test]
fn secure_url_fails_closed_on_unknown_or_malformed() {
    // No scheme / non-http(s) scheme / malformed authority -> not secure.
    assert!(!is_secure_artifact_url("/relative/path"));
    assert!(!is_secure_artifact_url("ftp://127.0.0.1/x"));
    assert!(!is_secure_artifact_url("http://[::1/x")); // unclosed bracket
    assert!(!is_secure_artifact_url(""));
}

#[test]
fn secure_url_rejects_malformed_ipv6_bracket_suffix() {
    // After `]` the only legal authority is empty or `:port`. A trailing
    // hostname smuggled after the bracket must not trust the inner `::1`.
    assert!(!is_secure_artifact_url("http://[::1]evil.example/x"));
    assert!(!is_secure_artifact_url("http://[::1]@evil.example/x"));
    assert!(!is_secure_artifact_url("http://[::1].evil.example/x"));
    // Sanity: the legitimate bracketed forms still pass.
    assert!(is_secure_artifact_url("http://[::1]/x"));
    assert!(is_secure_artifact_url("http://[::1]:8080/x"));
}

#[test]
fn secure_url_rejects_non_numeric_ports() {
    assert!(!is_secure_artifact_url("http://127.0.0.1:notaport/x"));
    assert!(!is_secure_artifact_url("http://localhost:notaport/x"));
    assert!(!is_secure_artifact_url("http://[::1]:notaport/x"));
    // Empty port is malformed -> rejected.
    assert!(!is_secure_artifact_url("http://127.0.0.1:/x"));
    // Numeric ports still pass.
    assert!(is_secure_artifact_url("http://127.0.0.1:65535/x"));
    assert!(is_secure_artifact_url("http://localhost:9000/x"));
}

// ── Architecture ────────────────────────────────────────────────────

#[test]
fn host_arch_is_non_empty() {
    let arch = host_arch();
    assert!(!arch.is_empty());
    assert!(arch.contains('-'), "expected 'arch-os' format, got: {arch}");
}

#[test]
fn check_arch_compatible_with_self() {
    let host = host_arch();
    assert!(check_arch_compatible(&host).is_ok());
}

#[test]
fn check_arch_mismatch() {
    let result = check_arch_compatible("mips-bsd");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("mips-bsd"),
        "error should contain artifact arch: {err}"
    );
}

// Runtime compatibility

#[test]
fn runtime_compat_absent_is_fail_open() {
    // The currently published manifests omit the field - must not block.
    assert!(check_runtime_compatible(None, "0.1.0").is_ok());
}

#[test]
fn runtime_compat_equal_is_ok() {
    assert!(check_runtime_compatible(Some("1.2.3"), "1.2.3").is_ok());
}

#[test]
fn runtime_compat_newer_engine_is_ok() {
    assert!(check_runtime_compatible(Some("1.2.0"), "1.2.1").is_ok());
    assert!(check_runtime_compatible(Some("1.2.0"), "1.3.0").is_ok());
    assert!(check_runtime_compatible(Some("1.2.0"), "2.0.0").is_ok());
}

#[test]
fn runtime_compat_older_engine_fails_closed() {
    let err = check_runtime_compatible(Some("1.5.0"), "1.2.0").unwrap_err();
    assert!(
        matches!(err, RuntimeCompatError::RuntimeTooOld { .. }),
        "got: {err}"
    );
}

#[test]
fn runtime_compat_unparseable_min_fails_closed() {
    let err = check_runtime_compatible(Some("not.a.version"), "1.2.0").unwrap_err();
    assert!(matches!(
        err,
        RuntimeCompatError::RuntimeVersionUnparseable { .. }
    ));
}

#[test]
fn runtime_compat_unparseable_engine_fails_closed() {
    // Defensive: engine version is normally env!(CARGO_PKG_VERSION) and
    // always valid, but a bad value must fail closed, not panic.
    let err = check_runtime_compatible(Some("1.0.0"), "garbage").unwrap_err();
    assert!(matches!(
        err,
        RuntimeCompatError::EngineVersionUnparseable { .. }
    ));
}

#[test]
fn runtime_compat_prerelease_ordering() {
    // A prerelease engine is older than the required stable release.
    let err = check_runtime_compatible(Some("1.2.0"), "1.2.0-rc.1").unwrap_err();
    assert!(matches!(err, RuntimeCompatError::RuntimeTooOld { .. }));
    // A stable engine satisfies a prerelease minimum.
    assert!(check_runtime_compatible(Some("1.2.0-rc.1"), "1.2.0").is_ok());
}
