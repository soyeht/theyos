#![cfg(test)]

use super::*;
use std::fs;
use tempfile::TempDir;

fn make_current_golden(assets_dir: &Path, claw: &str) {
    let fp = core_rs::artifact_meta::Fingerprint::new(
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    );
    let version_dir = core_rs::artifact_meta::golden_version_dir(assets_dir, claw, &fp);
    fs::create_dir_all(&version_dir).unwrap();
    fs::write(version_dir.join("rootfs.ext4"), b"fake-rootfs").unwrap();
    let meta = core_rs::artifact_meta::GoldenMeta {
        claw_type: claw.to_string(),
        fingerprint: fp.clone(),
        base_rootfs_sha256: "b".repeat(64),
        installer_plan_sha256: "c".repeat(64),
        kernel_sha256: "d".repeat(64),
        builder_version: "test".into(),
        created_at: "2026-04-01T00:00:00Z".into(),
    };
    core_rs::artifact_meta::write_meta(&version_dir.join("golden.meta.json"), &meta).unwrap();
    let current_link = core_rs::artifact_meta::golden_current_link(assets_dir, claw);
    core_rs::artifact_meta::update_current_link(&current_link, &fp).unwrap();
}

#[test]
fn resolve_claws_empty_returns_all() {
    let claws = resolve_claws(&[]);
    assert_eq!(claws.len(), all_claws().len());
}

#[test]
fn resolve_claws_filters_unknown() {
    let claws = resolve_claws(&["nullclaw".to_string(), "fakeclaw".to_string()]);
    assert_eq!(claws, vec!["nullclaw"]);
}

#[test]
fn cmd_check_all_fresh_returns_false() {
    let d = TempDir::new().unwrap();
    let claws = all_claws();
    // Create fake images (age-only staleness — no hash needed)
    for claw in &claws {
        let img = d.path().join(format!("ubuntu-24.04-{claw}.ext4"));
        fs::write(&img, b"fake").unwrap();
    }
    let any_stale = cmd_check(&claws, d.path(), 7, false);
    assert!(!any_stale, "all should be fresh");
}

#[test]
fn cmd_check_missing_image_returns_true() {
    let d = TempDir::new().unwrap();
    let any_stale = cmd_check(&["nullclaw"], d.path(), 7, false);
    assert!(any_stale, "missing image should be stale");
}

#[test]
fn cmd_list_does_not_panic() {
    let d = TempDir::new().unwrap();
    cmd_list(d.path()); // just ensure no panic
}

#[test]
fn parse_env_u32_accepts_positive_values() {
    assert_eq!(parse_env_u32("8192"), Some(8192));
    assert_eq!(parse_env_u32(" 4 "), Some(4));
}

#[test]
fn parse_env_u32_rejects_zero_negative_and_invalid_values() {
    assert_eq!(parse_env_u32("0"), None);
    assert_eq!(parse_env_u32("-1"), None);
    assert_eq!(parse_env_u32("not-a-number"), None);
    assert_eq!(parse_env_u32(""), None);
}

/// `cmd_dag_check` should output valid JSON even when no goldens or build
/// artifacts exist.  All claws should be reported as stale.
#[test]
fn cmd_dag_check_all_missing_outputs_valid_json() {
    let d = TempDir::new().unwrap();
    let assets_dir = d.path();

    // Minimal BuildContext — files don't need to exist for dag-check
    // (stale_reason_dag handles missing files gracefully).
    let ctx = BuildContext {
        base_rootfs: assets_dir.join("nonexistent-rootfs.ext4"),
        assets_dir: assets_dir.to_path_buf(),
        build_dir: d.path().join("build"),
        ssh_key: d.path().join("key"),
        firecracker_bin: d.path().join("fc"),
        kernel_image: d.path().join("vmlinux"),
        slirp_bin: d.path().join("slirp"),
        vcpu_count: 2,
        mem_mib: 4096,
        repo_root: d.path().to_path_buf(),
    };

    // Capture stdout by calling the internals directly.
    // (cmd_dag_check prints to stdout, which is hard to capture in-process,
    //  so test the underlying logic instead.)
    for claw in &all_claws() {
        let reason = imagebuild::runner::stale_reason_dag(claw, &ctx);
        assert!(
            reason.is_some(),
            "{claw} should be stale when nothing exists"
        );
    }
}

/// When a versionated golden exists with metadata, `stale_reason_dag` should
/// detect it as fresh if all inputs match.
#[test]
fn dag_check_detects_fresh_golden() {
    let d = TempDir::new().unwrap();
    let assets_dir = d.path();

    // Create fake base rootfs and kernel
    let rootfs = d.path().join("base.ext4");
    let kernel = d.path().join("vmlinux");
    fs::write(&rootfs, b"rootfs-content").unwrap();
    fs::write(&kernel, b"kernel-content").unwrap();

    let claw = "nullclaw";

    // Compute the plan hash the same way imagebuilder does
    let plan = vmrunner_rs::installer_plan::get_plan(claw).unwrap();
    let plan_hash = plan.content_hash();
    let rootfs_sha = core_rs::artifact_meta::sha256_file(&rootfs).unwrap();
    let kernel_sha = core_rs::artifact_meta::sha256_file(&kernel).unwrap();

    // Compute expected fingerprint
    let fp = core_rs::artifact_meta::golden_fingerprint(&rootfs_sha, &plan_hash, &kernel_sha);

    // Create versionated golden with matching metadata
    let ver_dir = core_rs::artifact_meta::golden_version_dir(assets_dir, claw, &fp);
    fs::create_dir_all(&ver_dir).unwrap();
    fs::write(ver_dir.join("rootfs.ext4"), b"golden").unwrap();

    let meta = core_rs::artifact_meta::GoldenMeta {
        claw_type: claw.to_string(),
        fingerprint: fp.clone(),
        base_rootfs_sha256: rootfs_sha,
        installer_plan_sha256: plan_hash,
        kernel_sha256: kernel_sha,
        builder_version: "test".to_string(),
        created_at: "2025-01-01T00:00:00Z".to_string(),
    };
    core_rs::artifact_meta::write_meta(&ver_dir.join("golden.meta.json"), &meta).unwrap();
    let link = core_rs::artifact_meta::golden_current_link(assets_dir, claw);
    core_rs::artifact_meta::update_current_link(&link, &fp).unwrap();

    let ctx = BuildContext {
        base_rootfs: rootfs,
        assets_dir: assets_dir.to_path_buf(),
        build_dir: d.path().join("build"),
        ssh_key: d.path().join("key"),
        firecracker_bin: d.path().join("fc"),
        kernel_image: kernel,
        slirp_bin: d.path().join("slirp"),
        vcpu_count: 2,
        mem_mib: 4096,
        repo_root: d.path().to_path_buf(),
    };

    let reason = imagebuild::runner::stale_reason_dag(claw, &ctx);
    assert!(
        reason.is_none(),
        "nullclaw should be fresh, got: {reason:?}"
    );
}

#[test]
fn publish_manifest_requires_url_source() {
    let d = TempDir::new().unwrap();
    let assets_dir = d.path();
    make_current_golden(assets_dir, "hermes-agent");
    let zst_path = d.path().join("rootfs.ext4.zst");
    fs::write(&zst_path, b"compressed-rootfs").unwrap();
    let output = d.path().join("latest.json");

    let args = PublishManifestArgs {
        claw_type: "hermes-agent".into(),
        zst_file: zst_path,
        base_url: String::new(),
        artifact_url: None,
        channel: "stable".into(),
        output: Some(output),
    };

    assert!(!cmd_publish_manifest(&args, assets_dir));
}

#[test]
fn publish_manifest_writes_valid_manifest_with_explicit_url() {
    let d = TempDir::new().unwrap();
    let assets_dir = d.path();
    make_current_golden(assets_dir, "hermes-agent");
    let zst_path = d.path().join("rootfs.ext4.zst");
    fs::write(&zst_path, b"compressed-rootfs").unwrap();
    let output = d.path().join("latest.json");

    let args = PublishManifestArgs {
        claw_type: "hermes-agent".into(),
        zst_file: zst_path,
        base_url: String::new(),
        artifact_url: Some("https://example.com/hermes-agent/rootfs.ext4.zst".into()),
        channel: "stable".into(),
        output: Some(output.clone()),
    };

    assert!(cmd_publish_manifest(&args, assets_dir));
    let json = fs::read_to_string(&output).unwrap();
    let manifest: core_rs::artifact_registry::ArtifactManifest =
        serde_json::from_str(&json).unwrap();
    assert!(manifest.validate().is_ok());
    assert_eq!(manifest.claw, "hermes-agent");
    assert_eq!(
        manifest.version,
        core_rs::manifest::get("hermes-agent")
            .expect("hermes manifest entry")
            .version
    );
    assert_eq!(
        manifest.url,
        "https://example.com/hermes-agent/rootfs.ext4.zst"
    );
}

// sign-manifest tests.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use core_rs::artifact_signature::{
    ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW, ArtifactSignatureEnvelope, ArtifactSignatureKey,
    verify_required_latest_json_signature,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

const SIGN_KEY_ID: &str = "test-signer-p256";
const LATEST_JSON_PRETTY: &[u8] = b"{\n  \"manifest_version\": 1,\n  \"claw\": \"picoclaw\"\n}\n";

fn test_signing_key(scalar: u8) -> SigningKey {
    SigningKey::from_slice(&[scalar; 32]).expect("valid test scalar")
}

/// A test-only signer that signs the payload with a fixed P-256 test key.
fn test_signer(scalar: u8) -> impl FnOnce(&[u8]) -> Result<String, SignManifestError> {
    move |payload: &[u8]| {
        let signature: Signature = test_signing_key(scalar).sign(payload);
        Ok(B64URL.encode(signature.to_bytes()))
    }
}

fn test_public_pin(scalar: u8, key_id: &str) -> ArtifactSignatureKey {
    let public = test_signing_key(scalar)
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    ArtifactSignatureKey::new(key_id, ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW, public)
}

fn envelope_json(envelope: &ArtifactSignatureEnvelope) -> Vec<u8> {
    serde_json::to_vec(envelope).expect("envelope json")
}

#[test]
fn sign_envelope_verifies_with_public_test_key() {
    let envelope =
        build_signature_envelope(LATEST_JSON_PRETTY, SIGN_KEY_ID, test_signer(7)).unwrap();
    assert_eq!(envelope.key_id, SIGN_KEY_ID);
    assert_eq!(envelope.alg, ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW);
    verify_required_latest_json_signature(
        LATEST_JSON_PRETTY,
        Some(&envelope_json(&envelope)),
        &[test_public_pin(7, SIGN_KEY_ID)],
    )
    .expect("produced signature verifies");
}

#[test]
fn sign_envelope_fails_against_tampered_manifest() {
    let envelope =
        build_signature_envelope(LATEST_JSON_PRETTY, SIGN_KEY_ID, test_signer(7)).unwrap();
    let mut tampered = LATEST_JSON_PRETTY.to_vec();
    tampered[0] = b' ';
    assert!(
        verify_required_latest_json_signature(
            &tampered,
            Some(&envelope_json(&envelope)),
            &[test_public_pin(7, SIGN_KEY_ID)],
        )
        .is_err()
    );
}

#[test]
fn sign_envelope_does_not_verify_against_reserialized_minified_bytes() {
    // The exact pretty bytes are signed; a re-serialized (minified) copy is a
    // different byte string and must not verify.
    let envelope =
        build_signature_envelope(LATEST_JSON_PRETTY, SIGN_KEY_ID, test_signer(7)).unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(LATEST_JSON_PRETTY).expect("fixture parses");
    let minified = serde_json::to_vec(&value).expect("minified json");
    assert_ne!(LATEST_JSON_PRETTY, minified.as_slice());
    assert!(
        verify_required_latest_json_signature(
            &minified,
            Some(&envelope_json(&envelope)),
            &[test_public_pin(7, SIGN_KEY_ID)],
        )
        .is_err()
    );
}

#[test]
fn sign_envelope_rejects_empty_key_id() {
    assert!(matches!(
        build_signature_envelope(LATEST_JSON_PRETTY, "  ", test_signer(7)),
        Err(SignManifestError::MissingKeyId)
    ));
}

#[test]
fn sign_envelope_rejects_empty_signature() {
    assert!(matches!(
        build_signature_envelope(
            LATEST_JSON_PRETTY,
            SIGN_KEY_ID,
            |_: &[u8]| Ok(String::new())
        ),
        Err(SignManifestError::EmptySignature)
    ));
}

#[test]
fn run_sign_manifest_writes_verifiable_default_sig_json() {
    let d = TempDir::new().unwrap();
    let manifest = d.path().join("latest.json");
    fs::write(&manifest, LATEST_JSON_PRETTY).unwrap();

    assert!(run_sign_manifest(
        &manifest,
        SIGN_KEY_ID,
        None,
        test_signer(7)
    ));

    let sig_path = d.path().join("latest.json.sig.json");
    assert!(
        sig_path.is_file(),
        "default sig path is <manifest>.sig.json"
    );
    let sig_bytes = fs::read(&sig_path).unwrap();
    verify_required_latest_json_signature(
        LATEST_JSON_PRETTY,
        Some(&sig_bytes),
        &[test_public_pin(7, SIGN_KEY_ID)],
    )
    .expect("written sig.json verifies against the manifest");
}

#[test]
fn run_sign_manifest_aborts_on_signer_failure_without_writing() {
    let d = TempDir::new().unwrap();
    let manifest = d.path().join("latest.json");
    fs::write(&manifest, LATEST_JSON_PRETTY).unwrap();

    assert!(!run_sign_manifest(
        &manifest,
        SIGN_KEY_ID,
        None,
        |_: &[u8]| Err(SignManifestError::Signer("boom".into()))
    ));
    assert!(
        !d.path().join("latest.json.sig.json").exists(),
        "no signature is written on signer failure"
    );
}

#[test]
fn cmd_sign_manifest_requires_a_signer() {
    let d = TempDir::new().unwrap();
    let manifest = d.path().join("latest.json");
    fs::write(&manifest, LATEST_JSON_PRETTY).unwrap();
    let args = SignManifestArgs {
        manifest,
        key_id: SIGN_KEY_ID.into(),
        signer_cmd: None,
        output: None,
    };
    assert!(!cmd_sign_manifest(&args));
}

#[test]
fn external_command_signer_returns_stdout_line() {
    let signer = external_command_signer("cat >/dev/null; printf 'sig-line-xyz'");
    assert_eq!(signer(b"payload").unwrap(), "sig-line-xyz");
}

#[test]
fn external_command_signer_nonzero_exit_fails() {
    let signer = external_command_signer("cat >/dev/null; exit 7");
    assert!(matches!(
        signer(b"payload"),
        Err(SignManifestError::Signer(_))
    ));
}

#[test]
fn verify_manifest_signature_accepts_valid_pair() {
    let d = TempDir::new().unwrap();
    let manifest = d.path().join("latest.json");
    fs::write(&manifest, LATEST_JSON_PRETTY).unwrap();
    assert!(run_sign_manifest(
        &manifest,
        SIGN_KEY_ID,
        None,
        test_signer(7)
    ));

    let keyring = ArtifactSignatureKeyring::new().with_current(test_public_pin(7, SIGN_KEY_ID));
    assert!(run_verify_manifest_signature(&manifest, None, &keyring));
}

#[test]
fn verify_manifest_signature_rejects_tampered_manifest() {
    let d = TempDir::new().unwrap();
    let manifest = d.path().join("latest.json");
    fs::write(&manifest, LATEST_JSON_PRETTY).unwrap();
    assert!(run_sign_manifest(
        &manifest,
        SIGN_KEY_ID,
        None,
        test_signer(7)
    ));
    fs::write(
        &manifest,
        b"{\"manifest_version\":1,\"claw\":\"picoclaw\"}\n",
    )
    .unwrap();

    let keyring = ArtifactSignatureKeyring::new().with_current(test_public_pin(7, SIGN_KEY_ID));
    assert!(!run_verify_manifest_signature(&manifest, None, &keyring));
}

#[test]
fn verify_manifest_signature_rejects_wrong_keyring() {
    let d = TempDir::new().unwrap();
    let manifest = d.path().join("latest.json");
    fs::write(&manifest, LATEST_JSON_PRETTY).unwrap();
    assert!(run_sign_manifest(
        &manifest,
        SIGN_KEY_ID,
        None,
        test_signer(7)
    ));

    let keyring = ArtifactSignatureKeyring::new().with_current(test_public_pin(9, "other-key"));
    assert!(!run_verify_manifest_signature(&manifest, None, &keyring));
}
