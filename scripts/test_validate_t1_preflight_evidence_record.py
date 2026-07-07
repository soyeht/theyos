#!/usr/bin/env python3
"""Tests for scripts/validate-t1-preflight-evidence-record.py."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("validate-t1-preflight-evidence-record.py")
SPEC = importlib.util.spec_from_file_location("validate_t1_preflight_evidence_record", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

ARTIFACT_SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_ARTIFACT_SHA = "fedcba9876543210fedcba9876543210fedcba98"


def valid_record(audit_root: str = "/private/t1-audit-root") -> dict[str, object]:
    return {
        "schema": validator.SCHEMA,
        "artifact_sha": ARTIFACT_SHA,
        "scope": validator.SCOPE,
        "production_activation": False,
        "owner_authorization": True,
        "owner_authorization_ref": "owner-authorization-ref",
        "rollback": True,
        "rollback_ref": "rollback-ref",
        "hardware_t1_t4": True,
        "hardware_evidence_ref": "hardware-evidence-ref",
        "audit_export_policy_ref": "audit-export-policy-ref",
        "device_session_config_ref": "device-session-config-ref",
        "audit_root": audit_root,
    }


def valid_hardware_pack() -> str:
    return f"""# T1-T4 Hardware Evidence Pack

PR #286
artifact_sha: {ARTIFACT_SHA}
scope: dev-host T1-T4 only
production_activation=false

- [x] Owner authorization reviewed for this exact PR and artifact SHA.
- [x] Prebuilt rollback artifact is available and selected for restore.
- [x] Reference content verification completed for owner, rollback, and hardware refs.
- [x] T1 interface evidence captured with before, during, and after snapshots.
- [x] T2 live validation evidence captured on dev host.
- [x] T3 cleanup and stop evidence captured.
- [x] T4 rollback evidence captured.
- [x] Production excluded and not touched.
"""


def valid_owner_authorization() -> str:
    return f"""# T1 Owner Authorization

| field | value |
|---|---|
| Artifact | PR #286, commit {ARTIFACT_SHA}, build artifact hash {ARTIFACT_SHA} |
| Scope | dev-host T1-T4 only; production explicitly excluded |
| Production activation | production_activation=false |
| Topology | Engine-dev engine-alpha, Claw-A claw-alpha, Device-D device-alpha, Relay-R relay-alpha, Member-M1 member-alpha |
| Time window | 2026-07-06T12:00:00Z through 2026-07-06T13:00:00Z |
| Operator | operator-alpha |
| Rollback artifact | rollback-alpha reviewed for this exact artifact |
| Data policy | Public evidence uses neutral aliases and redacts raw local details |
| Stop authority | Any reviewer or operator may stop the run immediately |
| Owner sentence | I authorize dev-host per-Claw VPN T1-T4 validation for PR #286 commit {ARTIFACT_SHA}; I do not authorize production activation. |
"""


def valid_rollback_evidence() -> str:
    return f"""# T1 Rollback Evidence

PR #286
artifact_sha: {ARTIFACT_SHA}
scope: dev-host T1-T4 only
production_activation=false

- [x] Previous known-good dev engine artifact package is available for the exact commit.
- [x] Prebuilt rollback artifact is available and selected for restore.
- [x] Restore command or service operation is documented privately.
- [x] Environment snapshot exists with secrets removed and redacted.
- [x] Linux route cleanup procedure is ready.
- [x] macOS route cleanup procedure is ready.
- [x] Linux TUN cleanup procedure is ready.
- [x] macOS utun cleanup procedure is ready.
- [x] Relay/process stop procedure is ready.
- [x] Baseline health verification checklist is ready.
- [x] Rollback does not rebuild locally after a failed run.
- [x] Production excluded and not touched.
"""


def valid_audit_export_policy() -> str:
    return f"""# T1 Audit Export Policy

PR #286
artifact_sha: {ARTIFACT_SHA}
scope: dev-host T1-T4 only
production_activation=false

- [x] HMAC-SHA-256 keyed export is required for every off-host audit export record.
- [x] Reviewed export key source is documented privately and contains no key bytes.
- [x] Export key rotation policy is defined before any off-host export.
- [x] Export key retention and retirement policy is defined before any off-host export.
- [x] Export JSONL data retention policy is bounded and documented.
- [x] Raw member/device/claw subject identifiers are omitted from off-host export.
- [x] Local pseudonymous hash values are omitted from off-host export.
- [x] Off-host export destination review is required before transfer.
- [x] Production excluded and not touched.
"""


def valid_device_session_config() -> str:
    return """{
  "schema": "t1-dev-runner-device-session-v1",
  "scope": "dev-host T1-T4 only",
  "production_activation": false,
  "platform": "macos",
  "local_side": "device",
  "device_ipv4": "198.18.0.1",
  "claw_ipv4": "198.18.0.2",
  "claw_route_prefix_len": 32,
  "mtu": 1280
}
"""


class ValidateT1PreflightEvidenceRecordTests(unittest.TestCase):
    def assert_validation_error(self, record: object, expected_error: str) -> None:
        errors = validator.validate_record(record, ARTIFACT_SHA, check_root_dir=False)
        self.assertIn(expected_error, errors)

    def test_valid_record_passes_without_root_dir_check(self) -> None:
        self.assertEqual([], validator.validate_record(valid_record(), ARTIFACT_SHA, False))

    def test_rejects_schema_scope_and_sha_mismatch(self) -> None:
        cases = (
            ("schema", "per_claw_vpn_t1_preflight_evidence_v2", "schema must be per_claw_vpn_t1_preflight_evidence_v1"),
            ("scope", "production", "scope must be dev-host T1-T4 only"),
            ("artifact_sha", OTHER_ARTIFACT_SHA, "record artifact_sha must match the expected artifact SHA"),
        )
        for field, value, expected_error in cases:
            with self.subTest(field=field):
                record = valid_record()
                record[field] = value
                self.assert_validation_error(record, expected_error)

    def test_rejects_production_activation_false_booleans_and_empty_refs(self) -> None:
        cases = (
            ("production_activation", True, "production_activation must be false"),
            ("owner_authorization", False, "owner_authorization must be true"),
            ("rollback", False, "rollback must be true"),
            ("hardware_t1_t4", False, "hardware_t1_t4 must be true"),
            ("owner_authorization_ref", " ", "owner_authorization_ref must be a non-empty string"),
            ("rollback_ref", "", "rollback_ref must be a non-empty string"),
            ("hardware_evidence_ref", None, "hardware_evidence_ref must be a non-empty string"),
            ("audit_export_policy_ref", None, "audit_export_policy_ref must be a non-empty string"),
            ("device_session_config_ref", None, "device_session_config_ref must be a non-empty string"),
            ("owner_authorization_ref", "<owner-authorization-record-ref>", "owner_authorization_ref must not be a template placeholder"),
            ("rollback_ref", " <prebuilt-rollback-artifact-ref> ", "rollback_ref must not be a template placeholder"),
            ("hardware_evidence_ref", "<sanitized-t1-t4-evidence-pack-ref>", "hardware_evidence_ref must not be a template placeholder"),
            ("audit_export_policy_ref", "<audit-export-policy-ref>", "audit_export_policy_ref must not be a template placeholder"),
            ("device_session_config_ref", "<device-session-config-ref>", "device_session_config_ref must not be a template placeholder"),
        )
        for field, value, expected_error in cases:
            with self.subTest(field=field):
                record = valid_record()
                record[field] = value
                self.assert_validation_error(record, expected_error)

    def test_rejects_relative_parent_dir_and_nul_audit_roots(self) -> None:
        for audit_root in ("relative/root", "/tmp/../t1-root", "/tmp/t1\x00root"):
            with self.subTest(audit_root=repr(audit_root)):
                self.assert_validation_error(
                    valid_record(audit_root),
                    "audit_root must be an absolute path with normal components only",
                )

    def test_check_root_dir_accepts_canonical_0700_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.realpath(tmp)
            os.chmod(root, 0o700)
            self.assertEqual([], validator.validate_record(valid_record(root), ARTIFACT_SHA, True))

    def test_check_root_dir_rejects_shared_mode_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.realpath(tmp)
            os.chmod(root, 0o755)
            errors = validator.validate_record(valid_record(root), ARTIFACT_SHA, True)
            self.assertIn("audit_root mode must be exactly 0700", errors)

    def test_check_root_dir_rejects_regular_file_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root_file = Path(tmp) / "root-file"
            root_file.write_text("not a directory", encoding="utf-8")
            errors = validator.validate_record(valid_record(str(root_file)), ARTIFACT_SHA, True)
            self.assertIn("audit_root must be a directory", errors)

    def test_check_root_dir_rejects_symlink_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            target = tmpdir / "target-root"
            target.mkdir(mode=0o700)
            link = tmpdir / "root-link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlink unavailable: {error.__class__.__name__}")

            errors = validator.validate_record(valid_record(str(link)), ARTIFACT_SHA, True)
            self.assertIn("audit_root must be canonical with no symlink ancestors", errors)
            self.assertIn("audit_root must not be a symlink", errors)

    def test_cli_missing_record_error_does_not_echo_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing_record = Path(tmp) / "private-evidence-record.json"
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), ARTIFACT_SHA, str(missing_record)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(2, proc.returncode)
            self.assertIn("ERROR: could not read evidence record: FileNotFoundError", proc.stderr)
            self.assertFalse(str(missing_record) in proc.stderr, "stderr leaked record path")
            self.assertFalse(missing_record.name in proc.stderr, "stderr leaked record file name")

    def test_cli_check_hardware_pack_accepts_valid_private_pack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            hardware_pack = tmpdir / "private-hardware-evidence.md"
            hardware_pack.write_text(valid_hardware_pack(), encoding="utf-8")
            record_path = tmpdir / "private-evidence-record.json"
            record = valid_record(os.path.realpath(audit_root))
            record["hardware_evidence_ref"] = str(hardware_pack)
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    ARTIFACT_SHA,
                    str(record_path),
                    "--check-root-dir",
                    "--check-hardware-pack",
                    "--expected-pr",
                    "286",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertIn("OK: T1 preflight evidence record validates", proc.stdout)

    def test_cli_check_hardware_pack_fails_without_echoing_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            hardware_pack = tmpdir / "private-hardware-evidence.md"
            hardware_pack.write_text(valid_hardware_pack().replace("- [x] T4 rollback", "- [ ] T4 rollback"), encoding="utf-8")
            record_path = tmpdir / "private-evidence-record.json"
            record = valid_record(os.path.realpath(audit_root))
            record["hardware_evidence_ref"] = str(hardware_pack)
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    ARTIFACT_SHA,
                    str(record_path),
                    "--check-root-dir",
                    "--check-hardware-pack",
                    "--expected-pr",
                    "286",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(1, proc.returncode)
            self.assertIn("ERROR: hardware_evidence_ref pack: hardware evidence pack must not contain unchecked checklist items", proc.stderr)
            self.assertFalse(str(hardware_pack) in proc.stderr, "stderr leaked hardware pack path")
            self.assertFalse(hardware_pack.name in proc.stderr, "stderr leaked hardware pack file name")

    def test_cli_check_hardware_pack_missing_file_does_not_echo_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            missing_pack = tmpdir / "private-hardware-evidence.md"
            record_path = tmpdir / "private-evidence-record.json"
            record = valid_record(os.path.realpath(audit_root))
            record["hardware_evidence_ref"] = str(missing_pack)
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    ARTIFACT_SHA,
                    str(record_path),
                    "--check-root-dir",
                    "--check-hardware-pack",
                    "--expected-pr",
                    "286",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(1, proc.returncode)
            self.assertIn("ERROR: hardware_evidence_ref pack could not be read: FileNotFoundError", proc.stderr)
            self.assertFalse(str(missing_pack) in proc.stderr, "stderr leaked hardware pack path")
            self.assertFalse(missing_pack.name in proc.stderr, "stderr leaked hardware pack file name")

    def test_cli_check_private_refs_accepts_valid_private_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            owner_record = tmpdir / "private-owner-authorization.md"
            rollback_record = tmpdir / "private-rollback-evidence.md"
            hardware_pack = tmpdir / "private-hardware-evidence.md"
            audit_export_policy = tmpdir / "private-audit-export-policy.md"
            device_session_config = tmpdir / "private-device-session-config.json"
            owner_record.write_text(valid_owner_authorization(), encoding="utf-8")
            rollback_record.write_text(valid_rollback_evidence(), encoding="utf-8")
            hardware_pack.write_text(valid_hardware_pack(), encoding="utf-8")
            audit_export_policy.write_text(valid_audit_export_policy(), encoding="utf-8")
            device_session_config.write_text(valid_device_session_config(), encoding="utf-8")
            record_path = tmpdir / "private-evidence-record.json"
            record = valid_record(os.path.realpath(audit_root))
            record["owner_authorization_ref"] = str(owner_record)
            record["rollback_ref"] = str(rollback_record)
            record["hardware_evidence_ref"] = str(hardware_pack)
            record["audit_export_policy_ref"] = str(audit_export_policy)
            record["device_session_config_ref"] = str(device_session_config)
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    ARTIFACT_SHA,
                    str(record_path),
                    "--check-root-dir",
                    "--check-private-refs",
                    "--expected-pr",
                    "286",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertIn("OK: T1 preflight evidence record validates", proc.stdout)

    def test_cli_check_private_refs_rejects_owner_without_echoing_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            owner_record = tmpdir / "private-owner-authorization.md"
            rollback_record = tmpdir / "private-rollback-evidence.md"
            hardware_pack = tmpdir / "private-hardware-evidence.md"
            audit_export_policy = tmpdir / "private-audit-export-policy.md"
            device_session_config = tmpdir / "private-device-session-config.json"
            owner_record.write_text(valid_owner_authorization().replace("production_activation=false", "production_activation=true"), encoding="utf-8")
            rollback_record.write_text(valid_rollback_evidence(), encoding="utf-8")
            hardware_pack.write_text(valid_hardware_pack(), encoding="utf-8")
            audit_export_policy.write_text(valid_audit_export_policy(), encoding="utf-8")
            device_session_config.write_text(valid_device_session_config(), encoding="utf-8")
            record_path = tmpdir / "private-evidence-record.json"
            record = valid_record(os.path.realpath(audit_root))
            record["owner_authorization_ref"] = str(owner_record)
            record["rollback_ref"] = str(rollback_record)
            record["hardware_evidence_ref"] = str(hardware_pack)
            record["audit_export_policy_ref"] = str(audit_export_policy)
            record["device_session_config_ref"] = str(device_session_config)
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    ARTIFACT_SHA,
                    str(record_path),
                    "--check-root-dir",
                    "--check-private-refs",
                    "--expected-pr",
                    "286",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(1, proc.returncode)
            self.assertIn("ERROR: owner_authorization_ref artifact: production_activation must be false", proc.stderr)
            self.assertFalse(str(owner_record) in proc.stderr, "stderr leaked owner authorization path")
            self.assertFalse(owner_record.name in proc.stderr, "stderr leaked owner authorization file name")

    def test_cli_check_private_refs_missing_rollback_does_not_echo_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            owner_record = tmpdir / "private-owner-authorization.md"
            missing_rollback = tmpdir / "private-rollback-evidence.md"
            hardware_pack = tmpdir / "private-hardware-evidence.md"
            audit_export_policy = tmpdir / "private-audit-export-policy.md"
            device_session_config = tmpdir / "private-device-session-config.json"
            owner_record.write_text(valid_owner_authorization(), encoding="utf-8")
            hardware_pack.write_text(valid_hardware_pack(), encoding="utf-8")
            audit_export_policy.write_text(valid_audit_export_policy(), encoding="utf-8")
            device_session_config.write_text(valid_device_session_config(), encoding="utf-8")
            record_path = tmpdir / "private-evidence-record.json"
            record = valid_record(os.path.realpath(audit_root))
            record["owner_authorization_ref"] = str(owner_record)
            record["rollback_ref"] = str(missing_rollback)
            record["hardware_evidence_ref"] = str(hardware_pack)
            record["audit_export_policy_ref"] = str(audit_export_policy)
            record["device_session_config_ref"] = str(device_session_config)
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    ARTIFACT_SHA,
                    str(record_path),
                    "--check-root-dir",
                    "--check-private-refs",
                    "--expected-pr",
                    "286",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(1, proc.returncode)
            self.assertIn("ERROR: rollback_ref artifact could not be read: FileNotFoundError", proc.stderr)
            self.assertFalse(str(missing_rollback) in proc.stderr, "stderr leaked rollback evidence path")
            self.assertFalse(missing_rollback.name in proc.stderr, "stderr leaked rollback evidence file name")

    def test_cli_check_private_refs_rejects_invalid_rollback_without_echoing_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            owner_record = tmpdir / "private-owner-authorization.md"
            rollback_record = tmpdir / "private-rollback-evidence.md"
            hardware_pack = tmpdir / "private-hardware-evidence.md"
            audit_export_policy = tmpdir / "private-audit-export-policy.md"
            device_session_config = tmpdir / "private-device-session-config.json"
            owner_record.write_text(valid_owner_authorization(), encoding="utf-8")
            rollback_record.write_text(
                valid_rollback_evidence().replace("production_activation=false", "production_activation=true"),
                encoding="utf-8",
            )
            hardware_pack.write_text(valid_hardware_pack(), encoding="utf-8")
            audit_export_policy.write_text(valid_audit_export_policy(), encoding="utf-8")
            device_session_config.write_text(valid_device_session_config(), encoding="utf-8")
            record_path = tmpdir / "private-evidence-record.json"
            record = valid_record(os.path.realpath(audit_root))
            record["owner_authorization_ref"] = str(owner_record)
            record["rollback_ref"] = str(rollback_record)
            record["hardware_evidence_ref"] = str(hardware_pack)
            record["audit_export_policy_ref"] = str(audit_export_policy)
            record["device_session_config_ref"] = str(device_session_config)
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    ARTIFACT_SHA,
                    str(record_path),
                    "--check-root-dir",
                    "--check-private-refs",
                    "--expected-pr",
                    "286",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(1, proc.returncode)
            self.assertIn("ERROR: rollback_ref artifact: production_activation must be false", proc.stderr)
            self.assertFalse(str(rollback_record) in proc.stderr, "stderr leaked rollback evidence path")
            self.assertFalse(rollback_record.name in proc.stderr, "stderr leaked rollback evidence file name")

    def test_cli_check_private_refs_rejects_invalid_hardware_without_echoing_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            owner_record = tmpdir / "private-owner-authorization.md"
            rollback_record = tmpdir / "private-rollback-evidence.md"
            hardware_pack = tmpdir / "private-hardware-evidence.md"
            audit_export_policy = tmpdir / "private-audit-export-policy.md"
            device_session_config = tmpdir / "private-device-session-config.json"
            owner_record.write_text(valid_owner_authorization(), encoding="utf-8")
            rollback_record.write_text(valid_rollback_evidence(), encoding="utf-8")
            hardware_pack.write_text(
                valid_hardware_pack().replace("- [x] T4 rollback", "- [ ] T4 rollback"),
                encoding="utf-8",
            )
            audit_export_policy.write_text(valid_audit_export_policy(), encoding="utf-8")
            device_session_config.write_text(valid_device_session_config(), encoding="utf-8")
            record_path = tmpdir / "private-evidence-record.json"
            record = valid_record(os.path.realpath(audit_root))
            record["owner_authorization_ref"] = str(owner_record)
            record["rollback_ref"] = str(rollback_record)
            record["hardware_evidence_ref"] = str(hardware_pack)
            record["audit_export_policy_ref"] = str(audit_export_policy)
            record["device_session_config_ref"] = str(device_session_config)
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    ARTIFACT_SHA,
                    str(record_path),
                    "--check-root-dir",
                    "--check-private-refs",
                    "--expected-pr",
                    "286",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(1, proc.returncode)
            self.assertIn(
                "ERROR: hardware_evidence_ref pack: hardware evidence pack must not contain unchecked checklist items",
                proc.stderr,
            )
            self.assertFalse(str(hardware_pack) in proc.stderr, "stderr leaked hardware pack path")
            self.assertFalse(hardware_pack.name in proc.stderr, "stderr leaked hardware pack file name")

    def test_cli_check_private_refs_rejects_missing_audit_export_policy_without_echoing_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            owner_record = tmpdir / "private-owner-authorization.md"
            rollback_record = tmpdir / "private-rollback-evidence.md"
            hardware_pack = tmpdir / "private-hardware-evidence.md"
            missing_policy = tmpdir / "private-audit-export-policy.md"
            device_session_config = tmpdir / "private-device-session-config.json"
            owner_record.write_text(valid_owner_authorization(), encoding="utf-8")
            rollback_record.write_text(valid_rollback_evidence(), encoding="utf-8")
            hardware_pack.write_text(valid_hardware_pack(), encoding="utf-8")
            device_session_config.write_text(valid_device_session_config(), encoding="utf-8")
            record_path = tmpdir / "private-evidence-record.json"
            record = valid_record(os.path.realpath(audit_root))
            record["owner_authorization_ref"] = str(owner_record)
            record["rollback_ref"] = str(rollback_record)
            record["hardware_evidence_ref"] = str(hardware_pack)
            record["audit_export_policy_ref"] = str(missing_policy)
            record["device_session_config_ref"] = str(device_session_config)
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    ARTIFACT_SHA,
                    str(record_path),
                    "--check-root-dir",
                    "--check-private-refs",
                    "--expected-pr",
                    "286",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(1, proc.returncode)
            self.assertIn("ERROR: audit_export_policy_ref policy could not be read: FileNotFoundError", proc.stderr)
            self.assertFalse(str(missing_policy) in proc.stderr, "stderr leaked audit export policy path")
            self.assertFalse(missing_policy.name in proc.stderr, "stderr leaked audit export policy file name")

    def test_cli_check_private_refs_rejects_invalid_audit_export_policy_without_echoing_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            owner_record = tmpdir / "private-owner-authorization.md"
            rollback_record = tmpdir / "private-rollback-evidence.md"
            hardware_pack = tmpdir / "private-hardware-evidence.md"
            audit_export_policy = tmpdir / "private-audit-export-policy.md"
            device_session_config = tmpdir / "private-device-session-config.json"
            owner_record.write_text(valid_owner_authorization(), encoding="utf-8")
            rollback_record.write_text(valid_rollback_evidence(), encoding="utf-8")
            hardware_pack.write_text(valid_hardware_pack(), encoding="utf-8")
            audit_export_policy.write_text(
                valid_audit_export_policy().replace("production_activation=false", "production_activation=true"),
                encoding="utf-8",
            )
            device_session_config.write_text(valid_device_session_config(), encoding="utf-8")
            record_path = tmpdir / "private-evidence-record.json"
            record = valid_record(os.path.realpath(audit_root))
            record["owner_authorization_ref"] = str(owner_record)
            record["rollback_ref"] = str(rollback_record)
            record["hardware_evidence_ref"] = str(hardware_pack)
            record["audit_export_policy_ref"] = str(audit_export_policy)
            record["device_session_config_ref"] = str(device_session_config)
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    ARTIFACT_SHA,
                    str(record_path),
                    "--check-root-dir",
                    "--check-private-refs",
                    "--expected-pr",
                    "286",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(1, proc.returncode)
            self.assertIn("ERROR: audit_export_policy_ref policy: production_activation must be false", proc.stderr)
            self.assertFalse(str(audit_export_policy) in proc.stderr, "stderr leaked audit export policy path")
            self.assertFalse(audit_export_policy.name in proc.stderr, "stderr leaked audit export policy file name")

    def test_cli_check_private_refs_rejects_missing_device_session_config_without_echoing_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            owner_record = tmpdir / "private-owner-authorization.md"
            rollback_record = tmpdir / "private-rollback-evidence.md"
            hardware_pack = tmpdir / "private-hardware-evidence.md"
            audit_export_policy = tmpdir / "private-audit-export-policy.md"
            missing_config = tmpdir / "private-device-session-config.json"
            owner_record.write_text(valid_owner_authorization(), encoding="utf-8")
            rollback_record.write_text(valid_rollback_evidence(), encoding="utf-8")
            hardware_pack.write_text(valid_hardware_pack(), encoding="utf-8")
            audit_export_policy.write_text(valid_audit_export_policy(), encoding="utf-8")
            record_path = tmpdir / "private-evidence-record.json"
            record = valid_record(os.path.realpath(audit_root))
            record["owner_authorization_ref"] = str(owner_record)
            record["rollback_ref"] = str(rollback_record)
            record["hardware_evidence_ref"] = str(hardware_pack)
            record["audit_export_policy_ref"] = str(audit_export_policy)
            record["device_session_config_ref"] = str(missing_config)
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    ARTIFACT_SHA,
                    str(record_path),
                    "--check-root-dir",
                    "--check-private-refs",
                    "--expected-pr",
                    "286",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(1, proc.returncode)
            self.assertIn("ERROR: device_session_config_ref config could not be read: FileNotFoundError", proc.stderr)
            self.assertFalse(str(missing_config) in proc.stderr, "stderr leaked device session config path")
            self.assertFalse(missing_config.name in proc.stderr, "stderr leaked device session config file name")

    def test_cli_check_private_refs_rejects_invalid_device_session_config_without_echoing_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            owner_record = tmpdir / "private-owner-authorization.md"
            rollback_record = tmpdir / "private-rollback-evidence.md"
            hardware_pack = tmpdir / "private-hardware-evidence.md"
            audit_export_policy = tmpdir / "private-audit-export-policy.md"
            device_session_config = tmpdir / "private-device-session-config.json"
            owner_record.write_text(valid_owner_authorization(), encoding="utf-8")
            rollback_record.write_text(valid_rollback_evidence(), encoding="utf-8")
            hardware_pack.write_text(valid_hardware_pack(), encoding="utf-8")
            audit_export_policy.write_text(valid_audit_export_policy(), encoding="utf-8")
            device_session_config.write_text(
                valid_device_session_config().replace('"device_ipv4": "198.18.0.1"', '"device_ipv4": "SECRET-DEVICE-IP"'),
                encoding="utf-8",
            )
            record_path = tmpdir / "private-evidence-record.json"
            record = valid_record(os.path.realpath(audit_root))
            record["owner_authorization_ref"] = str(owner_record)
            record["rollback_ref"] = str(rollback_record)
            record["hardware_evidence_ref"] = str(hardware_pack)
            record["audit_export_policy_ref"] = str(audit_export_policy)
            record["device_session_config_ref"] = str(device_session_config)
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    ARTIFACT_SHA,
                    str(record_path),
                    "--check-root-dir",
                    "--check-private-refs",
                    "--expected-pr",
                    "286",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(1, proc.returncode)
            self.assertIn(
                "ERROR: device_session_config_ref config: dev session config device_ipv4 must be a valid IPv4 address",
                proc.stderr,
            )
            self.assertFalse("SECRET-DEVICE-IP" in proc.stderr, "stderr leaked device session config value")
            self.assertFalse(str(device_session_config) in proc.stderr, "stderr leaked device session config path")
            self.assertFalse(device_session_config.name in proc.stderr, "stderr leaked device session config file name")


if __name__ == "__main__":
    unittest.main()
