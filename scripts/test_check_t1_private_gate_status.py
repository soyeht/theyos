#!/usr/bin/env python3
"""Tests for scripts/check-t1-private-gate-status.py."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-t1-private-gate-status.py")

ARTIFACT_SHA = "0123456789abcdef0123456789abcdef01234567"


def valid_record(audit_root: str) -> dict[str, object]:
    return {
        "schema": "per_claw_vpn_t1_preflight_evidence_v1",
        "artifact_sha": ARTIFACT_SHA,
        "scope": "dev-host T1-T4 only",
        "production_activation": False,
        "owner_authorization": True,
        "rollback": True,
        "hardware_t1_t4": True,
        "owner_authorization_ref": "owner-authorization-ref",
        "rollback_ref": "rollback-ref",
        "hardware_evidence_ref": "hardware-evidence-ref",
        "audit_export_policy_ref": "audit-export-policy-ref",
        "device_session_config_ref": "device-session-config-ref",
        "audit_root": audit_root,
    }


def owner_authorization() -> str:
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


def rollback_evidence() -> str:
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


def hardware_pack() -> str:
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


def audit_export_policy() -> str:
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


def device_session_config() -> str:
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


def write_private_artifacts(tmpdir: Path) -> dict[str, Path]:
    paths = {
        "owner_authorization_ref": tmpdir / "private-owner-authorization.md",
        "rollback_ref": tmpdir / "private-rollback-evidence.md",
        "hardware_evidence_ref": tmpdir / "private-hardware-evidence.md",
        "audit_export_policy_ref": tmpdir / "private-audit-export-policy.md",
        "device_session_config_ref": tmpdir / "private-device-session-config.json",
    }
    paths["owner_authorization_ref"].write_text(owner_authorization(), encoding="utf-8")
    paths["rollback_ref"].write_text(rollback_evidence(), encoding="utf-8")
    paths["hardware_evidence_ref"].write_text(hardware_pack(), encoding="utf-8")
    paths["audit_export_policy_ref"].write_text(audit_export_policy(), encoding="utf-8")
    paths["device_session_config_ref"].write_text(device_session_config(), encoding="utf-8")
    return paths


class CheckT1PrivateGateStatusTests(unittest.TestCase):
    def run_script(self, record_path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), ARTIFACT_SHA, str(record_path), *extra],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_complete_private_gate_passes_without_echoing_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            private_paths = write_private_artifacts(tmpdir)
            record = valid_record(os.path.realpath(audit_root))
            record.update({field: str(path) for field, path in private_paths.items()})
            record_path = tmpdir / "private-evidence-record.json"
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = self.run_script(record_path, "--check-root-dir", "--check-private-refs", "--expected-pr", "286")

            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertIn("OK: private T1 gate is complete-shaped", proc.stdout)
            self.assertIn("OK_PRIVATE_REF: owner_authorization_ref", proc.stdout)
            self.assertIn("OK_PRIVATE_REF: rollback_ref", proc.stdout)
            self.assertIn("OK_PRIVATE_REF: hardware_evidence_ref", proc.stdout)
            self.assertIn("OK_PRIVATE_REF: audit_export_policy_ref", proc.stdout)
            self.assertIn("OK_PRIVATE_REF: device_session_config_ref", proc.stdout)
            self.assertFalse(str(record_path) in proc.stdout + proc.stderr)
            self.assertFalse("private-owner-authorization.md" in proc.stdout + proc.stderr)

    def test_missing_owner_and_hardware_reports_fields_without_echoing_record_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            rollback_record = tmpdir / "private-rollback-evidence.md"
            audit_export_record = tmpdir / "private-audit-export-policy.md"
            device_config = tmpdir / "private-device-session-config.json"
            rollback_record.write_text(rollback_evidence(), encoding="utf-8")
            audit_export_record.write_text(audit_export_policy(), encoding="utf-8")
            device_config.write_text(device_session_config(), encoding="utf-8")
            record = valid_record(os.path.realpath(audit_root))
            record["owner_authorization"] = False
            record["hardware_t1_t4"] = False
            record["owner_authorization_ref"] = ""
            record["hardware_evidence_ref"] = ""
            record["rollback_ref"] = str(rollback_record)
            record["audit_export_policy_ref"] = str(audit_export_record)
            record["device_session_config_ref"] = str(device_config)
            record_path = tmpdir / "private-evidence-record.json"
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = self.run_script(record_path, "--check-root-dir", "--check-private-refs", "--expected-pr", "286")

            self.assertEqual(1, proc.returncode)
            self.assertIn("MISSING_OR_INVALID: owner_authorization", proc.stderr)
            self.assertIn("MISSING_OR_INVALID: owner_authorization_ref", proc.stderr)
            self.assertIn("MISSING_OR_INVALID: hardware_t1_t4", proc.stderr)
            self.assertIn("MISSING_OR_INVALID: hardware_evidence_ref", proc.stderr)
            self.assertFalse(str(record_path) in proc.stderr)
            self.assertFalse(record_path.name in proc.stderr)
            self.assertFalse("INVALID_PRIVATE_REF: rollback_ref" in proc.stderr)
            self.assertFalse("INVALID_PRIVATE_REF: audit_export_policy_ref" in proc.stderr)
            self.assertFalse("INVALID_PRIVATE_REF: device_session_config_ref" in proc.stderr)

    def test_invalid_private_ref_reports_field_without_echoing_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            private_paths = write_private_artifacts(tmpdir)
            private_paths["owner_authorization_ref"].write_text(
                owner_authorization().replace("production_activation=false", "production_activation=true"),
                encoding="utf-8",
            )
            record = valid_record(os.path.realpath(audit_root))
            record.update({field: str(path) for field, path in private_paths.items()})
            record_path = tmpdir / "private-evidence-record.json"
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = self.run_script(record_path, "--check-root-dir", "--check-private-refs", "--expected-pr", "286")

            self.assertEqual(1, proc.returncode)
            self.assertIn("INVALID_PRIVATE_REF: owner_authorization_ref", proc.stderr)
            self.assertFalse(str(private_paths["owner_authorization_ref"]) in proc.stderr)
            self.assertFalse(private_paths["owner_authorization_ref"].name in proc.stderr)

    def test_invalid_device_session_config_reports_field_without_echoing_path_or_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            private_paths = write_private_artifacts(tmpdir)
            private_paths["device_session_config_ref"].write_text(
                device_session_config().replace('"device_ipv4": "198.18.0.1"', '"device_ipv4": "SECRET-DEVICE-IP"'),
                encoding="utf-8",
            )
            record = valid_record(os.path.realpath(audit_root))
            record.update({field: str(path) for field, path in private_paths.items()})
            record_path = tmpdir / "private-evidence-record.json"
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = self.run_script(record_path, "--check-root-dir", "--check-private-refs", "--expected-pr", "286")

            self.assertEqual(1, proc.returncode)
            self.assertIn("INVALID_PRIVATE_REF: device_session_config_ref", proc.stderr)
            self.assertFalse("SECRET-DEVICE-IP" in proc.stderr)
            self.assertFalse(str(private_paths["device_session_config_ref"]) in proc.stderr)
            self.assertFalse(private_paths["device_session_config_ref"].name in proc.stderr)

    def test_record_sha_mismatch_reports_field_without_echoing_record_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            audit_root = tmpdir / "audit-root"
            audit_root.mkdir(mode=0o700)
            record = valid_record(os.path.realpath(audit_root))
            record["artifact_sha"] = "fedcba9876543210fedcba9876543210fedcba98"
            record_path = tmpdir / "private-evidence-record.json"
            record_path.write_text(json.dumps(record), encoding="utf-8")

            proc = self.run_script(record_path, "--check-root-dir")

            self.assertEqual(1, proc.returncode)
            self.assertIn("INVALID_RECORD: artifact_sha", proc.stderr)
            self.assertFalse(str(record_path) in proc.stderr)
            self.assertFalse(record_path.name in proc.stderr)

    def test_missing_record_error_does_not_echo_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing_record = Path(tmp) / "private-evidence-record.json"

            proc = self.run_script(missing_record)

            self.assertEqual(2, proc.returncode)
            self.assertIn("ERROR: could not read evidence record: FileNotFoundError", proc.stderr)
            self.assertFalse(str(missing_record) in proc.stderr)
            self.assertFalse(missing_record.name in proc.stderr)


if __name__ == "__main__":
    unittest.main()
