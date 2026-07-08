#!/usr/bin/env python3
"""Tests for scripts/assemble-t1-preflight-record.py.

All fixtures are doc-safe: synthetic aliases and documentation-range IPv4 only.
The tests prove the wrapper (1) assembles a record that passes the full
--check-private-refs chain from real inputs, (2) fails closed on a missing or
empty ref without fabricating a placeholder, (3) never emits a record with
production_activation true, and (4) never echoes a fixture secret or private
IPv4 in its output.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


WRAPPER = Path(__file__).with_name("assemble-t1-preflight-record.py")
VALIDATE_SCRIPT = Path(__file__).with_name("validate-t1-preflight-evidence-record.py")

SPEC = importlib.util.spec_from_file_location("assemble_t1_preflight_record", WRAPPER)
assert SPEC is not None and SPEC.loader is not None
wrapper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wrapper)

ARTIFACT_SHA = "0123456789abcdef0123456789abcdef01234567"


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


def write_refs(tmpdir: Path, *, device_session_config: str | None = None) -> dict[str, Path]:
    owner = tmpdir / "private-owner-authorization.md"
    rollback = tmpdir / "private-rollback-evidence.md"
    hardware = tmpdir / "private-hardware-evidence.md"
    audit_export_policy = tmpdir / "private-audit-export-policy.md"
    device_config = tmpdir / "private-device-session-config.json"
    owner.write_text(valid_owner_authorization(), encoding="utf-8")
    rollback.write_text(valid_rollback_evidence(), encoding="utf-8")
    hardware.write_text(valid_hardware_pack(), encoding="utf-8")
    audit_export_policy.write_text(valid_audit_export_policy(), encoding="utf-8")
    device_config.write_text(
        device_session_config if device_session_config is not None else valid_device_session_config(),
        encoding="utf-8",
    )
    return {
        "owner": owner,
        "rollback": rollback,
        "hardware": hardware,
        "audit_export_policy": audit_export_policy,
        "device_config": device_config,
    }


def run_wrapper(refs: dict[str, Path], out: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(WRAPPER),
            "--artifact-sha",
            ARTIFACT_SHA,
            "--owner-ref",
            str(refs["owner"]),
            "--rollback-ref",
            str(refs["rollback"]),
            "--hardware-ref",
            str(refs["hardware"]),
            "--audit-export-policy-ref",
            str(refs["audit_export_policy"]),
            "--device-session-config-ref",
            str(refs["device_config"]),
            "--out",
            str(out),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


class AssembleT1PreflightRecordTests(unittest.TestCase):
    def test_happy_path_assembles_record_that_passes_full_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            refs = write_refs(tmpdir)
            out = tmpdir / "private-evidence-record.json"

            proc = run_wrapper(refs, out)
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertIn(
                "OK: private T1 preflight evidence record assembled and fully validated",
                proc.stdout,
            )
            self.assertTrue(out.is_file())

            record = json.loads(out.read_text(encoding="utf-8"))
            self.assertIs(False, record["production_activation"])
            self.assertEqual("dev-host T1-T4 only", record["scope"])
            self.assertEqual(ARTIFACT_SHA, record["artifact_sha"])
            self.assertEqual(str(refs["owner"]), record["owner_authorization_ref"])
            self.assertEqual(str(refs["device_config"]), record["device_session_config_ref"])

            # The produced record independently passes the full validation chain.
            check = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATE_SCRIPT),
                    ARTIFACT_SHA,
                    str(out),
                    "--check-root-dir",
                    "--check-private-refs",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(0, check.returncode, check.stderr)
            self.assertIn("OK: T1 preflight evidence record validates", check.stdout)

    def test_missing_ref_fails_closed_without_fabrication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            refs = write_refs(tmpdir)
            missing = tmpdir / "does-not-exist-rollback.md"
            refs["rollback"] = missing
            out = tmpdir / "private-evidence-record.json"

            proc = run_wrapper(refs, out)
            self.assertEqual(1, proc.returncode)
            self.assertIn("ERROR: rollback_ref input is missing or empty", proc.stderr)
            # Fail-closed before any record is assembled: no placeholder synthesized.
            self.assertFalse(out.exists(), "wrapper must not write a record when a ref is missing")
            # Static error must not echo the missing path or file name.
            self.assertNotIn(str(missing), proc.stdout + proc.stderr)
            self.assertNotIn(missing.name, proc.stdout + proc.stderr)

    def test_empty_ref_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            refs = write_refs(tmpdir)
            empty = tmpdir / "empty-hardware-evidence.md"
            empty.write_text("   \n", encoding="utf-8")
            refs["hardware"] = empty
            out = tmpdir / "private-evidence-record.json"

            proc = run_wrapper(refs, out)
            self.assertEqual(1, proc.returncode)
            self.assertIn("ERROR: hardware_evidence_ref input is missing or empty", proc.stderr)
            self.assertFalse(out.exists(), "wrapper must not write a record for an empty ref")

    def test_never_emits_production_activation_true(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            refs = write_refs(tmpdir)
            out = tmpdir / "private-evidence-record.json"

            proc = run_wrapper(refs, out)
            self.assertEqual(0, proc.returncode, proc.stderr)
            raw = out.read_text(encoding="utf-8")
            record = json.loads(raw)
            self.assertIs(False, record["production_activation"])
            self.assertNotIn('"production_activation": true', raw)

    def test_invalid_ref_fails_closed_without_echoing_secret_value(self) -> None:
        secret_marker = "SECRET-DEVICE-IP-10.13.37.99"
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            tampered = valid_device_session_config().replace(
                '"device_ipv4": "198.18.0.1"', f'"device_ipv4": "{secret_marker}"'
            )
            refs = write_refs(tmpdir, device_session_config=tampered)
            out = tmpdir / "private-evidence-record.json"

            proc = run_wrapper(refs, out)
            self.assertEqual(1, proc.returncode)
            self.assertIn("ERROR: assembled record failed full preflight validation", proc.stderr)
            combined = proc.stdout + proc.stderr
            self.assertNotIn(secret_marker, combined, "wrapper output leaked the fixture secret value")
            self.assertNotIn("10.13.37.99", combined, "wrapper output leaked the fake private IPv4")
            self.assertNotIn(str(refs["device_config"]), combined, "wrapper output leaked a ref path")

    def test_rejects_non_hex_artifact_sha(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            refs = write_refs(tmpdir)
            out = tmpdir / "private-evidence-record.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(WRAPPER),
                    "--artifact-sha",
                    "not-a-valid-sha",
                    "--owner-ref",
                    str(refs["owner"]),
                    "--rollback-ref",
                    str(refs["rollback"]),
                    "--hardware-ref",
                    str(refs["hardware"]),
                    "--audit-export-policy-ref",
                    str(refs["audit_export_policy"]),
                    "--device-session-config-ref",
                    str(refs["device_config"]),
                    "--out",
                    str(out),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(1, proc.returncode)
            self.assertIn("ERROR: artifact_sha must be 40 hex characters", proc.stderr)
            self.assertFalse(out.exists())

    def test_ref_present_helper_rejects_missing_empty_and_whitespace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            missing = tmpdir / "missing.md"
            empty = tmpdir / "empty.md"
            whitespace = tmpdir / "whitespace.md"
            present = tmpdir / "present.md"
            empty.write_text("", encoding="utf-8")
            whitespace.write_text("  \n\t ", encoding="utf-8")
            present.write_text("content", encoding="utf-8")
            self.assertFalse(wrapper.ref_present(str(missing)))
            self.assertFalse(wrapper.ref_present(str(empty)))
            self.assertFalse(wrapper.ref_present(str(whitespace)))
            self.assertTrue(wrapper.ref_present(str(present)))


if __name__ == "__main__":
    unittest.main()
