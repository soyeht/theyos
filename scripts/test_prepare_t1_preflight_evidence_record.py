#!/usr/bin/env python3
"""Tests for scripts/prepare-t1-preflight-evidence-record.py."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("prepare-t1-preflight-evidence-record.py")
VALIDATOR_SCRIPT = Path(__file__).with_name("validate-t1-preflight-evidence-record.py")

PREPARE_SPEC = importlib.util.spec_from_file_location("prepare_t1_preflight_evidence_record", SCRIPT)
assert PREPARE_SPEC is not None and PREPARE_SPEC.loader is not None
prepare = importlib.util.module_from_spec(PREPARE_SPEC)
PREPARE_SPEC.loader.exec_module(prepare)

VALIDATOR_SPEC = importlib.util.spec_from_file_location("validate_t1_preflight_evidence_record", VALIDATOR_SCRIPT)
assert VALIDATOR_SPEC is not None and VALIDATOR_SPEC.loader is not None
validator = importlib.util.module_from_spec(VALIDATOR_SPEC)
VALIDATOR_SPEC.loader.exec_module(validator)

ARTIFACT_SHA = "0123456789abcdef0123456789abcdef01234567"


class PrepareT1PreflightEvidenceRecordTests(unittest.TestCase):
    def run_prepare(self, *extra_args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), ARTIFACT_SHA, *extra_args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def read_record(self, path: Path) -> dict[str, object]:
        with path.open("r", encoding="utf-8") as handle:
            record = json.load(handle)
        self.assertIsInstance(record, dict)
        return record

    def test_creates_private_draft_without_fabricating_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            record_path = tmpdir / "private-evidence.json"
            audit_root = tmpdir / "audit-root"

            proc = self.run_prepare("--record", str(record_path), "--audit-root", str(audit_root))

            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertIn("OK: private T1 preflight evidence draft updated", proc.stdout)
            self.assertIn("INFO: record remains incomplete until all private refs are supplied", proc.stdout)

            record = self.read_record(record_path)
            self.assertEqual(ARTIFACT_SHA, record["artifact_sha"])
            self.assertEqual(prepare.SCHEMA, record["schema"])
            self.assertEqual(prepare.SCOPE, record["scope"])
            self.assertIs(record["production_activation"], False)
            self.assertIs(record["owner_authorization"], False)
            self.assertIs(record["rollback"], False)
            self.assertIs(record["hardware_t1_t4"], False)
            self.assertEqual("", record["owner_authorization_ref"])
            self.assertEqual("", record["rollback_ref"])
            self.assertEqual("", record["hardware_evidence_ref"])
            self.assertEqual(os.path.realpath(audit_root), record["audit_root"])
            self.assertEqual(0o600, stat.S_IMODE(os.lstat(record_path).st_mode))
            self.assertEqual(0o700, stat.S_IMODE(os.lstat(audit_root).st_mode))
            self.assertEqual([], list(tmpdir.glob(".private-evidence.json.tmp-*")))

    def test_complete_private_refs_validate_with_root_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            record_path = tmpdir / "private-evidence.json"
            audit_root = tmpdir / "audit-root"

            proc = self.run_prepare(
                "--record",
                str(record_path),
                "--audit-root",
                str(audit_root),
                "--owner-ref",
                "owner-review-ref",
                "--rollback-ref",
                "rollback-artifact-ref",
                "--hardware-ref",
                "hardware-evidence-ref",
            )

            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertNotIn("record remains incomplete", proc.stdout)
            self.assertIn(
                "INFO: refs are present, but activation still must verify their reviewed contents",
                proc.stdout,
            )
            record = self.read_record(record_path)
            self.assertEqual([], validator.validate_record(record, ARTIFACT_SHA, check_root_dir=True))

    def test_preserves_real_existing_refs_but_discards_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            record_path = tmpdir / "private-evidence.json"
            audit_root = tmpdir / "audit-root"
            record_path.write_text(
                json.dumps(
                    {
                        "owner_authorization_ref": "owner-review-ref",
                        "rollback_ref": "<prebuilt-rollback-artifact-ref>",
                        "hardware_evidence_ref": "hardware-evidence-ref",
                    }
                ),
                encoding="utf-8",
            )

            proc = self.run_prepare("--record", str(record_path), "--audit-root", str(audit_root))

            self.assertEqual(0, proc.returncode, proc.stderr)
            record = self.read_record(record_path)
            self.assertIs(record["owner_authorization"], True)
            self.assertIs(record["rollback"], False)
            self.assertIs(record["hardware_t1_t4"], True)
            self.assertEqual("owner-review-ref", record["owner_authorization_ref"])
            self.assertEqual("", record["rollback_ref"])
            self.assertEqual("hardware-evidence-ref", record["hardware_evidence_ref"])

    def test_cli_does_not_echo_private_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            record_path = tmpdir / "private-evidence.json"
            audit_root = tmpdir / "audit-root"
            private_values = (
                str(record_path),
                str(audit_root),
                "owner-private-ref",
                "rollback-private-ref",
                "hardware-private-ref",
            )

            proc = self.run_prepare(
                "--record",
                private_values[0],
                "--audit-root",
                private_values[1],
                "--owner-ref",
                private_values[2],
                "--rollback-ref",
                private_values[3],
                "--hardware-ref",
                private_values[4],
            )

            self.assertEqual(0, proc.returncode, proc.stderr)
            combined_output = proc.stdout + proc.stderr
            for private_value in private_values:
                self.assertNotIn(private_value, combined_output)

    def test_invalid_artifact_sha_fails_before_writing_private_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            record_dir = tmpdir / "private-records"
            record_path = record_dir / "private-evidence.json"
            audit_root = tmpdir / "audit-root"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "not-a-sha",
                    "--record",
                    str(record_path),
                    "--audit-root",
                    str(audit_root),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(1, proc.returncode)
            self.assertEqual("", proc.stdout)
            self.assertIn("ERROR: artifact_sha must be 40 hex characters", proc.stderr)
            self.assertFalse(record_dir.exists())
            self.assertFalse(record_path.exists())
            self.assertFalse(audit_root.exists())
            self.assertNotIn(str(record_path), proc.stderr)
            self.assertNotIn(str(audit_root), proc.stderr)

    def test_restricts_existing_record_before_atomic_replace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            record_path = tmpdir / "private-evidence.json"
            audit_root = tmpdir / "audit-root"
            record_path.write_text("stale", encoding="utf-8")
            os.chmod(record_path, 0o644)

            proc = self.run_prepare("--record", str(record_path), "--audit-root", str(audit_root))

            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertEqual(0o600, stat.S_IMODE(os.lstat(record_path).st_mode))
            self.assertEqual([], list(tmpdir.glob(".private-evidence.json.tmp-*")))

    def test_creates_private_record_parent_directory_with_restricted_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            record_dir = tmpdir / "private-records"
            record_path = record_dir / "private-evidence.json"
            audit_root = tmpdir / "audit-root"

            proc = self.run_prepare("--record", str(record_path), "--audit-root", str(audit_root))

            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertTrue(record_path.exists())
            self.assertEqual(0o700, stat.S_IMODE(os.lstat(record_dir).st_mode))
            self.assertEqual(0o600, stat.S_IMODE(os.lstat(record_path).st_mode))

    def test_preserves_existing_private_record_parent_directory_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            record_dir = tmpdir / "private-records"
            record_dir.mkdir(mode=0o755)
            os.chmod(record_dir, 0o755)
            record_path = record_dir / "private-evidence.json"
            audit_root = tmpdir / "audit-root"

            proc = self.run_prepare("--record", str(record_path), "--audit-root", str(audit_root))

            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertEqual(0o755, stat.S_IMODE(os.lstat(record_dir).st_mode))
            self.assertEqual(0o600, stat.S_IMODE(os.lstat(record_path).st_mode))

    def test_default_record_does_not_chmod_existing_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            os.chmod(tmpdir, 0o755)
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), ARTIFACT_SHA],
                check=False,
                cwd=tmpdir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertEqual(0o755, stat.S_IMODE(os.lstat(tmpdir).st_mode))
            self.assertEqual(0o600, stat.S_IMODE(os.lstat(tmpdir / prepare.DEFAULT_RECORD).st_mode))


if __name__ == "__main__":
    unittest.main()
