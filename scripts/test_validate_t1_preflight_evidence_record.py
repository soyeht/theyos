#!/usr/bin/env python3
"""Tests for scripts/validate-t1-preflight-evidence-record.py."""

from __future__ import annotations

import importlib.util
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
        "audit_root": audit_root,
    }


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
            ("owner_authorization_ref", "<owner-authorization-record-ref>", "owner_authorization_ref must not be a template placeholder"),
            ("rollback_ref", " <prebuilt-rollback-artifact-ref> ", "rollback_ref must not be a template placeholder"),
            ("hardware_evidence_ref", "<sanitized-t1-t4-evidence-pack-ref>", "hardware_evidence_ref must not be a template placeholder"),
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


if __name__ == "__main__":
    unittest.main()
