#!/usr/bin/env python3
"""Tests for scripts/validate-t1-rollback-evidence.py."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("validate-t1-rollback-evidence.py")
SPEC = importlib.util.spec_from_file_location("validate_t1_rollback_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

ARTIFACT_SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_ARTIFACT_SHA = "fedcba9876543210fedcba9876543210fedcba98"


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


class ValidateT1RollbackEvidenceTests(unittest.TestCase):
    def assert_validation_error(self, markdown: str, expected_error: str) -> None:
        errors = validator.validate_rollback_evidence(markdown, ARTIFACT_SHA, expected_pr=286)
        self.assertIn(expected_error, errors)

    def test_valid_rollback_evidence_passes(self) -> None:
        self.assertEqual([], validator.validate_rollback_evidence(valid_rollback_evidence(), ARTIFACT_SHA, expected_pr=286))

    def test_rejects_wrong_sha_and_pr(self) -> None:
        self.assert_validation_error(
            valid_rollback_evidence().replace(ARTIFACT_SHA, OTHER_ARTIFACT_SHA),
            "rollback evidence must reference the expected artifact SHA",
        )
        self.assertIn(
            "rollback evidence must reference the expected PR",
            validator.validate_rollback_evidence(
                valid_rollback_evidence().replace("#286", "#285"),
                ARTIFACT_SHA,
                expected_pr=286,
            ),
        )

    def test_rejects_missing_scope_and_production_false(self) -> None:
        self.assert_validation_error(
            valid_rollback_evidence().replace("dev-host T1-T4 only", "production"),
            "scope must be dev-host T1-T4 only",
        )
        self.assert_validation_error(
            valid_rollback_evidence().replace("production_activation=false", "production_activation=true"),
            "production_activation must be false",
        )

    def test_rejects_unchecked_items_placeholders_private_paths_ips_and_secrets(self) -> None:
        cases = (
            ("- [ ] rollback artifact selected\n", "rollback evidence must not contain unchecked checklist items"),
            ("<prebuilt-rollback-artifact-ref>", "rollback evidence must not contain template placeholders"),
            (".".join(("172", "16", "0", "7")), "rollback evidence must use only documentation-safe IPv4 addresses"),
            ("/" + "Applications" + "/Soyeht.app", "rollback evidence must not contain local absolute paths"),
            ("password" + "=abc123", "rollback evidence must not contain secrets or key material"),
            ("-----" + "BE" + "GIN " + "PRIVATE KEY-----", "rollback evidence must not contain secrets or key material"),
        )
        for addition, expected_error in cases:
            with self.subTest(addition=addition):
                self.assert_validation_error(valid_rollback_evidence() + f"\n{addition}\n", expected_error)

    def test_allows_documentation_safe_ipv4_addresses(self) -> None:
        markdown = valid_rollback_evidence() + "\nExample documentation address: 198.18.0.1\n"
        self.assertEqual([], validator.validate_rollback_evidence(markdown, ARTIFACT_SHA, expected_pr=286))

    def test_rejects_missing_required_checked_items(self) -> None:
        self.assert_validation_error(
            valid_rollback_evidence().replace("- [x] Linux TUN cleanup procedure is ready.\n", ""),
            "rollback evidence must include checked item for Linux TUN cleanup",
        )
        self.assert_validation_error(
            valid_rollback_evidence().replace("- [x] Rollback does not rebuild locally after a failed run.\n", ""),
            "rollback evidence must include checked item for no local rebuild dependency",
        )
        self.assert_validation_error(
            valid_rollback_evidence().replace("- [x] Baseline health verification checklist is ready.\n", ""),
            "rollback evidence must include checked item for baseline health verification",
        )

    def test_cli_missing_record_error_does_not_echo_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing_record = Path(tmp) / "private-rollback-evidence.md"
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), ARTIFACT_SHA, str(missing_record), "--expected-pr", "286"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(2, proc.returncode)
            self.assertIn("ERROR: could not read rollback evidence: FileNotFoundError", proc.stderr)
            self.assertFalse(str(missing_record) in proc.stderr, "stderr leaked rollback evidence path")
            self.assertFalse(missing_record.name in proc.stderr, "stderr leaked rollback evidence file name")


if __name__ == "__main__":
    unittest.main()
