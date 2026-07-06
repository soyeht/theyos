#!/usr/bin/env python3
"""Tests for scripts/validate-t1-hardware-evidence-pack.py."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("validate-t1-hardware-evidence-pack.py")
SPEC = importlib.util.spec_from_file_location("validate_t1_hardware_evidence_pack", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

ARTIFACT_SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_ARTIFACT_SHA = "fedcba9876543210fedcba9876543210fedcba98"


def valid_pack() -> str:
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


class ValidateT1HardwareEvidencePackTests(unittest.TestCase):
    def assert_validation_error(self, markdown: str, expected_error: str) -> None:
        errors = validator.validate_pack(markdown, ARTIFACT_SHA, expected_pr=286)
        self.assertIn(expected_error, errors)

    def test_valid_pack_passes(self) -> None:
        self.assertEqual([], validator.validate_pack(valid_pack(), ARTIFACT_SHA, expected_pr=286))

    def test_rejects_wrong_sha_and_pr(self) -> None:
        self.assert_validation_error(
            valid_pack().replace(ARTIFACT_SHA, OTHER_ARTIFACT_SHA),
            "hardware evidence pack must reference the expected artifact SHA",
        )
        self.assertIn(
            "hardware evidence pack must reference the expected PR",
            validator.validate_pack(valid_pack().replace("#286", "#285"), ARTIFACT_SHA, expected_pr=286),
        )

    def test_rejects_missing_scope_and_production_false(self) -> None:
        self.assert_validation_error(
            valid_pack().replace("dev-host T1-T4 only", "production"),
            "scope must be dev-host T1-T4 only",
        )
        self.assert_validation_error(
            valid_pack().replace("production_activation=false", "production_activation=true"),
            "production_activation must be false",
        )

    def test_rejects_unchecked_items_and_placeholders(self) -> None:
        self.assert_validation_error(
            valid_pack().replace("- [x] T2 live validation", "- [ ] T2 live validation"),
            "hardware evidence pack must not contain unchecked checklist items",
        )
        self.assert_validation_error(
            valid_pack() + "\n- [x] Placeholder <hardware-evidence-ref>\n",
            "hardware evidence pack must not contain template placeholders",
        )

    def test_rejects_private_ips_paths_and_secret_assignments(self) -> None:
        cases = (
            (".".join(("192", "168", "1", "10")), "hardware evidence pack must use only documentation-safe IPv4 addresses"),
            ("/" + "Users" + "/person/private-log.txt", "hardware evidence pack must not contain local absolute paths"),
            (
                "/" + "Applications" + "/Soyeht.app",
                "hardware evidence pack must not contain local absolute paths",
            ),
            ("/" + "Applications", "hardware evidence pack must not contain local absolute paths"),
            ("/" + "etc" + "/hosts", "hardware evidence pack must not contain local absolute paths"),
            ("/" + "opt" + "/soyeht/log.txt", "hardware evidence pack must not contain local absolute paths"),
            ("token" + "=abc123", "hardware evidence pack must not contain secrets or key material"),
            ("-----" + "BE" + "GIN " + "PRIVATE KEY-----", "hardware evidence pack must not contain secrets or key material"),
        )
        for addition, expected_error in cases:
            with self.subTest(addition=addition):
                self.assert_validation_error(valid_pack() + f"\n{addition}\n", expected_error)

    def test_allows_documentation_safe_ipv4_addresses(self) -> None:
        markdown = valid_pack() + "\n- [x] Example route uses 192.0.2.10 and 198.18.0.1 only.\n"
        self.assertEqual([], validator.validate_pack(markdown, ARTIFACT_SHA, expected_pr=286))

    def test_rejects_missing_required_checked_items(self) -> None:
        self.assert_validation_error(
            valid_pack().replace("- [x] T4 rollback evidence captured.\n", ""),
            "hardware evidence pack must include checked item for T4 rollback",
        )
        self.assert_validation_error(
            valid_pack().replace("- [x] Reference content verification completed for owner, rollback, and hardware refs.\n", ""),
            "hardware evidence pack must include checked item for reference content verification",
        )
        self.assert_validation_error(
            valid_pack().replace("- [x] T1 interface evidence captured with before, during, and after snapshots.\n", ""),
            "hardware evidence pack must include checked item for T1 interface evidence",
        )

    def test_cli_missing_pack_error_does_not_echo_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing_pack = Path(tmp) / "private-hardware-evidence.md"
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), ARTIFACT_SHA, str(missing_pack), "--expected-pr", "286"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(2, proc.returncode)
            self.assertIn("ERROR: could not read hardware evidence pack: FileNotFoundError", proc.stderr)
            self.assertFalse(str(missing_pack) in proc.stderr, "stderr leaked pack path")
            self.assertFalse(missing_pack.name in proc.stderr, "stderr leaked pack file name")


if __name__ == "__main__":
    unittest.main()
