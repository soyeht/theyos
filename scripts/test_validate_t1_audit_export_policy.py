#!/usr/bin/env python3
"""Tests for scripts/validate-t1-audit-export-policy.py."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("validate-t1-audit-export-policy.py")
SPEC = importlib.util.spec_from_file_location("validate_t1_audit_export_policy", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

ARTIFACT_SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_ARTIFACT_SHA = "fedcba9876543210fedcba9876543210fedcba98"


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


class ValidateT1AuditExportPolicyTests(unittest.TestCase):
    def assert_validation_error(self, markdown: str, expected_error: str) -> None:
        errors = validator.validate_audit_export_policy(markdown, ARTIFACT_SHA, expected_pr=286)
        self.assertIn(expected_error, errors)

    def test_valid_audit_export_policy_passes(self) -> None:
        self.assertEqual(
            [],
            validator.validate_audit_export_policy(valid_audit_export_policy(), ARTIFACT_SHA, expected_pr=286),
        )

    def test_rejects_wrong_sha_and_pr(self) -> None:
        self.assert_validation_error(
            valid_audit_export_policy().replace(ARTIFACT_SHA, OTHER_ARTIFACT_SHA),
            "audit export policy must reference the expected artifact SHA",
        )
        self.assertIn(
            "audit export policy must reference the expected PR",
            validator.validate_audit_export_policy(
                valid_audit_export_policy().replace("#286", "#285"),
                ARTIFACT_SHA,
                expected_pr=286,
            ),
        )

    def test_rejects_missing_scope_and_production_false(self) -> None:
        self.assert_validation_error(
            valid_audit_export_policy().replace("dev-host T1-T4 only", "production"),
            "scope must be dev-host T1-T4 only",
        )
        self.assert_validation_error(
            valid_audit_export_policy().replace("production_activation=false", "production_activation=true"),
            "production_activation must be false",
        )

    def test_rejects_unchecked_items_placeholders_private_paths_ips_and_secrets(self) -> None:
        cases = (
            ("- [ ] export key rotation policy selected\n", "audit export policy must not contain unchecked checklist items"),
            ("<audit-export-key-source>", "audit export policy must not contain template placeholders"),
            (".".join(("172", "16", "0", "7")), "audit export policy must use only documentation-safe IPv4 addresses"),
            ("/" + "Applications" + "/Soyeht.app", "audit export policy must not contain local absolute paths"),
            ("export" + "_key" + "=abc123", "audit export policy must not contain secrets or key material"),
            ("-----" + "BE" + "GIN " + "PRIVATE KEY-----", "audit export policy must not contain secrets or key material"),
        )
        for addition, expected_error in cases:
            with self.subTest(addition=addition):
                self.assert_validation_error(valid_audit_export_policy() + f"\n{addition}\n", expected_error)

    def test_allows_documentation_safe_ipv4_addresses(self) -> None:
        markdown = valid_audit_export_policy() + "\nExample documentation address: 198.18.0.1\n"
        self.assertEqual([], validator.validate_audit_export_policy(markdown, ARTIFACT_SHA, expected_pr=286))

    def test_rejects_missing_required_checked_items(self) -> None:
        self.assert_validation_error(
            valid_audit_export_policy().replace(
                "- [x] Reviewed export key source is documented privately and contains no key bytes.\n",
                "",
            ),
            "audit export policy must include checked item for reviewed export key source",
        )
        self.assert_validation_error(
            valid_audit_export_policy().replace(
                "- [x] Export key rotation policy is defined before any off-host export.\n",
                "",
            ),
            "audit export policy must include checked item for export key rotation policy",
        )
        self.assert_validation_error(
            valid_audit_export_policy().replace(
                "- [x] Local pseudonymous hash values are omitted from off-host export.\n",
                "",
            ),
            "audit export policy must include checked item for local pseudonymous hash omission",
        )

    def test_cli_missing_policy_error_does_not_echo_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing_policy = Path(tmp) / "private-audit-export-policy.md"
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), ARTIFACT_SHA, str(missing_policy), "--expected-pr", "286"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(2, proc.returncode)
            self.assertIn("ERROR: could not read audit export policy: FileNotFoundError", proc.stderr)
            self.assertFalse(str(missing_policy) in proc.stderr, "stderr leaked audit export policy path")
            self.assertFalse(missing_policy.name in proc.stderr, "stderr leaked audit export policy file name")


if __name__ == "__main__":
    unittest.main()
