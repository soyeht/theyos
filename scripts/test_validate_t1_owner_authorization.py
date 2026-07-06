#!/usr/bin/env python3
"""Tests for scripts/validate-t1-owner-authorization.py."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("validate-t1-owner-authorization.py")
SPEC = importlib.util.spec_from_file_location("validate_t1_owner_authorization", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

ARTIFACT_SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_ARTIFACT_SHA = "fedcba9876543210fedcba9876543210fedcba98"


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


class ValidateT1OwnerAuthorizationTests(unittest.TestCase):
    def assert_validation_error(self, markdown: str, expected_error: str) -> None:
        errors = validator.validate_owner_authorization(markdown, ARTIFACT_SHA, expected_pr=286)
        self.assertIn(expected_error, errors)

    def test_valid_owner_authorization_passes(self) -> None:
        self.assertEqual([], validator.validate_owner_authorization(valid_owner_authorization(), ARTIFACT_SHA, expected_pr=286))

    def test_rejects_wrong_sha_and_pr(self) -> None:
        self.assert_validation_error(
            valid_owner_authorization().replace(ARTIFACT_SHA, OTHER_ARTIFACT_SHA),
            "owner authorization must reference the expected artifact SHA",
        )
        self.assertIn(
            "owner authorization must reference the expected PR",
            validator.validate_owner_authorization(
                valid_owner_authorization().replace("#286", "#285"),
                ARTIFACT_SHA,
                expected_pr=286,
            ),
        )

    def test_rejects_missing_scope_production_false_and_owner_sentence(self) -> None:
        self.assert_validation_error(
            valid_owner_authorization().replace("dev-host T1-T4 only", "production"),
            "scope must be dev-host T1-T4 only",
        )
        self.assert_validation_error(
            valid_owner_authorization().replace("production_activation=false", "production_activation=true"),
            "production_activation must be false",
        )
        self.assert_validation_error(
            valid_owner_authorization().replace("I do not authorize production activation.", "production use is allowed."),
            "owner authorization must include the required owner sentence",
        )

    def test_rejects_missing_required_fields(self) -> None:
        self.assert_validation_error(
            valid_owner_authorization().replace("| Stop authority | Any reviewer or operator may stop the run immediately |\n", ""),
            "owner authorization must include stop authority",
        )
        self.assert_validation_error(
            valid_owner_authorization().replace("| Rollback artifact | rollback-alpha reviewed for this exact artifact |\n", ""),
            "owner authorization must include rollback artifact",
        )
        self.assert_validation_error(
            valid_owner_authorization().replace("uses neutral aliases and redacts raw local details", "is unspecified"),
            "owner authorization must include data policy",
        )

    def test_rejects_unchecked_items_placeholders_private_paths_ips_and_secrets(self) -> None:
        cases = (
            ("- [ ] owner approval pending\n", "owner authorization must not contain unchecked checklist items"),
            ("<owner-authorization-ref>", "owner authorization must not contain template placeholders"),
            (".".join(("10", "0", "0", "5")), "owner authorization must use only documentation-safe IPv4 addresses"),
            ("/" + "Applications" + "/Soyeht.app", "owner authorization must not contain local absolute paths"),
            ("api_key" + "=abc123", "owner authorization must not contain secrets or key material"),
            ("-----" + "BE" + "GIN " + "PRIVATE KEY-----", "owner authorization must not contain secrets or key material"),
        )
        for addition, expected_error in cases:
            with self.subTest(addition=addition):
                self.assert_validation_error(valid_owner_authorization() + f"\n{addition}\n", expected_error)

    def test_allows_documentation_safe_ipv4_addresses(self) -> None:
        markdown = valid_owner_authorization() + "\nExample documentation address: 192.0.2.10\n"
        self.assertEqual([], validator.validate_owner_authorization(markdown, ARTIFACT_SHA, expected_pr=286))

    def test_cli_missing_record_error_does_not_echo_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing_record = Path(tmp) / "private-owner-authorization.md"
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), ARTIFACT_SHA, str(missing_record), "--expected-pr", "286"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(2, proc.returncode)
            self.assertIn("ERROR: could not read owner authorization: FileNotFoundError", proc.stderr)
            self.assertFalse(str(missing_record) in proc.stderr, "stderr leaked owner authorization path")
            self.assertFalse(missing_record.name in proc.stderr, "stderr leaked owner authorization file name")


if __name__ == "__main__":
    unittest.main()
