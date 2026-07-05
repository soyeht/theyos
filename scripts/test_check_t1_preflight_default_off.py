#!/usr/bin/env python3
"""Tests for scripts/check-t1-preflight-default-off.py."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-t1-preflight-default-off.py")
SPEC = importlib.util.spec_from_file_location("check_t1_preflight_default_off", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


class CheckT1PreflightDefaultOffTests(unittest.TestCase):
    def test_build_checks_pins_non_live_filters(self) -> None:
        checks = checker.build_checks(skip_python=False, skip_rust=False)
        self.assertEqual(
            [
                "prepare-helper-tests",
                "validator-tests",
                "source-guard",
                "mount-audit-sink",
                "mounted-t1-missing-preflight",
            ],
            [check.name for check in checks],
        )

        commands = [" ".join(check.command) for check in checks]
        self.assertIn("scripts/test_prepare_t1_preflight_evidence_record.py", commands[0])
        self.assertIn("scripts/test_validate_t1_preflight_evidence_record.py", commands[1])
        self.assertIn("product_a_per_claw_vpn_dev_config_remains_default_off_and_unwired", commands[2])
        self.assertIn("t1_mount_audit_sink", commands[3])
        self.assertIn("mounted_t1_iptunnel_router", commands[4])
        for command in commands:
            self.assertNotIn("run_until_stopped", command)
            self.assertNotIn("build_runtime", command)
            self.assertNotIn("Soyeht.app", command)

    def test_dry_run_prints_commands_without_running_subprocesses(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = checker.main(["--dry-run", "--skip-rust"])

        self.assertEqual(0, code)
        output = stdout.getvalue()
        self.assertIn("prepare-helper-tests", output)
        self.assertIn("validator-tests", output)
        self.assertIn("OK: T1 preflight/default-off check bundle passed", output)

    def test_no_checks_selected_fails(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = checker.main(["--skip-python", "--skip-rust"])

        self.assertEqual(2, code)
        self.assertIn("ERROR: no checks selected", stderr.getvalue())

    def test_timeout_fails_closed(self) -> None:
        check = checker.Check("slow-check", ("sleep", "999"), Path.cwd())

        def fake_run(*_args: object, **_kwargs: object) -> object:
            raise subprocess.TimeoutExpired(cmd=check.command, timeout=1)

        original_run = checker.subprocess.run
        checker.subprocess.run = fake_run
        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = checker.run_check(check, dry_run=False, timeout_seconds=1)
        finally:
            checker.subprocess.run = original_run

        self.assertEqual(124, code)
        self.assertIn("slow-check", stdout.getvalue())
        self.assertIn("ERROR: slow-check timed out after 1s", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
