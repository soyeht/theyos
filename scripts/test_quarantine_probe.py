#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import tempfile
import unittest
from unittest import mock
import os
from pathlib import Path

from quarantine_probe import (
    ProbeConfig,
    cargo_test_command,
    classify_cargo_output,
    run_probe,
)


TEST_NAME = "crate::tests::quarantined_test"


def cargo_output(
    *, count: int, status: str | None = None, duration_s: str | None = None
) -> str:
    lines = [f"running {count} test" + ("s" if count != 1 else "")]
    if status is not None:
        lines.append(f"test {TEST_NAME} ... {status}")
    if duration_s is not None:
        summary_status = "FAILED" if status == "FAILED" else "ok"
        passed = "1" if status == "ok" else "0"
        failed = "1" if status == "FAILED" else "0"
        lines.append(
            f"test result: {summary_status}. {passed} passed; {failed} failed; "
            f"finished in {duration_s}s"
        )
    return "\n".join(lines) + "\n"


class QuarantineProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        environment = mock.patch.dict(
            os.environ,
            {"RUNNER_OS": "fixture-os", "GITHUB_JOB": "fixture-job"},
        )
        environment.start()
        self.addCleanup(environment.stop)

    def test_cargo_command_selects_library_target_by_default(self) -> None:
        config = ProbeConfig("999", 1, "fixture", TEST_NAME, Path("workspace"))
        self.assertEqual(
            cargo_test_command(config),
            (
                "cargo",
                "test",
                "--locked",
                "-p",
                "fixture",
                "--lib",
                "--",
                "--ignored",
                "--exact",
                TEST_NAME,
                "--test-threads=1",
            ),
        )

    def test_cargo_command_selects_named_integration_test_target(self) -> None:
        config = ProbeConfig(
            "470",
            5,
            "e2e-rs",
            TEST_NAME,
            Path("workspace"),
            test_target="phase3_observability_audit",
            require_pass=True,
        )
        self.assertEqual(
            cargo_test_command(config),
            (
                "cargo",
                "test",
                "--locked",
                "-p",
                "e2e-rs",
                "--test",
                "phase3_observability_audit",
                "--",
                "--ignored",
                "--exact",
                TEST_NAME,
                "--test-threads=1",
            ),
        )

    def test_zero_selected_is_invalid_even_when_cargo_returns_zero(self) -> None:
        observation = classify_cargo_output(
            cargo_output(count=0, duration_s="0.37"), 0, TEST_NAME
        )
        self.assertEqual(observation.result, "INVALID")
        self.assertEqual(observation.selected, 0)
        self.assertEqual(observation.duration_s, "0.37")

    def test_valid_pass_requires_one_exact_result_and_zero_returncode(self) -> None:
        observation = classify_cargo_output(
            cargo_output(count=1, status="ok", duration_s="0.37"), 0, TEST_NAME
        )
        self.assertEqual(observation.result, "PASS")
        self.assertEqual(observation.selected, 1)
        self.assertEqual(observation.duration_s, "0.37")

    def test_valid_failure_preserves_cargo_duration(self) -> None:
        observation = classify_cargo_output(
            cargo_output(count=1, status="FAILED", duration_s="0.41"),
            101,
            TEST_NAME,
        )
        self.assertEqual(observation.result, "FAIL")
        self.assertEqual(observation.duration_s, "0.41")

    def test_missing_duration_does_not_change_classification(self) -> None:
        observation = classify_cargo_output(
            cargo_output(count=1, status="ok"), 0, TEST_NAME
        )
        self.assertEqual(observation.result, "PASS")
        self.assertEqual(observation.duration_s, "unknown")

    def test_ambiguous_duration_is_unknown(self) -> None:
        output = cargo_output(count=1, status="ok", duration_s="0.37")
        output += "test result: ok. 1 passed; 0 failed; finished in 0.38s\n"
        observation = classify_cargo_output(output, 0, TEST_NAME)
        self.assertEqual(observation.result, "PASS")
        self.assertEqual(observation.duration_s, "unknown")

    def test_summary_counts_known_and_unknown_durations(self) -> None:
        runner = mock.Mock(
            side_effect=[
                subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=cargo_output(count=1, status="ok", duration_s="0.37"),
                ),
                subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=cargo_output(count=1, status="ok"),
                ),
            ]
        )

        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary"
            rc = run_probe(
                ProbeConfig("999", 2, "fixture", TEST_NAME, Path(directory)),
                runner=runner,
                summary=summary,
            )
            self.assertEqual(rc, 0)
            self.assertIn(
                "duration_known=1 duration_unknown=1",
                summary.read_text(encoding="utf-8"),
            )

    def test_harness_observes_deliberate_failure_without_becoming_a_gate(self) -> None:
        def failing_runner(*_args, **_kwargs):
            return subprocess.CompletedProcess(
                args=[],
                returncode=101,
                stdout=cargo_output(count=1, status="FAILED", duration_s="0.41"),
            )

        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary"
            rc = run_probe(
                ProbeConfig("999", 1, "fixture", TEST_NAME, Path(directory)),
                runner=failing_runner,
                summary=summary,
            )
            self.assertEqual(rc, 0)
            self.assertIn(
                "PROBE_999 os=fixture-os job=fixture-job "
                "attempt=1 selected=1 result=FAIL rc=101 duration_s=0.41",
                summary.read_text(encoding="utf-8"),
            )
            self.assertIn(
                "PROBE_999 os=fixture-os job=fixture-job "
                "attempts=1 passes=0 failures=1 invalid=0 "
                "duration_known=1 duration_unknown=0",
                summary.read_text(encoding="utf-8"),
            )

    def test_required_policy_fails_when_all_valid_attempts_fail(self) -> None:
        runner = mock.Mock(
            return_value=subprocess.CompletedProcess(
                args=[],
                returncode=101,
                stdout=cargo_output(count=1, status="FAILED", duration_s="0.41"),
            )
        )

        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary"
            rc = run_probe(
                ProbeConfig(
                    "470",
                    2,
                    "fixture",
                    TEST_NAME,
                    Path(directory),
                    require_pass=True,
                ),
                runner=runner,
                summary=summary,
            )
            self.assertEqual(rc, 1)
            self.assertIn(
                "attempts=2 passes=0 failures=2 invalid=0",
                summary.read_text(encoding="utf-8"),
            )

    def test_required_policy_passes_after_one_valid_pass(self) -> None:
        runner = mock.Mock(
            side_effect=[
                subprocess.CompletedProcess(
                    args=[],
                    returncode=101,
                    stdout=cargo_output(count=1, status="FAILED", duration_s="0.41"),
                ),
                subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=cargo_output(count=1, status="ok", duration_s="0.37"),
                ),
            ]
        )

        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary"
            rc = run_probe(
                ProbeConfig(
                    "470",
                    2,
                    "fixture",
                    TEST_NAME,
                    Path(directory),
                    require_pass=True,
                ),
                runner=runner,
                summary=summary,
            )
            self.assertEqual(rc, 0)
            self.assertIn(
                "attempts=2 passes=1 failures=1 invalid=0",
                summary.read_text(encoding="utf-8"),
            )

    def test_invalid_instrument_overrides_a_valid_required_pass(self) -> None:
        runner = mock.Mock(
            side_effect=[
                subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=cargo_output(count=1, status="ok", duration_s="0.37"),
                ),
                subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=cargo_output(count=0, duration_s="0.00"),
                ),
            ]
        )

        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary"
            rc = run_probe(
                ProbeConfig(
                    "470",
                    2,
                    "fixture",
                    TEST_NAME,
                    Path(directory),
                    require_pass=True,
                ),
                runner=runner,
                summary=summary,
            )
            self.assertEqual(rc, 2)
            self.assertIn(
                "attempts=2 passes=1 failures=0 invalid=1",
                summary.read_text(encoding="utf-8"),
            )

    def test_harness_rejects_vacuous_success(self) -> None:
        def empty_runner(*_args, **_kwargs):
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout=cargo_output(count=0)
            )

        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary"
            rc = run_probe(
                ProbeConfig(
                    "999",
                    1,
                    "fixture",
                    TEST_NAME,
                    Path(directory),
                    require_pass=True,
                ),
                runner=empty_runner,
                summary=summary,
            )
            self.assertEqual(rc, 2)
            self.assertIn("invalid=1", summary.read_text(encoding="utf-8"))

    def test_build_error_is_invalid_not_a_test_failure(self) -> None:
        observation = classify_cargo_output("error: could not compile\n", 101, TEST_NAME)
        self.assertEqual(observation.result, "INVALID")

    def test_timeout_is_invalid_not_a_test_failure(self) -> None:
        def timeout_runner(*_args, **_kwargs):
            raise subprocess.TimeoutExpired(
                cmd="cargo",
                timeout=1,
                output=cargo_output(count=1, status="FAILED", duration_s="0.41"),
            )

        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary"
            rc = run_probe(
                ProbeConfig("999", 1, "fixture", TEST_NAME, Path(directory), 1),
                runner=timeout_runner,
                summary=summary,
            )
            self.assertEqual(rc, 2)
            self.assertIn("invalid=1", summary.read_text(encoding="utf-8"))
            self.assertIn("duration_s=unknown", summary.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
