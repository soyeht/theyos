#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import tempfile
import unittest
from unittest import mock
import os
from pathlib import Path

from quarantine_probe import ProbeConfig, classify_cargo_output, run_probe


TEST_NAME = "crate::tests::quarantined_test"


def cargo_output(
    *, count: int, status: str | None = None, duration_s: str | None = None
) -> str:
    lines = [f"running {count} test" + ("s" if count != 1 else "")]
    if status is not None:
        lines.append(f"test {TEST_NAME} ... {status}")
    if duration_s is not None:
        summary_status = "ok" if status == "ok" else "FAILED"
        passed, failed = ("1", "0") if status == "ok" else ("0", "1")
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

    def test_zero_selected_is_invalid_even_when_cargo_returns_zero(self) -> None:
        observation = classify_cargo_output(cargo_output(count=0), 0, TEST_NAME)
        self.assertEqual(observation.result, "INVALID")
        self.assertEqual(observation.selected, 0)

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

    def test_harness_rejects_vacuous_success(self) -> None:
        def empty_runner(*_args, **_kwargs):
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout=cargo_output(count=0)
            )

        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary"
            rc = run_probe(
                ProbeConfig("999", 1, "fixture", TEST_NAME, Path(directory)),
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
