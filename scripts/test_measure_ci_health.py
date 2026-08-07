#!/usr/bin/env python3
"""Self-tests for scripts/measure-ci-health.py — the pure logic only.

The API-touching paths are exercised by live measurement; everything a wrong
implementation could get wrong WITHOUT network (counts, buckets, the ladder,
attempt selection, classing, reconciliation) is pinned here on synthetic data.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("measure-ci-health.py")
spec = importlib.util.spec_from_file_location("measure_ci_health", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def job(job_id, name, attempt=1, conclusion="success", workflow=".github/workflows/backend-ci.yml",
        started="2026-08-07T10:00:00Z", completed="2026-08-07T10:40:00Z", steps=None):
    return {
        "id": job_id,
        "name": name,
        "run_attempt": attempt,
        "conclusion": conclusion,
        "started_at": started,
        "completed_at": completed,
        "steps": steps or [
            {"name": "only", "started_at": started, "completed_at": completed},
        ],
        "_workflow_path": workflow,
        "_run_id": 1,
    }


class LadderTests(unittest.TestCase):
    def test_zero_attempts_measures_nothing(self):
        self.assertIsNone(gate.ci_upper_bound(0, 0))
        self.assertIsNone(gate.ladder_rung(0))

    def test_bound_is_three_over_n_at_zero_failures(self):
        self.assertAlmostEqual(0.05, gate.ci_upper_bound(60, 0), places=6)

    def test_bound_grows_with_failures(self):
        self.assertAlmostEqual(0.05, gate.ci_upper_bound(100, 2), places=6)

    def test_rungs_are_a_staircase_not_a_dial(self):
        self.assertIsNone(gate.ladder_rung(59))
        self.assertEqual((60, 0.05), gate.ladder_rung(60))
        self.assertEqual((60, 0.05), gate.ladder_rung(149))
        self.assertEqual((150, 0.02), gate.ladder_rung(150))
        self.assertEqual((300, 0.01), gate.ladder_rung(300))
        self.assertEqual((300, 0.01), gate.ladder_rung(10_000))


class CountingTests(unittest.TestCase):
    def test_same_name_different_id_is_two_jobs(self):
        # The shim and the real build publish identical names; counting by name
        # double-counts a PR and halves the flake rate's meaning.
        jobs = [
            job(11, "Build & Test (Rust / Linux)"),
            job(12, "Build & Test (Rust / Linux)", workflow=".github/workflows/backend-ci-docs-shim.yml"),
        ]
        self.assertEqual(2, len(gate.dedup_jobs_by_id(jobs)))

    def test_duplicate_id_is_one_job(self):
        jobs = [job(11, "x"), job(11, "x")]
        self.assertEqual(1, len(gate.dedup_jobs_by_id(jobs)))


class AttemptSelectionTests(unittest.TestCase):
    def test_cancelled_attempt_never_closes(self):
        attempts = [job(1, "ctx", attempt=1, conclusion="cancelled")]
        self.assertIsNone(gate.last_closed_attempt(attempts))

    def test_last_closed_attempt_wins_over_earlier_green(self):
        # Rerun-to-green must WORSEN the latency metric and stay visible in the
        # failure count: the signal is the LAST closed attempt, not the best.
        attempts = [
            job(1, "ctx", attempt=1, conclusion="failure"),
            job(2, "ctx", attempt=2, conclusion="success"),
        ]
        self.assertEqual(2, gate.last_closed_attempt(attempts)["run_attempt"])

    def test_later_cancelled_does_not_shadow_closed(self):
        attempts = [
            job(1, "ctx", attempt=1, conclusion="failure"),
            job(2, "ctx", attempt=2, conclusion="cancelled"),
        ]
        self.assertEqual(1, gate.last_closed_attempt(attempts)["run_attempt"])

    def test_attempt_number_ties_break_on_completion_time(self):
        # Two DIFFERENT runs of one head both number their attempts from 1; the
        # last to close is what decided.
        attempts = [
            job(1, "ctx", attempt=1, completed="2026-08-07T10:40:00Z"),
            job(2, "ctx", attempt=1, completed="2026-08-07T11:40:00Z"),
        ]
        self.assertEqual(2, gate.last_closed_attempt(attempts)["id"])

    def test_shim_never_decides_over_a_real_build(self):
        # Same context name, one shim (green, 3s) and one real (red, 45min):
        # the real decides. Letting the shim win is the measured lie I13.
        jobs = [
            job(1, "ctx", conclusion="success",
                workflow=".github/workflows/backend-ci-docs-shim.yml"),
            job(2, "ctx", conclusion="failure"),
        ]
        self.assertEqual(2, gate.decisive_attempt(jobs, "ctx")["id"])

    def test_shim_decides_when_no_real_build_ran(self):
        jobs = [
            job(1, "ctx", conclusion="success",
                workflow=".github/workflows/backend-ci-docs-shim.yml"),
        ]
        self.assertEqual(1, gate.decisive_attempt(jobs, "ctx")["id"])


class ClassingTests(unittest.TestCase):
    def test_real_backend_run_is_code(self):
        jobs = gate.dedup_jobs_by_id([job(1, "Build & Test (Rust / Linux)")])
        self.assertEqual("code", gate.classify_pr(jobs))

    def test_shim_only_is_docs_only(self):
        jobs = gate.dedup_jobs_by_id(
            [job(1, "Build & Test (Rust / Linux)", workflow=".github/workflows/backend-ci-docs-shim.yml")]
        )
        self.assertEqual("docs-only", gate.classify_pr(jobs))

    def test_identity_is_workflow_path_not_job_name(self):
        # Same name, real path -> code. The name is precisely what cannot be
        # trusted here.
        jobs = gate.dedup_jobs_by_id([job(1, "anything at all")])
        self.assertEqual("code", gate.classify_pr(jobs))


class ExclusionTests(unittest.TestCase):
    def test_injection_and_probe_branches_are_excluded(self):
        self.assertTrue(gate.is_excluded_branch("zz-inj-i2-ports"))
        self.assertTrue(gate.is_excluded_branch("zz-probe-2026-08-07"))

    def test_normal_branches_are_not(self):
        self.assertFalse(gate.is_excluded_branch("fix/anything"))
        self.assertFalse(gate.is_excluded_branch("main"))
        self.assertFalse(gate.is_excluded_branch(None))
        self.assertFalse(gate.is_excluded_branch(""))


class HonestyTests(unittest.TestCase):
    """A rate with unbucked failures must not read as a clean rate."""

    def _result(self, unclassified: bool) -> dict:
        return {
            "repo": "x/y",
            "window_run_count": 1,
            "job_count_exact_by_id": 4,
            "required_attempts": 200,
            "required_attempts_rated": 200,
            "required_attempts_shim": 0,
            "required_failures": 2,
            "failure_buckets": {"unclassified": 2} if unclassified else {"flake": 2},
            "unclassified_failures": (
                [{"job_id": 1, "run_id": 1, "attempt": 1, "name": "n", "head_branch": "b"}] * 2
                if unclassified
                else []
            ),
            "flake_rate_observed": 0.0 if unclassified else 0.01,
            "flake_rate_ci_upper_95": 0.025,
            "certifiable_rung": None if unclassified else {"n": 150, "claim_lt": 0.02},
            "heads": [],
            "p50_decisive_signal_minutes_by_class": {},
            "p50_runner_minutes_per_pr_by_class": {},
            "divergence_green_pr_red_main": [],
            "ungated_main_runs": [],
            "runs": [],
        }

    def test_unclassified_failures_block_certification(self):
        out = gate.render(self._result(unclassified=True))
        self.assertIn("NOT certifiable", out)
        self.assertNotIn("certifiable: <", out)

    def test_all_classified_allows_the_rung(self):
        out = gate.render(self._result(unclassified=False))
        self.assertIn("certifiable: <2%", out)


class ReconciliationTests(unittest.TestCase):
    def test_method_a_and_b_agree_on_gapless_steps(self):
        jobs = gate.dedup_jobs_by_id([job(1, "x")])
        rec = gate.reconcile_run(jobs)
        self.assertEqual(1, rec["jobs_timed"])
        self.assertEqual(2400.0, rec["method_b_job_wall_seconds"])
        self.assertEqual(2400.0, rec["method_a_step_sum_seconds"])
        self.assertEqual(0.0, rec["delta_seconds"])

    def test_gaps_between_steps_show_up_as_delta(self):
        steps = [
            {"name": "one", "started_at": "2026-08-07T10:00:00Z", "completed_at": "2026-08-07T10:10:00Z"},
            {"name": "two", "started_at": "2026-08-07T10:20:00Z", "completed_at": "2026-08-07T10:30:00Z"},
        ]
        jobs = gate.dedup_jobs_by_id([job(1, "x", steps=steps)])
        rec = gate.reconcile_run(jobs)
        self.assertEqual(1200.0, rec["method_a_step_sum_seconds"])
        self.assertEqual(2400.0, rec["method_b_job_wall_seconds"])
        self.assertEqual(1200.0, rec["delta_seconds"])

    def test_missing_timestamps_are_not_timed(self):
        jobs = gate.dedup_jobs_by_id([job(1, "x", completed=None)])
        rec = gate.reconcile_run(jobs)
        self.assertEqual(0, rec["jobs_timed"])


if __name__ == "__main__":
    unittest.main()
