#!/usr/bin/env python3
"""Tests for scripts/check-chronic-reds.py.

The negative tests are the point -- the plan (3.5) calls the notification the
most dangerous step, and a gate that silently stops paging is worse than none.
The decision logic (classify) is exercised here with fixed clocks and in-memory
inputs, asserting exactly the contract:

  * orphan red, no open issue -> CREATE action with assignee + a deadline that
    is now+sla (i.e. the page is sent immediately, well inside 24h);
  * orphan red, open issue last pinged <sla ago -> NO action (do not spam);
  * orphan red, open issue last pinged >=sla ago -> RE-PING action;
  * orphan issue whose check went green -> CLOSE action;
  * red matched by a declaration before its expiry -> DECLARED, no action;
  * red matched by a declaration past its expiry -> EXPIRED finding;
  * matrix contexts collapse to one declaration via prefix matching;
  * distinct orphans each get their own CREATE (dedup is per-check).
"""

from __future__ import annotations

import importlib.util
from io import StringIO
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("check-chronic-reds.py")
SPEC = importlib.util.spec_from_file_location("check_chronic_reds", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)

NOW = datetime(2026, 8, 7, 12, 0, tzinfo=timezone.utc)
SLA = timedelta(hours=24)
ONCALL = "caiosalgado"


def declared(check: str, owner: str = ONCALL, expires_days: int = 2, issue: int | None = None):
    return gate.Declared(
        check=check,
        owner=owner,
        expires=NOW + timedelta(days=expires_days),
        issue=issue,
        reason="",
    )


def expired_decl(check: str):
    return gate.Declared(check=check, owner=ONCALL, expires=NOW - timedelta(days=1), issue=None, reason="")


def issue(number: int, ctx: str, last_ping_days_ago: float | None, created_days_ago: float = 5):
    return gate.OrphanIssue(
        number=number,
        context=ctx,
        created_at=NOW - timedelta(days=created_days_ago),
        last_ping=(NOW - timedelta(days=last_ping_days_ago) if last_ping_days_ago is not None else None),
    )


def observation(status: str, conclusion: str | None = None):
    return gate.CheckObservation(status=status, conclusion=conclusion)


def failures(*contexts: str):
    return {context: observation("completed", "failure") for context in contexts}


class ClassifyTests(unittest.TestCase):
    def test_orphan_with_no_issue_creates_with_assignee_and_deadline(self):
        c = gate.classify(failures("Foo Check"), [], [], NOW, ONCALL, SLA)
        self.assertEqual(c.orphans, ["Foo Check"])
        creates = [a for a in c.actions if a.kind == "create"]
        self.assertEqual(len(creates), 1)
        a = creates[0]
        self.assertEqual(a.context, "Foo Check")
        self.assertEqual(a.assignee, ONCALL)
        # deadline is now+sla -> the page goes out immediately (<<24h)
        self.assertEqual(a.deadline, NOW + SLA)

    def test_orphan_recently_pinged_is_not_re_pinged(self):
        oi = issue(7, "Foo Check", last_ping_days_ago=0.5)  # 12h < sla
        c = gate.classify(failures("Foo Check"), [], [oi], NOW, ONCALL, SLA)
        self.assertEqual(c.orphans, ["Foo Check"])
        self.assertEqual([a.kind for a in c.actions], [])  # no create, no reping

    def test_orphan_pinged_over_sla_is_re_pinged(self):
        oi = issue(7, "Foo Check", last_ping_days_ago=2)  # >=sla (48h)
        c = gate.classify(failures("Foo Check"), [], [oi], NOW, ONCALL, SLA)
        repings = [a for a in c.actions if a.kind == "reping"]
        self.assertEqual(len(repings), 1)
        self.assertEqual(repings[0].number, 7)
        self.assertEqual([a.kind for a in c.actions if a.kind == "create"], [])

    def test_orphan_issue_with_no_ping_uses_creation_as_the_clock(self):
        # last_ping None -> the create was the first page; sla counts from there.
        oi = issue(7, "Foo Check", last_ping_days_ago=None, created_days_ago=3)  # >sla since create
        c = gate.classify(failures("Foo Check"), [], [oi], NOW, ONCALL, SLA)
        self.assertEqual([a.kind for a in c.actions], ["reping"])

    def test_green_check_closes_its_orphan_issue(self):
        oi = issue(7, "Foo Check", last_ping_days_ago=1)
        c = gate.classify(
            {"Foo Check": observation("completed", "success")}, [], [oi], NOW, ONCALL, SLA
        )
        closes = [a for a in c.actions if a.kind == "close"]
        self.assertEqual(len(closes), 1)
        self.assertEqual(closes[0].number, 7)

    def test_queued_in_progress_and_absent_observations_never_close(self):
        oi = issue(7, "Foo Check", last_ping_days_ago=1)
        for label, observations in [
            ("queued", {"Foo Check": observation("queued")}),
            ("in_progress", {"Foo Check": observation("in_progress")}),
            ("absent", {}),
        ]:
            with self.subTest(label=label):
                c = gate.classify(observations, [], [oi], NOW, ONCALL, SLA)
                self.assertEqual([a.kind for a in c.actions if a.kind == "close"], [])

    def test_completed_failure_keeps_orphan_open_and_in_normal_flow(self):
        oi = issue(7, "Foo Check", last_ping_days_ago=2)
        c = gate.classify(failures("Foo Check"), [], [oi], NOW, ONCALL, SLA)
        self.assertEqual(c.orphans, ["Foo Check"])
        self.assertEqual([a.kind for a in c.actions], ["reping"])

    def test_mixed_contexts_close_only_explicit_completed_success(self):
        issues = [
            issue(1, "Green", last_ping_days_ago=1),
            issue(2, "Queued", last_ping_days_ago=1),
            issue(3, "Red", last_ping_days_ago=1),
            issue(4, "Absent", last_ping_days_ago=1),
        ]
        observations = {
            "Green": observation("completed", "success"),
            "Queued": observation("queued"),
            "Red": observation("completed", "failure"),
        }
        c = gate.classify(observations, [], issues, NOW, ONCALL, SLA)
        self.assertEqual([a.number for a in c.actions if a.kind == "close"], [1])
        self.assertEqual(c.orphans, ["Red"])

    def test_all_explicit_completed_success_observations_close(self):
        issues = [
            issue(1, "Green A", last_ping_days_ago=1),
            issue(2, "Green B", last_ping_days_ago=1),
        ]
        observations = {
            "Green A": observation("completed", "success"),
            "Green B": observation("completed", "success"),
        }
        c = gate.classify(observations, [], issues, NOW, ONCALL, SLA)
        self.assertEqual([a.number for a in c.actions if a.kind == "close"], [1, 2])

    def test_declared_red_within_expiry_is_ok_no_action(self):
        d = declared("Foo Check")
        c = gate.classify(failures("Foo Check"), [d], [], NOW, ONCALL, SLA)
        self.assertEqual(c.declared_ok, ["Foo Check"])
        self.assertEqual(c.orphans, [])
        self.assertEqual(c.expired, [])
        self.assertEqual(c.actions, [])

    def test_declared_red_past_expiry_is_expired_finding(self):
        d = expired_decl("Foo Check")
        c = gate.classify(failures("Foo Check"), [d], [], NOW, ONCALL, SLA)
        self.assertEqual(c.expired, [("Foo Check", d.expires)])
        self.assertEqual(c.orphans, [])
        self.assertEqual(c.actions, [])  # no orphan paging; the declaration lapsed, reported

    def test_prefix_declaration_covers_matrix_variants(self):
        d = declared("Published-target candidate")
        failing = [
            "Published-target candidate (x86_64-unknown-linux-musl)",
            "Published-target candidate (aarch64-apple-darwin)",
        ]
        c = gate.classify(failures(*failing), [d], [], NOW, ONCALL, SLA)
        self.assertEqual(sorted(c.declared_ok), sorted(failing))
        self.assertEqual(c.orphans, [])

    def test_distinct_orphans_each_get_their_own_create(self):
        failing = ["Red A", "Red B", "Red C"]
        c = gate.classify(failures(*failing), [], [], NOW, ONCALL, SLA)
        creates = [a.context for a in c.actions if a.kind == "create"]
        self.assertEqual(sorted(creates), sorted(failing))

    def test_blocking_tooth_is_not_fabricated(self):
        # The gate produces findings + notification only; it never emits a
        # "promote to required" action. (Escalation is a declared admin step.)
        c = gate.classify(failures("Orphan X"), [], [], NOW, ONCALL, SLA)
        self.assertFalse(any(a.kind == "block" or a.kind == "promote" for a in c.actions))


class CheckObservationFetchTests(unittest.TestCase):
    def fetch(self, payload: object):
        with patch.object(gate, "_gh", return_value=json.dumps(payload)):
            return gate.fetch_check_observations("owner/repo", "current-main-sha")

    def test_fetch_keeps_the_newest_run_id_per_context(self):
        observations = self.fetch(
            [
                {"id": 9, "name": "Foo", "status": "completed", "conclusion": "success"},
                {"id": 10, "name": "Foo", "status": "in_progress", "conclusion": None},
                {"id": 11, "name": "Bar", "status": "completed", "conclusion": "failure"},
            ]
        )
        self.assertEqual(observations["Foo"], observation("in_progress"))
        self.assertEqual(observations["Bar"], observation("completed", "failure"))

    def test_fetch_rejects_malformed_or_incomplete_shapes(self):
        invalid_payloads = [
            "",
            "not json",
            {},
            [None],
            [{}],
            [{"id": 1, "status": "queued", "conclusion": None}],
            [{"id": 1, "name": "Foo", "conclusion": None}],
            [{"id": 1, "name": "Foo", "status": "completed", "conclusion": None}],
            [{"id": 1, "name": "Foo", "status": "completed", "conclusion": 7}],
        ]
        for payload in invalid_payloads:
            with self.subTest(payload=payload), patch.object(gate, "_gh", return_value=json.dumps(payload)):
                with self.assertRaises(gate.GateCannotRun):
                    gate.fetch_check_observations("owner/repo", "current-main-sha")
        with patch.object(gate, "_gh", return_value=""):
            with self.assertRaises(gate.GateCannotRun):
                gate.fetch_check_observations("owner/repo", "current-main-sha")


class RunTests(unittest.TestCase):
    def test_fresh_sha_with_sibling_checks_queued_never_closes_an_orphan(self):
        queued = {
            "Consumption coverage gate": observation("queued"),
            "Owner-present structural boundary": observation("queued"),
            "Repo hygiene gates": observation("queued"),
        }
        existing = [
            issue(455, "Consumption coverage gate", last_ping_days_ago=1),
            issue(456, "Owner-present structural boundary", last_ping_days_ago=1),
            issue(457, "Repo hygiene gates", last_ping_days_ago=1),
        ]
        out = StringIO()
        with (
            patch.object(gate, "load_enrollment", return_value=(ONCALL, SLA, [])),
            patch.object(gate, "main_tip_sha", return_value="fresh-main-sha"),
            patch.object(gate, "fetch_check_observations", return_value=queued) as fetch_observations,
            patch.object(gate, "fetch_orphan_issues", return_value=existing),
            patch.object(gate, "execute") as execute,
        ):
            result = gate.run("owner/repo", Path("unused"), dry_run=False, out=out)
        self.assertEqual(result, 0)
        fetch_observations.assert_called_once_with("owner/repo", "fresh-main-sha")
        execute.assert_not_called()
        self.assertIn("main tip: fresh-main-sha", out.getvalue())

    def test_main_change_between_observation_and_write_fails_closed(self):
        success = {"Owner-present structural boundary": observation("completed", "success")}
        existing = [issue(456, "Owner-present structural boundary", last_ping_days_ago=1)]
        with (
            patch.object(gate, "load_enrollment", return_value=(ONCALL, SLA, [])),
            patch.object(gate, "main_tip_sha", side_effect=["observed-sha", "newer-sha"]),
            patch.object(gate, "fetch_check_observations", return_value=success),
            patch.object(gate, "fetch_orphan_issues", return_value=existing),
            patch.object(gate, "execute") as execute,
        ):
            with self.assertRaises(gate.GateCannotRun):
                gate.run("owner/repo", Path("unused"), dry_run=False, out=StringIO())
        execute.assert_not_called()

    def test_stable_main_allows_explicit_green_close(self):
        success = {"Owner-present structural boundary": observation("completed", "success")}
        existing = [issue(456, "Owner-present structural boundary", last_ping_days_ago=1)]
        with (
            patch.object(gate, "load_enrollment", return_value=(ONCALL, SLA, [])),
            patch.object(gate, "main_tip_sha", return_value="current-sha") as main_tip,
            patch.object(gate, "fetch_check_observations", return_value=success),
            patch.object(gate, "fetch_orphan_issues", return_value=existing),
            patch.object(gate, "execute") as execute,
        ):
            result = gate.run("owner/repo", Path("unused"), dry_run=False, out=StringIO())
        self.assertEqual(result, 0)
        self.assertEqual(main_tip.call_count, 2)
        self.assertEqual([action.kind for action in execute.call_args.args[0]], ["close"])
        self.assertEqual(execute.call_args.kwargs["expected_sha"], "current-sha")


class ExecuteTests(unittest.TestCase):
    def test_stable_main_allows_every_write_in_the_batch(self):
        actions = [
            gate.Action(kind="close", context="First", number=1),
            gate.Action(kind="close", context="Second", number=2),
        ]
        with (
            patch.object(gate, "main_tip_sha", return_value="current-sha") as main_tip,
            patch.object(gate, "_gh") as gh,
        ):
            gate.execute(
                actions, "owner/repo", dry_run=False, expected_sha="current-sha", out=StringIO()
            )
        self.assertEqual(main_tip.call_count, 2)
        self.assertEqual(gh.call_count, 2)

    def test_main_change_between_writes_stops_before_the_second_action(self):
        actions = [
            gate.Action(kind="close", context="First", number=1),
            gate.Action(kind="close", context="Second", number=2),
        ]
        with (
            patch.object(gate, "main_tip_sha", side_effect=["current-sha", "newer-sha"]),
            patch.object(gate, "_gh") as gh,
        ):
            with self.assertRaises(gate.GateCannotRun):
                gate.execute(
                    actions, "owner/repo", dry_run=False, expected_sha="current-sha", out=StringIO()
                )
        self.assertEqual(gh.call_count, 1)
        self.assertEqual(gh.call_args.args[0][0:3], ["issue", "close", "1"])


class ParseDateTests(unittest.TestCase):
    def test_bare_date_is_end_of_day_utc(self):
        dt = gate.parse_date("2026-08-09")
        self.assertEqual(dt, datetime(2026, 8, 9, 23, 59, 59, tzinfo=timezone.utc))

    def test_iso_datetime_is_utc_normalized(self):
        dt = gate.parse_date("2026-08-09T10:00:00Z")
        self.assertEqual(dt.tzinfo, timezone.utc)


class LatestPingTests(unittest.TestCase):
    def comment(self, body: str, created_at: str) -> dict[str, str]:
        return {"body": body, "created_at": created_at}

    def latest(self, pages: list[list[dict[str, str]]]):
        with patch.object(gate, "_gh", return_value=json.dumps(pages)) as mocked:
            actual = gate._latest_ping("owner/repo", 17)
        self.assertEqual(
            mocked.call_args.args[0],
            ["api", "--paginate", "--slurp", "repos/owner/repo/issues/17/comments"],
        )
        return actual

    def test_latest_ping_accepts_zero_comments(self):
        self.assertIsNone(self.latest([[]]))

    def test_latest_ping_reads_one_comment(self):
        actual = self.latest([[self.comment("chronic-red re-ping", "2026-08-10T12:00:00Z")]])
        self.assertEqual(actual, datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc))

    def test_latest_ping_uses_the_newest_of_multiple_comments(self):
        actual = self.latest(
            [[
                self.comment("chronic-red re-ping", "2026-08-09T12:00:00Z"),
                self.comment("ordinary discussion", "2026-08-10T11:00:00Z"),
                self.comment("chronic-red re-ping", "2026-08-10T12:00:00Z"),
            ]]
        )
        self.assertEqual(actual, datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc))

    def test_latest_ping_flattens_all_fourteen_pages(self):
        # `--slurp` preserves each remote page as an inner array. The latest
        # ping can be on the final page and must not be silently ignored.
        pages = [
            [self.comment("ordinary discussion", f"2026-08-{day:02d}T12:00:00Z")]
            for day in range(1, 14)
        ]
        pages.append([self.comment("chronic-red re-ping", "2026-08-14T12:00:00Z")])
        actual = self.latest(pages)
        self.assertEqual(actual, datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc))

    def test_latest_ping_rejects_invalid_json_and_shapes(self):
        invalid_payloads = [
            "",
            " \t\n",
            "not json",
            "[]\n[]",  # concatenated pages are not one valid JSON response
            json.dumps({}),
            json.dumps([]),  # `--slurp` always returns at least one page
            json.dumps([{}]),
            json.dumps([["not an object"]]),
            json.dumps([[{"body": "x"}]]),
            json.dumps([[{"body": 7, "created_at": "2026-08-10T12:00:00Z"}]]),
            json.dumps([[{"body": "x", "created_at": 7}]]),
            json.dumps([[{"body": "chronic-red re-ping", "created_at": "not-a-date"}]]),
        ]
        for payload in invalid_payloads:
            with self.subTest(payload=payload), patch.object(gate, "_gh", return_value=payload):
                with self.assertRaises(gate.GateCannotRun):
                    gate._latest_ping("owner/repo", 17)


if __name__ == "__main__":
    unittest.main(verbosity=2)
