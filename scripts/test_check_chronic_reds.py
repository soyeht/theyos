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
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

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


class ClassifyTests(unittest.TestCase):
    def test_orphan_with_no_issue_creates_with_assignee_and_deadline(self):
        c = gate.classify(["Foo Check"], [], [], NOW, ONCALL, SLA)
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
        c = gate.classify(["Foo Check"], [], [oi], NOW, ONCALL, SLA)
        self.assertEqual(c.orphans, ["Foo Check"])
        self.assertEqual([a.kind for a in c.actions], [])  # no create, no reping

    def test_orphan_pinged_over_sla_is_re_pinged(self):
        oi = issue(7, "Foo Check", last_ping_days_ago=2)  # >=sla (48h)
        c = gate.classify(["Foo Check"], [], [oi], NOW, ONCALL, SLA)
        repings = [a for a in c.actions if a.kind == "reping"]
        self.assertEqual(len(repings), 1)
        self.assertEqual(repings[0].number, 7)
        self.assertEqual([a.kind for a in c.actions if a.kind == "create"], [])

    def test_orphan_issue_with_no_ping_uses_creation_as_the_clock(self):
        # last_ping None -> the create was the first page; sla counts from there.
        oi = issue(7, "Foo Check", last_ping_days_ago=None, created_days_ago=3)  # >sla since create
        c = gate.classify(["Foo Check"], [], [oi], NOW, ONCALL, SLA)
        self.assertEqual([a.kind for a in c.actions], ["reping"])

    def test_green_check_closes_its_orphan_issue(self):
        oi = issue(7, "Foo Check", last_ping_days_ago=1)
        c = gate.classify([], [], [oi], NOW, ONCALL, SLA)  # "Foo Check" no longer failing
        closes = [a for a in c.actions if a.kind == "close"]
        self.assertEqual(len(closes), 1)
        self.assertEqual(closes[0].number, 7)

    def test_declared_red_within_expiry_is_ok_no_action(self):
        d = declared("Foo Check")
        c = gate.classify(["Foo Check"], [d], [], NOW, ONCALL, SLA)
        self.assertEqual(c.declared_ok, ["Foo Check"])
        self.assertEqual(c.orphans, [])
        self.assertEqual(c.expired, [])
        self.assertEqual(c.actions, [])

    def test_declared_red_past_expiry_is_expired_finding(self):
        d = expired_decl("Foo Check")
        c = gate.classify(["Foo Check"], [d], [], NOW, ONCALL, SLA)
        self.assertEqual(c.expired, [("Foo Check", d.expires)])
        self.assertEqual(c.orphans, [])
        self.assertEqual(c.actions, [])  # no orphan paging; the declaration lapsed, reported

    def test_prefix_declaration_covers_matrix_variants(self):
        d = declared("Published-target candidate")
        failing = [
            "Published-target candidate (x86_64-unknown-linux-musl)",
            "Published-target candidate (aarch64-apple-darwin)",
        ]
        c = gate.classify(failing, [d], [], NOW, ONCALL, SLA)
        self.assertEqual(sorted(c.declared_ok), sorted(failing))
        self.assertEqual(c.orphans, [])

    def test_distinct_orphans_each_get_their_own_create(self):
        failing = ["Red A", "Red B", "Red C"]
        c = gate.classify(failing, [], [], NOW, ONCALL, SLA)
        creates = [a.context for a in c.actions if a.kind == "create"]
        self.assertEqual(sorted(creates), sorted(failing))

    def test_blocking_tooth_is_not_fabricated(self):
        # The gate produces findings + notification only; it never emits a
        # "promote to required" action. (Escalation is a declared admin step.)
        c = gate.classify(["Orphan X"], [], [], NOW, ONCALL, SLA)
        self.assertFalse(any(a.kind == "block" or a.kind == "promote" for a in c.actions))


class ParseDateTests(unittest.TestCase):
    def test_bare_date_is_end_of_day_utc(self):
        dt = gate.parse_date("2026-08-09")
        self.assertEqual(dt, datetime(2026, 8, 9, 23, 59, 59, tzinfo=timezone.utc))

    def test_iso_datetime_is_utc_normalized(self):
        dt = gate.parse_date("2026-08-09T10:00:00Z")
        self.assertEqual(dt.tzinfo, timezone.utc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
