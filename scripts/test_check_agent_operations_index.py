#!/usr/bin/env python3
"""Tests for scripts/check-agent-operations-index.py.

Every check carries a negative test: the defect it exists to catch is
constructed, and the gate is asserted to go red on it. A positive test alone
cannot tell a working guard from one that stopped guarding.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-agent-operations-index.py")
SPEC = importlib.util.spec_from_file_location("check_agent_operations_index", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)

REPO_ROOT = Path(__file__).resolve().parents[1]
TODAY = dt.date(2026, 8, 6)


def valid_index() -> str:
    """A minimal index carrying every required section and a fresh claim."""
    return """# Agent operations index

## 0. Why this file, and not `CLAUDE.md`

`CLAUDE.md` and `AGENTS.md` are in `.gitignore`, so they never reach a worktree.
The private store lives at `~/.soyeht-ops/`.
`MEASURED 2026-08-06 origin/main@e60bad85`

## 2. Aliases used in all public text

`Relay-R` is the rented relay VPS.

## 3. Where the code is

The apps live in soyeht-ios. The cross-repo gate is
`.github/workflows/contracts-cross-repo-sync.yml` and covers one fixture only.

## 4. Gates that keep this from happening again

| gate | goes red when |
|---|---|
| `scripts/check-agent-operations-index.py` | the map rots |
| `scripts/check-cross-repo-ffi-pin.py` `PENDING 2026-08-14` | the iOS pin is behind |
Discussing the words MEASURED and PENDING in prose is not a marker.

## 5. Measuring this repo without getting it wrong

`admin/rust/Cargo.toml` carries an exclude list.
CI compiles those libraries but never runs their tests.

## 6. The dating rule

Every claim carries a date and a tree.

## 8. Where authorization actually lives

`~/.soyeht-ops/authorizations.md` is the record.
"""


def content_errors(markdown: str, *, today: dt.date = TODAY, max_age_days: int = 30, max_lines: int = 200):
    return checker.index_content_errors(markdown, today, max_age_days, max_lines)


class IndexContentTests(unittest.TestCase):
    def test_valid_index_passes(self) -> None:
        self.assertEqual([], content_errors(valid_index()))

    def test_rejects_index_that_grew_into_a_manual(self) -> None:
        bloated = valid_index() + "\nfiller line\n" * 300
        errors = content_errors(bloated)
        self.assertTrue(
            any("lines is a manual" in error for error in errors),
            f"length guard did not fire: {errors}",
        )

    def test_rejects_each_missing_required_section(self) -> None:
        removals = (
            ("~/.soyeht-ops", "the private operator store pointer"),
            ("soyeht-ios", "the iOS repository location"),
            ("contracts-cross-repo-sync.yml", "the cross-repo pin hazard"),
            ("## 4. Gates that keep this from happening again", "the gates table"),
            ("## 5. Measuring this repo without getting it wrong", "the measuring section"),
            ("## 6. The dating rule", "the dating rule"),
            ("## 2. Aliases used in all public text", "the aliases table"),
            ("authorizations.md", "where authorization lives"),
            ("exclude", "the exclude-list warning"),
        )
        for needle, expected in removals:
            with self.subTest(section=expected):
                self.assertIn(
                    f"index must carry {expected}",
                    content_errors(valid_index().replace(needle, "REDACTED")),
                )


class DatedClaimTests(unittest.TestCase):
    def test_rejects_a_claim_that_aged_out(self) -> None:
        """The failure this gate exists for: a number nobody re-evaluated."""

        def aged(today: dt.date) -> list[str]:
            return [e for e in content_errors(valid_index(), today=today) if "days old; re-measure" in e]

        self.assertEqual([], aged(dt.date(2026, 9, 5)), "age guard fired one day early (30 days)")
        self.assertEqual(
            ["MEASURED claim is 31 days old; re-measure and restate the date"],
            aged(dt.date(2026, 9, 6)),
        )

    def test_rejects_an_index_with_no_dated_claim_at_all(self) -> None:
        """A guard search that finds nothing must not report clean."""
        stripped = valid_index().replace("MEASURED 2026-08-06 origin/main@e60bad85", "")
        self.assertIn("index must carry at least one MEASURED claim", content_errors(stripped))

    def test_rejects_a_malformed_marker_instead_of_ignoring_it(self) -> None:
        cases = (
            "MEASURED 2026-8-6 origin/main@e60bad85",
            "MEASURED 2026-08-06 origin/main",
            "MEASURED origin/main@e60bad85",
            "MEASURED",
        )
        for broken in cases:
            with self.subTest(marker=broken):
                markdown = valid_index().replace("MEASURED 2026-08-06 origin/main@e60bad85", broken)
                self.assertIn("index contains a malformed MEASURED marker", content_errors(markdown))

    def test_rejects_an_unknown_or_future_tree(self) -> None:
        unknown = valid_index().replace("origin/main@e60bad85", "some-other-repo@e60bad85")
        self.assertIn(
            "MEASURED marker names an unknown tree: some-other-repo",
            content_errors(unknown),
        )
        self.assertIn(
            "MEASURED marker is dated in the future",
            content_errors(valid_index(), today=dt.date(2026, 8, 5)),
        )

    def test_rejects_an_expired_or_malformed_pending_promise(self) -> None:
        self.assertIn(
            "PENDING promise has expired; land it or restate it",
            content_errors(valid_index(), today=dt.date(2026, 8, 15)),
        )
        self.assertIn(
            "index contains a malformed PENDING marker",
            content_errors(valid_index().replace("PENDING 2026-08-14", "PENDING soon")),
        )

    def test_rejects_a_tree_ref_the_repo_cannot_resolve(self) -> None:
        bogus = "0" * 40
        markdown = valid_index().replace("e60bad85", bogus)
        errors = checker.tree_ref_errors(markdown, lambda sha: checker.git_commit_exists(REPO_ROOT, sha))
        self.assertIn(f"MEASURED marker cites a commit this repo cannot resolve: origin/main@{bogus}", errors)

    def test_accepts_a_tree_ref_the_repo_can_resolve(self) -> None:
        head = subprocess.run(
            ("git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"),
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        markdown = f"`MEASURED 2026-08-06 origin/main@{head}`\n"
        # Non-vacuity: the marker must actually be seen, or the empty result
        # below would prove nothing.
        self.assertEqual(1, len(checker.measured_markers(markdown)))
        self.assertEqual(
            [],
            checker.tree_ref_errors(markdown, lambda sha: checker.git_commit_exists(REPO_ROOT, sha)),
        )

    def test_foreign_tree_ref_is_accepted_without_local_resolution(self) -> None:
        markdown = "`MEASURED 2026-08-06 soyeht-ios@39524164`\n"
        self.assertEqual(1, len(checker.measured_markers(markdown)))
        self.assertEqual([], checker.tree_ref_errors(markdown, lambda sha: False))

    def test_an_unbackticked_marker_is_not_counted_as_a_claim(self) -> None:
        """Markers are code spans. Prose that merely looks like one is not one."""
        prose = valid_index().replace("`MEASURED 2026-08-06 origin/main@e60bad85`", "MEASURED 2026-08-06 origin/main@e60bad85")
        self.assertIn("index must carry at least one MEASURED claim", content_errors(prose))


class PrivacyTests(unittest.TestCase):
    def test_rejects_values_a_public_repo_must_not_carry(self) -> None:
        cases = (
            (".".join(("10", "44", "0", "1")), "index must use only documentation-safe IPv4 addresses"),
            ("/" + "Users" + "/someone/theyos", "index must not contain local absolute paths"),
            ("someone" + "@example.com", "index must not contain account or email addresses"),
            ("api_key" + "=abc123", "index must not contain secrets or key material"),
            ("-----" + "BE" + "GIN " + "PRIVATE KEY-----", "index must not contain secrets or key material"),
        )
        for addition, expected in cases:
            with self.subTest(addition=expected):
                self.assertIn(expected, content_errors(valid_index() + f"\n{addition}\n"))

    def test_allows_documentation_ipv4_and_the_tilde_store_path(self) -> None:
        markdown = valid_index() + "\nExample address 192.0.2.10 and the store at ~/.soyeht-ops/apple.md\n"
        self.assertEqual([], content_errors(markdown))


class LinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        (self.repo / "docs").mkdir()
        (self.repo / "scripts").mkdir()
        (self.repo / "docs" / "household-protocol.md").write_text("x", encoding="utf-8")
        (self.repo / "scripts" / "check-thing.py").write_text("x", encoding="utf-8")
        (self.repo / "scripts" / "test_check_thing.py").write_text("x", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    @property
    def exists(self):
        return lambda rel: (self.repo / rel).exists()

    def test_resolving_links_pass(self) -> None:
        markdown = "See `docs/household-protocol.md` and `scripts/check-thing.py`.\n"
        self.assertEqual([], checker.link_errors(markdown, self.exists))

    def test_rejects_a_dead_link(self) -> None:
        markdown = "See `docs/plan-that-was-deleted.md`.\n"
        self.assertIn(
            "index points at a path that does not exist: docs/plan-that-was-deleted.md",
            checker.link_errors(markdown, self.exists),
        )

    def test_rejects_a_gate_with_no_co_located_test(self) -> None:
        (self.repo / "scripts" / "test_check_thing.py").unlink()
        markdown = "See `scripts/check-thing.py`.\n"
        self.assertIn(
            "gate scripts/check-thing.py has no co-located test at scripts/test_check_thing.py",
            checker.link_errors(markdown, self.exists),
        )

    def test_pending_row_exempts_its_own_line_only(self) -> None:
        pending = "| `scripts/check-not-landed.py` `PENDING 2026-08-14` | soon |\n"
        self.assertEqual([], checker.link_errors(pending, self.exists))
        landed = "| `scripts/check-not-landed.py` | now |\n"
        self.assertIn(
            "index points at a path that does not exist: scripts/check-not-landed.py",
            checker.link_errors(landed, self.exists),
        )

    def test_a_pending_marker_in_prose_does_not_exempt_the_line(self) -> None:
        """Only a well-formed marker exempts. Writing PENDING in prose must not."""
        line = "PENDING work: see `docs/plan-that-was-deleted.md`.\n"
        self.assertIn(
            "index points at a path that does not exist: docs/plan-that-was-deleted.md",
            checker.link_errors(line, self.exists),
        )


class ReachabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_rejects_an_untracked_index(self) -> None:
        self.assertEqual(
            [
                f"{checker.INDEX_REL} is not tracked in git; "
                "an untracked map never reaches a worktree or CI"
            ],
            checker.tracked_errors(lambda rel: False),
        )
        self.assertEqual([], checker.tracked_errors(lambda rel: True))

    def test_rejects_an_entrypoint_that_does_not_point_here(self) -> None:
        (self.repo / "CLAUDE.md").write_text("# Some other heading\n\nno pointer\n", encoding="utf-8")
        (self.repo / "AGENTS.md").write_text(f"# READ FIRST: {checker.INDEX_REL}\n", encoding="utf-8")
        errors = checker.entrypoint_errors(self.repo, lambda rel: True)
        self.assertEqual(
            [f"CLAUDE.md must point at {checker.INDEX_REL} within its first 20 lines"],
            errors,
        )

    def test_rejects_a_pointer_buried_below_the_window(self) -> None:
        buried = "filler\n" * 40 + f"see {checker.INDEX_REL}\n"
        (self.repo / "CLAUDE.md").write_text(buried, encoding="utf-8")
        (self.repo / "AGENTS.md").write_text(f"{checker.INDEX_REL}\n", encoding="utf-8")
        self.assertIn(
            f"CLAUDE.md must point at {checker.INDEX_REL} within its first 20 lines",
            checker.entrypoint_errors(self.repo, lambda rel: True),
        )

    def test_absent_entrypoint_passes_only_when_provably_ignored(self) -> None:
        self.assertEqual([], checker.entrypoint_errors(self.repo, lambda rel: True))
        errors = checker.entrypoint_errors(self.repo, lambda rel: False)
        self.assertEqual(
            [
                "CLAUDE.md is absent and not git-ignored; its absence is unexplained",
                "AGENTS.md is absent and not git-ignored; its absence is unexplained",
            ],
            errors,
        )


class CliTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_repo_passes_its_own_gate(self) -> None:
        """Resolved against origin/main, which is the tree the index ships in.

        A local checkout may sit on an unrelated branch where a mapped path does
        not exist yet; that is the working-tree mistake section 5 warns about,
        not an index defect. CI runs without `--also-in` because its checkout is
        the tree under test.
        """
        if not checker.git_commit_exists(REPO_ROOT, "origin/main"):
            self.skipTest("origin/main is not fetched in this clone")
        proc = self.run_cli("--repo", str(REPO_ROOT), "--also-in", "origin/main", "--today", TODAY.isoformat())
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertIn("OK: agent operations index is tracked", proc.stdout)

    def test_unresolvable_tree_is_exit_two_not_a_pass(self) -> None:
        proc = self.run_cli("--repo", str(REPO_ROOT), "--also-in", "no/such/ref")
        self.assertEqual(2, proc.returncode)
        self.assertIn("--also-in does not resolve", proc.stderr)

    def test_missing_index_is_exit_two_not_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(("git", "-C", tmp, "init", "-q"), check=True)
            proc = self.run_cli("--repo", tmp)
            self.assertEqual(2, proc.returncode)
            self.assertIn("could not read", proc.stderr)

    def test_non_utf8_index_is_exit_two_not_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(("git", "-C", tmp, "init", "-q"), check=True)
            index = Path(tmp) / checker.INDEX_REL
            index.parent.mkdir(parents=True)
            index.write_bytes(b"\xff\xfe not utf-8")
            proc = self.run_cli("--repo", tmp)
            self.assertEqual(2, proc.returncode)
            self.assertIn("not valid UTF-8", proc.stderr)

    def test_non_git_repo_is_exit_two_not_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_cli("--repo", tmp)
            self.assertEqual(2, proc.returncode)
            self.assertIn("not a git repository", proc.stderr)

    def test_unparseable_today_is_exit_two_not_a_pass(self) -> None:
        proc = self.run_cli("--repo", str(REPO_ROOT), "--today", "yesterday")
        self.assertEqual(2, proc.returncode)
        self.assertIn("--today must be an ISO date", proc.stderr)

    def test_repo_goes_red_when_every_claim_has_aged_out(self) -> None:
        """End-to-end proof the age mechanism reaches the real index."""
        if not checker.git_commit_exists(REPO_ROOT, "origin/main"):
            self.skipTest("origin/main is not fetched in this clone")
        proc = self.run_cli(
            "--repo", str(REPO_ROOT), "--also-in", "origin/main", "--today", "2027-01-01", "--max-age-days", "30"
        )
        self.assertEqual(1, proc.returncode)
        self.assertIn("days old; re-measure", proc.stderr)


if __name__ == "__main__":
    unittest.main()
