#!/usr/bin/env python3
"""Tests for scripts/check-plan-doc-freshness.py.

The negative tests are the point.  A positive test cannot catch a gate that
stopped gating, so each defect the gate exists to catch is constructed here in a
real throwaway git repository and the gate is asserted to go red on it:

  * code landing on an anchored path after the anchor;
  * the same, after the document has been *edited* (the trap: touching a file is
    not re-verifying its claims);
  * an anchor path that matches nothing (a vacuous gate is not a passing gate);
  * a path that exists only in the index, not in the measured tree;
  * a missing, duplicated, unterminated, mistyped or short-SHA anchor;
  * an anchor SHA that is absent, unreachable, or contradicted by the prose;
  * an enrollment file that is unreadable, malformed, empty, or has quietly
    dropped a required document.

Real git is used rather than a stub because the gate's correctness depends on
git's own pathspec semantics -- `git ls-tree` ignores wildcards while `git log`
and `git ls-files` honour them -- and a stub would agree with whatever the gate
happened to do.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from datetime import date, timedelta
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-plan-doc-freshness.py")
SPEC = importlib.util.spec_from_file_location("check_plan_doc_freshness", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
# The module must be in sys.modules before it executes: `from __future__ import
# annotations` makes dataclass field types strings, and dataclasses resolves
# them through sys.modules[cls.__module__].
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)


CODE_FILE = "admin/rust/server-rs/src/vpn_dev_config.rs"
OTHER_CODE_FILE = "admin/rust/frontend/src/app.ts"
ANCHORED_PATHS = ("admin/rust/server-rs/src/vpn_*.rs",)
DOC = "docs/vpn-plan.md"
ABSENT_SHA = "0123456789abcdef0123456789abcdef01234567"


def anchor_block(sha: str, measured: str = "2026-08-06", paths: tuple[str, ...] = ANCHORED_PATHS) -> str:
    lines = ["<!-- doc-freshness-anchor", f"measured: {measured}", f"sha: {sha}", "paths:"]
    lines.extend(f"  - {path}" for path in paths)
    lines.append("-->")
    return "\n".join(lines)


def plan_document(sha: str, measured: str = "2026-08-06", paths: tuple[str, ...] = ANCHORED_PATHS, body: str = "") -> str:
    return (
        "# VPN plan\n\n"
        f"Measured against `origin/main` at `{sha}` on {measured}.\n\n"
        f"{anchor_block(sha, measured, paths)}\n\n"
        "## 1. State\n\nThe datapath is compiled out.\n"
        f"{body}"
    )


class TempRepo:
    """A throwaway git repository, hermetic from the developer's git config."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.env = dict(os.environ)
        self.env.update(
            {
                "HOME": str(root / ".fakehome"),
                "XDG_CONFIG_HOME": str(root / ".fakehome" / ".config"),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_AUTHOR_NAME": "doc freshness test",
                "GIT_AUTHOR_EMAIL": "test@example.invalid",
                "GIT_COMMITTER_NAME": "doc freshness test",
                "GIT_COMMITTER_EMAIL": "test@example.invalid",
            }
        )
        (root / ".fakehome").mkdir(parents=True, exist_ok=True)
        self.git("init", "--quiet")

    def git(self, *args: str, when: str | None = None) -> str:
        env = dict(self.env)
        if when is not None:
            env["GIT_AUTHOR_DATE"] = when
            env["GIT_COMMITTER_DATE"] = when
        proc = subprocess.run(
            ("git", "-C", str(self.root), "-c", "commit.gpgsign=false", *args),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
        return proc.stdout

    def write(self, relative_path: str, text: str) -> None:
        target = self.root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def commit(self, message: str, when: str = "2026-08-06T09:00:00+0000") -> str:
        self.git("add", "-A")
        self.git("commit", "--quiet", "-m", message, when=when)
        return self.git("rev-parse", "HEAD").strip()

    def write_enrollment(self, documents: list[dict[str, object]], schema: str = gate.ENROLLMENT_SCHEMA) -> None:
        self.write(
            "docs/doc-freshness-enrollment.json",
            json.dumps({"schema": schema, "documents": documents}, indent=2) + "\n",
        )


class DocFreshnessTestCase(unittest.TestCase):
    """Base case: a repo whose plan document is anchored at the tip and is fresh."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo = TempRepo(Path(self._tmp.name))
        self.repo.write(CODE_FILE, "pub const DEFAULT_OFF: bool = true;\n")
        self.repo.write(OTHER_CODE_FILE, "export const app = 1;\n")
        self.repo.write(DOC, "placeholder\n")
        self.repo.write_enrollment([{"path": DOC, "status": "anchored"}])
        self.anchor_sha = self.repo.commit("seed")
        self.repo.write(DOC, plan_document(self.anchor_sha))
        self.repo.commit("write the plan")

    def run_gate(self, *args: str, required: tuple[str, ...] = ()) -> tuple[int, str, str]:
        original = gate.REQUIRED_ANCHORED
        gate.REQUIRED_ANCHORED = required
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = gate.main(["--repo-root", str(self.repo.root), *args])
        finally:
            gate.REQUIRED_ANCHORED = original
        return code, out.getvalue(), err.getvalue()

    def assert_red(self, *args: str, contains: str, required: tuple[str, ...] = ()) -> str:
        code, out, err = self.run_gate(*args, required=required)
        self.assertEqual(1, code, f"expected a finding, got exit {code}\nstdout={out}\nstderr={err}")
        self.assertNotIn("OK:", out, "a gate with a finding must not also report OK")
        self.assertIn(contains, err)
        return err

    def assert_green(self, *args: str, required: tuple[str, ...] = ()) -> str:
        code, out, err = self.run_gate(*args, required=required)
        self.assertEqual(0, code, f"expected a pass, got exit {code}\nstdout={out}\nstderr={err}")
        self.assertIn("OK:", out)
        return out


class FreshnessTests(DocFreshnessTestCase):
    def test_anchored_document_at_the_tip_passes(self) -> None:
        # Also the instrument check: ANCHORED_PATHS is a wildcard pathspec, so a
        # gate that resolved paths with `git ls-tree` (which ignores wildcards)
        # would call it dead and this positive test would go red.
        self.assert_green()

    def test_unrelated_code_moving_does_not_redden_the_document(self) -> None:
        self.repo.write(OTHER_CODE_FILE, "export const app = 2;\n")
        self.repo.commit("frontend churn")
        self.assert_green()

    def test_commit_on_an_anchored_path_after_the_anchor_is_red(self) -> None:
        self.repo.write(CODE_FILE, "pub const DEFAULT_OFF: bool = false;\n")
        drift = self.repo.commit("flip the default")
        err = self.assert_red(contains="code the document describes moved after its anchor")
        self.assertIn(drift[:12], err, "the report must name the commit that made the document stale")

    def test_editing_the_document_does_not_clear_a_stale_anchor(self) -> None:
        """The trap. Touching a file is not re-verifying its claims."""
        self.repo.write(CODE_FILE, "pub const DEFAULT_OFF: bool = false;\n")
        self.repo.commit("flip the default")
        self.assert_red(contains="code the document describes moved after its anchor")

        # Rewrite the document extensively -- new prose, new date in the text,
        # a fresh commit touching only the document. The anchor SHA is untouched.
        self.repo.write(
            DOC,
            plan_document(self.anchor_sha, body="\n## 2. Rewritten 2026-09-01 with a great deal of new prose.\n"),
        )
        self.repo.commit("rewrite the plan")
        self.assert_red(contains="code the document describes moved after its anchor")

        # Only advancing the anchor -- the deliberate act of whoever re-measured
        # -- clears it.
        head = self.repo.git("rev-parse", "HEAD").strip()
        self.repo.write(DOC, plan_document(head, measured="2026-09-01"))
        self.repo.commit("re-measure", when="2026-09-01T09:00:00+0000")
        self.assert_green()

    def test_reverting_the_code_still_counts_as_movement(self) -> None:
        original = (self.repo.root / CODE_FILE).read_text(encoding="utf-8")
        self.repo.write(CODE_FILE, "pub const DEFAULT_OFF: bool = false;\n")
        self.repo.commit("flip the default")
        self.repo.write(CODE_FILE, original)
        self.repo.commit("flip it back")
        # The tree matches the anchor again, but the document's claims about the
        # intervening code were never re-checked, and §-level claims may have
        # been about the flipped state. Movement is the signal, not the diff.
        self.assert_red(contains="code the document describes moved after its anchor")


class VacuityTests(DocFreshnessTestCase):
    def test_anchor_path_matching_nothing_is_red_not_clean(self) -> None:
        self.repo.write(DOC, plan_document(self.anchor_sha, paths=("admin/rust/server-rs/src/typo_*.rs",)))
        self.repo.commit("typo the anchored path")
        self.assert_red(contains="match no file at")

    def test_one_dead_path_among_live_ones_is_red(self) -> None:
        self.repo.write(
            DOC,
            plan_document(self.anchor_sha, paths=(*ANCHORED_PATHS, "admin/rust/nonexistent-rs/")),
        )
        self.repo.commit("add a dead path")
        self.assert_red(contains="admin/rust/nonexistent-rs/")

    def test_path_present_only_in_the_index_does_not_count_as_present(self) -> None:
        """`git ls-files --with-tree` overlays the index; the measured tree must win."""
        self.repo.write(DOC, plan_document(self.anchor_sha, paths=("admin/rust/staged-only-rs/lib.rs",)))
        self.repo.commit("anchor a path that does not exist yet")
        self.repo.write("admin/rust/staged-only-rs/lib.rs", "// staged, never committed\n")
        self.repo.git("add", "admin/rust/staged-only-rs/lib.rs")
        self.assert_red(contains="match no file at")

    def test_empty_document_set_passes_only_under_an_unexpired_deadline(self) -> None:
        """An empty enrollment is a deadline, never an unconditional pass.

        This used to assert exit 2 flatly. The contract changed on 2026-08-06
        when the planning corpus was retired: refusing the empty state outright
        would have forced whoever retired the last plan to delete or disable the
        gate, which is worse. So the empty state passes -- but ONLY while
        PLAN_ENROLLMENT_DEADLINE is in the future, and this test pins both sides.
        Asserting just the pass would leave the failing branch unreached, which
        is how a guard quietly stops guarding.
        """
        # Both sides must be empty. Auto-discovery scans docs/ for anchor blocks
        # regardless of enrollment, so emptying the file alone leaves the fixture
        # document in scope and the interregnum path is never reached.
        self.repo.write_enrollment([])
        self.repo.git("rm", "--quiet", DOC)
        self.repo.commit("retire the last plan and empty the enrollment")

        code, out, err = self.run_gate()
        self.assertEqual(0, code)
        self.assertIn("no plan document is enrolled", out)
        self.assertIn(gate.PLAN_ENROLLMENT_DEADLINE.isoformat(), out)

        expired = gate.PLAN_ENROLLMENT_DEADLINE + timedelta(days=1)
        with mock.patch.object(gate, "PLAN_ENROLLMENT_DEADLINE", date(2026, 1, 1)):
            code, out, err = self.run_gate()
        self.assertEqual(1, code)
        self.assertNotIn("OK:", out)
        self.assertIn("grace period ended", err)
        self.assertIsInstance(expired, date)

    def test_all_exempt_cannot_pass(self) -> None:
        self.repo.write(DOC, "# VPN plan\n\nno anchor here\n")
        self.repo.write_enrollment(
            [{"path": DOC, "status": "exempt", "reason": "migrating", "expires": "2099-01-01"}]
        )
        self.repo.commit("exempt everything")
        code, out, err = self.run_gate()
        self.assertEqual(2, code)
        self.assertNotIn("OK:", out)
        self.assertIn("checks nothing is not a pass", err)


class AnchorIntegrityTests(DocFreshnessTestCase):
    def test_enrolled_document_without_an_anchor_is_red(self) -> None:
        self.repo.write(DOC, "# VPN plan\n\nMeasured 2026-08-06 against origin/main.\n")
        self.repo.commit("drop the anchor")
        self.assert_red(contains="carries no doc-freshness anchor block")

    def test_enrolled_document_that_is_absent_is_red(self) -> None:
        (self.repo.root / DOC).unlink()
        self.repo.commit("delete the document")
        self.assert_red(contains="missing or unreadable")

    def test_document_that_is_not_utf8_is_red(self) -> None:
        (self.repo.root / DOC).write_bytes(b"# VPN plan\n\xff\xfe not utf-8\n")
        self.repo.commit("corrupt the document")
        self.assert_red(contains="not valid UTF-8")

    def test_anchor_sha_absent_from_the_repository_is_red(self) -> None:
        self.repo.write(DOC, plan_document(ABSENT_SHA))
        self.repo.commit("anchor at a commit that does not exist")
        self.assert_red(contains="is not a commit in this repository")

    def test_anchor_sha_not_an_ancestor_of_the_ref_is_red(self) -> None:
        base = self.repo.git("rev-parse", "HEAD").strip()
        self.repo.git("checkout", "--quiet", "-b", "sidebranch")
        self.repo.write(CODE_FILE, "pub const SIDE: bool = true;\n")
        side = self.repo.commit("side branch commit")
        self.repo.git("checkout", "--quiet", "-")
        self.repo.write(DOC, plan_document(side))
        self.repo.commit("anchor at a commit this branch does not contain")
        self.assertNotEqual(base, side)
        self.assert_red(contains="is not an ancestor of")

    def test_measured_date_before_the_anchor_commit_is_red(self) -> None:
        self.repo.write(CODE_FILE, "pub const LATER: bool = true;\n")
        later = self.repo.commit("a later commit", when="2026-08-20T09:00:00+0000")
        self.repo.write(DOC, plan_document(later, measured="2026-07-01"))
        self.repo.commit("claim a measurement predating the tree", when="2026-08-21T09:00:00+0000")
        self.assert_red(contains="was only committed on")

    def test_anchor_sha_absent_from_the_prose_is_red(self) -> None:
        document = (
            "# VPN plan\n\nMeasured against `origin/main` on 2026-08-06.\n\n"
            f"{anchor_block(self.anchor_sha)}\n\n## 1. State\n"
        )
        self.repo.write(DOC, document)
        self.repo.commit("hide the sha from the reader")
        self.assert_red(contains="is never named in the document's visible text")

    def test_two_anchor_blocks_are_red(self) -> None:
        self.repo.write(DOC, plan_document(self.anchor_sha) + "\n" + anchor_block(self.anchor_sha) + "\n")
        self.repo.commit("add a second anchor")
        self.assert_red(contains="anchor blocks; exactly one is allowed")

    def test_unterminated_anchor_block_is_red(self) -> None:
        self.repo.write(
            DOC,
            f"# VPN plan\n\n`{self.anchor_sha}`\n\n<!-- doc-freshness-anchor\nmeasured: 2026-08-06\n"
            f"sha: {self.anchor_sha}\npaths:\n  - {ANCHORED_PATHS[0]}\n",
        )
        self.repo.commit("forget the closing marker")
        self.assert_red(contains="is not terminated")

    def test_stray_anchor_outside_the_enrollment_is_still_checked(self) -> None:
        stray = "docs/unenrolled-plan.md"
        self.repo.write(stray, plan_document(self.anchor_sha, paths=("admin/rust/server-rs/src/typo_*.rs",)))
        self.repo.commit("write an anchored document nobody enrolled")
        self.assert_red(contains=f"{stray}: anchor path(s) match no file")


class AnchorParsingTests(unittest.TestCase):
    """The anchor grammar, unit level. Malformed is a failure, never a default."""

    def parse(self, body: str) -> tuple[object, list[str]]:
        return gate.parse_anchor(f"<!-- doc-freshness-anchor\n{body}\n-->\n")

    def test_valid_anchor_parses(self) -> None:
        anchor, errors = self.parse(f"measured: 2026-08-06\nsha: {ABSENT_SHA}\npaths:\n  - src/a.rs\n  - src/b_*.rs")
        self.assertEqual([], errors)
        assert anchor is not None
        self.assertEqual(date(2026, 8, 6), anchor.measured)
        self.assertEqual(ABSENT_SHA, anchor.sha)
        self.assertEqual(("src/a.rs", "src/b_*.rs"), anchor.paths)

    def test_document_without_an_anchor_reports_absence_not_an_error(self) -> None:
        anchor, errors = gate.parse_anchor("# plain document\n")
        self.assertIsNone(anchor)
        self.assertEqual([], errors)

    def test_malformed_anchors_are_rejected(self) -> None:
        cases = (
            (f"sha: {ABSENT_SHA}\npaths:\n  - src/a.rs", "missing required key 'measured'"),
            ("measured: 2026-08-06\npaths:\n  - src/a.rs", "missing required key 'sha'"),
            (f"measured: 2026-08-06\nsha: {ABSENT_SHA}", "missing required key 'paths'"),
            (f"measured: 2026-08-06\nsha: {ABSENT_SHA}\npaths:", "must list at least one pathspec"),
            (f"measured: 2026-08-06\nsha: {ABSENT_SHA}\npaths: src/a.rs", "must be a list"),
            (f"measured: 2026-08-06\nsha: {ABSENT_SHA[:8]}\npaths:\n  - src/a.rs", "40-character commit SHA"),
            (f"measured: 06/08/2026\nsha: {ABSENT_SHA}\npaths:\n  - src/a.rs", "real calendar date"),
            (f"measured: 2026-02-30\nsha: {ABSENT_SHA}\npaths:\n  - src/a.rs", "real calendar date"),
            (f"measured: 2026-08-06\nsha: {ABSENT_SHA}\npath:\n  - src/a.rs", "unknown anchor key 'path'"),
            (
                f"measured: 2026-08-06\nmeasured: 2026-08-07\nsha: {ABSENT_SHA}\npaths:\n  - src/a.rs",
                "appears twice",
            ),
            (
                f"measured: 2026-08-06\nsha: {ABSENT_SHA}\npaths:\n  - :(exclude)src/a.rs",
                "pathspec magic",
            ),
            (f"measured: 2026-08-06\nsha: {ABSENT_SHA}\npaths:\n  - ../outside.rs", "escape the repository"),
            (f"measured: 2026-08-06\nsha: {ABSENT_SHA}\npaths:\n  - /abs/path.rs", "repository-relative"),
            (
                f"measured: 2026-08-06\nsha: {ABSENT_SHA}\npaths:\n  - src/a.rs\n  - src/a.rs",
                "is listed twice",
            ),
            (f"measured 2026-08-06\nsha: {ABSENT_SHA}\npaths:\n  - src/a.rs", "unparseable anchor line"),
        )
        for body, expected in cases:
            with self.subTest(expected=expected):
                anchor, errors = self.parse(body)
                self.assertIsNone(anchor)
                self.assertTrue(
                    any(expected in error for error in errors),
                    f"expected {expected!r} in {errors!r}",
                )


class EnrollmentTests(DocFreshnessTestCase):
    def test_required_document_missing_from_the_enrollment_is_red(self) -> None:
        self.assert_red(contains="missing from the enrollment file", required=("docs/other-plan.md",))

    def test_required_document_downgraded_to_exempt_is_red(self) -> None:
        self.repo.write(DOC, "# VPN plan\n\nno anchor\n")
        self.repo.write_enrollment(
            [
                {"path": DOC, "status": "exempt", "reason": "migrating", "expires": "2099-01-01"},
                {"path": "docs/second.md", "status": "anchored"},
            ]
        )
        self.repo.write("docs/second.md", plan_document(self.anchor_sha))
        self.repo.commit("downgrade the required document")
        self.assert_red(contains="must be enrolled as 'anchored'", required=(DOC,))

    def test_expired_exemption_is_red(self) -> None:
        self.repo.write("docs/second.md", "# second\n\nno anchor\n")
        self.repo.write_enrollment(
            [
                {"path": DOC, "status": "anchored"},
                {"path": "docs/second.md", "status": "exempt", "reason": "migrating", "expires": "2026-08-05"},
            ]
        )
        self.repo.commit("add an exemption")
        self.assert_red("--today", "2026-08-06", contains="exemption expired on 2026-08-05")

    def test_unexpired_exemption_passes_but_is_counted(self) -> None:
        self.repo.write("docs/second.md", "# second\n\nno anchor\n")
        self.repo.write_enrollment(
            [
                {"path": DOC, "status": "anchored"},
                {"path": "docs/second.md", "status": "exempt", "reason": "migrating", "expires": "2026-09-01"},
            ]
        )
        self.repo.commit("add an exemption")
        out = self.assert_green("--today", "2026-08-06")
        self.assertIn("1 exempt", out)

    def test_exempt_document_that_carries_an_anchor_is_red(self) -> None:
        self.repo.write("docs/second.md", plan_document(self.anchor_sha))
        self.repo.write_enrollment(
            [
                {"path": DOC, "status": "anchored"},
                {"path": "docs/second.md", "status": "exempt", "reason": "migrating", "expires": "2099-01-01"},
            ]
        )
        self.repo.commit("contradict the exemption")
        self.assert_red(contains="enrolled as exempt but carries an anchor")

    def test_exemption_without_reason_or_expiry_is_rejected(self) -> None:
        for entry, expected in (
            ({"path": "docs/second.md", "status": "exempt", "expires": "2099-01-01"}, "non-empty 'reason'"),
            ({"path": "docs/second.md", "status": "exempt", "reason": "x"}, "must carry an 'expires' date"),
            (
                {"path": "docs/second.md", "status": "exempt", "reason": "x", "expires": "soon"},
                "unparseable 'expires' date",
            ),
        ):
            with self.subTest(expected=expected):
                self.repo.write_enrollment([{"path": DOC, "status": "anchored"}, entry])
                code, out, err = self.run_gate()
                self.assertEqual(2, code)
                self.assertNotIn("OK:", out)
                self.assertIn(expected, err)

    def test_broken_enrollment_files_cannot_pass(self) -> None:
        enrollment = self.repo.root / "docs/doc-freshness-enrollment.json"
        cases = (
            ("not json at all", "not valid JSON"),
            ('["a"]', "must be a JSON object"),
            ('{"documents": []}', f"must declare schema '{gate.ENROLLMENT_SCHEMA}'"),
            (
                json.dumps({"schema": gate.ENROLLMENT_SCHEMA, "documents": [{"path": DOC, "status": "maybe"}]}),
                "must declare status",
            ),
            (
                json.dumps({"schema": gate.ENROLLMENT_SCHEMA, "documents": [{"path": DOC, "statuss": "anchored"}]}),
                "unknown keys",
            ),
            (
                json.dumps(
                    {
                        "schema": gate.ENROLLMENT_SCHEMA,
                        "documents": [{"path": DOC, "status": "anchored"}, {"path": DOC, "status": "anchored"}],
                    }
                ),
                "twice",
            ),
            (
                json.dumps({"schema": gate.ENROLLMENT_SCHEMA, "documents": [{"path": "../escape.md", "status": "anchored"}]}),
                "escape the repository",
            ),
        )
        for text, expected in cases:
            with self.subTest(expected=expected):
                enrollment.write_text(text, encoding="utf-8")
                code, out, err = self.run_gate()
                self.assertEqual(2, code, f"stdout={out} stderr={err}")
                self.assertNotIn("OK:", out)
                self.assertIn(expected, err)

    def test_deleted_enrollment_file_cannot_pass(self) -> None:
        (self.repo.root / "docs/doc-freshness-enrollment.json").unlink()
        code, out, err = self.run_gate()
        self.assertEqual(2, code)
        self.assertNotIn("OK:", out)
        self.assertIn("could not read enrollment file", err)

    def test_missing_scan_root_cannot_pass(self) -> None:
        code, out, err = self.run_gate("--scan-root", "no-such-directory")
        self.assertEqual(2, code)
        self.assertNotIn("OK:", out)
        self.assertIn("is not a directory", err)

    def test_unresolvable_ref_cannot_pass(self) -> None:
        code, out, err = self.run_gate("--ref", "refs/heads/does-not-exist")
        self.assertEqual(2, code)
        self.assertNotIn("OK:", out)
        self.assertIn("could not resolve --ref", err)

    def test_non_repository_cannot_pass(self) -> None:
        with tempfile.TemporaryDirectory() as plain:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = gate.main(["--repo-root", plain])
            self.assertEqual(2, code)
            self.assertNotIn("OK:", out.getvalue())
            self.assertIn("not a git work tree", err.getvalue())


class ShippedConfigurationTests(unittest.TestCase):
    def test_required_floor_is_never_empty(self) -> None:
        """Shrinking the floor must cost two edits, not one.

        The floor used to name the five VPN/commercial plans; they were retired
        on 2026-08-06 when the product was replanned, and this assertion moved
        with them rather than being deleted.

        Be precise about what an empty floor would and would not do, because an
        earlier draft of this docstring got it wrong and a wrong reason is more
        dangerous than no reason. Emptying REQUIRED_ANCHORED does NOT produce a
        passing gate: `load_enrollment` rejects an empty `documents` list, and
        `main` exits 2 on `checked == 0` with "a freshness gate that checks
        nothing is not a pass". Measured, not reasoned about. So this assertion
        is not what stands between the repo and that false green -- those two
        guards are, and they must not be removed on the belief that this test
        covers them.

        What this pins is narrower and still worth pinning: the floor names at
        least one document, and every entry looks like a docs markdown path. It
        is deliberately weaker than the named-set assertion it replaced, and the
        cost is real -- retargeting the floor at a one-pathspec stub now passes
        both this test and the gate, where the old assertion refused it. That
        trade was accepted because naming documents that no longer exist is a
        worse failure, but it is a trade, not a free simplification.
        """
        for path in gate.REQUIRED_ANCHORED:
            self.assertTrue(path.startswith("docs/"), path)
            self.assertTrue(path.endswith(".md"), path)
        if gate.REQUIRED_ANCHORED:
            return
        # The floor is empty, which is only tolerable while the deadline is
        # armed.  Pin BOTH halves: an empty floor with a deadline already in the
        # past is a red build somebody has to fix, and an empty floor with a
        # deadline pushed years out is the gate switched off in a way that looks
        # like it is on.  A year is generous for writing one plan and short
        # enough that nobody can park here.
        self.assertIsInstance(gate.PLAN_ENROLLMENT_DEADLINE, date)
        self.assertLess(
            gate.PLAN_ENROLLMENT_DEADLINE - date(2026, 8, 6),
            timedelta(days=365),
            "an empty floor may only be held open by a deadline under a year out",
        )

    def test_empty_floor_fails_once_the_deadline_passes(self) -> None:
        """The grace period must be a deadline, not a permanent pass.

        Without this, `report_replan_interregnum` is a function that returns 0
        and nothing proves the other branch is reachable -- the exact shape of a
        guard that stopped guarding.
        """
        before = gate.PLAN_ENROLLMENT_DEADLINE - timedelta(days=1)
        on_the_day = gate.PLAN_ENROLLMENT_DEADLINE
        after = gate.PLAN_ENROLLMENT_DEADLINE + timedelta(days=1)

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(0, gate.report_replan_interregnum(before))
            self.assertEqual(1, gate.report_replan_interregnum(on_the_day))
            self.assertEqual(1, gate.report_replan_interregnum(after))
        self.assertIn("fails on", out.getvalue())
        self.assertIn("grace period ended", err.getvalue())

    def test_shipped_enrollment_file_parses_and_enrolls_the_floor(self) -> None:
        enrollment = gate.REPO_ROOT / gate.DEFAULT_ENROLLMENT
        if not enrollment.exists():
            self.skipTest("enrollment file is not present in this checkout")
        entries, errors = gate.load_enrollment(enrollment)
        self.assertEqual([], errors)
        for required in gate.REQUIRED_ANCHORED:
            self.assertIn(required, entries)
            self.assertEqual(gate.STATUS_ANCHORED, entries[required].status)


class CommandLineTests(DocFreshnessTestCase):
    """One end-to-end run through the real entry point, for exit-code discipline.

    A subprocess cannot have REQUIRED_ANCHORED monkeypatched, so this repo has to
    satisfy the real floor. That is deliberate: it exercises the floor check
    through the shipped constant rather than a test-supplied stand-in.
    """

    def setUp(self) -> None:
        super().setUp()
        documents: list[dict[str, object]] = [{"path": DOC, "status": "anchored"}]
        for required in gate.REQUIRED_ANCHORED:
            self.repo.write(required, plan_document(self.anchor_sha))
            documents.append({"path": required, "status": "anchored"})
        self.repo.write_enrollment(documents)
        # The floor may legitimately be empty (see PLAN_ENROLLMENT_DEADLINE), in
        # which case this writes exactly what the base fixture already committed
        # and `git commit` fails with "nothing to commit" -- a fixture crash that
        # would read as a gate failure. Commit only when something changed.
        if self.repo.git("status", "--porcelain").strip():
            self.repo.commit("enroll the required floor")

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--repo-root", str(self.repo.root), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def test_cli_exit_codes(self) -> None:
        fresh = self.run_cli()
        self.assertEqual(0, fresh.returncode, fresh.stderr)
        self.assertIn("OK:", fresh.stdout)

        self.repo.write(CODE_FILE, "pub const DEFAULT_OFF: bool = false;\n")
        self.repo.commit("flip the default")
        stale = self.run_cli()
        self.assertEqual(1, stale.returncode)
        self.assertEqual("", stale.stdout)
        self.assertIn("doc-freshness finding", stale.stderr)

        (self.repo.root / "docs/doc-freshness-enrollment.json").write_text("{", encoding="utf-8")
        broken = self.run_cli()
        self.assertEqual(2, broken.returncode)
        self.assertEqual("", broken.stdout)

    def test_output_stays_repository_relative(self) -> None:
        self.repo.write(CODE_FILE, "pub const DEFAULT_OFF: bool = false;\n")
        self.repo.commit("flip the default")
        stale = self.run_cli()
        self.assertNotIn(str(self.repo.root), stale.stdout + stale.stderr)


if __name__ == "__main__":
    unittest.main()
