#!/usr/bin/env python3
"""Tests for scripts/check-branch-hygiene.py.

Every test builds a real git repository and drives the gate end to end. The
negative tests construct the defect the gate exists to catch and assert the
gate goes red; the paired positive tests construct the lookalike that must
stay green, because a predicate is only stated once both of its sides are
pinned.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-branch-hygiene.py")
SPEC = importlib.util.spec_from_file_location("check_branch_hygiene", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(repo), *args),
        capture_output=True,
        check=True,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(repo)},
    )
    return result.stdout.decode()


def write(repo: Path, path: str, body: str) -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")


def commit(repo: Path, message: str) -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


def lines(prefix: str, count: int) -> str:
    return "".join(f"{prefix} line {index}\n" for index in range(count))


class RepoFixture:
    """A repository with a crate component, a main line of work and a remote."""

    def __init__(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="branch-hygiene-"))
        self.repo = self.dir / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "config", "user.email", "gate@example.invalid")
        git(self.repo, "config", "user.name", "Gate Test")
        git(self.repo, "config", "commit.gpgsign", "false")

        write(self.repo, "crate-a/Cargo.toml", '[package]\nname = "crate-a"\n')
        write(self.repo, "crate-a/src/lib.rs", lines("base", 5))
        write(self.repo, "crate-a/src/legacy.rs", lines("legacy", 20))
        write(self.repo, "crate-b/Cargo.toml", '[package]\nname = "crate-b"\n')
        write(self.repo, "crate-b/src/lib.rs", lines("b-base", 5))
        commit(self.repo, "base")
        self.base = git(self.repo, "rev-parse", "HEAD").strip()

    def advance_main(self) -> None:
        """main ships a new file in crate-a and grows an existing one."""
        write(self.repo, "crate-a/src/ffi.rs", lines("shipped-ffi", 40))
        write(self.repo, "crate-a/src/lib.rs", lines("base", 5) + lines("shipped", 30))
        commit(self.repo, "ship crate-a ffi")

    def branch_from_base(self, name: str) -> None:
        git(self.repo, "checkout", "-q", "-b", name, self.base)

    def checkout_main(self) -> None:
        git(self.repo, "checkout", "-q", "main")

    def publish(self, name: str) -> None:
        """Give a branch a remote copy without needing a real remote."""
        oid = git(self.repo, "rev-parse", name).strip()
        git(self.repo, "update-ref", f"refs/remotes/origin/{name}", oid)

    def publish_main(self) -> None:
        self.publish("main")

    def pr_state_file(self, entries: list[dict]) -> str:
        path = self.dir / "prs.json"
        path.write_text(json.dumps(entries), encoding="utf-8")
        return str(path)

    def run(self, *argv: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = gate.main(["--repo", str(self.repo), "--main-ref", "origin/main", *argv])
        return code, stdout.getvalue(), stderr.getvalue()

    def cleanup(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


class BranchHygieneTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RepoFixture()
        self.addCleanup(self.fixture.cleanup)
        self.no_prs = self.fixture.pr_state_file([])


class RevertingPredicateTests(BranchHygieneTestCase):
    """Both sides of 'merging this would delete work the main ref has'."""

    def test_negative_branch_missing_a_file_main_shipped_in_its_component_is_red(self) -> None:
        # The defect: a branch named for delivered work that predates the file
        # carrying it. It touches crate-a, so it presents itself as crate-a's
        # state, but has no copy of crate-a/src/ffi.rs at all.
        fixture = self.fixture
        fixture.branch_from_base("feat/crate-a-network-settings")
        write(fixture.repo, "crate-a/src/settings.rs", lines("branch-settings", 4))
        commit(fixture.repo, "branch adds settings")
        fixture.checkout_main()
        fixture.advance_main()
        fixture.publish_main()
        fixture.publish("feat/crate-a-network-settings")

        code, out, err = fixture.run(
            "--branch",
            "feat/crate-a-network-settings",
            "--pr-state-file",
            self.no_prs,
        )

        self.assertEqual(
            1,
            code,
            "a branch that never had the file main shipped in a component it touches "
            "must fail: merging it as that component's state deletes shipped work",
        )
        self.assertIn("would delete", err)
        self.assertIn("crate-a/src/ffi.rs", err + out)
        self.assertIn("branch has no copy of this file", out)

    def test_positive_branch_deliberately_deleting_old_code_is_green(self) -> None:
        # The lookalike, built so the overlap computation actually runs: the
        # path IS in scope (the branch touches it, main changed it after the
        # fork), main's change is a pure deletion, and the branch's own removal
        # is of lines that existed at the merge base.
        #
        #   base   legacy.rs = lines 0..19
        #   branch legacy.rs = lines 10..19   (deliberately drops 0..9)
        #   main   legacy.rs = lines 0..18    (drops 19; adds nothing)
        #
        # main holds lines 0..9 that the branch lacks, but it did not ADD them
        # after the fork -- the branch removed them on purpose. Reverted = 0.
        fixture = self.fixture
        fixture.branch_from_base("chore/drop-legacy")
        kept = "".join(f"legacy line {index}\n" for index in range(10, 20))
        write(fixture.repo, "crate-a/src/legacy.rs", kept)
        commit(fixture.repo, "drop the first half of the legacy module")
        fixture.checkout_main()
        trimmed = "".join(f"legacy line {index}\n" for index in range(0, 19))
        write(fixture.repo, "crate-a/src/legacy.rs", trimmed)
        commit(fixture.repo, "main trims one legacy line and adds nothing")
        fixture.publish_main()
        fixture.publish("chore/drop-legacy")

        base = git(fixture.repo, "merge-base", "main", "chore/drop-legacy").strip()
        self.assertEqual(
            fixture.base,
            base,
            "precondition: the branch must have diverged, or the scope is empty "
            "and this test would pass without exercising the predicate",
        )
        self.assertIn(
            "crate-a/src/legacy.rs",
            git(fixture.repo, "diff", "--name-only", base, "main"),
            "precondition: main must have changed the path, or it is out of scope",
        )

        code, out, err = fixture.run("--branch", "chore/drop-legacy", "--pr-state-file", self.no_prs)

        self.assertEqual(
            0,
            code,
            "deleting code that existed at the merge base is the branch's own "
            "decision; only lines main ADDED after the fork count as reverted. "
            f"stderr={err}",
        )
        self.assertIn("OK: no branch in the fail scope reverts the main ref", out)

    def test_positive_branch_stale_only_outside_the_components_it_touches_is_green(self) -> None:
        # The other lookalike: the branch is behind main, but only in crate-a,
        # which it never touches. A three-way merge keeps main's crate-a.
        fixture = self.fixture
        fixture.branch_from_base("feat/crate-b-only")
        write(fixture.repo, "crate-b/src/extra.rs", lines("b-extra", 4))
        commit(fixture.repo, "branch touches crate-b only")
        fixture.checkout_main()
        fixture.advance_main()
        fixture.publish_main()
        fixture.publish("feat/crate-b-only")

        code, out, err = fixture.run("--branch", "feat/crate-b-only", "--pr-state-file", self.no_prs)

        self.assertEqual(
            0,
            code,
            "staleness in a component the branch never touches is not a hazard; "
            f"flagging it would make every unrebased branch red. stderr={err}",
        )
        self.assertIn("OK: no branch in the fail scope reverts the main ref", out)

    def test_negative_branch_with_an_older_copy_of_a_grown_file_is_red(self) -> None:
        # Second defect shape: the branch has crate-a/src/lib.rs, but its copy
        # predates the 30 lines main added.
        fixture = self.fixture
        fixture.branch_from_base("feat/crate-a-tweak")
        write(fixture.repo, "crate-a/src/lib.rs", lines("base", 5) + "branch tweak\n")
        commit(fixture.repo, "branch tweaks lib.rs")
        fixture.checkout_main()
        fixture.advance_main()
        fixture.publish_main()
        fixture.publish("feat/crate-a-tweak")

        code, out, err = fixture.run("--branch", "feat/crate-a-tweak", "--pr-state-file", self.no_prs)

        self.assertEqual(1, code, f"an older copy of a file main grew must fail. stdout={out}")
        self.assertIn("crate-a/src/lib.rs", out + err)
        self.assertIn("branch has an older copy", out)

    def test_positive_rebased_branch_is_green(self) -> None:
        # The remedy the gate prescribes must actually clear it.
        fixture = self.fixture
        fixture.branch_from_base("feat/crate-a-rebased")
        write(fixture.repo, "crate-a/src/settings.rs", lines("branch-settings", 4))
        commit(fixture.repo, "branch adds settings")
        fixture.checkout_main()
        fixture.advance_main()
        git(fixture.repo, "checkout", "-q", "feat/crate-a-rebased")
        git(fixture.repo, "rebase", "-q", "main")
        fixture.checkout_main()
        fixture.publish_main()
        fixture.publish("feat/crate-a-rebased")

        code, out, err = fixture.run("--branch", "feat/crate-a-rebased", "--pr-state-file", self.no_prs)

        self.assertEqual(0, code, f"rebasing is the prescribed fix and must clear the gate. stderr={err}")
        self.assertIn("OK: no branch in the fail scope reverts the main ref", out)

    def test_reverting_branch_outside_the_fail_scope_is_reported_not_failed(self) -> None:
        fixture = self.fixture
        fixture.branch_from_base("feat/crate-a-network-settings")
        write(fixture.repo, "crate-a/src/settings.rs", lines("branch-settings", 4))
        commit(fixture.repo, "branch adds settings")
        fixture.checkout_main()
        fixture.advance_main()
        fixture.publish_main()
        fixture.publish("feat/crate-a-network-settings")
        git(fixture.repo, "checkout", "-q", "-b", "review/current", "main")
        fixture.publish("review/current")

        code, out, _ = fixture.run("--branch", "review/current", "--pr-state-file", self.no_prs)

        self.assertEqual(0, code, "sprawl is reported at exit 0; only the fail scope is enforced")
        self.assertIn("feat/crate-a-network-settings: would delete", out)

    def test_fail_scope_all_enforces_every_branch(self) -> None:
        fixture = self.fixture
        fixture.branch_from_base("feat/crate-a-network-settings")
        write(fixture.repo, "crate-a/src/settings.rs", lines("branch-settings", 4))
        commit(fixture.repo, "branch adds settings")
        fixture.checkout_main()
        fixture.advance_main()
        fixture.publish_main()
        fixture.publish("feat/crate-a-network-settings")

        code, _, err = fixture.run("--fail-scope", "all", "--pr-state-file", self.no_prs)

        self.assertEqual(1, code)
        self.assertIn("feat/crate-a-network-settings", err)

    def test_fail_scope_open_pr_ignores_a_reverting_branch_with_no_open_pr(self) -> None:
        fixture = self.fixture
        fixture.branch_from_base("feat/crate-a-network-settings")
        write(fixture.repo, "crate-a/src/settings.rs", lines("branch-settings", 4))
        commit(fixture.repo, "branch adds settings")
        fixture.checkout_main()
        fixture.advance_main()
        fixture.publish_main()
        fixture.publish("feat/crate-a-network-settings")

        closed = fixture.pr_state_file(
            [{"number": 7, "headRefName": "feat/crate-a-network-settings", "state": "CLOSED"}]
        )
        code, out, _ = fixture.run("--fail-scope", "open-pr", "--pr-state-file", closed)
        self.assertEqual(0, code)
        self.assertIn("feat/crate-a-network-settings: would delete", out)

        opened = fixture.pr_state_file(
            [{"number": 7, "headRefName": "feat/crate-a-network-settings", "state": "OPEN"}]
        )
        code, _, err = fixture.run("--fail-scope", "open-pr", "--pr-state-file", opened)
        self.assertEqual(1, code, "the same branch with an OPEN PR is a live merge candidate and must fail")
        self.assertIn("feat/crate-a-network-settings", err)


class SquashMergeClassificationTests(BranchHygieneTestCase):
    def test_squash_merged_branch_is_invisible_to_the_commit_graph_but_reported(self) -> None:
        fixture = self.fixture
        fixture.branch_from_base("feat/squashed")
        # Two commits, so the squash collapses them into one new patch. A
        # single-commit branch would squash to an identical patch and patch-id
        # WOULD still catch it; the invisible case is the multi-commit one.
        write(fixture.repo, "crate-b/src/extra.rs", lines("b-extra", 4))
        commit(fixture.repo, "branch work part one")
        write(fixture.repo, "crate-b/src/extra.rs", lines("b-extra", 4) + lines("b-more", 4))
        commit(fixture.repo, "branch work part two")
        fixture.checkout_main()
        git(fixture.repo, "merge", "-q", "--squash", "feat/squashed")
        commit(fixture.repo, "squash merge of feat/squashed")
        fixture.publish_main()
        fixture.publish("feat/squashed")

        merged_by_graph = git(fixture.repo, "for-each-ref", "--format=%(refname)", "--merged", "main", "refs/heads")
        self.assertNotIn(
            "refs/heads/feat/squashed",
            merged_by_graph,
            "precondition: the commit graph must NOT see the squash merge, "
            "otherwise this test proves nothing about the classifier",
        )
        cherry = git(fixture.repo, "cherry", "main", "feat/squashed")
        self.assertTrue(
            any(line.startswith("+") for line in cherry.splitlines()),
            "precondition: patch-id must also miss a squash merge",
        )

        prs = fixture.pr_state_file([{"number": 42, "headRefName": "feat/squashed", "state": "MERGED"}])
        code, out, _ = fixture.run("--branch", "main", "--pr-state-file", prs)

        self.assertEqual(0, code)
        self.assertIn("REPORT: merged #42 still present", out)
        self.assertIn("feat/squashed", out)
        self.assertIn("'git branch --merged' misses 2 of them", out)

    def test_zero_unique_commits_branch_is_reported_as_a_husk(self) -> None:
        fixture = self.fixture
        git(fixture.repo, "branch", "stale/copy-of-main")
        fixture.publish_main()
        fixture.publish("stale/copy-of-main")

        code, out, _ = fixture.run("--branch", "main", "--pr-state-file", self.no_prs)

        self.assertEqual(0, code)
        self.assertIn("REPORT: no unique patch", out)
        self.assertIn("stale/copy-of-main", out)


class WorktreeTests(BranchHygieneTestCase):
    def test_untracked_only_worktree_is_dirty_and_never_disposable(self) -> None:
        # The defect this pins: six VPN documents existing nowhere else were
        # found untracked inside a worktree that a modified-files-only check
        # would have called clean.
        fixture = self.fixture
        git(fixture.repo, "branch", "wt/husk")
        fixture.publish_main()
        fixture.publish("wt/husk")
        worktree = fixture.dir / "wt-husk"
        git(fixture.repo, "worktree", "add", "-q", str(worktree), "wt/husk")
        (worktree / "vpn-notes.md").write_text("only copy of this document\n", encoding="utf-8")

        self.assertEqual(
            "",
            git(worktree, "status", "--porcelain=v1").strip().replace("?? vpn-notes.md", "").strip(),
            "precondition: the only change is untracked",
        )

        code, out, _ = fixture.run("--branch", "main", "--pr-state-file", self.no_prs)

        self.assertEqual(0, code)
        self.assertIn("worktree DIRTY, never disposable", out)
        self.assertIn("untracked files 1", out)
        self.assertNotIn("wt-husk: ", out.split("==> local-only-work-at-risk")[0].replace("DIRTY", ""))
        disposable_lines = [line for line in out.splitlines() if "clean and its branch has no unique patch" in line]
        self.assertEqual(
            [],
            [line for line in disposable_lines if "wt-husk" in line],
            "a worktree holding untracked files must never appear as disposable",
        )

    def test_clean_worktree_on_a_husk_branch_is_reported_disposable(self) -> None:
        fixture = self.fixture
        git(fixture.repo, "branch", "wt/husk")
        fixture.publish_main()
        fixture.publish("wt/husk")
        worktree = fixture.dir / "wt-husk"
        git(fixture.repo, "worktree", "add", "-q", str(worktree), "wt/husk")

        code, out, _ = fixture.run("--branch", "main", "--pr-state-file", self.no_prs)

        self.assertEqual(0, code)
        self.assertIn("worktree clean and its branch has no unique patch", out)

    def test_primary_worktree_is_never_disposable(self) -> None:
        # The checkout you are standing in is not spare capacity, however
        # clean it is and however few unique commits its branch carries.
        fixture = self.fixture
        fixture.publish_main()

        code, out, _ = fixture.run("--branch", "main", "--pr-state-file", self.no_prs)

        self.assertEqual(0, code)
        self.assertIn("REPORT: no unique patch (local): main", out)
        self.assertIn("INFO: primary worktree, never disposable", out)
        self.assertIn("INFO: worktrees with no uncommitted work and no unique patch: 0", out)

    def test_clean_worktree_on_a_branch_with_unique_work_is_not_disposable(self) -> None:
        # Disposable needs BOTH conditions. A clean worktree whose branch still
        # carries unique work is not spare capacity.
        fixture = self.fixture
        fixture.publish_main()
        git(fixture.repo, "checkout", "-q", "-b", "wt/live", "main")
        write(fixture.repo, "crate-b/src/live.rs", lines("live", 3))
        commit(fixture.repo, "unique work on the worktree branch")
        fixture.publish("wt/live")
        fixture.checkout_main()
        worktree = fixture.dir / "wt-live"
        git(fixture.repo, "worktree", "add", "-q", str(worktree), "wt/live")

        self.assertEqual(
            "",
            git(worktree, "status", "--porcelain=v1").strip(),
            "precondition: the worktree must be clean, or dirtiness alone would explain the result",
        )

        code, out, _ = fixture.run("--branch", "main", "--pr-state-file", self.no_prs)

        self.assertEqual(0, code)
        disposable = [line for line in out.splitlines() if "clean and its branch has no unique patch" in line]
        self.assertEqual(
            [],
            [line for line in disposable if "wt-live" in line],
            "a worktree whose branch has unique commits must never be called disposable",
        )
        self.assertIn("INFO: worktrees with no uncommitted work and no unique patch: 0", out)

    def test_no_absolute_path_outside_the_repository_is_printed(self) -> None:
        fixture = self.fixture
        git(fixture.repo, "branch", "wt/husk")
        fixture.publish_main()
        fixture.publish("wt/husk")
        worktree = fixture.dir / "wt-husk"
        git(fixture.repo, "worktree", "add", "-q", str(worktree), "wt/husk")

        code, out, err = fixture.run("--branch", "main", "--pr-state-file", self.no_prs)

        self.assertEqual(0, code)
        self.assertNotIn(str(fixture.dir), out + err)
        self.assertNotIn(str(fixture.repo), out + err)
        self.assertIn("<external>/wt-husk", out)


class LocalOnlyWorkTests(BranchHygieneTestCase):
    def test_local_branch_with_no_remote_copy_is_reported_loudly(self) -> None:
        fixture = self.fixture
        fixture.publish_main()
        git(fixture.repo, "checkout", "-q", "-b", "local/only-copy", "main")
        write(fixture.repo, "crate-b/src/precious.rs", lines("precious", 3))
        commit(fixture.repo, "work that exists nowhere else")
        fixture.checkout_main()

        code, out, _ = fixture.run("--branch", "main", "--pr-state-file", self.no_prs)

        self.assertEqual(0, code)
        self.assertIn("LOSS-RISK: local/only-copy", out)
        self.assertIn("One 'git branch -D' from permanent loss", out)

    def test_local_branch_with_a_remote_copy_is_not_reported_at_risk(self) -> None:
        fixture = self.fixture
        fixture.publish_main()
        git(fixture.repo, "checkout", "-q", "-b", "local/pushed", "main")
        write(fixture.repo, "crate-b/src/pushed.rs", lines("pushed", 3))
        commit(fixture.repo, "work that is also on the remote")
        fixture.publish("local/pushed")
        fixture.checkout_main()

        code, out, _ = fixture.run("--branch", "main", "--pr-state-file", self.no_prs)

        self.assertEqual(0, code)
        self.assertNotIn("LOSS-RISK: local/pushed", out)
        self.assertIn("INFO: local branches whose work exists on no remote: 0", out)


class FailClosedTests(BranchHygieneTestCase):
    def test_missing_pr_state_file_is_an_error(self) -> None:
        fixture = self.fixture
        fixture.publish_main()
        code, _, err = fixture.run("--branch", "main", "--pr-state-file", str(fixture.dir / "absent.json"))
        self.assertEqual(2, code)
        self.assertIn("could not read PR state file", err)

    def test_unparseable_pr_state_is_an_error(self) -> None:
        fixture = self.fixture
        fixture.publish_main()
        broken = fixture.dir / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        code, _, err = fixture.run("--branch", "main", "--pr-state-file", str(broken))
        self.assertEqual(2, code)
        self.assertIn("not valid JSON", err)

    def test_pr_state_entry_without_a_head_ref_is_an_error(self) -> None:
        fixture = self.fixture
        fixture.publish_main()
        path = fixture.pr_state_file([{"number": 1, "state": "MERGED"}])
        code, _, err = fixture.run("--branch", "main", "--pr-state-file", path)
        self.assertEqual(2, code)
        self.assertIn("headRefName", err)

    def test_unknown_main_ref_is_an_error(self) -> None:
        fixture = self.fixture
        code, _, err = fixture.run("--branch", "main", "--pr-state-file", self.no_prs)
        self.assertEqual(2, code, "origin/main was never published: the gate must not proceed")
        self.assertIn("ref could not be resolved", err)

    def test_repository_with_no_branches_is_an_error(self) -> None:
        # A search that finds nothing must not be reported as clean. Strip the
        # repository down to the main ref alone so discovery genuinely returns
        # an empty set.
        fixture = self.fixture
        fixture.publish_main()
        git(fixture.repo, "checkout", "-q", "--detach", "main")
        git(fixture.repo, "branch", "-q", "-D", "main")

        self.assertEqual(
            [],
            gate.discover_branches(fixture.repo, "refs/remotes/origin/main", 60),
            "precondition: discovery must really be empty, or this proves nothing",
        )

        with self.assertRaises(gate.GateError) as raised:
            gate.analyze(fixture.repo, "refs/remotes/origin/main", 60, {})
        self.assertIn("refusing to report", str(raised.exception))

        code, _, err = fixture.run(
            "--main-ref",
            "refs/remotes/origin/main",
            "--branch",
            "main",
            "--pr-state-file",
            self.no_prs,
        )
        self.assertEqual(2, code)
        self.assertIn("ERROR:", err)

    def test_git_failure_is_an_error_not_an_empty_result(self) -> None:
        # This is the bug that produced a silent all-green during development:
        # a git invocation that failed, whose stderr was swallowed, and whose
        # empty stdout parsed as "nothing reverted".
        with self.assertRaises(gate.GateError) as raised:
            gate.git(self.fixture.repo, "diff", "--no-such-flag")
        self.assertIn("failed with exit", str(raised.exception))

    def test_git_timeout_is_an_error(self) -> None:
        with self.assertRaises(gate.GateError) as raised:
            gate.run_git(self.fixture.repo, "log", "--all", timeout=0)
        self.assertIn("timed out", str(raised.exception))

    def test_detached_head_without_a_branch_argument_is_an_error(self) -> None:
        fixture = self.fixture
        fixture.publish_main()
        git(fixture.repo, "checkout", "-q", "--detach", "main")
        code, _, err = fixture.run("--pr-state-file", self.no_prs)
        self.assertEqual(2, code)
        self.assertIn("HEAD is detached", err)

    def test_unknown_selected_branch_is_an_error(self) -> None:
        fixture = self.fixture
        fixture.publish_main()
        code, _, err = fixture.run("--branch", "no/such/branch", "--pr-state-file", self.no_prs)
        self.assertEqual(2, code)
        self.assertIn("could not be resolved", err)

    def test_unavailable_pr_state_never_reports_a_clean_classification(self) -> None:
        fixture = self.fixture
        fixture.publish_main()
        original = gate.shutil.which
        gate.shutil.which = lambda _name: None
        try:
            code, _, err = fixture.run("--branch", "main")
            self.assertEqual(2, code, "an unavailable gh must fail closed by default")
            self.assertIn("gh unavailable", err)

            code, out, _ = fixture.run("--branch", "main", "--allow-missing-pr-state")
        finally:
            gate.shutil.which = original
        self.assertEqual(0, code)
        self.assertIn("classification is INCOMPLETE, not clean", out)
        self.assertIn("cannot classify: PR state unavailable", out)
        self.assertNotIn("merged-PR branches still present: 0", out)


class PredicateUnitTests(unittest.TestCase):
    def test_component_of_prefers_the_nearest_manifest_root(self) -> None:
        roots = ("admin/rust/household-rs", "admin/rust")
        self.assertEqual("admin/rust/household-rs", gate.component_of("admin/rust/household-rs/src/lib.rs", roots))
        self.assertEqual("admin/rust", gate.component_of("admin/rust/Cargo.lock", roots))

    def test_component_of_falls_back_without_a_manifest(self) -> None:
        self.assertEqual("docs/product-a", gate.component_of("docs/product-a/plan.md", ()))
        self.assertEqual("docs", gate.component_of("docs/plan.md", ()))
        self.assertEqual("<repo-root>", gate.component_of("README.md", ()))

    def test_added_lines_parser_treats_hunk_content_as_content(self) -> None:
        # A content line that looks like a diff header must not be read as one.
        fixture = RepoFixture()
        self.addCleanup(fixture.cleanup)
        write(fixture.repo, "crate-b/src/tricky.rs", "")
        commit(fixture.repo, "empty tricky")
        first = git(fixture.repo, "rev-parse", "HEAD").strip()
        write(fixture.repo, "crate-b/src/tricky.rs", "+++ b/decoy\n@@ decoy\nreal line\n")
        commit(fixture.repo, "tricky content")
        second = git(fixture.repo, "rev-parse", "HEAD").strip()

        added = gate.added_lines_by_path(fixture.repo, first, second, ["crate-b/src/tricky.rs"], 60)
        counter = added["crate-b/src/tricky.rs"]
        self.assertEqual(3, sum(counter.values()), f"all three content lines belong to the file: {counter}")
        self.assertIn("real line", counter)
        self.assertNotIn("decoy", counter)


if __name__ == "__main__":
    unittest.main()
