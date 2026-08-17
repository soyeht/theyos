#!/usr/bin/env python3
"""Adversarial tests for safe_external_write.py."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("safe_external_write.py")
SPEC = importlib.util.spec_from_file_location("safe_external_write", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
guard = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = guard
SPEC.loader.exec_module(guard)


class MentionSyntaxTests(unittest.TestCase):
    def test_blocks_current_future_and_markdown_mentions(self) -> None:
        cases = (
            "@khai",
            "@Khai",
            "(@zelia)",
            "`@khai`",
            "@future-agent-2027",
            "line one\n@delia",
            "email foo@bar.com and @gloria",
            "-@ilia",
            "+@ilia",
            ".@ilia",
            "_@ilia",
            "|@delia|",
            "**@gloria**",
            ">@saira",
        )
        for payload in cases:
            with self.subTest(payload=payload):
                self.assertTrue(guard.find_mentions(payload))

    def test_preserves_email_mailto_math_and_bare_at(self) -> None:
        cases = (
            "noreply@anthropic.com",
            "caio.salgado@gmail.com",
            "foo+bar@example.com",
            "foo-bar@example.com",
            "10@unidade",
            "[mail](mailto:x@y.com)",
            "5 @ 3 euros",
            "trailing @",
        )
        for payload in cases:
            with self.subTest(payload=payload):
                self.assertEqual((), guard.find_mentions(payload))

    def test_known_false_positives_fail_closed(self) -> None:
        cases = (
            "docs/@types/index.d.ts",
            "foo.@example.com",
            "foo-@example.com",
            "foo_@example.com",
        )
        for payload in cases:
            with self.subTest(payload=payload):
                self.assertTrue(guard.find_mentions(payload))

    def test_blocks_entity_encoded_mentions_that_can_be_copied_from_rendered_text(self) -> None:
        cases = (
            "&#64;khai",
            "&#064;khai",
            "&#x40;khai",
            "&#x040;khai",
            "&#X40;Khai",
            "&#64khai",
            "&#x40khai",
            "&commat;khai",
        )
        for payload in cases:
            with self.subTest(payload=payload):
                self.assertTrue(guard.find_mentions(payload))

    def test_entity_encoded_email_is_not_a_mention(self) -> None:
        self.assertEqual((), guard.find_mentions("noreply&#64;example.com"))

    def test_allowlist_is_case_insensitive_and_does_not_hide_another_mention(self) -> None:
        self.assertEqual((), guard.find_mentions("@Khai", frozenset({"khai"})))
        found = guard.find_mentions("@Khai and @ilia", frozenset({"khai"}))
        self.assertEqual(("ilia",), tuple(item.username for item in found))

    def test_locations_are_one_based(self) -> None:
        found = guard.find_mentions("safe\n  @khai")
        self.assertEqual((guard.Mention(username="khai", line=2, column=3),), found)


class ExecutionBoundaryTests(unittest.TestCase):
    def _payload_file(self, body: str) -> str:
        tmp = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False)
        self.addCleanup(Path(tmp.name).unlink, missing_ok=True)
        with tmp:
            tmp.write(body)
        return tmp.name

    def test_rejected_payload_never_executes_child(self) -> None:
        payload = self._payload_file("credit @khai")
        stderr = io.StringIO()
        with mock.patch.object(guard.subprocess, "run") as run, contextlib.redirect_stderr(stderr):
            code = guard.main(["--payload-file", payload, "--", "gh", "issue", "comment"])
        self.assertEqual(2, code)
        run.assert_not_called()
        self.assertIn("BLOCKED", stderr.getvalue())

    def _stdin(self, body: bytes) -> mock.Mock:
        stream = mock.Mock()
        stream.buffer.read.return_value = body
        return stream

    def test_payload_file_is_check_only_and_cannot_execute_child(self) -> None:
        payload = self._payload_file("credit agent-khai")
        stderr = io.StringIO()
        with mock.patch.object(guard.subprocess, "run") as run, contextlib.redirect_stderr(stderr):
            code = guard.main(["--payload-file", payload, "--", "gh", "issue", "comment"])
        self.assertEqual(2, code)
        run.assert_not_called()
        self.assertIn("requires --stdin", stderr.getvalue())

    def test_clean_stdin_executes_exact_child_and_propagates_status(self) -> None:
        payload = b"credit agent-khai"
        completed = mock.Mock(returncode=17)
        with (
            mock.patch.object(guard.sys, "stdin", self._stdin(payload)),
            mock.patch.object(guard.subprocess, "run", return_value=completed) as run,
        ):
            code = guard.main(["--stdin", "--", "gh", "issue", "comment", "123"])
        self.assertEqual(17, code)
        run.assert_called_once_with(
            ["gh", "issue", "comment", "123", "--body-file", "-"],
            input=payload,
            check=False,
            env=mock.ANY,
        )
        child_env = run.call_args.kwargs["env"]
        self.assertEqual("github.com", child_env["GH_HOST"])
        self.assertEqual("soyeht/theyos", child_env["GH_REPO"])

    def test_mention_in_command_argument_blocks_clean_stdin(self) -> None:
        payload = b"clean body"
        with (
            mock.patch.object(guard.sys, "stdin", self._stdin(payload)),
            mock.patch.object(guard.subprocess, "run") as run,
        ):
            code = guard.main(["--stdin", "--", "gh", "pr", "create", "--title", "credit @khai"])
        self.assertEqual(2, code)
        run.assert_not_called()

    def test_rejects_unvalidated_body_file_channel(self) -> None:
        payload = b"clean body"
        with (
            mock.patch.object(guard.sys, "stdin", self._stdin(payload)),
            mock.patch.object(guard.subprocess, "run") as run,
        ):
            code = guard.main(
                [
                    "--stdin",
                    "--",
                    "gh",
                    "issue",
                    "comment",
                    "123",
                    "--body-file",
                    "/tmp/unvalidated",
                ]
            )
        self.assertEqual(2, code)
        run.assert_not_called()

    def test_rejects_short_body_file_alias(self) -> None:
        payload = b"clean body"
        with (
            mock.patch.object(guard.sys, "stdin", self._stdin(payload)),
            mock.patch.object(guard.subprocess, "run") as run,
        ):
            code = guard.main(
                ["--stdin", "--", "gh", "issue", "edit", "123", "-F", "/tmp/unvalidated"]
            )
        self.assertEqual(2, code)
        run.assert_not_called()

    def test_rejects_shell_and_environment_indirection(self) -> None:
        payload = b"clean body"
        with (
            mock.patch.object(guard.sys, "stdin", self._stdin(payload)),
            mock.patch.object(guard.subprocess, "run") as run,
        ):
            code = guard.main(["--stdin", "--", "sh", "-c", "gh pr edit 1 --body $BODY"])
        self.assertEqual(2, code)
        run.assert_not_called()

    def test_git_commit_adapter_injects_message_stdin(self) -> None:
        payload = b"safe commit message"
        completed = mock.Mock(returncode=0)
        with (
            mock.patch.object(guard.sys, "stdin", self._stdin(payload)),
            mock.patch.object(guard.subprocess, "run", return_value=completed) as run,
        ):
            code = guard.main(["--stdin", "--", "git", "commit"])
        self.assertEqual(0, code)
        run.assert_called_once_with(
            ["git", "commit", "-F", "-"], input=payload, check=False, env=None
        )

    def test_rejects_alternate_git_message_channel(self) -> None:
        payload = b"safe commit message"
        with (
            mock.patch.object(guard.sys, "stdin", self._stdin(payload)),
            mock.patch.object(guard.subprocess, "run") as run,
        ):
            code = guard.main(["--stdin", "--", "git", "commit", "-F", "/tmp/unsafe"])
        self.assertEqual(2, code)
        run.assert_not_called()

    def test_closed_grammar_rejects_other_payload_sources_and_push(self) -> None:
        cases = (
            ["gh", "pr", "edit", "489", "--body-file=/tmp/unvalidated"],
            ["gh", "pr", "edit", "489", "-b", "unvalidated"],
            ["gh", "pr", "create", "--fill"],
            ["gh", "pr", "create", "--template", "/tmp/unvalidated"],
            ["gh", "issue", "create", "--recover", "draft"],
            ["gh", "api", "repos/example/repo/issues", "--input", "/tmp/unvalidated"],
            ["git", "commit", "-m", "unvalidated"],
            ["git", "push"],
            ["gh", "issue", "create", "--title", "safe", "--repo", "other/repo"],
        )
        for command in cases:
            with self.subTest(command=command):
                with self.assertRaises(guard.UnsafeCommand):
                    guard.prepare_command(command)

    def test_general_github_writers_accept_only_same_repo_decimal_targets(self) -> None:
        cases = (
            ["gh", "pr", "edit", "16", "--title", "safe"],
            ["gh", "pr", "review", "16", "--approve"],
            ["gh", "pr", "comment", "16"],
            ["gh", "issue", "edit", "16", "--title", "safe"],
            ["gh", "issue", "comment", "16"],
        )
        for command in cases:
            with self.subTest(command=command):
                prepared = guard.prepare_command(command)
                self.assertIn("16", prepared)
                self.assertEqual(["--body-file", "-"], prepared[-2:])

    def test_general_github_writers_reject_cross_repo_and_ref_targets(self) -> None:
        command_prefixes = (
            (["gh", "pr", "edit"], ["--title", "safe"]),
            (["gh", "pr", "review"], ["--approve"]),
            (["gh", "pr", "comment"], []),
            (["gh", "issue", "edit"], ["--title", "safe"]),
            (["gh", "issue", "comment"], []),
        )
        targets = (
            "https://github.com/soyeht/soyeht-ios/pull/16",
            "soyeht/soyeht-ios#16",
            "refs/pull/16/head",
            "ci/governed-macos-release",
            "016",
            "0",
        )
        for prefix, suffix in command_prefixes:
            for target in targets:
                with self.subTest(command=prefix, target=target):
                    with self.assertRaises(guard.UnsafeCommand):
                        guard.prepare_command([*prefix, target, *suffix])

    def test_cross_repo_targets_fail_before_any_mutation(self) -> None:
        commands = (
            [
                "gh",
                "pr",
                "edit",
                "https://github.com/soyeht/soyeht-ios/pull/16",
                "--title",
                "safe",
            ],
            [
                "gh",
                "pr",
                "review",
                "https://github.com/soyeht/soyeht-ios/pull/16",
                "--approve",
            ],
            ["gh", "pr", "comment", "soyeht/soyeht-ios#16"],
            [
                "gh",
                "issue",
                "edit",
                "https://github.com/soyeht/soyeht-ios/issues/16",
                "--title",
                "safe",
            ],
            ["gh", "issue", "comment", "soyeht/soyeht-ios#16"],
        )
        for command in commands:
            with self.subTest(command=command):
                with (
                    mock.patch.object(guard.sys, "stdin", self._stdin(b"safe body")),
                    mock.patch.object(guard.subprocess, "run") as run,
                ):
                    code = guard.main(["--stdin", "--", *command])
                self.assertEqual(2, code)
                run.assert_not_called()

    def test_github_destination_overrides_inherited_environment(self) -> None:
        with mock.patch.dict(
            guard.os.environ,
            {"GH_HOST": "enterprise.invalid", "GH_REPO": "other/repo"},
            clear=False,
        ):
            environment = guard.child_environment(["gh", "issue", "comment"])
        assert environment is not None
        self.assertEqual("github.com", environment["GH_HOST"])
        self.assertEqual("soyeht/theyos", environment["GH_REPO"])

    def test_check_only_is_green_for_name_without_at_sign(self) -> None:
        payload = self._payload_file("display agent-khai without notifying")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = guard.main(["--payload-file", payload])
        self.assertEqual(0, code)
        self.assertIn("OK", stdout.getvalue())

    def test_allowlist_is_visible_in_success_output(self) -> None:
        payload = self._payload_file("intentional @Khai")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = guard.main(["--payload-file", payload, "--allow-mention", "khai"])
        self.assertEqual(0, code)
        self.assertIn("WAIVER", stderr.getvalue())
        self.assertIn("khai", stderr.getvalue())


class PullRequestBodyRESTAdapterTests(unittest.TestCase):
    HEAD = "1" * 40
    BASE = "2" * 40
    ENDPOINT = "repos/soyeht/theyos/pulls/20"

    class FakeAPI:
        def __init__(self, reads: list[object], mutations: list[object]) -> None:
            self.reads = list(reads)
            self.mutations = list(mutations)
            self.calls: list[tuple[object, ...]] = []

        def read(self, endpoint: str) -> object:
            self.calls.append(("read", endpoint))
            value = self.reads.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value

        def mutate_json(
            self, method: str, endpoint: str, payload: dict[str, object]
        ) -> object:
            self.calls.append(("mutate", method, endpoint, payload))
            value = self.mutations.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value

    def snapshot(
        self,
        body: str,
        *,
        head: str | None = None,
        draft: bool = True,
    ) -> dict[str, object]:
        return {
            "number": 20,
            "state": "open",
            "draft": draft,
            "head": {"sha": head or self.HEAD},
            "base": {"sha": self.BASE},
            "body": body,
        }

    @staticmethod
    def api_error(status: int, detail: str = "sensitive-header: redacted") -> Exception:
        return guard.GitHubAPIError(
            ["gh", "api", "--method", "PATCH", "endpoint"],
            1,
            f"HTTP {status}: {detail}",
        )

    def execute(
        self,
        api: "PullRequestBodyRESTAdapterTests.FakeAPI",
        payload: str = "new body",
    ) -> tuple[int, list[float], str, str]:
        sleeps: list[float] = []
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = guard.execute_pr_body_update(
                ["gh", "pr", "edit", "20"],
                payload,
                api=api,
                sleep=sleeps.append,
            )
        return code, sleeps, stdout.getvalue(), stderr.getvalue()

    def test_normal_200_patch_and_readback(self) -> None:
        old = self.snapshot("old body")
        new = self.snapshot("new body")
        api = self.FakeAPI([old, new], [new])
        code, sleeps, stdout, stderr = self.execute(api)
        self.assertEqual(0, code)
        self.assertEqual([], sleeps)
        self.assertEqual(
            [
                ("read", self.ENDPOINT),
                ("mutate", "PATCH", self.ENDPOINT, {"body": "new body"}),
                ("read", self.ENDPOINT),
            ],
            api.calls,
        )
        self.assertIn('"mutation_attempts":1', stdout)
        self.assertNotIn("new body", stdout + stderr)

    def test_applied_patch_returning_503_is_success_without_second_mutation(self) -> None:
        api = self.FakeAPI(
            [self.snapshot("old body"), self.snapshot("new body")],
            [self.api_error(503)],
        )
        code, sleeps, stdout, stderr = self.execute(api)
        self.assertEqual(0, code)
        self.assertEqual([], sleeps)
        self.assertEqual(1, sum(call[0] == "mutate" for call in api.calls))
        self.assertNotIn("new body", stdout + stderr)

    def test_503_with_old_body_retries_then_succeeds(self) -> None:
        old = self.snapshot("old body")
        new = self.snapshot("new body")
        api = self.FakeAPI([old, old, new], [self.api_error(503), new])
        code, sleeps, stdout, _ = self.execute(api)
        self.assertEqual(0, code)
        self.assertEqual([5.0], sleeps)
        self.assertEqual(2, sum(call[0] == "mutate" for call in api.calls))
        self.assertIn('"mutation_attempts":2', stdout)

    def test_three_503_with_old_body_exhausts(self) -> None:
        old = self.snapshot("old body")
        api = self.FakeAPI(
            [old, old, old, old],
            [self.api_error(503), self.api_error(503), self.api_error(503)],
        )
        sleeps: list[float] = []
        with self.assertRaisesRegex(
            guard.PullRequestBodyGuardError, "exhausted HTTP 503"
        ):
            guard.execute_pr_body_update(
                ["gh", "pr", "edit", "20"],
                "new body",
                api=api,
                sleep=sleeps.append,
            )
        self.assertEqual([5.0, 5.0], sleeps)
        self.assertEqual(3, sum(call[0] == "mutate" for call in api.calls))

    def test_4xx_is_single_mutation_and_sanitized(self) -> None:
        api = self.FakeAPI([self.snapshot("old body")], [self.api_error(403)])
        sleeps: list[float] = []
        with self.assertRaisesRegex(
            guard.PullRequestBodyGuardError, "PATCH failed with HTTP 403"
        ) as raised:
            guard.execute_pr_body_update(
                ["gh", "pr", "edit", "20"],
                "private body marker",
                api=api,
                sleep=sleeps.append,
            )
        self.assertEqual([], sleeps)
        self.assertEqual(1, sum(call[0] == "mutate" for call in api.calls))
        self.assertNotIn("sensitive-header", str(raised.exception))
        self.assertNotIn("private body marker", str(raised.exception))

    def test_drift_and_third_body_state_fail_without_retry(self) -> None:
        cases = (
            self.snapshot("old body", head="3" * 40),
            self.snapshot("third body"),
        )
        for observed in cases:
            with self.subTest(observed=observed):
                api = self.FakeAPI(
                    [self.snapshot("old body"), observed],
                    [self.api_error(503)],
                )
                sleeps: list[float] = []
                with self.assertRaises(guard.PullRequestBodyGuardError):
                    guard.execute_pr_body_update(
                        ["gh", "pr", "edit", "20"],
                        "new body",
                        api=api,
                        sleep=sleeps.append,
                    )
                self.assertEqual([], sleeps)
                self.assertEqual(1, sum(call[0] == "mutate" for call in api.calls))

    def test_invalid_patch_shape_stops_without_readback_or_retry(self) -> None:
        api = self.FakeAPI([self.snapshot("old body")], [{}])
        sleeps: list[float] = []
        with self.assertRaisesRegex(
            guard.PullRequestBodyGuardError, "shape is invalid"
        ):
            guard.execute_pr_body_update(
                ["gh", "pr", "edit", "20"],
                "new body",
                api=api,
                sleep=sleeps.append,
            )
        self.assertEqual([], sleeps)
        self.assertEqual(2, len(api.calls))

    def test_readback_503_has_bounded_read_only_retry(self) -> None:
        new = self.snapshot("new body")
        api = self.FakeAPI(
            [self.snapshot("old body"), self.api_error(503), new],
            [new],
        )
        code, sleeps, _, _ = self.execute(api)
        self.assertEqual(0, code)
        self.assertEqual([5.0], sleeps)
        self.assertEqual(1, sum(call[0] == "mutate" for call in api.calls))

    def test_body_only_main_uses_rest_adapter_and_preserves_other_modes(self) -> None:
        stream = mock.Mock()
        stream.buffer.read.return_value = b"safe body"
        with (
            mock.patch.object(guard.sys, "stdin", stream),
            mock.patch.object(guard, "execute_pr_body_update", return_value=0) as rest,
            mock.patch.object(guard.subprocess, "run") as run,
        ):
            code = guard.main(["--stdin", "--", "gh", "pr", "edit", "20"])
        self.assertEqual(0, code)
        rest.assert_called_once_with(
            ["gh", "pr", "edit", "20"], "safe body"
        )
        run.assert_not_called()

        prepared = guard.prepare_command(
            ["gh", "pr", "edit", "20", "--title", "safe title"]
        )
        self.assertEqual(["--body-file", "-"], prepared[-2:])


def load_tests(
    loader: unittest.TestLoader,
    tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    """Run the dedicated governed-release adversarial suite in the CI entrypoint."""
    release_tests_path = Path(__file__).with_name("test_safe_external_release.py")
    release_spec = importlib.util.spec_from_file_location(
        "test_safe_external_release", release_tests_path
    )
    assert release_spec is not None and release_spec.loader is not None
    release_tests = importlib.util.module_from_spec(release_spec)
    sys.modules[release_spec.name] = release_tests
    release_spec.loader.exec_module(release_tests)
    tests.addTests(loader.loadTestsFromModule(release_tests))
    return tests


if __name__ == "__main__":
    unittest.main()
