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
        )

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
        run.assert_called_once_with(["git", "commit", "-F", "-"], input=payload, check=False)

    def test_rejects_alternate_git_message_channel(self) -> None:
        payload = b"safe commit message"
        with (
            mock.patch.object(guard.sys, "stdin", self._stdin(payload)),
            mock.patch.object(guard.subprocess, "run") as run,
        ):
            code = guard.main(["--stdin", "--", "git", "commit", "-F", "/tmp/unsafe"])
        self.assertEqual(2, code)
        run.assert_not_called()

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


if __name__ == "__main__":
    unittest.main()
