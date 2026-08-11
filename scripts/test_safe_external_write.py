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

    def test_clean_payload_executes_exact_child_and_propagates_status(self) -> None:
        payload = self._payload_file("credit agent-khai")
        completed = mock.Mock(returncode=17)
        with mock.patch.object(guard.subprocess, "run", return_value=completed) as run:
            code = guard.main(["--payload-file", payload, "--", "gh", "issue", "comment"])
        self.assertEqual(17, code)
        run.assert_called_once_with(["gh", "issue", "comment"], input=None, check=False)

    def test_check_only_is_green_for_entity_encoded_display(self) -> None:
        payload = self._payload_file("display &#64;khai without notifying")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = guard.main(["--payload-file", payload])
        self.assertEqual(0, code)
        self.assertIn("OK", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
