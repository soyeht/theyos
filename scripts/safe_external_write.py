#!/usr/bin/env python3
"""Validate a final outbound payload before executing an external write.

Repository agents must route GitHub comments, issue/PR bodies, review bodies,
commit messages, e-mail, and other externally visible prose through this
wrapper.  The validation happens after templating, on the exact bytes supplied
to the child command.

Examples:

  printf '%s' "$BODY" | python3 scripts/safe_external_write.py --stdin -- \
      gh pr create --title "Safe title" ...

  printf '%s' "$MESSAGE" | python3 scripts/safe_external_write.py --stdin -- \
      git commit

With no command after ``--``, the program performs a check only. Executing a
child requires ``--stdin`` so the child receives the exact bytes that passed
validation; payload files are check-only and cannot introduce a read-after-
validation race. Executed commands use a closed grammar: the wrapper itself
adds the stdin-reading body/message flag. Unsupported writers are check-only
until a reviewed adapter is added.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


# GitHub mention syntax, deliberately fail-closed.  The preceding-character
# rule distinguishes ordinary e-mail addresses (foo@example.com) from mentions
# after whitespace, punctuation, Markdown, or pasted diff prefixes.  Known
# false positives such as docs/@types and rare local-parts ending in '-', '_',
# or '.' should be rewritten without an at-sign or explicitly allowlisted rather
# than weakening the predicate.
MENTION_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])@([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)"
)
ENTITY_MENTION_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:&#0*64;?|&#x0*40;?|&commat;)"
    r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Mention:
    username: str
    line: int
    column: int


class UnsafeCommand(ValueError):
    """Raised when a child command can source outbound text outside stdin."""


def find_mentions(payload: str, allowed: frozenset[str] = frozenset()) -> tuple[Mention, ...]:
    """Return non-allowlisted mention-shaped tokens with 1-based locations."""
    normalized_allowed = {name.lower() for name in allowed}
    found: list[Mention] = []
    for pattern in (MENTION_PATTERN, ENTITY_MENTION_PATTERN):
        for match in pattern.finditer(payload):
            username = match.group(1)
            if username.lower() in normalized_allowed:
                continue
            start = match.start()
            line = payload.count("\n", 0, start) + 1
            previous_newline = payload.rfind("\n", 0, start)
            column = start - previous_newline
            found.append(Mention(username=username, line=line, column=column))
    found.sort(key=lambda mention: (mention.line, mention.column, mention.username.lower()))
    return tuple(found)


def _read_payload(args: argparse.Namespace) -> tuple[str, bytes | None]:
    if args.stdin:
        raw = sys.stdin.buffer.read()
        return raw.decode("utf-8"), raw

    chunks: list[str] = []
    for path_text in args.payload_file:
        path = Path(path_text)
        chunks.append(path.read_text(encoding="utf-8"))
    return "\n".join(chunks), None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--payload-file",
        action="append",
        default=[],
        metavar="PATH",
        help="final payload file to validate; repeat for title/body/message files",
    )
    source.add_argument(
        "--stdin",
        action="store_true",
        help="read and validate the final payload from stdin, then forward it to the child",
    )
    parser.add_argument(
        "--allow-mention",
        action="append",
        default=[],
        metavar="GITHUB_USER",
        help="explicitly allow an intentional GitHub notification (default: none)",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="external write command to execute only after validation; prefix with --",
    )
    return parser


GH_COMMANDS: dict[tuple[str, str], tuple[int, int, frozenset[str], frozenset[str]]] = {
    # (minimum positional args, maximum positional args, value flags, boolean flags)
    ("issue", "comment"): (
        1,
        1,
        frozenset({"--repo"}),
        frozenset({"--create-if-none", "--edit-last"}),
    ),
    ("issue", "create"): (
        0,
        0,
        frozenset(
            {
                "--assignee",
                "--blocked-by",
                "--blocking",
                "--label",
                "--milestone",
                "--parent",
                "--project",
                "--repo",
                "--title",
                "--type",
            }
        ),
        frozenset(),
    ),
    ("issue", "edit"): (
        1,
        100,
        frozenset(
            {
                "--add-assignee",
                "--add-blocked-by",
                "--add-blocking",
                "--add-label",
                "--add-project",
                "--add-sub-issue",
                "--milestone",
                "--parent",
                "--remove-assignee",
                "--remove-blocked-by",
                "--remove-blocking",
                "--remove-label",
                "--remove-project",
                "--remove-sub-issue",
                "--repo",
                "--title",
                "--type",
            }
        ),
        frozenset({"--remove-milestone", "--remove-parent", "--remove-type"}),
    ),
    ("pr", "comment"): (
        0,
        1,
        frozenset({"--repo"}),
        frozenset({"--create-if-none", "--edit-last"}),
    ),
    ("pr", "create"): (
        0,
        0,
        frozenset(
            {
                "--assignee",
                "--base",
                "--head",
                "--label",
                "--milestone",
                "--project",
                "--repo",
                "--reviewer",
                "--title",
            }
        ),
        frozenset({"--draft", "--no-maintainer-edit"}),
    ),
    ("pr", "edit"): (
        0,
        1,
        frozenset(
            {
                "--add-assignee",
                "--add-label",
                "--add-project",
                "--add-reviewer",
                "--base",
                "--milestone",
                "--remove-assignee",
                "--remove-label",
                "--remove-project",
                "--remove-reviewer",
                "--repo",
                "--title",
            }
        ),
        frozenset({"--remove-milestone"}),
    ),
    ("pr", "review"): (
        0,
        1,
        frozenset({"--repo"}),
        frozenset({"--approve", "--comment", "--request-changes"}),
    ),
}


def _parse_closed_flags(
    arguments: Sequence[str],
    value_flags: frozenset[str],
    boolean_flags: frozenset[str],
) -> tuple[list[str], set[str]]:
    """Validate long-form flags and return positional args plus flags seen."""
    positional: list[str] = []
    seen: set[str] = set()
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if not token.startswith("--"):
            if token.startswith("-"):
                raise UnsafeCommand(f"short flags are not supported by guarded writer: {token}")
            positional.append(token)
            index += 1
            continue

        flag, separator, inline_value = token.partition("=")
        if flag in boolean_flags:
            if separator:
                raise UnsafeCommand(f"boolean flag does not take a value: {flag}")
            seen.add(flag)
            index += 1
            continue
        if flag not in value_flags:
            raise UnsafeCommand(f"unsupported flag for guarded writer: {flag}")
        seen.add(flag)
        if separator:
            if not inline_value:
                raise UnsafeCommand(f"missing value for guarded writer flag: {flag}")
            index += 1
            continue
        if index + 1 >= len(arguments) or arguments[index + 1].startswith("--"):
            raise UnsafeCommand(f"missing value for guarded writer flag: {flag}")
        index += 2
    return positional, seen


def prepare_command(command: Sequence[str]) -> list[str]:
    """Return a child command whose only prose source is the validated stdin."""
    command = list(command)
    if command[:2] == ["git", "commit"]:
        if len(command) != 2:
            raise UnsafeCommand("guarded git commit accepts no caller-supplied flags")
        return ["git", "commit", "-F", "-"]

    if len(command) < 3 or command[0] != "gh":
        raise UnsafeCommand("unsupported external writer; add a reviewed stdin adapter first")

    key = (command[1], command[2])
    grammar = GH_COMMANDS.get(key)
    if grammar is None:
        raise UnsafeCommand(f"unsupported GitHub writer: gh {command[1]} {command[2]}")
    minimum, maximum, value_flags, boolean_flags = grammar
    positional, seen = _parse_closed_flags(command[3:], value_flags, boolean_flags)
    if not minimum <= len(positional) <= maximum:
        raise UnsafeCommand(
            f"gh {key[0]} {key[1]} expects {minimum}..{maximum} positional targets"
        )
    if key in {("issue", "create"), ("pr", "create")} and "--title" not in seen:
        raise UnsafeCommand(f"gh {key[0]} create requires an explicit --title")
    if key == ("pr", "review") and not seen.intersection(
        {"--approve", "--comment", "--request-changes"}
    ):
        raise UnsafeCommand("gh pr review requires an explicit review disposition")
    return command + ["--body-file", "-"]


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    payload, forwarded_stdin = _read_payload(args)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]

    allowed = frozenset(args.allow_mention)
    blocked = find_mentions(payload, allowed)
    # Titles and inline message fragments are command arguments rather than
    # stdin for several CLIs. Validate them too; checking only the body would
    # leave another outbound text channel unguarded.
    blocked_command = find_mentions("\n".join(command), allowed)
    blocked = blocked + blocked_command
    if blocked:
        print("BLOCKED: outbound payload contains mention-shaped tokens:", file=sys.stderr)
        for mention in blocked:
            print(
                f"  line {mention.line}, column {mention.column}: username={mention.username!r}",
                file=sys.stderr,
            )
        print(
            "Use a name without an at-sign. HTML entity encodings are also blocked "
            "because rendered text can be copied back into a live mention. Allowlist "
            "only a deliberately authorized GitHub notification.",
            file=sys.stderr,
        )
        return 2

    if allowed:
        print(
            "WAIVER: explicit GitHub mention allowlist="
            + ",".join(sorted(allowed, key=str.lower)),
            file=sys.stderr,
        )

    if not command:
        print("OK: outbound payload contains no unapproved GitHub mentions")
        return 0

    if not args.stdin:
        print(
            "BLOCKED: executing an external write requires --stdin so the child "
            "receives the exact payload bytes that were validated",
            file=sys.stderr,
        )
        return 2

    try:
        prepared_command = prepare_command(command)
    except UnsafeCommand as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2

    try:
        completed = subprocess.run(prepared_command, input=forwarded_stdin, check=False)
    except FileNotFoundError as error:
        print(f"external write command not found: {error.filename}", file=sys.stderr)
        return 127
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
