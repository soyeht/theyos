#!/usr/bin/env python3
"""Validate a final outbound payload before executing an external write.

Repository agents must route GitHub comments, issue/PR bodies, review bodies,
commit messages, e-mail, and other externally visible prose through this
wrapper.  The validation happens after templating, on the exact bytes supplied
to the child command.

Examples:

  python3 scripts/safe_external_write.py --payload-file /tmp/body -- \
      gh issue comment 123 --body-file /tmp/body

  printf '%s' "$BODY" | python3 scripts/safe_external_write.py --stdin -- \
      gh pr create --body-file - ...

With no command after ``--``, the program performs a check only.
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
# or '.' should be encoded as &#64; rather than weakening the predicate.
MENTION_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])@([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)"
)


@dataclass(frozen=True)
class Mention:
    username: str
    line: int
    column: int


def find_mentions(payload: str, allowed: frozenset[str] = frozenset()) -> tuple[Mention, ...]:
    """Return non-allowlisted mention-shaped tokens with 1-based locations."""
    normalized_allowed = {name.lower() for name in allowed}
    found: list[Mention] = []
    for match in MENTION_PATTERN.finditer(payload):
        username = match.group(1)
        if username.lower() in normalized_allowed:
            continue
        start = match.start()
        line = payload.count("\n", 0, start) + 1
        previous_newline = payload.rfind("\n", 0, start)
        column = start - previous_newline
        found.append(Mention(username=username, line=line, column=column))
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


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    payload, forwarded_stdin = _read_payload(args)
    blocked = find_mentions(payload, frozenset(args.allow_mention))
    if blocked:
        print("BLOCKED: outbound payload contains mention-shaped tokens:", file=sys.stderr)
        for mention in blocked:
            print(
                f"  line {mention.line}, column {mention.column}: username={mention.username!r}",
                file=sys.stderr,
            )
        print(
            "Use a name without @ or encode the display-only token as &#64;. "
            "Allowlist only a deliberately authorized GitHub notification.",
            file=sys.stderr,
        )
        return 2

    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("OK: outbound payload contains no unapproved GitHub mentions")
        return 0

    try:
        completed = subprocess.run(command, input=forwarded_stdin, check=False)
    except FileNotFoundError as error:
        print(f"external write command not found: {error.filename}", file=sys.stderr)
        return 127
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
