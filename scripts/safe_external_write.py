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
until a reviewed adapter is added. ``git push`` is intentionally outside the
execution grammar because its published text is existing history, not stdin;
commit messages are guarded when they are created. General GitHub prose
adapters are intentionally pinned to ``github.com/soyeht/theyos``. Their only
permitted explicit issue or pull-request target is a strict positive decimal
identifier in that repository; URLs, owner/repository selectors, refs, and
branch names are rejected before execution. The separate
``governed-release`` family is hardcoded to
``github.com/soyeht/soyeht-ios`` and cannot redirect at runtime. The dedicated
``governed-ios-pr-create`` adapter can create only the draft consumer PR from
``ci/governed-macos-release`` into ``soyeht/soyeht-ios:main``. It cannot edit,
ready, review, or merge a PR and does not add a general destination selector.
The companion ``governed-ios-pr-body-update`` adapter can change only the body
of that same consumer PR number 16 while it remains open and draft; every
other field is a hardcoded readback invariant.
The ``governed-theyos-v0126-tag`` adapter is narrower still: it can author
the one annotated backend tag ``v0.1.26`` locally, or push only that already
validated ref. Creation and push are separate invocations, each with one
mutation and a complete readback.
Any further repository or operation requires an explicit code change and
review.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import quote


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
SAFE_GITHUB_HOST = "github.com"
SAFE_GITHUB_REPO = "soyeht/theyos"
RELEASE_GITHUB_REPO = "soyeht/soyeht-ios"
IOS_PR_BASE = "main"
IOS_PR_HEAD = "ci/governed-macos-release"
IOS_PR_HEAD_OWNER = "soyeht"
IOS_PR_NUMBER = 16
IOS_PR_TITLE = "ci(macos): make release workflow build-only and governed"
RELEASE_TAG_PREFIX = "refs/tags/mac-v"
RELEASE_PROJECT_FILE = "TerminalApp/Soyeht.xcodeproj/project.pbxproj"
RELEASE_WORKFLOW_FILE = ".github/workflows/macos-release.yml"
RELEASE_EXECUTION_CONTRACT_SHA256 = {
    ".github/workflows/macos-release.yml": "522a852c2601b431266fd7de3718daaa028cbf45a5dfbc22d69a0cb52802bd3b",
    ".github/workflows/xcode.yml": "7fedc9ebe251950479eead626e3fb89d880077d51c68b8df4aaf7f383602d486",
    "scripts/ci/test-ios": "6359805f5fa0bb9c435cd20b6e1eafb6747c4d4baa730b142502e39c61bffb7e",
    "scripts/ci/check-governed-macos-release.py": "a9799bad49ae966e2462070da1e90c0a8ccaaa17cd73d70d8664a816e392c83a",
}
RELEASE_CONTRACT_MARKER = b"# governed-release-contract: theyos-safe-external-write-v1"
RELEASE_REQUIRED_BUILD_MARKER = b"# governed-release-required-build: scripts/ci/check-governed-macos-release.py"
RELEASE_CONTRACT_REQUIRED_ACTIVE_LINES = (
    b"      expected_ref:",
    b"      expected_oid:",
    b"  contents: read",
    b"        uses: actions/upload-artifact@v4",
    b"          if-no-files-found: error",
)
RELEASE_CONTRACT_FORBIDDEN = (
    b"gh release",
    b"git tag",
    b"git push",
    b"--clobber",
)
RELEASE_ASSET_NAMES = frozenset({"Soyeht.dmg", "appcast.xml"})
THEYOS_REPOSITORY_URL = "https://github.com/soyeht/theyos.git"
THEYOS_TAG_VERSION = "0.1.26"
THEYOS_TAG = f"v{THEYOS_TAG_VERSION}"
THEYOS_TAG_REF = f"refs/tags/{THEYOS_TAG}"
THEYOS_TAG_MESSAGE = f"theyos-engine {THEYOS_TAG_VERSION}\n"
THEYOS_VERSION_FILE = "VERSION"
THEYOS_CARGO_FILE = "admin/rust/soyeht-rs/Cargo.toml"
FULL_OID_PATTERN = re.compile(r"[0-9a-f]{40}")
VERSION_PATTERN = re.compile(
    r"[0-9]+(?:\.[0-9]+){1,2}(?:[.-][0-9A-Za-z]+)?"
)
MARKETING_VERSION_PATTERN = re.compile(
    rb"\bMARKETING_VERSION\s*=\s*([^;\r\n]+)\s*;"
)


@dataclass(frozen=True)
class Mention:
    username: str
    line: int
    column: int


class UnsafeCommand(ValueError):
    """Raised when a child command can source outbound text outside stdin."""


class ReleaseGuardError(ValueError):
    """Raised when a governed release precondition or readback fails."""


class TheyosTagGuardError(ValueError):
    """Raised when the fixed theyos v0.1.26 tag boundary fails closed."""


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
        frozenset(),
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
                "--title",
                "--type",
            }
        ),
        frozenset({"--remove-milestone", "--remove-parent", "--remove-type"}),
    ),
    ("pr", "comment"): (
        0,
        1,
        frozenset(),
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
                "--title",
            }
        ),
        frozenset({"--remove-milestone"}),
    ),
    ("pr", "review"): (
        0,
        1,
        frozenset(),
        frozenset({"--approve", "--comment", "--request-changes"}),
    ),
}

LOCAL_GITHUB_TARGET_COMMANDS = frozenset(
    {
        ("issue", "comment"),
        ("issue", "edit"),
        ("pr", "comment"),
        ("pr", "edit"),
        ("pr", "review"),
    }
)
LOCAL_GITHUB_NUMBER_PATTERN = re.compile(r"[1-9][0-9]*")


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
    if key in LOCAL_GITHUB_TARGET_COMMANDS and any(
        LOCAL_GITHUB_NUMBER_PATTERN.fullmatch(target) is None for target in positional
    ):
        raise UnsafeCommand(
            f"gh {key[0]} {key[1]} accepts only positive decimal "
            "targets in soyeht/theyos"
        )
    if key in {("issue", "create"), ("pr", "create")} and "--title" not in seen:
        raise UnsafeCommand(f"gh {key[0]} create requires an explicit --title")
    if key == ("pr", "review") and not seen.intersection(
        {"--approve", "--comment", "--request-changes"}
    ):
        raise UnsafeCommand("gh pr review requires an explicit review disposition")
    return command + ["--body-file", "-"]


def child_environment(command: Sequence[str]) -> dict[str, str] | None:
    """Pin GitHub writers to this repository instead of inheriting a destination."""
    if not command or command[0] != "gh":
        return None
    environment = os.environ.copy()
    environment["GH_HOST"] = SAFE_GITHUB_HOST
    environment["GH_REPO"] = SAFE_GITHUB_REPO
    return environment


class GitHubAPIError(RuntimeError):
    """A failed, non-interactive GitHub API request."""

    def __init__(self, command: Sequence[str], returncode: int, stderr: str) -> None:
        super().__init__(
            f"GitHub API request failed with exit {returncode}: "
            f"{' '.join(command[:6])}: {stderr.strip()}"
        )
        self.returncode = returncode
        self.stderr = stderr

    @property
    def is_not_found(self) -> bool:
        return "HTTP 404" in self.stderr


class GitHubAPI:
    """Minimal API client pinned to the governed iOS repository."""

    def _request(
        self,
        method: str,
        endpoint: str,
        *,
        body: bytes | None = None,
        headers: Sequence[str] = (),
        paginate: bool = False,
    ) -> Any:
        command = [
            "gh",
            "api",
            "--hostname",
            SAFE_GITHUB_HOST,
            "--method",
            method,
            "--header",
            "Accept: application/vnd.github+json",
            "--header",
            "X-GitHub-Api-Version: 2022-11-28",
        ]
        for header in headers:
            command.extend(["--header", header])
        if paginate:
            command.extend(["--paginate", "--slurp"])
        command.append(endpoint)
        if body is not None:
            command.extend(["--input", "-"])

        environment = os.environ.copy()
        environment["GH_HOST"] = SAFE_GITHUB_HOST
        environment["GH_REPO"] = RELEASE_GITHUB_REPO
        completed = subprocess.run(
            command,
            input=body,
            capture_output=True,
            check=False,
            env=environment,
        )
        if completed.returncode:
            raise GitHubAPIError(
                command,
                completed.returncode,
                completed.stderr.decode("utf-8", errors="replace"),
            )
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise ReleaseGuardError(
                f"GitHub API returned non-JSON success for {method} {endpoint}"
            ) from error

    def read(self, endpoint: str) -> Any:
        return self._request("GET", endpoint)

    def read_optional(self, endpoint: str) -> Any | None:
        try:
            return self.read(endpoint)
        except GitHubAPIError as error:
            if error.is_not_found:
                return None
            raise

    def read_pages(self, endpoint: str) -> list[Any]:
        pages = self._request("GET", endpoint, paginate=True)
        if not isinstance(pages, list):
            raise ReleaseGuardError("paginated GitHub response is not a list")
        flattened: list[Any] = []
        for page in pages:
            if not isinstance(page, list):
                raise ReleaseGuardError("paginated GitHub page is not a list")
            flattened.extend(page)
        return flattened

    def mutate_json(self, method: str, endpoint: str, payload: Mapping[str, Any]) -> Any:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self._request(
            method,
            endpoint,
            body=body,
            headers=("Content-Type: application/json",),
        )

    def upload_asset(
        self,
        release_id: int,
        name: str,
        payload: bytes,
        upload_url: str,
    ) -> Any:
        expected_template = (
            f"https://uploads.github.com/repos/{RELEASE_GITHUB_REPO}/releases/"
            f"{release_id}/assets{{?name,label}}"
        )
        if upload_url != expected_template:
            raise ReleaseGuardError("release upload URL readback mismatch")
        token_result = subprocess.run(
            ["gh", "auth", "token", "--hostname", SAFE_GITHUB_HOST],
            capture_output=True,
            check=False,
        )
        if token_result.returncode:
            raise ReleaseGuardError("cannot obtain GitHub authentication for asset upload")
        token = token_result.stdout.decode("utf-8").strip()
        if not token:
            raise ReleaseGuardError("GitHub authentication token is empty")
        endpoint = (
            f"/repos/{RELEASE_GITHUB_REPO}/releases/{release_id}/assets"
            f"?name={quote(name, safe='')}"
        )
        connection = http.client.HTTPSConnection("uploads.github.com", timeout=900)
        try:
            connection.request(
                "POST",
                endpoint,
                body=payload,
                headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/octet-stream",
                "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            response = connection.getresponse()
            response_bytes = response.read()
            if response.status < 200 or response.status >= 300:
                raise ReleaseGuardError(
                    f"GitHub asset upload failed with HTTP {response.status}"
                )
        except (OSError, http.client.HTTPException) as error:
            raise ReleaseGuardError("GitHub asset upload failed before readback") from error
        finally:
            connection.close()
            token = ""
        try:
            return json.loads(response_bytes)
        except json.JSONDecodeError as error:
            raise ReleaseGuardError("asset upload returned non-JSON success") from error


@dataclass(frozen=True)
class ReleaseCommon:
    tag_ref: str
    tag: str
    version: str
    target_oid: str
    expected_main: str


@dataclass(frozen=True)
class IOSDraftPRExpectation:
    expected_head_oid: str
    title: str
    body: str


@dataclass(frozen=True)
class IOSDraftPRBodyUpdateExpectation:
    expected_head_oid: str
    expected_old_body_sha256: str
    expected_old_body_size: int
    body: str


@dataclass(frozen=True)
class AssetExpectation:
    name: str
    size: int
    sha256: str


RELEASE_OPERATION_FLAGS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    # (required single-value flags beyond the common set, repeatable flags)
    "tag-object-create": (frozenset(), frozenset()),
    "tag-ref-create": (frozenset({"--tag-object-oid"}), frozenset()),
    "release-draft-create": (
        frozenset({"--title", "--tag-object-oid"}),
        frozenset(),
    ),
    "asset-upload": (
        frozenset(
            {
                "--release-id",
                "--tag-object-oid",
                "--asset-name",
                "--asset-path",
                "--asset-sha256",
                "--asset-size",
            }
        ),
        frozenset(),
    ),
    "release-publish": (
        frozenset({"--release-id", "--tag-object-oid"}),
        frozenset({"--asset"}),
    ),
}
RELEASE_COMMON_FLAGS = frozenset(
    {"--tag-ref", "--version", "--target-oid", "--expected-main"}
)


def _parse_release_arguments(arguments: Sequence[str]) -> tuple[str, dict[str, list[str]]]:
    if not arguments:
        raise UnsafeCommand("governed-release requires an operation")
    operation = arguments[0]
    grammar = RELEASE_OPERATION_FLAGS.get(operation)
    if grammar is None:
        raise UnsafeCommand(f"unsupported governed-release operation: {operation}")
    required_extra, repeatable = grammar
    allowed = RELEASE_COMMON_FLAGS | required_extra | repeatable
    values: dict[str, list[str]] = {}
    index = 1
    while index < len(arguments):
        flag = arguments[index]
        if flag not in allowed:
            raise UnsafeCommand(f"unsupported governed-release argument: {flag}")
        if index + 1 >= len(arguments) or arguments[index + 1].startswith("--"):
            raise UnsafeCommand(f"missing value for governed-release argument: {flag}")
        if flag not in repeatable and flag in values:
            raise UnsafeCommand(f"duplicate governed-release argument: {flag}")
        values.setdefault(flag, []).append(arguments[index + 1])
        index += 2

    required = RELEASE_COMMON_FLAGS | required_extra
    missing = sorted(flag for flag in required if flag not in values)
    if missing:
        raise UnsafeCommand(
            "missing governed-release arguments: " + ", ".join(missing)
        )
    if operation == "release-publish" and len(values.get("--asset", [])) != 2:
        raise UnsafeCommand("release-publish requires exactly two --asset values")
    return operation, values


def _single(values: Mapping[str, list[str]], flag: str) -> str:
    candidates = values.get(flag, [])
    if len(candidates) != 1:
        raise UnsafeCommand(f"governed-release requires exactly one {flag}")
    return candidates[0]


def _full_oid(value: str, label: str) -> str:
    if FULL_OID_PATTERN.fullmatch(value) is None:
        raise ReleaseGuardError(f"{label} must be a lowercase, full 40-hex OID")
    return value


def _release_common(values: Mapping[str, list[str]]) -> ReleaseCommon:
    version = _single(values, "--version")
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ReleaseGuardError("release version has invalid grammar")
    tag_ref = _single(values, "--tag-ref")
    expected_tag_ref = f"{RELEASE_TAG_PREFIX}{version}"
    if tag_ref != expected_tag_ref:
        raise ReleaseGuardError(
            f"tag ref must be the complete expected ref {expected_tag_ref!r}"
        )
    return ReleaseCommon(
        tag_ref=tag_ref,
        tag=tag_ref.removeprefix("refs/tags/"),
        version=version,
        target_oid=_full_oid(_single(values, "--target-oid"), "target OID"),
        expected_main=_full_oid(_single(values, "--expected-main"), "expected main"),
    )


def _expect_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseGuardError(f"{label} is not a JSON object")
    return value


def _read_repository_file(
    api: GitHubAPI,
    path: str,
    oid: str,
    label: str,
) -> bytes:
    value = _expect_mapping(
        api.read(f"repos/{RELEASE_GITHUB_REPO}/contents/{path}?ref={oid}"),
        label,
    )
    if value.get("type") != "file" or value.get("encoding") != "base64":
        raise ReleaseGuardError(f"{label} is not a base64 file")
    try:
        encoded = re.sub(r"\s+", "", str(value.get("content", "")))
        return base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as error:
        raise ReleaseGuardError(f"{label} has invalid base64") from error


def _assert_common_release_state(api: GitHubAPI, common: ReleaseCommon) -> None:
    main_ref = _expect_mapping(
        api.read(f"repos/{RELEASE_GITHUB_REPO}/git/ref/heads/main"),
        "main ref",
    )
    main_object = _expect_mapping(main_ref.get("object"), "main ref object")
    if main_object.get("type") != "commit" or main_object.get("sha") != common.expected_main:
        raise ReleaseGuardError("origin/main drifted from the expected full OID")

    commit = _expect_mapping(
        api.read(f"repos/{RELEASE_GITHUB_REPO}/commits/{common.target_oid}"),
        "target commit",
    )
    if commit.get("sha") != common.target_oid:
        raise ReleaseGuardError("target commit readback does not match the requested OID")

    comparison = _expect_mapping(
        api.read(
            f"repos/{RELEASE_GITHUB_REPO}/compare/"
            f"{common.target_oid}...{common.expected_main}"
        ),
        "target/main comparison",
    )
    merge_base = _expect_mapping(comparison.get("merge_base_commit"), "merge base")
    if comparison.get("status") not in {"ahead", "identical"}:
        raise ReleaseGuardError("target OID is not already merged into origin/main")
    if merge_base.get("sha") != common.target_oid:
        raise ReleaseGuardError("target OID is not the merge base of origin/main")

    project_bytes = _read_repository_file(
        api,
        RELEASE_PROJECT_FILE,
        common.target_oid,
        "project version source",
    )
    versions = {
        match.group(1).decode("utf-8").strip()
        for match in MARKETING_VERSION_PATTERN.finditer(project_bytes)
    }
    if versions != {common.version}:
        raise ReleaseGuardError(
            f"declared MARKETING_VERSION set {sorted(versions)!r} does not equal "
            f"the requested version {common.version!r}"
        )

    execution_contract = {
        path: _read_repository_file(
            api,
            path,
            common.target_oid,
            f"governed release execution contract {path}",
        )
        for path in RELEASE_EXECUTION_CONTRACT_SHA256
    }
    workflow_bytes = execution_contract[RELEASE_WORKFLOW_FILE]
    if workflow_bytes.count(RELEASE_CONTRACT_MARKER) != 1:
        raise ReleaseGuardError(
            "the governed iOS workflow contract is absent or duplicated; "
            "consumer PR B must be in the target commit"
        )
    if workflow_bytes.count(RELEASE_REQUIRED_BUILD_MARKER) != 1:
        raise ReleaseGuardError(
            "the governed iOS required-build contract is absent or duplicated; "
            "consumer PR B must be in the target commit"
        )
    active_lines = tuple(
        line.rstrip()
        for line in workflow_bytes.splitlines()
        if not line.lstrip().startswith(b"#")
    )
    missing_contract = [
        line.decode("ascii", errors="replace")
        for line in RELEASE_CONTRACT_REQUIRED_ACTIVE_LINES
        if line not in active_lines
    ]
    forbidden_contract = [
        token.decode("ascii", errors="replace")
        for token in RELEASE_CONTRACT_FORBIDDEN
        if any(token.lower() in line.lower() for line in active_lines)
    ]
    if missing_contract or forbidden_contract:
        raise ReleaseGuardError(
            "governed iOS workflow contract mismatch: "
            f"missing={missing_contract!r}, forbidden={forbidden_contract!r}"
        )
    mismatched_bytes = [
        path
        for path, expected_sha256 in RELEASE_EXECUTION_CONTRACT_SHA256.items()
        if hashlib.sha256(execution_contract[path]).hexdigest() != expected_sha256
    ]
    if mismatched_bytes:
        raise ReleaseGuardError(
            "governed iOS execution-contract bytes do not match the reviewed "
            f"consumer quartet: {mismatched_bytes!r}"
        )

    ambiguous_branch = api.read_optional(
        f"repos/{RELEASE_GITHUB_REPO}/git/ref/heads/{common.tag}"
    )
    if ambiguous_branch is not None:
        raise ReleaseGuardError("a branch exists with the release tag's short name")


def _assert_release_absent(api: GitHubAPI, common: ReleaseCommon) -> None:
    if api.read_optional(
        f"repos/{RELEASE_GITHUB_REPO}/releases/tags/{common.tag}"
    ) is not None:
        raise ReleaseGuardError("release tag is already associated with a release")
    releases = api.read_pages(f"repos/{RELEASE_GITHUB_REPO}/releases?per_page=100")
    for release in releases:
        if isinstance(release, dict) and release.get("tag_name") == common.tag:
            raise ReleaseGuardError("release tag is already used by a draft or release")


def _assert_tag_absent(api: GitHubAPI, common: ReleaseCommon) -> None:
    if api.read_optional(
        f"repos/{RELEASE_GITHUB_REPO}/git/ref/tags/{common.tag}"
    ) is not None:
        raise ReleaseGuardError("release tag ref already exists")
    _assert_release_absent(api, common)


def _expected_tag_message(common: ReleaseCommon) -> str:
    return f"Soyeht {common.version}\n"


def _read_tag(
    api: GitHubAPI,
    common: ReleaseCommon,
    expected_tag_object_oid: str,
) -> tuple[str, Mapping[str, Any]]:
    tag_ref = _expect_mapping(
        api.read(f"repos/{RELEASE_GITHUB_REPO}/git/ref/tags/{common.tag}"),
        "tag ref",
    )
    if tag_ref.get("ref") != common.tag_ref:
        raise ReleaseGuardError("tag ref readback name mismatch")
    ref_object = _expect_mapping(tag_ref.get("object"), "tag ref object")
    if ref_object.get("type") != "tag":
        raise ReleaseGuardError("release ref is not an annotated tag object")
    tag_object_oid = _full_oid(str(ref_object.get("sha", "")), "tag object OID")
    if tag_object_oid != expected_tag_object_oid:
        raise ReleaseGuardError("release ref drifted to a different tag object")
    tag_object = _expect_mapping(
        api.read(f"repos/{RELEASE_GITHUB_REPO}/git/tags/{tag_object_oid}"),
        "tag object",
    )
    target = _expect_mapping(tag_object.get("object"), "tag target")
    if tag_object.get("tag") != common.tag:
        raise ReleaseGuardError("tag object name mismatch")
    if tag_object.get("message") != _expected_tag_message(common):
        raise ReleaseGuardError("tag object message is not the fixed governed message")
    if target.get("type") != "commit" or target.get("sha") != common.target_oid:
        raise ReleaseGuardError("tag object does not point directly to the expected commit")
    return tag_object_oid, tag_object


def _read_release(
    api: GitHubAPI,
    common: ReleaseCommon,
    release_id: int,
    tag_object_oid: str,
) -> Mapping[str, Any]:
    release = _expect_mapping(
        api.read(f"repos/{RELEASE_GITHUB_REPO}/releases/{release_id}"),
        "release",
    )
    if release.get("id") != release_id:
        raise ReleaseGuardError("release ID readback mismatch")
    if release.get("tag_name") != common.tag:
        raise ReleaseGuardError("release tag readback mismatch")
    # GitHub documents target_commitish as material only when the named tag does
    # not already exist. This flow creates the annotated ref first, so bind the
    # release through the authoritative ref -> tag object -> commit chain below.
    _read_tag(api, common, tag_object_oid)
    return release


def _release_id(value: str) -> int:
    if not value.isascii() or not value.isdigit() or int(value) <= 0:
        raise ReleaseGuardError("release ID must be a positive decimal integer")
    return int(value)


def _asset_expectation(value: str) -> AssetExpectation:
    pieces = value.split(":")
    if len(pieces) != 3:
        raise ReleaseGuardError("asset expectation must be NAME:SIZE:SHA256")
    name, size_text, digest = pieces
    if name not in RELEASE_ASSET_NAMES:
        raise ReleaseGuardError(f"unexpected release asset name: {name!r}")
    if not size_text.isascii() or not size_text.isdigit() or int(size_text) <= 0:
        raise ReleaseGuardError("asset size must be a positive decimal integer")
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ReleaseGuardError("asset SHA-256 must be 64 lowercase hex characters")
    return AssetExpectation(name=name, size=int(size_text), sha256=digest)


def _remote_assets(release: Mapping[str, Any]) -> dict[str, AssetExpectation]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ReleaseGuardError("release assets readback is not a list")
    result: dict[str, AssetExpectation] = {}
    for asset_value in assets:
        asset = _expect_mapping(asset_value, "release asset")
        name = str(asset.get("name", ""))
        if name in result:
            raise ReleaseGuardError(f"duplicate remote asset name: {name!r}")
        digest_text = str(asset.get("digest", ""))
        if not digest_text.startswith("sha256:"):
            raise ReleaseGuardError(f"remote asset {name!r} lacks a SHA-256 digest")
        if asset.get("state") != "uploaded":
            raise ReleaseGuardError(f"remote asset {name!r} is not fully uploaded")
        size = asset.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ReleaseGuardError(f"remote asset {name!r} has invalid size")
        result[name] = AssetExpectation(
            name=name,
            size=size,
            sha256=digest_text.removeprefix("sha256:"),
        )
    return result


def _read_asset_bytes(path_text: str, expectation: AssetExpectation) -> bytes:
    asset_path = Path(path_text)
    if not asset_path.is_absolute():
        raise ReleaseGuardError("asset path must be absolute")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(asset_path, flags)
    except OSError as error:
        raise ReleaseGuardError(f"cannot open release asset safely: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ReleaseGuardError("release asset is not a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ReleaseGuardError("release asset changed while it was being read")
    payload = b"".join(chunks)
    if len(payload) != expectation.size:
        raise ReleaseGuardError("release asset size does not match the expected size")
    if hashlib.sha256(payload).hexdigest() != expectation.sha256:
        raise ReleaseGuardError("release asset digest does not match the expected SHA-256")
    return payload


def _emit_release_receipt(operation: str, **fields: Any) -> None:
    receipt = {
        "operation": operation,
        "repository": RELEASE_GITHUB_REPO,
        **fields,
    }
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))


def _parse_ios_pr_create_arguments(arguments: Sequence[str]) -> tuple[str, str]:
    allowed = frozenset({"--expected-head-oid", "--title"})
    values: dict[str, str] = {}
    index = 0
    while index < len(arguments):
        flag = arguments[index]
        if flag not in allowed:
            raise UnsafeCommand(f"unsupported governed iOS PR argument: {flag}")
        if flag in values:
            raise UnsafeCommand(f"duplicate governed iOS PR argument: {flag}")
        if index + 1 >= len(arguments) or arguments[index + 1].startswith("--"):
            raise UnsafeCommand(f"missing value for governed iOS PR argument: {flag}")
        values[flag] = arguments[index + 1]
        index += 2
    missing = sorted(allowed - values.keys())
    if missing:
        raise UnsafeCommand(
            "missing governed iOS PR arguments: " + ", ".join(missing)
        )
    title = values["--title"]
    if not title or "\n" in title or "\r" in title:
        raise ReleaseGuardError("governed iOS PR title must be one nonempty line")
    return _full_oid(values["--expected-head-oid"], "expected PR head OID"), title


def _parse_ios_pr_body_update_arguments(
    arguments: Sequence[str],
) -> tuple[str, str, int]:
    allowed = frozenset(
        {
            "--expected-head-oid",
            "--expected-old-body-sha256",
            "--expected-old-body-size",
        }
    )
    values: dict[str, str] = {}
    index = 0
    while index < len(arguments):
        flag = arguments[index]
        if flag not in allowed:
            raise UnsafeCommand(f"unsupported governed iOS PR body argument: {flag}")
        if flag in values:
            raise UnsafeCommand(f"duplicate governed iOS PR body argument: {flag}")
        if index + 1 >= len(arguments) or arguments[index + 1].startswith("--"):
            raise UnsafeCommand(f"missing value for governed iOS PR body argument: {flag}")
        values[flag] = arguments[index + 1]
        index += 2
    missing = sorted(allowed - values.keys())
    if missing:
        raise UnsafeCommand(
            "missing governed iOS PR body arguments: " + ", ".join(missing)
        )
    digest = values["--expected-old-body-sha256"]
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ReleaseGuardError("expected old PR body SHA-256 must be 64 lowercase hex digits")
    size_text = values["--expected-old-body-size"]
    if re.fullmatch(r"[1-9][0-9]*", size_text) is None:
        raise ReleaseGuardError("expected old PR body size must be a positive decimal integer")
    return (
        _full_oid(values["--expected-head-oid"], "expected PR head OID"),
        digest,
        int(size_text),
    )


def _assert_ios_pr_head(
    api: GitHubAPI,
    expected_head_oid: str,
) -> None:
    branch_ref = _expect_mapping(
        api.read(f"repos/{RELEASE_GITHUB_REPO}/git/ref/heads/{IOS_PR_HEAD}"),
        "governed iOS PR head ref",
    )
    branch_object = _expect_mapping(
        branch_ref.get("object"), "governed iOS PR head object"
    )
    if (
        branch_ref.get("ref") != f"refs/heads/{IOS_PR_HEAD}"
        or branch_object.get("type") != "commit"
        or branch_object.get("sha") != expected_head_oid
    ):
        raise ReleaseGuardError(
            "governed iOS PR remote branch does not equal the expected full OID"
        )


def _assert_ios_pr_absent(api: GitHubAPI) -> None:
    head = quote(f"{IOS_PR_HEAD_OWNER}:{IOS_PR_HEAD}", safe="")
    matches = api.read_pages(
        f"repos/{RELEASE_GITHUB_REPO}/pulls?state=all&head={head}"
        f"&base={IOS_PR_BASE}&per_page=100"
    )
    if matches:
        raise ReleaseGuardError(
            "a pull request already exists for the governed iOS consumer branch"
        )


def execute_governed_ios_pr_create(
    arguments: Sequence[str],
    payload: str,
    *,
    api: GitHubAPI | None = None,
) -> int:
    """Create exactly the fixed iOS consumer draft PR and read it back."""
    expected_head_oid, title = _parse_ios_pr_create_arguments(arguments)
    if not payload:
        raise ReleaseGuardError("governed iOS PR body must not be empty")
    expectation = IOSDraftPRExpectation(
        expected_head_oid=expected_head_oid,
        title=title,
        body=payload,
    )
    client = api or GitHubAPI()
    _assert_ios_pr_head(client, expectation.expected_head_oid)
    _assert_ios_pr_absent(client)
    created = _expect_mapping(
        client.mutate_json(
            "POST",
            f"repos/{RELEASE_GITHUB_REPO}/pulls",
            {
                "base": IOS_PR_BASE,
                "body": expectation.body,
                "draft": True,
                "head": f"{IOS_PR_HEAD_OWNER}:{IOS_PR_HEAD}",
                "title": expectation.title,
            },
        ),
        "created governed iOS PR",
    )
    number = created.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
        raise ReleaseGuardError("created governed iOS PR has invalid number")

    # Recheck the remote ref after the single mutation before accepting the PR.
    _assert_ios_pr_head(client, expectation.expected_head_oid)
    readback = _expect_mapping(
        client.read(f"repos/{RELEASE_GITHUB_REPO}/pulls/{number}"),
        "governed iOS PR readback",
    )
    head = _expect_mapping(readback.get("head"), "governed iOS PR readback head")
    base = _expect_mapping(readback.get("base"), "governed iOS PR readback base")
    head_repo = _expect_mapping(head.get("repo"), "governed iOS PR head repository")
    base_repo = _expect_mapping(base.get("repo"), "governed iOS PR base repository")
    if (
        readback.get("number") != number
        or readback.get("state") != "open"
        or readback.get("draft") is not True
        or readback.get("title") != expectation.title
        or readback.get("body") != expectation.body
        or head.get("ref") != IOS_PR_HEAD
        or head.get("sha") != expectation.expected_head_oid
        or head_repo.get("full_name") != RELEASE_GITHUB_REPO
        or base.get("ref") != IOS_PR_BASE
        or base_repo.get("full_name") != RELEASE_GITHUB_REPO
    ):
        raise ReleaseGuardError("governed iOS draft PR readback mismatch")
    print(
        json.dumps(
            {
                "base": IOS_PR_BASE,
                "draft": True,
                "head": IOS_PR_HEAD,
                "head_oid": expectation.expected_head_oid,
                "operation": "governed-ios-pr-create",
                "pr_number": number,
                "repository": RELEASE_GITHUB_REPO,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _assert_ios_pr_body_update_readback(
    readback: Mapping[str, Any],
    expectation: IOSDraftPRBodyUpdateExpectation,
    expected_body: str,
) -> None:
    head = _expect_mapping(readback.get("head"), "governed iOS PR body readback head")
    base = _expect_mapping(readback.get("base"), "governed iOS PR body readback base")
    head_repo = _expect_mapping(head.get("repo"), "governed iOS PR body head repository")
    base_repo = _expect_mapping(base.get("repo"), "governed iOS PR body base repository")
    if (
        readback.get("number") != IOS_PR_NUMBER
        or readback.get("state") != "open"
        or readback.get("draft") is not True
        or readback.get("title") != IOS_PR_TITLE
        or readback.get("body") != expected_body
        or head.get("ref") != IOS_PR_HEAD
        or head.get("sha") != expectation.expected_head_oid
        or head_repo.get("full_name") != RELEASE_GITHUB_REPO
        or base.get("ref") != IOS_PR_BASE
        or base_repo.get("full_name") != RELEASE_GITHUB_REPO
    ):
        raise ReleaseGuardError("governed iOS draft PR body readback mismatch")


def execute_governed_ios_pr_body_update(
    arguments: Sequence[str],
    payload: str,
    *,
    api: GitHubAPI | None = None,
) -> int:
    """Update only the fixed iOS consumer draft PR body and read it back."""
    expected_head_oid, old_digest, old_size = _parse_ios_pr_body_update_arguments(
        arguments
    )
    if not payload:
        raise ReleaseGuardError("governed iOS PR body must not be empty")
    if find_mentions(payload):
        raise ReleaseGuardError("governed iOS PR body failed the outbound writer check")
    expectation = IOSDraftPRBodyUpdateExpectation(
        expected_head_oid=expected_head_oid,
        expected_old_body_sha256=old_digest,
        expected_old_body_size=old_size,
        body=payload,
    )
    client = api or GitHubAPI()
    _assert_ios_pr_head(client, expectation.expected_head_oid)
    before = _expect_mapping(
        client.read(f"repos/{RELEASE_GITHUB_REPO}/pulls/{IOS_PR_NUMBER}"),
        "governed iOS PR body preflight",
    )
    old_body = before.get("body")
    if not isinstance(old_body, str):
        raise ReleaseGuardError("governed iOS PR old body is not text")
    _assert_ios_pr_body_update_readback(before, expectation, old_body)
    old_bytes = old_body.encode("utf-8")
    if (
        len(old_bytes) != expectation.expected_old_body_size
        or hashlib.sha256(old_bytes).hexdigest()
        != expectation.expected_old_body_sha256
    ):
        raise ReleaseGuardError("governed iOS PR old body bytes do not match expectation")
    if old_body == expectation.body:
        raise ReleaseGuardError("governed iOS PR body update must change the body")

    client.mutate_json(
        "PATCH",
        f"repos/{RELEASE_GITHUB_REPO}/pulls/{IOS_PR_NUMBER}",
        {"body": expectation.body},
    )

    _assert_ios_pr_head(client, expectation.expected_head_oid)
    after = _expect_mapping(
        client.read(f"repos/{RELEASE_GITHUB_REPO}/pulls/{IOS_PR_NUMBER}"),
        "governed iOS PR body readback",
    )
    _assert_ios_pr_body_update_readback(after, expectation, expectation.body)
    print(
        json.dumps(
            {
                "base": IOS_PR_BASE,
                "body_sha256": hashlib.sha256(
                    expectation.body.encode("utf-8")
                ).hexdigest(),
                "body_size": len(expectation.body.encode("utf-8")),
                "draft": True,
                "head": IOS_PR_HEAD,
                "head_oid": expectation.expected_head_oid,
                "operation": "governed-ios-pr-body-update",
                "pr_number": IOS_PR_NUMBER,
                "repository": RELEASE_GITHUB_REPO,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def execute_governed_release(
    arguments: Sequence[str],
    payload: str,
    *,
    api: GitHubAPI | None = None,
) -> int:
    """Execute exactly one governed iOS tag/release mutation and read it back."""
    operation, values = _parse_release_arguments(arguments)
    common = _release_common(values)
    tag_object_oid_argument = (
        None
        if operation == "tag-object-create"
        else _full_oid(_single(values, "--tag-object-oid"), "tag object OID")
    )
    client = api or GitHubAPI()
    _assert_common_release_state(client, common)

    if operation == "tag-object-create":
        if payload != _expected_tag_message(common):
            raise ReleaseGuardError("annotated tag message must equal the fixed governed message")
        _assert_tag_absent(client, common)
        created = _expect_mapping(
            client.mutate_json(
                "POST",
                f"repos/{RELEASE_GITHUB_REPO}/git/tags",
                {
                    "tag": common.tag,
                    "message": payload,
                    "object": common.target_oid,
                    "type": "commit",
                },
            ),
            "created tag object",
        )
        tag_object_oid = _full_oid(str(created.get("sha", "")), "created tag object OID")
        readback = _expect_mapping(
            client.read(f"repos/{RELEASE_GITHUB_REPO}/git/tags/{tag_object_oid}"),
            "created tag object readback",
        )
        target = _expect_mapping(readback.get("object"), "created tag target")
        if (
            readback.get("tag") != common.tag
            or readback.get("message") != payload
            or target.get("type") != "commit"
            or target.get("sha") != common.target_oid
        ):
            raise ReleaseGuardError("created tag object readback mismatch")
        _assert_common_release_state(client, common)
        _assert_tag_absent(client, common)
        _emit_release_receipt(
            operation,
            tag_ref=common.tag_ref,
            tag_object_oid=tag_object_oid,
            target_oid=common.target_oid,
        )
        return 0

    if operation not in {"tag-ref-create", "release-draft-create"} and payload:
        raise ReleaseGuardError(f"{operation} requires empty stdin")

    if operation == "tag-ref-create":
        if payload != _expected_tag_message(common):
            raise ReleaseGuardError("tag-ref-create requires the fixed governed tag message")
        assert tag_object_oid_argument is not None
        tag_object_oid = tag_object_oid_argument
        _assert_tag_absent(client, common)
        tag_object = _expect_mapping(
            client.read(f"repos/{RELEASE_GITHUB_REPO}/git/tags/{tag_object_oid}"),
            "tag object",
        )
        target = _expect_mapping(tag_object.get("object"), "tag object target")
        if (
            tag_object.get("tag") != common.tag
            or tag_object.get("message") != payload
            or target.get("type") != "commit"
            or target.get("sha") != common.target_oid
        ):
            raise ReleaseGuardError("tag object is not the expected annotated commit tag")
        client.mutate_json(
            "POST",
            f"repos/{RELEASE_GITHUB_REPO}/git/refs",
            {"ref": common.tag_ref, "sha": tag_object_oid},
        )
        _assert_common_release_state(client, common)
        read_oid, _ = _read_tag(client, common, tag_object_oid)
        if read_oid != tag_object_oid:
            raise ReleaseGuardError("created tag ref points to a different tag object")
        _assert_release_absent(client, common)
        _emit_release_receipt(
            operation,
            tag_ref=common.tag_ref,
            tag_object_oid=tag_object_oid,
            target_oid=common.target_oid,
        )
        return 0

    assert tag_object_oid_argument is not None
    _read_tag(client, common, tag_object_oid_argument)

    if operation == "release-draft-create":
        if not payload:
            raise ReleaseGuardError("release body must not be empty")
        title = _single(values, "--title")
        if not title:
            raise ReleaseGuardError("release title must not be empty")
        _assert_release_absent(client, common)
        created = _expect_mapping(
            client.mutate_json(
                "POST",
                f"repos/{RELEASE_GITHUB_REPO}/releases",
                {
                    "tag_name": common.tag,
                    "target_commitish": common.target_oid,
                    "name": title,
                    "body": payload,
                    "draft": True,
                    "prerelease": False,
                    "generate_release_notes": False,
                    "make_latest": "false",
                },
            ),
            "created draft release",
        )
        release_id = created.get("id")
        if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id <= 0:
            raise ReleaseGuardError("created release has invalid ID")
        _assert_common_release_state(client, common)
        release = _read_release(
            client, common, release_id, tag_object_oid_argument
        )
        if (
            release.get("draft") is not True
            or release.get("prerelease") is not False
            or release.get("name") != title
            or release.get("body") != payload
            or _remote_assets(release)
        ):
            raise ReleaseGuardError("draft release readback mismatch")
        _emit_release_receipt(
            operation,
            release_id=release_id,
            tag_ref=common.tag_ref,
            target_oid=common.target_oid,
        )
        return 0

    release_id = _release_id(_single(values, "--release-id"))
    release = _read_release(client, common, release_id, tag_object_oid_argument)
    if release.get("draft") is not True:
        raise ReleaseGuardError("asset and publish operations require a draft release")

    if operation == "asset-upload":
        expectation = _asset_expectation(
            f"{_single(values, '--asset-name')}:"
            f"{_single(values, '--asset-size')}:"
            f"{_single(values, '--asset-sha256')}"
        )
        remote_before = _remote_assets(release)
        if expectation.name in remote_before:
            raise ReleaseGuardError("release asset name is already in use")
        asset_bytes = _read_asset_bytes(_single(values, "--asset-path"), expectation)
        upload_url = release.get("upload_url")
        if not isinstance(upload_url, str):
            raise ReleaseGuardError("draft release lacks an upload URL")
        created = _expect_mapping(
            client.upload_asset(
                release_id,
                expectation.name,
                asset_bytes,
                upload_url,
            ),
            "uploaded asset",
        )
        asset_id = created.get("id")
        if not isinstance(asset_id, int) or isinstance(asset_id, bool) or asset_id <= 0:
            raise ReleaseGuardError("uploaded asset has invalid ID")
        _assert_common_release_state(client, common)
        readback = _expect_mapping(
            client.read(f"repos/{RELEASE_GITHUB_REPO}/releases/assets/{asset_id}"),
            "uploaded asset readback",
        )
        expected_digest = f"sha256:{expectation.sha256}"
        if (
            readback.get("name") != expectation.name
            or readback.get("size") != expectation.size
            or readback.get("digest") != expected_digest
            or readback.get("state") != "uploaded"
        ):
            raise ReleaseGuardError("uploaded asset readback mismatch")
        release_after = _read_release(
            client, common, release_id, tag_object_oid_argument
        )
        expected_after = {**remote_before, expectation.name: expectation}
        if _remote_assets(release_after) != expected_after:
            raise ReleaseGuardError("release asset-set readback mismatch after upload")
        _emit_release_receipt(
            operation,
            asset_id=asset_id,
            asset_name=expectation.name,
            asset_sha256=expectation.sha256,
            asset_size=expectation.size,
            release_id=release_id,
        )
        return 0

    if operation == "release-publish":
        expected_assets: dict[str, AssetExpectation] = {}
        for value in values.get("--asset", []):
            expectation = _asset_expectation(value)
            if expectation.name in expected_assets:
                raise ReleaseGuardError("duplicate expected asset name")
            expected_assets[expectation.name] = expectation
        if frozenset(expected_assets) != RELEASE_ASSET_NAMES:
            raise ReleaseGuardError("publish requires the exact governed asset-name set")
        if _remote_assets(release) != expected_assets:
            raise ReleaseGuardError("draft release assets do not match the publish manifest")
        client.mutate_json(
            "PATCH",
            f"repos/{RELEASE_GITHUB_REPO}/releases/{release_id}",
            {"draft": False, "make_latest": "true"},
        )
        _assert_common_release_state(client, common)
        published = _read_release(
            client, common, release_id, tag_object_oid_argument
        )
        if published.get("draft") is not False:
            raise ReleaseGuardError("release publish readback is still draft")
        if published.get("prerelease") is not False:
            raise ReleaseGuardError("release publish readback is unexpectedly prerelease")
        if _remote_assets(published) != expected_assets:
            raise ReleaseGuardError("published release assets changed during publish")
        _emit_release_receipt(
            operation,
            release_id=release_id,
            tag_ref=common.tag_ref,
            target_oid=common.target_oid,
        )
        return 0

    raise AssertionError(f"unhandled governed release operation: {operation}")


class TheyosV0126TagGit:
    """Git boundary for the one governed theyos v0.1.26 annotated tag."""

    def _run(
        self,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        allowed_returncodes: frozenset[int] = frozenset({0}),
    ) -> subprocess.CompletedProcess[bytes]:
        command = ["git", *arguments]
        completed = subprocess.run(
            command,
            input=input_bytes,
            capture_output=True,
            check=False,
        )
        if completed.returncode not in allowed_returncodes:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            raise TheyosTagGuardError(
                f"git command failed with exit {completed.returncode}: "
                f"{' '.join(command[:8])}: {stderr}"
            )
        return completed

    def output(
        self,
        arguments: Sequence[str],
        *,
        allowed_returncodes: frozenset[int] = frozenset({0}),
    ) -> tuple[int, bytes]:
        completed = self._run(arguments, allowed_returncodes=allowed_returncodes)
        return completed.returncode, completed.stdout

    def repository_root(self) -> Path:
        _, output = self.output(["rev-parse", "--show-toplevel"])
        text = output.decode("utf-8", errors="strict").strip()
        if not text:
            raise TheyosTagGuardError("git repository root is empty")
        return Path(text).resolve()

    def origin_urls(self, *, push: bool) -> tuple[str, ...]:
        arguments = ["remote", "get-url"]
        if push:
            arguments.append("--push")
        arguments.extend(["--all", "origin"])
        _, output = self.output(arguments)
        return tuple(output.decode("utf-8", errors="strict").splitlines())

    def config_values(self, key: str) -> tuple[str, ...]:
        returncode, output = self.output(
            ["config", "--get-all", key],
            allowed_returncodes=frozenset({0, 1}),
        )
        if returncode == 1:
            return ()
        return tuple(output.decode("utf-8", errors="strict").splitlines())

    def head_oid(self) -> str:
        _, output = self.output(["rev-parse", "HEAD"])
        return output.decode("ascii", errors="strict").strip()

    def origin_main_oid(self) -> str:
        _, output = self.output(["rev-parse", "refs/remotes/origin/main"])
        return output.decode("ascii", errors="strict").strip()

    def object_type(self, oid: str) -> str:
        _, output = self.output(["cat-file", "-t", oid])
        return output.decode("ascii", errors="strict").strip()

    def clean(self) -> bool:
        _, output = self.output(
            ["status", "--porcelain=v1", "--untracked-files=all"]
        )
        return output == b""

    def read_repository_file(self, relative_path: str) -> bytes:
        root = self.repository_root()
        path = (root / relative_path).resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise TheyosTagGuardError(
                "version path escapes the repository"
            ) from error
        if path.is_symlink() or not path.is_file():
            raise TheyosTagGuardError(
                f"required version file is not a regular file: {relative_path}"
            )
        return path.read_bytes()

    def local_ref(self, ref: str) -> str | None:
        returncode, output = self.output(
            ["show-ref", "--verify", "--hash", ref],
            allowed_returncodes=frozenset({0, 1}),
        )
        if returncode == 1:
            return None
        return output.decode("ascii", errors="strict").strip()

    def remote_refs(self, refs: Sequence[str]) -> dict[str, str]:
        _, output = self.output(["ls-remote", "origin", *refs])
        found: dict[str, str] = {}
        for raw_line in output.splitlines():
            fields = raw_line.decode("ascii", errors="strict").split("\t")
            if len(fields) != 2 or fields[1] in found:
                raise TheyosTagGuardError("remote ref readback is malformed or duplicated")
            found[fields[1]] = fields[0]
        return found

    def tag_object_bytes(self, tag_object_oid: str) -> bytes:
        _, output = self.output(["cat-file", "tag", tag_object_oid])
        return output

    def create_tag(self, target_oid: str, message: bytes) -> None:
        self._run(
            [
                "-c",
                "core.hooksPath=/dev/null",
                "tag",
                "--annotate",
                "--no-sign",
                "--cleanup=verbatim",
                "--file=-",
                THEYOS_TAG,
                target_oid,
            ],
            input_bytes=message,
        )

    def push_tag(self) -> None:
        self._run(
            [
                "-c",
                "push.followTags=false",
                "-c",
                "push.gpgSign=false",
                "push",
                "--no-follow-tags",
                "--no-signed",
                "--no-verify",
                "--porcelain",
                "origin",
                f"{THEYOS_TAG_REF}:{THEYOS_TAG_REF}",
            ]
        )


def _parse_theyos_v0126_tag_arguments(
    arguments: Sequence[str],
) -> tuple[str, str, str]:
    if not arguments:
        raise UnsafeCommand("governed-theyos-v0126-tag requires an operation")
    operation = arguments[0]
    if operation not in {"create", "push"}:
        raise UnsafeCommand(
            f"unsupported governed-theyos-v0126-tag operation: {operation}"
        )
    values: dict[str, str] = {}
    index = 1
    while index < len(arguments):
        flag = arguments[index]
        if flag not in {"--target-oid", "--expected-main"}:
            raise UnsafeCommand(
                f"unsupported governed-theyos-v0126-tag argument: {flag}"
            )
        if flag in values:
            raise UnsafeCommand(
                f"duplicate governed-theyos-v0126-tag argument: {flag}"
            )
        if index + 1 >= len(arguments):
            raise UnsafeCommand(
                f"missing value for governed-theyos-v0126-tag argument: {flag}"
            )
        values[flag] = arguments[index + 1]
        index += 2
    missing = {"--target-oid", "--expected-main"} - values.keys()
    if missing:
        raise UnsafeCommand(
            "missing governed-theyos-v0126-tag arguments: "
            + ", ".join(sorted(missing))
        )
    target_oid = _full_oid(values["--target-oid"], "target OID")
    expected_main = _full_oid(values["--expected-main"], "expected main OID")
    if target_oid != expected_main:
        raise TheyosTagGuardError("tag target and expected main must be identical")
    return operation, target_oid, expected_main


def _cargo_package_version(payload: bytes) -> str:
    match = re.search(
        rb"(?ms)^\[package\][ \t]*\r?$.*?^version[ \t]*=[ \t]*\"([^\"\r\n]+)\"[ \t]*\r?$",
        payload,
    )
    if match is None:
        raise TheyosTagGuardError("canonical Cargo package version is missing")
    return match.group(1).decode("utf-8", errors="strict")


def _tag_object_fields(payload: bytes) -> tuple[dict[bytes, bytes], bytes]:
    header, separator, message = payload.partition(b"\n\n")
    if not separator:
        raise TheyosTagGuardError("annotated tag object has no header/message separator")
    fields: dict[bytes, bytes] = {}
    for line in header.splitlines():
        name, separator, value = line.partition(b" ")
        if not separator or name in fields:
            raise TheyosTagGuardError("annotated tag object header is malformed or duplicated")
        fields[name] = value
    if set(fields) != {b"object", b"type", b"tag", b"tagger"}:
        raise TheyosTagGuardError("annotated tag object has unexpected headers")
    if re.fullmatch(rb".+ <[^<>\r\n]+> [0-9]+ [+-][0-9]{4}", fields[b"tagger"]) is None:
        raise TheyosTagGuardError("annotated tag object tagger is invalid")
    return fields, message


def _assert_local_tag(
    git: TheyosV0126TagGit,
    target_oid: str,
) -> str:
    tag_object_oid = git.local_ref(THEYOS_TAG_REF)
    if tag_object_oid is None:
        raise TheyosTagGuardError("governed local tag is absent")
    tag_object_oid = _full_oid(tag_object_oid, "local tag object OID")
    if git.object_type(tag_object_oid) != "tag":
        raise TheyosTagGuardError("governed local tag is lightweight")
    fields, message = _tag_object_fields(git.tag_object_bytes(tag_object_oid))
    if (
        fields[b"object"].decode("ascii", errors="strict") != target_oid
        or fields[b"type"] != b"commit"
        or fields[b"tag"].decode("utf-8", errors="strict") != THEYOS_TAG
        or message != THEYOS_TAG_MESSAGE.encode("utf-8")
    ):
        raise TheyosTagGuardError("governed local annotated tag readback mismatch")
    return tag_object_oid


def _assert_theyos_tag_api_absent(api: GitHubAPI) -> None:
    if api.read_optional(
        f"repos/{SAFE_GITHUB_REPO}/git/ref/tags/{THEYOS_TAG}"
    ) is not None:
        raise TheyosTagGuardError("governed tag already exists in the GitHub API")


def _assert_theyos_main_api(api: GitHubAPI, expected_main: str) -> None:
    value = _expect_mapping(
        api.read(f"repos/{SAFE_GITHUB_REPO}/git/ref/heads/main"),
        "theyos main ref",
    )
    target = _expect_mapping(value.get("object"), "theyos main target")
    if (
        value.get("ref") != "refs/heads/main"
        or target.get("type") != "commit"
        or target.get("sha") != expected_main
    ):
        raise TheyosTagGuardError("GitHub API main ref drifted")


def _assert_theyos_tag_api_readback(
    api: GitHubAPI,
    tag_object_oid: str,
    target_oid: str,
) -> None:
    value = _expect_mapping(
        api.read(f"repos/{SAFE_GITHUB_REPO}/git/ref/tags/{THEYOS_TAG}"),
        "theyos tag ref",
    )
    target = _expect_mapping(value.get("object"), "theyos tag ref target")
    if (
        value.get("ref") != THEYOS_TAG_REF
        or target.get("type") != "tag"
        or target.get("sha") != tag_object_oid
    ):
        raise TheyosTagGuardError("GitHub API tag ref readback mismatch")
    tag_object = _expect_mapping(
        api.read(f"repos/{SAFE_GITHUB_REPO}/git/tags/{tag_object_oid}"),
        "theyos tag object",
    )
    peeled = _expect_mapping(tag_object.get("object"), "theyos tag object target")
    if (
        tag_object.get("sha") != tag_object_oid
        or tag_object.get("tag") != THEYOS_TAG
        or tag_object.get("message") != THEYOS_TAG_MESSAGE
        or peeled.get("type") != "commit"
        or peeled.get("sha") != target_oid
    ):
        raise TheyosTagGuardError("GitHub API annotated tag readback mismatch")


def _assert_theyos_v0126_preconditions(
    git: TheyosV0126TagGit,
    api: GitHubAPI,
    target_oid: str,
    expected_main: str,
) -> None:
    canonical_origin = (THEYOS_REPOSITORY_URL,)
    if git.origin_urls(push=False) != canonical_origin:
        raise TheyosTagGuardError(
            "origin must have exactly one canonical theyos fetch URL"
        )
    if git.origin_urls(push=True) != canonical_origin:
        raise TheyosTagGuardError(
            "origin must have exactly one canonical theyos push URL"
        )
    for key in (
        "remote.origin.push",
        "remote.origin.receivepack",
        "push.pushOption",
        "remote.origin.mirror",
    ):
        if git.config_values(key):
            raise TheyosTagGuardError(f"unsafe Git configuration is set: {key}")
    if git.head_oid() != target_oid:
        raise TheyosTagGuardError("HEAD does not equal the governed tag target")
    if git.origin_main_oid() != expected_main:
        raise TheyosTagGuardError("origin/main does not equal expected main")
    if git.object_type(target_oid) != "commit":
        raise TheyosTagGuardError("governed tag target is not a commit")
    if not git.clean():
        raise TheyosTagGuardError("worktree is not clean")
    if git.read_repository_file(THEYOS_VERSION_FILE) != (
        THEYOS_TAG_VERSION + "\n"
    ).encode("utf-8"):
        raise TheyosTagGuardError("VERSION is not exactly the governed version")
    cargo_version = _cargo_package_version(
        git.read_repository_file(THEYOS_CARGO_FILE)
    )
    if cargo_version != THEYOS_TAG_VERSION:
        raise TheyosTagGuardError("canonical Cargo version is not the governed version")

    refs = git.remote_refs(
        (
            "refs/heads/main",
            f"refs/heads/{THEYOS_TAG}",
            THEYOS_TAG_REF,
            f"{THEYOS_TAG_REF}^{{}}",
        )
    )
    if refs.get("refs/heads/main") != expected_main:
        raise TheyosTagGuardError("remote main does not equal expected main")
    if f"refs/heads/{THEYOS_TAG}" in refs:
        raise TheyosTagGuardError("remote branch makes the tag name ambiguous")
    if git.local_ref(f"refs/heads/{THEYOS_TAG}") is not None:
        raise TheyosTagGuardError("local branch makes the tag name ambiguous")
    _assert_theyos_main_api(api, expected_main)


def execute_governed_theyos_v0126_tag(
    arguments: Sequence[str],
    payload: str,
    *,
    git: TheyosV0126TagGit | None = None,
    api: GitHubAPI | None = None,
) -> int:
    """Create locally or push the one fixed annotated theyos v0.1.26 tag."""
    operation, target_oid, expected_main = _parse_theyos_v0126_tag_arguments(
        arguments
    )
    repository = git or TheyosV0126TagGit()
    client = api or GitHubAPI()
    _assert_theyos_v0126_preconditions(
        repository, client, target_oid, expected_main
    )

    remote_refs = repository.remote_refs(
        (THEYOS_TAG_REF, f"{THEYOS_TAG_REF}^{{}}")
    )
    if remote_refs:
        raise TheyosTagGuardError("governed tag already exists remotely")
    _assert_theyos_tag_api_absent(client)

    if operation == "create":
        if payload != THEYOS_TAG_MESSAGE:
            raise TheyosTagGuardError(
                "annotated tag message must equal the fixed governed message"
            )
        if repository.local_ref(THEYOS_TAG_REF) is not None:
            raise TheyosTagGuardError("governed local tag already exists")
        repository.create_tag(target_oid, payload.encode("utf-8"))
        tag_object_oid = _assert_local_tag(repository, target_oid)
    else:
        if payload:
            raise TheyosTagGuardError("tag push accepts no payload")
        tag_object_oid = _assert_local_tag(repository, target_oid)
        # Re-read every moving precondition immediately before the sole push.
        _assert_theyos_v0126_preconditions(
            repository, client, target_oid, expected_main
        )
        if repository.remote_refs(
            (THEYOS_TAG_REF, f"{THEYOS_TAG_REF}^{{}}")
        ):
            raise TheyosTagGuardError("governed tag appeared before push")
        _assert_theyos_tag_api_absent(client)
        repository.push_tag()
        remote_refs = repository.remote_refs(
            (THEYOS_TAG_REF, f"{THEYOS_TAG_REF}^{{}}")
        )
        if remote_refs != {
            THEYOS_TAG_REF: tag_object_oid,
            f"{THEYOS_TAG_REF}^{{}}": target_oid,
        }:
            raise TheyosTagGuardError("remote tag ref or peeled target mismatch")
        _assert_theyos_tag_api_readback(
            client, tag_object_oid, target_oid
        )

    print(
        json.dumps(
            {
                "operation": f"governed-theyos-v0126-tag-{operation}",
                "tag_ref": THEYOS_TAG_REF,
                "tag_object_oid": tag_object_oid,
                "target_oid": target_oid,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


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


    if command[:1] == ["governed-release"]:
        try:
            return execute_governed_release(command[1:], payload)
        except (UnsafeCommand, ReleaseGuardError, GitHubAPIError) as error:
            print(f"BLOCKED: {error}", file=sys.stderr)
            return 2

    if command[:1] == ["governed-ios-pr-create"]:
        try:
            return execute_governed_ios_pr_create(command[1:], payload)
        except (UnsafeCommand, ReleaseGuardError, GitHubAPIError) as error:
            print(f"BLOCKED: {error}", file=sys.stderr)
            return 2

    if command[:1] == ["governed-ios-pr-body-update"]:
        try:
            return execute_governed_ios_pr_body_update(command[1:], payload)
        except (UnsafeCommand, ReleaseGuardError, GitHubAPIError) as error:
            print(f"BLOCKED: {error}", file=sys.stderr)
            return 2

    if command[:1] == ["governed-theyos-v0126-tag"]:
        try:
            return execute_governed_theyos_v0126_tag(command[1:], payload)
        except (
            UnsafeCommand,
            ReleaseGuardError,
            TheyosTagGuardError,
            GitHubAPIError,
        ) as error:
            print(f"BLOCKED: {error}", file=sys.stderr)
            return 2

    try:
        prepared_command = prepare_command(command)
    except UnsafeCommand as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2

    try:
        completed = subprocess.run(
            prepared_command,
            input=forwarded_stdin,
            check=False,
            env=child_environment(prepared_command),
        )
    except FileNotFoundError as error:
        print(f"external write command not found: {error.filename}", file=sys.stderr)
        return 127
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
