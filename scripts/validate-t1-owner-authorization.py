#!/usr/bin/env python3
"""Validate a private T1 owner authorization record without printing values."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path


SCOPE = "dev-host T1-T4 only"

CHECKBOX_RE = re.compile(r"^\s*[-*]\s+\[([ xX])\]\s+(?P<label>.+?)\s*$", re.MULTILINE)
PLACEHOLDER_RE = re.compile(r"<[^>\n]+>")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ABSOLUTE_LOCAL_PATH_RE = re.compile(r"(?<![\w:/])/[A-Za-z][A-Za-z0-9._-]*(?:/[^\s`|)<>,;:]+)*")
SECRET_ASSIGNMENT_RE = re.compile(
    r"\b(?:api[_-]?key|token|password|secret|private[_-]?key)\b\s*[:=]\s*\S+",
    re.IGNORECASE,
)
PRIVATE_KEY_BLOCK_RE = re.compile("BE" "GIN " + r"[A-Z0-9 -]*" + "PRIVATE KEY", re.IGNORECASE)
OWNER_SENTENCE_RE = re.compile(
    r"I authorize dev-host per-Claw VPN T1-T4 validation for .+; "
    r"I do not authorize production activation\.",
    re.IGNORECASE,
)


def documentation_ipv4_network(octets: tuple[int, int, int, int], prefix: int) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(f"{'.'.join(str(octet) for octet in octets)}/{prefix}")


DOCUMENTATION_IPV4_NETWORKS = tuple(
    documentation_ipv4_network(octets, prefix)
    for octets, prefix in (
        ((192, 0, 2, 0), 24),
        ((198, 51, 100, 0), 24),
        ((203, 0, 113, 0), 24),
        ((198, 18, 0, 0), 15),
    )
)

REQUIRED_TEXT: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("artifact", re.compile(r"\bartifact\b", re.IGNORECASE)),
    ("topology", re.compile(r"\btopology\b.*\bengine\b.*\bclaw\b.*\bdevice\b.*\brelay\b.*\bmember\b", re.IGNORECASE)),
    ("time window", re.compile(r"\btime window\b.*\bthrough\b", re.IGNORECASE)),
    ("operator", re.compile(r"\boperator\b", re.IGNORECASE)),
    ("rollback artifact", re.compile(r"\brollback artifact\b", re.IGNORECASE)),
    ("data policy", re.compile(r"\bdata policy\b.*\b(redact|neutral alias)", re.IGNORECASE)),
    ("stop authority", re.compile(r"\bstop authority\b.*\bstop\b", re.IGNORECASE)),
    (
        "production exclusion",
        re.compile(
            r"\bproduction\b.*\b(exclude[ds]?|not touched|false|no)\b|"
            r"\b(exclude[ds]?|not touched|no)\b.*\bproduction\b",
            re.IGNORECASE,
        ),
    ),
)


def is_full_git_sha(value: str) -> bool:
    return len(value) == 40 and all(byte in "0123456789abcdefABCDEF" for byte in value)


def has_unchecked_items(markdown: str) -> bool:
    return any(match.group(1) == " " for match in CHECKBOX_RE.finditer(markdown))


def normalized_text(markdown: str) -> str:
    return re.sub(r"\s+", " ", markdown.replace("`", "")).strip()


def has_false_production_activation(markdown: str) -> bool:
    normalized = normalized_text(markdown)
    return (
        re.search(r"\bproduction[_ -]?activation\b\s*[:=]\s*false\b", normalized, re.IGNORECASE)
        is not None
    )


def has_true_production_activation(markdown: str) -> bool:
    normalized = normalized_text(markdown)
    return (
        re.search(r"\bproduction[_ -]?activation\b\s*[:=]\s*true\b", normalized, re.IGNORECASE)
        is not None
    )


def contains_non_documentation_ipv4(markdown: str) -> bool:
    for match in IPV4_RE.finditer(markdown):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            return True
        if not any(address in network for network in DOCUMENTATION_IPV4_NETWORKS):
            return True
    return False


def privacy_errors(markdown: str) -> list[str]:
    errors: list[str] = []
    if contains_non_documentation_ipv4(markdown):
        errors.append("owner authorization must use only documentation-safe IPv4 addresses")
    if ABSOLUTE_LOCAL_PATH_RE.search(markdown):
        errors.append("owner authorization must not contain local absolute paths")
    if PRIVATE_KEY_BLOCK_RE.search(markdown) or SECRET_ASSIGNMENT_RE.search(markdown):
        errors.append("owner authorization must not contain secrets or key material")
    return errors


def validate_owner_authorization(markdown: str, expected_sha: str, expected_pr: int | None) -> list[str]:
    errors: list[str] = []
    if "\x00" in markdown:
        return ["owner authorization must be UTF-8 text without NUL bytes"]

    text = normalized_text(markdown)
    if not is_full_git_sha(expected_sha):
        errors.append("expected artifact SHA must be 40 hex characters")
    elif expected_sha not in markdown:
        errors.append("owner authorization must reference the expected artifact SHA")

    if expected_pr is not None and f"#{expected_pr}" not in markdown:
        errors.append("owner authorization must reference the expected PR")

    if SCOPE not in markdown:
        errors.append("scope must be dev-host T1-T4 only")
    if has_true_production_activation(markdown) or not has_false_production_activation(markdown):
        errors.append("production_activation must be false")
    if OWNER_SENTENCE_RE.search(text) is None:
        errors.append("owner authorization must include the required owner sentence")

    if PLACEHOLDER_RE.search(markdown):
        errors.append("owner authorization must not contain template placeholders")
    if has_unchecked_items(markdown):
        errors.append("owner authorization must not contain unchecked checklist items")
    errors.extend(privacy_errors(markdown))

    for label, pattern in REQUIRED_TEXT:
        if pattern.search(text) is None:
            errors.append(f"owner authorization must include {label}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a private Product A per-Claw VPN T1 owner authorization "
            "record. Error output names missing sections only; it does not echo "
            "private authorization values."
        )
    )
    parser.add_argument("expected_artifact_sha", help="exact 40-hex artifact SHA")
    parser.add_argument("owner_authorization_record", help="path to the private owner authorization record")
    parser.add_argument("--expected-pr", type=int, help="expected activation PR number")
    args = parser.parse_args()

    try:
        markdown = Path(args.owner_authorization_record).read_text(encoding="utf-8")
    except UnicodeDecodeError:
        print("ERROR: owner authorization is not valid UTF-8", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"ERROR: could not read owner authorization: {error.__class__.__name__}", file=sys.stderr)
        return 2

    errors = validate_owner_authorization(markdown, args.expected_artifact_sha, args.expected_pr)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("OK: T1 owner authorization validates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
