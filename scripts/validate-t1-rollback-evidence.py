#!/usr/bin/env python3
"""Validate a private T1 rollback evidence record without printing values."""

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

REQUIRED_CHECKED_ITEMS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "previous known-good dev engine artifact",
        re.compile(r"\b(previous known-good|known-good)\b.*\b(dev engine|artifact|package)\b", re.IGNORECASE),
    ),
    ("prebuilt rollback", re.compile(r"\bprebuilt\b.*\brollback\b|\brollback\b.*\bprebuilt\b", re.IGNORECASE)),
    (
        "restore operation",
        re.compile(r"\brestore\b.*\b(command|operation|service)\b|\b(command|operation|service)\b.*\brestore\b", re.IGNORECASE),
    ),
    (
        "redacted environment snapshot",
        re.compile(r"\b(env|environment)\b.*\bsnapshot\b.*\b(secret|redact)", re.IGNORECASE),
    ),
    ("Linux route cleanup", re.compile(r"\bLinux\b.*\broute\b.*\bcleanup\b", re.IGNORECASE)),
    ("macOS route cleanup", re.compile(r"\bmacOS\b.*\broute\b.*\bcleanup\b", re.IGNORECASE)),
    ("Linux TUN cleanup", re.compile(r"\bLinux\b.*\bTUN\b.*\bcleanup\b", re.IGNORECASE)),
    ("macOS utun cleanup", re.compile(r"\bmacOS\b.*\butun\b.*\bcleanup\b", re.IGNORECASE)),
    ("relay/process stop", re.compile(r"\b(relay|process)\b.*\bstop\b|\bstop\b.*\b(relay|process)\b", re.IGNORECASE)),
    ("baseline health verification", re.compile(r"\bbaseline\b.*\bhealth\b.*\bverif", re.IGNORECASE)),
    ("no local rebuild dependency", re.compile(r"\b(no|not|must not|does not)\b.*\brebuild\b", re.IGNORECASE)),
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


def checked_items(markdown: str) -> list[str]:
    return [match.group("label") for match in CHECKBOX_RE.finditer(markdown) if match.group(1).lower() == "x"]


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
        errors.append("rollback evidence must use only documentation-safe IPv4 addresses")
    if ABSOLUTE_LOCAL_PATH_RE.search(markdown):
        errors.append("rollback evidence must not contain local absolute paths")
    if PRIVATE_KEY_BLOCK_RE.search(markdown) or SECRET_ASSIGNMENT_RE.search(markdown):
        errors.append("rollback evidence must not contain secrets or key material")
    return errors


def validate_rollback_evidence(markdown: str, expected_sha: str, expected_pr: int | None) -> list[str]:
    errors: list[str] = []
    if "\x00" in markdown:
        return ["rollback evidence must be UTF-8 text without NUL bytes"]

    if not is_full_git_sha(expected_sha):
        errors.append("expected artifact SHA must be 40 hex characters")
    elif expected_sha not in markdown:
        errors.append("rollback evidence must reference the expected artifact SHA")

    if expected_pr is not None and f"#{expected_pr}" not in markdown:
        errors.append("rollback evidence must reference the expected PR")

    if SCOPE not in markdown:
        errors.append("scope must be dev-host T1-T4 only")
    if has_true_production_activation(markdown) or not has_false_production_activation(markdown):
        errors.append("production_activation must be false")

    if PLACEHOLDER_RE.search(markdown):
        errors.append("rollback evidence must not contain template placeholders")
    if has_unchecked_items(markdown):
        errors.append("rollback evidence must not contain unchecked checklist items")
    errors.extend(privacy_errors(markdown))

    checked = checked_items(markdown)
    if not checked:
        errors.append("rollback evidence must contain checked checklist items")
    for label, pattern in REQUIRED_CHECKED_ITEMS:
        if not any(pattern.search(item) for item in checked):
            errors.append(f"rollback evidence must include checked item for {label}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a private Product A per-Claw VPN T1 rollback evidence "
            "record. Error output names missing sections only; it does not echo "
            "private rollback values."
        )
    )
    parser.add_argument("expected_artifact_sha", help="exact 40-hex artifact SHA")
    parser.add_argument("rollback_evidence", help="path to the private rollback evidence record")
    parser.add_argument("--expected-pr", type=int, help="expected activation PR number")
    args = parser.parse_args()

    try:
        markdown = Path(args.rollback_evidence).read_text(encoding="utf-8")
    except UnicodeDecodeError:
        print("ERROR: rollback evidence is not valid UTF-8", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"ERROR: could not read rollback evidence: {error.__class__.__name__}", file=sys.stderr)
        return 2

    errors = validate_rollback_evidence(markdown, args.expected_artifact_sha, args.expected_pr)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("OK: T1 rollback evidence validates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
