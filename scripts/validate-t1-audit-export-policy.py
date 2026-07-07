#!/usr/bin/env python3
"""Validate a private T1 audit export policy without printing its values."""

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
    r"\b(?:api[_-]?key|token|password|secret|private[_-]?key|hmac[_-]?key|export[_-]?key)\b\s*[:=]\s*\S+",
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
        "HMAC-SHA-256 keyed export",
        re.compile(r"\bHMAC\b.*\bSHA-?256\b.*\bkeyed\b|\bkeyed\b.*\bHMAC\b.*\bSHA-?256\b", re.IGNORECASE),
    ),
    (
        "reviewed export key source",
        re.compile(
            r"\bexport\b.*\bkey\b.*\bsource\b.*\breview(?:ed)?\b|"
            r"\breview(?:ed)?\b.*\bexport\b.*\bkey\b.*\bsource\b",
            re.IGNORECASE,
        ),
    ),
    (
        "export key rotation policy",
        re.compile(r"\bexport\b.*\bkey\b.*\brotation\b|\brotation\b.*\bexport\b.*\bkey\b", re.IGNORECASE),
    ),
    (
        "export key retention policy",
        re.compile(r"\bexport\b.*\bkey\b.*\b(retention|retire|retirement)\b", re.IGNORECASE),
    ),
    (
        "export data retention policy",
        re.compile(r"\bexport\b.*\b(data|JSONL|record)\b.*\bretention\b|\bretention\b.*\bexport\b.*\b(data|JSONL|record)\b", re.IGNORECASE),
    ),
    (
        "raw subject redaction",
        re.compile(
            r"\b(raw|plain)\b.*\b(member|device|claw|subject)\b.*\b(redact(?:ed)?|omit(?:ted)?|exclude(?:d)?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "local pseudonymous hash omission",
        re.compile(r"\blocal\b.*\bpseudonymous\b.*\bhash\b.*\b(omit(?:ted)?|exclude(?:d)?|not)\b", re.IGNORECASE),
    ),
    (
        "off-host destination review",
        re.compile(r"\boff-host\b.*\b(destination|recipient|export)\b.*\breview\b", re.IGNORECASE),
    ),
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
        errors.append("audit export policy must use only documentation-safe IPv4 addresses")
    if ABSOLUTE_LOCAL_PATH_RE.search(markdown):
        errors.append("audit export policy must not contain local absolute paths")
    if PRIVATE_KEY_BLOCK_RE.search(markdown) or SECRET_ASSIGNMENT_RE.search(markdown):
        errors.append("audit export policy must not contain secrets or key material")
    return errors


def validate_audit_export_policy(markdown: str, expected_sha: str, expected_pr: int | None) -> list[str]:
    errors: list[str] = []
    if "\x00" in markdown:
        return ["audit export policy must be UTF-8 text without NUL bytes"]

    if not is_full_git_sha(expected_sha):
        errors.append("expected artifact SHA must be 40 hex characters")
    elif expected_sha not in markdown:
        errors.append("audit export policy must reference the expected artifact SHA")

    if expected_pr is not None and f"#{expected_pr}" not in markdown:
        errors.append("audit export policy must reference the expected PR")

    if SCOPE not in markdown:
        errors.append("scope must be dev-host T1-T4 only")
    if has_true_production_activation(markdown) or not has_false_production_activation(markdown):
        errors.append("production_activation must be false")

    if PLACEHOLDER_RE.search(markdown):
        errors.append("audit export policy must not contain template placeholders")
    if has_unchecked_items(markdown):
        errors.append("audit export policy must not contain unchecked checklist items")
    errors.extend(privacy_errors(markdown))

    checked = checked_items(markdown)
    if not checked:
        errors.append("audit export policy must contain checked checklist items")
    for label, pattern in REQUIRED_CHECKED_ITEMS:
        if not any(pattern.search(item) for item in checked):
            errors.append(f"audit export policy must include checked item for {label}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a private Product A per-Claw VPN T1 audit export policy. "
            "Error output names missing sections only; it does not echo private "
            "export policy values."
        )
    )
    parser.add_argument("expected_artifact_sha", help="exact 40-hex artifact SHA")
    parser.add_argument("audit_export_policy", help="path to the private audit export policy")
    parser.add_argument("--expected-pr", type=int, help="expected activation PR number")
    args = parser.parse_args()

    try:
        markdown = Path(args.audit_export_policy).read_text(encoding="utf-8")
    except UnicodeDecodeError:
        print("ERROR: audit export policy is not valid UTF-8", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"ERROR: could not read audit export policy: {error.__class__.__name__}", file=sys.stderr)
        return 2

    errors = validate_audit_export_policy(markdown, args.expected_artifact_sha, args.expected_pr)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("OK: T1 audit export policy validates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
