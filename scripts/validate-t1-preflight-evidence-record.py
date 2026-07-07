#!/usr/bin/env python3
"""Validate a private T1 preflight evidence record without printing its values."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path, PurePosixPath
from types import ModuleType


SCHEMA = "per_claw_vpn_t1_preflight_evidence_v1"
SCOPE = "dev-host T1-T4 only"
REQUIRED_TRUE = ("owner_authorization", "rollback", "hardware_t1_t4")
REQUIRED_REFS = (
    "owner_authorization_ref",
    "rollback_ref",
    "hardware_evidence_ref",
    "audit_export_policy_ref",
)
OWNER_AUTHORIZATION_VALIDATOR = Path(__file__).with_name("validate-t1-owner-authorization.py")
ROLLBACK_EVIDENCE_VALIDATOR = Path(__file__).with_name("validate-t1-rollback-evidence.py")
HARDWARE_PACK_VALIDATOR = Path(__file__).with_name("validate-t1-hardware-evidence-pack.py")
AUDIT_EXPORT_POLICY_VALIDATOR = Path(__file__).with_name("validate-t1-audit-export-policy.py")


def is_full_git_sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(byte in "0123456789abcdefABCDEF" for byte in value)
    )


def has_only_root_and_normal_components(path: str) -> bool:
    if "\x00" in path:
        return False
    pure = PurePosixPath(path)
    if not pure.is_absolute():
        return False
    return all(part not in ("", ".", "..") for part in pure.parts[1:])


def is_template_placeholder(value: str) -> bool:
    stripped = value.strip()
    return stripped.startswith("<") and stripped.endswith(">")


def validate_root_dir(path: str) -> list[str]:
    errors: list[str] = []
    if os.path.realpath(path) != os.path.abspath(path):
        errors.append("audit_root must be canonical with no symlink ancestors")
    try:
        metadata = os.lstat(path)
    except OSError:
        return ["audit_root does not exist or cannot be stat()ed"]

    if stat.S_ISLNK(metadata.st_mode):
        errors.append("audit_root must not be a symlink")
    if not stat.S_ISDIR(metadata.st_mode):
        errors.append("audit_root must be a directory")
    if metadata.st_uid != os.geteuid():
        errors.append("audit_root must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        errors.append("audit_root mode must be exactly 0700")
    return errors


def validate_record(record: object, expected_sha: str, check_root_dir: bool) -> list[str]:
    errors: list[str] = []
    if not isinstance(record, dict):
        return ["record must be a JSON object"]

    if record.get("schema") != SCHEMA:
        errors.append("schema must be per_claw_vpn_t1_preflight_evidence_v1")
    if record.get("scope") != SCOPE:
        errors.append("scope must be dev-host T1-T4 only")
    if record.get("production_activation") is not False:
        errors.append("production_activation must be false")

    if not is_full_git_sha(expected_sha):
        errors.append("expected artifact SHA must be 40 hex characters")
    if not is_full_git_sha(record.get("artifact_sha")):
        errors.append("record artifact_sha must be 40 hex characters")
    elif record.get("artifact_sha") != expected_sha:
        errors.append("record artifact_sha must match the expected artifact SHA")

    for field in REQUIRED_TRUE:
        if record.get(field) is not True:
            errors.append(f"{field} must be true")

    for field in REQUIRED_REFS:
        value = record.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field} must be a non-empty string")
        elif is_template_placeholder(value):
            errors.append(f"{field} must not be a template placeholder")

    audit_root = record.get("audit_root")
    if not isinstance(audit_root, str) or not has_only_root_and_normal_components(audit_root):
        errors.append("audit_root must be an absolute path with normal components only")
    elif check_root_dir:
        errors.extend(validate_root_dir(audit_root))

    return errors


def load_sibling_validator(module_name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("validator unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_private_ref(record: dict[str, object], field: str) -> tuple[str | None, str | None]:
    ref = record.get(field)
    if not isinstance(ref, str) or not ref.strip() or is_template_placeholder(ref):
        return None, None

    try:
        return Path(ref).read_text(encoding="utf-8"), None
    except UnicodeDecodeError:
        return None, f"{field} artifact is not valid UTF-8"
    except OSError as error:
        return None, f"{field} artifact could not be read: {error.__class__.__name__}"


def validate_owner_authorization_ref(record: dict[str, object], expected_sha: str, expected_pr: int | None) -> list[str]:
    markdown, error = read_private_ref(record, "owner_authorization_ref")
    if error is not None:
        return [error]
    if markdown is None:
        return []

    try:
        validator = load_sibling_validator("validate_t1_owner_authorization", OWNER_AUTHORIZATION_VALIDATOR)
    except RuntimeError:
        return ["owner_authorization_ref artifact validator is unavailable"]

    artifact_errors = validator.validate_owner_authorization(markdown, expected_sha, expected_pr)
    return [f"owner_authorization_ref artifact: {error}" for error in artifact_errors]


def validate_rollback_ref(record: dict[str, object], expected_sha: str, expected_pr: int | None) -> list[str]:
    markdown, error = read_private_ref(record, "rollback_ref")
    if error is not None:
        return [error]
    if markdown is None:
        return []

    try:
        validator = load_sibling_validator("validate_t1_rollback_evidence", ROLLBACK_EVIDENCE_VALIDATOR)
    except RuntimeError:
        return ["rollback_ref artifact validator is unavailable"]

    artifact_errors = validator.validate_rollback_evidence(markdown, expected_sha, expected_pr)
    return [f"rollback_ref artifact: {error}" for error in artifact_errors]


def validate_hardware_evidence_ref(record: dict[str, object], expected_sha: str, expected_pr: int | None) -> list[str]:
    markdown, error = read_private_ref(record, "hardware_evidence_ref")
    if error is not None:
        return [error.replace("artifact", "pack")]
    if markdown is None:
        return []

    try:
        validator = load_sibling_validator("validate_t1_hardware_evidence_pack", HARDWARE_PACK_VALIDATOR)
    except RuntimeError:
        return ["hardware_evidence_ref pack validator is unavailable"]

    pack_errors = validator.validate_pack(markdown, expected_sha, expected_pr)
    return [f"hardware_evidence_ref pack: {error}" for error in pack_errors]


def validate_audit_export_policy_ref(record: dict[str, object], expected_sha: str, expected_pr: int | None) -> list[str]:
    markdown, error = read_private_ref(record, "audit_export_policy_ref")
    if error is not None:
        return [error.replace("artifact", "policy")]
    if markdown is None:
        return []

    try:
        validator = load_sibling_validator("validate_t1_audit_export_policy", AUDIT_EXPORT_POLICY_VALIDATOR)
    except RuntimeError:
        return ["audit_export_policy_ref policy validator is unavailable"]

    policy_errors = validator.validate_audit_export_policy(markdown, expected_sha, expected_pr)
    return [f"audit_export_policy_ref policy: {error}" for error in policy_errors]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a private Product A per-Claw VPN T1 preflight evidence "
            "record. Error output names failed fields but does not echo field values."
        )
    )
    parser.add_argument("expected_artifact_sha", help="exact 40-hex artifact SHA")
    parser.add_argument("record_json", help="path to the private evidence JSON record")
    parser.add_argument(
        "--check-root-dir",
        action="store_true",
        help="also require audit_root to exist, be current-user-owned, non-symlink, and mode 0700",
    )
    parser.add_argument(
        "--check-hardware-pack",
        action="store_true",
        help="also validate the private hardware_evidence_ref pack shape without printing its path or values",
    )
    parser.add_argument(
        "--check-owner-authorization",
        action="store_true",
        help="also validate the private owner_authorization_ref shape without printing its path or values",
    )
    parser.add_argument(
        "--check-rollback",
        action="store_true",
        help="also validate the private rollback_ref shape without printing its path or values",
    )
    parser.add_argument(
        "--check-private-refs",
        action="store_true",
        help=(
            "also validate owner_authorization_ref, rollback_ref, hardware_evidence_ref, "
            "and audit_export_policy_ref shapes"
        ),
    )
    parser.add_argument(
        "--check-audit-export-policy",
        action="store_true",
        help="also validate the private audit_export_policy_ref shape without printing its path or values",
    )
    parser.add_argument("--expected-pr", type=int, help="expected activation PR number for chained private artifact checks")
    args = parser.parse_args()

    try:
        with open(args.record_json, "r", encoding="utf-8") as handle:
            record = json.load(handle)
    except OSError as error:
        print(f"ERROR: could not read evidence record: {error.__class__.__name__}", file=sys.stderr)
        return 2
    except json.JSONDecodeError:
        print("ERROR: evidence record is not valid JSON", file=sys.stderr)
        return 2

    errors = validate_record(record, args.expected_artifact_sha, args.check_root_dir)
    if not errors:
        if args.check_owner_authorization or args.check_private_refs:
            errors.extend(validate_owner_authorization_ref(record, args.expected_artifact_sha, args.expected_pr))
        if args.check_rollback or args.check_private_refs:
            errors.extend(validate_rollback_ref(record, args.expected_artifact_sha, args.expected_pr))
        if args.check_hardware_pack or args.check_private_refs:
            errors.extend(validate_hardware_evidence_ref(record, args.expected_artifact_sha, args.expected_pr))
        if args.check_audit_export_policy or args.check_private_refs:
            errors.extend(validate_audit_export_policy_ref(record, args.expected_artifact_sha, args.expected_pr))
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("OK: T1 preflight evidence record validates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
