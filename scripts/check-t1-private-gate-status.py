#!/usr/bin/env python3
"""Report private T1 activation gate status without printing values."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType


PREFLIGHT_VALIDATOR = Path(__file__).with_name("validate-t1-preflight-evidence-record.py")
TRUE_FIELDS = ("owner_authorization", "rollback", "hardware_t1_t4")
REF_FIELDS = (
    "owner_authorization_ref",
    "rollback_ref",
    "hardware_evidence_ref",
    "audit_export_policy_ref",
    "device_session_config_ref",
)


def load_preflight_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("validate_t1_preflight_evidence_record", PREFLIGHT_VALIDATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError("preflight validator unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def is_present_ref(value: object, validator: ModuleType) -> bool:
    return isinstance(value, str) and bool(value.strip()) and not validator.is_template_placeholder(value)


def load_record(path: str) -> tuple[object | None, str | None]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle), None
    except OSError as error:
        return None, f"could not read evidence record: {error.__class__.__name__}"
    except json.JSONDecodeError:
        return None, "evidence record is not valid JSON"


def summarize_basic_status(record: object, validator: ModuleType) -> tuple[list[str], list[str]]:
    ok: list[str] = []
    missing_or_invalid: list[str] = []
    if not isinstance(record, dict):
        return ok, ["record"]

    for field in TRUE_FIELDS:
        if record.get(field) is True:
            ok.append(field)
        else:
            missing_or_invalid.append(field)

    for field in REF_FIELDS:
        if is_present_ref(record.get(field), validator):
            ok.append(field)
        else:
            missing_or_invalid.append(field)

    return ok, missing_or_invalid


def private_ref_status(
    record: dict[str, object],
    validator: ModuleType,
    expected_sha: str,
    expected_pr: int | None,
) -> tuple[list[str], list[str]]:
    ok: list[str] = []
    errors: list[str] = []

    def check_device_session_config(
        checked_record: dict[str, object],
        _expected_sha: str,
        _expected_pr: int | None,
    ) -> list[str]:
        return validator.validate_device_session_config_ref(checked_record)

    ref_checks = (
        ("owner_authorization_ref", validator.validate_owner_authorization_ref),
        ("rollback_ref", validator.validate_rollback_ref),
        ("hardware_evidence_ref", validator.validate_hardware_evidence_ref),
        ("audit_export_policy_ref", validator.validate_audit_export_policy_ref),
        ("device_session_config_ref", check_device_session_config),
    )
    for field, check in ref_checks:
        if not is_present_ref(record.get(field), validator):
            continue
        if check(record, expected_sha, expected_pr):
            errors.append(field)
        else:
            ok.append(field)
    return ok, errors


def record_error_field(error: str) -> str:
    if error.startswith("record artifact_sha") or error.startswith("expected artifact SHA"):
        return "artifact_sha"
    if error.startswith("schema"):
        return "schema"
    if error.startswith("scope"):
        return "scope"
    if error.startswith("production_activation"):
        return "production_activation"
    if error.startswith("audit_root"):
        return "audit_root"
    for field in TRUE_FIELDS + REF_FIELDS:
        if error.startswith(field):
            return field
    return "record"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Report private Product A per-Claw VPN T1 activation gate status. "
            "Output names fields only; it never prints private paths or values."
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
        "--check-private-refs",
        action="store_true",
        help="also validate private ref artifact shapes without printing paths or values",
    )
    parser.add_argument("--expected-pr", type=int, help="expected activation PR number for private artifact checks")
    args = parser.parse_args(argv)

    try:
        validator = load_preflight_validator()
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    record, read_error = load_record(args.record_json)
    if read_error is not None:
        print(f"ERROR: {read_error}", file=sys.stderr)
        return 2

    base_errors = validator.validate_record(record, args.expected_artifact_sha, args.check_root_dir)
    ok_fields, missing_or_invalid_fields = summarize_basic_status(record, validator)
    for field in ok_fields:
        print(f"OK: {field}")
    for field in missing_or_invalid_fields:
        print(f"MISSING_OR_INVALID: {field}", file=sys.stderr)
    for field in dict.fromkeys(record_error_field(error) for error in base_errors):
        if field not in missing_or_invalid_fields:
            print(f"INVALID_RECORD: {field}", file=sys.stderr)

    ok_private_ref_fields: list[str] = []
    invalid_ref_fields: list[str] = []
    if args.check_private_refs and isinstance(record, dict):
        ok_private_ref_fields, invalid_ref_fields = private_ref_status(
            record,
            validator,
            args.expected_artifact_sha,
            args.expected_pr,
        )
        for field in ok_private_ref_fields:
            print(f"OK_PRIVATE_REF: {field}")
        for field in invalid_ref_fields:
            print(f"INVALID_PRIVATE_REF: {field}", file=sys.stderr)

    if base_errors or missing_or_invalid_fields or invalid_ref_fields:
        print("ERROR: private T1 gate is incomplete", file=sys.stderr)
        return 1

    print("OK: private T1 gate is complete-shaped")
    print("INFO: shape/privacy status only; truth/content review remains required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
