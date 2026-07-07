#!/usr/bin/env python3
"""Prepare a private T1 preflight evidence record without printing its values."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from pathlib import Path


SCHEMA = "per_claw_vpn_t1_preflight_evidence_v1"
SCOPE = "dev-host T1-T4 only"
DEFAULT_RECORD = ".env.t1-preflight-evidence.json"
DEFAULT_AUDIT_ROOT = ".run/t1-audit-root"


def is_full_git_sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(byte in "0123456789abcdefABCDEF" for byte in value)
    )


def is_template_placeholder(value: object) -> bool:
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    return stripped.startswith("<") and stripped.endswith(">")


def keep_real_ref(value: object) -> str:
    if isinstance(value, str) and value.strip() and not is_template_placeholder(value):
        return value
    return ""


def select_private_ref(provided: str | None, existing: object) -> str:
    if provided is not None:
        return keep_real_ref(provided)
    return keep_real_ref(existing)


def missing_private_ref_fields(
    owner_ref: str,
    rollback_ref: str,
    hardware_ref: str,
    audit_export_policy_ref: str,
    device_session_config_ref: str,
) -> list[str]:
    missing: list[str] = []
    if not owner_ref:
        missing.append("owner_authorization_ref")
    if not rollback_ref:
        missing.append("rollback_ref")
    if not hardware_ref:
        missing.append("hardware_evidence_ref")
    if not audit_export_policy_ref:
        missing.append("audit_export_policy_ref")
    if not device_session_config_ref:
        missing.append("device_session_config_ref")
    return missing


def canonical_private_audit_root(path: str) -> str:
    root = Path(path).expanduser()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    return os.path.realpath(root)


def write_private_record(path: str, record: dict[str, object]) -> None:
    output = Path(path)
    created_parent = not output.parent.exists()
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if created_parent:
        os.chmod(output.parent, 0o700)
    if output.exists():
        os.chmod(output, 0o600)

    fd, temp_name = tempfile.mkstemp(prefix=f".{output.name}.tmp-", dir=output.parent)
    temp_output = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2)
            handle.write("\n")
        os.replace(temp_output, output)
    except BaseException:
        try:
            os.unlink(temp_output)
        except OSError:
            pass
        raise
    os.chmod(output, 0o600)


def load_existing_record(path: str) -> dict[str, object]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            existing = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(existing, dict):
        return existing
    return {}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Create or update the private Product A per-Claw VPN T1 preflight "
            "evidence record. The command prints status only, never record values."
        )
    )
    parser.add_argument("artifact_sha", help="exact 40-hex artifact SHA")
    parser.add_argument(
        "--record",
        default=DEFAULT_RECORD,
        help="private output JSON path (default: .env.t1-preflight-evidence.json)",
    )
    parser.add_argument(
        "--audit-root",
        default=DEFAULT_AUDIT_ROOT,
        help="private audit root to create with mode 0700 (default: .run/t1-audit-root)",
    )
    parser.add_argument("--owner-ref", help="private owner authorization reference")
    parser.add_argument("--rollback-ref", help="private rollback artifact reference")
    parser.add_argument("--hardware-ref", help="private T1-T4 hardware evidence reference")
    parser.add_argument("--audit-export-policy-ref", help="private audit export policy reference")
    parser.add_argument("--device-session-config-ref", help="private Device-side session config reference")
    args = parser.parse_args()

    if not is_full_git_sha(args.artifact_sha):
        print("ERROR: artifact_sha must be 40 hex characters", file=sys.stderr)
        return 1

    existing = load_existing_record(args.record)
    owner_ref = select_private_ref(args.owner_ref, existing.get("owner_authorization_ref"))
    rollback_ref = select_private_ref(args.rollback_ref, existing.get("rollback_ref"))
    hardware_ref = select_private_ref(args.hardware_ref, existing.get("hardware_evidence_ref"))
    audit_export_policy_ref = select_private_ref(
        args.audit_export_policy_ref,
        existing.get("audit_export_policy_ref"),
    )
    device_session_config_ref = select_private_ref(
        args.device_session_config_ref,
        existing.get("device_session_config_ref"),
    )
    audit_root = canonical_private_audit_root(args.audit_root)

    record = {
        "schema": SCHEMA,
        "artifact_sha": args.artifact_sha,
        "scope": SCOPE,
        "production_activation": False,
        "owner_authorization": bool(owner_ref),
        "rollback": bool(rollback_ref),
        "hardware_t1_t4": bool(hardware_ref),
        "owner_authorization_ref": owner_ref,
        "rollback_ref": rollback_ref,
        "hardware_evidence_ref": hardware_ref,
        "audit_export_policy_ref": audit_export_policy_ref,
        "device_session_config_ref": device_session_config_ref,
        "audit_root": audit_root,
    }
    write_private_record(args.record, record)

    mode = stat.S_IMODE(os.lstat(audit_root).st_mode)
    if mode != 0o700:
        print("ERROR: audit root mode was not set to 0700", file=sys.stderr)
        return 1

    print("OK: private T1 preflight evidence draft updated")
    print("OK: private audit root is present with mode 0700")
    missing_refs = missing_private_ref_fields(
        owner_ref,
        rollback_ref,
        hardware_ref,
        audit_export_policy_ref,
        device_session_config_ref,
    )
    if missing_refs:
        print("INFO: record remains incomplete until all private refs are supplied")
        print(f"INFO: missing private refs: {', '.join(missing_refs)}")
    else:
        print("INFO: refs are present, but activation still must verify their reviewed contents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
