#!/usr/bin/env python3
"""One-shot assembly and full validation of the private T1 #281 preflight record.

This wrapper does not compute or invent any evidence. Given the run's real
captured evidence (paths to the five real ref files a human supplies after a
run) plus the engine build artifact SHA, it:

  1. assembles the SHA-bound #281 record by delegating to the existing
     prepare-t1-preflight-evidence-record.py logic (imported, not reimplemented),
  2. runs the full validate-t1-preflight-evidence-record.py --check-private-refs
     chain over the assembled record, and
  3. refuses (fail-closed, non-zero exit, static error) if any ref path is
     missing or empty or if any validator rejects.

production_activation is always false (dev scope). A missing ref is a hard
failure, never a synthesized placeholder. Output is status only: it never
echoes a ref's content, a secret, a private IPv4 address, or a filesystem path.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType


PREPARE_SCRIPT = Path(__file__).with_name("prepare-t1-preflight-evidence-record.py")
VALIDATE_SCRIPT = Path(__file__).with_name("validate-t1-preflight-evidence-record.py")

# (argparse destination, private record field name) for the five real refs.
REF_FIELDS = (
    ("owner_ref", "owner_authorization_ref"),
    ("rollback_ref", "rollback_ref"),
    ("hardware_ref", "hardware_evidence_ref"),
    ("audit_export_policy_ref", "audit_export_policy_ref"),
    ("device_session_config_ref", "device_session_config_ref"),
)

AUDIT_ROOT_DIRNAME = ".t1-audit-root"


def load_module(module_name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ref_present(path_str: str) -> bool:
    """Report whether a ref path points at readable, non-empty content.

    Missing, unreadable, empty, or whitespace-only files are absent. Non-UTF-8
    content is treated as present so the downstream shape validator, not this
    wrapper, produces the static rejection. Never returns or logs the content.
    """

    try:
        content = Path(path_str).read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return True
    except OSError:
        return False
    return bool(content.strip())


def derive_audit_root(out: str) -> str:
    return str(Path(out).expanduser().absolute().parent / AUDIT_ROOT_DIRNAME)


def run_prepare(
    prepare_mod: ModuleType,
    artifact_sha: str,
    out: str,
    audit_root: str,
    refs: dict[str, str],
) -> int:
    argv = [
        str(PREPARE_SCRIPT),
        artifact_sha,
        "--record",
        out,
        "--audit-root",
        audit_root,
        "--owner-ref",
        refs["owner_ref"],
        "--rollback-ref",
        refs["rollback_ref"],
        "--hardware-ref",
        refs["hardware_ref"],
        "--audit-export-policy-ref",
        refs["audit_export_policy_ref"],
        "--device-session-config-ref",
        refs["device_session_config_ref"],
    ]
    saved_argv = sys.argv
    sys.argv = argv
    try:
        return int(prepare_mod.main())
    finally:
        sys.argv = saved_argv


def record_production_activation_is_false(out: str) -> bool:
    try:
        with open(out, "r", encoding="utf-8") as handle:
            record = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(record, dict) and record.get("production_activation") is False


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Assemble and fully validate the private Product A per-Claw VPN T1 "
            "#281 preflight evidence record from real captured evidence. Prints "
            "status only; never echoes ref values, secrets, addresses, or paths."
        )
    )
    parser.add_argument("--artifact-sha", required=True, help="exact 40-hex engine build artifact SHA")
    parser.add_argument("--owner-ref", required=True, help="path to the real owner authorization evidence")
    parser.add_argument("--rollback-ref", required=True, help="path to the real rollback evidence")
    parser.add_argument("--hardware-ref", required=True, help="path to the real T1-T4 hardware evidence pack")
    parser.add_argument("--audit-export-policy-ref", required=True, help="path to the real audit export policy")
    parser.add_argument(
        "--device-session-config-ref",
        required=True,
        help="path to the real Device-side session config",
    )
    parser.add_argument("--out", required=True, help="private output record JSON path")
    args = parser.parse_args()

    try:
        prepare_mod = load_module("prepare_t1_preflight_evidence_record", PREPARE_SCRIPT)
    except (OSError, RuntimeError):
        print("ERROR: preparation logic is unavailable", file=sys.stderr)
        return 1

    if not prepare_mod.is_full_git_sha(args.artifact_sha):
        print("ERROR: artifact_sha must be 40 hex characters", file=sys.stderr)
        return 1

    refs = {
        "owner_ref": args.owner_ref,
        "rollback_ref": args.rollback_ref,
        "hardware_ref": args.hardware_ref,
        "audit_export_policy_ref": args.audit_export_policy_ref,
        "device_session_config_ref": args.device_session_config_ref,
    }

    for arg_key, field_name in REF_FIELDS:
        if not ref_present(refs[arg_key]):
            print(f"ERROR: {field_name} input is missing or empty", file=sys.stderr)
            return 1

    audit_root = derive_audit_root(args.out)

    prepare_rc = run_prepare(prepare_mod, args.artifact_sha, args.out, audit_root, refs)
    if prepare_rc != 0:
        print("ERROR: preflight record could not be assembled", file=sys.stderr)
        return 1

    if not record_production_activation_is_false(args.out):
        print("ERROR: assembled record must set production_activation to false", file=sys.stderr)
        return 1

    validation = subprocess.run(
        [
            sys.executable,
            str(VALIDATE_SCRIPT),
            args.artifact_sha,
            args.out,
            "--check-root-dir",
            "--check-private-refs",
        ],
        check=False,
    )
    if validation.returncode != 0:
        print("ERROR: assembled record failed full preflight validation", file=sys.stderr)
        return 1

    if not record_production_activation_is_false(args.out):
        print("ERROR: assembled record must set production_activation to false", file=sys.stderr)
        return 1

    print("OK: private T1 preflight evidence record assembled and fully validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
