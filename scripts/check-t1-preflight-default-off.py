#!/usr/bin/env python3
"""Run the local non-live T1 preflight/default-off check bundle."""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
RUST_MANIFEST = "admin/rust/Cargo.toml"


@dataclass(frozen=True)
class Check:
    name: str
    command: tuple[str, ...]
    cwd: Path


def python_check(name: str, script: str) -> Check:
    return Check(name, (sys.executable, script), REPO_ROOT)


def rust_check(name: str, package: str, *cargo_args: str) -> Check:
    return Check(
        name,
        ("cargo", "test", "-p", package, "--manifest-path", RUST_MANIFEST, *cargo_args),
        REPO_ROOT,
    )


def build_checks(skip_python: bool, skip_rust: bool) -> list[Check]:
    checks: list[Check] = []
    if not skip_python:
        checks.extend(
            (
                python_check("prepare-helper-tests", "scripts/test_prepare_t1_preflight_evidence_record.py"),
                python_check("validator-tests", "scripts/test_validate_t1_preflight_evidence_record.py"),
                python_check(
                    "owner-authorization-validator-tests",
                    "scripts/test_validate_t1_owner_authorization.py",
                ),
                python_check(
                    "rollback-evidence-validator-tests",
                    "scripts/test_validate_t1_rollback_evidence.py",
                ),
                python_check(
                    "hardware-evidence-pack-validator-tests",
                    "scripts/test_validate_t1_hardware_evidence_pack.py",
                ),
                python_check(
                    "audit-export-policy-validator-tests",
                    "scripts/test_validate_t1_audit_export_policy.py",
                ),
            )
        )
    if not skip_rust:
        checks.extend(
            (
                rust_check(
                    "source-guard",
                    "server-rs",
                    "--test",
                    "owner_events",
                    "product_a_per_claw_vpn_dev_config_remains_default_off_and_unwired",
                    "--",
                    "--nocapture",
                ),
                rust_check("mount-audit-sink", "server-rs", "--lib", "t1_mount_audit_sink", "--", "--nocapture"),
                rust_check(
                    "audit-sink-durability-rotation",
                    "server-rs",
                    "--lib",
                    "t1_spooled_audit_sink",
                    "--",
                    "--nocapture",
                ),
                rust_check(
                    "audit-log-fixed-path",
                    "server-rs",
                    "--lib",
                    "t1_audit_log_path",
                    "--",
                    "--nocapture",
                ),
                rust_check(
                    "audit-export-hmac",
                    "server-rs",
                    "--lib",
                    "t1_audit_export_jsonl",
                    "--",
                    "--nocapture",
                ),
                rust_check(
                    "mounted-t1-missing-preflight",
                    "server-rs",
                    "--lib",
                    "mounted_t1_iptunnel_router",
                    "--",
                    "--nocapture",
                ),
                rust_check(
                    "friend-cli-iptunnel-reject",
                    "friend-cli-rs",
                    "rejects_iptunnel_before_connecting",
                    "--",
                    "--nocapture",
                ),
                rust_check(
                    "t1-iptunnel-dev-runner-validate",
                    "t1-iptunnel-dev-runner-rs",
                    "--",
                    "--nocapture",
                ),
            )
        )
    return checks


def run_check(check: Check, dry_run: bool, timeout_seconds: int) -> int:
    print(f"==> {check.name}")
    print(" ".join(check.command))
    if dry_run:
        return 0
    try:
        return subprocess.run(check.command, cwd=check.cwd, check=False, timeout=timeout_seconds).returncode
    except subprocess.TimeoutExpired:
        print(f"ERROR: {check.name} timed out after {timeout_seconds}s", file=sys.stderr)
        return 124


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run local non-live Product A per-Claw VPN T1 checks. The bundle "
            "uses unit tests and source guard only; it does not open TUN/utun, "
            "install routes, launch runtime, or touch production apps."
        )
    )
    parser.add_argument("--dry-run", action="store_true", help="print the checks without executing them")
    parser.add_argument("--skip-python", action="store_true", help="skip Python validator/helper tests")
    parser.add_argument("--skip-rust", action="store_true", help="skip Rust source-guard and mount tests")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=900,
        help="per-check timeout in seconds",
    )
    args = parser.parse_args(argv)

    checks = build_checks(skip_python=args.skip_python, skip_rust=args.skip_rust)
    if not checks:
        print("ERROR: no checks selected", file=sys.stderr)
        return 2

    for check in checks:
        code = run_check(check, args.dry_run, args.timeout_seconds)
        if code != 0:
            print(f"ERROR: {check.name} failed", file=sys.stderr)
            return code

    print("OK: T1 preflight/default-off check bundle passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
