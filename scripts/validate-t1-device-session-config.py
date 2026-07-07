#!/usr/bin/env python3
"""Validate a private T1 Device-side session config without printing its values."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path


SCHEMA = "t1-dev-runner-device-session-v1"
SCOPE = "dev-host T1-T4 only"
PLATFORMS = ("linux", "macos")
CLAW_ROUTE_PREFIX_LEN = 32
MIN_MTU = 1280
MAX_MTU = 9000


def required_string(config: dict[str, object], field: str, errors: list[str]) -> str | None:
    value = config.get(field)
    if not isinstance(value, str) or not value.strip() or value.strip() != value:
        errors.append(f"dev session config {field} must be a non-empty string")
        return None
    return value


def required_int(config: dict[str, object], field: str, errors: list[str]) -> int | None:
    value = config.get(field)
    if type(value) is not int:
        errors.append(f"dev session config {field} must be an integer")
        return None
    return value


def parse_ipv4(value: str | None, field: str, errors: list[str]) -> ipaddress.IPv4Address | None:
    if value is None:
        return None
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        errors.append(f"dev session config {field} must be a valid IPv4 address")
        return None


def validate_device_session_config(config: object) -> list[str]:
    errors: list[str] = []
    if not isinstance(config, dict):
        return ["dev session config must be a JSON object"]

    schema = required_string(config, "schema", errors)
    if schema is not None and schema != SCHEMA:
        errors.append("dev session config schema invalid")

    scope = required_string(config, "scope", errors)
    if scope is not None and scope != SCOPE:
        errors.append("dev session config scope invalid")

    if config.get("production_activation") is not False:
        errors.append("dev session config production_activation must be false")

    platform = required_string(config, "platform", errors)
    if platform is not None and platform not in PLATFORMS:
        errors.append("dev session config platform invalid")

    local_side = required_string(config, "local_side", errors)
    if local_side is not None and local_side != "device":
        errors.append("dev session config local_side must be device")

    claw_route_prefix_len = required_int(config, "claw_route_prefix_len", errors)
    if claw_route_prefix_len is not None and claw_route_prefix_len != CLAW_ROUTE_PREFIX_LEN:
        errors.append("dev session config claw_route_prefix_len must be 32")

    mtu = required_int(config, "mtu", errors)
    if mtu is not None and not (MIN_MTU <= mtu <= MAX_MTU):
        errors.append("dev session config mtu invalid")

    device_ipv4 = parse_ipv4(required_string(config, "device_ipv4", errors), "device_ipv4", errors)
    claw_ipv4 = parse_ipv4(required_string(config, "claw_ipv4", errors), "claw_ipv4", errors)
    if device_ipv4 is not None and claw_ipv4 is not None:
        if (
            device_ipv4.is_unspecified
            or device_ipv4.is_multicast
            or claw_ipv4.is_unspecified
            or claw_ipv4.is_multicast
            or device_ipv4 == claw_ipv4
        ):
            errors.append("dev session config IPv4 pair invalid")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a private Product A per-Claw VPN T1 Device-side session "
            "config. Error output names failed fields only; it does not echo "
            "private paths or IPv4 values."
        )
    )
    parser.add_argument(
        "device_session_config",
        help="path to the private Device-side session config JSON",
    )
    args = parser.parse_args()

    try:
        config = json.loads(Path(args.device_session_config).read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        print("ERROR: dev session config is not valid UTF-8", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"ERROR: could not read dev session config: {error.__class__.__name__}", file=sys.stderr)
        return 2
    except json.JSONDecodeError:
        print("ERROR: dev session config is not valid JSON", file=sys.stderr)
        return 2

    errors = validate_device_session_config(config)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("OK: T1 device session config validates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
