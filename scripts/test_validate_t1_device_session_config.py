#!/usr/bin/env python3
"""Tests for scripts/validate-t1-device-session-config.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("validate-t1-device-session-config.py")
SPEC = importlib.util.spec_from_file_location("validate_t1_device_session_config", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def valid_config() -> dict[str, object]:
    return {
        "schema": validator.SCHEMA,
        "scope": validator.SCOPE,
        "production_activation": False,
        "platform": "macos",
        "local_side": "device",
        "device_ipv4": "198.18.0.1",
        "claw_ipv4": "198.18.0.2",
        "claw_route_prefix_len": 32,
        "mtu": 1280,
    }


class ValidateT1DeviceSessionConfigTests(unittest.TestCase):
    def assert_validation_error(self, config: object, expected_error: str) -> None:
        errors = validator.validate_device_session_config(config)
        self.assertIn(expected_error, errors)

    def test_valid_device_session_config_passes(self) -> None:
        self.assertEqual([], validator.validate_device_session_config(valid_config()))

    def test_rejects_schema_scope_production_platform_local_side_prefix_and_mtu(self) -> None:
        cases = (
            ("schema", "t1-dev-runner-device-session-v0", "dev session config schema invalid"),
            ("scope", "production", "dev session config scope invalid"),
            ("production_activation", True, "dev session config production_activation must be false"),
            ("platform", "windows", "dev session config platform invalid"),
            ("local_side", "claw", "dev session config local_side must be device"),
            ("claw_route_prefix_len", 24, "dev session config claw_route_prefix_len must be 32"),
            ("mtu", 1279, "dev session config mtu invalid"),
            ("mtu", 9001, "dev session config mtu invalid"),
        )
        for field, value, expected_error in cases:
            with self.subTest(field=field, value=value):
                config = valid_config()
                config[field] = value
                self.assert_validation_error(config, expected_error)

    def test_rejects_invalid_ipv4_pair_without_echoing_values(self) -> None:
        config = valid_config()
        config["device_ipv4"] = "SECRET-DEVICE-IP"
        errors = validator.validate_device_session_config(config)
        self.assertIn("dev session config device_ipv4 must be a valid IPv4 address", errors)
        self.assertFalse(any("SECRET-DEVICE-IP" in error for error in errors))

        config = valid_config()
        config["claw_ipv4"] = config["device_ipv4"]
        self.assert_validation_error(config, "dev session config IPv4 pair invalid")

        config = valid_config()
        config["device_ipv4"] = "0.0.0.0"
        self.assert_validation_error(config, "dev session config IPv4 pair invalid")

        config = valid_config()
        config["claw_ipv4"] = "224.0.0.1"
        self.assert_validation_error(config, "dev session config IPv4 pair invalid")

    def test_rejects_non_object_and_missing_fields(self) -> None:
        self.assert_validation_error([], "dev session config must be a JSON object")
        config = valid_config()
        del config["device_ipv4"]
        self.assert_validation_error(config, "dev session config device_ipv4 must be a non-empty string")

    def test_cli_accepts_valid_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "private-device-session-config.json"
            config_path.write_text(json.dumps(valid_config()), encoding="utf-8")

            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(config_path)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertIn("OK: T1 device session config validates", proc.stdout)

    def test_cli_invalid_config_does_not_echo_private_path_or_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "private-device-session-config.json"
            config = valid_config()
            config["device_ipv4"] = "SECRET-DEVICE-IP"
            config_path.write_text(json.dumps(config), encoding="utf-8")

            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(config_path)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(1, proc.returncode)
            self.assertIn("ERROR: dev session config device_ipv4 must be a valid IPv4 address", proc.stderr)
            self.assertFalse("SECRET-DEVICE-IP" in proc.stderr)
            self.assertFalse(str(config_path) in proc.stderr)
            self.assertFalse(config_path.name in proc.stderr)

    def test_cli_missing_config_error_does_not_echo_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing_config = Path(tmp) / "private-device-session-config.json"

            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(missing_config)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(2, proc.returncode)
            self.assertIn("ERROR: could not read dev session config: FileNotFoundError", proc.stderr)
            self.assertFalse(str(missing_config) in proc.stderr)
            self.assertFalse(missing_config.name in proc.stderr)


if __name__ == "__main__":
    unittest.main()
