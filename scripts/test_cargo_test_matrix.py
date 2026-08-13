#!/usr/bin/env python3
"""Focused tests for feature-surface Cargo process environments."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("cargo_test_matrix.py")
SPEC = importlib.util.spec_from_file_location("cargo_test_matrix", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
matrix = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = matrix
SPEC.loader.exec_module(matrix)


class FeatureSurfaceDebugInfoTests(unittest.TestCase):
    def test_feature_surface_disables_debug_info_for_cargo(self) -> None:
        target = Path(tempfile.mkdtemp())
        captured: list[dict[str, str]] = []

        def fake_fresh_target() -> Path:
            os.environ.setdefault("CLAWS_CATALOG_JSON", str(target / "claws-catalog.json"))
            os.environ["CARGO_TARGET_DIR"] = str(target)
            return target

        def fake_run(*_args: object, **kwargs: object) -> None:
            env = kwargs["env"]
            assert isinstance(env, dict)
            captured.append(env)

        with (
            patch.object(matrix, "fresh_target", side_effect=fake_fresh_target),
            patch.object(matrix, "matrix", return_value=[matrix.Row("workspace", None)]),
            patch.object(matrix.subprocess, "run", side_effect=fake_run),
            patch.dict(os.environ, {"CARGO_PROFILE_DEV_DEBUG": "2"}),
        ):
            self.assertEqual(matrix.run_compile(False), 0)

        self.assertEqual(captured[0]["CARGO_PROFILE_DEV_DEBUG"], "0")
        self.assertEqual(captured[0]["CARGO_TARGET_DIR"], str(target))
        self.assertEqual(captured[0]["CLAWS_CATALOG_JSON"], str(target / "claws-catalog.json"))

    def test_derive_does_not_override_debug_info(self) -> None:
        target = Path(tempfile.mkdtemp())
        captured: list[dict[str, str]] = []

        def fake_fresh_target() -> Path:
            os.environ.setdefault("CLAWS_CATALOG_JSON", str(target / "claws-catalog.json"))
            os.environ["CARGO_TARGET_DIR"] = str(target)
            return target

        def fake_run(*_args: object, **kwargs: object) -> None:
            env = kwargs["env"]
            assert isinstance(env, dict)
            captured.append(env)

        with (
            patch.object(matrix, "fresh_target", side_effect=fake_fresh_target),
            patch.object(matrix, "matrix", return_value=[matrix.Row("workspace", None)]),
            patch.object(matrix.subprocess, "run", side_effect=fake_run),
            patch.object(matrix, "depfile_inputs", return_value=set()),
            patch.dict(os.environ, {"CARGO_PROFILE_DEV_DEBUG": "2"}),
        ):
            self.assertEqual(matrix.run_compile(True), 0)

        self.assertEqual(captured[0]["CARGO_PROFILE_DEV_DEBUG"], "2")
        self.assertEqual(captured[0]["CARGO_TARGET_DIR"], str(target))
        self.assertEqual(captured[0]["CLAWS_CATALOG_JSON"], str(target / "claws-catalog.json"))


if __name__ == "__main__":
    unittest.main()
